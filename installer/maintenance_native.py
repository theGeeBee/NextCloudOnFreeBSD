"""Internal, operator-assisted offline capture/restore controller.

NOT a CLI recipe. The production admission gate remains the empty native recipe
catalog. ``acceptance_session`` is an explicit trusted Python harness boundary,
not a JSON permission, and must only be used on an approved disposable machine.
No publication, package changes or migration implementation lives here. Local
snapshots are not an independent copy, a rehearsal, or full disaster recovery.
"""

from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass, replace
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import time
import uuid

from . import maintenance_fence as fence, recovery_sets as recovery
from .generations import _encode, _json
from .maintenance import executor_record, _deployment
from .maintenance_journal import NativeJournal, require_native_recipe
from .maintenance_state import NativeState


DENIED = "Native maintenance refused; retain the closed pair and private evidence"
APP = "/usr/local/www/nextcloud/occ"
SERVICES = {"nextcloud": ("cron", "sshd", "apache24", "php_fpm", "mysql-server", "redis"),
            "onlyoffice": ("cron", "sshd", "nginx", "supervisord")}
PROCESSES = {"cron": {"cron"}, "sshd": {"sshd", "sshd-session"},
             "apache24": {"httpd"}, "php_fpm": {"php-fpm"},
             "mysql-server": {"mariadbd", "mysqld", "mysqld_safe", "mariadbd-safe"},
             "redis": {"redis-server"}, "nginx": {"nginx"},
             "supervisord": {"supervisord", "node", "docservice", "converter"}}


def _require(value):
    if not value:
        raise ValueError(DENIED)


def _boot(value):
    _require(type(value) is str)
    match = re.fullmatch(r"\{\s*sec = ([1-9][0-9]*),\s*usec = ([0-9]+)\s*\}[^\r\n]*", value)
    _require(match is not None and int(match[2]) < 1000000)
    return value


@dataclass(frozen=True)
class RequiescenceAssessment:
    eligible: bool
    blockers: tuple[str, ...]
    binding_sha256: str | None = None


@dataclass(frozen=True)
class OriginalRestoreAssessment:
    eligible: bool
    blockers: tuple[str, ...]
    binding_sha256: str | None = None


def _runtime_files(root, names):
    """Read-only executable/config identity; never traverse a jail symlink."""
    root, result, total = Path(root), {}, 0
    pending = list(names)
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
                          s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    while pending:
        name = pending.pop()
        _require(name.startswith("/") and str(Path(name)) == name and ".." not in Path(name).parts)
        path = root / name.lstrip("/")
        for parent in (root, *list(path.parents)[:list(path.parents).index(root)]):
            info = parent.lstat()
            _require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o022)
        if name in result:
            continue
        if not os.path.lexists(path):
            result[name] = None
            continue
        before = path.lstat()
        _require(before.st_uid == os.geteuid() and (stat.S_ISLNK(before.st_mode) or not before.st_mode & 0o022))
        meta = dict(mode=stat.S_IMODE(before.st_mode), uid=before.st_uid, gid=before.st_gid)
        if stat.S_ISDIR(before.st_mode):
            meta["type"] = "directory"
            pending.extend(str(Path(name) / child.name) for child in path.iterdir())
        elif stat.S_ISLNK(before.st_mode):
            meta.update(type="link", target=os.readlink(path))
        else:
            _require(stat.S_ISREG(before.st_mode) and before.st_size <= 1024 ** 3)
            digest = hashlib.sha256()
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as stream:
                _require(identity(os.fstat(stream.fileno())) == identity(before))
                size = 0
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    size += len(block)
                    total += len(block)
                    _require(size <= before.st_size and total <= 4 * 1024 ** 3)
                    digest.update(block)
                _require(size == before.st_size and identity(os.fstat(stream.fileno())) == identity(before))
            meta.update(type="file", size=size, sha256=digest.hexdigest())
        # Reading can update atime. Identity/content-change fields exclude it.
        after = path.lstat()
        _require(identity(before) == identity(after))
        result[name] = meta
        _require(len(result) + len(pending) <= 100000)
    return result


@contextmanager
def _pkg_database_identity(root):
    """Bracket a checkpointed pkg 2.8.4 DB; sidecars are transient, not receipts.

    Requires exclusive operator-owned package management plus controller locks.
    This detects replacement/drift, not arbitrary concurrent root transactions.
    Read-only pkg may touch SHM and fchown an empty WAL (ctime only);
    no nonempty WAL or rollback journal is accepted.
    Newly appearing sidecars deliberately refuse until a fresh assessment.
    """
    root, opened, directories, files = Path(root), [], [], []
    def identity(info, *, shm=False, wal=False, directory=False):
        value = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink)
        if not directory:
            value += (info.st_size,)
            if not shm:
                value += (info.st_mtime_ns,)
                # pkg 2.8.4's SQLite unixOpen calls robustFchown on WAL opens.
                # Same-owner fchown may update ctime without changing data.
                if not wal:
                    value += (info.st_ctime_ns,)
        return value

    def safe(info, *, directory=False):
        _require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
                 and info.st_uid == os.geteuid() and not info.st_mode & 0o022
                 and (directory or info.st_nlink == 1))

    try:
        parent = None
        for name in (str(root), "var", "db", "pkg"):
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            safe(before, directory=True)
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            opened.append(fd)
            _require(identity(os.fstat(fd), directory=True) == identity(before, directory=True))
            directories.append((name, parent, fd, identity(before, directory=True)))
            parent = fd
        for suffix in ("", "-wal", "-shm", "-journal"):
            name = "local.sqlite" + suffix
            try:
                before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                _require(suffix != "")
                files.append((name, None, None, suffix))
                continue
            _require(suffix != "-journal")
            safe(before)
            # The observed 2.8.4 empty-WAL profile uses one 32-KiB SHM region.
            # Larger layouts are outside this narrowly reviewed contract.
            _require(suffix != "-wal" or before.st_size == 0)
            _require(suffix != "-shm" or before.st_size <= 32768)
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            opened.append(fd)
            expected = identity(before, shm=suffix == "-shm", wal=suffix == "-wal")
            _require(identity(os.fstat(fd), shm=suffix == "-shm", wal=suffix == "-wal") == expected)
            files.append((name, fd, expected, suffix))
        before = _runtime_files(root, ["/var/db/pkg/local.sqlite"])
        yield before
        _require(_runtime_files(root, ["/var/db/pkg/local.sqlite"]) == before)
        for name, fd, expected, suffix in files:
            try:
                after = os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                _require(fd is None)
                continue
            _require(fd is not None)
            _require(identity(after, shm=suffix == "-shm", wal=suffix == "-wal") == expected
                     and identity(os.fstat(fd), shm=suffix == "-shm", wal=suffix == "-wal") == expected)
        for name, parent_fd, fd, expected in directories:
            _require(identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False), directory=True) == expected
                     and identity(os.fstat(fd), directory=True) == expected)
    finally:
        for fd in reversed(opened):
            os.close(fd)


class AcceptanceHarness(ABC):
    """Executable source review supplied by a trusted, explicit test harness.

    admit_source must inspect the original installed code/packages/config/apps,
    disallow unmanaged writers/external dependencies and bind the reviewed startup
    inventory. It raises on failure; returning a boolean cannot admit anything.
    The controller independently checks native services, identities, storage, PF,
    shutdown logs and closure. Never instantiate from an operator document.
    """

    @abstractmethod
    def descriptor(self):
        """Fixed reviewed implementation identity; no native-accepted claim."""

    @abstractmethod
    def admit_source(self, deployment):
        """Return {startup: exact reviewed startup hashes, evidence: private ref}.

        Evidence is a source-bound assessment of external integrations and all
        installed writers, not a boolean assertion or newly adopted baseline.
        """


class MigrationAdapter(ABC):
    """A later reviewed fixed Python updater; never loaded from a record/path."""

    @abstractmethod
    def descriptor(self):
        """Exact source-bound NativeState recipe descriptor."""

    @abstractmethod
    def execute(self, context):
        """Perform its own reviewed update checkpoints, return retained evidence."""


def production_admission(operation):
    """Must precede locks, filesystem writes, probes, or any other effects."""
    # The compiled catalog remains empty until the complete recipe has passed
    # native acceptance. Receipt/report fields never populate that catalog.
    return require_native_recipe(operation)


class NativeBackend(recovery.NativeBackend):
    """Fixed native commands; all jailed execution uses Deployment's numeric JID."""

    def __init__(self, deployment, *, timeout=60, clock=time.monotonic, sleep=time.sleep):
        super().__init__(deployment.runner)
        self.d = deployment
        self.c = deployment.config
        self.timeout, self.clock, self.sleep = timeout, clock, sleep

    def jailed(self, jail, *args, check=True):
        try:
            result = self.d.jail(jail, *args, check=False, hide_output=True, timeout=self.timeout)
            _require(type(result.returncode) is int and (not check or result.returncode == 0))
            _require(isinstance(result.stdout, str) and len(result.stdout) <= recovery.MAX_FILE)
            return result
        except Exception:
            raise ValueError(DENIED) from None

    def identity(self, *, running=True):
        """Validate exact Bastille membership before every start/stop operation."""
        from .lifecycle import _checked_jails
        expected = {self.c.nextcloud_jail, self.c.onlyoffice_jail}
        _require({name for name, _ in _checked_jails(self.d, stopped=not running)} == expected)
        for jail, hostname in ((self.c.nextcloud_jail, self.c.nextcloud_host),
                               (self.c.onlyoffice_jail, self.c.onlyoffice_host)):
            _require(self.output("bastille", "config", jail, "get", "path") == str(self.d.jail_root(jail)))
            _require(self.output("bastille", "config", jail, "get", "host.hostname") == hostname)
            for suffix in ("", "/root"):
                dataset = f"{self.c.bastille_dataset}/jails/{jail}{suffix}"
                _require(self.get(dataset, recovery.OWNER) == self.c.instance)
                _require(self.get(dataset, recovery.MANAGER) == "cloud-installer")
            if running:
                self.d.require_running_jail(jail)

    def owned_live(self):
        from .network import storage_guard
        self.identity()
        script = storage_guard(self.c, self.d.storage, self.d.registry.root, lifecycle=False)
        for jail in (self.c.nextcloud_jail, self.c.onlyoffice_jail):
            before = self.d.require_running_jail(jail)
            result = self.runner.run("/bin/sh", "-s", "--", jail, input=script,
                                     hide_output=True, timeout=self.timeout)
            _require(result.returncode == 0 and self.d.require_running_jail(jail) == before)

    def source_observations(self):
        """Concrete live source checks, independent of harness-returned evidence."""
        from .enrollment import _source, _inputs, _packages, _json as read_json
        from .runtime_inventory import collect_php
        source = _source(self.d)
        _inputs(self.d)
        packages = _packages(self.d, read_json(self.d.state / "inventory.json"))
        status = json.loads(self.occ("status", "--output=json"))
        _require(status.get("installed") is True and status.get("maintenance") is False
                 and status.get("needsDbUpgrade") is False and status.get("version") == "35.0.1.1")
        apps = json.loads(self.occ("app:list", "--output=json"))
        _require(type(apps.get("enabled")) is dict and apps["enabled"].get("onlyoffice") == "10.2.1"
                 and "files_external" not in apps["enabled"])
        # Unknown application/integration configuration still requires explicit
        # source review by admit_source. Retain only its digest, never secrets.
        config = json.loads(self.occ("config:list", "--private", "--output=json"))
        _require(type(config.get("system")) is dict and type(config.get("apps")) is dict)
        system = config["system"]
        _require(not any(system.get(key) for key in ("objectstore", "objectstore_multibucket"))
                 and system.get("datadirectory") == "/var/nc-data" and system.get("dbtype") == "mysql"
                 and system.get("dbhost") in ("127.0.0.1", "localhost", "localhost:/var/run/mysql/mysql.sock"))
        php = collect_php(self.d)
        from .maintenance_preflight import _php
        from .versions import load_policy, package_upstream
        _php(php, self.d.versions, load_policy())
        database = self.jailed(self.c.nextcloud_jail, "/usr/local/bin/mariadb", "--no-defaults",
            "--protocol=socket", "--socket=/var/run/mysql/mysql.sock", "--user=root", "--batch",
            "--skip-column-names", "--execute", "SELECT VERSION()").stdout.strip()
        expected = package_upstream(self.d.versions["packages"]["nextcloud"][self.d.versions["roles"]["database"]]["version"])
        _require(expected.startswith("12.3.") and database.startswith(expected + "-MariaDB"))
        return dict(source=source, packages=packages, php=php, status=status, database=database,
                    reclosure_runtime=self.reclosure_runtime(),
                    apps_sha256=hashlib.sha256(_encode(apps)).hexdigest(),
                    config_sha256=hashlib.sha256(_encode(config)).hexdigest())

    def reclosure_runtime(self, retained=None):
        """Original package DB/runtime identity; cold checks execute no jail code.

        Captured at source admission and pinned in the recovery copies. A matching
        Initial admission uses native pkg queries. Later checks require byte-
        identical package DBs before trusting those retained file lists. Python's
        optional SQLite extension is not shipped by FreeBSD's python311 port.
        Executable hashes and the signed-lock artifact stage are checked separately.
        """
        packages, databases, files = {}, {}, {}
        if retained is not None:
            _require(type(retained) is dict and set(retained) == {
                "packages", "package_databases", "database", "files", "database_files", "database_layout"})
        plan = self.d.versions
        from .versions import package_upstream
        database = plan["roles"]["database"]
        locked = plan["packages"]["nextcloud"]
        _require(package_upstream(locked[database]["version"]).startswith("12.3."))
        closure, pending = set(), [database]
        while pending:
            name = pending.pop()
            if name not in closure:
                _require(name in locked)
                closure.add(name)
                pending.extend(locked[name]["dependencies"])
        for jail, group in ((self.c.nextcloud_jail, "nextcloud"), (self.c.onlyoffice_jail, "onlyoffice")):
            root = self.d.jail_root(jail)
            with _pkg_database_identity(root) as before:
                if retained is None:
                    # Admission already authenticated executables/configuration.
                    # Disable plugins BEFORE config dispatch; do not mask READ_LOCK
                    # while inspecting its configured value. No persistent edits.
                    inspect = ("pkg", "-o", "PKG_ENABLE_PLUGINS=false")
                    for key, expected in (("READ_LOCK", "no"), ("PLUGINS", ""), ("PKG_DBDIR", "/var/db/pkg")):
                        _require(self.jailed(jail, *inspect, "config", key).stdout.strip() == expected)
                    query = (*inspect, "-o", "READ_LOCK=false", "query")
                    rows = [line.split() for line in self.jailed(jail, *query, "%n %v %o").stdout.splitlines() if line.strip()]
                else:
                    _require(before == retained["package_databases"][jail])
                    rows = retained["packages"][jail]
                _require(type(rows) is list and 0 < len(rows) <= 100000
                         and all(type(row) is list and len(row) == 3 and all(type(item) is str for item in row) for row in rows)
                         and len({row[0] for row in rows}) == len(rows))
                actual = {row[0]: tuple(row[1:]) for row in rows}
                _require(actual.get("pkg") == ("2.8.4", "ports-mgmt/pkg"))
                _require(all(actual.get(name) == (item["version"], item["origin"])
                             for name, item in plan["packages"][group].items()))
                extras = actual.keys() - plan["packages"][group].keys() - {"pkg"}
                _require(all(re.fullmatch(r"FreeBSD-[A-Za-z0-9_+.-]+", name)
                              and actual[name][1] == "base/" + name for name in extras))
                packages[jail] = sorted(rows)
                if group == "nextcloud":
                    if retained is None:
                        paths = sorted({path for name in sorted(closure)
                                        for path in self.jailed(jail, *query, "%Fp", name).stdout.splitlines()})
                    else:
                        paths = retained["database_files"]
                    _require(type(paths) is list and 0 < len(paths) <= 100000
                             and all(type(path) is str for path in paths) and paths == sorted(set(paths)))
                    _require("/usr/local/libexec/mariadbd" in paths and "/usr/local/bin/mariadbd-safe" in paths)
                    from .maintenance_pkg_layout import PAMFILE, capture_mariadb_pam
                    pam = {}
                    if PAMFILE in paths:
                        # The authenticated database closure includes this exact
                        # initialized port layout. Never relax generic ownership.
                        pam = capture_mariadb_pam(root, package_name=database,
                            package_version=locked[database]["version"], package_origin=locked[database]["origin"])
                    files = _runtime_files(root, [path for path in paths if path != PAMFILE] + ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/lib", "/lib", "/libexec",
                        "/usr/local/etc/mysql", "/etc/my.cnf", "/etc/mysql", "/usr/local/etc/my.cnf",
                        "/root/.my.cnf", "/root/.mylogin.cnf", "/etc/libmap.conf", "/usr/local/etc/libmap.d"])
                    _require(all(name not in files or files[name] == value for name, value in pam.items()))
                    files.update(pam)
                    _require(all(files[path] is not None for path in paths))
                databases[jail] = before
        for name in ("my.cnf", ".my.cnf", ".mylogin.cnf"):
            _require(not os.path.lexists(Path(self.c.mount_root) / "nc-database" / name))
        # mysql-server's rc prestart can invoke mariadb-install-db when mysql/ is
        # missing. Re-quiescence must never turn missing data into a fresh server.
        data = Path(self.c.mount_root) / "nc-database"
        layout = {}
        for name in (".", "mysql", "mysql/global_priv.frm", "mysql/global_priv.MAD", "mysql/global_priv.MAI",
                     "ibdata1", "ib_logfile0"):
            info = (data / name).lstat()
            directory = name in (".", "mysql")
            _require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_size > 0)
                     and not info.st_mode & 0o002)
            layout[name] = dict(uid=info.st_uid, gid=info.st_gid, mode=stat.S_IMODE(info.st_mode), directory=directory)
        return dict(packages=packages, package_databases=databases, database=locked[database], files=files,
                    database_files=paths, database_layout=layout)

    def database_ready(self):
        """Wait for native InnoDB crash recovery using only root Unix-socket SQL."""
        from .versions import package_upstream
        expected = package_upstream(self.d.versions["packages"]["nextcloud"][self.d.versions["roles"]["database"]]["version"])
        _require(expected.startswith("12.3."))
        deadline = self.clock() + self.timeout
        while True:
            result = self.jailed(self.c.nextcloud_jail, "/usr/local/bin/mariadb", "--no-defaults", "--protocol=socket",
                "--socket=/var/run/mysql/mysql.sock", "--user=root", "--batch", "--skip-column-names",
                "--execute", "SELECT VERSION(), @@global.innodb_force_recovery, 1", check=False)
            if result.returncode == 0:
                row = result.stdout.strip().split("\t")
                _require(len(row) == 3 and row[0].startswith(expected + "-MariaDB") and row[1:] == ["0", "1"])
                _require(len([p for p in self.running(self.c.nextcloud_jail, "mysql-server")
                              if p[2] in ("mariadbd", "mysqld")]) == 1)
                return dict(version=row[0], innodb_force_recovery=0, socket="/var/run/mysql/mysql.sock")
            _require(self.clock() < deadline)
            self.sleep(0.2)

    def processes(self, jail):
        text = self.jailed(jail, "ps", "-ax", "-o", "pid=", "-o", "ppid=", "-o", "comm=").stdout
        rows = []
        for line in text.splitlines():
            row = line.split()
            _require(len(row) == 3 and row[0].isdigit() and int(row[0]) > 0 and row[1].isdigit())
            rows.append((int(row[0]), int(row[1]), Path(row[2]).name))
        _require(rows and len({row[0] for row in rows}) == len(rows))
        return rows

    def running(self, jail, service):
        return self._service_rows(jail, service, self.processes(jail))

    def _service_rows(self, jail, service, rows):
        result = [row for row in rows if row[2] in PROCESSES[service]]
        # FreeBSD's comm is the executable, not the script or setproctitle.
        # The ports run mariadbd-safe through sh and supervisord through Python.
        # Never allow all shells/Python workers just to accommodate those parents.
        for row in rows:
            if service == "mysql-server" and row[2] == "sh":
                interpreter, scripts = "/bin/sh", {"/usr/local/bin/mariadbd-safe", "/usr/local/bin/mysqld_safe"}
            elif service == "supervisord" and re.fullmatch(r"python3\.[0-9]+", row[2]):
                interpreter, scripts = "/usr/local/bin/" + row[2], {"/usr/local/bin/supervisord"}
            else:
                continue
            text = self.jailed(jail, "ps", "-ww", "-p", str(row[0]), "-o", "pid=", "-o", "ppid=", "-o", "comm=", "-o", "args=").stdout
            fields = text.split(None, 5)
            _require(len(fields) >= 5 and fields[:3] == [str(row[0]), str(row[1]), row[2]])
            if fields[3] == interpreter and fields[4] in scripts:
                result.append(row)
        return result

    def wait_stopped(self, jail, service):
        deadline = self.clock() + self.timeout
        while self.running(jail, service):
            _require(self.clock() < deadline)
            self.sleep(0.2)

    def wait_writer_closure(self, *, database_running):
        """Also drain orphaned cron/PHP/editor helpers, not only rc PID files.

        Unknown processes refuse rather than killing a writer or assuming that
        its parent daemon's successful stop covered its process group.
        """
        deadline = self.clock() + self.timeout
        for jail in (self.c.nextcloud_jail, self.c.onlyoffice_jail):
            allowed = {"init", "syslogd", "ps"}
            if database_running and jail == self.c.nextcloud_jail:
                allowed |= PROCESSES["mysql-server"] | PROCESSES["redis"]
            while True:
                rows = self.processes(jail)
                wrappers = set()
                if database_running and jail == self.c.nextcloud_jail:
                    database = self._service_rows(jail, "mysql-server", rows)
                    wrappers = {row[0] for row in database if row[2] == "sh"
                                and any(child[1] == row[0] and child[2] in ("mariadbd", "mysqld")
                                        for child in database)}
                if not any(row[2] not in allowed and row[0] not in wrappers for row in rows):
                    break
                _require(self.clock() < deadline)
                self.sleep(0.2)

    def stop(self, jail, service):
        _require(service in PROCESSES)
        if not self.running(jail, service):
            return
        if service == "apache24":
            self.jailed(jail, "/usr/local/sbin/apachectl", "-k", "graceful-stop")
        elif service == "php_fpm":
            pid = self.jailed(jail, "cat", "/var/run/php-fpm.pid").stdout.strip()
            _require(pid.isdigit() and int(pid) > 0)
            rows = self.running(jail, service)
            _require(any(row[0] == int(pid) for row in rows))
            # QUIT is FPM's graceful stop, never TERM/KILL a busy worker.
            self.jailed(jail, "kill", "-QUIT", pid)
        else:
            self.jailed(jail, "service", service, "onestop")
        self.wait_stopped(jail, service)

    def service_states(self):
        result = {}
        for role, jail in (("nextcloud", self.c.nextcloud_jail), ("onlyoffice", self.c.onlyoffice_jail)):
            result[jail] = {name: bool(self.running(jail, name)) for name in SERVICES[role]}
        return result

    def closed_flags(self):
        for role, jail in (("nextcloud", self.c.nextcloud_jail), ("onlyoffice", self.c.onlyoffice_jail)):
            for service in fence.SERVICES[role]:
                _require(self.jailed(jail, "sysrc", "-n", service + "_enable").stdout.strip() == "NO")

    def pair_state(self):
        expected = {jail: str(self.d.jail_root(jail)) for jail in (self.c.nextcloud_jail, self.c.onlyoffice_jail)}
        found = set()
        for line in self.output("jls", "-d", "jid", "name", "path", "dying").splitlines():
            row = line.split()
            _require(len(row) == 4 and row[0].isdigit() and int(row[0]) > 0 and row[3] in ("true", "false"))
            if row[1] in expected or row[2] in expected.values():
                _require(row[1] in expected and row[2] == expected[row[1]] and row[3] == "false" and row[1] not in found)
                found.add(row[1])
        _require(not found or found == set(expected))
        return "running" if found else "stopped"

    def occ(self, *args):
        return self.jailed(self.c.nextcloud_jail, "mdo", "-u", "www", "/usr/local/bin/php",
                           "-d", "display_errors=0", "-d", "log_errors=0", APP, *args).stdout

    def _deny_status(self, timeout=20):
        _require(self.c.tls_mode != "external")
        host = self.c.public_hostname
        # Connect to the actual backend port while retaining SNI/certificate name.
        ca = ("--cacert", self.c.ca_file) if self.c.ca_file else ()
        timeout = max(1, min(20, int(timeout)))
        result = self.runner.run("curl", "--silent", "--show-error", "--noproxy", "*", *ca,
            "--max-time", str(timeout), "--resolve", f"{host}:443:{self.c.nextcloud_ip}",
            "--header", f"Host: {host}" + (f":{self.c.public_https_port}" if self.c.public_https_port != 443 else ""),
            "--output", "/dev/null", "--write-out", "%{http_code}", f"https://{host}/status.php",
            hide_output=True, timeout=timeout + 5, check=False)
        _require(result.returncode == 0 and result.stdout.strip() in ("200", "503"))
        return result.stdout.strip()

    def deny_probe(self):
        _require(self._deny_status() == "503")

    def wait_deny_probe(self, recheck):
        """Await only the authenticated old-200 -> closed-503 reload transition.

        Transport/TLS/unknown responses fail immediately. A 503 is ingress
        readiness only, never a writer/drain/cold-boundary proof.
        """
        _require(callable(recheck) and self.timeout > 0)
        deadline = self.clock() + min(self.timeout, 30)
        while True:
            _require(self.clock() < deadline)
            recheck()
            jid = self.d.require_running_jail(self.c.nextcloud_jail)
            remaining = deadline - self.clock()
            _require(remaining > 0)
            status = self._deny_status(math.ceil(remaining))
            _require(self.d.require_running_jail(self.c.nextcloud_jail) == jid)
            recheck()
            _require(self.clock() <= deadline)
            if status == "503":
                return
            remaining = deadline - self.clock()
            _require(remaining > 0)
            self.sleep(min(0.2, remaining))

    def loopback_probe(self):
        host = self.c.public_hostname
        ca = ("--cacert", "/root/cloud-installer/tls/ca.pem") if self.c.ca_file else ()
        result = self.jailed(self.c.nextcloud_jail, "curl", "--silent", "--show-error", "--noproxy", "*", *ca,
            "--max-time", "20", "--resolve", f"{host}:443:127.0.0.1", f"https://{host}/status.php")
        value = json.loads(result.stdout)
        _require(value.get("installed") is True and value.get("maintenance") is True)
        return value

    def clean_mysql_stop(self):
        """Pin an open, owned log inode/offset and the actual server PID.

        The rc service's success or a missing process alone is never clean-shutdown
        proof. Rotation, truncation, excessive output or missing markers refuse.
        """
        self.owned_live()
        jail = self.c.nextcloud_jail
        rows = [row for row in self.running(jail, "mysql-server") if row[2] in ("mariadbd", "mysqld")]
        _require(len(rows) == 1)
        pid = rows[0][0]
        config = self.jailed(jail, "/usr/local/bin/my_print_defaults", "mysqld").stdout.splitlines()
        logs = [line.split("=", 1)[1] for line in config if line.startswith(("--log-error=", "--log_error="))]
        _require(logs and logs[-1] == "/var/log/mysql/mysqld.err")
        effective = self.jailed(jail, "/usr/local/bin/mariadb", "--no-defaults", "--protocol=socket",
            "--socket=/var/run/mysql/mysql.sock", "--user=root", "--batch", "--skip-column-names",
            "--execute", "SELECT @@global.log_error, @@global.pid_file").stdout.strip().split("\t")
        _require(len(effective) == 2 and effective[0] == "/var/log/mysql/mysqld.err"
                 and re.fullmatch(r"/var/(?:run/mysql|db/mysql)/[A-Za-z0-9_.-]+\.pid", effective[1]))
        _require(self.jailed(jail, "cat", effective[1]).stdout.strip() == str(pid))
        path = Path(self.c.mount_root) / "nc-db-logs/mysqld.err"
        _require(self.output("realpath", str(path)) == str(path))
        mysql_uid = self.jailed(jail, "id", "-u", "mysql").stdout.strip()
        _require(mysql_uid.isdigit())
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                     and before.st_uid == int(mysql_uid) and not before.st_mode & 0o027)
            stream.seek(before.st_size)
            _require([row for row in self.running(jail, "mysql-server")
                      if row[2] in ("mariadbd", "mysqld")] == rows)
            self.stop(jail, "mysql-server")
            after = os.fstat(stream.fileno())
            current = path.lstat()
            _require((after.st_dev, after.st_ino) == (current.st_dev, current.st_ino)
                     == (before.st_dev, before.st_ino) and before.st_size <= after.st_size
                     and after.st_size - before.st_size <= 1024 * 1024)
            segment = stream.read(1024 * 1024 + 1)
            _require(len(segment) == after.st_size - before.st_size)
            # MariaDB's error log identifies the executable, not the PID on each
            # line. Bind PID via the exact process immediately before rc shutdown.
            _require(re.search(rb"(?m)^.*(?:mariadbd|mysqld).*: Shutdown complete\r?$", segment))
            _require(not self.running(jail, "mysql-server"))
        return dict(pid=pid, device=before.st_dev, inode=before.st_ino, offset=before.st_size,
                    end=after.st_size, segment_sha256=hashlib.sha256(segment).hexdigest())

    def stop_pair(self):
        self.identity()
        self.wait_writer_closure(database_running=False)
        for role, jail in (("nextcloud", self.c.nextcloud_jail), ("onlyoffice", self.c.onlyoffice_jail)):
            _require(not any(self.running(jail, name) for name in SERVICES[role]))
        for jail in (self.c.onlyoffice_jail, self.c.nextcloud_jail):
            from .lifecycle import _require_jail
            _require_jail(self.d, jail)
            self.d.require_running_jail(jail)
            self.run("bastille", "stop", jail)


class NativeContext:
    """Lock-scoped controller; never retain outside acceptance_session."""

    def __init__(self, registry, native, operation, deployment, admission):
        self.registry, self.native, self.operation = registry, native, operation
        self.store = native.store
        self.d, self.c, self.admission = deployment, deployment.config, admission
        self.backend = NativeBackend(deployment)
        self.directory = f"maintenance/operations/{operation}"
        intent, inputs = native.read(operation)
        self.journal = NativeJournal(registry, operation, self.store.reference(self.directory + "/intent.json"),
                                     inputs["recipe"], native=native)
        self.journal.initialize()
        self.active = False
        self._original_restore_consent = None

    def check(self, *, closed=False):
        _require(self.active)
        self.registry._require_lock()
        from .enrollment_start import _held
        _held(self.store, f"instances/{self.c.instance}/database-operation.lock")
        intent, inputs = self.native.read(self.operation)
        value = self.journal.read()
        _require(not value["publication_may_have_begun"] and not value["recovery_publication_may_have_begun"])
        from .maintenance_operations import _network_binding
        from .host import verify_managed_network
        _require(_network_binding(self.store) == inputs["network"])
        verify_managed_network(self.d.registry, self.backend.runner)
        self.d.require_original_artifact()
        if closed:
            fence.verify_closed(self.store, self.profile())
        return intent, inputs, value

    def record(self, name, value):
        _require(re.fullmatch(r"[a-z0-9-]+", name))
        return self.store._write_once(self.directory + "/" + name + ".json", _encode(value), recover=True)

    def _require_no_cancellation(self):
        # Cancellation imports the native service policy and must still use check().
        from .maintenance_cancellation import require_no_cancellation
        require_no_cancellation(self)

    def profile(self):
        return self.store.reference(self.directory + "/closed-profile.json")

    def _recovery_context(self, *, readonly=False):
        intent, inputs, journal = self.check()
        from .maintenance_operations import load_operation
        parent, plan, _ = load_operation(self.registry, inputs["cache_owner"])
        evidence = []
        for name, role, reference in self._evidence(inputs, parent, readonly=readonly):
            evidence.append(recovery.Evidence(name, role, self.store.root / reference["path"], reference["sha256"]))
        ackpath = self.directory + "/offline-acknowledgement.json"
        if readonly:
            _require(self.store._present(ackpath))
        ack = (recovery.OfflineAcknowledgement(self.store.root / ackpath, self.store.reference(ackpath)["sha256"])
               if self.store._present(ackpath) else None)
        if readonly:
            self.store._check(self.store._path(self.directory + "/recovery").lstat(), directory=True)
        else:
            self.store._mkdir(self.directory + "/recovery")
        return recovery.RecoveryContext(self.c, self.operation, inputs["executor"]["source_sha256"],
            inputs["executor"]["executor_sha256"], parent["plan"]["sha256"], intent["base_graph"]["sha256"],
            hashlib.sha256(_encode(inputs["network"])).hexdigest(), self.store.root / self.directory / "recovery",
            tuple(evidence), cold_boundary=self.cold_boundary, checkpoint=self.checkpoint,
            schema_version=2, quiescence_mode=recovery.OPERATOR_OFFLINE,
            preparation_sha256=inputs["preparation"]["sha256"], offline_acknowledgement=ack,
            original_restore=getattr(self, "_original_restore_consent", None))

    def _evidence(self, inputs, parent, *, readonly=False):
        """Private host copies, including credentials, never staged into a jail."""
        def retain(path, data):
            if readonly:
                reference = self.store.reference(path)
                _require(self.store._bound(reference) == data)
                return reference
            return self.store._write_once(path, data, recover=True)
        records = [("inputs", "inputs", self.store.reference(self.directory + "/native-inputs.json")),
                   ("plan", "inputs", parent["plan"]), ("preparation", "inputs", inputs["preparation"]),
                   ("graph", "graph", self.native.read(self.operation)[0]["base_graph"])]
        for name, pair in inputs["originals"][self.c.instance]["files"].items():
            if pair is not None:
                records.append((name.replace(".", "-"), "source" if name == "source.sha256" else "metadata", pair["retained"]))
        for name, ref in inputs["network"]["records"].items():
            records.append(("pf-" + name.replace(".", "-"), "pf", ref))
        for name in ("admission", "source-observations", "original-services", "closed-profile"):
            path = self.directory + "/" + name + ".json"
            if readonly:
                _require(self.store._present(path))
            if self.store._present(path):
                records.append((name, "metadata", self.store.reference(path)))
        profile = self.directory + "/closed-profile.json"
        if self.store._present(profile):
            for index, item in enumerate(_json(self.store._read(profile))["files"]):
                for kind in ("original", "closed"):
                    records.append((f"profile-{index}-{kind}", "metadata", item[kind]))
        initial = self.directory + "/initial-closure.json"
        if readonly:
            _require(self.store._present(initial))
        if self.store._present(initial):
            reference = self.store.reference(initial)
            shutdown = _json(self.store._bound(reference))["shutdown"]
            self.store._bound(shutdown)
            records.extend((("initial-closure", "metadata", reference), ("capture-clean-shutdown", "metadata", shutdown)))
        for name in ("secrets.json", "inputs.sha256", "inventory.json"):
            data = self.store._read(f"instances/{self.c.instance}/{name}")
            ref = retain(self.directory + "/private-" + name, data)
            records.append(("private-" + name.replace(".", "-"), "credentials" if name == "secrets.json" else "metadata", ref))
        tls = {}
        from .enrollment import _bytes
        for field in ("certificate_file", "private_key_file", "ca_file"):
            path = getattr(self.c, field)
            if path:
                data = _bytes(Path(path), private=field == "private_key_file")
                ref = retain(self.directory + "/" + field, data)
                records.append((field, "tls", ref))
                tls[field] = ref
        # ACME keys/certificates are covered by the exact original jail root;
        # supplied originals above are retained privately outside that root too.
        records.append(("tls-binding", "tls", retain(self.directory + "/tls-binding.json", _encode(dict(
            mode=self.c.tls_mode, supplied=tls, root=str(self.d.jail_root(self.c.nextcloud_jail)))))))
        return records

    def acknowledge(self, confirmation):
        context = self._recovery_context()
        _require(confirmation == recovery.offline_acknowledgement_phrase(context))
        return self.record("offline-acknowledgement", recovery.offline_acknowledgement_record(context))

    def offline_phrase(self):
        """Prompt text only; the harness must obtain the operator's own input."""
        return recovery.offline_acknowledgement_phrase(self._recovery_context())

    def quiesce(self, confirmation):
        """One attempt only; interruption keeps closed state, never guesses drain."""
        self._require_no_cancellation()
        _, _, journal = self.check()
        _require(journal["phase"] == "capture" and not journal["steps"])
        _require(self.c.tls_mode != "external")
        ack = self.acknowledge(confirmation)
        self.backend.owned_live()
        states = self.backend.service_states()
        prior = self.record("original-services", dict(pair={self.c.nextcloud_jail: "running", self.c.onlyoffice_jail: "running"},
                                                       services=states))
        roots = {jail: str(self.d.jail_root(jail)) for jail in states}
        profile = fence.capture_profile(dict(config=json.loads(self.c.to_json()), roots=roots,
            baseline=self.admission["startup"], operator_saved_closed=True), self.store, self.operation)
        self.journal.step_start("close-writers", replay="never", precondition=prior)
        try:
            fence.install_profile(self.registry, profile)
            self.check(closed=True)
            self.backend.closed_flags()
            self.backend.jailed(self.c.nextcloud_jail, "/usr/local/sbin/apachectl", "configtest")
            self.backend.jailed(self.c.nextcloud_jail, "/usr/local/sbin/apachectl", "-k", "graceful")
            def current_closure():
                self._require_no_cancellation()
                self.check(closed=True)
                self.backend.closed_flags()
            self.backend.wait_deny_probe(current_closure)
            ingress = self.record("ingress-denied", dict(profile=profile, probe="host-direct-TLS-503"))
            self.backend.stop(self.c.nextcloud_jail, "apache24")
            for jail in states:
                for service in ("cron", "sshd"):
                    self.backend.stop(jail, service)
            self.backend.stop(self.c.nextcloud_jail, "php_fpm")
            for service in ("nginx", "supervisord"):
                self.backend.stop(self.c.onlyoffice_jail, service)
            self.backend.wait_writer_closure(database_running=True)
            self.backend.occ("maintenance:mode", "--on")
            shutdown = self._stop_database()
            self.backend.stop(self.c.nextcloud_jail, "redis")
            self.backend.stop_pair()
            self.check(closed=True)
            context = self._recovery_context()
            storage = self.backend.storage(context)
            closure = self.record("initial-closure", dict(binding=context.binding(), clean_database_shutdown=True,
                                  profile=profile, shutdown=shutdown, storage=storage,
                                  original_services=prior, acknowledgement=ack))
            self.journal.step_complete("close-writers", closure)
            self.journal.advance("quiesced", dict(offline_acknowledgement=ack, admission=self.admission["evidence"],
                ingress=ingress, shutdown=shutdown, closure=closure))
        except Exception:
            self.journal.fail("capture-failed")
            raise ValueError(DENIED) from None

    def cold_boundary(self, context, action):
        """Every invocation reads current locks, journal, roots, PF and mounts."""
        if action == "restore" and context.original_restore is not None:
            return self._original_restore_boundary(context)
        _, _, journal = self.check(closed=True)
        _require(context.binding() == self._recovery_context().binding())
        recovery._acknowledgement(context)
        _require(action in ("capture", "restore"))
        storage = self.backend.storage(context)  # Includes live/dying jails and nullfs.
        shutdown = _json(self.store._read(self.directory + "/current-shutdown.json"))["proof"]
        stopped = _json(self.store._bound(shutdown))
        _require(_boot(stopped["boot"]) == _boot(self.backend.output("sysctl", "-n", "kern.boottime")))
        # A later controlled start invalidates the original clean-stop proof.
        starts = self.directory + "/validation-started.json"
        current_start = self.store.reference(starts) if self.store._present(starts) else None
        _require(stopped["after_start"] == current_start)
        prior = _json(self.store._read(self.directory + "/original-services.json"))
        _require(set(prior["pair"]) == {self.c.nextcloud_jail, self.c.onlyoffice_jail})
        manifest_path = context.directory / "manifest.json"
        anchor = recovery._load(manifest_path)["cold_boundary"] if manifest_path.exists() else None
        phase = journal["last_safe_phase"] if journal["phase"] == "recovery-required" else journal["phase"]
        _require(phase != "recovery-reclosing")
        if "reclosure" in stopped:
            _require(stopped["reclosure"]["capture_anchor_sha256"] == anchor)
            self.store._bound(stopped["reclosure"]["request"])
            self.store._bound(stopped["reclosure"]["readiness"])
        if phase == "recovery-reclosed":
            receipt = _json(self.store._bound(journal["evidence"]["reclosure"]))
            _require(receipt["shutdown"] == shutdown and receipt["boot"] == stopped["boot"]
                     and receipt["capture_anchor_sha256"] == anchor)
        value = dict(action=action, storage=storage, binding=context.binding(), phase=journal["phase"],
            clean_database_shutdown=True, office_drained=False, initial_closure=journal["evidence"].get("closure"),
            shutdown=shutdown, profile=self.profile(), journal=self.store.reference(self.journal.path),
            nonce=uuid.uuid4().hex)
        # The manifest pins this hash; derive the private path without scanning
        # or adding an evidence member after the recovery context was frozen.
        observation = self.record("closure-" + hashlib.sha256(_encode(value)).hexdigest(), value)
        return recovery.ColdBoundary(context.binding(), journal["phase"], observation["sha256"],
            tuple(sorted(prior["pair"].items())), True, False, True, True, True, True, False, False,
            recovery.OPERATOR_OFFLINE, context.offline_acknowledgement.sha256, anchor)

    def _stop_database(self, *, reclosure=None, expected_boot=None):
        boot = _boot(self.backend.output("sysctl", "-n", "kern.boottime"))
        _require(expected_boot is None or boot == expected_boot)
        observation = self.backend.clean_mysql_stop()
        _require(boot == _boot(self.backend.output("sysctl", "-n", "kern.boottime")))
        starts = self.directory + "/validation-started.json"
        value = dict(observation=observation, boot=boot,
                     after_start=self.store.reference(starts) if self.store._present(starts) else None)
        if reclosure is not None:
            value["reclosure"] = reclosure
        reference = self.record("clean-shutdown-" + uuid.uuid4().hex, value)
        path = self.directory + "/current-shutdown.json"
        self.store._put(path, {"proof": reference}, replace=self.store._present(path))
        return reference

    def _verify_reclosure_stage(self):
        from .maintenance_operations import load_operation, _artifact_bindings
        from .maintenance_staging import verify_stage
        _, inputs, _ = self.check(closed=True)
        parent, plan, journal = load_operation(self.registry, inputs["cache_owner"])
        staged = journal.read()
        _require(staged["phase"] == "staged")
        verify_stage(self.store.root, parent["operation"], plan["artifacts"], staged["evidence"]["artifacts"],
                     **_artifact_bindings(self.registry, parent, plan))

    def _cold_reclosure_set(self, context, journal):
        """Topology/copies only: deliberately no historical clean-stop assertion."""
        recovery._context(context)
        reference = journal["evidence"]["recovery_set"]
        _require(reference["path"] == self.directory + "/recovery/manifest.json")
        manifest = recovery.validate_manifest(context, _json(self.store._bound(reference)))
        _require(len(manifest["datasets"]) == len(manifest["snapshots"]) == 14)
        _require(recovery._copies(context) == manifest["evidence"])
        _require(self.backend.pair_state() == "stopped")
        self.backend.identity(running=False)
        _require(self.backend.storage(context) == manifest["datasets"])
        _require(self.backend.snapshots(context, manifest["datasets"], restoring=True) == manifest["snapshots"])
        # Starting a database on a partially rolled-back set is never authorized.
        _require(not os.path.lexists(context.directory / "restore.json"))
        return manifest

    def _reclosure_preflight(self):
        _, _, journal = self.check(closed=True)  # Publication refusal precedes native probes.
        phase = journal["last_safe_phase"] if journal["phase"] == "recovery-required" else journal["phase"]
        _require(phase in ("recovery-ready", "migrating", "awaiting-reboot", "validating", "committed-closed",
                           "recovery-reclosing", "recovery-reclosed"))
        context = self._recovery_context(readonly=True)
        manifest = self._cold_reclosure_set(context, journal)
        self._verify_reclosure_stage()
        runtime = self.store.reference(self.directory + "/source-observations.json")
        original = _json(self.store._bound(runtime))["reclosure_runtime"]
        _require(type(original) is dict and original and self.backend.reclosure_runtime(original) == original)
        boot = _boot(self.backend.output("sysctl", "-n", "kern.boottime"))
        shutdown = _json(self.store._read(self.directory + "/current-shutdown.json"))["proof"]
        stopped = _json(self.store._bound(shutdown))
        previous_boot = _boot(stopped["boot"])
        starts = self.directory + "/validation-started.json"
        current_start = self.store.reference(starts) if self.store._present(starts) else None
        fresh = previous_boot == boot and stopped["after_start"] == current_start
        if fresh:
            # An interrupted attempt may already have produced a verifiable new
            # clean stop. Reconcile that exact attempt read-only; never restart it.
            _require(phase == "recovery-reclosing" and "reclosure" in stopped)
            binding = stopped["reclosure"]
            _require(binding["request"] == journal["evidence"]["reclosure_request"]
                     and binding["capture_anchor_sha256"] == manifest["cold_boundary"])
            request = _json(self.store._bound(binding["request"]))
            _require(request["boot"] == boot and request["manifest"] == journal["evidence"]["recovery_set"])
            self.store._bound(binding["readiness"])
        _require(_boot(self.backend.output("sysctl", "-n", "kern.boottime")) == boot)
        self._cold_reclosure_set(context, journal)
        return dict(phase=phase, journal=self.store.reference(self.journal.path), boot=boot, old_shutdown=shutdown,
                    starts=current_start, manifest=journal["evidence"]["recovery_set"], runtime=runtime,
                    capture_anchor_sha256=manifest["cold_boundary"], decision="reconcile" if fresh else "start")

    def assess_requiescence(self):
        """Strict read-only assessment; no permission files, repairs or starts."""
        try:
            self._require_no_cancellation()
            value = self._reclosure_preflight()
            return RequiescenceAssessment(True, (), hashlib.sha256(_encode(value)).hexdigest())
        except Exception:
            return RequiescenceAssessment(False, ("Cold re-quiescence assessment failed; retain the closed pair and evidence",))

    def _completed_reclosure(self, journal):
        """Read-only reconciliation of a completed receipt before phase commit."""
        value = self._reclosure_preflight()
        _require(value["phase"] == "recovery-reclosing" and value["decision"] == "reconcile")
        request = journal["evidence"]["reclosure_request"]
        steps = [step for step in journal["steps"].values() if step["phase"] == "recovery-reclosing"
                 and step["state"] == "complete" and step["precondition"] == request]
        _require(len(steps) == 1)
        reference = steps[0]["observation"]
        receipt = _json(self.store._bound(reference))
        manifest = _json(self.store._bound(value["manifest"]))
        _require(receipt == dict(kind="native-reclosure", request=request, shutdown=value["old_shutdown"], boot=value["boot"],
            capture_anchor_sha256=value["capture_anchor_sha256"], manifest=value["manifest"],
            datasets=manifest["datasets"], snapshots=manifest["snapshots"]))
        return reference, receipt, manifest

    def _finish_reclosure(self, request, shutdown):
        _, _, journal = self.check(closed=True)
        context = self._recovery_context(readonly=True)
        manifest = self._cold_reclosure_set(context, journal)
        stopped = _json(self.store._bound(shutdown))
        boot = _boot(self.backend.output("sysctl", "-n", "kern.boottime"))
        start = self.store.reference(self.directory + "/validation-started.json")
        _require(stopped["boot"] == boot and stopped["after_start"] == start
                 and stopped["reclosure"]["request"] == request
                 and stopped["reclosure"]["capture_anchor_sha256"] == manifest["cold_boundary"])
        self.store._bound(stopped["reclosure"]["readiness"])
        runtime = _json(self.store._read(self.directory + "/source-observations.json"))["reclosure_runtime"]
        _require(self.backend.reclosure_runtime(runtime) == runtime)
        self.check(closed=True)
        _require(_boot(self.backend.output("sysctl", "-n", "kern.boottime")) == boot)
        self._cold_reclosure_set(context, journal)
        return self.record("reclosed-" + uuid.uuid4().hex, dict(kind="native-reclosure", request=request, shutdown=shutdown,
            boot=boot, capture_anchor_sha256=manifest["cold_boundary"], manifest=journal["evidence"]["recovery_set"],
            datasets=manifest["datasets"], snapshots=manifest["snapshots"]))

    def requiesce(self, confirmation, *, assessment=None):
        """Explicit DB-only crash recovery/clean stop, never migration or rollback.

        Interrupted attempts require the exact fresh assess_requiescence() result
        and a fully stopped pair. A partial/live boot is refused, not restarted.
        """
        self._require_no_cancellation()
        _require(confirmation == "REQUIESCE-MAINTENANCE " + self.operation)
        value = self._reclosure_preflight()
        expected = RequiescenceAssessment(True, (), hashlib.sha256(_encode(value)).hexdigest())
        interrupted = value["phase"] == "recovery-reclosing"
        _require((not interrupted and assessment is None) or
                 (type(assessment) is RequiescenceAssessment and assessment == expected))
        intent, _, journal = self.check(closed=True)
        if value["decision"] == "reconcile":
            request = journal["evidence"]["reclosure_request"]
            shutdown = value["old_shutdown"]
            closure = self._finish_reclosure(request, shutdown)
        else:
            prior = self.record("reclose-prior-" + uuid.uuid4().hex, journal)
            request = self.record("reclose-request-" + uuid.uuid4().hex, dict(schema_version=1,
                kind="native-reclosure-request", operation=self.operation, confirmation=confirmation,
                prior_phase=journal["phase"], prior_last_safe_phase=journal["last_safe_phase"], prior_journal=prior,
                boot=value["boot"], old_shutdown=value["old_shutdown"], capture_anchor_sha256=value["capture_anchor_sha256"],
                manifest=value["manifest"], runtime=value["runtime"], assessment_sha256=expected.binding_sha256,
                profile=self.profile()))
            self.journal.advance("recovery-reclosing", dict(reclosure_request=request, closure=journal["evidence"]["closure"]))
            step = "reclose-" + uuid.uuid4().hex
            self.journal.step_start(step, replay="never", precondition=request)
            try:
                with fence.validation_starts(self.registry, intent, self.profile(), phase="recovery-reclosing"):
                    _require(self.backend.pair_state() == "stopped")
                    marker = self.record("start-" + uuid.uuid4().hex, dict(phase="recovery-reclosing", request=request, boot=value["boot"]))
                    path = self.directory + "/validation-started.json"
                    self.store._put(path, {"attempt": marker}, replace=self.store._present(path))
                    for jail in (self.c.nextcloud_jail, self.c.onlyoffice_jail):
                        self.check(closed=True)
                        _require(_boot(self.backend.output("sysctl", "-n", "kern.boottime")) == value["boot"])
                        from .lifecycle import _require_jail
                        _require_jail(self.d, jail, stopped=True)
                        self.backend.run("bastille", "start", jail)
                    self.backend.owned_live()
                    self.backend.closed_flags()
                    self.backend.wait_writer_closure(database_running=False)
                    runtime = _json(self.store._bound(value["runtime"]))["reclosure_runtime"]
                    _require(self.backend.reclosure_runtime(runtime) == runtime)
                    self.check(closed=True)
                    self.backend.jailed(self.c.nextcloud_jail, "service", "mysql-server", "onestart")
                    ready = self.record("db-ready-" + uuid.uuid4().hex, self.backend.database_ready())
                    self.backend.wait_writer_closure(database_running=True)
                    shutdown = self._stop_database(expected_boot=value["boot"], reclosure=dict(
                        request=request, readiness=ready, capture_anchor_sha256=value["capture_anchor_sha256"]))
                    self.backend.stop_pair()
                closure = self._finish_reclosure(request, shutdown)
                self.journal.step_complete(step, closure)
            except BaseException:
                self.journal.fail("reconciliation-failed")
                raise ValueError(DENIED) from None
        self.journal.advance("recovery-reclosed", dict(reclosure=closure, shutdown=shutdown, closure=closure))
        return dict(state="recovery-reclosed", closure=closure, rollback_started=False, recovered=False)

    def close_for_recovery(self):
        """Fresh clean closure after a controlled migration/validation start.

        Both jails must still be live. An abruptly lost database or partial boot
        has no invented clean-stop proof and requires separate manual assessment.
        """
        self._require_no_cancellation()
        _, _, journal = self.check(closed=True)
        _require(journal["phase"] in ("migrating", "validating", "committed-closed", "recovery-required", "recovery-validating"))
        self.backend.owned_live()
        self.backend.closed_flags()
        if self.backend.running(self.c.nextcloud_jail, "apache24"):
            self.backend.deny_probe()
        self.backend.stop(self.c.nextcloud_jail, "apache24")
        for jail in (self.c.nextcloud_jail, self.c.onlyoffice_jail):
            for service in ("cron", "sshd"):
                self.backend.stop(jail, service)
        self.backend.stop(self.c.nextcloud_jail, "php_fpm")
        for service in ("nginx", "supervisord"):
            self.backend.stop(self.c.onlyoffice_jail, service)
        self.backend.wait_writer_closure(database_running=True)
        self._stop_database()
        self.backend.stop(self.c.nextcloud_jail, "redis")
        self.backend.stop_pair()
        self.backend.storage(self._recovery_context())
        self.check(closed=True)

    def close_for_original_restore(self, confirmation):
        """Stop discardable writers without asserting clean DB shutdown.

        Original clean capture and all 14 current identities precede every stop.
        A half-running pair, unknown writer or failed graceful stop refuses; no
        service is started and no SQL/log-based database health proof is needed.
        """
        self._require_no_cancellation()
        _require(confirmation == f"RESTORE-ORIGINAL {self.operation} DISCARD-CLOSED-CHANGES")
        journal, context, manifest, capture = self._original_restore_evidence()
        _require(self.backend.pair_state() == "running")
        self.backend.owned_live()
        self.backend.closed_flags()
        _require(self.backend.dataset_storage(context) == manifest["datasets"])
        _require(self.backend.snapshots(context, manifest["datasets"], restoring=True) == manifest["snapshots"])
        recovery._restore_journal(context, manifest, self.backend)
        self.check(closed=True)
        request = self.record("restore-original-stop-" + uuid.uuid4().hex, dict(
            binding=context.binding(), confirmation=confirmation, manifest=journal["evidence"]["recovery_set"],
            capture_closure=capture, capture_anchor_sha256=manifest["cold_boundary"], profile=self.profile(),
            journal=self.store.reference(self.journal.path), boot=_boot(self.backend.output("sysctl", "-n", "kern.boottime")),
            restore_basis=recovery.ORIGINAL_CLEAN_SET, clean_database_shutdown=False, office_drained=False))
        if self.backend.running(self.c.nextcloud_jail, "apache24"):
            self.backend.deny_probe()
        self.backend.stop(self.c.nextcloud_jail, "apache24")
        for jail in (self.c.nextcloud_jail, self.c.onlyoffice_jail):
            for service in ("cron", "sshd"):
                self.backend.stop(jail, service)
        self.backend.stop(self.c.nextcloud_jail, "php_fpm")
        for service in ("nginx", "supervisord"):
            self.backend.stop(self.c.onlyoffice_jail, service)
        self.backend.stop(self.c.nextcloud_jail, "mysql-server")
        self.backend.stop(self.c.nextcloud_jail, "redis")
        self.backend.wait_writer_closure(database_running=False)
        self.backend.stop_pair()
        assessment = self.assess_original_restore()
        _require(assessment.eligible)
        return dict(state="stopped", request=request, assessment=assessment,
                    clean_database_shutdown=False, office_drained=False, rollback_started=False)

    def checkpoint(self, phase, member, digest):
        self.check(closed=True)
        self.record("checkpoint-" + uuid.uuid4().hex, dict(phase=phase, member=member, sha256=digest))

    def _original_capture(self, context, journal, manifest):
        """Authenticate the original affirmative capture, never the current DB."""
        initial_ref = self.store.reference(self.directory + "/initial-closure.json")
        initial = _json(self.store._bound(initial_ref))
        _require(initial.get("clean_database_shutdown") is True and initial.get("binding") == context.binding())
        services = self.store.reference(self.directory + "/original-services.json")
        acknowledgement = self.store.reference(self.directory + "/offline-acknowledgement.json")
        _require(initial == dict(binding=context.binding(), clean_database_shutdown=True, profile=self.profile(),
            shutdown=initial["shutdown"], storage=manifest["datasets"], original_services=services, acknowledgement=acknowledgement))
        _require(_json(self.store._bound(services))["pair"] == manifest["original_services"])
        shutdown_ref = initial["shutdown"]
        _require(re.fullmatch(re.escape(self.directory) + r"/clean-shutdown-[a-f0-9]{32}\.json", shutdown_ref["path"]))
        shutdown = _json(self.store._bound(shutdown_ref))
        _require(set(shutdown) == {"observation", "boot", "after_start"} and shutdown["after_start"] is None)
        _boot(shutdown["boot"])  # Historical identity only: never compared with this boot.
        observation = shutdown["observation"]
        _require(type(observation) is dict and set(observation) == {"pid", "device", "inode", "offset", "end", "segment_sha256"})
        _require(all(type(observation[key]) is int and observation[key] >= 0 for key in ("pid", "device", "inode", "offset", "end"))
                 and observation["pid"] > 0 and observation["inode"] > 0 and observation["end"] > observation["offset"]
                 and recovery._hash(observation["segment_sha256"]))
        for name, reference in (("initial-closure", initial_ref), ("capture-clean-shutdown", shutdown_ref)):
            _require(manifest["evidence"][name]["sha256"] == reference["sha256"])
            members = [item for item in context.evidence if item.name == name]
            _require(len(members) == 1 and members[0].sha256 == reference["sha256"]
                     and members[0].path == self.store.root / reference["path"])
        anchor_ref = dict(path=self.directory + "/closure-" + manifest["cold_boundary"] + ".json",
                          sha256=manifest["cold_boundary"])
        anchor = _json(self.store._bound(anchor_ref))
        _require(anchor.get("action") == "capture" and anchor.get("phase") == "quiesced"
                 and anchor.get("clean_database_shutdown") is True and anchor.get("office_drained") is False
                 and anchor.get("binding") == context.binding() and anchor.get("initial_closure") == initial_ref
                 and anchor.get("shutdown") == shutdown_ref and anchor.get("storage") == manifest["datasets"]
                 and anchor.get("profile") == self.profile() and re.fullmatch(r"[a-f0-9]{32}", anchor.get("nonce", "")))
        history = journal["history"]
        _require(any(event["event"] == "step-complete" and event["name"] == "close-writers"
                     and event["phase"] == "capture" and event["step"]["phase"] == "capture"
                     and event["step"]["state"] == "complete" and event["step"]["observation"] == initial_ref
                     and event["step"]["precondition"] == services for event in history))
        _require(any(event["event"] == "transition" and event["phase"] == "quiesced"
                     and event["evidence"].get("closure") == initial_ref and event["evidence"].get("shutdown") == shutdown_ref
                     and event["evidence"].get("offline_acknowledgement") == acknowledgement for event in history))
        _require(any(event["event"] == "transition" and event["phase"] == "recovery-ready"
                     and event["evidence"].get("recovery_set") == journal["evidence"]["recovery_set"]
                     and event["evidence"].get("closure") == initial_ref for event in history))
        return initial_ref

    def _original_restore_evidence(self):
        """Read-only original-capture authentication shared by live/cold closure."""
        self._require_no_cancellation()
        _, _, journal = self.check(closed=True)
        phase = journal["last_safe_phase"] if journal["phase"] == "recovery-required" else journal["phase"]
        _require(phase in ("recovery-ready", "migrating", "awaiting-reboot", "validating", "committed-closed",
                           "recovery-reclosing", "recovery-reclosed", "restoring"))
        _require(not any(event["phase"] in ("opening", "complete", "recovery-opening", "recovered", "restored-closed", "recovery-validating")
                         or event["error"] in ("closure-lost", "publication-uncertain") for event in journal["history"]))
        context = self._recovery_context(readonly=True)
        recovery._context(context)
        reference = journal["evidence"]["recovery_set"]
        _require(reference["path"] == self.directory + "/recovery/manifest.json")
        manifest = recovery.validate_manifest(context, _json(self.store._bound(reference)))
        _require(len(manifest["datasets"]) == len(manifest["snapshots"]) == 14)
        _require(recovery._copies(context) == manifest["evidence"])
        capture = self._original_capture(context, journal, manifest)
        return journal, context, manifest, capture

    def _original_restore_preflight(self):
        """Read-only whole-set assessment, independent of discarded DB health.

        The reviewed installer-owned host has no host application writers. Its
        operation/database locks, persistent boot/profile guards, fully stopped
        jails and canonical mount closure remain the current-writer contract.
        """
        journal, context, manifest, capture = self._original_restore_evidence()
        reference = journal["evidence"]["recovery_set"]
        _require(self.backend.pair_state() == "stopped")
        self.backend.identity(running=False)
        _require(self.backend.storage(context) == manifest["datasets"])
        _require(self.backend.snapshots(context, manifest["datasets"], restoring=True) == manifest["snapshots"])
        recovery._restore_journal(context, manifest, self.backend)
        boot = _boot(self.backend.output("sysctl", "-n", "kern.boottime"))
        self.check(closed=True)
        summary = dict(binding=context.binding(), journal=self.store.reference(self.journal.path), boot=boot,
                       manifest=reference, capture_closure=capture, capture_anchor_sha256=manifest["cold_boundary"],
                       profile=self.profile())
        return summary, context, manifest

    def assess_original_restore(self):
        """Read-only eligibility for discarding closed changes to restore all 14."""
        try:
            summary, _, _ = self._original_restore_preflight()
            return OriginalRestoreAssessment(True, (), hashlib.sha256(_encode(summary)).hexdigest())
        except Exception:
            return OriginalRestoreAssessment(False, ("Original clean-set restore assessment failed; retain private evidence and the stopped pair",))

    def _original_restore_boundary(self, context):
        consent = getattr(self, "_original_restore_consent", None)
        _require(type(consent) is recovery.OriginalRestoreConsent and context.original_restore == consent)
        summary, current, manifest = self._original_restore_preflight()
        _require(context.binding() == current.binding())
        recovery._original_restore_consent(context)
        approved = recovery._load(consent.current_closure.path)
        _require(approved["boot"] == summary["boot"] and consent.manifest_sha256 == recovery._json_hash(manifest)
                 and consent.capture_anchor_sha256 == summary["capture_anchor_sha256"]
                 and consent.capture_closure.sha256 == summary["capture_closure"]["sha256"])
        _, _, journal = self.check(closed=True)
        observation = self.record("discardable-observation-" + uuid.uuid4().hex, dict(**summary,
            restore_basis=recovery.ORIGINAL_CLEAN_SET, clean_database_shutdown=False, office_drained=False,
            consent=dict(path=str(consent.path), sha256=consent.sha256), nonce=uuid.uuid4().hex))
        return recovery.ColdBoundary(context.binding(), journal["phase"], observation["sha256"],
            tuple(sorted(manifest["original_services"].items())), False, False, True, True, True, True, False, False,
            recovery.OPERATOR_OFFLINE, context.offline_acknowledgement.sha256, manifest["cold_boundary"],
            recovery.ORIGINAL_CLEAN_SET, consent.capture_closure.sha256, consent.sha256)

    def restore_original(self, confirmation, *, assessment=None):
        """Explicitly discard closed target changes; never start or repair its DB."""
        self._require_no_cancellation()
        _require(confirmation == f"RESTORE-ORIGINAL {self.operation} DISCARD-CLOSED-CHANGES")
        _require(getattr(self, "_original_restore_consent", None) is None)
        summary, context, manifest = self._original_restore_preflight()
        expected = OriginalRestoreAssessment(True, (), hashlib.sha256(_encode(summary)).hexdigest())
        _require(type(assessment) is OriginalRestoreAssessment and assessment == expected)
        current_ref = self.record("discardable-closure-" + uuid.uuid4().hex, dict(**summary,
            restore_basis=recovery.ORIGINAL_CLEAN_SET, clean_database_shutdown=False, office_drained=False, nonce=uuid.uuid4().hex))
        capture = recovery.Evidence("initial-closure", "metadata", self.store.root / summary["capture_closure"]["path"],
                                    summary["capture_closure"]["sha256"])
        current = recovery.Evidence("discardable-closure", "metadata", self.store.root / current_ref["path"], current_ref["sha256"])
        consent_ref = self.record("restore-original-consent-" + uuid.uuid4().hex,
            recovery.original_restore_record(context, recovery._json_hash(manifest), manifest["cold_boundary"], capture, current))
        consent = recovery.OriginalRestoreConsent(self.store.root / consent_ref["path"], consent_ref["sha256"],
            recovery._json_hash(manifest), manifest["cold_boundary"], capture, current)
        recovery._original_restore_consent(replace(context, original_restore=consent))
        self._original_restore_consent = consent
        try:
            # Re-enter restoring with a fresh explicit consent after interruption;
            # the pinned member journal/assessment still governs every rollback.
            if self.journal.read()["phase"] == "restoring":
                self.journal.fail("interrupted")
            return self.recover()
        finally:
            self._original_restore_consent = None

    def capture(self):
        self._require_no_cancellation()
        _, _, journal = self.check(closed=True)
        _require(journal["phase"] in ("quiesced", "recovery-ready"))
        context = self._recovery_context()
        recovery.capture(context, self.backend)
        reference = self.store.reference(self.directory + "/recovery/manifest.json")
        if journal["phase"] == "quiesced":
            self.journal.advance("recovery-ready", dict(recovery_set=reference, closure=journal["evidence"]["closure"]))
        return dict(state="recovery-ready", manifest=reference, independent_copy_verified=False,
                    machine_drain_verified=False, unsaved_editor_work_covered=False, recovered=False)

    def _start_closed(self, phase):
        """Caller holds validation_starts for the current exact journal hash."""
        _require(phase in ("migrating", "validating", "recovery-validating"))
        state = self.backend.pair_state()
        path = self.directory + "/validation-started.json"
        _require(state == "stopped" or self.store._present(path))
        self.backend.identity(running=state == "running")
        reference = self.record("start-" + uuid.uuid4().hex, dict(profile=self.profile(), phase=phase, prior_state=state))
        self.store._put(path, {"attempt": reference}, replace=self.store._present(path))
        if state == "stopped":
            for jail in (self.c.nextcloud_jail, self.c.onlyoffice_jail):
                from .lifecycle import _require_jail
                _require_jail(self.d, jail, stopped=True)
                self.backend.run("bastille", "start", jail)
        self.backend.owned_live()
        self.backend.closed_flags()
        # Migration adapters may temporarily make code writable. Only their
        # bounded CLI worker may execute it: do not start FPM/HTTP/editor workers
        # until the separate validating phase.
        services_by_role = ((self.c.nextcloud_jail, ("mysql-server", "redis", "php_fpm", "apache24")),
                            (self.c.onlyoffice_jail, ("supervisord", "nginx")))
        if phase == "migrating":
            services_by_role = ((self.c.nextcloud_jail, ("mysql-server", "redis")),
                                (self.c.onlyoffice_jail, ()))
            self.backend.wait_writer_closure(database_running=True)
        for jail, services in services_by_role:
            for service in services:
                self.check(closed=True)
                if not self.backend.running(jail, service):
                    self.backend.jailed(jail, "service", service, "onestart")
                _require(self.backend.running(jail, service))
            _require(not self.backend.running(jail, "cron") and not self.backend.running(jail, "sshd"))
        if phase == "migrating":
            self.backend.wait_writer_closure(database_running=True)
        else:
            self.backend.deny_probe()

    def migrate(self, adapter):
        """Only an explicitly supplied reviewed adapter; snapshots precede effects.

        This is the harness integration seam for nextcloud_update.Authority, not
        a shipped update recipe. Failed/ambiguous callbacks cannot be replayed.
        """
        self._require_no_cancellation()
        _require(isinstance(adapter, MigrationAdapter))
        intent, inputs, journal = self.check(closed=True)
        _require(journal["phase"] == "recovery-ready" and adapter.descriptor() == inputs["recipe"])
        self.capture()  # Revalidate complete 14-member identities/private copies.
        manifest = journal["evidence"]["recovery_set"]
        self.store._bound(manifest)
        self.journal.advance("migrating", dict(recipe=self.store.reference(self.directory + "/native-inputs.json"),
                                              closure=journal["evidence"]["closure"]))
        self.journal.step_start("reviewed-migration", replay="never", precondition=manifest)
        try:
            # All journal writes precede this exact-hash permission context.
            with fence.validation_starts(self.registry, intent, self.profile(), phase="migrating"):
                self._start_closed("migrating")
                self.check(closed=True)
                evidence = adapter.execute(self)
                self.store._bound(evidence)
            self.journal.step_complete("reviewed-migration", evidence)
            return dict(state="migrating", observation=evidence, ready=False, publication_required=True)
        except Exception:
            self.journal.fail("migration-failed")
            raise ValueError(DENIED) from None

    def assess(self):
        try:
            self._require_no_cancellation()
        except ValueError:
            return recovery.RestoreAssessment(False, ("Cancellation forbids restoration",))
        _, _, journal = self.check(closed=True)
        phase = journal["last_safe_phase"] if journal["phase"] == "recovery-required" else journal["phase"]
        original = getattr(self, "_original_restore_consent", None) is not None
        if phase == "recovery-reclosing" and not original:
            try:
                _, _, manifest = self._completed_reclosure(journal)
                return recovery.RestoreAssessment(True, (), recovery._json_hash(manifest))
            except Exception:
                return recovery.RestoreAssessment(False, ("Re-quiescence lacks a freshly verified complete closure receipt",))
        allowed = {"recovery-ready", "migrating", "validating", "restoring", "committed-closed", "recovery-reclosed"}
        if original:
            allowed |= {"awaiting-reboot", "recovery-reclosing"}
        if phase not in allowed:
            return recovery.RestoreAssessment(False, ("Operation phase forbids rollback",))
        context = self._recovery_context()
        if journal["phase"] in ("recovery-required", "restoring"):
            return recovery.assess_restore(context, self.backend)
        # The recovery primitive requires an already-recorded restoring phase.
        # Before that transition, perform its same non-mutating topology/copy
        # checks under our actual current phase, without inventing a phase proof.
        try:
            recovery._context(context)
            proof = self.cold_boundary(context, "restore")
            value = recovery.validate_manifest(context, recovery._load(context.directory / "manifest.json"))
            _require(proof.capture_anchor_sha256 == value["cold_boundary"]
                     and proof.evidence_sha256 != value["cold_boundary"]
                     and dict(proof.original_services) == value["original_services"])
            _require(recovery._copies(context) == value["evidence"])
            _require(self.backend.storage(context) == value["datasets"])
            _require(self.backend.snapshots(context, value["datasets"], restoring=True) == value["snapshots"])
            recovery._restore_journal(context, value, self.backend)
            return recovery.RestoreAssessment(True, (), recovery._json_hash(value))
        except (ValueError, OSError, KeyError, TypeError):
            return recovery.RestoreAssessment(False, ("Fresh closed-set recovery assessment failed",))

    def recover(self):
        """Dataset recovery only. Never repeat rollback after canary writes."""
        self._require_no_cancellation()
        _, _, journal = self.check(closed=True)
        phase = journal["last_safe_phase"] if journal["phase"] == "recovery-required" else journal["phase"]
        consent = getattr(self, "_original_restore_consent", None)
        if phase == "recovery-reclosing" and consent is None:
            # Explicit RESTORE may seal an already completed closure checkpoint;
            # it cannot start/retry a database or manufacture completion evidence.
            reference, receipt, _ = self._completed_reclosure(journal)
            self.journal.advance("recovery-reclosed", dict(reclosure=reference, shutdown=receipt["shutdown"], closure=reference))
            journal = self.journal.read()
            phase = journal["phase"]
        if phase in ("restored-closed", "recovery-validating"):
            return dict(state=phase, recovered=False, rollback_repeated=False)
        allowed = {"recovery-ready", "migrating", "validating", "restoring", "committed-closed", "recovery-reclosed"}
        if consent is not None:
            allowed |= {"awaiting-reboot", "recovery-reclosing"}
        _require(phase in allowed)
        assessment = self.assess()
        _require(assessment.eligible)
        if journal["phase"] != "restoring":
            reference = journal["evidence"]["restore_assessment"] if phase == "restoring" else self.record("restore-assessment", {
                "manifest": journal["evidence"]["recovery_set"], "manifest_sha256": assessment.manifest_sha256,
                "scope": "verified-cold-set-nonrecursive-rollback"})
            evidence = dict(restore_assessment=reference, closure=journal["evidence"]["closure"])
            if consent is not None:
                evidence.update(original_restore_consent=dict(path=str(consent.path.relative_to(self.store.root)), sha256=consent.sha256),
                                closure=dict(path=str(consent.current_closure.path.relative_to(self.store.root)), sha256=consent.current_closure.sha256))
            self.journal.advance("restoring", evidence)
        context = self._recovery_context()
        assessment = recovery.assess_restore(context, self.backend)
        _require(assessment.eligible)
        result = recovery.restore(context, self.backend)
        reference = self.record("restored-set", result)
        self.journal.supersede_steps(reference)
        fence.install_profile(self.registry, self.profile())
        self.check(closed=True)
        self.journal.advance("restored-closed", dict(restored_set=reference,
            closure=self.record("restored-closure", {"profile": self.profile(), "restored_set": reference})))
        return result

    def validate_closed(self, *, expected_version, integration=None):
        """Manual service starts under the temporary exact-phase boot permission.

        Integration must perform secret-based cache/connector tests through the
        caller's phase-specific stdin channel. Its absence blocks full readiness.
        No API here restores normal rc flags, cron, SSH, or public ingress.
        """
        self._require_no_cancellation()
        intent, _, journal = self.check(closed=True)
        _require(expected_version in ("35.0.1.1", "35.0.2.2"))
        phase = journal["phase"]
        if phase == "restored-closed":
            self.journal.advance("recovery-validating", dict(restored_set=journal["evidence"]["restored_set"],
                closure=journal["evidence"]["closure"], validation_permission=self.profile()))
            phase = "recovery-validating"
        _require(phase in ("validating", "recovery-validating"))
        _require(phase != "recovery-validating" or expected_version == "35.0.1.1")
        fingerprint = False
        if phase == "recovery-validating":
            current = self.journal.read()
            step = current["steps"].get("data-fingerprint")
            _require(step is None or step["state"] == "complete")
            if step is None:
                self.journal.step_start("data-fingerprint", replay="never", precondition=current["evidence"]["restored_set"])
                fingerprint = True
        # Mark before the first start: crash cannot reuse the historical DB proof.
        with fence.validation_starts(self.registry, intent, self.profile(), phase=phase):
            self._start_closed(phase)
            self.backend.loopback_probe()
            status = json.loads(self.backend.occ("status", "--output=json"))
            _require(status.get("installed") is True and status.get("maintenance") is True
                     and status.get("needsDbUpgrade") is False and status.get("version") == expected_version)
            if fingerprint:
                self.backend.occ("maintenance:data-fingerprint")
            if integration is not None:
                _require(callable(integration))
                proof = integration(self)
                _require(type(proof) is dict and set(proof) == {"cache", "connector"})
                for ref in proof.values():
                    self.store._bound(ref)
            self.check(closed=True)
        if fingerprint:
            self.journal.step_complete("data-fingerprint", self.record("fingerprint-observed", dict(
                command="maintenance:data-fingerprint", version=expected_version, closed=True)))
        return dict(state=phase, closed_status_verified=True, integration_verified=integration is not None,
                    ready=False, recovered=False, publication_required=True)


@contextmanager
def acceptance_session(registry, runner, *, harness, preparation=None, operation=None, candidate=None):
    """Explicit trusted harness only; normal CLI must call production_admission.

    Starts a separate execution intent, preserving the inert preparation. Resume
    requires its exact original executor/recipe and never resumes publication.
    """
    _require(isinstance(harness, AcceptanceHarness))
    from .maintenance_admission import SourceAdmission
    from . import maintenance_candidate as candidates
    source_admission = type(harness) is SourceAdmission
    _require(source_admission or candidate is None)
    # Profile mutation/start permission requires the lock's explicit recovery
    # authorization even on a new harness capture. A new operation still checks
    # the ordinary idle entry guard before inspecting/admitting its source.
    with registry.locked(recovery=True):
        native = NativeState(registry, executor_record())
        if operation is None:
            from .maintenance import entry_guard
            entry_guard("mutation", registry=registry)
            from .maintenance_operations import load_operation, _artifact_bindings
            from .maintenance_staging import verify_stage
            _require(preparation is not None)
            parent = _json(native.store._bound(preparation))
            parent, plan, staged = load_operation(registry, parent["operation"])
            staged_record = staged.read()
            _require(staged_record["phase"] == "staged")
            verify_stage(registry.root, parent["operation"], plan["artifacts"], staged_record["evidence"]["artifacts"],
                         **_artifact_bindings(registry, parent, plan))
            deployment = _deployment(registry, parent["instance"], runner)
        else:
            _, inputs = native.read(operation)
            _require(inputs["recipe"] == harness.descriptor())
            if source_admission:
                reference = _json(native.store._read(f"maintenance/operations/{operation}/candidate-reference.json"))
                native.store._bound(reference)
                retained = candidates.load(native.store, inputs["cache_owner"])
                _require(retained.reference == reference)
                if candidate is not None:
                    _require(type(candidate) is candidates.CapturedCandidate and candidate.operation == retained.operation
                             and candidate.reference == retained.reference)
            deployment = _deployment(native.view(operation), inputs["instance"], runner)
        from .operations import _database_guard
        with _database_guard(deployment):
            if operation is None:
                deployment.require_original_artifact()
                backend = NativeBackend(deployment)
                backend.owned_live()
                if source_admission:
                    _require(type(candidate) is candidates.CapturedCandidate and candidate.operation == parent["operation"])
                    checked = candidates.revalidate_for_execution(candidate, deployment, source_admission=harness)
                    _require(type(checked) is candidates.RevalidatedCandidate and checked.reference == candidate.reference)
                    admission = checked.admission
                    native.store._bound(checked.reference)
                else:
                    admission = harness.admit_source(deployment)
                _require(type(admission) is dict and set(admission) == {"startup", "evidence"})
                native.store._bound(admission["evidence"])
                actual = {jail: fence.startup_inventory(deployment.jail_root(jail),
                          nextcloud=jail == deployment.config.nextcloud_jail)
                          for jail in (deployment.config.nextcloud_jail, deployment.config.onlyoffice_jail)}
                _require(admission["startup"] == actual)
                # Admit installed code before executing its PHP/occ helpers.
                observations = backend.source_observations()
                initial_records = {"admission.json": admission, "source-observations.json": observations}
                if source_admission:
                    initial_records["candidate-reference.json"] = checked.reference
                    candidates.require_execution_freshness(native.store, checked)
                operation = "execution-" + uuid.uuid4().hex
                native.begin(operation, deployment.config.instance, preparation=preparation, recipe=harness.descriptor(),
                             initial_records=initial_records)
                deployment = _deployment(native.view(operation), deployment.config.instance, runner)
            else:
                admission = _json(native.store._read(f"maintenance/operations/{operation}/admission.json"))
                native.store._bound(admission["evidence"])
            context = NativeContext(registry, native, operation, deployment, admission)
            context.active = True
            try:
                context.check()
                yield context
            finally:
                context.active = False
