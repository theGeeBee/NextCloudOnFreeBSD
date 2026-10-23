"""Live, non-enrolled native upgrade transport and read-only inspection.

The entrypoint owns host/platform checks, consent and operation/database locks.
This module neither enrolls an instance nor reads its installation secrets or
version locks. Registry configuration supplies resource identity hints only.
"""

import json
from pathlib import Path
import re
import stat
import subprocess
from urllib.parse import urlsplit, urlunsplit

from . import bounded_process


APP = "/usr/local/www/nextcloud"
OUTPUT_LIMIT = 16 * 1024 * 1024
PKG = ("/usr/local/sbin/pkg", "-o", "PKG_ENABLE_PLUGINS=false")


class UpgradeRunner:
    """Private, bounded production transport for the optional upgrade path.

    The shared transport caps stdout/stderr while draining, owns and reaps its
    process group on timeout/cancellation, and never inherits the environment.
    stdout/stderr are returned privately with a combined byte ceiling.
    ``capture``/``hide_output`` are accepted for Runner compatibility, but output
    is always private. Tests can still inject their own runner into LiveTarget.
    """

    def run(self, *args, capture=True, check=True, timeout=120, input=None, hide_output=False):
        try:
            if (not args or any(type(arg) is not str or not arg or "\0" in arg for arg in args)
                    or type(timeout) not in (int, float) or not 0 < timeout <= 3600):
                raise ValueError
            if input is None:
                stdin = b""
            elif isinstance(input, str):
                stdin = input.encode("utf-8")
            elif isinstance(input, bytes):
                stdin = input
            else:
                raise ValueError
            argv = args
            if not args[0].startswith("/"):
                # env performs native PATH lookup, not shell parsing. The PATH
                # comes exclusively from the fixed environment below; never use
                # workstation shutil.which or a caller's inherited search path.
                if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_+.-]*", args[0]):
                    raise ValueError
                argv = ("/usr/bin/env", *args)
            result = bounded_process.run(argv, stdin=stdin, env=dict(bounded_process.ENV),
                                         timeout=timeout, output_limit=OUTPUT_LIMIT, capture_stderr=True)
            if (not isinstance(result.stdout, bytes) or not isinstance(result.stderr, bytes)
                    or len(result.stdout) + len(result.stderr) > OUTPUT_LIMIT):
                raise ValueError
            stdout = result.stdout.decode("utf-8")
            stderr = result.stderr.decode("utf-8")
            if check and result.returncode:
                raise RuntimeError
        except Exception:
            raise RuntimeError("Native upgrade command failed; output suppressed") from None
        return subprocess.CompletedProcess(args, result.returncode, stdout, stderr)

    def output(self, *args):
        return self.run(*args).stdout.strip()


def _object(text):
    try:
        value = json.loads(text)
    except (ValueError, TypeError):
        raise ValueError("Native command returned invalid JSON") from None
    if not isinstance(value, dict):
        raise ValueError("Native command did not return a JSON object")
    return value


def _stable(value, *, internal=False):
    pattern = r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    if internal:
        pattern += r"(?:\.(0|[1-9][0-9]*))?"
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        raise ValueError("A stable application version is required")
    return ".".join(value.split(".")[:3])


def _status(text):
    value = _object(text)
    version = _stable(value.get("version"), internal=True)
    if "versionstring" in value and _stable(value["versionstring"]) != version:
        raise ValueError("Nextcloud public and internal versions disagree")
    if (value.get("installed") is not True or value.get("maintenance") is not False
            or value.get("needsDbUpgrade") is not False):
        raise ValueError("Nextcloud must be installed, outside maintenance and without a pending database upgrade")
    # Never return arbitrary application output in public reports.
    return dict(version=version, internal_version=value["version"], installed=True,
                maintenance=False, needsDbUpgrade=False,
                status=dict(version=value["version"], installed=True,
                            maintenance=False, needsDbUpgrade=False))


def _directories(path, owners=(0,)):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("An absolute native resource path is required")
    for part in (*reversed(path.parents), path):
        info = part.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in owners
                or info.st_mode & 0o022):
            raise ValueError("Unsafe native resource directory")
    return path


def _https_url(value):
    try:
        parsed = urlsplit(value)
        valid = (parsed.scheme == "https" and parsed.hostname and not parsed.username
                 and not parsed.password and not parsed.query and not parsed.fragment
                 and (parsed.port is None or 0 < parsed.port < 65536)
                 and not any(ord(c) <= 32 or ord(c) == 127 for c in value))
    except (ValueError, TypeError):
        valid = False
    if not valid:
        raise ValueError("Live integration requires a credential-free HTTPS URL")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/") + "/", "", ""))


class LiveTarget:
    """Checked transport for one installer-created, ready, unenrolled pair.

    ``run_jail`` is also used by consented mutation adapters. It rechecks registry
    eligibility on every call; callers must hold their operation-specific locks.
    ``inspect`` and ``verify`` run observations only. Neither accepts maintenance
    mode: the migration adapter must handle its own explicitly closed interval.
    """

    def __init__(self, registry, runner, instance):
        self.registry, self.runner = registry, runner
        self.instance = instance
        self._eligible()
        self.config = registry.load(instance)
        from .config import require_native_backend
        require_native_backend(self.config, "Native upgrade/restore/verification")
        self.state = registry.instance_path(instance)
        self.nc, self.office = self.config.nextcloud_jail, self.config.onlyoffice_jail
        self.nc_root = Path(self.config.bastille_root) / "jails" / self.nc / "root"
        self.office_root = Path(self.config.bastille_root) / "jails" / self.office / "root"
        if self.nc == self.office or self.nc_root == self.office_root:
            raise ValueError("Two separate jail identities are required")

    def _eligible(self):
        # Check before Registry.load/status can resolve an enrolled generation.
        if self.registry.lifecycle_enabled():
            raise ValueError("Native upgrade requires an unenrolled instance; enrolled systems need a reviewed transition")
        if self.registry.status(self.instance).get("state") != "ready":
            raise ValueError("Native upgrade requires a ready installer-created instance")

    def _run(self, *argv, input=None, timeout=120, check=True):
        if (type(timeout) not in (int, float) or not 0 < timeout <= 3600
                or not argv or any(not isinstance(arg, str) or "\0" in arg for arg in argv)):
            raise ValueError("Invalid bounded native command")
        try:
            result = self.runner.run(*argv, input=input, timeout=timeout, check=False,
                                     capture=True, hide_output=True)
        except Exception:
            # Third-party/fake runners may include argv, stdin or output in any
            # exception. No diagnostics from private application commands escape.
            raise RuntimeError("Native command could not complete; output suppressed") from None
        if (not isinstance(result.stdout, str) or not isinstance(result.stderr, str)
                or len(result.stdout) + len(result.stderr) > OUTPUT_LIMIT):
            raise RuntimeError("Native command returned invalid or excessive output")
        if check and result.returncode:
            raise RuntimeError("Native command failed; output suppressed")
        return subprocess.CompletedProcess(argv, result.returncode, result.stdout, result.stderr)

    def _identity(self, jail):
        if jail not in (self.nc, self.office):
            raise ValueError("Refusing to execute in an unrelated jail")
        root = self.nc_root if jail == self.nc else self.office_root
        _directories(root)
        configured = self._run("bastille", "config", jail, "get", "path").stdout.strip()
        result = self._run("jls", "-j", jail, "jid", "name", "path", check=False)
        row = result.stdout.split()
        if (configured != str(root) or result.returncode or len(row) != 3
                or not re.fullmatch(r"[1-9][0-9]*", row[0])
                or row[1:] != [jail, str(root)]):
            raise RuntimeError("Jail is stopped or its configured/live identity differs")
        return int(row[0])

    def require_running_jail(self, jail):
        """Return a checked numeric JID, also usable by bounded SQL streamers."""
        self._eligible()
        return self._identity(jail)

    def run_jail(self, jail, *argv, input=None, timeout=120, check=True):
        jid = self.require_running_jail(jail)
        try:
            return self._run("jexec", str(jid), *argv, input=input, timeout=timeout, check=check)
        finally:
            # Also executes for failed commands, timeouts and interruption.
            if self.require_running_jail(jail) != jid:
                raise RuntimeError("Jail restarted during native command execution") from None

    def _account(self):
        uid = self.run_jail(self.nc, "/usr/bin/id", "-u", "www").stdout.strip()
        gid = self.run_jail(self.nc, "/usr/bin/id", "-g", "www").stdout.strip()
        if not re.fullmatch(r"[1-9][0-9]*", uid) or not re.fullmatch(r"[1-9][0-9]*", gid):
            raise ValueError("A non-root www account is required")
        app = self.nc_root / APP.lstrip("/")
        _directories(app.parent)
        # The supported updater temporarily owns its application directory as
        # www. Its parents must remain root-owned; occ itself runs only as www.
        info = app.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, int(uid))
                or info.st_mode & 0o022):
            raise ValueError("Unsafe Nextcloud application directory")
        config = app / "config"
        info = config.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != int(uid) or info.st_mode & 0o022):
            raise ValueError("Unsafe Nextcloud configuration directory")
        info = (config / "config.php").lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != int(uid) or info.st_mode & 0o027):
            raise ValueError("Unsafe Nextcloud configuration file")
        return dict(uid=int(uid), gid=int(gid))

    def occ(self, *argv, check=True, timeout=120):
        self._account()
        # The shell program is constant: dynamic arguments remain positional.
        return self.run_jail(self.nc, "mdo", "-u", "www", "/bin/sh", "-c",
            'cd /usr/local/www/nextcloud && exec "$@"', "nextcloud-occ",
            "/usr/local/bin/php", "-d", "display_errors=0", "-d", "log_errors=0",
            "-d", "zend.exception_ignore_args=1", APP + "/occ", "--no-interaction",
            *argv, check=check, timeout=timeout)

    def private_config(self):
        """Return actual private configuration in memory only; never report it."""
        value = _object(self.occ("config:list", "--private", "--output=json").stdout)
        if not isinstance(value.get("system"), dict) or not isinstance(value.get("apps"), dict):
            raise ValueError("Nextcloud private configuration has an invalid structure")
        return value

    def inspect(self):
        self._eligible()
        identities = {jail: dict(jid=self._identity(jail), root=str(root))
                      for jail, root in ((self.nc, self.nc_root), (self.office, self.office_root))}
        if len({item["jid"] for item in identities.values()}) != 2:
            raise ValueError("Jail pair has ambiguous numeric identities")
        status = _status(self.occ("status", "--output=json").stdout)
        package = self.run_jail(self.office, *PKG, "query", "%n|%v|%o", "onlyoffice-documentserver").stdout.strip().split("|")
        if (len(package) != 3 or package[0] != "onlyoffice-documentserver"
                or package[2] != "www/onlyoffice-documentserver"
                or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:_[0-9]+)?(?:,[0-9]+)?", package[1])):
            raise ValueError("Unsupported native Document Server package identity")
        upstream = _stable(re.split(r"[_,]", package[1])[0])
        php = _stable(self.run_jail(self.nc, "/usr/local/bin/php", "-r", "echo PHP_VERSION;").stdout.strip())
        fpm = self.run_jail(self.nc, "/usr/local/sbin/php-fpm", "-v").stdout
        match = re.match(r"PHP ([0-9]+\.[0-9]+\.[0-9]+) \(fpm-fcgi\)", fpm)
        if not match or match[1] != php:
            raise ValueError("PHP CLI and FPM versions do not match")
        self.run_jail(self.nc, "/usr/local/sbin/php-fpm", "-t")
        database = self.run_jail(self.nc, "/usr/local/bin/mariadb", "--no-defaults", "--protocol=socket",
            "--socket=/var/run/mysql/mysql.sock", "--user=root", "--batch", "--skip-column-names",
            "--execute", "SELECT VERSION()").stdout.strip()
        match = re.fullmatch(r"([0-9]+\.[0-9]+\.[0-9]+)-MariaDB(?:-[A-Za-z0-9.+_~-]+)?", database)
        if not match:
            raise ValueError("Unsupported live database version")
        release = self._run("freebsd-version", "-u").stdout.strip()
        abi = self._run(*PKG, "config", "ABI").stdout.strip()
        if (not re.fullmatch(r"[0-9]+\.[0-9]+-RELEASE(?:-p[0-9]+)?", release)
                or not re.fullmatch(r"FreeBSD:[0-9]+:[a-z0-9]+", abi)):
            raise ValueError("Invalid native host release or ABI observation")
        for jail, identity in identities.items():
            if self._identity(jail) != identity["jid"]:
                raise RuntimeError("Jail identity changed during live inspection")
        return dict(nextcloud=status,
                    office=dict(package=package[0], package_name=package[0], version=package[1], upstream=upstream),
                    php=dict(version=php, fpm_version=php, fpm_config_valid=True),
                    database=dict(version=match[1], server_version=database, engine="mariadb"),
                    hostrelease=release, ABI=abi, identities=identities)

    def verify(self, expected_nextcloud=None):
        """Verify current services/integration, preserving manually changed settings."""
        report = self.inspect()
        if expected_nextcloud is not None and report["nextcloud"]["version"] != _stable(expected_nextcloud):
            raise ValueError("Nextcloud does not match the requested upgrade target")
        for jail, services in ((self.nc, ("mysql-server", "redis", "php_fpm", "apache24", "cron")),
                               (self.office, ("supervisord", "nginx"))):
            for service in services:
                self.run_jail(jail, "service", service, "onestatus")
        if self.config.antivirus:
            for service in ("clamav_clamd", "clamav_freshclam"):
                self.run_jail(self.nc, "service", service, "onestatus")
        self.run_jail(self.nc, "/usr/local/sbin/apachectl", "configtest")
        self.run_jail(self.office, "/usr/local/sbin/nginx", "-t")
        processes = self.run_jail(self.office, "/usr/local/bin/supervisorctl", "status", "ds:docservice", "ds:metrics").stdout
        if any(not re.search(rf"(?m)^{name}\s+RUNNING\b", processes) for name in ("ds:docservice", "ds:metrics")):
            raise RuntimeError("Native Document Server processes are not running")
        actual = self.private_config()
        public_url = _https_url(actual["system"].get("overwrite.cli.url"))
        office_config = actual["apps"].get("onlyoffice", {})
        if not isinstance(office_config, dict):
            raise ValueError("Invalid live Document Server connector configuration")
        office_url = _https_url(office_config.get("DocumentServerUrl"))
        # curl uses its normal trust store. Custom CA configuration remains native;
        # do not substitute a stale installer runtime.json or disable TLS checks.
        curl = ("/usr/local/bin/curl", "--silent", "--show-error", "--fail", "--noproxy", "*", "--max-time", "30")
        status = _status(self.run_jail(self.nc, *curl, public_url + "status.php", timeout=40).stdout)
        if status != report["nextcloud"]:
            raise RuntimeError("HTTP and CLI Nextcloud status differ")
        health = self.run_jail(self.nc, *curl, office_url + "healthcheck", timeout=40).stdout.strip()
        if health != "true":
            raise RuntimeError("Document Server health check failed")
        self.occ("onlyoffice:documentserver", "--check", timeout=120)
        report["verification"] = dict(services=True, configuration=True, https=True,
                                      office_health=True, connector=True)
        return report
