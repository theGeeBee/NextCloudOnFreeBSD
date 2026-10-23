"""Host-side operations used by the install.sh menu, never standalone CLIs.

The caller holds the installer-wide operation lock and has checked the host.
Database operations also take an instance lock. Database streams deliberately
use jexec with a checked numeric JID: Bastille's console headers must not enter
SQL, and Runner.run's captured output must never buffer a database in memory.
"""

from contextlib import contextmanager, ExitStack
from datetime import datetime, timezone
import base64
import fcntl
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import stat
import subprocess
import tarfile
import tempfile
import time

from .state import atomic_json, config_digest, private_json

BACKUP_ROOT = Path("/var/db/cloud-installer/backups")
ROOT_UID = 0
APP = "/usr/local/www/nextcloud"
HELPER = "/usr/local/libexec/cloud-nextcloud-maintenance.php"
CHUNK = 256 * 1024
CONFIG_LIMIT = 16 * 1024 * 1024
CONFIG_FILES = 256
STREAM_TIMEOUT = 3600
SERVICES = ("cron", "apache24", "php_fpm")
DB_OPTIONS = ("--no-defaults", "--protocol=socket", "--socket=/var/run/mysql/mysql.sock", "-uroot")
PACKAGE_FILES = {"database.sql.gz", "nextcloud-config.tar.gz"}
BACKUP_WARNING = ("Database/config backup only: includes every user's database records, contacts and calendars, "
                  "but no user files, encryption-key files in the data directory, custom apps or themes. "
                  "A coherent full recovery also needs matching application and data backups.")


def _absolute(path):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("Use an absolute path without parent traversal")
    return path


def _directories(path, *, owners=None):
    """Reject symlinks in every path component, including intermediate ones."""
    path = _absolute(path)
    owners = {0, ROOT_UID} if owners is None else owners
    for part in (*reversed(path.parents), path):
        info = part.lstat()
        sticky_root = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in owners
                or (info.st_mode & 0o022 and not sticky_root)):
            raise ValueError(f"Unsafe directory: {part}")
    return path


def _private_directory(path, *, create=False):
    path = _absolute(path)
    if create and not path.exists() and not path.is_symlink():
        if not path.parent.exists():
            _private_directory(path.parent, create=True)
        else:
            _directories(path.parent)
        path.mkdir(mode=0o700)
    _directories(path)
    info = path.lstat()
    if info.st_uid != ROOT_UID or info.st_mode & 0o077:
        raise ValueError(f"Directory must be root-owned and private: {path}")
    return path


def _file(path, *, owners=None, private=True):
    """Open once, without following links; validate the descriptor we actually use."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid not in (owners if owners is not None else {ROOT_UID})
                or info.st_mode & (0o077 if private else 0o022)):
            raise ValueError(f"Unsafe regular file: {path}")
        stream = os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise
    return stream


@contextmanager
def _new_file(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        yield stream
        stream.flush()
        os.fsync(stream.fileno())


def _sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextmanager
def _database_guard(deployment):
    if os.geteuid() != ROOT_UID:
        raise ValueError("Database operations require host root")
    state = _private_directory(deployment.state)
    fd = os.open(state / "database-operation.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID or info.st_mode & 0o077 or info.st_nlink != 1:
            raise ValueError("Unsafe database operation lock")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Another database operation is already running") from None
        yield
    finally:
        os.close(fd)


def _restore_journal(deployment):
    path = _private_directory(deployment.state) / "restore.json"
    if not path.exists() and not path.is_symlink():
        return None
    with _file(path) as stream:
        if os.fstat(stream.fileno()).st_size > 2 * 1024 * 1024:
            raise ValueError("Restore journal exceeds its size limit")
    record = private_json(path)
    # A phase-less legacy record might already have restarted writers; refuse it.
    if (not isinstance(record, dict) or record.get("schema_version") != 1
            or record.get("state") not in ("pending", "complete")
            or record.get("phase") not in ("importing", "validated")
            or (record.get("state") == "complete" and record.get("phase") != "validated")
            or record.get("instance") != deployment.config.instance
            or not isinstance(record.get("metadata"), dict)
            or not isinstance(record.get("code_sha256"), dict) or not record["code_sha256"]
            or not isinstance(record.get("started"), str)):
        raise ValueError("Invalid restore journal; retain it for host-root recovery")
    for key in ("config_sha256", "source_manifest_sha256", "prebackup_manifest_sha256"):
        if not isinstance(record.get(key), str) or not re.fullmatch(r"[a-f0-9]{64}", record[key]):
            raise ValueError("Invalid restore journal identity")
    for key in ("source", "prebackup"):
        if not isinstance(record.get(key), str):
            raise ValueError("Invalid restore journal package path")
        _absolute(record[key])
    paused = record.get("paused")
    if (not isinstance(paused, dict) or type(paused.get("maintenance")) is not bool
            or not isinstance(paused.get("services"), dict) or set(paused["services"]) != set(SERVICES)
            or any(type(value) is not bool for value in paused["services"].values())):
        raise ValueError("Invalid original service states in restore journal")
    return record


def _refuse_pending_restore(deployment):
    record = _restore_journal(deployment)
    if record and record["state"] == "pending":
        raise RuntimeError("A database restore is pending; retry the same restore package: " + record["source"])


def _checked(deployment, *args, **kwargs):
    result = deployment.jail(deployment.config.nextcloud_jail, *args,
                             capture=True, check=False, hide_output=True, **kwargs)
    if result.returncode:
        # SQL, PHP and application error messages can contain private input.
        raise RuntimeError("Nextcloud maintenance command failed; application services may need host-side attention")
    return result.stdout or ""


def _install_helper(deployment):
    _checked(deployment, "/usr/bin/install", "-d", "-o", "root", "-g", "wheel", "-m", "755", "/usr/local/libexec")
    _checked(deployment, "/usr/bin/install", "-o", "root", "-g", "www", "-m", "640",
             "/root/cloud-installer/resources/jails/maintenance.php", HELPER)


def _occ(deployment, *args):
    return _checked(deployment, "mdo", "-u", "www", "/usr/local/bin/php",
                    "-d", "display_errors=0", "-d", "zend.exception_ignore_args=1",
                    APP + "/occ", "--no-interaction", *args)


def _helper(deployment, mode, *, input=None):
    return _checked(deployment, "mdo", "-u", "www", "/usr/local/bin/php",
                    "-d", "display_errors=0", "-d", "log_errors=0", "-d", "zend.exception_ignore_args=1",
                    HELPER, mode, input=input)


def _json(text):
    try:
        value = json.loads(text)
    except (ValueError, TypeError):
        raise ValueError("Invalid maintenance metadata") from None
    if not isinstance(value, dict):
        raise ValueError("Maintenance metadata must be an object")
    return value


def _status(deployment, *, require_locked_version=True):
    value = _json(_occ(deployment, "status", "--output=json"))
    if (value.get("installed") is not True or value.get("needsDbUpgrade") is not False
            or type(value.get("maintenance")) is not bool):
        raise ValueError("An installed Nextcloud instance without pending database upgrades is required")
    if require_locked_version and (
            not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", str(value.get("version", "")))
            or ".".join(value["version"].split(".")[:3]) != deployment.versions["applications"]["nextcloud"]):
        raise ValueError("An installed Nextcloud instance at the locked version without pending upgrades is required")
    return value


def _database_version(deployment):
    version = _checked(deployment, "/usr/local/bin/mariadb", *DB_OPTIONS,
                       "--batch", "--skip-column-names", "--execute", "SELECT VERSION()").strip()
    expected = deployment.versions["packages"]["nextcloud"][deployment.versions["roles"]["database"]]["version"].split(",")[0].split("_")[0]
    if not re.fullmatch(re.escape(expected) + r"-MariaDB(?:-[A-Za-z0-9.+~-]+)?", version):
        raise ValueError("MariaDB must match the retained version lock; automatic database upgrades are unsupported")
    return version


def _metadata(deployment):
    status = _status(deployment)
    config = _json(_helper(deployment, "metadata"))
    if (not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", str(config.get("instance_id", "")))
            or not re.fullmatch(r"[A-Za-z0-9_]{1,32}", str(config.get("table_prefix", "")))
            or not re.fullmatch(r"[a-f0-9]{64}", str(config.get("runtime_binding", "")))):
        raise ValueError("Unexpected Nextcloud configuration identity")
    version = _database_version(deployment)
    raw = _checked(deployment, "/usr/local/bin/mariadb", *DB_OPTIONS, "--batch", "--skip-column-names",
                   "--execute", "SELECT TABLE_NAME,TABLE_TYPE,COALESCE(ENGINE,'') FROM information_schema.TABLES "
                   "WHERE TABLE_SCHEMA='nextcloud' ORDER BY TABLE_NAME")
    tables = []
    for line in raw.splitlines():
        fields = line.split("\t")
        if (len(fields) != 3 or not re.fullmatch(r"[A-Za-z0-9_]+", fields[0])
                or fields[1:] not in (["BASE TABLE", "InnoDB"], ["VIEW", ""])):
            raise ValueError("The database must use transactional InnoDB tables (views are supported)")
        tables.append(fields)
    names = {row[0] for row in tables}
    required = {config["table_prefix"] + name for name in (
        "users", "appconfig", "filecache", "migrations", "calendars", "calendarobjects", "addressbooks", "cards")}
    if not required <= names or len(names) != len(tables) or len(tables) > 10000:
        raise ValueError("Incomplete or unexpected Nextcloud schema, including contacts/calendar tables")
    apps = _json(_occ(deployment, "app:list", "--output=json"))
    if not isinstance(apps.get("enabled"), dict) or not apps["enabled"]:
        raise ValueError("Missing application-version inventory")
    return {**config, "nextcloud_version": status["version"], "mariadb_version": version,
            "apps": apps, "tables": tables, "maintenance": status["maintenance"]}


class _Paused:
    """Record running states before changing anything; never enable rc services."""

    def __init__(self, deployment, *, saved=None):
        self.deployment = deployment
        self.jid = deployment.require_running_jail(deployment.config.nextcloud_jail)
        # A checked pending journal supplies the original states without
        # bootstrapping PHP against a possibly missing/half-imported database.
        self.maintenance = saved["maintenance"] if saved is not None else _status(deployment)["maintenance"]
        self.services = dict(saved["services"]) if saved is not None else {name: self.running(name) for name in SERVICES}

    def identity(self):
        if self.deployment.require_running_jail(self.deployment.config.nextcloud_jail) != self.jid:
            raise RuntimeError("Jail identity changed during maintenance")

    def running(self, name):
        result = self.deployment.jail(self.deployment.config.nextcloud_jail,
                                      "service", name, "onestatus", capture=True, check=False)
        if result.returncode not in (0, 1):
            raise RuntimeError("Cannot determine prior service state")
        return result.returncode == 0

    def pause(self):
        try:
            self.identity()
            if not self.maintenance:
                _occ(self.deployment, "maintenance:mode", "--on")
            self.stop_writers()
        except BaseException:
            self.resume()
            raise

    def stop_writers(self):
        """Also usable for an interrupted restore: no occ, DB reads or startup."""
        self.identity()
        failures = []
        for name in SERVICES:
            try:
                self.deployment.jail(self.deployment.config.nextcloud_jail, "service", name, "onestop",
                                     check=False, capture=True, timeout=120)
                if self.running(name):
                    failures.append(name)
            except Exception:
                failures.append(name)
        if failures:
            raise RuntimeError("Nextcloud writer services did not stop: " + ", ".join(failures))
        # Stopping cron does not terminate an already-running cron.php.
        deadline = time.monotonic() + 120
        while True:
            result = self.deployment.jail(self.deployment.config.nextcloud_jail,
                                          "pgrep", "-u", "www", "-x", "php", check=False, capture=True)
            if result.returncode == 1:
                break
            if result.returncode != 0 or time.monotonic() >= deadline:
                raise RuntimeError("Existing www PHP tasks did not drain; retry after they finish")
            time.sleep(1)
        self.identity()

    def resume(self):
        self.identity()
        # A failed maintenance-mode reset must not expose a partial application.
        _occ(self.deployment, "maintenance:mode", "--on" if self.maintenance else "--off")
        failures = []
        for name in reversed(SERVICES):
            try:
                if self.services[name] and not self.running(name):
                    _checked(self.deployment, "service", name, "onestart")
                if self.running(name) != self.services[name]:
                    raise RuntimeError("Service state did not recover")
            except Exception:
                failures.append(name)
        if failures:
            raise RuntimeError("Could not restore prior service states: " + ", ".join(failures))


@contextmanager
def _stream_process(deployment, command, *, writing=False):
    jail = deployment.config.nextcloud_jail
    jid = deployment.require_running_jail(jail)
    # No shell, password environment, temporary SQL file, or diagnostic dump.
    process = subprocess.Popen(["/usr/sbin/jexec", "-U", "root", str(jid), *command],
                               stdin=subprocess.PIPE if writing else subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL if writing else subprocess.PIPE,
                               stderr=subprocess.DEVNULL, bufsize=0, umask=0o077,
                               env={"PATH": "/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/bin", "LC_ALL": "C"})
    try:
        with selectors.DefaultSelector() as selector:
            stream = process.stdin if writing else process.stdout
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_WRITE if writing else selectors.EVENT_READ)
            deadline = time.monotonic() + STREAM_TIMEOUT
            yield process, stream, selector, deadline
            stream.close()
            result = process.wait(timeout=max(0.01, deadline - time.monotonic()))
            if result:
                raise RuntimeError("Database stream failed; no SQL or credentials were printed")
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        for stream in (process.stdin, process.stdout):
            if stream is not None:
                stream.close()
        if deployment.require_running_jail(jail) != jid:
            raise RuntimeError("Managed jail changed identity during database streaming")


def _ready(selector, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0 or not selector.select(remaining):
        raise RuntimeError("Database streaming timed out")


def _dump(deployment, path):
    count = 0
    command = ["/usr/local/bin/mariadb-dump", *DB_OPTIONS, "--single-transaction", "--quick",
               "--routines", "--events", "--triggers", "--hex-blob", "--default-character-set=utf8mb4", "nextcloud"]
    with _new_file(path) as output, gzip.GzipFile(fileobj=output, mode="wb", mtime=0, filename="") as compressed:
        with _stream_process(deployment, command) as (_, source, selector, deadline):
            while True:
                _ready(selector, deadline)
                try:
                    data = os.read(source.fileno(), CHUNK)
                except BlockingIOError:
                    continue
                if not data:
                    break
                compressed.write(data)
                count += len(data)
    if not count:
        raise RuntimeError("Database dump was empty")
    return count


def _import(deployment, source, expected_bytes):
    # Dropping the *whole* database also removes tables created since the backup.
    # A journaled retry may follow an interruption between DROP and CREATE:
    # connect without selecting a database, and select it only after creation.
    prelude = (b"SET SESSION sql_log_bin=0;\nSET SESSION sql_log_off=1;\n"
               b"SET SESSION long_query_time=31536000;\nDROP DATABASE IF EXISTS `nextcloud`;\n"
               b"CREATE DATABASE `nextcloud` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;\nUSE `nextcloud`;\n")
    command = ["/usr/local/bin/mariadb", *DB_OPTIONS, "--batch", "--binary-mode", "--skip-reconnect",
               "--local-infile=0", "--default-character-set=utf8mb4"]
    source.seek(0)
    with gzip.GzipFile(fileobj=source, mode="rb") as sql:
        with _stream_process(deployment, command, writing=True) as (_, target, selector, deadline):
            data, count = prelude, 0
            while data:
                view = memoryview(data)
                while view:
                    _ready(selector, deadline)
                    try:
                        size = os.write(target.fileno(), view)
                    except BlockingIOError:
                        continue
                    view = view[size:]
                data = sql.read(CHUNK)
                count += len(data)
                if count > expected_bytes:
                    raise ValueError("Expanded SQL exceeds its manifest size")
            if count != expected_bytes:
                raise ValueError("Expanded SQL does not match its manifest size")


def _config_directory(deployment):
    jail = deployment.config.nextcloud_jail
    deployment.require_running_jail(jail)
    uid = int(_checked(deployment, "id", "-u", "www").strip())
    gid = int(_checked(deployment, "id", "-g", "www").strip())
    root = _directories(deployment.jail_root(jail))
    directory = root / APP.lstrip("/") / "config"
    _directories(directory, owners={0, ROOT_UID, uid})
    return directory, uid, gid


def _config_files(directory, uid):
    files = []
    for count, path in enumerate(directory.rglob("*"), start=1):
        relative = path.relative_to(directory).as_posix()
        if count > 2 * CONFIG_FILES or len(PurePosixPath(relative).parts) > 8:
            raise ValueError("Configuration tree exceeds the backup limit")
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
            raise ValueError("Configuration backups refuse symlinks, hard links and special files")
        if info.st_uid not in {ROOT_UID, uid} or info.st_mode & 0o022:
            raise ValueError("Unsafe application configuration ownership/mode")
        if stat.S_ISDIR(info.st_mode):
            continue
        if len(files) >= CONFIG_FILES:
            raise ValueError("Configuration tree exceeds the backup limit")
        files.append((relative, path))
    if "config.php" not in {name for name, _ in files}:
        raise ValueError("Nextcloud config.php is missing")
    return sorted(files)


def _capture_config(deployment, path):
    directory, uid, _ = _config_directory(deployment)
    total = 0
    with _new_file(path) as destination, tarfile.open(fileobj=destination, mode="w:gz") as archive:
        for name, source in _config_files(directory, uid):
            with _file(source, owners={ROOT_UID, uid}, private=False) as stream:
                info = os.fstat(stream.fileno())
                total += info.st_size
                if total > CONFIG_LIMIT:
                    raise ValueError("Configuration exceeds the 16 MiB backup limit")
                entry = tarfile.TarInfo(name)
                entry.size, entry.mode = info.st_size, 0o600
                archive.addfile(entry, stream)


def _hash(stream):
    stream.seek(0)
    digest = hashlib.sha256()
    for block in iter(lambda: stream.read(CHUNK), b""):
        digest.update(block)
    stream.seek(0)
    return digest.hexdigest()


def _package_path(deployment, output):
    if output is None:
        parent = _private_directory(BACKUP_ROOT / deployment.config.instance, create=True)
        output = parent / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    output = _absolute(output)
    for forbidden in (Path(deployment.state), Path(deployment.config.mount_root),
                      Path(deployment.jail_root(deployment.config.nextcloud_jail)),
                      Path(deployment.jail_root(deployment.config.onlyoffice_jail))):
        if output == forbidden or forbidden in output.parents:
            raise ValueError("Backups must be outside instance state, datasets and jail roots")
    _private_directory(output.parent)
    output.mkdir(mode=0o700)  # Never merge, overwrite or reuse an incomplete backup.
    return output


def _snapshot(deployment, output=None):
    jid = deployment.require_running_jail(deployment.config.nextcloud_jail)
    metadata = _metadata(deployment)
    if metadata["maintenance"] is not True:
        raise RuntimeError("Backup requires maintenance mode")
    path = _package_path(deployment, output)
    count = _dump(deployment, path / "database.sql.gz")
    _capture_config(deployment, path / "nextcloud-config.tar.gz")
    if deployment.require_running_jail(deployment.config.nextcloud_jail) != jid:
        raise RuntimeError("Jail identity changed during backup capture")
    hashes = {}
    for name in sorted(PACKAGE_FILES):
        with _file(path / name) as stream:
            hashes[name] = _hash(stream)
    manifest = {"schema_version": 1, "scope": "entire-nextcloud-database-and-config", "includes_user_files": False,
                "instance": deployment.config.instance, "public_hostname": deployment.config.public_hostname,
                "public_url": deployment.config.public_url,
                "created_at": datetime.now(timezone.utc).isoformat(), "database": "nextcloud",
                "sql_bytes": count, "metadata": metadata, "sha256": hashes}
    with _new_file(path / "manifest.json") as stream:
        stream.write((json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode())
    return path


def _publish(path):
    with _file(path / "manifest.json") as stream:
        digest = _hash(stream)
    with _new_file(path / ".complete.tmp") as stream:
        stream.write((digest + "\n").encode("ascii"))
    os.replace(path / ".complete.tmp", path / "COMPLETE")
    _sync_directory(path)
    _sync_directory(path.parent)


def backup_database(deployment, output=None):
    """Return a new host-only database/config package directory (no user files)."""
    from .config import require_native_backend
    require_native_backend(deployment.config, "Database backup")
    print(BACKUP_WARNING)
    with _database_guard(deployment):
        _refuse_pending_restore(deployment)
        # Refuse dependency drift before pausing an otherwise working service.
        # The quiesced snapshot still rechecks metadata for consistency.
        _database_version(deployment)
        _install_helper(deployment)
        paused = _Paused(deployment)
        paused.pause()
        try:
            path = _snapshot(deployment, output)
        finally:
            paused.resume()
        _publish(path)
        return path


def _read_config_archive(stream):
    stream.seek(0)
    files, total = {}, 0
    # Bound the *whole* expanded tar before parsing extension headers: a PAX
    # header can otherwise allocate memory before member.size is inspected.
    limit = CONFIG_LIMIT + CONFIG_FILES * 2048 + 10240
    with gzip.GzipFile(fileobj=stream, mode="rb") as compressed:
        raw = compressed.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("Expanded configuration archive exceeds its limit")
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for member in archive:
            name = PurePosixPath(member.name)
            if (not member.isfile() or member.issparse() or name.is_absolute() or ".." in name.parts
                    or str(name) != member.name or name.parts == () or len(name.parts) > 8
                    or any(ord(char) < 32 or ord(char) == 127 for char in member.name)
                    or member.name in files or len(files) >= CONFIG_FILES or member.size < 0):
                raise ValueError("Unsafe configuration archive member")
            total += member.size
            if total > CONFIG_LIMIT:
                raise ValueError("Expanded configuration exceeds 16 MiB")
            files[member.name] = archive.extractfile(member).read(member.size)
    if "config.php" not in files:
        raise ValueError("Backup has no config.php")
    if any(str(parent) in files for name in files for parent in PurePosixPath(name).parents):
        raise ValueError("Configuration archive contains conflicting file/directory paths")
    # Never evaluate archived PHP while validating a package.
    return files


@contextmanager
def _read_package(path):
    path = _private_directory(_absolute(path))
    if {entry.name for entry in path.iterdir()} != PACKAGE_FILES | {"manifest.json", "COMPLETE"}:
        raise ValueError("Backup is incomplete or contains unexpected files")
    with ExitStack() as stack:
        streams = {name: stack.enter_context(_file(path / name))
                   for name in PACKAGE_FILES | {"manifest.json", "COMPLETE"}}
        if os.fstat(streams["manifest.json"].fileno()).st_size > 1024 * 1024:
            raise ValueError("Backup manifest exceeds 1 MiB")
        marker = streams["COMPLETE"].read(66)
        manifest_digest = _hash(streams["manifest.json"])
        if marker != (manifest_digest + "\n").encode("ascii"):
            raise ValueError("Backup completion/manifest checksum mismatch")
        manifest = _json(streams["manifest.json"].read(1024 * 1024 + 1))
        if (manifest.get("schema_version") != 1 or manifest.get("database") != "nextcloud"
                or manifest.get("scope") != "entire-nextcloud-database-and-config"
                or manifest.get("includes_user_files") is not False
                or type(manifest.get("sql_bytes")) is not int or manifest["sql_bytes"] < 1
                or not isinstance(manifest.get("sha256"), dict) or set(manifest["sha256"]) != PACKAGE_FILES):
            raise ValueError("Unsupported backup manifest")
        for name in PACKAGE_FILES:
            if _hash(streams[name]) != manifest["sha256"][name]:
                raise ValueError("Backup file checksum mismatch")
        config = _read_config_archive(streams["nextcloud-config.tar.gz"])
        count = 0
        with gzip.GzipFile(fileobj=streams["database.sql.gz"], mode="rb") as sql:
            for block in iter(lambda: sql.read(CHUNK), b""):
                count += len(block)
                if count > manifest["sql_bytes"]:
                    raise ValueError("Expanded SQL exceeds its manifest size")
        if count != manifest["sql_bytes"]:
            raise ValueError("Invalid expanded SQL size")
        streams["database.sql.gz"].seek(0)
        yield manifest, config, streams["database.sql.gz"], manifest_digest


def _compatible(deployment, manifest, current):
    saved = manifest.get("metadata")
    if (manifest.get("instance") != deployment.config.instance
            or manifest.get("public_hostname") != deployment.config.public_hostname
            or manifest.get("public_url") != deployment.config.public_url or not isinstance(saved, dict)):
        raise ValueError("Backup belongs to a different instance/hostname")
    for key in ("instance_id", "nextcloud_version", "mariadb_version", "apps", "table_prefix", "runtime_binding"):
        if saved.get(key) != current.get(key):
            raise ValueError("Backup version, application inventory or runtime identity does not match: " + key)
    if saved.get("maintenance") is not True or not isinstance(saved.get("tables"), list):
        raise ValueError("Backup was not captured in a supported maintenance state")


def _restore_environment(deployment):
    """Read-only owned storage/PF guard, independent of Nextcloud's database."""
    jail = deployment.config.nextcloud_jail
    jid = deployment.require_running_jail(jail)
    result = deployment.runner.run(f"/usr/local/libexec/{deployment.config.instance}-storage-guard", jail,
                                   capture=True, check=False, hide_output=True, timeout=60)
    if result.returncode:
        raise RuntimeError("Restore refused: the managed storage/network guard failed")
    if deployment.require_running_jail(jail) != jid:
        raise RuntimeError("Jail identity changed during restore preflight")
    return jid


def _code_identity(deployment, metadata):
    """Pin deployed version/signature markers; never execute PHP to resume."""
    directory, uid, _ = _config_directory(deployment)
    app = directory.parent
    enabled = metadata.get("apps", {}).get("enabled")
    if not isinstance(enabled, dict) or not 1 <= len(enabled) <= CONFIG_FILES:
        raise ValueError("Invalid enabled-app inventory for restore")
    paths = [app / "version.php", app / "core/signature.json"]
    for name in sorted(enabled):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", name):
            raise ValueError("Invalid application ID in restore inventory")
        candidates = [app / parent / name / "appinfo/info.xml" for parent in ("apps", "custom_apps")]
        candidates = [path for path in candidates if path.exists() or path.is_symlink()]
        if len(candidates) != 1:
            raise ValueError("Missing or ambiguous deployed application metadata: " + name)
        paths.extend(candidates)
        signature = candidates[0].with_name("signature.json")
        if signature.exists() or signature.is_symlink():
            paths.append(signature)
    hashes = {}
    for path in paths:
        _directories(path.parent, owners={0, ROOT_UID, uid})
        with _file(path, owners={ROOT_UID, uid}, private=False) as stream:
            if path == app / "version.php":
                version = re.search(rb"\$OC_Version\s*=\s*(?:array\s*\(|\[)\s*([0-9]+)\s*,\s*([0-9]+)\s*,\s*([0-9]+)\s*,\s*([0-9]+)",
                                    stream.read(65537))
                if not version or b".".join(version.groups()).decode("ascii") != metadata.get("nextcloud_version"):
                    raise ValueError("Deployed Nextcloud version file does not match the restore identity")
            hashes[path.relative_to(app).as_posix()] = _hash(stream)
    return hashes


def _check_restore_retry(deployment, record, source, manifest, manifest_digest):
    if record["config_sha256"] != config_digest(deployment.config):
        raise ValueError("Pending restore configuration changed; restore the original host configuration before retrying")
    if record["source"] != str(source) or record["source_manifest_sha256"] != manifest_digest:
        raise ValueError("A restore is pending for a different backup. Retry exactly " + record["source"]
                         + "; retained pre-restore backup: " + record["prebackup"])
    _compatible(deployment, manifest, record["metadata"])
    # Retention is part of the transaction: never replace this package with a
    # dump of a half-restored database, or infer it from a directory timestamp.
    with _read_package(record["prebackup"]) as (before, _, _, digest):
        if digest != record["prebackup_manifest_sha256"] or before["metadata"] != record["metadata"]:
            raise ValueError("Retained pre-restore backup no longer matches the pending journal")
        _compatible(deployment, before, record["metadata"])
    jid = _restore_environment(deployment)
    if _database_version(deployment) != record["metadata"].get("mariadb_version"):
        raise ValueError("MariaDB version changed during the pending restore")
    if _code_identity(deployment, record["metadata"]) != record["code_sha256"]:
        raise ValueError("Deployed core/application version or signature files changed during the pending restore")
    if deployment.require_running_jail(deployment.config.nextcloud_jail) != jid:
        raise RuntimeError("Jail identity changed during restore retry validation")
    return jid


def _restore_config(deployment, files):
    directory, uid, gid = _config_directory(deployment)
    existing = _config_files(directory, uid)
    for name, data in files.items():
        target = directory / name
        # Parents are derived only from already-validated archive members.
        for parent in reversed(target.parent.parents):
            if directory in parent.parents and not parent.exists():
                parent.mkdir(mode=0o750)
                os.chown(parent, uid, gid)
        if not target.parent.exists():
            target.parent.mkdir(mode=0o750)
            os.chown(target.parent, uid, gid)
        _directories(target.parent, owners={0, ROOT_UID, uid})
        # A killed attempt can leave a temporary file. Never reuse/truncate it;
        # a successful replay removes superseded regular config files below.
        fd, temporary = tempfile.mkstemp(prefix=".cloud-restore-", suffix=".tmp", dir=target.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                os.fchown(stream.fileno(), uid, gid)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
            _sync_directory(target.parent)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    for name, path in existing:
        if name not in files:
            path.unlink()
    _sync_directory(directory)


def restore_database(deployment, backup_path, *, confirmation):
    """Restore a trusted same-instance package; return its retained pre-backup.

    Once destructive SQL starts, any failure leaves maintenance on and all
    writer services stopped. Only an explicit retry of this journal's exact
    package may replace a partial database. After the durable validated phase,
    retries only finalize service states and never replay application data.
    """
    from .config import require_native_backend
    require_native_backend(deployment.config, "Database restore")
    if confirmation != "RESTORE " + deployment.config.instance:
        raise ValueError("Restore confirmation must exactly match RESTORE <instance>")
    print(BACKUP_WARNING)
    source = _absolute(backup_path)
    with _database_guard(deployment), _read_package(source) as (manifest, files, sql, manifest_digest):
        journal_path = Path(deployment.state) / "restore.json"
        record = _restore_journal(deployment)
        retry = record is not None and record["state"] == "pending"
        if retry:
            jid = _check_restore_retry(deployment, record, source, manifest, manifest_digest)
            paused = _Paused(deployment, saved=record["paused"])
            before = Path(record["prebackup"])
        else:
            jid = _restore_environment(deployment)
            _install_helper(deployment)
            _compatible(deployment, manifest, _metadata(deployment))
            paused = _Paused(deployment)
        if paused.jid != jid:
            raise RuntimeError("Jail identity changed before restore quiescence")
        if not retry:
            paused.pause()
            record = None
            try:
                before = _snapshot(deployment)
                _publish(before)
                current = _metadata(deployment)
                _compatible(deployment, manifest, current)
                with _file(before / "manifest.json") as stream:
                    before_digest = _hash(stream)
                    if _json(stream.read())["metadata"] != current:
                        raise ValueError("Application identity changed during pre-restore backup")
                code = _code_identity(deployment, current)
                paused.identity()
                record = {"schema_version": 1, "state": "pending", "phase": "importing",
                          "instance": deployment.config.instance,
                          "source": str(source), "source_manifest_sha256": manifest_digest,
                          "prebackup": str(before), "prebackup_manifest_sha256": before_digest,
                          "config_sha256": config_digest(deployment.config), "metadata": current, "code_sha256": code,
                          "paused": {"maintenance": paused.maintenance, "services": paused.services},
                          "started": datetime.now(timezone.utc).isoformat()}
                # Durable intent only after the complete pre-backup and all
                # healthy-instance checks, immediately before replacement.
                atomic_json(journal_path, record)
            except BaseException:
                try:
                    # atomic_json may have renamed successfully before an
                    # fsync error. SQL/config replacement has not started yet.
                    if record is not None and _restore_journal(deployment) == record:
                        journal_path.unlink()
                        _sync_directory(journal_path.parent)
                finally:
                    paused.resume()
                raise
        importing = record["phase"] == "importing"
        finishing = database_healthy = False
        try:
            if retry:
                paused.stop_writers()  # No occ against the interrupted database.
            paused.identity()
            if importing:
                # The trusted package was captured in maintenance mode. Once
                # validated, neither this configuration nor SQL may be replayed.
                _restore_config(deployment, files)
                paused.identity()
                _import(deployment, sql, manifest["sql_bytes"])
                paused.identity()
                # Clear ephemeral caches/locks only when persistent SQL rewinds.
                if _checked(deployment, "redis-cli", "-s", "/var/run/redis/private/nextcloud.sock", "FLUSHDB").strip() != "OK":
                    raise RuntimeError("Could not clear stale application cache after restore")
            _install_helper(deployment)
            restored = _metadata(deployment)
            paused.identity()
            _compatible(deployment, manifest, restored)
            if (restored["tables"] != manifest["metadata"]["tables"]
                    or (importing and not restored["maintenance"])):
                raise RuntimeError("Restored schema or maintenance state does not match the backup")
            if importing:
                _occ(deployment, "integrity:check-core")
                _occ(deployment, "maintenance:data-fingerprint")
            database_healthy = True
            paused.identity()
            # This must be durable BEFORE maintenance is disabled or any writer
            # starts: a crash afterwards must preserve legitimate new writes.
            # Republish on finalization retries too, covering a previous rename
            # whose directory fsync failed while the validated phase was visible.
            validated = {**record, "phase": "validated"}
            atomic_json(journal_path, validated)
            record = validated
            paused.resume()
            paused.identity()
            finishing = True
            atomic_json(journal_path, {**record, "state": "complete", "completed": datetime.now(timezone.utc).isoformat()})
        except BaseException:
            if finishing:
                try:
                    # Even if the complete journal renamed before fsync failed, retain only
                    # finalization intent; never downgrade to importing.
                    atomic_json(journal_path, record)
                except Exception:
                    pass
            phase = record["phase"]
            try:
                saved = _restore_journal(deployment)
                if saved and saved["phase"] == "validated":
                    phase = "validated"  # Checkpoint rename may precede an fsync error.
                elif phase != "validated":
                    phase = saved["phase"] if saved else None
            except Exception:
                if phase != "validated":
                    phase = None  # An unreadable checkpoint must never authorize config replay.
            cleanup_failed = False
            try:
                paused.stop_writers()
                if phase == "importing":
                    _restore_config(deployment, files)  # Maintenance on, without executing PHP.
                elif phase == "validated" and database_healthy:
                    _occ(deployment, "maintenance:mode", "--on")
                else:
                    cleanup_failed = True
            except Exception:
                cleanup_failed = True
            detail = ""
            if phase == "validated":
                detail = " Validated data will not be replayed; retry only finalizes the original maintenance/service states."
            elif phase is None:
                detail = " Restore phase could not be read; host-root journal inspection is required."
            if cleanup_failed:
                detail += " Writer shutdown or maintenance mode could not be confirmed; inspect from host root before retrying."
            raise RuntimeError("Restore is pending; cron/apache24/php_fpm must remain stopped. Correct the cause and retry "
                               "the same restore package with RESTORE " + deployment.config.instance + ": " + str(source)
                               + ". Retained pre-restore backup: " + str(before) + detail) from None
        return before


def create_user(deployment, username, password, display_name="", email=""):
    """Create a normal Nextcloud user through occ, with credentials only on stdin."""
    if not isinstance(username, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}", username):
        raise ValueError("Invalid Nextcloud username")
    if (not isinstance(password, str) or not 14 <= len(password) <= 1024
            or any(ord(char) < 32 or ord(char) == 127 for char in password)):
        raise ValueError("Password must contain 14–1024 characters without control characters")
    for value in (display_name, email):
        if not isinstance(value, str) or len(value) > 254 or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("Invalid account details")
    if email and not re.fullmatch(r"[A-Za-z0-9_+%.\-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}", email):
        raise ValueError("Invalid email address")
    _refuse_pending_restore(deployment)
    # User creation is a live occ operation, not a version-bound restore. Let
    # Nextcloud's supported command validate compatibility after manual upgrades.
    if _status(deployment, require_locked_version=False)["maintenance"]:
        raise ValueError("Cannot add a Nextcloud user during maintenance")
    _install_helper(deployment)
    payload = {"username": username, "password": password, "display_name": display_name, "email": email}
    result = _json(_helper(deployment, "create-user", input=json.dumps(payload)))
    if result != {"created": username, "admin": False}:
        raise RuntimeError("User creation did not return a verified normal-user result")
    return result


def _public_key(text):
    if not isinstance(text, str) or len(text) > 16384 or any(ord(char) < 32 for char in text.strip()):
        raise ValueError("Supply one OpenSSH public key, not a private key or authorized_keys options")
    fields = text.strip().split()
    if len(fields) < 2 or fields[0] not in {
        "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
    }:
        raise ValueError("Unsupported public key format")
    try:
        blob = base64.b64decode(fields[1], validate=True)
        length = int.from_bytes(blob[:4], "big")
        if length < 1 or blob[4:4 + length] != fields[0].encode("ascii") or len(blob) <= 4 + length:
            raise ValueError("Invalid key blob")
    except (ValueError, UnicodeError):
        raise ValueError("Invalid OpenSSH public key") from None
    return fields[0] + " " + fields[1] + "\n"  # Discard comments/options; ssh-keygen checks the full blob in-jail.


def configure_ssh(deployment):
    """Configure key-only SSH; root delegation requires explicit ssh_admin opt-in."""
    config = deployment.config
    if not config.jail_ssh:
        return
    username = config.ssh_username
    shell = getattr(config, "ssh_shell", "sh")
    admin = getattr(config, "ssh_admin", False)
    if (not re.fullmatch(r"[a-z][a-z0-9_-]{0,30}", username)
            or username in {"root", "operator", "www", "mysql", "redis", "nobody", "sshd", "toor"}):
        raise ValueError("Choose an unused non-system SSH username, for example cloudop")
    if shell not in ("sh", "zsh"):
        raise ValueError("SSH shell must be sh or zsh")
    if type(admin) is not bool:
        raise ValueError("SSH administration selection must be boolean")
    source = _absolute(config.ssh_key_file)
    _directories(source.parent)
    with _file(source, private=False) as stream:
        key = _public_key(stream.read(16385).decode("ascii"))
    payload = json.dumps({"username": username, "shell": shell, "public_key": key, "admin": admin})
    for jail in config.jails:
        result = deployment.jail(jail, "/bin/sh", "/root/cloud-installer/resources/jails/ssh.sh",
                                 input=payload, capture=True, check=False)
        if result.returncode:
            raise RuntimeError("Jail SSH setup failed in " + jail + "; inspect host-side installation state")
        if _json(result.stdout or "") != {"username": username, "shell": shell, "admin": admin}:
            raise RuntimeError("Jail SSH worker did not confirm the selected account policy in " + jail)
