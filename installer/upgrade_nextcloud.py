"""One-use native NC 35.0.1 -> 35.0.2 adapter (no enrollment).

The caller owns live jail identity, locks, consent, compatible dependencies/apps,
backup, maintenance-on, stopped web/FPM/cron/office writers, and configuration
protection/service restoration. ``run_jail``/``occ`` must use bounded private
output, clean environments, and terminate/reap timed-out processes. This module
never publishes services or resumes an uncertain attempt.
Adapter-owned commands request unchecked results to retain bounded stdout/stderr
privately without changing the general checked transport's generic exceptions.

``run_dir`` is an existing private host directory. Public artifacts are freshly
downloaded into a separate root-owned jail directory; only the authenticated ZIP
is made www-readable. No original installation archive is required. Prepared
objects are invocation-local, not serialized execution permissions.

API evidence: nextcloud/updater v35.0.1 lib/{UpdateCommand,Updater}.php and
nextcloud/server v35.0.2 {core/Command/Upgrade,lib/private/Updater}.php, reviewed
2026-10-18. See docs/nextcloud-update-recipe.md for the fixed-edge findings.
"""

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import secrets
import ssl
import stat
import traceback
import time
import urllib.parse
import urllib.request

from . import nextcloud_update as artifacts


APP = artifacts.APP
SOURCE = artifacts.SOURCE
TARGET = artifacts.TARGET
STAGING = "/var/db/cloud-installer-upgrade"
OUTPUT_LIMIT = 1024 * 1024
PHP = ("/usr/local/bin/php", "-d", "memory_limit=2048M", "-d", "log_errors=0",
       "-d", "display_errors=0", "-d", "zend.exception_ignore_args=1")
WWW_PHP = ("/usr/bin/mdo", "-u", "www", *PHP)
_ROOT_UID = 0


class UpgradeError(ValueError):
    """Public-safe error; detailed command output belongs only in run_dir."""


@dataclass(frozen=True)
class Prepared:
    summary: dict
    run_dir: Path = field(repr=False)
    jail_root: Path = field(repr=False)
    jail: str = field(repr=False)
    stage: str = field(repr=False)
    www_uid: int = field(repr=False)
    www_gid: int = field(repr=False)
    source: artifacts.Inventory = field(repr=False)
    destination: artifacts.Inventory = field(repr=False)
    files: tuple = field(repr=False)
    signature: str = field(repr=False)


def _private_directory(path):
    with artifacts._directory(path) as fd:
        info = os.fstat(fd)
        if info.st_uid != _ROOT_UID or stat.S_IMODE(info.st_mode) != 0o700:
            raise UpgradeError("Upgrade run directory must be root-owned and private")


def _save(directory, name, data):
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    return artifacts._create(directory, name, data=data[:OUTPUT_LIMIT], limit=OUTPUT_LIMIT)


def _command(run_dir, name, call):
    diagnostics = b""
    try:
        result = call()
        output = _text(result)
        if not isinstance(output, str):
            raise UpgradeError("Native command returned invalid output")
        stderr = getattr(result, "stderr", "")
        if not isinstance(stderr, str):
            raise UpgradeError("Native command returned invalid diagnostics")
        diagnostics = (output + stderr).encode(errors="replace")[:OUTPUT_LIMIT]
        _save(run_dir, name + ".log", output + stderr)
        if len(output.encode()) + len(stderr.encode()) > OUTPUT_LIMIT:
            raise UpgradeError("Native command output exceeded its bound")
        if getattr(result, "returncode", 0) != 0:
            raise UpgradeError("Native command failed")
        return output
    except Exception as error:
        # Never copy argv, exception text, or a whole configuration into reports.
        output = diagnostics
        for attr in ("stdout", "stderr"):
            value = getattr(error, attr, None)
            if isinstance(value, str):
                value = value.encode(errors="replace")
            if isinstance(value, bytes):
                output += value[:OUTPUT_LIMIT - len(output)]
        _save(run_dir, name + ".failure.log", output)
        raise UpgradeError("Nextcloud command failed; retain private upgrade diagnostics") from None


def _text(result):
    return result if isinstance(result, str) else result.stdout


class _HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if (parsed.scheme != "https" or parsed.hostname not in
                {"nextcloud.com", "www.nextcloud.com", "download.nextcloud.com"}
                or parsed.username or parsed.password or parsed.port not in (None, 443)):
            raise UpgradeError("Release download redirected outside official HTTPS origins")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _download(url, directory, name, limit):
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _HTTPSRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    with artifacts._directory(directory) as parent:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
        with os.fdopen(fd, "wb") as output:
            with opener.open(url, timeout=120) as response:
                if response.status != 200:
                    raise UpgradeError("Official release download failed")
                deadline = time.monotonic() + 600
                class BoundedResponse:
                    def read(self, size):
                        if time.monotonic() > deadline:
                            raise UpgradeError("Official release download exceeded its deadline")
                        return response.read(size)
                digest, size = artifacts._digest(BoundedResponse(), limit, output)
            output.flush()
            os.fsync(output.fileno())
        os.fsync(parent)
    return artifacts.FileHash(name, size, digest)


def _host(target, absolute):
    return Path(target.nc_root) / absolute.lstrip("/")


def _installed_auth(target, inventory, uid):
    records = {item.path: item for item in inventory.files}
    for name in (artifacts.PHAR, artifacts.CERT):
        item = records[name]
        if artifacts._digest_file(_host(target, APP + "/" + name), artifacts.MAX_FILE,
                                  (uid,)) != (item.sha256, item.size):
            raise UpgradeError("Installed updater/certificate differs from authenticated source release")
    artifacts._version(artifacts._read(_host(target, APP + "/version.php"), 65536, (uid,)), SOURCE)


def prepare(target, target_version, run_dir):
    """Authenticate fresh source tar/target ZIP and installed PHAR before downtime.

    Requires already installed jail gpg/PHP/OpenSSL and www. Does not install any
    dependency. ``summary`` is public; all other fields are local implementation
    state. Refuses other release edges rather than treating arbitrary latest as
    implemented. Source authentication is not an installed core baseline gate.
    """
    if target_version != TARGET[0]:
        raise UpgradeError("Only Nextcloud 35.0.1 -> 35.0.2 is implemented")
    run_dir = Path(run_dir)
    _private_directory(run_dir)
    _save(run_dir, "nextcloud-prepare.started", "35.0.1 -> 35.0.2\n")
    try:
        uid = int(_text(target.run_jail(target.nc, "/usr/bin/id", "-u", "www")).strip())
        gid = int(_text(target.run_jail(target.nc, "/usr/bin/id", "-g", "www")).strip())
        if uid <= 0 or gid <= 0:
            raise UpgradeError("Invalid Nextcloud service identity")
        artifacts._version(artifacts._read(_host(target, APP + "/version.php"), 65536, (uid,)), SOURCE)
        parent = _host(target, STAGING)
        with artifacts._directory(parent.parent) as fd:
            try:
                os.mkdir(parent.name, 0o710, dir_fd=fd)
            except FileExistsError:
                pass
        with artifacts._directory(parent) as fd:
            info = os.fstat(fd)
            if info.st_uid != _ROOT_UID or info.st_mode & 0o022:
                raise UpgradeError("Untrusted artifact staging directory")
            os.fchown(fd, _ROOT_UID, gid)
            os.fchmod(fd, 0o710)
        stage = STAGING + "/" + secrets.token_hex(16)
        directory = _host(target, stage)
        artifacts._mkdir(directory)
        _save(run_dir, "nextcloud-stage.json", json.dumps({"jail_path": stage}))
        files = []
        source_name = "nextcloud-35.0.1.tar.bz2"
        target_name = "nextcloud-35.0.2.zip"
        for name, limit in ((source_name, artifacts.MAX_ARCHIVE), (source_name + ".asc", 65536),
                            (target_name, artifacts.MAX_ARCHIVE), (target_name + ".asc", 65536),
                            (target_name + ".sig", 2048), ("nextcloud.asc", 1024 * 1024)):
            url = ("https://nextcloud.com/nextcloud.asc" if name == "nextcloud.asc" else
                   "https://download.nextcloud.com/server/releases/" + name)
            files.append(_download(url, directory, name, limit))
        if 3 * next(f.size for f in files if f.path == target_name) + 256 * 1024**2 > 2048 * 1024**2:
            raise UpgradeError("Release exceeds the bounded PHP signature-verification memory budget")
        artifacts._mkdir(directory / "gnupg")
        gpg = ("/usr/local/bin/gpg", "--no-options", "--homedir", stage + "/gnupg",
               "--batch", "--no-tty", "--no-auto-key-retrieve", "--auto-key-locate", "clear")
        _command(run_dir, "nextcloud-import-key", lambda: target.run_jail(
            target.nc, *gpg, "--import", stage + "/nextcloud.asc", check=False))
        for name, label in ((source_name, "source"), (target_name, "target")):
            status = _command(run_dir, "nextcloud-pgp-" + label, lambda: target.run_jail(
                target.nc, *gpg, "--status-fd", "1", "--verify", stage + "/" + name + ".asc",
                stage + "/" + name, timeout=600, check=False))
            artifacts._pgp_valid(status.encode("ascii"))
        source, certificate = artifacts._source_inventory(directory / source_name)
        _installed_auth(target, source, uid)
        files.append(artifacts._create(directory, "source-core.crt", data=certificate))
        signature = artifacts.canonical_signature(artifacts._read(directory / (target_name + ".sig"), 2048))
        _command(run_dir, "nextcloud-openssl", lambda: target.run_jail(
            target.nc, *PHP, "-r", artifacts._VERIFY_SIGNATURE.decode().removeprefix("<?php\n"),
            "--", stage + "/" + target_name, stage + "/" + target_name + ".sig",
            stage + "/source-core.crt", timeout=600, check=False))
        destination = artifacts._zip_inventory(directory / target_name)
        summary = {"source": SOURCE[0], "target": TARGET[0], "release_key": artifacts.RELEASE_KEY,
                   "zip_sha256": next(f.sha256 for f in files if f.path == target_name),
                   "php_memory_mib": 2048,
                   "authentication": ["pinned OpenPGP", "source-certificate OpenSSL SHA-512"]}
        prepared = Prepared(summary, run_dir, Path(target.nc_root), target.nc, stage, uid, gid,
                            source, destination, tuple(files), signature)
        _bound(target, prepared)
        _save(run_dir, "nextcloud-artifacts.json", json.dumps(summary, sort_keys=True))
        return prepared
    except Exception:
        raise UpgradeError("Nextcloud preparation failed; retain private artifacts and diagnostics") from None


def _bound(target, prepared):
    if (not isinstance(prepared, Prepared) or Path(target.nc_root) != prepared.jail_root
            or target.nc != prepared.jail):
        raise UpgradeError("Prepared Nextcloud artifacts belong to another target")
    _private_directory(prepared.run_dir)
    for item in prepared.files:
        if artifacts._digest_file(_host(target, prepared.stage + "/" + item.path), artifacts.MAX_ARCHIVE) != (
                item.sha256, item.size):
            raise UpgradeError("Authenticated release artifacts changed")


def _protected(name):
    # Custom themes are preserved by the native updater. Only the official
    # example/README are included in our permission/identity domain.
    first = name.split("/", 1)[0]
    return (first in {"config", "custom_apps", "data", "tls", ".well-known"}
            or first == "themes" and name != "themes" and name != "themes/README"
            and name != "themes/example" and not name.startswith("themes/example/"))


def _paths(inventory):
    files = {item.path: item for item in inventory.files if not _protected(item.path)}
    directories = {""} | {name for name in inventory.directories if not _protected(name)}
    for name in (*files, *(link.path for link in inventory.links)):
        directories.update(str(p) if str(p) != "." else "" for p in Path(name).parents)
    return files, directories, {link.path: link.target for link in inventory.links}


def _tree(target, prepared, inventory):
    """Check topology without following links; never baseline-hash source core."""
    files, directories, links = _paths(inventory)
    def walk(fd, prefix):
        for name in os.listdir(fd):
            relative = prefix + name
            if _protected(relative):
                continue
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                if relative not in links or os.readlink(name, dir_fd=fd) != links[relative]:
                    raise UpgradeError("Unexpected symlink in official Nextcloud core")
            elif stat.S_ISDIR(info.st_mode) and relative in directories:
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    walk(child, relative + "/")
                finally:
                    os.close(child)
            elif not (stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and relative in files):
                raise UpgradeError("Unrecognized path in official Nextcloud core")
    with artifacts._directory(_host(target, APP), (prepared.www_uid,)) as fd:
        walk(fd, "")


def _permissions(target, prepared, inventory, *, writable, missing=False):
    files, directories, links = _paths(inventory)
    uid = prepared.www_uid if writable else _ROOT_UID
    # Each descriptor is pinned through no-follow parents, including on failure.
    for name in sorted(directories | set(files), key=lambda p: (p.count("/"), p)):
        path = _host(target, APP + ("/" + name if name else ""))
        try:
            with artifacts._directory(path.parent, (prepared.www_uid,)) as parent:
                if missing and name in links:
                    info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                    if stat.S_ISLNK(info.st_mode) and os.readlink(path.name, dir_fd=parent) == links[name]:
                        continue
                fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=parent)
                try:
                    info = os.fstat(fd)
                    directory = name in directories
                    if (info.st_uid not in (_ROOT_UID, prepared.www_uid)
                            or directory and not stat.S_ISDIR(info.st_mode)
                            or not directory and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1)):
                        raise UpgradeError("Unsafe official core permission target")
                    os.fchown(fd, uid, prepared.www_gid)
                    os.fchmod(fd, 0o750 if directory or files[name].executable else 0o640)
                finally:
                    os.close(fd)
        except FileNotFoundError:
            if not missing:
                raise
    # Source license aliases stay root-owned; their authenticated regular targets
    # receive the transition. No symlink is followed or recursively chowned.


def _target_bytes(target, prepared, *, migrated=False):
    _tree(target, prepared, prepared.destination)
    for item in prepared.destination.files:
        if migrated and item.path == "config/CAN_INSTALL":
            # Native NC35 Updater removes this archive marker during migration.
            if os.path.lexists(_host(target, APP + "/" + item.path)):
                raise UpgradeError("Native migration did not remove CAN_INSTALL")
            continue
        with artifacts._file(_host(target, APP + "/" + item.path), artifacts.MAX_FILE,
                             (prepared.www_uid,)) as stream:
            artifacts.code_file_identity(stream, item)
    artifacts._version(artifacts._read(_host(target, APP + "/version.php"), 65536,
                                       (prepared.www_uid,)), TARGET)


def _config(target, *, suppressed=False):
    config = target.private_config()
    config = config.get("system", config)
    if (config.get("maintenance") is not True or config.get("updater.release.channel", "stable") != "stable"
            or config.get("datadirectory") != "/var/nc-data"
            or config.get("updatedirectory", "/var/nc-data") != "/var/nc-data"
            or "appstoreenabled" in config and type(config["appstoreenabled"]) is not bool
            or suppressed and config.get("appstoreenabled") is not False):
        raise UpgradeError("Nextcloud maintenance/channel/app-store prerequisite changed")
    return config


def apply(target, prepared, checkpoint):
    """One attempt after the caller's backup and writer quiescence.

    ``checkpoint(step, state, details)`` appends private bounded progress; it is
    not a boot fence. An exclusive local marker prevents automatic same-run replay.
    Any failure retains artifacts/output, attempts safe re-hardening, and leaves
    ordinary maintenance/failure reporting to the parent. Never downgrades code.
    """
    _bound(target, prepared)
    _save(prepared.run_dir, "nextcloud-apply.started", "No automatic replay\n")
    phase = "prerequisites"
    changed_permissions = False
    suppressed = False
    safe_occ = True
    original = None
    def step(name, action):
        nonlocal phase
        phase = name
        checkpoint(name, "before", {})
        result = action()
        checkpoint(name, "after", {})
        return result
    def occ(label, *args, timeout=120):
        return _command(prepared.run_dir, "nextcloud-" + label,
                        lambda: target.occ(*args, timeout=timeout, check=False))
    def restore():
        args = (("config:system:set", "appstoreenabled", "--type=boolean",
                 "--value=" + str(original[1]).lower()) if original[0] else
                ("config:system:delete", "appstoreenabled"))
        occ("restore-appstore", *args)
        current = _config(target)
        if ("appstoreenabled" in current, current.get("appstoreenabled")) != original:
            raise UpgradeError("App-store setting restoration did not verify")
    try:
        config = _config(target)
        original = ("appstoreenabled" in config, config.get("appstoreenabled"))
        _save(prepared.run_dir, "nextcloud-appstore.json", json.dumps(original))
        _installed_auth(target, prepared.source, prepared.www_uid)
        _tree(target, prepared, prepared.source)
        # The supported source updater uses the config owner as its run identity.
        with artifacts._file(_host(target, APP + "/config/config.php"), 1024 * 1024,
                             (prepared.www_uid,)) as stream:
            info = os.fstat(stream.fileno())
            # NC35 Config::writeData defaults to 0640 after native occ writes.
            # Preserve either safe mode, with the verified service user's group.
            if (info.st_uid != prepared.www_uid or info.st_gid != prepared.www_gid
                    or stat.S_IMODE(info.st_mode) not in (0o600, 0o640)):
                raise UpgradeError("Nextcloud config must retain its www owner and private mode")
        _command(prepared.run_dir, "nextcloud-updater-state", lambda: target.run_jail(
            target.nc, *WWW_PHP, "--", input=artifacts._UPDATER_STATE.decode(), check=False))
        suppressed = True
        step("suppress-appstore", lambda: occ("suppress-appstore", "config:system:set", "appstoreenabled",
                                              "--type=boolean", "--value=false"))
        _config(target, suppressed=True)
        directory = _host(target, prepared.stage)
        with artifacts._directory(directory) as fd:
            archive = os.open("nextcloud-35.0.2.zip", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                os.fchown(archive, _ROOT_UID, prepared.www_gid)
                os.fchmod(archive, 0o640)
            finally:
                os.close(archive)
            os.fchown(fd, _ROOT_UID, prepared.www_gid)
            os.fchmod(fd, 0o710)
        changed_permissions = True
        step("writable-core", lambda: _permissions(target, prepared, prepared.source, writable=True))
        _bound(target, prepared)
        _installed_auth(target, prepared.source, prepared.www_uid)
        safe_occ = False
        step("native-updater", lambda: _command(prepared.run_dir, "nextcloud-updater", lambda: target.run_jail(
            target.nc, *WWW_PHP, APP + "/" + artifacts.PHAR, "--no-interaction", "--no-upgrade", "--no-backup",
            "--url", "file://" + prepared.stage + "/nextcloud-35.0.2.zip", "--signature", prepared.signature,
            timeout=3600, check=False)))
        step("target-code", lambda: _target_bytes(target, prepared))
        safe_occ = True
        def integrity():
            if json.loads(occ("integrity", "integrity:check-core", "--output=json", timeout=600)) != []:
                raise UpgradeError("Target core integrity did not verify")
        step("target-integrity", integrity)
        _config(target, suppressed=True)
        step("occ-upgrade", lambda: occ("upgrade", "upgrade", timeout=3600))
        _config(target, suppressed=True)
        _target_bytes(target, prepared, migrated=True)
        status = json.loads(occ("status", "status", "--output=json"))
        if (status.get("installed") is not True or status.get("version") != TARGET[1]
                or status.get("versionstring") != TARGET[0] or status.get("needsDbUpgrade") is not False
                or status.get("maintenance") is not True):
            raise UpgradeError("Nextcloud migration status did not verify")
        step("restore-appstore", restore)
        suppressed = False
        step("harden-core", lambda: _permissions(target, prepared, prepared.destination, writable=False))
        changed_permissions = False
        result = {"source": SOURCE[0], "target": TARGET[0], "maintenance": True,
                  "code_verified": True, "migration_verified": True}
        _save(prepared.run_dir, "nextcloud-result.json", json.dumps(result, sort_keys=True))
        return result
    except BaseException as error:
        try:
            _save(prepared.run_dir, "nextcloud-error.json", json.dumps(dict(
                error_type=type(error).__name__, message=str(error),
                frames=[dict(file=f.filename, line=f.lineno, function=f.name)
                        for f in traceback.extract_tb(error.__traceback__)])))
        except Exception:
            pass  # Diagnostic storage failure must not prevent permission cleanup.
        cleanup = {"appstore_restored": not suppressed, "core_hardened": not changed_permissions}
        if suppressed and safe_occ and phase != "restore-appstore":
            try:
                restore()
                cleanup["appstore_restored"] = True
            except Exception:
                cleanup["appstore_restored"] = False
        if changed_permissions:
            try:
                # Mixed source/target trees are not trusted to execute PHP. Only
                # existing allowlisted nodes are hardened through no-follow FDs.
                union = artifacts.Inventory(tuple({f.path: f for f in
                    (*prepared.source.files, *prepared.destination.files)}.values()),
                    tuple(set(prepared.source.directories) | set(prepared.destination.directories)),
                    prepared.source.links)
                _permissions(target, prepared, union, writable=False, missing=True)
                cleanup["core_hardened"] = True
            except Exception:
                cleanup["core_hardened"] = False
        details = {"phase": phase, "automatic_replay": False, **cleanup}
        _save(prepared.run_dir, "nextcloud-failure.json", json.dumps(details, sort_keys=True))
        checkpoint(phase, "failed", details)
        raise UpgradeError("Nextcloud upgrade incomplete; retain private run state and assess before retrying") from None
