"""M3 local, immutable artifact staging, before any application downtime.

The caller validates the retained versions plan against its config/policy and
binds that plan, current generation/graph and executor in its maintenance plan.
Pass that plan's hash to stage while holding Registry.locked(). This module
revalidates the retained closure structure; saved assessment reports are not
version locks. It never discovers, downloads, installs, extracts or executes.

The cache covers all retained host/Nextcloud/ONLYOFFICE package archives and the
public current installer payload. Catalog provenance belongs to the retained
plan: matching archive bytes is not a new authenticity or solver check. Cached
ports archives exclude pkgbase archives, Nextcloud release tarballs and connector
release/signature downloads. This is not full reinstall coverage or full disaster
recovery. Snapshot recovery does not supply base archives. A momentary free-space
check is not a capacity assurance; staging authorizes no upgrade edge.
"""

import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile

from .generations import Store, _digest, _encode, _id, _reference, _relative
from .paths import PROJECT_ROOT
from .resolution import _plan_inventory
from .state import Registry


MAX_FILES = 4096
MAX_SOURCE_FILE = 16 * 1024 * 1024
MAX_SOURCE_BYTES = 128 * 1024 * 1024
MAX_PACKAGE_BYTES = 8 * 1024 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024 * 1024
MAX_METADATA_BYTES = 4 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024
_ROOT_UID = 0

# Keep these public runtime names aligned with tools/build-release.py. Unknown
# source files fail closed rather than silently changing the historical digest.
_NEXTCLOUD = (
    "certbot-cron", "certbot-deploy", "challenge.conf", "cloud_php_dirs", "httpd.conf",
    "https.conf", "external.conf", "my.cnf", "mysql-flush-logs", "newsyslog.conf", "packages.txt",
    "php-fpm.conf", "php.ini", "redis.conf", "www-crontab", "www.conf",
    "www-none.conf", "https-none.conf", "external-none.conf",
)
_RESOURCES = {
    "resources/vm/bootstrap.sh",
    "resources/versions.json", "resources/plugins/onlyoffice.json", "resources/packages/fonts.txt",
    *("resources/jails/" + name for name in (
        "nextcloud.sh", "onlyoffice.sh", "versions.sh", "ssh.sh", "maintenance.php", "nextcloud-bootstrap.php",
        "runtime-inventory.php", "nextcloud-cron-fence.php")),
    *("resources/templates/nextcloud/" + name for name in _NEXTCLOUD),
    *("resources/templates/onlyoffice/" + name for name in ("nginx.conf", "proxy.conf", "supervisord.conf")),
}
_SOURCE_DIRS = {"installer", "resources"}
for _name in _RESOURCES:
    _SOURCE_DIRS.update(str(parent) for parent in Path(_name).parents if str(parent) != ".")


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def _absolute(path):
    path = Path(path)
    if ".." in path.parts:
        raise ValueError("Unsafe artifact path")
    return Path(os.path.abspath(path))  # Never resolve away a symlink.


def _ancestors(path):
    for parent in reversed((path, *path.parents)):
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid())
                or (info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX))):
            raise ValueError("Unsafe artifact directory ancestry")


def _directory(path, *, private=False):
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or (stat.S_IMODE(info.st_mode) != 0o700 if private else info.st_mode & 0o7022)):
        raise ValueError("Unsafe artifact directory")


def _file(info, limit, *, private=False):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
            or not 0 <= info.st_size <= limit
            or (stat.S_IMODE(info.st_mode) != 0o600 if private else info.st_mode & 0o7022)):
        raise ValueError("Unsafe artifact file or byte bound exceeded")


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            info.st_uid, info.st_mode, info.st_nlink)


def _stream(path, limit, *, private=False, output=None, aggregate=None):
    """Hash/copy with bounded reads and verify both opened inode and path again."""
    _ancestors(path.parent)
    before = path.lstat()
    _file(before, limit, private=private)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        opened = os.fstat(source.fileno())
        _file(opened, limit, private=private)
        if _identity(before) != _identity(opened):
            raise ValueError("Artifact changed before read")
        digest, size = hashlib.sha256(), 0
        while True:
            chunk = source.read(min(CHUNK_BYTES, limit - size + 1))
            if not chunk:
                break
            size += len(chunk)
            if size > limit:
                raise ValueError("Artifact byte bound exceeded")
            digest.update(chunk)
            if aggregate is not None:
                aggregate.update(chunk)
            if output is not None:
                output.write(chunk)
        after = os.fstat(source.fileno())
        if (_identity(before) != _identity(after) or _identity(before) != _identity(path.lstat())
                or size != before.st_size):
            raise ValueError("Artifact changed during read")
    return digest.hexdigest(), size


def _children(directory):
    # Path.iterdir() materializes the directory on some Python versions.
    with os.scandir(directory) as entries:
        for entry in entries:
            yield Path(entry.path)


def _source(root):
    root = _absolute(root)
    _ancestors(root)
    _directory(root)
    names, visited = ["install.sh"], 1

    def visit(directory):
        nonlocal visited
        _directory(directory)
        # Bound enumeration before retaining/sorting names, including entries
        # excluded from the historical source digest.
        for path in _children(directory):
            visited += 1
            if visited > MAX_FILES:
                raise ValueError("Source file count bound exceeded")
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                _directory(path)
                if path.name == "__pycache__":
                    continue  # Identical exclusion to deploy.source_digest().
                if path.relative_to(root).as_posix() not in _SOURCE_DIRS:
                    raise ValueError("Non-public source directory")
                visit(path)
            else:
                _file(info, MAX_SOURCE_FILE)
                if path.suffix == ".pyc":
                    continue
                relative = path.relative_to(root).as_posix()
                if (relative not in _RESOURCES
                        and not re.fullmatch(r"installer/[A-Za-z_][A-Za-z0-9_]*\.py", relative)):
                    raise ValueError("Non-public source file")
                names.append(relative)

    for directory in ("installer", "resources"):
        visit(root / directory)
    return _source_bytes(root, names)


def _source_bytes(root, names, *, private=False):
    """Hash explicit public members after a complete size preflight.

    Live callers validate their source tree first; cache callers validate EVERY
    cache member through _existing, including retained unpublished temporaries.
    Those temporaries are never source members or inputs to the source identity.
    """
    if not {"install.sh", "installer/__init__.py", "installer/main.py", *_RESOURCES}.issubset(names):
        raise ValueError("Public source payload is incomplete")
    if len(names) > MAX_FILES:
        raise ValueError("Source file count bound exceeded")
    total = 0
    for name in names:
        info = (root / name).lstat()
        _file(info, MAX_SOURCE_FILE, private=private)
        total += info.st_size
        if total > MAX_SOURCE_BYTES:
            raise ValueError("Public source payload bound exceeded")
    digest, specs, total = hashlib.sha256(), [], 0
    # Historical ordering: installer subtree, then resources subtree; the shell
    # belongs to executor identity, not deploy.source_digest().
    for name in sorted(name for name in names if name != "install.sh"):
        digest.update(name.encode() + b"\0")
        checksum, size = _stream(root / name, min(MAX_SOURCE_FILE, MAX_SOURCE_BYTES - total),
                                 private=private, aggregate=digest)
        total += size
        specs.append(dict(kind="source", path="source/" + name, sha256=checksum, size=size))
    shell, size = _stream(root / "install.sh", min(MAX_SOURCE_FILE, MAX_SOURCE_BYTES - total),
                          private=private)
    specs.append(dict(kind="source", path="source/install.sh", sha256=shell, size=size))
    source_hash = digest.hexdigest()
    executor = hashlib.sha256((source_hash + "\n").encode())
    # Stream again rather than keeping even the bounded shell in memory.
    if _stream(root / "install.sh", size, private=private, aggregate=executor) != (shell, size):
        raise ValueError("Source entrypoint changed")
    return specs, source_hash, executor.hexdigest()


def _package_specs(versions_plan):
    if versions_plan is None:
        return []
    if len(_encode(versions_plan)) > MAX_METADATA_BYTES:
        raise ValueError("Retained version lock exceeds byte bound")
    packages = _plan_inventory(versions_plan)
    if len(packages) > MAX_FILES:
        raise ValueError("Package count bound exceeded")
    by_hash = {}
    for name, record in packages.items():
        checksum = record["checksum"]
        if not re.fullmatch(r"[a-fA-F0-9]{64}", checksum):
            raise ValueError("Retained lock lacks package archive SHA256; no guessed lock is permitted")
        by_hash.setdefault(checksum.lower(), []).append(name)
    return sorted((dict(kind="package", path="packages/" + checksum + ".pkg", sha256=checksum,
                        packages=sorted(names)) for checksum, names in by_hash.items()),
                  key=lambda item: item["path"])


def required_artifacts(versions_plan, source_root):
    """Sorted bounded specs, derived only from a retained lock and public source.

    None explicitly selects source-only recovery preparation, with no claim of
    retained package archive coverage. Otherwise supply a validated versions lock.
    Package checksums must be archive SHA256 hex, not pkg's opaque manifest
    checksums. A legacy lock lacking archive hashes cannot be retrofitted here.
    No URL, command, package name or path supplied independently is accepted.
    """
    packages = _package_specs(versions_plan)
    specs, _, _ = _source(source_root)
    specs.extend(packages)
    return validate_specs(sorted(specs, key=lambda item: item["path"]))


def validate_specs(expected):
    """Validate JSON spec shape/bounds, not its authority as a version lock."""
    if type(expected) is not list or not expected or len(expected) > MAX_FILES:
        raise ValueError("Invalid artifact count")
    if len(_encode(expected)) > MAX_METADATA_BYTES:
        raise ValueError("Artifact metadata bound exceeded")
    paths = []
    for item in expected:
        if type(item) is not dict:
            raise ValueError("Invalid artifact specification")
        kind = item.get("kind")
        fields = {"kind", "path", "sha256", "size" if kind == "source" else "packages"}
        if set(item) != fields or kind not in ("source", "package"):
            raise ValueError("Invalid artifact specification fields")
        _relative(item["path"])
        _digest(item["sha256"])
        if kind == "source":
            name = item["path"].removeprefix("source/")
            if (not item["path"].startswith("source/") or
                    (name != "install.sh" and name not in _RESOURCES
                     and not re.fullmatch(r"installer/[A-Za-z_][A-Za-z0-9_]*\.py", name))
                    or type(item["size"]) is not int or not 0 <= item["size"] <= MAX_SOURCE_FILE):
                raise ValueError("Invalid public source specification")
        elif (item["path"] != "packages/" + item["sha256"] + ".pkg"
              or type(item["packages"]) is not list or not item["packages"]
              or len(item["packages"]) > MAX_FILES
              or any(type(name) is not str or not re.fullmatch(r"[A-Za-z0-9_+.-]{1,256}", name)
                     for name in item["packages"])
              or sorted(set(item["packages"])) != item["packages"]):
            raise ValueError("Invalid package specification")
        paths.append(item["path"])
    if paths != sorted(set(paths)):
        raise ValueError("Artifact specs must be sorted and unique")
    if sum(item.get("size", 0) for item in expected) > MAX_SOURCE_BYTES:
        raise ValueError("Source specification byte bound exceeded")
    return expected


def _publish(path, writer):
    """Single-link publication under caller's global lock; never replace."""
    if path.exists() or path.is_symlink():
        raise ValueError("Immutable staged artifact already exists")
    fd, temporary = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            writer(stream)
            stream.flush()
            os.fsync(stream.fileno())
        # Same contract as Store._write: all supported writers hold the global
        # lock; unrelated root writers bypassing that lock are not supported.
        if path.exists() or path.is_symlink():
            raise ValueError("Immutable staged artifact already exists")
        os.rename(temporary, path)
        Store._sync(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)  # Only this invocation's unpublished temporary.


def _metadata(path, value):
    data = _encode(value)
    if len(data) > MAX_METADATA_BYTES:
        raise ValueError("Stage metadata bound exceeded")
    if path.exists() or path.is_symlink():
        if _stream(path, MAX_METADATA_BYTES, private=True) != (_hash(data), len(data)):
            raise ValueError("Immutable staging inputs changed")
    else:
        _publish(path, lambda stream: stream.write(data))
    return _hash(data)


def _intent(operation, expected, versions_plan, plan_sha256, source_sha256, executor_sha256):
    return dict(schema_version=1, operation=operation, plan_sha256=plan_sha256,
                versions_sha256=_hash(_encode(versions_plan)), source_sha256=source_sha256,
                executor_sha256=executor_sha256, source_root=str(_absolute(PROJECT_ROOT)), artifacts=expected)


def _manifest(operation, intent_hash, records, versions_plan):
    return dict(schema_version=1, operation=operation, intent_sha256=intent_hash,
                artifacts=records, package_archives_complete=versions_plan is not None,
                snapshot_recovery_includes_base_archives=False, full_disaster_recovery=False,
                capacity_assured=False, execution_authorized=False)


def _match_metadata(path, value):
    """Strict canonical bytes check; unlike _metadata this can never publish."""
    data = _encode(value)
    if len(data) > MAX_METADATA_BYTES:
        raise ValueError("Stage metadata bound exceeded")
    digest = _hash(data)
    if _stream(path, MAX_METADATA_BYTES, private=True) != (digest, len(data)):
        raise ValueError("Immutable staging inputs changed")
    return digest


def _orphan_temporaries(directory):
    """A crash before first intent publication may leave only unpublished bytes."""
    count, total = 0, 0
    for path in _children(directory):
        count += 1
        if count > MAX_FILES or not re.fullmatch(r"\.pending-[A-Za-z0-9_-]{1,128}", path.name):
            raise ValueError("Staging intent is missing; recovery assessment required")
        info = path.lstat()
        _file(info, MAX_METADATA_BYTES, private=True)
        total += info.st_size
        if total > MAX_TOTAL_BYTES:
            raise ValueError("Staging total byte bound exceeded")


def _capacity(directory, missing_bytes):
    """Momentary free-space check only: no reservation or capacity guarantee."""
    filesystem = os.statvfs(directory)
    if filesystem.f_frsize <= 0:
        raise ValueError("Invalid staging filesystem capacity information")
    available = max(0, filesystem.f_bavail) * filesystem.f_frsize
    # Reserve a bounded allowance for immutable intent/manifest metadata. The
    # intent is already durable; allowing both records is deliberately conservative.
    if available < missing_bytes + 2 * MAX_METADATA_BYTES:
        raise ValueError("Insufficient available staging capacity for missing artifacts and metadata")


def _existing(directory, expected):
    """Check EVERY existing member before permitting any artifact additions."""
    allowed = {item["path"]: item for item in expected}
    directories = {"."}
    for name in allowed:
        directories.update(str(parent) for parent in Path(name).parents)
    present, count, total = {}, 0, 0

    def visit(path):
        nonlocal count, total
        _directory(path, private=True)
        for child in _children(path):
            count += 1
            if count > MAX_FILES * 2:
                raise ValueError("Staging member count bound exceeded")
            relative = child.relative_to(directory).as_posix()
            if stat.S_ISDIR(child.lstat().st_mode):
                if relative not in directories:
                    raise ValueError("Unexpected staging directory")
                visit(child)
            elif child.name.startswith(".pending-"):
                # Interrupted unpublished writes are retained, never adopted or
                # pruned. Include them in the byte budget, even on replay.
                if not re.fullmatch(r"\.pending-[A-Za-z0-9_-]{1,128}", child.name):
                    raise ValueError("Invalid unpublished staging temporary")
                _file(child.lstat(), MAX_PACKAGE_BYTES, private=True)
                total += child.lstat().st_size
            elif relative in ("intent.json", "manifest.json"):
                _file(child.lstat(), MAX_METADATA_BYTES, private=True)
            else:
                item = allowed.get(relative)
                if item is None:
                    raise ValueError("Unexpected staged artifact")
                checksum, size = _stream(child, MAX_SOURCE_FILE if item["kind"] == "source"
                                         else MAX_PACKAGE_BYTES, private=True)
                if checksum != item["sha256"] or (item["kind"] == "source" and size != item["size"]):
                    raise ValueError("Existing staged artifact changed")
                total += size
                present[relative] = size
            if total > MAX_TOTAL_BYTES:
                raise ValueError("Staging total byte bound exceeded")
    visit(directory)
    return present, total


def verify_stage(root, operation, expected, receipt, *, plan_sha256, source_sha256,
                 executor_sha256, versions_plan):
    """Read-only receipt/cache verification; never an execution authorization.

    Rehash all retained files, check the complete manifest and immutable intent,
    and reconstruct the cached source/executor identity. Original package inputs
    and source bytes are not needed. The bound original source path must still
    equal PROJECT_ROOT. No lock, directory creation, repair or publication occurs.
    """
    if os.geteuid() != _ROOT_UID:
        raise ValueError("Artifact verification requires root")
    root = _absolute(root)
    _id(operation)
    for digest in (plan_sha256, source_sha256, executor_sha256):
        _digest(digest)
    validate_specs(expected)
    if [item for item in expected if item["kind"] == "package"] != _package_specs(versions_plan):
        raise ValueError("Expected package artifacts differ from retained lock")
    prefix = "maintenance/operations/" + operation + "/artifacts"
    _reference(receipt, prefix + "/manifest.json")
    _ancestors(root)
    _directory(root, private=True)
    store = Store(root)
    intent_path = store._path(prefix + "/intent.json")
    directory = intent_path.parent
    intent = _intent(operation, expected, versions_plan, plan_sha256, source_sha256, executor_sha256)
    intent_hash = _match_metadata(intent_path, intent)
    present, _ = _existing(directory, expected)
    if len(present) != len(expected):
        raise ValueError("Completed staging manifest has missing artifacts")
    specs, actual_source, actual_executor = _source_bytes(
        directory / "source", [item["path"][7:] for item in expected if item["kind"] == "source"],
        private=True)
    if (sorted(specs, key=lambda item: item["path"]) != [item for item in expected if item["kind"] == "source"]
            or (actual_source, actual_executor) != (source_sha256, executor_sha256)):
        raise ValueError("Cached source/executor differs from the maintenance plan")
    records = [{**item, "size": present[item["path"]]} for item in expected]
    manifest = _manifest(operation, intent_hash, records, versions_plan)
    manifest_hash = _match_metadata(directory / "manifest.json", manifest)
    if manifest_hash != receipt["sha256"]:
        raise ValueError("Staging receipt hash changed")
    _match_metadata(intent_path, intent)
    return manifest


def stage(root, operation, expected, package_directory, source_root, *, registry,
          versions_plan, plan_sha256, source_sha256, executor_sha256):
    """Explicit same-plan stage/retry; returns root-relative manifest reference.

    root must equal registry.root; source_root must be the current PROJECT_ROOT.
    All bindings are mandatory. Missing/changed inputs leave the intent and any
    completed immutable members recoverable by another explicit identical call.
    versions_plan=None is allowed only with the exact source-only spec list;
    package_directory is unused in that case. Local package inputs, including
    already cached members, must remain present and unchanged for each call.
    The caller owns its maintenance fence and verifies graph/config/generation
    bindings before and after this call. No service or host state is mutated.
    """
    if not isinstance(registry, Registry) or not registry._locked:
        raise ValueError("Staging requires the caller's global Registry.locked() lock")
    if os.geteuid() != _ROOT_UID:
        raise ValueError("Artifact staging requires root")
    root, source_root = _absolute(root), _absolute(source_root)
    if root != _absolute(registry.root) or source_root != _absolute(PROJECT_ROOT):
        raise ValueError("Staging requires the exact registry and current source path")
    _id(operation)
    for digest in (plan_sha256, source_sha256, executor_sha256):
        _digest(digest)
    validate_specs(expected)
    _ancestors(root)
    _directory(root, private=True)
    store = Store(root)
    prefix = "maintenance/operations/" + operation + "/artifacts"
    directory = root / prefix
    intent = _intent(operation, expected, versions_plan, plan_sha256, source_sha256, executor_sha256)
    # Never adopt an orphan cache whose immutable intent was lost.
    if directory.exists() or directory.is_symlink():
        store._path(prefix + "/intent.json")
        _directory(directory, private=True)
        if not (directory / "intent.json").exists():
            _orphan_temporaries(directory)
        _existing(directory, expected)
    else:
        store._mkdir(prefix)
    intent_hash = _metadata(directory / "intent.json", intent)
    # Durable intent precedes input failures; changing expected inputs on retry
    # cannot reinterpret previously staged data as a different lock or plan.
    if required_artifacts(versions_plan, source_root) != expected:
        raise ValueError("Expected artifacts differ from retained lock/current source")
    _, actual_source, actual_executor = _source(source_root)
    if (actual_source, actual_executor) != (source_sha256, executor_sha256):
        raise ValueError("Current source/executor differs from the maintenance plan")
    packages = None
    if any(item["kind"] == "package" for item in expected):
        packages = _absolute(package_directory)
        _ancestors(packages)
        _directory(packages)
    present, total = _existing(directory, expected)
    records = []
    # Preflight ALL local inputs, including those already cached, before copying.
    inputs = []
    for item in expected:
        source = (source_root / item["path"][7:] if item["kind"] == "source"
                  else packages / (item["sha256"] + ".pkg"))
        limit = MAX_SOURCE_FILE if item["kind"] == "source" else MAX_PACKAGE_BYTES
        checksum, size = _stream(source, limit)
        if checksum != item["sha256"] or (item["kind"] == "source" and size != item["size"]):
            raise ValueError("Local artifact differs from exact retained hash")
        if item["path"] not in present:
            total += size
        if total > MAX_TOTAL_BYTES:
            raise ValueError("Staging total byte bound exceeded")
        inputs.append((item, source, limit, size, _identity(source.lstat())))
        records.append({**item, "size": size})
    manifest = _manifest(operation, intent_hash, records, versions_plan)
    # An existing manifest must also match before adding anything on replay.
    manifest_path = directory / "manifest.json"
    if manifest_path.exists() or manifest_path.is_symlink():
        _metadata(manifest_path, manifest)
        if len(present) != len(expected):
            raise ValueError("Completed staging manifest has missing artifacts")
    if len(present) != len(expected) or not manifest_path.exists():
        _capacity(directory, sum(size for item, _, _, size, _ in inputs if item["path"] not in present))
    for item, source, limit, size, identity in inputs:
        if _identity(source.lstat()) != identity:
            raise ValueError("Local artifact changed after preflight")
        if item["path"] in present:
            continue
        destination = directory / item["path"]
        store._mkdir(str(destination.parent.relative_to(root)))
        def copy(stream):
            if _stream(source, limit, output=stream) != (item["sha256"], size):
                raise ValueError("Local artifact changed during staging")
        _publish(destination, copy)
    for item, source, limit, size, identity in inputs:
        if _identity(source.lstat()) != identity or _stream(source, limit) != (item["sha256"], size):
            raise ValueError("Local artifact changed after staging")
    if required_artifacts(versions_plan, source_root) != expected:
        raise ValueError("Public source payload changed after staging")
    _existing(directory, expected)
    digest = _metadata(manifest_path, manifest)
    return {"path": prefix + "/manifest.json", "sha256": digest}
