"""Disabled, injected primitives for the exact NC 35.0.1.1 -> 35.0.2.2 edge.

No CLI, recipe registration, downloads, package operations or publication. See
docs/nextcloud-update-recipe.md. This is not a maintenance executor: a trusted
parent must implement Authority using live locks, original-root/JID verification,
persistent writer/ingress closure, coherent recovery-set verification and the
unchanged PHP/DB/package/app/connector inventories. A JSON boolean is not authority.

The parent also owns controlled, inventory-bound temporary code permissions and
re-hardening (never recursive chown, never config/custom_apps/data/TLS), config
ownership/mode preservation and capacity checks. Checkpoints must be durable,
reject replay of begun effects, and bind their arguments to the operation.
Exceptions/zero exits never authorize retries, recovery completion or publication.
Native acceptance has NOT RUN. All runners in the accompanying tests are fake.
"""

from abc import ABC, abstractmethod
import base64
from contextlib import contextmanager
from dataclasses import asdict, dataclass, fields
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import tarfile
from typing import Callable
import zipfile


SOURCE = ("35.0.1", "35.0.1.1")
TARGET = ("35.0.2", "35.0.2.2")
RELEASE_KEY = "28806A878AE423A28372792ED75899B9A724937A"
# Reviewed 2026-10-17 from the pinned-key-authenticated 35.0.1 tarball,
# SHA256 7ed305e880192d804ba83179a19dd22257679608d63161a611ce3f8a918d2aa6.
# Exact canonical {relative path: sibling target} map: 121 license aliases.
SOURCE_ALIASES_SHA256 = "bd7feff788467c533cf811ace270bf820b755f4b0e01ce26a4f8834f4994ad38"
APP = "/usr/local/www/nextcloud"
RETAINED = "/var/db/cloud-installer/nextcloud-release.tar.bz2"
SHA_PROOF = "/var/db/cloud-installer/nextcloud-release.sha256"
STAGING = "/var/db/cloud-installer-maintenance"
PHAR = "updater/updater.phar"
CERT = "resources/codesigning/core.crt"
MAX_ARCHIVE = 1024 * 1024 * 1024
MAX_FILE = 128 * 1024 * 1024
MAX_EXPANDED = 4 * 1024 * 1024 * 1024
MAX_ENTRIES = 100000
MAX_CENTRAL = 32 * 1024 * 1024
CHUNK = 1024 * 1024
_ROOT_UID = 0
DENIED = "Nextcloud update primitive refused; retain private state for assessment"
# Fixed root-path output of authenticated 35.0.1/35.0.2 Setup::updateHtaccess
# with webRoot='' and htaccess.RewriteBase='/', as configured by this installer.
HTACCESS_ROOT_SUFFIX = br'''#### DO NOT CHANGE ANYTHING ABOVE THIS LINE ####

ErrorDocument 403 /index.php/error/403
ErrorDocument 404 /index.php/error/404
<IfModule mod_rewrite.c>
  Options -MultiViews
  RewriteRule ^core/js/oc.js$ index.php [PT,E=PATH_INFO:$1]
  RewriteRule ^core/preview.png$ index.php [PT,E=PATH_INFO:$1]
  RewriteCond %{REQUEST_FILENAME} !\.(css|js|mjs|svg|gif|ico|jpg|jpeg|png|webp|html|otf|ttf|woff2?|map|webm|mp4|mp3|ogg|wav|flac|wasm|tflite)$
  RewriteCond %{REQUEST_FILENAME} !/core/ajax/update\.php
  RewriteCond %{REQUEST_FILENAME} !/core/img/(favicon\.ico|manifest\.json)$
  RewriteCond %{REQUEST_FILENAME} !/(cron|public|remote|status)\.php
  RewriteCond %{REQUEST_FILENAME} !/ocs/v(1|2)\.php
  RewriteCond %{REQUEST_FILENAME} !/robots\.txt
  RewriteCond %{REQUEST_FILENAME} !/(ocs-provider|updater)/
  RewriteCond %{REQUEST_URI} !^/\.well-known/(acme-challenge|pki-validation)/.*
  RewriteCond %{REQUEST_FILENAME} !/richdocumentscode(_arm64)?/proxy.php$
  RewriteRule . index.php [PT,E=PATH_INFO:$1]
  RewriteBase /
  <IfModule mod_env.c>
    SetEnv front_controller_active true
    <IfModule mod_dir.c>
      DirectorySlash off
    </IfModule>
  </IfModule>
</IfModule>
'''


class UpdateError(ValueError):
    pass


class Phase(Enum):
    ARTIFACTS = "artifacts"
    CONFIG = "config"
    UPDATER = "updater"
    TARGET = "target"
    MIGRATION = "migration"
    RESTORE_CONFIG = "restore-config"


@dataclass(frozen=True)
class SourceReference:
    archive_sha256: str
    proof_sha256: str


class Authority(ABC):
    """Trusted Python integration, deliberately no JSON/from_dict constructor.

    Every method raises on refusal and returns None on success, never a boolean.
    validate must check live identity, parent lock and phase-specific admission.
    All non-ARTIFACTS phases require persistent closure and verified recovery.
    UPDATER additionally requires config owner www, stable channel, maintenance
    true, appstore false and journaled bounded writable code. The checkpoint
    rejects earlier attempts; postchecks may observe this attempt in progress.
    MIGRATION additionally requires target integrity, appstore false, maintenance
    true and unchanged connector/runtime inventories. No phase permits publication.
    """

    @abstractmethod
    def validate(self, context, phase: Phase) -> None:
        """Recheck real name/root/JID and live parent phase prerequisites."""

    @abstractmethod
    def source(self, context, reference: SourceReference) -> None:
        """Bind retained install archive/proof to original instance state.

        A caller-provided hash or the existence of the .sha256 file is insufficient.
        Refuse if installation provenance/original immutable metadata is absent.
        stage_artifacts additionally requires fresh pinned-PGP authentication of
        these retained archive bytes using the supplied detached source signature.
        """

    @abstractmethod
    def artifacts(self, context, bundle) -> None:
        """Bind staged receipt and full inventories to this operation's journal."""

    @abstractmethod
    def checkpoint(self, context, event: str, state: str, binding: str) -> None:
        """Fsync before/effect-after records; refuse a repeated 'before' effect.

        A returned 'after' records command success only, not semantic completion.
        Missing after (including a failed postcheck) means ambiguous; never retry.
        """


@dataclass(frozen=True)
class NativeResult:
    returncode: int
    stdout: bytes = b""
    stderr: bytes = b""


@dataclass(frozen=True)
class NativeContext:
    operation: str
    jid: int
    jail_name: str
    jail_root: Path
    www_uid: int
    www_gid: int
    memory_mib: int
    authority: Authority
    runner: Callable

    def __post_init__(self):
        if (not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", self.operation)
                or type(self.jid) is not int or self.jid < 1
                or not re.fullmatch(r"[a-z][a-z0-9]{0,7}nc", self.jail_name)
                or type(self.www_uid) is not int or self.www_uid < 1
                or type(self.www_gid) is not int or self.www_gid < 1
                or type(self.memory_mib) is not int or not 512 <= self.memory_mib <= 16384
                or not isinstance(self.authority, Authority) or not callable(self.runner)
                or not isinstance(self.jail_root, Path) or not self.jail_root.is_absolute()
                or str(self.jail_root) != os.path.normpath(self.jail_root)):
            raise UpdateError(DENIED)

    @property
    def stage(self):
        return STAGING + "/" + self.operation

    def host(self, absolute):
        if not absolute.startswith("/") or ".." in Path(absolute).parts:
            raise UpdateError(DENIED)
        return self.jail_root / absolute[1:]


@dataclass(frozen=True)
class FileHash:
    path: str
    size: int
    sha256: str
    executable: bool = False

    def __post_init__(self):
        if type(self.executable) is not bool:
            raise UpdateError(DENIED)


@dataclass(frozen=True)
class LicenseAlias:
    path: str
    target: str


@dataclass(frozen=True)
class Inventory:
    files: tuple[FileHash, ...]
    directories: tuple[str, ...]
    links: tuple[LicenseAlias, ...] = ()


@dataclass(frozen=True)
class StagedUpdate:
    operation: str
    source: SourceReference
    artifacts: tuple[FileHash, ...]
    source_inventory: Inventory
    target_inventory: Inventory
    signature: str
    receipt_sha256: str


@dataclass(frozen=True)
class TargetCodeProof:
    operation: str
    receipt_sha256: str


@dataclass(frozen=True)
class AppStoreSetting:
    exists: bool
    value: bool

    def __post_init__(self):
        if type(self.exists) is not bool or type(self.value) is not bool or (not self.exists and self.value):
            raise UpdateError(DENIED)


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def _none(result):
    if result is not None:
        raise UpdateError(DENIED)


def _guard(context, phase):
    if not isinstance(context, NativeContext) or os.geteuid() != _ROOT_UID:
        raise UpdateError(DENIED)
    _none(context.authority.validate(context, phase))


def _checkpoint(context, event, state, binding):
    _none(context.authority.checkpoint(context, event, state, binding))


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


@contextmanager
def _directory(path, owners=()):
    """Pin every component with openat/O_NOFOLLOW; never resolve jail symlinks."""
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise UpdateError(DENIED)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            # Root-owned sticky ancestors allow private offline test directories.
            sticky = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
            if info.st_uid not in (0, _ROOT_UID, *owners) or (info.st_mode & 0o022 and not sticky):
                raise UpdateError(DENIED)
        yield fd
    finally:
        os.close(fd)


@contextmanager
def _file(path, limit, owners=()):
    path = Path(path)
    with _directory(path.parent, owners) as parent:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_uid not in (_ROOT_UID, *owners) or before.st_mode & 0o7022
                    or not 0 <= before.st_size <= limit):
                raise UpdateError(DENIED)
            yield stream
            after = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if _identity(before) != _identity(after) or _identity(before) != _identity(os.fstat(stream.fileno())):
                raise UpdateError(DENIED)


def _read(path, limit, owners=()):
    with _file(path, limit, owners) as stream:
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise UpdateError(DENIED)
        return data


def _digest(stream, limit, output=None):
    digest, size = hashlib.sha256(), 0
    while True:
        chunk = stream.read(min(CHUNK, limit - size + 1))
        if not chunk:
            break
        size += len(chunk)
        if size > limit:
            raise UpdateError(DENIED)
        digest.update(chunk)
        if output is not None:
            output.write(chunk)
    return digest.hexdigest(), size


def _digest_file(path, limit, owners=()):
    with _file(path, limit, owners) as stream:
        return _digest(stream, limit)


def code_file_identity(stream, item):
    """Authenticate stock bytes or the one reviewed root .htaccess derivation.

    Return the FULL live identity, not a normalized hash, for retained evidence.
    Unknown prefixes, suffixes, webroots and changes to other files still refuse.
    The caller owns no-follow fd/ownership/race checks and archive authority.
    """
    if item.path == ".htaccess":
        if item.executable or type(item.size) is not int or not 0 <= item.size <= 65536:
            raise UpdateError(DENIED)
        content = stream.read(65536 + len(HTACCESS_ROOT_SUFFIX) + 1)
        stock = content
        if len(content) == item.size + len(HTACCESS_ROOT_SUFFIX) and content[item.size:] == HTACCESS_ROOT_SUFFIX:
            stock = content[:item.size]
        if len(stock) != item.size or _hash(stock) != item.sha256:
            raise UpdateError(DENIED)
        return _hash(content), len(content)
    observed = _digest(stream, MAX_FILE)
    if observed != (item.sha256, item.size):
        raise UpdateError(DENIED)
    return observed


def _create(directory, name, *, data=None, source=None, limit=MAX_ARCHIVE):
    # O_EXCL: retain partial evidence and refuse reuse, including failed staging.
    with _directory(directory) as parent:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(fd, "wb") as output:
            if source is not None:
                with _file(source, limit) as stream:
                    digest, size = _digest(stream, limit, output)
            else:
                if len(data) > limit:
                    raise UpdateError(DENIED)
                output.write(data)
                digest, size = _hash(data), len(data)
            output.flush()
            os.fsync(output.fileno())
        os.fsync(parent)
    return FileHash(name, size, digest)


def _mkdir(path):
    with _directory(path.parent) as parent:
        os.mkdir(path.name, 0o700, dir_fd=parent)
        os.fsync(parent)


def canonical_signature(raw):
    """One canonical base64 line, optionally terminated by one LF; <=2 KiB."""
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= 2048:
        raise UpdateError(DENIED)
    value = raw[:-1] if raw.endswith(b"\n") else raw
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError:
        raise UpdateError(DENIED) from None
    if not decoded or base64.b64encode(decoded) != value:
        raise UpdateError(DENIED)
    return value.decode("ascii")


def _version(data, expected):
    if len(data) > 65536:
        raise UpdateError(DENIED)
    text = data.decode("utf-8")
    assignments = re.findall(r"\$OC_Version\s*=\s*(?:\[([^\]]*)\]|array\(([^)]*)\))\s*;", text)
    strings = re.findall(r"\$OC_VersionString\s*=\s*['\"]([0-9.]+)['\"]\s*;", text)
    channels = re.findall(r"\$OC_Channel\s*=\s*['\"]([^'\"]+)['\"]\s*;", text)
    if (len(assignments) != 1 or strings != [expected[0]] or channels != ["stable"]
            or len(re.findall(r"\$OC_Version\s*=", text)) != 1):
        raise UpdateError(DENIED)
    numbers = (assignments[0][0] or assignments[0][1]).split(",")
    if len(numbers) != 4 or any(not re.fullmatch(r"\s*[0-9]+\s*", n) for n in numbers):
        raise UpdateError(DENIED)
    if ".".join(str(int(n)) for n in numbers) != expected[1]:
        raise UpdateError(DENIED)


def _member(name, directory, seen):
    if (not isinstance(name, str) or len(name) > 1024 or "\\" in name or ":" in name
            or any(ord(c) < 32 or ord(c) > 126 for c in name)):
        raise UpdateError(DENIED)
    parts = name.rstrip("/").split("/")
    if parts[0] != "nextcloud" or any(p in ("", ".", "..") for p in parts):
        raise UpdateError(DENIED)
    relative = "/".join(parts[1:])
    if not relative and not directory:
        raise UpdateError(DENIED)
    if (parts[1:2] and parts[1] in ("data", "custom_apps", "tls")
            or relative == "config/config.php"):
        raise UpdateError(DENIED)
    # Track implicit parents as well: case aliases and file/directory conflicts
    # must fail even when the archive omits explicit directory entries.
    for index in range(1, len(parts)):
        parent = "/".join(parts[1:index])
        old = seen.get(parent.casefold())
        if old is not None and (old[0] != parent or not old[1]):
            raise UpdateError(DENIED)
        if old is None:
            seen[parent.casefold()] = (parent, True, False)
    key = relative.casefold()
    old = seen.get(key)
    if old is not None and (old[0] != relative or old[2] or not directory or not old[1]):
        raise UpdateError(DENIED)
    seen[key] = (relative, directory, True)
    if len(seen) > MAX_ENTRIES * 4:
        raise UpdateError(DENIED)
    return relative


def _inventory(entries, expected):
    files, directories, links, seen, total, special = [], [], [], {}, 0, {}
    for number, entry in enumerate(entries, 1):
        if number > MAX_ENTRIES:
            raise UpdateError(DENIED)
        if isinstance(entry, LicenseAlias):
            relative = _member(entry.path, False, seen)
            links.append(LicenseAlias(relative, entry.target))
            continue
        name, directory, size, mode, opener = entry
        relative = _member(name, directory, seen)
        if directory:
            if size:
                raise UpdateError(DENIED)
            directories.append(relative)
            continue
        total += size
        if not 0 <= size <= MAX_FILE or total > MAX_EXPANDED:
            raise UpdateError(DENIED)
        with opener() as stream:
            if relative in ("version.php", CERT):
                data = stream.read(65537)
                if len(data) != size or len(data) > 65536:
                    raise UpdateError(DENIED)
                special[relative] = data
                digest, actual = _hash(data), len(data)
            else:
                digest, actual = _digest(stream, size)
        if actual != size:
            raise UpdateError(DENIED)
        # Match installation's chmod u=rwX,g=rX,o=: any archive execute bit
        # becomes owner/group execute, never an arbitrary live-tree permission.
        files.append(FileHash(relative, size, digest, bool(mode & 0o111)))
    _version(special.get("version.php", b""), expected)
    if not {PHAR, CERT, "occ"}.issubset({f.path for f in files}):
        raise UpdateError(DENIED)
    inventory = Inventory(tuple(sorted(files, key=lambda f: f.path)), tuple(sorted(directories)),
                          tuple(sorted(links, key=lambda f: f.path)))
    if links and expected != SOURCE:
        raise UpdateError(DENIED)
    source_aliases(inventory)
    return inventory, special[CERT]


def _alias_target(target):
    if (type(target) is not str or not target.endswith(".license") or len(target) > 1024
            or target in (".", "..") or any(c in target for c in ("/", "\\", ":"))
            or any(ord(c) < 32 or ord(c) > 126 for c in target)):
        raise UpdateError(DENIED)
    return target


def source_aliases(inventory):
    """Exact reviewed source-only topology; no filesystem dereference or inference.

    The signed source inventory binds link text separately from regular target
    bytes. Empty legacy inventories retain their original no-links meaning.
    """
    aliases = {}
    files = {item.path: item for item in inventory.files}
    for link in inventory.links:
        if (type(link) is not LicenseAlias or type(link.path) is not str or link.path in aliases
                or not link.path.endswith(".license")):
            raise UpdateError(DENIED)
        _member("nextcloud/" + link.path, False, {})
        target = _alias_target(link.target)
        if link.path in files:
            raise UpdateError(DENIED)
        aliases[link.path] = target
    if aliases and _hash(json.dumps(aliases, sort_keys=True, separators=(",", ":")).encode()) != SOURCE_ALIASES_SHA256:
        raise UpdateError(DENIED)
    # The exact reviewed map contains one two-hop license alias. Resolve only
    # metadata, never filesystem paths; cycles/deeper chains remain forbidden.
    for path in aliases:
        seen = set()
        destination = path
        while destination in aliases:
            if destination in seen or len(seen) >= 2:
                raise UpdateError(DENIED)
            seen.add(destination)
            destination = str(Path(destination).parent / aliases[destination])
        regular = files.get(destination)
        if regular is None or regular.executable:
            raise UpdateError(DENIED)
    return aliases


def inventory_receipt(source, target):
    """Preserve legacy receipt keys/bytes when no source aliases are present."""
    source_aliases(source)
    if target.links:
        raise UpdateError(DENIED)
    result = dict(source_files=[asdict(item) for item in source.files], source_directories=list(source.directories),
                  target_files=[asdict(item) for item in target.files], target_directories=list(target.directories))
    if source.links:
        result["source_links"] = [asdict(item) for item in source.links]
    return result


def inventory_record(inventory):
    """Canonical inventory representation, preserving legacy link-free hashes."""
    result = asdict(inventory)
    if not inventory.links:
        result.pop("links")
    return result


def bundle_record(bundle):
    """Canonical prepared/candidate bundle; never retrofit stored documents."""
    result = asdict(bundle)
    result["source_inventory"] = inventory_record(bundle.source_inventory)
    result["target_inventory"] = inventory_record(bundle.target_inventory)
    return result


class _BoundedTarInfo(tarfile.TarInfo):
    def _proc_member(self, tar):
        # Reject extension headers before tarfile reads attacker-sized PAX/GNU
        # payloads. Bounded long paths are needed by official distribution trees.
        tar._cloud_headers = getattr(tar, "_cloud_headers", 0) + 1
        if tar._cloud_headers > MAX_ENTRIES * 2:
            raise UpdateError(DENIED)
        if self.type in (tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK):
            tar._cloud_metadata = getattr(tar, "_cloud_metadata", 0) + self.size
            limit = 1025 if self.type == tarfile.GNUTYPE_LONGLINK else 65536
            if not 0 <= self.size <= limit or tar._cloud_metadata > MAX_CENTRAL:
                raise UpdateError(DENIED)
        elif self.type == tarfile.SYMTYPE:
            if self.size != 0:
                raise UpdateError(DENIED)
        elif self.type not in (tarfile.DIRTYPE, tarfile.REGTYPE, tarfile.AREGTYPE) or not 0 <= self.size <= MAX_FILE:
            raise UpdateError(DENIED)
        return super()._proc_member(tar)


def _source_inventory(path):
    with _file(path, MAX_ARCHIVE) as source:
        with tarfile.open(fileobj=source, mode="r|bz2", tarinfo=_BoundedTarInfo) as archive:
            def entries():
                for member in archive:
                    if (member.type not in (tarfile.DIRTYPE, tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.SYMTYPE)
                            or member.mode & 0o7000 or member.pax_headers):
                        raise UpdateError(DENIED)
                    if member.issym():
                        _alias_target(member.linkname)
                        yield LicenseAlias(member.name, member.linkname)
                        continue
                    yield member.name, member.isdir(), member.size, member.mode, lambda m=member: archive.extractfile(m)
            return _inventory(entries(), SOURCE)


def _zip_inventory(path):
    with _file(path, MAX_ARCHIVE) as source:
        # Bound the central directory BEFORE ZipFile materializes its inventory.
        source.seek(0, os.SEEK_END)
        length = source.tell()
        if length < 22:
            raise UpdateError(DENIED)
        source.seek(-22, os.SEEK_END)
        magic, disk, start, count, total, size, offset, comment = struct.unpack("<4s4H2LH", source.read(22))
        if (magic != b"PK\x05\x06" or disk or start or comment or count != total
                or not 1 <= count < min(MAX_ENTRIES, 65535) or size > MAX_CENTRAL
                or offset + size != length - 22):
            raise UpdateError(DENIED)
        source.seek(0)
        with zipfile.ZipFile(source) as archive:
            def entries():
                for member in archive.infolist():
                    mode = member.external_attr >> 16
                    kind = stat.S_IFMT(mode)
                    if (member.orig_filename != member.filename or member.flag_bits & 1
                            or member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                            or kind not in (0, stat.S_IFDIR if member.is_dir() else stat.S_IFREG)
                            or mode & 0o7000):
                        raise UpdateError(DENIED)
                    yield member.filename, member.is_dir(), member.file_size, mode, lambda m=member: archive.open(m)
            return _inventory(entries(), TARGET)[0]


def decode_bundle(value):
    """Decode an exact public receipt shape; this grants no execution authority.

    Callers must independently bind the retained record and reauthenticate its
    archives before trusting these inventories, including their executable bits.
    Missing fields are refused even where Python fixture constructors default.
    """
    def shape(item, cls):
        if type(item) is not dict or set(item) != {field.name for field in fields(cls)}:
            raise UpdateError(DENIED)

    def digest(value):
        if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise UpdateError(DENIED)

    def records(items, *, artifacts=False):
        if type(items) is not list or not 0 < len(items) <= MAX_ENTRIES:
            raise UpdateError(DENIED)
        result, seen, total = [], set(), 0
        for item in items:
            shape(item, FileHash)
            name = item["path"]
            if (type(name) is not str or not name or name.casefold() in seen
                    or _member("nextcloud/" + name, False, {}) != name
                    or (artifacts and ("/" in name or item["executable"] is not False))
                    or type(item["size"]) is not int
                    or not 0 <= item["size"] <= (MAX_ARCHIVE if artifacts else MAX_FILE)
                    or type(item["executable"]) is not bool):
                raise UpdateError(DENIED)
            digest(item["sha256"])
            total += item["size"]
            if total > MAX_EXPANDED:
                raise UpdateError(DENIED)
            seen.add(name.casefold())
            result.append(FileHash(**item))
        return tuple(result)

    def inventory(item, *, source=False):
        if type(item) is not dict or set(item) not in ({"files", "directories"}, {"files", "directories", "links"}):
            raise UpdateError(DENIED)
        files = records(item["files"])
        directories = item["directories"]
        if type(directories) is not list or len(directories) > MAX_ENTRIES:
            raise UpdateError(DENIED)
        seen = {}
        for name in directories:
            if type(name) is not str or _member("nextcloud/" + name, True, seen) != name:
                raise UpdateError(DENIED)
        for record in files:
            _member("nextcloud/" + record.path, False, seen)
        raw_links = item.get("links", [])
        if type(raw_links) is not list or len(raw_links) > MAX_ENTRIES or raw_links and not source:
            raise UpdateError(DENIED)
        links = []
        for link in raw_links:
            shape(link, LicenseAlias)
            if type(link["path"]) is not str:
                raise UpdateError(DENIED)
            _member("nextcloud/" + link["path"], False, seen)
            links.append(LicenseAlias(**link))
        result = Inventory(files, tuple(directories), tuple(links))
        source_aliases(result)
        return result

    shape(value, StagedUpdate)
    if (type(value["operation"]) is not str
            or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", value["operation"]) is None
            or type(value["signature"]) is not str):
        raise UpdateError(DENIED)
    try:
        signature = canonical_signature(value["signature"].encode("ascii"))
    except UnicodeError:
        raise UpdateError(DENIED) from None
    if signature != value["signature"]:
        raise UpdateError(DENIED)
    shape(value["source"], SourceReference)
    for field in value["source"].values():
        digest(field)
    digest(value["receipt_sha256"])
    return StagedUpdate(value["operation"], SourceReference(**value["source"]),
                        records(value["artifacts"], artifacts=True),
                         inventory(value["source_inventory"], source=True), inventory(value["target_inventory"]),
                        signature, value["receipt_sha256"])


def _native(context, phase, argv, *, stdin=b"", event=None, binding="", output_limit=65536):
    """Runner must bound captured output, retain stderr privately and honor timeout.

    env replaces (never merges) the inherited environment; stdin is explicit.
    No native runner is installed here. Postidentity checks run even on failure.
    """
    _guard(context, phase)
    if event:
        _checkpoint(context, event, "before", binding)
    try:
        try:
            result = context.runner(
                ("/usr/sbin/jexec", str(context.jid), *argv), stdin=stdin,
                env={"PATH": "/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin", "LC_ALL": "C"},
                timeout=3600, output_limit=output_limit)
        finally:
            _guard(context, phase)
        if (not isinstance(result, NativeResult) or type(result.returncode) is not int
                or result.returncode != 0 or not isinstance(result.stdout, bytes)
                or len(result.stdout) > output_limit):
            raise UpdateError(DENIED)
    except Exception:
        raise UpdateError(DENIED) from None
    if event:
        _checkpoint(context, event, "after", binding)
    return result.stdout


def _pgp_valid(status):
    valid = False
    for line in status.decode("ascii").splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] == "[GNUPG:]":
            if fields[1] in {"BADSIG", "ERRSIG", "REVKEYSIG", "EXPKEYSIG", "EXPSIG", "NO_PUBKEY", "FAILURE"}:
                raise UpdateError(DENIED)
            if fields[1] == "VALIDSIG":
                if len(fields) not in (11, 12) or RELEASE_KEY not in (fields[2], fields[11] if len(fields) == 12 else ""):
                    raise UpdateError(DENIED)
                valid = True
    if not valid:
        raise UpdateError(DENIED)


def _php(context):
    return ("/usr/bin/mdo", "-u", "www", "/usr/local/bin/php", "-d", f"memory_limit={context.memory_mib}M",
            "-d", "log_errors=0", "-d", "display_errors=0", "-d", "zend.exception_ignore_args=1")


_VERIFY_SIGNATURE = b'''<?php
$zip = file_get_contents($argv[1]);
$sig = base64_decode(trim(file_get_contents($argv[2])), true);
$cert = file_get_contents($argv[3]);
exit(is_string($zip) && is_string($sig) && is_string($cert) &&
    openssl_verify($zip, $sig, $cert, OPENSSL_ALGO_SHA512) === 1 ? 0 : 1);
'''


def _source_bound(context, reference):
    if (_digest_file(context.host(RETAINED), MAX_ARCHIVE)[0] != reference.archive_sha256
            or _hash(_read(context.host(SHA_PROOF), 128)) != reference.proof_sha256):
        raise UpdateError(DENIED)


def stage_artifacts(context, *, target_zip, target_asc, target_sig, source_asc, public_key):
    """Authenticate public artifacts before any application mutation.

    Caller creates a root-owned 0700 STAGING parent through its storage guard.
    A new operation directory is exclusive and never cleaned up automatically.
    Hashes are byte bindings, NOT substitutes for source provenance or signatures.
    source_asc authenticates the retained installation tarball with RELEASE_KEY;
    it does not authorize adopting an operator-supplied replacement source hash.
    Source inventory/version, certificate and PHAR are trusted only after this
    independent verification and rechecking original archive/proof byte bindings.
    """
    _guard(context, Phase.ARTIFACTS)
    reference = SourceReference(_digest_file(context.host(RETAINED), MAX_ARCHIVE)[0],
                                _hash(_read(context.host(SHA_PROOF), 128)))
    proof = _read(context.host(SHA_PROOF), 128)
    if proof not in (reference.archive_sha256.encode(), (reference.archive_sha256 + "\n").encode()):
        raise UpdateError(DENIED)
    _none(context.authority.source(context, reference))
    directory = context.host(context.stage)
    _checkpoint(context, "stage-artifacts", "before", reference.archive_sha256)
    _mkdir(directory)
    records = []
    for name, path, limit in (("nextcloud-35.0.2.zip", target_zip, MAX_ARCHIVE),
                              ("nextcloud-35.0.2.zip.asc", target_asc, 65536),
                              ("nextcloud-35.0.2.zip.sig", target_sig, 2048),
                              ("nextcloud-35.0.1.tar.bz2.asc", source_asc, 65536),
                              ("nextcloud.asc", public_key, 1024 * 1024)):
        records.append(_create(directory, name, source=Path(path), limit=limit))
    by_name = {record.path: record for record in records}
    signature = canonical_signature(_read(directory / "nextcloud-35.0.2.zip.sig", 2048))
    # The source updater reads the full archive into PHP memory; the parent must
    # also prove real capacity, this conservative arithmetic is only a lower gate.
    if context.memory_mib * 1024 * 1024 < 3 * by_name["nextcloud-35.0.2.zip"].size + 256 * 1024 * 1024:
        raise UpdateError(DENIED)
    _mkdir(directory / "gnupg")
    gpg = ("/usr/local/bin/gpg", "--no-options", "--homedir", context.stage + "/gnupg",
           "--batch", "--no-tty", "--no-auto-key-retrieve", "--auto-key-locate", "clear")
    _native(context, Phase.ARTIFACTS, (*gpg, "--import", context.stage + "/nextcloud.asc"),
            event="import-release-key", binding=by_name["nextcloud.asc"].sha256)
    _source_bound(context, reference)
    source_status = _native(context, Phase.ARTIFACTS, (*gpg, "--status-fd", "1", "--verify",
                            context.stage + "/nextcloud-35.0.1.tar.bz2.asc", RETAINED))
    _pgp_valid(source_status)
    _source_bound(context, reference)
    source_inventory, cert = _source_inventory(context.host(RETAINED))
    _source_bound(context, reference)
    source_files = {item.path: item for item in source_inventory.files}
    for name in (PHAR, CERT):
        digest, size = _digest_file(context.host(APP + "/" + name), MAX_FILE)
        if (digest, size) != (source_files[name].sha256, source_files[name].size):
            raise UpdateError(DENIED)
    records.append(_create(directory, "source-core.crt", data=cert))
    status = _native(context, Phase.ARTIFACTS, (*gpg, "--status-fd", "1", "--verify",
                     context.stage + "/nextcloud-35.0.2.zip.asc", context.stage + "/nextcloud-35.0.2.zip"))
    _pgp_valid(status)
    # Fixed PHP/OpenSSL verifier uses certificate bytes from the authenticated
    # retained source archive, not an operator-selected trust file. Run as root
    # while public staging remains 0700/0600; no application config is loaded.
    _native(context, Phase.ARTIFACTS,
            ("/usr/local/bin/php", "-d", f"memory_limit={context.memory_mib}M", "-d", "display_errors=0",
             "-d", "log_errors=0", "-r", _VERIFY_SIGNATURE.decode().removeprefix("<?php\n"),
             "--", context.stage + "/nextcloud-35.0.2.zip", context.stage + "/nextcloud-35.0.2.zip.sig",
             context.stage + "/source-core.crt"))
    target_inventory = _zip_inventory(directory / "nextcloud-35.0.2.zip")
    _source_bound(context, reference)
    for record in records:
        if _digest_file(directory / record.path, MAX_ARCHIVE) != (record.sha256, record.size):
            raise UpdateError(DENIED)
    receipt = json.dumps({
        "source": reference.__dict__, "source_version": SOURCE, "target_version": TARGET,
        "operation": context.operation, "key": RELEASE_KEY,
        "artifacts": [r.__dict__ for r in records],
        **inventory_receipt(source_inventory, target_inventory),
    }, sort_keys=True, separators=(",", ":")).encode()
    record = _create(directory, "receipt.json", data=receipt, limit=MAX_CENTRAL)
    bundle = StagedUpdate(context.operation, reference, tuple(records), source_inventory,
                          target_inventory, signature, record.sha256)
    _guard(context, Phase.ARTIFACTS)
    _checkpoint(context, "stage-artifacts", "after", record.sha256)
    return bundle


def _bound(context, bundle, phase):
    _guard(context, phase)
    if not isinstance(bundle, StagedUpdate) or bundle.operation != context.operation:
        raise UpdateError(DENIED)
    _none(context.authority.artifacts(context, bundle))
    directory = context.host(context.stage)
    if _digest_file(directory / "receipt.json", MAX_CENTRAL)[0] != bundle.receipt_sha256:
        raise UpdateError(DENIED)
    for record in bundle.artifacts:
        if _digest_file(directory / record.path, MAX_ARCHIVE) != (record.sha256, record.size):
            raise UpdateError(DENIED)
    if canonical_signature(_read(directory / "nextcloud-35.0.2.zip.sig", 2048)) != bundle.signature:
        raise UpdateError(DENIED)


def expose_target_zip(context, bundle):
    """Journal only the public ZIP's read access; no writable www staging files."""
    _bound(context, bundle, Phase.CONFIG)
    _checkpoint(context, "expose-target-zip", "before", bundle.receipt_sha256)
    # Parent must arrange root:www 0710 traversal on STAGING itself. This new
    # operation directory becomes root:www 0710; all siblings remain 0600.
    with _directory(context.host(context.stage)) as parent:
        fd = os.open("nextcloud-35.0.2.zip", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != _ROOT_UID:
                raise UpdateError(DENIED)
            os.fchown(fd, _ROOT_UID, context.www_gid)
            os.fchmod(fd, 0o640)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fchown(parent, _ROOT_UID, context.www_gid)
        os.fchmod(parent, 0o710)
        os.fsync(parent)
    _guard(context, Phase.CONFIG)
    _checkpoint(context, "expose-target-zip", "after", bundle.receipt_sha256)


_CONFIG_PROBE = b'''<?php
ob_start(); $CONFIG = []; require '/usr/local/www/nextcloud/config/config.php'; ob_end_clean();
$exists = array_key_exists('appstoreenabled', $CONFIG);
if (($exists && !is_bool($CONFIG['appstoreenabled'])) || ($CONFIG['maintenance'] ?? null) !== true ||
    ($CONFIG['updater.release.channel'] ?? 'stable') !== 'stable') { exit(1); }
echo json_encode(['exists' => $exists, 'value' => $exists ? $CONFIG['appstoreenabled'] : false]);
'''

_UPDATER_STATE = b'''<?php
ob_start(); $CONFIG = []; require '/usr/local/www/nextcloud/config/config.php'; ob_end_clean();
$id = $CONFIG['instanceid'] ?? null;
if (!is_string($id) || !preg_match('/^[a-zA-Z0-9]{1,64}$/D', $id) ||
    ($CONFIG['datadirectory'] ?? null) !== '/var/nc-data') { exit(1); }
$directory = '/var/nc-data/updater-' . $id;
if (is_link('/var/nc-data') || is_link($directory) ||
    file_exists($directory . '/.step') || is_link($directory . '/.step')) { exit(1); }
'''


def probe_appstore(context, *, phase=Phase.CONFIG):
    if phase not in (Phase.CONFIG, Phase.UPDATER, Phase.MIGRATION, Phase.RESTORE_CONFIG):
        raise UpdateError(DENIED)
    _guard(context, phase)
    path = context.host(APP + "/config/config.php")
    with _file(path, 1024 * 1024, (context.www_uid,)) as stream:
        info = os.fstat(stream.fileno())
        if info.st_uid != context.www_uid or stat.S_IMODE(info.st_mode) != 0o600:
            raise UpdateError(DENIED)
    raw = _native(context, phase, (*_php(context), "--"), stdin=_CONFIG_PROBE, output_limit=128)
    try:
        value = json.loads(raw)
        if set(value) != {"exists", "value"}:
            raise ValueError
        return AppStoreSetting(**value)
    except (ValueError, TypeError):
        raise UpdateError(DENIED) from None


def suppress_appstore(context, original):
    if not isinstance(original, AppStoreSetting) or probe_appstore(context) != original:
        raise UpdateError(DENIED)
    binding = json.dumps(original.__dict__, sort_keys=True)
    _native(context, Phase.CONFIG, (*_php(context), APP + "/occ", "--no-interaction",
            "config:system:set", "appstoreenabled", "--type=boolean", "--value=false"),
            event="suppress-appstore", binding=binding)
    if probe_appstore(context) != AppStoreSetting(True, False):
        raise UpdateError(DENIED)


def restore_appstore(context, original):
    """Only under closure; parent must bind original to the suppression record."""
    if not isinstance(original, AppStoreSetting):
        raise UpdateError(DENIED)
    if probe_appstore(context, phase=Phase.RESTORE_CONFIG) != AppStoreSetting(True, False):
        raise UpdateError(DENIED)
    args = (("config:system:set", "appstoreenabled", "--type=boolean", "--value=" + str(original.value).lower())
            if original.exists else ("config:system:delete", "appstoreenabled"))
    _native(context, Phase.RESTORE_CONFIG, (*_php(context), APP + "/occ", "--no-interaction", *args),
            event="restore-appstore", binding=json.dumps(original.__dict__, sort_keys=True))
    if probe_appstore(context, phase=Phase.RESTORE_CONFIG) != original:
        raise UpdateError(DENIED)


def invoke_updater(context, bundle):
    """One attempt only. Success is NOT target-code or migration proof."""
    _bound(context, bundle, Phase.UPDATER)
    source = next(item for item in bundle.source_inventory.files if item.path == PHAR)
    if _digest_file(context.host(APP + "/" + PHAR), MAX_FILE, (context.www_uid,)) != (source.sha256, source.size):
        raise UpdateError(DENIED)
    if probe_appstore(context, phase=Phase.UPDATER) != AppStoreSetting(True, False):
        raise UpdateError(DENIED)
    _version(_read(context.host(APP + "/version.php"), 65536, (context.www_uid,)), SOURCE)
    _native(context, Phase.UPDATER, (*_php(context), "--"), stdin=_UPDATER_STATE)
    _native(context, Phase.UPDATER, (*_php(context), APP + "/" + PHAR,
            "--no-interaction", "--no-upgrade", "--url", "file://" + context.stage + "/nextcloud-35.0.2.zip",
            "--signature", bundle.signature), event="updater", binding=bundle.receipt_sha256)


def verify_target_code(context, bundle):
    """Independently hash ALL target files, then require native integrity JSON.

    Conservatively rejects modified distributed files, including .user.ini; the
    parent must also reject unexpected core files/apps and check live inventories.
    Neither updater exit status nor absence of .step is used as evidence.
    """
    _bound(context, bundle, Phase.TARGET)
    _target_bytes(context, bundle)
    output = _native(context, Phase.TARGET, (*_php(context), APP + "/occ", "--no-interaction",
                     "integrity:check-core", "--output=json"),
                     event="target-integrity", binding=bundle.receipt_sha256)
    if output.strip() != b"[]":
        raise UpdateError(DENIED)
    _checkpoint(context, "target-code-verified", "after", bundle.receipt_sha256)
    return TargetCodeProof(context.operation, bundle.receipt_sha256)


def _target_bytes(context, bundle):
    for item in bundle.target_inventory.files:
        with _file(context.host(APP + "/" + item.path), MAX_FILE, (context.www_uid,)) as stream:
            code_file_identity(stream, item)


def migrate(context, bundle, proof):
    """Separate one-shot occ upgrade. Maintenance stays enabled; no publication."""
    _bound(context, bundle, Phase.MIGRATION)
    if proof != TargetCodeProof(context.operation, bundle.receipt_sha256):
        raise UpdateError(DENIED)
    # Re-probe all bytes rather than relying on a serializable proof token. The
    # parent MIGRATION guard must bind the prior target-code-verified checkpoint;
    # integrity:check-core can persist results, so it is itself a one-shot effect.
    _target_bytes(context, bundle)
    if probe_appstore(context, phase=Phase.MIGRATION) != AppStoreSetting(True, False):
        raise UpdateError(DENIED)
    _native(context, Phase.MIGRATION, (*_php(context), APP + "/occ", "--no-interaction", "upgrade"),
            event="occ-upgrade", binding=bundle.receipt_sha256)
    if probe_appstore(context, phase=Phase.MIGRATION) != AppStoreSetting(True, False):
        raise UpdateError(DENIED)
