"""Private separate-pool recovery streams. Trusted lock-scoped caller API only.

No production admission, pool creation, application restore, or physical-disk
independence claim. Failed staging/receives are retained for manual assessment.
Receipt references must be retained by the caller, never reconstructed from an
untrusted bundle. Stream adapters are executable trusted code, not JSON inputs.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time
from functools import wraps
from typing import Protocol

from . import recovery_sets as recovery

SCOPE = "separate-zfs-pool; physical independence unassessed"
PURPOSE = "org.cloud-installer:purpose"
DESTINATION_PURPOSE = "maintenance-recovery"
DENIED = "Recovery export refused; retain private staging for explicit recovery assessment"
NAME = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]*(?:/[A-Za-z0-9][A-Za-z0-9_.:-]*)*\Z")
BUNDLE = re.compile(r"ci-([a-z][a-z0-9]{0,7})-([A-Za-z0-9][A-Za-z0-9_-]{0,79})\Z")


def _require(ok):
    recovery._require(ok, DENIED)


def _fields(value, keys):
    _require(type(value) is dict and set(value) == set(keys.split()))


def _guard(function):
    @wraps(function)
    def guarded(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except BaseException:
            raise recovery.RecoveryError(DENIED) from None
    return guarded


def _require_root():
    _require(os.geteuid() == 0)


class Context(Protocol):
    backend: recovery.NativeBackend

    def check(self, *, closed=False): ...
    def _recovery_context(self, *, readonly=False) -> recovery.RecoveryContext: ...


class StreamRunner(Protocol):
    def send(self, snapshot: str, fd: int, limit: int): ...
    def receive(self, target: str, fd: int, size: int, properties: tuple[str, ...]): ...


class NativeStreams:
    """Bounded pipe; no captured stream/stderr, inherited secrets, or other PIDs."""

    def __init__(self, timeout=3600):
        self.timeout = timeout

    def send(self, snapshot, fd, limit):
        self._pipe(("zfs", "send", "-p", snapshot), fd, limit, sending=True)

    def receive(self, target, fd, size, properties):
        self._pipe(("zfs", "receive", "-u", "-o", "canmount=off", "-o", "mountpoint=none",
                    *(arg for prop in properties for arg in ("-o", prop)), target), fd, size, sending=False)

    def _pipe(self, argv, fd, limit, *, sending):
        end = time.monotonic() + self.timeout
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL if sending else subprocess.PIPE,
            stdout=subprocess.PIPE if sending else subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True, close_fds=True, env={"PATH": "/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin"})
        pipe = process.stdout if sending else process.stdin
        try:
            os.set_blocking(pipe.fileno(), False)
            total, pending = 0, b""
            with selectors.DefaultSelector() as selector:
                selector.register(pipe, selectors.EVENT_READ if sending else selectors.EVENT_WRITE)
                while True:
                    remaining = end - time.monotonic()
                    _require(remaining > 0)
                    if not selector.select(min(remaining, 1)):
                        continue
                    if sending:
                        data = os.read(pipe.fileno(), 1024 * 1024)
                        if not data:
                            break
                        total += len(data)
                        _require(total <= limit)
                        view = memoryview(data)
                        while view:
                            view = view[os.write(fd, view):]
                    else:
                        if not pending:
                            pending = os.read(fd, min(1024 * 1024, limit - total + 1))
                        if not pending:
                            _require(total == limit)
                            break
                        _require(total + len(pending) <= limit)
                        count = os.write(pipe.fileno(), pending)
                        total += count
                        pending = pending[count:]
            pipe.close()
            _require(process.wait(timeout=max(0.001, end - time.monotonic())) == 0 and total > 0)
        except BaseException:
            # Only this newly created session/process group. KILL also handles STOP.
            if process.returncode is None:  # Unreaped PID cannot have been reused.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.wait()
            raise recovery.RecoveryError(DENIED) from None
        finally:
            pipe.close()


def _private(path, directory=False):
    path = recovery._path(path, directory=directory)
    info = path.lstat()
    _require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600))
    return path


def _sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write(path, data):
    _private(path.parent, True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    _sync(path.parent)


def _file(path, limit):
    _private(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(fd)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit)
        digest, size = hashlib.sha256(), 0
        while data := stream.read(1024 * 1024):
            size += len(data)
            _require(size <= limit)
            digest.update(data)
        after = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_mode, s.st_uid, s.st_nlink)
        _require(identity(before) == identity(after) == identity(path.lstat()) and size == before.st_size)
    return {"sha256": digest.hexdigest(), "size": size}


def _source(ctx):
    _require_root()
    ctx.check(closed=True)  # NativeContext checks held global/database locks.
    c, b = ctx._recovery_context(), ctx.backend
    _require(c.schema_version == 2 and len(c.resources) == 14 and isinstance(b, recovery.NativeBackend))
    proof = recovery._boundary(c, "capture")  # Initial clean shutdown, stable closed pair.
    path = _private(c.directory / "manifest.json")
    value = recovery.validate_manifest(c, recovery._load(path))
    recovery._capture_identity(c, value, proof)
    _require(b.storage(c) == value["datasets"] and b.snapshots(c, value["datasets"]) == value["snapshots"])
    _require(recovery._copies(c) == value["evidence"])
    return c, b, value, _file(path, recovery.MAX_FILE)


def _name(name):
    _require(isinstance(name, str) and NAME.fullmatch(name) is not None)
    return name


def _topology(c, b, name, *, owned=False):
    _name(name)
    if not owned:
        _local(b, name, recovery.MANAGER, "cloud-installer")
        _local(b, name, PURPOSE, DESTINATION_PURPOSE)
    pool = name.split("/")[0]
    _require(pool != c.config.pool and b.get(name, "type") == "filesystem" and b.get(name, "origin") == "-")
    poolguid = b.output("zpool", "get", "-Hp", "-o", "value", "guid", pool)
    sourceguid = b.output("zpool", "get", "-Hp", "-o", "value", "guid", c.config.pool)
    recovery._number(poolguid, True)
    recovery._number(sourceguid, True)
    _require(poolguid != sourceguid)
    mount = b.get(name, "mountpoint")
    _require(mount.startswith("/") and str(Path(mount)) == mount and ".." not in Path(mount).parts
             and not any(recovery._related(mount, r.mountpoint) for r in c.resources)
             and not recovery._related(mount, str(c.directory)))
    _private(Path(mount), True)
    _require(b.get(name, "mounted") == "yes" and b.output("realpath", mount) == mount)
    rows = [line.split() for line in b.output("mount", "-p").splitlines()]
    _require(all(len(row) == 6 for row in rows))
    _require([r[:3] for r in rows if r[0] == name or r[1] == mount] == [[name, mount, "zfs"]])
    _require(not any(r[2] == "nullfs" and (recovery._related(r[0], mount) or recovery._related(r[1], mount)) for r in rows))
    if owned:
        _require(not any(r[1].startswith(mount + "/") for r in rows))
    else:
        _parent_children(b, name, mount, rows)
    df = b.output("df", "-P", mount).splitlines()
    _require(len(df) == 2 and len(df[-1].split()) == 6
             and df[-1].split()[0] == name and df[-1].split()[-1] == mount)
    guid = b.get(name, "guid")
    recovery._number(guid, True)
    if owned:
        for prop in _properties(c):
            key, value = prop.split("=", 1)
            _local(b, name, key, value)
    return dict(dataset=name, guid=guid, pool_guid=poolguid, mountpoint=mount)


def _local(b, name, key, value):
    _require(b.output("zfs", "get", "-Hp", "-o", "value,source", key, name).split() == [value, "local"])


def _parent_children(b, parent, mount, rows):
    """Inspect only public identities of existing direct-child operation bundles."""
    seen = set()
    for row in rows:
        name, path, kind = row[:3]
        if not (name.startswith(parent + "/") or path.startswith(mount + "/")):
            continue
        suffix = name.removeprefix(parent + "/")
        match = BUNDLE.fullmatch(suffix)
        _require(kind == "zfs" and name.startswith(parent + "/") and match is not None
                 and path == mount + "/" + suffix and name not in seen)
        seen.add(name)
        for key, value in ((recovery.MANAGER, "cloud-installer"),
                           (recovery.OWNER, match[1]), (recovery.TOKEN, match[2])):
            _local(b, name, key, value)
        for key, value in (("type", "filesystem"), ("origin", "-"), ("mounted", "yes"), ("mountpoint", path)):
            _require(b.get(name, key) == value)
        recovery._number(b.get(name, "guid"), True)
        _private(Path(path), True)
        _require(b.output("realpath", path) == path)
        df = b.output("df", "-P", path).splitlines()
        _require(len(df) == 2 and len(df[-1].split()) == 6
                  and df[-1].split()[0] == name and df[-1].split()[-1] == path)
    # Mount inventory alone omits dormant datasets and volumes. Retain known
    # operation-owned nonmounting receive trees too; inspecting their topology
    # does not adopt them or claim their streams have passed rehearsal.
    descendants = b.output("zfs", "list", "-H", "-o", "name", "-r", "-t", "filesystem,volume", parent).splitlines()
    _require(len(descendants) == len(set(descendants)) and {parent, *seen} <= set(descendants))
    dormant = set(descendants) - {parent, *seen}
    for name in dormant:
        bundles = [bundle for bundle in seen if name.startswith(bundle + "/")]
        _require(len(bundles) == 1)
        bundle = bundles[0]
        parts = name[len(bundle) + 1:].split("/")
        _require(1 <= len(parts) <= 2 and NAME.fullmatch(parts[0]) is not None)
        if len(parts) == 2:
            _require(parts[1] in {f"member-{index:02d}" for index in range(14)}
                     and bundle + "/" + parts[0] in dormant)
        match = BUNDLE.fullmatch(bundle.removeprefix(parent + "/"))
        for key, value in ((recovery.MANAGER, "cloud-installer"),
                           (recovery.OWNER, match[1]), (recovery.TOKEN, match[2])):
            _local(b, name, key, value)
        for key, value in (("type", "filesystem"), ("origin", "-"), ("mounted", "no"),
                           ("canmount", "off"), ("mountpoint", "none")):
            _require(b.get(name, key) == value)
        recovery._number(b.get(name, "guid"), True)


def _properties(c):
    return (f"{recovery.MANAGER}=cloud-installer", f"{recovery.OWNER}={c.config.instance}",
            f"{recovery.TOKEN}={c.operation_id}")


def _inventory(b, pool):
    return b.output("zfs", "list", "-H", "-o", "name", "-t", "filesystem,volume", "-r", pool).splitlines()


def _new(b, name):
    _require(not any(recovery._related(name, n) and (n == name or n.startswith(name + "/"))
                     for n in _inventory(b, name.split("/")[0])))


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


@_guard
def export(ctx: Context, destinationdataset: str, *, streams: StreamRunner | None = None):
    """Return a pinned receipt reference; existing unreceipted staging is refused."""
    c, b, manifest, original = _source(ctx)
    _name(destinationdataset)
    root = destinationdataset + f"/ci-{c.config.instance}-{c.operation_id}"
    parent = _topology(c, b, destinationdataset)
    local = c.directory / "export-receipt.json"
    if local.exists() or local.is_symlink():
        receipt = recovery._load(_private(local))
        _require(receipt.get("root") == root)
        verify(ctx, receipt)
        return receipt
    _new(b, root)
    limits = []
    for snapshot in sorted(manifest["snapshots"]):
        lines = b.output("zfs", "send", "-nP", "-p", snapshot).splitlines()
        sizes = [line.split()[1] for line in lines if len(line.split()) == 2 and line.split()[0] == "size"]
        _require(len(sizes) == 1)
        estimate = recovery._number(sizes[0], True)
        limits.append(estimate + max(1024 ** 2, (estimate + 9) // 10))
    _require(recovery._number(b.get(destinationdataset, "available")) >= sum(limits) + recovery.MAX_TOTAL + recovery.MAX_FILE)
    mount = Path(parent["mountpoint"]) / root.rsplit("/", 1)[1]
    _require(not mount.exists() and not mount.is_symlink())
    b.run("zfs", "create", "-u", "-o", "canmount=noauto", "-o", "mountpoint=" + str(mount),
          *(arg for p in _properties(c) for arg in ("-o", p)), root)
    b.run("zfs", "mount", root)
    mount.chmod(0o700)
    topology = _topology(c, b, root, owned=True)
    records = []
    adapter = streams or NativeStreams()
    for index, (snapshot, limit) in enumerate(zip(sorted(manifest["snapshots"]), limits)):
        _require(_source(ctx)[2:] == (manifest, original))
        _require(_topology(c, b, root, owned=True) == topology)
        _require(recovery._number(b.get(root, "available")) >= limit)
        path = mount / f"{index:02d}.zfs"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            adapter.send(snapshot, fd, limit)
            os.fsync(fd)
        finally:
            os.close(fd)
        _require(_source(ctx)[2:] == (manifest, original))
        record = dict(path=path.name, snapshot=snapshot, limit=limit, **_file(path, limit))
        _require(record["size"] > 0)
        records.append(record)
    (mount / "files").mkdir(mode=0o700)
    for item in manifest["evidence"].values():
        _write(mount / item["path"], recovery._read(c.directory / item["path"]))
    _write(mount / "manifest.json", recovery._read(c.directory / "manifest.json"))
    _write(mount / "offline-acknowledgement.json", recovery._read(c.offline_acknowledgement.path))
    value = dict(schema_version=1, binding=c.binding(), manifest=original, datasets=manifest["datasets"],
        snapshots=manifest["snapshots"], destination=topology, owner="cloud-installer", threat_scope=SCOPE,
        streams=records, evidence=manifest["evidence"], acknowledgement_sha256=c.offline_acknowledgement.sha256)
    _write(mount / "export.json", _encode(value))
    receipt = dict(root=root, path=str(mount / "export.json"), **_file(mount / "export.json", recovery.MAX_FILE))
    verify(ctx, receipt)
    _write(local, _encode(receipt))
    return receipt


@_guard
def verify(ctx: Context, receipt: dict):
    """Rehash the complete pinned bundle and recheck native topology; read-only."""
    return _verify_bundle(receipt, *_source(ctx))


def _verify_bundle(receipt, c, b, manifest, original):
    _fields(receipt, "root path sha256 size")
    _require(recovery._hash(receipt["sha256"]) and type(receipt["size"]) is int
             and 0 < receipt["size"] <= recovery.MAX_FILE and isinstance(receipt["path"], str))
    topology = _topology(c, b, receipt["root"], owned=True)
    mount = Path(topology["mountpoint"])
    _require(receipt["root"].endswith(f"/ci-{c.config.instance}-{c.operation_id}")
             and receipt["path"] == str(mount / "export.json"))
    _require(_file(mount / "export.json", receipt["size"]) == {k: receipt[k] for k in ("sha256", "size")})
    value = recovery._load(mount / "export.json")
    _fields(value, "schema_version binding manifest datasets snapshots destination owner threat_scope streams evidence acknowledgement_sha256")
    expected = dict(schema_version=1, binding=c.binding(), manifest=original, datasets=manifest["datasets"],
        snapshots=manifest["snapshots"], destination=topology, owner="cloud-installer", threat_scope=SCOPE,
        evidence=manifest["evidence"], acknowledgement_sha256=c.offline_acknowledgement.sha256)
    _require(_encode({k: value[k] for k in expected}) == _encode(expected))
    _require(type(value["streams"]) is list and len(value["streams"]) == 14)
    for index, (item, snapshot) in enumerate(zip(value["streams"], sorted(manifest["snapshots"]))):
        _fields(item, "path snapshot limit sha256 size")
        _require(item["path"] == f"{index:02d}.zfs" and item["snapshot"] == snapshot
                 and type(item["limit"]) is int and type(item["size"]) is int and 0 < item["size"] <= item["limit"]
                 and recovery._hash(item["sha256"]))
        _require(_file(mount / item["path"], item["size"]) == {k: item[k] for k in ("sha256", "size")})
    _require(_file(mount / "manifest.json", recovery.MAX_FILE) == original)
    _private(mount / "files", True)
    for item in manifest["evidence"].values():
        _require(_file(mount / item["path"], recovery.MAX_FILE) == {k: item[k] for k in ("sha256", "size")})
    _require(_file(mount / "offline-acknowledgement.json", recovery.MAX_FILE)["sha256"] == c.offline_acknowledgement.sha256)
    return dict(evidencecopyverified=True, restorestream_rehearsal=False,
                fullapplicationrestorerehearsal=False, threat_scope=SCOPE, receipt=dict(receipt))


def _live_storage(c, b, manifest):
    """Read-only original identities with ONLY the configured live nullfs graph."""
    roots = {j: f"{c.config.bastille_root}/jails/{j}/root"
             for j in (c.config.nextcloud_jail, c.config.onlyoffice_jail)}
    jails, jids = {}, set()
    for line in b.output("jls", "-d", "jid", "name", "path", "dying").splitlines():
        row = line.split()
        _require(len(row) == 4 and row[3] in ("true", "false") and row[0] not in jids)
        recovery._number(row[0], True)
        jids.add(row[0])
        if row[1] in roots or any(recovery._related(row[2], r.mountpoint) for r in c.resources):
            _require(row[1] in roots and row[2] == roots[row[1]] and row[3] == "false" and row[1] not in jails)
            jails[row[1]] = row[0]
    _require(set(jails) == set(roots))
    expected = {(r.name, r.mountpoint, "zfs") for r in c.resources}
    expected.update((d.mountpoint, roots[d.jail] + d.target, "nullfs")
                    for d in recovery.datasets(c.config) if d.jail)
    devices = {("devfs", root + "/dev", "devfs") for root in roots.values()}
    seen = set()
    for line in b.output("mount", "-p").splitlines():
        row = line.split()
        _require(len(row) == 6 and "\\" not in row[0] + row[1] and row[1].startswith("/"))
        triple = tuple(row[:3])
        related = (row[0] in manifest["datasets"] or
                   any(row[1] == r.mountpoint or row[1].startswith(r.mountpoint + "/") or
                       (row[2] == "nullfs" and (recovery._related(row[0], r.mountpoint) or
                                               recovery._related(row[1], r.mountpoint))) for r in c.resources))
        if related:
            _require(triple in expected | devices and triple not in seen)
            seen.add(triple)
    _require(expected <= seen)
    for source, target, kind in expected:
        if kind == "nullfs":
            _require(b.output("realpath", source) == source and b.output("realpath", target) == target)
    for root in recovery._roots(c):
        names = b.output("zfs", "list", "-H", "-o", "name", "-t", "filesystem,volume", "-r", root).splitlines()
        _require(len(names) == len(set(names)) and set(names) ==
                 {r.name for r in c.resources if r.name == root or r.name.startswith(root + "/")})
    for r in c.resources:
        for key, expected_value in (("guid", manifest["datasets"][r.name]["guid"]), ("type", "filesystem"),
                ("origin", "-"), ("mounted", "yes"), ("mountpoint", r.mountpoint),
                (recovery.MANAGER, "cloud-installer"), (recovery.OWNER, c.config.instance)):
            _require(b.get(r.name, key) == expected_value)
        _require(b.output("realpath", r.mountpoint) == r.mountpoint)
        df = b.output("df", "-P", r.mountpoint).splitlines()
        _require(len(df) == 2 and len(df[-1].split()) == 6 and df[-1].split()[0] == r.name
                 and df[-1].split()[-1] == r.mountpoint)
    _require(b.snapshots(c, manifest["datasets"]) == manifest["snapshots"])
    return jails


def _retained_source(ctx):
    _require_root()
    journal = ctx.check(closed=True)[2]
    _require(journal["phase"] in ("validating", "recovery-validating", "committed-closed")
             and journal["publication_may_have_begun"] is False
             and journal["recovery_publication_may_have_begun"] is False)
    c, b = ctx._recovery_context(readonly=True), ctx.backend
    recovery._context(c)  # Validates bindings/acknowledgement, never invokes the cold callback.
    _require(c.schema_version == 2 and len(c.resources) == 14 and isinstance(b, recovery.NativeBackend))
    path = _private(c.directory / "manifest.json")
    manifest = recovery.validate_manifest(c, recovery._load(path))
    for e in c.evidence:
        _require(not any(Path(e.path).is_relative_to(r.mountpoint) for r in c.resources))
        _require(_file(e.path, recovery.MAX_FILE) ==
                 {k: manifest["evidence"][e.name][k] for k in ("sha256", "size")})
    _require(recovery._copies(c) == manifest["evidence"])
    return (c, b, manifest, _file(path, recovery.MAX_FILE)), _encode(journal), _live_storage(c, b, manifest)


@_guard
def verify_retained(ctx: Context, receipt: dict):
    """Live closed-profile recheck only; no new drain/closure or application proof.

    Uses NativeContext's read-only original-context projection. The publication
    caller separately binds full controller/application restoration evidence.
    """
    source, journal, jails = _retained_source(ctx)
    result = _verify_bundle(receipt, *source)
    c, b, manifest, _ = source
    pin = c.directory / "export-rehearsal.json"
    path = Path(receipt["path"]).parent / "rehearsal.json"
    if pin.exists() or pin.is_symlink():
        reference = recovery._load(_private(pin))
        _fields(reference, "path sha256 size")
        _require(reference["path"] == str(path) and recovery._hash(reference["sha256"])
                 and type(reference["size"]) is int and 0 < reference["size"] <= recovery.MAX_FILE)
        _require(_file(path, recovery.MAX_FILE) == {k: reference[k] for k in ("sha256", "size")})
        value = recovery._load(path)
        _fields(value, "evidencecopyverified restorestream_rehearsal fullapplicationrestorerehearsal threat_scope receipt received target")
        expected = dict(result, restorestream_rehearsal=True)
        _require(_encode({k: value[k] for k in expected}) == _encode(expected))
        _received(c, b, receipt, manifest, value["target"], value["received"])
        result.update(restorestream_rehearsal=True, rehearsal=dict(reference))
    else:
        _require(not path.exists() and not path.is_symlink())
    again, current, live = _retained_source(ctx)
    _require(again[2:] == source[2:] and current == journal and live == jails)
    _require(_topology(c, b, receipt["root"], owned=True) ==
             recovery._load(Path(receipt["path"]))["destination"])
    _require(_file(Path(receipt["path"]), recovery.MAX_FILE) == {k: receipt[k] for k in ("sha256", "size")})
    return dict(result, physical_independence_unassessed=True)


def _received(c, b, receipt, manifest, target, received):
    _fields(target, "dataset guid")
    name = _name(target["dataset"])
    recovery._number(target["guid"], True)
    _require(name.startswith(receipt["root"] + "/") and name.count("/") == receipt["root"].count("/") + 1
             and b.get(name, "guid") == target["guid"] and type(received) is list and len(received) == 14)
    for index, (row, snapshot) in enumerate(zip(received, sorted(manifest["snapshots"]))):
        _fields(row, "source target guid dataset_guid")
        child = name + f"/member-{index:02d}"
        _require(row["source"] == snapshot and row["target"] == child + "@" + snapshot.split("@")[1]
                 and row["guid"] == manifest["snapshots"][snapshot]["guid"]
                 and b.get(row["target"], "guid") == row["guid"] and b.get(child, "guid") == row["dataset_guid"])
        recovery._number(row["dataset_guid"], True)
    names = {name, *(r["target"].split("@")[0] for r in received)}
    actual = [n for n in _inventory(b, name.split("/")[0]) if n == name or n.startswith(name + "/")]
    _require(len(actual) == 15 and set(actual) == names)
    for member in names:
        for key, expected in (("canmount", "off"), ("mountpoint", "none"), ("mounted", "no"), ("type", "filesystem"), ("origin", "-")):
            _require(b.get(member, key) == expected)
        for prop in _properties(c):
            key, expected = prop.split("=", 1)
            _require(b.output("zfs", "get", "-Hp", "-o", "value,source", key, member).split() == [expected, "local"])
    _require(b.output("zfs", "list", "-H", "-t", "snapshot", "-o", "name", "-r", name).splitlines()
             == [r["target"] for r in received])
    _require(not any(row.split()[0] in names for row in b.output("mount", "-p").splitlines()))


@_guard
def rehearse(ctx: Context, receipt: dict, targetdataset: str | None = None, *, streams: StreamRunner | None = None):
    """Receive all 14 into NEW independent nonmounting children; never rollback."""
    result = verify(ctx, receipt)
    c, b, manifest, _ = _source(ctx)
    target = _name(targetdataset or receipt["root"] + "/rehearsal")
    _require(target.startswith(receipt["root"] + "/") and target.count("/") == receipt["root"].count("/") + 1)
    _new(b, target)
    value = recovery._load(Path(receipt["path"]))
    _require(recovery._number(b.get(receipt["root"], "available")) >= sum(i["limit"] for i in value["streams"]))
    b.run("zfs", "create", "-u", "-o", "canmount=off", "-o", "mountpoint=none",
          *(arg for p in _properties(c) for arg in ("-o", p)), target)
    received = []
    for index, item in enumerate(value["streams"]):
        verify(ctx, receipt)
        name = target + f"/member-{index:02d}"
        _new(b, name)
        fd = os.open(Path(receipt["path"]).parent / item["path"], os.O_RDONLY | os.O_NOFOLLOW)
        try:
            (streams or NativeStreams()).receive(name, fd, item["size"], _properties(c))
        finally:
            os.close(fd)
        snapshot = name + "@" + item["snapshot"].split("@")[1]
        _require(b.get(snapshot, "guid") == manifest["snapshots"][item["snapshot"]]["guid"])
        for key, expected in (("canmount", "off"), ("mountpoint", "none"), ("mounted", "no"), ("origin", "-"), ("type", "filesystem")):
            _require(b.get(name, key) == expected)
        for p in _properties(c):
            key, expected = p.split("=", 1)
            _require(b.get(name, key) == expected)
        received.append(dict(source=item["snapshot"], target=snapshot, guid=b.get(snapshot, "guid"), dataset_guid=b.get(name, "guid")))
    verify(ctx, receipt)
    target_ref = dict(dataset=target, guid=b.get(target, "guid"))
    _received(c, b, receipt, manifest, target_ref, received)
    result.update(restorestream_rehearsal=True, received=received, target=target_ref)
    path = Path(receipt["path"]).parent / "rehearsal.json"
    _write(path, _encode(result))
    _write(c.directory / "export-rehearsal.json", _encode(dict(path=str(path), **_file(path, recovery.MAX_FILE))))
    return result
