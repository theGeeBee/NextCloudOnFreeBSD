"""Run-local native ZFS checkpoint. Caller owns locks and clean service shutdown.

Both jails must stay stopped during capture/rollback. This is not an off-pool
backup: host OS/configuration, external storage and unsaved edits are excluded.
"""

import json
import os
from pathlib import Path
import re
import stat
import uuid

from .config import datasets
from .state import atomic_json

ROOT_UID = 0
OWNER = "org.cloud-installer:instance"
MANAGER = "org.cloud-installer:owner"
PROPERTIES = "name,type,guid,mountpoint,mounted,origin," + OWNER + "," + MANAGER
NOTE = "Local ZFS checkpoint of jail/package/application data only; operator-owned backups remain necessary. Not host OS/PF/config recovery or complete DR."


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _related(left, right):
    return left == right or left.startswith(right + "/") or right.startswith(left + "/")


def _number(value):
    return isinstance(value, str) and re.fullmatch(r"[1-9][0-9]{0,19}", value) is not None


def _path(value):
    return (isinstance(value, str) and value.startswith("/") and not value.startswith("//")
            and str(Path(value)) == value and ".." not in Path(value).parts
            and not any(c.isspace() or ord(c) < 32 or c == "\\" for c in value))


def _directory(value):
    path = Path(value)
    _require(os.geteuid() == ROOT_UID and _path(str(path)), "Root and an absolute private report directory are required")
    for parent in reversed(path.parents):
        info = parent.lstat()
        _require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, ROOT_UID)
                 and (not info.st_mode & 0o022 or info.st_uid == 0 and info.st_mode & stat.S_ISVTX),
                 "Unsafe snapshot report ancestor")
    if not path.exists() and not path.is_symlink():
        path.mkdir(mode=0o700)
    info = path.lstat()
    _require(stat.S_ISDIR(info.st_mode) and info.st_uid == ROOT_UID and not info.st_mode & 0o077,
             "Snapshot report directory must be private and root-owned")
    return path


def _layout(target):
    c = target.config.validate()
    expected = {item.name: item.mountpoint for item in datasets(c)}
    roots = [c.dataset_root]
    for jail, actual, actual_root in ((c.nextcloud_jail, target.nc, target.nc_root),
                                      (c.onlyoffice_jail, target.office, target.office_root)):
        root, mount = f"{c.bastille_dataset}/jails/{jail}", f"{c.bastille_root}/jails/{jail}"
        _require(actual == jail and str(actual_root) == mount + "/root", "Configured jail identity differs")
        roots.append(root)
        expected.update({root: mount, root + "/root": mount + "/root"})
    return roots, expected


def _stopped(target, points):
    for jail, root in ((target.nc, target.nc_root), (target.office, target.office_root)):
        _require(target.runner.output("bastille", "config", jail, "get", "path") == str(root),
                 "Bastille jail root changed")
    seen = set()
    # FreeBSD -d includes dying jails; explicit fields omit a header.
    for line in target.runner.output("jls", "-d", "jid", "name", "path", "dying").splitlines():
        row = line.split()
        _require(len(row) == 4 and _number(row[0]) and row[0] not in seen
                 and _path(row[2]) and row[3] in ("true", "false"), "Invalid live/dying jail inventory")
        seen.add(row[0])
        _require(row[1] not in (target.nc, target.office) and not any(_related(row[2], p) for p in points),
                 "Both affected jails must be stopped, including dying jail references")


def _storage(target, roots, expected):
    output, found = target.runner.output, {}
    for root in roots:
        for line in output("zfs", "list", "-Hp", "-t", "filesystem,volume", "-o", PROPERTIES, "-r", root).splitlines():
            row = line.split("\t")
            _require(len(row) == 8, "Invalid native ZFS filesystem inventory")
            name, kind, guid, mount, mounted, origin, owner, manager = row
            _require(name not in found and (name == root or name.startswith(root + "/"))
                     and re.fullmatch(r"[A-Za-z0-9_./:-]+", name) and ".." not in name.split("/"), "Unexpected dataset member")
            _require(kind == "filesystem" and _number(guid) and owner == target.config.instance
                     and manager == "cloud-installer" and origin == "-" and mounted == "yes", "Dataset ownership/type/mount changed")
            _require(_path(mount) and mount == expected.get(name, expected[root] + name[len(root):]), "Dataset mountpoint changed")
            found[name] = dict(guid=guid, mountpoint=mount)
    _require(set(expected) <= set(found) and len({v["guid"] for v in found.values()}) == len(found), "Missing or duplicate dataset members")
    points = {v["mountpoint"]: name for name, v in found.items()}
    _require(len(points) == len(found), "Duplicate dataset mountpoints")
    devices = {output("stat", "-f", "%d", p) for p in points}
    _require(all(re.fullmatch(r"[0-9]+", value) for value in devices), "Invalid filesystem device identity")
    rows = [line.split() for line in output("mount", "-p").splitlines()]
    for row in rows:
        _require(len(row) == 6 and _path(row[1]) and "\\" not in row[0], "Invalid native mount inventory")
        if row[0] in found or any(row[1] == p or row[1].startswith(p + "/") for p in points):
            _require(row[1] in points and row[:3] == [points[row[1]], row[1], "zfs"], "Unexpected dataset mount or covering filesystem")
        if row[2] == "nullfs":
            for endpoint in row[:2]:
                canonical = output("realpath", endpoint)
                _require(_path(canonical) and not any(_related(canonical, p) for p in points)
                         and output("stat", "-f", "%d", canonical) not in devices, "Related nullfs mount remains")
    for name, value in found.items():
        mount = value["mountpoint"]
        _require(output("realpath", mount) == mount and [r[:3] for r in rows if r[1] == mount] == [[name, mount, "zfs"]], "Actual dataset mount differs")
        df = output("df", "-P", mount).splitlines()
        _require(len(df) == 2 and len(df[1].split()) == 6 and df[1].split()[0] == name
                 and df[1].split()[-1] == mount, "Dataset covering filesystem changed")
    _stopped(target, points)
    return found


def _snapshots(target, roots, storage, suffix, restoring=False):
    inventory = {}
    for root in roots:
        for line in target.runner.output("zfs", "list", "-Hp", "-t", "snapshot", "-o", "name,guid,createtxg", "-r", root).splitlines():
            row = line.split("\t")
            _require(len(row) == 3 and row[0] not in inventory and row[0].count("@") == 1
                     and row[0].split("@")[0] in storage and _number(row[1]) and _number(row[2]), "Invalid snapshot inventory")
            inventory[row[0]] = dict(guid=row[1], createtxg=row[2])
    names = {name + "@" + suffix for name in storage}
    _require(names <= inventory.keys(), "Incomplete snapshot set")
    members = {name: inventory[name] for name in sorted(names)}
    _require(len({v["createtxg"] for v in members.values()}) == 1
             and len({v["guid"] for v in members.values()}) == len(members), "Snapshot set is not one atomic transaction")
    if restoring:
        for name, meta in members.items():
            _require(not any(other != name and other.split("@")[0] == name.split("@")[0]
                             and int(value["createtxg"]) >= int(meta["createtxg"])
                             for other, value in inventory.items()), "Newer snapshot blocks rollback; nothing will be deleted")
    return members


def create(target, directory):
    """Capture all descendants with one atomic native snapshot command."""
    roots, expected = _layout(target)
    _stopped(target, expected.values())
    storage = _storage(target, roots, expected)
    path = _directory(directory)
    _require(not any(_related(str(path), v["mountpoint"]) for v in storage.values()), "Report must be outside snapshot trees")
    _require(not os.path.lexists(path / "report.json"), "A snapshot report already exists; use a fresh run directory")
    record = dict(schema_version=1, instance=target.config.instance, directory=str(path), roots=roots,
                  suffix="upgrade-" + uuid.uuid4().hex, datasets=storage, members={}, state="snapshot-pending", note=NOTE)
    atomic_json(path / "report.json", record)
    try:
        _stopped(target, expected.values())
        target.runner.run("zfs", "snapshot", "-r", *(root + "@" + record["suffix"] for root in roots), timeout=120)
        _require(_storage(target, roots, expected) == storage, "Dataset set changed during snapshot")
        record["members"] = _snapshots(target, roots, storage, record["suffix"])
        record["state"] = "captured"
        atomic_json(path / "report.json", record)
        return record
    except BaseException as error:
        record["state"] = "snapshot-failed"
        record["error"] = str(error) if isinstance(error, ValueError) else "Native snapshot operation failed or was interrupted"
        atomic_json(path / "report.json", record)
        raise RuntimeError("Snapshot capture failed; both jails remain stopped. Retain the run report and inspect any created snapshots.") from None


def restore(target, record):
    """Validate the entire set before any individual, nonrecursive rollback."""
    roots, expected = _layout(target)
    _stopped(target, expected.values())
    _require(isinstance(record, dict) and record.get("schema_version") == 1 and record.get("state") == "captured"
             and record.get("instance") == target.config.instance and record.get("roots") == roots
             and isinstance(record.get("suffix"), str) and re.fullmatch(r"upgrade-[a-f0-9]{32}", record["suffix"]), "Snapshot record does not match this target")
    path = _directory(record["directory"])
    fd = os.open(path / "report.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        _require(stat.S_ISREG(info.st_mode) and info.st_uid == ROOT_UID and info.st_nlink == 1
                 and not info.st_mode & 0o077 and info.st_size <= 4 * 1024 * 1024, "Unsafe snapshot report")
        _require(json.loads(source.read(4 * 1024 * 1024 + 1)) == record, "Snapshot report changed")
    result = dict(record, state="restoring", rolled_back=[])
    try:
        def preflight():
            _stopped(target, expected.values())
            storage = _storage(target, roots, expected)
            _require(storage == record["datasets"], "Dataset identity or complete member set changed")
            _require(_snapshots(target, roots, storage, record["suffix"], restoring=True) == record["members"], "Snapshot GUID or complete member set changed")
        preflight()
        atomic_json(path / "report.json", result)
        # Parents before nested datasets, matching the existing native recovery contract.
        for name in sorted(record["datasets"], key=lambda value: (value.count("/"), value)):
            preflight()
            result["rollback_target"] = name + "@" + record["suffix"]
            target.runner.run("zfs", "rollback", name + "@" + record["suffix"], timeout=120)
            result["rolled_back"].append(name)
            atomic_json(path / "report.json", result)
        preflight()
        result["state"] = "restored"
        atomic_json(path / "report.json", result)
        return result
    except BaseException as error:
        result["state"] = "restore-failed"
        result["error"] = str(error) if isinstance(error, ValueError) else "Native rollback operation failed or was interrupted"
        atomic_json(path / "report.json", result)
        raise RuntimeError("Snapshot rollback failed or was refused; jails remain stopped. Rollback may be partial; inspect report.json before recovery.") from None
