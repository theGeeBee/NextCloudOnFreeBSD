"""Quiesced initialization snapshots and explicitly confirmed unpublished recovery.

The caller holds Registry.locked() and has validated the FreeBSD host. This is
not a general backup/restore API: only the four pre-install datasets may roll
back, and any publication attempt permanently closes this recovery boundary.
"""

import json
import os
from pathlib import Path
import re
import stat
import time
import uuid

from .config import datasets
from .operations import _database_guard, _directories, _sync_directory
from .state import Journal, atomic_json, config_digest, private_json, timestamp


OWNER = "org.cloud-installer:instance"
TOKEN = "org.cloud-installer:initialization"
SNAPSHOT = "cloud-installer-initialization"
PARTS = ("nc-app", "nc-data", "nc-database", "nc-db-logs")
INSTALL = "Nextcloud installation"
PUBLICATION = "Nextcloud publication"
CHECKPOINT = "quiesced initialization checkpoint"


def _inputs(d):
    c = d.config.validate()
    if config_digest(d.registry.load(c.instance)) != config_digest(c):
        raise ValueError("Initialization recovery requires the unchanged registered configuration")
    private_json(d.state / "deployment.json")  # Never invent a missing ownership journal.
    journal = Journal(d.state / "deployment.json", c)
    status = d.registry.status(d.config.instance)
    if status.get("state") not in ("installing", "failed"):
        raise ValueError("Initialization operations require an installing or failed instance")
    if journal.data["steps"].get("Nextcloud database", {}).get("state") != "complete":
        raise ValueError("Complete the Nextcloud database phase first")
    return journal


def _layout(d):
    choices = {item.name: item for item in datasets(d.config)}
    return [choices[d.config.dataset_root + "/" + part] for part in PARTS]


def _jail(d, name):
    """Include dying jails; FreeBSD libjail exports booleans as false/true."""
    matches = []
    for line in d.runner.output("jls", "-d", "jid", "name", "path", "dying").splitlines():
        identity, dying = line.rsplit(None, 1)
        jid, actual, root = identity.split(None, 2)
        if actual == name or root == str(d.jail_root(name)):
            if (actual != name or root != str(d.jail_root(name)) or not jid.isdigit()
                    or int(jid) < 1 or dying not in ("false", "true")):
                raise ValueError("Managed jail identity changed")
            matches.append((int(jid), dying == "true"))
    if len(matches) > 1:
        raise ValueError("Ambiguous live/dying managed jail identity")
    return matches[0] if matches else None


def _stop(d, name):
    live = _jail(d, name)
    if live and not live[1]:
        if d.require_running_jail(name) != live[0]:
            raise ValueError("Managed jail changed before quiescing")
        d.runner.run("bastille", "stop", name)
    for _ in range(60):
        if _jail(d, name) is None:
            break
        time.sleep(1)
    else:
        raise RuntimeError("Jail did not stop completely; initialization snapshots were not changed")
    root = str(d.jail_root(name)) + "/"
    if any(len(row) >= 3 and row[2] == "nullfs" and row[1].startswith(root)
           for line in d.runner.output("mount", "-p").splitlines() if (row := line.split())):
        raise RuntimeError("Stopped jail retains nullfs mounts; inspect it before initialization recovery")


def _start_nextcloud(d):
    name = d.config.nextcloud_jail
    d.runner.run(f"/usr/local/libexec/{d.config.instance}-storage-guard", name)
    live = _jail(d, name)
    if live and live[1]:
        raise RuntimeError("Nextcloud jail is still dying; retry after it stops")
    if live is None:
        d.runner.run("bastille", "start", name)
    d.require_running_jail(name)


def _storage(d):
    """Check properties, real paths, covering mounts, jail roots and leaf datasets."""
    mounted = [line.split() for line in d.runner.output("mount", "-p").splitlines()]
    points = [(item.name, item.mountpoint) for item in _layout(d)]
    points += [(f"{d.config.bastille_dataset}/jails/{name}/root", str(d.jail_root(name)))
               for name in d.config.jails]
    result = {}
    for name, point in points:
        for key, expected in ((OWNER, d.config.instance), ("type", "filesystem"),
                              ("mountpoint", point), ("mounted", "yes")):
            if d.runner.output("zfs", "get", "-H", "-o", "value", key, name) != expected:
                raise ValueError("Initialization dataset ownership, type or mountpoint changed")
        if (d.runner.output("realpath", point) != point
                or not any(row[:3] == [name, point, "zfs"] for row in mounted)
                or d.runner.output("df", "-P", point).splitlines()[-1].split()[0] != name):
            raise ValueError("Initialization dataset is not its real, uncovered managed mount")
        guid = d.runner.output("zfs", "get", "-Hp", "-o", "value", "guid", name)
        if not guid.isdigit() or int(guid) < 1:
            raise ValueError("Missing dataset GUID")
        result[name] = {"mountpoint": point, "guid": guid}
    live = _jail(d, d.config.nextcloud_jail)
    for item in _layout(d):
        if d.runner.output("zfs", "list", "-H", "-o", "name", "-t", "filesystem,volume", "-r", item.name).splitlines() != [item.name]:
            raise ValueError("Initialization datasets must have no child datasets")
        target = str(d.jail_root(d.config.nextcloud_jail)) + item.target
        matches = [row[:3] for row in mounted if len(row) >= 3 and row[1] == target]
        if (live or matches) and matches != [[item.mountpoint, target, "nullfs"]]:
            raise ValueError("Nextcloud's live mount does not match its owned dataset")
    return result


def _snapshots(d):
    result = {}
    text = d.runner.output("zfs", "list", "-H", "-p", "-t", "snapshot", "-o",
                           "name,guid,creation,createtxg", "-r", d.config.dataset_root)
    for line in text.splitlines():
        name, guid, creation, txg = line.split()
        if name in result or not all(value.isdigit() and int(value) > 0 for value in (guid, creation, txg)):
            raise ValueError("Invalid initialization snapshot inventory")
        result[name] = {"guid": guid, "creation": creation, "createtxg": txg}
    return result


def _record(d, storage):
    path = d.state / "initialization.json"
    if not path.exists() and not path.is_symlink():
        return None
    value = private_json(path)
    expected = {item.name + "@" + SNAPSHOT for item in _layout(d)}
    if (value.get("schema_version") != 1 or value.get("instance") != d.config.instance
            or value.get("config_sha256") != config_digest(d.config) or value.get("datasets") != storage
            or value.get("names") != sorted(expected) or value.get("state") not in ("prepared", "complete")
            or not re.fullmatch(r"[a-f0-9]{32}", value.get("token", ""))
            or not isinstance(value.get("snapshots"), dict) or set(value["snapshots"]) - expected
            or not isinstance(value.get("recoveries"), list)
            or (value["state"] == "complete" and set(value["snapshots"]) != expected)):
        raise ValueError("Initialization journal/configuration/dataset identity changed")
    return value


def _verify_snapshots(d, record, *, restoring=False):
    all_snapshots = _snapshots(d)
    found = {name: all_snapshots[name] for name in record["names"] if name in all_snapshots}
    if found and len(found) != len(record["names"]):
        raise ValueError("Incomplete atomic initialization snapshot set; nothing will be overwritten")
    if not found:
        if record["state"] == "complete" or record["snapshots"] or restoring:
            raise ValueError("The retained initialization checkpoint is missing")
        return {}
    for name, values in found.items():
        if (d.runner.output("zfs", "get", "-H", "-o", "value", OWNER, name) != d.config.instance
                or d.runner.output("zfs", "get", "-H", "-o", "value", TOKEN, name) != record["token"]
                or (name in record["snapshots"] and record["snapshots"][name] != values)):
            raise ValueError("Initialization snapshot ownership/GUID/creation identity changed")
        if restoring:
            prefix = name.split("@", 1)[0] + "@"
            if any(other != name and other.startswith(prefix) and int(meta["createtxg"]) >= int(values["createtxg"])
                   for other, meta in all_snapshots.items()):
                raise ValueError("Initialization snapshot is not the latest; recursive rollback is forbidden")
            if (d.runner.output("zfs", "get", "-H", "-o", "value", "clones", name) != "-"
                    or d.runner.output("zfs", "get", "-Hp", "-o", "value", "userrefs", name) != "0"):
                raise ValueError("Initialization snapshot has clones or holds; manual review is required")
    if len({value["createtxg"] for value in found.values()}) != 1:
        raise ValueError("Initialization snapshots do not share an atomic transaction")
    return found


def checkpoint_initialization(deployment):
    d = deployment
    with _database_guard(d):
        journal = _inputs(d)
        d.verify_source()
        storage = _storage(d)
        record = _record(d, storage)
        names = sorted(item.name + "@" + SNAPSHOT for item in _layout(d))
        if record is None and set(names) & _snapshots(d).keys():
            raise ValueError("Same-name initialization snapshots exist without a capture intent; refusing adoption")
        found = _verify_snapshots(d, record) if record else {}
        if not found:
            if INSTALL in journal.data["steps"]:
                raise ValueError("Cannot create an initialization checkpoint after installation was attempted")
            d.runner.run(f"/usr/local/libexec/{d.config.instance}-storage-guard", d.config.nextcloud_jail)
            _start_nextcloud(d)
            _storage(d)  # Verify actual nullfs mappings before reading application state.
            d.jail(d.config.nextcloud_jail, "/bin/sh", "/root/cloud-installer/resources/jails/nextcloud.sh",
                   "checkpoint-ready", input=json.dumps({"db_password": d.secrets["db_password"]}))
            for name in d.config.jails:
                _stop(d, name)
            if _storage(d) != storage:
                raise ValueError("Dataset identities changed during quiescing")
            record = record or {"schema_version": 1, "instance": d.config.instance,
                                "config_sha256": config_digest(d.config), "state": "prepared",
                                "token": uuid.uuid4().hex, "datasets": storage, "names": names,
                                "snapshots": {}, "prepared": timestamp(), "recoveries": []}
            atomic_json(d.state / "initialization.json", record)
            d.runner.run("zfs", "snapshot", "-o", f"{OWNER}={d.config.instance}", "-o", f"{TOKEN}={record['token']}", *names)
            found = _verify_snapshots(d, record)
            if not found:
                raise RuntimeError("ZFS did not create the atomic initialization checkpoint")
        record.update(state="complete", snapshots=found)
        atomic_json(d.state / "initialization.json", record)
        # Restore all selected jails' checked running state. Native ONLYOFFICE
        # retains its later worker's strict live-jail requirement.
        d.ensure_running()  # Complete checkpoints never recheck the now-partial DB.
        return record


def _private_marker(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1:
        raise ValueError("Unsafe initialization control marker")


def _start_permission(d, *, block):
    allowed, retained = d.state / "allow-start", d.state / "allow-start.initialization-recovery"
    source, target = (allowed, retained) if block else (retained, allowed)
    if source.exists() or source.is_symlink():
        _private_marker(source)
        if target.exists() or target.is_symlink():
            raise ValueError("Ambiguous initialization start guard")
        source.rename(target)
        _sync_directory(d.state)
    else:
        _private_marker(target)


def recover_initialization(deployment, *, confirmation):
    d = deployment
    if confirmation != "RESET-INITIALIZATION " + d.config.instance:
        raise ValueError("Initialization recovery requires the exact typed confirmation")
    with _database_guard(d):
        journal = _inputs(d)
        steps = journal.data["steps"]
        if PUBLICATION in steps or steps.get(INSTALL, {}).get("state") not in ("failed", "running"):
            raise ValueError("Only an incomplete installation with no publication attempt can be reset")
        d.verify_source()
        record = _record(d, _storage(d))
        if not record or record["state"] != "complete":
            raise ValueError("A complete retained initialization checkpoint is required")
        _verify_snapshots(d, record, restoring=True)  # Check ALL four before any rollback.
        root = _directories(d.jail_root(d.config.nextcloud_jail) / "var/db/cloud-installer")
        if any((root / name).exists() or (root / name).is_symlink() for name in ("nextcloud-published", "nextcloud-finished")):
            raise ValueError("Nextcloud publication markers prohibit initialization recovery")
        marker = root / "nextcloud-installed"
        if marker.exists() or marker.is_symlink():
            _private_marker(marker)
        recovery = {"state": "running", "started": timestamp(), "install_attempt": steps[INSTALL].get("attempt", 0), "restored": []}
        record["recoveries"].append(recovery)
        atomic_json(d.state / "initialization.json", record)
        try:
            for name in d.config.jails:
                _stop(d, name)
            _start_permission(d, block=True)  # A partial rollback cannot be started by ordinary Resume.
            for name in record["names"]:
                _record(d, _storage(d))
                _verify_snapshots(d, record, restoring=True)
                d.runner.run("zfs", "rollback", name)  # Deliberately no recursive/force flags.
                recovery["restored"].append(name)
                atomic_json(d.state / "initialization.json", record)
            _record(d, _storage(d))
            _verify_snapshots(d, record, restoring=True)
            app = Path(d.config.mount_root) / "nc-app/config/config.php"
            d.runner.run("test", "!", "-e", str(app))
            d.runner.run("test", "!", "-L", str(app))
            if marker.exists():
                _private_marker(marker)
                marker.unlink()
                _sync_directory(root)
            steps[INSTALL].update(state="failed", initialization_reset=timestamp())
            steps[CHECKPOINT] = {**steps.get(CHECKPOINT, {}), "state": "complete"}
            journal.save()  # Preserve installation attempt counters and all earlier phases.
            recovery.update(state="complete", completed=timestamp())
            atomic_json(d.state / "initialization.json", record)
            d.registry.set_status(d.config.instance, "failed", next_action="resume", initialization_recovered=True)
            _start_permission(d, block=False)
        except BaseException as error:
            recovery.update(state="failed", error_type=type(error).__name__, failed=timestamp())
            atomic_json(d.state / "initialization.json", record)
            d.registry.set_status(d.config.instance, "failed", next_action="recover-install", error_type=type(error).__name__)
            raise RuntimeError("Initialization recovery did not finish; leave the jail stopped and retry recover-install") from None
        return "Resume"
