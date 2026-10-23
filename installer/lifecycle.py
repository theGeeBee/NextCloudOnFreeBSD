"""Explicitly confirmed removal. No data deletion is part of install/resume."""

import json
import os
import re
import stat
import subprocess
import time

from .deploy import OWNER
from .state import Journal, atomic_json, config_digest, private_json


RUNTIME_STEPS = ("disable boot and stop instance", "withdraw instance firewall access",
                 "remove owned jail roots", "remove private bridges")
JAIL_TEARDOWN_SECONDS = 10
JAIL_POLL_SECONDS = 0.25


def _kernel_jail(runner, name, root, *, timeout=2):
    """Absence requires a successful complete FreeBSD15.1 kernel inventory."""
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate kernel inventory field")
            value[key] = item
        return value

    try:
        result = runner.run("jls", "--libxo", "json", "-d", "jid", "name", "path", "dying",
                            check=False, timeout=timeout)
        if (result.returncode or not isinstance(result.stderr, str) or result.stderr or not isinstance(result.stdout, str)
                or len(result.stdout) > 4 * 1024 * 1024):
            raise ValueError("Kernel inventory command failed")
        data = json.loads(result.stdout, object_pairs_hook=unique)
        if (not isinstance(data, dict) or set(data) != {"__version", "jail-information"}
                or data["__version"] != "2" or not isinstance(data["jail-information"], dict)
                or set(data["jail-information"]) != {"jail"}):
            raise ValueError("Unsupported kernel inventory")
        rows = data["jail-information"]["jail"]
        if not isinstance(rows, list):
            raise ValueError("Invalid kernel inventory rows")
        names, jids, selected = set(), set(), None
        for row in rows:
            if (not isinstance(row, dict) or set(row) != {"jid", "name", "path", "dying"}
                    or any(not isinstance(row[key], str) or not row[key] for key in row)
                    or not re.fullmatch(r"[1-9][0-9]*", row["jid"])
                    or not row["path"].startswith("/") or row["dying"] not in ("true", "false")
                    or row["name"] in names or row["jid"] in jids):
                raise ValueError("Ambiguous kernel jail identity")
            names.add(row["name"])
            jids.add(row["jid"])
            if row["name"] == name:
                if row["path"] != str(root):
                    raise ValueError("Kernel jail root identity changed")
                selected = {"jid": int(row["jid"]), "dying": row["dying"] == "true"}
        return selected
    except (OSError, subprocess.SubprocessError, ValueError, TypeError, RecursionError):
        raise RuntimeError("Cannot verify kernel jail identity/absence; removal refused, roots retained") from None


def _wait_for_jail_exit(runner, name, root, expected_jid):
    """Wait only for the same dying jail; never retry stop or accept a live jail."""
    deadline = time.monotonic() + JAIL_TEARDOWN_SECONDS
    announced = False
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError(f"Jail {name} teardown timed out; roots retained. Retry removal after teardown clears")
        current = _kernel_jail(runner, name, root, timeout=min(2, remaining))
        if time.monotonic() >= deadline:
            raise RuntimeError(f"Jail {name} teardown timed out; roots retained. Retry removal after teardown clears")
        if current is None:
            return
        if current["jid"] != expected_jid:
            raise RuntimeError("Jail identity changed during teardown; roots retained")
        if not current["dying"]:
            raise RuntimeError("Jail did not stop; nothing will be destroyed")
        if not announced:
            print(f"Waiting up to {JAIL_TEARDOWN_SECONDS}s for jail {name} teardown...", flush=True)
            announced = True
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(JAIL_POLL_SECONDS, remaining))


def _runtime_removed(deployment, status):
    """Removal evidence survives switching workflows and a failed data-only purge."""
    c, state = deployment.config, deployment.state
    removed = status["state"] == "removed"
    for filename in ("removal.json", "purge.json"):
        path = state / filename
        if not path.exists() and not path.is_symlink():
            continue
        data = private_json(path)
        # Removal/purge journals bind the effective configuration at removal,
        # unlike the original installation journal retained by a successor.
        if (not isinstance(data, dict) or data.get("schema_version") != c.schema_version
                or data.get("config_sha256") != config_digest(c) or not isinstance(data.get("steps"), dict)):
            raise ValueError("Removal ownership journal does not match this instance configuration")
        steps = data["steps"]
        removed |= all(isinstance(steps.get(name), dict) and steps[name].get("state") == "complete"
                       for name in RUNTIME_STEPS)
    tombstone = state / "removed.json"
    if tombstone.exists() or tombstone.is_symlink():
        value = private_json(tombstone)
        # Legacy tombstones have no config digest; the private, permanently
        # reserved instance-state directory and exact dataset bind their identity.
        if (not isinstance(value, dict) or value.get("dataset") != c.dataset_root
                or type(value.get("data_retained")) is not bool
                or value.get("credentials_retained") is not True or value.get("backups_retained") is not True):
            raise ValueError("Removal tombstone does not match this instance")
        removed = True
    return removed


def _check_network_allocations(deployment):
    c = deployment.config
    bridges = set(c.bridges)
    for other in deployment.registry.network_configs(exclude=c.instance):
        if c.network.overlaps(other.network) or bridges & set(other.bridges):
            raise ValueError("Removal network allocations are now owned by another active instance")


def _checked_jails(deployment, names=None, *, stopped=False):
    """Validate all selected targets before quiescing/destruction, including stopped roots.

    Bastille 1.4.4 common.sh:set_target prefix-completes a missing target. Never
    invoke a targeted command using dataset existence or a previous checkpoint
    alone. list.sh supports `list -j path` (Name/Path); `-a` is deprecated and
    `list -j all` omits Name. No target argument is passed to this inventory.
    """
    c, runner = deployment.config, deployment.runner
    names = names if names is not None else c.jails
    mounts = [line.split() for line in runner.output("mount", "-p").splitlines()]
    candidates = []
    for name in names:
        root = deployment.jail_root(name)
        parent = f"{c.bastille_dataset}/jails/{name}"
        points = ((parent, root.parent), (parent + "/root", root))
        present = [runner.run("zfs", "list", "-H", dataset, check=False).returncode == 0
                   for dataset, _ in points]
        if not any(present):
            if root.parent.exists() or root.parent.is_symlink():
                raise ValueError("Unexpected non-ZFS jail remnants; inspect them manually rather than deleting arbitrary paths")
            if _kernel_jail(runner, name, root) is not None:
                raise ValueError("A live/dying jail has no owned storage; removal refused")
            continue
        intent = deployment.state / (name + ".creating.json")
        if (not intent.exists() or private_json(intent) != {"name": name, "root": str(root), "release": c.release}):
            raise ValueError("Refusing removal of an unreserved jail")
        if not all(present):
            raise ValueError("Incomplete jail datasets; removal requires the owned parent and root")
        descendants = runner.output("zfs", "list", "-H", "-o", "name", "-t", "filesystem,volume", "-r", parent).splitlines()
        if set(descendants) != {parent, parent + "/root"}:
            raise ValueError("Unexpected jail dataset descendants; recursive destruction refused")
        for dataset, point in points:
            for key, expected in ((OWNER, c.instance), ("org.cloud-installer:owner", "cloud-installer"),
                                  ("type", "filesystem"), ("mountpoint", str(point)), ("mounted", "yes")):
                if runner.output("zfs", "get", "-H", "-o", "value", key, dataset) != expected:
                    raise ValueError("Refusing an unowned jail dataset or changed/unmounted jail filesystem")
            if not point.is_dir() or point.resolve() != point:
                raise ValueError("Jail mountpoint must be its real directory")
            actual = [row[:3] for row in mounts if len(row) >= 3 and row[1] == str(point)]
            rows = runner.output("df", "-P", str(point)).splitlines()
            if (actual != [[dataset, str(point), "zfs"]] or not rows or not rows[-1].split()
                    or rows[-1].split()[0] != dataset):
                raise RuntimeError("Jail dataset is not its actual uncovered ZFS mount")
        allowed = {str(point): (dataset, "zfs") for dataset, point in points}
        if not stopped:
            allowed.update({str(root) + item.target: (item.mountpoint, "nullfs")
                            for item in deployment.storage if item.jail == name})
            allowed[str(root / "dev")] = ("devfs", "devfs")
        for row in mounts:
            if len(row) >= 3 and row[1].startswith(str(root.parent) + "/"):
                if allowed.get(row[1]) != (row[0], row[2]):
                    raise RuntimeError("Foreign or persistent jail mounts remain active; removal refused")
        conf = root.parent / "jail.conf"
        try:
            info = conf.lstat()
        except FileNotFoundError:
            raise ValueError("Missing owned jail.conf; refusing Bastille target resolution") from None
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o022 or info.st_nlink != 1):
            raise ValueError("jail.conf must be an owned regular file without group/other writes")
        if stopped and _kernel_jail(runner, name, root) is not None:
            raise RuntimeError("Jail restarted or is still dying; stop it before retrying removal")
        candidates.append((name, parent))
    if not candidates:
        return candidates
    try:
        inventory = json.loads(runner.output("bastille", "list", "-j", "path"))
    except ValueError:
        raise ValueError("Bastille did not return a valid named JSON jail inventory") from None
    if (not isinstance(inventory, list) or any(not isinstance(row, dict)
            or not isinstance(row.get("Name"), str) or not isinstance(row.get("Path"), str) for row in inventory)
            or len({row["Name"] for row in inventory}) != len(inventory)):
        raise ValueError("Bastille did not return an unambiguous named JSON jail inventory")
    paths = {row["Name"]: row["Path"] for row in inventory}
    for name, _ in candidates:
        if paths.get(name) != str(deployment.jail_root(name)):
            raise ValueError("Exact Bastille jail identity changed or is missing from inventory; removal refused")
    for name, _ in candidates:
        if runner.output("bastille", "config", name, "get", "path") != str(deployment.jail_root(name)):
            raise ValueError("Jail root identity changed; removal refused")
    return candidates


def _require_jail(deployment, name, *, stopped=False):
    if not _checked_jails(deployment, (name,), stopped=stopped):
        raise ValueError("Jail disappeared before its targeted Bastille mutation; removal refused")


def remove_instance(deployment, *, purge_data=False, confirmation):
    c, runner, registry = deployment.config, deployment.runner, deployment.registry
    phrase = ("PURGE " if purge_data else "REMOVE ") + c.instance
    if confirmation != phrase:
        raise ValueError("Instance removal requires the exact typed confirmation")
    previous = registry.status(c.instance)
    if previous["state"] == "removed" and (not purge_data or previous.get("data_retained") is False):
        return
    journal = Journal(deployment.state / ("purge.json" if purge_data else "removal.json"), c, deployment.progress)
    retained_flag = journal.data.get("runtime_already_removed", False)
    if type(retained_flag) is not bool:
        raise ValueError("Invalid runtime removal checkpoint")
    runtime_removed = _runtime_removed(deployment, previous) or retained_flag
    if not runtime_removed:
        _check_network_allocations(deployment)
    if "runtime_already_removed" not in journal.data or runtime_removed != retained_flag:
        journal.data["runtime_already_removed"] = runtime_removed
        journal.save()
    registry.set_status(c.instance, "removing", purge_data=purge_data)

    def stop():
        candidates = _checked_jails(deployment)
        if c.has_office and not c.native_office:
            from .office_vm import vm_paths, detach_native_vm_datastore, disable_vm_boot_service
            disable_vm_boot_service(deployment)
            paths = vm_paths(c)
            intent = deployment.state / (paths['name']+'.creating.json')
            if intent.exists() or intent.is_symlink():
                # Unsealed creation is intentionally refused by the ownership
                # helper. Do not destroy a partial/uncertain guest to make remove
                # proceed, and never pass VM names to Bastille.
                vm_marker = deployment.state / 'allow-vm-start'
                if vm_marker.exists() or vm_marker.is_symlink():
                    vm_marker.rename(deployment.state / 'allow-vm-start.disabled')
                detach_native_vm_datastore(deployment)
            else:
                from pathlib import Path
                if Path(paths['root']).exists() or Path(paths['root']).is_symlink():
                    raise ValueError('VM storage exists without its creation reservation; removal refused')
        marker = deployment.state / "allow-start"
        if marker.exists():
            marker.rename(deployment.state / "allow-start.disabled")
        for name, _ in candidates:
            _require_jail(deployment, name)
            runner.run("bastille", "config", name, "set", "boot", "off")
            current = _kernel_jail(runner, name, deployment.jail_root(name))
            if current is not None and not current["dying"]:
                _require_jail(deployment, name)
                if deployment.require_running_jail(name) != current["jid"]:
                    raise RuntimeError("Jail identity changed before stop; roots retained")
                runner.run("bastille", "stop", name, capture=False)
            _wait_for_jail_exit(runner, name, deployment.jail_root(name), current["jid"] if current else None)

    def withdraw_network():
        _check_network_allocations(deployment)
        if any(item.instance == c.instance for item in registry.network_configs()):
            deployment.configure_network(removing=True)
        _check_network_allocations(deployment)
        # Old PF states can outlive a rule reload. Kill only this instance's
        # endpoints, never global management or another instance's states.
        if (registry.root / "network/active").exists():
            addresses = (c.nextcloud_ip, c.onlyoffice_ip) if c.has_office else (c.nextcloud_ip,)
            for address in addresses:
                runner.run("pfctl", "-k", address)
                runner.run("pfctl", "-k", "0.0.0.0/0", "-k", address)

    def destroy_roots():
        candidates = _checked_jails(deployment, stopped=True)
        # Validate both roots before destroying either, then recheck each exact
        # target. A completed stop checkpoint does not establish current mounts.
        for name, dataset in candidates:
            _require_jail(deployment, name, stopped=True)
            runner.run("bastille", "destroy", "-y", name, capture=False)
            if runner.run("zfs", "list", "-H", dataset, check=False).returncode == 0:
                raise RuntimeError("Bastille did not destroy the requested jail root")

    def clean_bridges():
        _check_network_allocations(deployment)
        for bridge in c.bridges:
            gateway = c.nextcloud_gateway if bridge == c.nextcloud_bridge else c.onlyoffice_gateway
            result = runner.run("ifconfig", bridge, check=False)
            if result.returncode == 0:
                if "member:" in result.stdout or f"inet {gateway} " not in result.stdout:
                    raise ValueError("Bridge identity changed or still has members; cleanup refused")
                runner.run("ifconfig", bridge, "destroy")
            cloned = runner.run("sysrc", "-n", "cloned_interfaces", check=False).stdout.split()
            runner.run("sysrc", "cloned_interfaces=" + " ".join(value for value in cloned if value != bridge))
            runner.run("sysrc", "-x", f"ifconfig_{bridge}", check=False)

    def purge():
        if runner.run("zfs", "list", "-H", c.dataset_root, check=False).returncode:
            return
        actual = set(runner.output("zfs", "list", "-H", "-o", "name", "-r", c.dataset_root).splitlines())
        expected = {item.name for item in deployment.storage}
        if not actual or not actual <= expected:
            raise ValueError("Unexpected descendants exist below the instance dataset; purge refused")
        for name in actual:
            if runner.output("zfs", "get", "-H", "-o", "value", OWNER, name) != c.instance:
                raise ValueError("Unowned dataset encountered; purge refused")
        runner.run("zfs", "destroy", "-r", c.dataset_root, capture=False)
        if runner.run("zfs", "list", "-H", c.dataset_root, check=False).returncode == 0:
            raise RuntimeError("Instance data destruction did not finish")

    # A later purge of retained data must not touch network allocations that a
    # new instance may legitimately have reused since runtime removal.
    steps = [] if journal.data["runtime_already_removed"] else list(zip(
        RUNTIME_STEPS, (stop, withdraw_network, destroy_roots, clean_bridges)))
    if purge_data:
        steps.append(("permanently destroy instance data and snapshots", purge))
    journal.run(steps)
    atomic_json(deployment.state / "removed.json", {"data_retained": not purge_data,
                "dataset": c.dataset_root, "credentials_retained": True, "backups_retained": True})
    registry.set_status(c.instance, "removed", data_retained=not purge_data)
