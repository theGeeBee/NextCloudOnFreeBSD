"""Checkpointed instance orchestration on an exclusively managed FreeBSD host."""

from pathlib import Path
import hashlib
import json
import os
import re
import select
import shutil
import sys
import time
import uuid

from .config import STATE_DIR, Dataset, datasets
from .host import write_json, write_private
from .network import pf_rules, storage_guard
from . import firewall
from .paths import PROJECT_ROOT as ROOT, RESOURCES
from .state import Journal, Registry, atomic_json, atomic_write, private_json, private_directory


PF_FILE = Path("/etc/pf.cloud-installer.conf")
OWNER = "org.cloud-installer:instance"
COMPLETE_MESSAGE = "Installer checks passed; external proxy/browser/reboot acceptance remains required.\n"


def source_digest():
    """Identity of execution code/resources, independent of live credentials."""
    digest = hashlib.sha256()
    for directory in (ROOT / "installer", RESOURCES):
        for path in sorted(directory.rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                digest.update(str(path.relative_to(ROOT)).encode() + b"\0" + path.read_bytes())
    return digest.hexdigest() + "\n"


def public_directories(path, boundary):
    """Create public jail/host ancestors without inheriting the private umask.

    Existing directory modes are never widened; callers must supply an already
    verified root. Private state/payload directories must not use this helper.
    """
    boundary = Path(boundary)
    parts = Path(path).relative_to(boundary).parts
    if (boundary.is_symlink() or not boundary.is_dir()
            or any(part in (".", "..") for part in parts)):
        raise ValueError("Unexpected public directory boundary")
    current = boundary
    for part in parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("Public directory ancestors must not be symlinks")
        if current.exists():
            if not current.is_dir():
                raise ValueError("Public directory ancestor is not a directory")
        else:
            current.mkdir(mode=0o755)
            current.chmod(0o755)


def managed_block(path, label, contents, mode=0o644):
    """Replace our delimited block only; preserve unrelated packaged defaults."""
    path = Path(path)
    start, end = f"# BEGIN cloud-installer {label}", f"# END cloud-installer {label}"
    text = path.read_text() if path.exists() else ""
    if text.count(start) != text.count(end) or text.count(start) > 1:
        raise ValueError(f"Ambiguous managed block in {path}")
    block = start + "\n" + contents.rstrip() + "\n" + end
    if start in text:
        text = re.sub(re.escape(start) + r".*?" + re.escape(end), lambda _: block, text, flags=re.S)
    else:
        text = text.rstrip() + "\n\n" + block + "\n"
    atomic_write(path, text, mode)


class Deployment:
    def __init__(self, config, secrets, runner, ssh_connection=None, *, registry=None, progress=None):
        self.config = config.validate()
        config.require_jail_backend("Deployment operations")
        self.secrets = secrets
        self.runner = runner
        self.ssh_connection = ssh_connection
        self.registry = registry or Registry()
        self.state = self.registry.instance_path(config.instance)
        self.progress = progress
        self.storage = datasets(config)
        self.manifest = {}
        self._versions = None
        self._vm_image = None

    @property
    def versions(self):
        from .resolution import validate_plan
        if self._versions is None:
            path = self.registry.evidence_path(self.config.instance, "versions.json")
            if not path.is_file() or path.is_symlink():
                raise ValueError("No retained version lock: use the original installer artifact for an older deployment; do not infer an upgrade")
            policy_reader = getattr(self.registry, "version_policy", None)
            policy = policy_reader(self.config.instance) if policy_reader is not None else None
            self._versions = validate_plan(self.config, private_json(path), policy=policy)
        return self._versions

    def prepare_versions(self):
        """Resolve once, before host/storage mutations; Resume never reselects."""
        from .discovery import discover, probe_packages
        from .resolution import resolve
        path = self.state / "versions.json"
        if path.exists() or path.is_symlink():
            plan = self.versions
        else:
            if (self.state / "deployment.json").exists() or (self.state / "source.sha256").exists():
                raise ValueError("An existing deployment without a version lock requires its original artifact; automatic adoption/upgrades are unsupported")
            plan = resolve(self.config, discover(self.config, self.runner, directory=self.registry.root))
        probe_packages(self.config, plan, self.runner, directory=self.registry.root)
        # Shared host prerequisites cannot be silently changed for a new jail.
        for name, package in plan["packages"]["host"].items():
            current = self.runner.run("pkg", "query", "%v|%o", name, check=False)
            if current.returncode == 0 and current.stdout.strip() != package["version"] + "|" + package["origin"]:
                raise ValueError(f"Installed host package {name} differs from the resolved plan; an explicit host maintenance assessment is required")
        if not path.exists():
            atomic_json(path, plan)
        self._versions = plan
        return plan

    def checkpoint(self):
        atomic_json(self.state / "inventory.json", self.manifest)

    @property
    def plugin_lock(self):
        from .plugins import validate_lock
        from .versions import in_family, package_upstream
        path = self.registry.evidence_path(self.config.instance, "plugins.json")
        if not path.is_file() or path.is_symlink():
            raise ValueError("Selected plugins require their original retained lock; no automatic plugin adoption")
        lock = private_json(path)
        validate_lock(lock, self.config.onlyoffice_plugins)
        # Keep the catalog immutable; selected manifests are checked separately
        # against the actual Docs patch. Full native identities remain pkg-locked.
        version = package_upstream(self.versions["packages"]["onlyoffice"]["onlyoffice-documentserver"]["version"])
        if not in_family(version, "9.4"):
            raise ValueError("Selected plugins are not reviewed for this ONLYOFFICE version")
        return lock

    def prepare_plugins(self):
        from .plugins import check_payloads, make_lock, prepare
        from .versions import package_upstream
        if not self.config.onlyoffice_plugins:
            return
        path = self.state / "plugins.json"
        if (self.state / "source.sha256").exists():
            self.require_original_artifact()
        if not path.exists() and not path.is_symlink():
            if (self.state / "deployment.json").exists() or (self.state / "source.sha256").exists():
                raise ValueError("An existing deployment cannot acquire a guessed plugin lock")
            atomic_json(path, make_lock(self.config.onlyoffice_plugins))
        lock = self.plugin_lock
        # Authenticate all selected bytes before provisioning; Resume reuses only
        # this exact selection and refuses changed/unavailable locked inputs.
        prepare(lock, self.state / "plugin-artifacts")
        check_payloads(lock, self.state / "plugin-artifacts", docs_version=package_upstream(
            self.versions["packages"]["onlyoffice"]["onlyoffice-documentserver"]["version"]))

    def stage_plugins(self, target):
        from .plugins import check_cache
        lock = self.plugin_lock
        source = self.state / "plugin-artifacts"
        check_cache(lock, source)
        atomic_json(target / "plugins.json", lock)
        destination = private_directory(target / "plugin-artifacts")
        for name, record in lock["plugins"].items():
            for item in record["artifacts"]:
                relative = Path(name) / item["path"]
                parent = destination
                for component in relative.parts[:-1]:
                    parent = private_directory(parent / component)
                output = destination / relative
                if output.is_symlink() or (output.exists() and not output.is_file()):
                    raise ValueError("Unsafe plugin staging destination")
                shutil.copyfile(source / relative, output, follow_symlinks=False)
                output.chmod(0o600)
        check_cache(lock, destination)

    def plugin_command(self, mode):
        from .versions import package_upstream
        if mode not in ("install", "verify"):
            raise ValueError("Unknown managed plugin operation")
        if not self.config.onlyoffice_plugins:
            return
        self.plugin_lock  # Bind the staged jail operation to the immutable host selection.
        payload = self.jail_root(self.config.onlyoffice_jail) / "root/cloud-installer"
        if private_json(payload / "plugins.json") != self.plugin_lock:
            raise ValueError("Staged plugin lock differs from retained host selection")
        self.jail(self.config.onlyoffice_jail, "python3", "/root/cloud-installer/installer/plugins.py", mode,
                  "--lock", "/root/cloud-installer/plugins.json",
                   "--cache", "/root/cloud-installer/plugin-artifacts",
                   "--docs-version", package_upstream(self.versions["packages"]["onlyoffice"]["onlyoffice-documentserver"]["version"]),
                  "--root", "/usr/local/www/onlyoffice/documentserver/sdkjs-plugins",
                  "--state", "/var/db/cloud-installer-onlyoffice/plugins")
        if mode == "verify":
            self.manifest["onlyoffice_plugins"] = {
                name: {"version": record["version"], "guid": record["guid"]}
                for name, record in self.plugin_lock["plugins"].items()}

    def pkg(self, *args, **kwargs):
        return self.runner.run("/usr/bin/env", "-i",
                               "PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin", "LC_ALL=C",
                               "pkg", "-C", "/dev/null", "-o", f"REPOS_DIR={self.registry.root / 'repos'}", *args, **kwargs)

    def jail_root(self, name):
        if name not in self.config.jails:
            raise ValueError("Unexpected jail name")
        return Path(self.config.bastille_root, "jails", name, "root")

    def require_running_jail(self, name):
        if name not in self.config.jails:
            raise ValueError("Refusing to execute in an unmanaged jail")
        result = self.runner.run("jls", "-j", name, "jid", "name", "path", check=False)
        identity = (result.stdout or "").split()
        if (result.returncode or len(identity) != 3 or not identity[0].isdigit()
                or int(identity[0]) < 1 or identity[1] != name or identity[2] != str(self.jail_root(name))):
            raise RuntimeError(f"Managed jail {name} is stopped or has an unexpected identity/root")
        return int(identity[0])

    def jail(self, name, *args, **kwargs):
        # Bastille 1.4.4 cmd skips stopped jails with exit status zero. Require
        # the same live jail identity on both sides, not just command success.
        jid = self.require_running_jail(name)
        # jexec receives stdin unchanged. Bastille's multi-target cmd helper may
        # consume stdin; pin execution to the live JID already checked above.
        result = self.runner.run("jexec", str(jid), *args, **kwargs)
        if self.require_running_jail(name) != jid:
            raise RuntimeError(f"Managed jail {name} restarted during command execution")
        return result

    def install_manager(self):
        repos = private_directory(self.registry.root / "repos")
        atomic_write(repos / "FreeBSD.conf", '''FreeBSD-ports: {
  url: "pkg+https://pkg.FreeBSD.org/${ABI}/''' + self.config.repository + '''",
  mirror_type: "srv", signature_type: "fingerprints",
  fingerprints: "/usr/share/keys/pkg", enabled: yes
}
''')
        packages, missing = self.versions["packages"]["host"], False
        for name, record in packages.items():
            installed = self.runner.run("pkg", "query", "%v|%o", name, check=False)
            if installed.returncode:
                missing = True
            elif installed.stdout.strip() != record["version"] + "|" + record["origin"]:
                raise ValueError(f"Installed host package {name} differs from the retained version plan; refusing an implicit upgrade/downgrade")
        if missing:
            self.pkg("update", "-r", "FreeBSD-ports", capture=False)
            for name, record in packages.items():
                identity = self.pkg("rquery", "-U", "-r", "FreeBSD-ports", "%n|%v|%o|%u%d%{%|%}", name).stdout.strip()
                edges = self.pkg("rquery", "-U", "-r", "FreeBSD-ports", "%dn|%dv|%do", name).stdout.strip().splitlines()
                expected_edges = [f"{key}|{value['version']}|{value['origin']}" for key, value in record["dependencies"].items()]
                if identity != "|".join(record[key] for key in ("name", "version", "origin", "checksum")) or sorted(edges) != sorted(expected_edges):
                    raise ValueError(f"Host package {name} repository version/dependencies differ from the retained plan; no substitution is permitted")
            args = [name + "-" + record["version"] for name, record in sorted(packages.items())]
            self.pkg("install", "-n", "-y", "-U", "-r", "FreeBSD-ports", *args, capture=False)
            self.pkg("install", "-y", "-U", "-r", "FreeBSD-ports", *args, capture=False)
        for name, record in packages.items():
            if self.runner.output("pkg", "query", "%v|%o", name) != record["version"] + "|" + record["origin"]:
                raise RuntimeError(f"Installed host package {name} does not match the resolved version/origin")
        self.manifest["bastille_package"] = self.runner.output("pkg", "query", "%nv", "bastille")
        # Configure a private Bastille prefix, never the host's application paths.
        c = self.config
        settings = {"bastille_zfs_enable": "YES", "bastille_zfs_zpool": c.pool,
                     "bastille_zfs_prefix": "cloud-installer/bastille", "bastille_prefix": c.bastille_root,
                    "bastille_logsdir": c.bastille_root + "/logs", "bastille_network_vnet_type": "if_bridge",
                    "bastille_pf_conf": str(PF_FILE)}
        for key, value in settings.items():
            self.runner.run("sysrc", "-f", "/usr/local/etc/bastille/bastille.conf", f"{key}={value}")

    def ensure_dataset(self, dataset, owner):
        exists = self.runner.run("zfs", "list", "-H", dataset.name, check=False).returncode == 0
        if exists:
            if self.runner.output("zfs", "get", "-H", "-o", "value", OWNER, dataset.name) != owner:
                raise ValueError(f"Refusing unowned dataset: {dataset.name}")
            if self.runner.output("zfs", "get", "-H", "-o", "value", "mountpoint", dataset.name) != dataset.mountpoint:
                raise ValueError(f"Managed dataset mountpoint changed: {dataset.name}")
        else:
            target = Path(dataset.mountpoint)
            if target.is_symlink() or (target.exists() and any(target.iterdir())):
                raise ValueError(f"Refusing to cover existing storage: {dataset.mountpoint}")
            command = ["zfs", "create", "-o", f"{OWNER}={owner}", "-o", "org.cloud-installer:owner=cloud-installer"]
            for name, value in dataset.properties.items():
                command.extend(["-o", f"{name}={value}"])
            self.runner.run(*command, dataset.name)
        if self.runner.output("zfs", "get", "-H", "-o", "value", "mounted", dataset.name) != "yes":
            self.runner.run("zfs", "mount", dataset.name)
        # ZFS properties and the actual mount must agree, not just a directory.
        if self.runner.output("df", "-P", dataset.mountpoint).splitlines()[-1].split()[0] != dataset.name:
            raise RuntimeError(f"Dataset is not the actual filesystem at {dataset.mountpoint}")

    def create_shared_storage(self):
        c = self.config
        shared = [Dataset(f"{c.pool}/cloud-installer", "/srv/cloud-installer", executable=True),
                        Dataset(f"{c.pool}/cloud-installer/instances", "/srv/cloud-installer/instances", executable=True),
                        Dataset(c.bastille_dataset, c.bastille_root, executable=True)]
        if c.backend in ('eurooffice','collabora'):
            from .office_vm import vm_paths
            paths = vm_paths(c)
            shared.append(Dataset(paths['manager_dataset'], paths['manager_root']))
        for dataset in shared:
            self.ensure_dataset(dataset, "shared")
            self.runner.run("chmod", "700", dataset.mountpoint)

    def create_storage(self):
        for dataset in self.storage:
            self.ensure_dataset(dataset, self.config.instance)
            if dataset.name in (self.config.dataset_root, self.config.dataset_root + '/office-vm'):
                # Jail processes enter their root vnodes directly, but ordinary
                # host users must not traverse into raw document caches/secrets.
                self.runner.run("chmod", "700", dataset.mountpoint)

    def configure_network(self, *, removing=False):
        from .host import verify_managed_network
        c = self.config
        if firewall.pending_transactions(self.registry.root):
            raise ValueError("An unconfirmed network transaction remains; use recover-network before another PF change")
        for module in ("if_bridge", "if_epair", "pf"):
            self.runner.run("kldload", "-n", module)
        active = self.registry.root / "network/active"
        previous = active.resolve() if active.is_symlink() else None
        if previous:
            verify_managed_network(self.registry, self.runner)
        else:
            for args in (("-sr",), ("-sn",), ("-s", "Anchors"), ("-ss",)):
                if self.runner.output("pfctl", *args):
                    raise ValueError("Foreign PF rules, anchors or states appeared after preflight; refusing to replace them")
        state = private_directory(self.registry.root / "transactions" / uuid.uuid4().hex)
        backups = {}
        for source in (Path("/etc/rc.conf"), Path("/etc/sysctl.conf"), Path("/boot/loader.conf"), PF_FILE):
            backup = source.name + ".before"
            if source == PF_FILE and previous:
                # Rollback must come from the committed record, not mutable
                # disk contents even if they drift after read-only preflight.
                policy = private_json(previous / "firewall-transition.json")["network"]["pf_rules"]
                write_private(state / backup, policy)
                backups[str(source)] = backup
            elif source.exists():
                write_private(state / backup, source.read_text())
                backups[str(source)] = backup
            else:
                backups[str(source)] = None
        configs = self.registry.network_configs(exclude=c.instance)
        if not removing:
            configs.append(c)
        bridges = {} if removing else {
            name: c.nextcloud_gateway if name == c.nextcloud_bridge else c.onlyoffice_gateway for name in c.bridges
            if self.runner.run("ifconfig", name, check=False).returncode != 0}
        sysctls = {"net.link.bridge.pfil_member": "0", "net.link.bridge.pfil_bridge": "1",
                   "net.link.bridge.pfil_local_phys": "0", "net.link.bridge.pfil_onlyip": "1"}
        transaction = {"forwarding": self.runner.output("sysctl", "-n", "net.inet.ip.forwarding"),
                       "boot_identity": self.runner.output("sysctl", "-n", "kern.boottime"),
                       "instances": sorted(item.instance for item in configs),
                       "bridge_sysctls": {name: self.runner.output("sysctl", "-n", name) for name in sysctls},
                       "bridges": list(bridges), "previous_pf_enabled": bool(previous),
                       "previous_pf_file": str(state / (PF_FILE.name + ".before")) if previous else None,
                       "active_link": str(active), "previous_active": str(previous) if previous else None,
                       "backups": backups, "deadline": time.monotonic() + 180,
                       "network": {"bridge_addresses": bridges,
                                    "bridge_sysctls": sysctls, "pf_file": str(PF_FILE),
                                    "pf_rules": pf_rules(configs, self.ssh_connection, host_config=c)}}
        write_json(state / "firewall-transition.json", transaction)
        # The detached supervisor owns a separate process-group worker. The
        # interactive parent must NEVER hold a network lock: SIGSTOP or a stall
        # here must not prevent independent rollback.
        controller = firewall.arm(state)
        try:
            controller.wait_applied()
            self.enable_firewall_with_confirmation(controller)
        except BaseException:
            controller.cancel()
            raise

    def enable_firewall_with_confirmation(self, controller):
        deadline = controller.deadline
        remaining = max(0, int(deadline - time.monotonic()) - 5)
        print("\nPF is active. Open a SECOND SSH session to confirm management access.")
        print(f"Type KEEP within {remaining} seconds. Otherwise PF/network changes are rolled back.", flush=True)
        if not select.select([sys.stdin], [], [], remaining)[0] or sys.stdin.readline().strip() != "KEEP":
            raise RuntimeError("Firewall not confirmed")
        controller.confirm()

    def configure_devfs(self):
        directory = Path("/usr/local/etc/cloud-jails")
        directory.mkdir(mode=0o700, exist_ok=True)
        rules = directory / "devfs.rules"
        atomic_write(rules, '''[bastille_vnet=13]
add include $devfsrules_hide_all
add include $devfsrules_unhide_basic
add include $devfsrules_unhide_login
add include $devfsrules_jail
add include $devfsrules_jail_vnet
add path 'bpf*' unhide
''')
        rulesets = self.runner.run("sysrc", "-n", "devfs_rulesets", check=False).stdout.strip().split()
        if str(rules) not in rulesets:
            self.runner.run("sysrc", f"devfs_rulesets+= {rules}")
        self.runner.run("service", "devfs", "restart", capture=False)
        if not self.runner.output("devfs", "rule", "-s", "13", "show"):
            raise RuntimeError("Bastille's VNET devfs ruleset 13 did not load")
        # rc ordering alone is insufficient: the per-jail exec.prepare guard
        # below enforces policy/mount readiness even if this rc command fails.
        script = Path("/usr/local/etc/rc.d/cloud_jails_guard")
        atomic_write(script, '''#!/bin/sh
# PROVIDE: cloud_jails_guard
# REQUIRE: NETWORKING pf zfs devfs
# BEFORE: bastille
# KEYWORD: nojail
. /etc/rc.subr
name=cloud_jails_guard
rcvar=cloud_jails_guard_enable
start_cmd=cloud_jails_guard_start
stop_cmd=:
cloud_jails_guard_start() {
    /sbin/pfctl -s Running >/dev/null 2>&1
}
load_rc_config "$name"
run_rc_command "$1"
''', mode=0o700)
        self.runner.run("sysrc", "cloud_jails_guard_enable=YES")

    def bootstrap_jails(self):
        c = self.config
        release = Path(c.bastille_root, "releases", c.release)
        if not (release / "bin/sh").is_file():
            self.runner.run("bastille", "bootstrap", "--pkgbase", c.release, capture=False)
        for name in c.jails:
            address, bridge, gateway, hostname = (
                (c.nextcloud_ip, c.nextcloud_bridge, c.nextcloud_gateway, c.nextcloud_host)
                if name == c.nextcloud_jail else
                (c.onlyoffice_ip, c.onlyoffice_bridge, c.onlyoffice_gateway, c.onlyoffice_host))
            intent = self.state / (name + ".creating.json")
            root = self.jail_root(name)
            if not root.parent.exists():
                atomic_json(intent, {"name": name, "root": str(root), "release": c.release})
                self.runner.run("bastille", "create", "-T", "-B", "--no-boot", "-g", gateway, "-n", c.dns_server,
                                name, c.release, address + "/30", bridge, capture=False)
            elif not intent.exists() or private_json(intent) != {"name": name, "root": str(root), "release": c.release}:
                raise ValueError("A jail path exists without this instance's creation reservation; refusing adoption")
            if not (root / "bin/sh").is_file() or not (root.parent / "jail.conf").is_file():
                raise RuntimeError(f"Incomplete Bastille root for {name}; remove this failed instance through the menu before recreating it")
            actual_path = self.runner.output("bastille", "config", name, "get", "path")
            if actual_path != str(self.jail_root(name)):
                raise ValueError("Bastille returned an unexpected jail root path")
            # create starts a jail even with --no-boot; stop before mounting storage.
            if self.runner.run("jls", "-j", name, check=False).returncode == 0:
                self.require_running_jail(name)
                self.runner.run("bastille", "stop", name, capture=False)
            if self.runner.run("jls", "-j", name, check=False).returncode == 0:
                raise RuntimeError("Bastille did not stop the jail; refusing to cover live storage with mounts")
            self.runner.run("zfs", "set", f"{OWNER}={c.instance}", f"{c.bastille_dataset}/jails/{name}")
            # Thick send/receive can carry release properties. Pin the actual
            # root explicitly rather than depending on inherited ownership.
            self.runner.run("zfs", "set", f"{OWNER}={c.instance}", f"{c.bastille_dataset}/jails/{name}/root")
            quota = c.system_quota_gib
            if c.native_office:
                quota = c.system_quota_gib // 2 if name == c.nextcloud_jail else c.system_quota_gib - c.system_quota_gib // 2
            if quota:
                self.runner.run("zfs", "set", f"quota={quota}G", f"{c.bastille_dataset}/jails/{name}")
            self.runner.run("bastille", "config", name, "set", "host.hostname", hostname)

    def attach_storage(self):
        c = self.config
        guard_path = Path(f"/usr/local/libexec/{c.instance}-storage-guard")
        public_directories(guard_path.parent, Path("/usr/local"))
        atomic_write(guard_path, storage_guard(c, self.storage, self.registry.root), mode=0o700)
        for jail in c.jails:
            if self.runner.run("jls", "-j", jail, check=False).returncode == 0:
                self.require_running_jail(jail)
                self.runner.run("bastille", "stop", jail, capture=False)
            root = self.jail_root(jail)
            if not root.is_dir() or root.is_symlink():
                raise ValueError("Unexpected Bastille jail root layout")
            mappings = sorted((item for item in self.storage if item.jail == jail),
                              key=lambda item: len(Path(item.target).parts))
            for dataset in mappings:
                # Seed base log files before nullfs hides the jail's /var/log.
                if dataset.target == "/var/log":
                    for source in (root / "var/log").iterdir():
                        destination = Path(dataset.mountpoint) / source.name
                        if not destination.exists() and not destination.is_symlink():
                            if source.is_dir() and not source.is_symlink():
                                shutil.copytree(source, destination, symlinks=True)
                            else:
                                shutil.copy2(source, destination, follow_symlinks=False)
                parents = [item for item in mappings if item != dataset and
                           Path(item.target) in Path(dataset.target).parents]
                if parents:
                    parent = max(parents, key=lambda item: len(item.target))
                    target = Path(parent.mountpoint) / Path(dataset.target).relative_to(parent.target)
                    boundary = Path(parent.mountpoint)
                else:
                    target = root / dataset.target.lstrip("/")
                    boundary = root
                public_directories(target, boundary)
            jail_dir = root.parent
            conf_path = jail_dir / "jail.conf"
            jail_conf = conf_path.read_text()
            if "mount.fstab" not in jail_conf:
                raise ValueError("Bastille jail.conf has no persistent fstab; port layout changed")
            # Bastille's fstab is the native persistent-mount interface. Direct
            # editing here avoids starting a jail before its mounts are complete.
            fstab = jail_dir / "fstab"
            managed_block(fstab, "persistent mounts", "\n".join(
                f"{dataset.mountpoint} {root}{dataset.target} nullfs rw 0 0" for dataset in mappings))
            self.install_prepare_guard(jail, guard_path)
            # Internal DNS keeps HTTPS hostname validation and avoids NAT hairpinning.
            hosts = f"{c.nextcloud_ip} {c.public_hostname} {c.nextcloud_host}"
            if c.native_office:
                hosts += f"\n{c.onlyoffice_ip} {c.onlyoffice_host}"
            managed_block(root / "etc/hosts", "instance hosts", hosts)
        atomic_write(self.state / "allow-start", "Instance resource ownership and mount graph installed.\n")
        self.ensure_running()

    def ensure_running(self):
        for jail in self.config.jails:
            self.runner.run(f"/usr/local/libexec/{self.config.instance}-storage-guard", jail)
            if self.runner.run("jls", "-j", jail, check=False).returncode != 0:
                self.runner.run("bastille", "start", jail, capture=False)
            self.require_running_jail(jail)

    def install_prepare_guard(self, jail, script):
        # Use the native property interface. VNET jail.conf contains shell
        # ${epair0}/${epair0%a} expressions; brace counting/replacement corrupts it.
        # exec.prepare is distinct from Bastille's existing exec.prestart hooks.
        self.runner.run("bastille", "config", jail, "set", "exec.prepare", f"{script} {jail}")

    def stage_payloads(self):
        from .version_runtime import connector_text, dependency_text, package_text, runtime_versions
        c = self.config
        # Only runtime settings belong in a jail, not host management addresses,
        # dataset administration settings or source private-key paths.
        common = {key: getattr(c, key) for key in (
            "instance", "public_hostname", "admin_username", "admin_email", "timezone", "repository",
            "tls_mode", "acme_email", "php_memory_mb", "db_buffer_mb", "redis_memory_mb", "upload_max_mb",
            "font_profile")}
        common.update(nextcloud_ip=c.nextcloud_ip, **({"onlyoffice_ip": c.onlyoffice_ip} if c.has_office else {}),
                       php_children=c.php_children, db_name="nextcloud", public_url=c.public_url,
                       storage_url=c.storage_url, proxy_networks=c.trusted_proxy_networks)
        if c.backend == "none":
            common.pop("storage_url")
        # Copy an allowlist, never the repository root, .git, saved configs or logs.
        for jail in c.jails:
            target = self.jail_root(jail) / "root/cloud-installer"
            target.mkdir(mode=0o700, exist_ok=True)
            if target.is_symlink():
                raise ValueError("Provisioning payload directory must not be a symlink")
            vhosts = ('www-none.conf','https-none.conf','external-none.conf') if c.backend == 'none' else (
                'www.conf','https.conf','external.conf')
            sources = ("installer", "resources") if c.native_office else (
                *("resources/templates/nextcloud/" + name for name in (
                    "certbot-cron", "certbot-deploy", "challenge.conf", "cloud_php_dirs", "httpd.conf",
                    "my.cnf", "mysql-flush-logs", "newsyslog.conf", "php-fpm.conf", "php.ini", "redis.conf",
                    "www-crontab", *vhosts)),
                *("resources/jails/" + name for name in ("nextcloud.sh", "nextcloud-bootstrap.php",
                    "nextcloud-cron-fence.php", "runtime-inventory.php", "maintenance.php", "versions.sh", "ssh.sh")))
            for relative in sources:
                source = ROOT / relative
                if source.is_symlink() or any(path.is_symlink() for path in source.rglob("*")):
                    raise ValueError("Payload source must not contain symlinks")
                destination = target / relative
                if source.is_dir():
                    shutil.copytree(source, destination,
                                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"), dirs_exist_ok=True)
                else:
                    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    shutil.copy2(source, destination, follow_symlinks=False)
            runtime = dict(common)
            if jail == c.onlyoffice_jail:
                runtime = {key: common[key] for key in ("public_hostname", "public_url", "storage_url",
                            "nextcloud_ip", "onlyoffice_ip", "repository", "tls_mode", "font_profile")}
                runtime["additional_fonts"] = bool(c.additional_fonts_dir)
                runtime["accept_microsoft_fonts"] = c.accept_microsoft_fonts
            else:
                runtime.pop("instance")
                runtime.pop("font_profile")
                if c.nextcloud_apps or c.additional_nextcloud_apps:
                    runtime["nextcloud_apps"] = ",".join(c.selected_nextcloud_apps) or "none"
            group = "onlyoffice" if jail == c.onlyoffice_jail else "nextcloud"
            packages = package_text(self.versions, group)
            dependencies = dependency_text(self.versions, group)
            runtime["versions"] = runtime_versions(self.versions, packages, dependencies)
            atomic_write(target / "packages.lock", packages)
            atomic_write(target / "packages.dependencies", dependencies)
            if c.has_office:
                atomic_write(target / "connector.json", connector_text(self.versions))
            if c.native_office:
                atomic_write(target / "fonts-unavailable", "".join(name + "\n" for name in self.versions.get("fonts_unavailable", [])))
            atomic_json(target / "runtime.json", runtime)
            tls = target / "tls"
            tls.mkdir(mode=0o700, exist_ok=True)
            if c.tls_mode == "provided":
                if jail == c.nextcloud_jail:
                    atomic_write(tls / "fullchain.pem", Path(c.certificate_file).read_text())
                    atomic_write(tls / "privkey.pem", Path(c.private_key_file).read_text())
            if c.ca_file:
                atomic_write(tls / "ca.pem", Path(c.ca_file).read_text())
            if jail == c.onlyoffice_jail and c.additional_fonts_dir:
                self.stage_fonts(target / "fonts")
            if jail == c.onlyoffice_jail and c.onlyoffice_plugins:
                self.stage_plugins(target)

    def stage_fonts(self, target):
        source = Path(self.config.additional_fonts_dir)
        target.mkdir(mode=0o700, exist_ok=True)
        total, count = 0, 0
        for path in sorted(source.rglob("*")):
            if path.is_symlink():
                raise ValueError("Custom font inputs must not contain symlinks")
            if path.is_dir():
                continue
            if not path.is_file() or path.suffix.lower() not in (".ttf", ".otf", ".ttc"):
                raise ValueError("Custom font directory may contain only regular TTF, OTF and TTC font files")
            total += path.stat().st_size
            count += 1
            if total > 2 * 1024 ** 3 or count > 10000:
                raise ValueError("Custom fonts exceed the 2 GiB / 10,000-file input limit")
            with path.open("rb") as stream:
                if stream.read(4) not in (b"\x00\x01\x00\x00", b"OTTO", b"ttcf", b"true"):
                    raise ValueError("Unrecognized custom font file header")
            destination = target / path.relative_to(source)
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copyfile(path, destination, follow_symlinks=False)
            destination.chmod(0o600)

    def install_nextcloud(self):
        self.nextcloud_phase("prepare")

    def nextcloud_phase(self, phase, keys=()):
        kwargs = {"input": json.dumps({key: self.secrets[key] for key in keys}),
                  "progress_label": "Nextcloud " + phase} if keys else {"capture": False}
        self.jail(self.config.nextcloud_jail, "/bin/sh", "/root/cloud-installer/resources/jails/nextcloud.sh", phase, **kwargs)

    def install_onlyoffice(self):
        self.config.require_native_backend("ONLYOFFICE installation")
        self.jail(self.config.onlyoffice_jail, "/bin/sh", "/root/cloud-installer/resources/jails/onlyoffice.sh",
                  input=json.dumps({"jwt_secret": self.secrets["jwt_secret"]}), progress_label="ONLYOFFICE packages/fonts/services")
        unavailable = self.jail_root(self.config.onlyoffice_jail) / "var/db/cloud-installer-onlyoffice/fonts-unavailable"
        if unavailable.is_file():
            names = unavailable.read_text().splitlines()
            if names and all(re.fullmatch(r"[A-Za-z0-9_+-]+", name) for name in names):
                print("Optional font packages unavailable in this repository: " + ", ".join(names), flush=True)

    def prepare_office_vm_image(self):
        from .office_vm import vm_paths, native_vm_identity, acquire_guest_image
        if self.config.backend not in ('eurooffice','collabora'):
            raise ValueError('The selected VM installation path is not implemented')
        paths=vm_paths(self.config)
        receipt=self.state/(paths['name']+'.creating.json')
        if receipt.exists() or receipt.is_symlink():
            record=private_json(receipt)
            if isinstance(record,dict) and 'vm_config_sha256' in record:
                native_vm_identity(self) # Sealed creation does not need the old acquisition cache.
                self._vm_image=None
                return
        if Path(paths['root']).exists() or Path(paths['root']).is_symlink():
            raise ValueError('Uncertain partial VM creation requires inspection before host mutations')
        self._vm_image=acquire_guest_image(self)

    def create_office_vm(self):
        from .office_vm import create_native_vm
        return create_native_vm(self,getattr(self,'_vm_image',None))

    def start_office_vm(self):
        from .office_vm import start_native_vm, wait_native_guest
        start_native_vm(self,install_continuation=True)
        return wait_native_guest(self)

    def bootstrap_office_vm(self):
        from .office_vm import bootstrap_native_guest
        return bootstrap_native_guest(self)

    def install_vm_office(self):
        from .office_vm import install_eurooffice_container,install_collabora_container
        return (install_collabora_container if self.config.backend=='collabora' else install_eurooffice_container)(self)

    def check_office_vm_bootstrap(self):
        from .office_vm import verify_native_guest_bootstrap
        return verify_native_guest_bootstrap(self)

    def continue_vm_office(self):
        from .office_vm import install_eurooffice_container,install_collabora_container
        return (install_collabora_container if self.config.backend=='collabora' else install_eurooffice_container)(self,require_existing=True)

    def restart_office_vm(self):
        from .office_vm import stop_native_vm
        stop_native_vm(self)
        self.start_office_vm()

    def integrate(self):
        from .operations import _database_guard
        # The caller already holds the host operation lock. Keep the database
        # guard through writer closure, initial cron and schedule publication.
        with _database_guard(self):
            self._integrate()

    def _integrate(self):
        c = self.config
        if c.backend == "none":
            self.nextcloud_phase("finish")
            return
        if c.backend == 'eurooffice':
            from .office_vm import vm_apache_proxy, vm_connector_settings
            settings = vm_connector_settings(c,jwt_secret=self.secrets.get('jwt_secret'))
            self.wait_for_vm_office()
            payload = self.jail_root(c.nextcloud_jail) / 'root/cloud-installer'
            atomic_write(payload / 'apache-onlyoffice.conf',vm_apache_proxy(c))
            self.jail(c.nextcloud_jail,'/bin/sh','/root/cloud-installer/resources/jails/nextcloud.sh','finish',
                      input=json.dumps(settings),
                      progress_label='Nextcloud Euro-Office integration')
            return
        if c.backend=='collabora':
            from .office_vm import vm_apache_proxy,vm_connector_settings
            self.collabora_readiness_identity(publish=True)
            payload=self.jail_root(c.nextcloud_jail)/'root/cloud-installer'
            atomic_write(payload/'apache-onlyoffice.conf',vm_apache_proxy(c))
            self.jail(c.nextcloud_jail,'/bin/sh','/root/cloud-installer/resources/jails/nextcloud.sh','finish',
                      input=json.dumps(vm_connector_settings(c)),progress_label='Nextcloud Collabora activation')
            self.verify_connector_urls()
            return
        c.require_native_backend("Document integration")
        from .office import apache_proxy, connector_settings
        from .version_runtime import dependency_text, package_text, runtime_versions
        # Resume can skip office provisioning after ensure_running starts jails.
        # Supervisor/DocService startup is asynchronous even when rc succeeds.
        self.wait_for_office()
        runtime = {"public_hostname": c.public_hostname, "nextcloud_ip": c.nextcloud_ip,
                   "onlyoffice_ip": c.onlyoffice_ip, "jwt_secret": self.secrets["jwt_secret"],
                   "repository": c.repository, "tls_mode": c.tls_mode,
                    "public_url": c.public_url, "storage_url": c.storage_url}
        runtime["versions"] = runtime_versions(self.versions, package_text(self.versions, "nextcloud"),
                                              dependency_text(self.versions, "nextcloud"))
        payload = self.jail_root(c.nextcloud_jail) / "root/cloud-installer"
        atomic_write(payload / "apache-onlyoffice.conf", apache_proxy(runtime))
        self.jail(c.nextcloud_jail, "/bin/sh", "/root/cloud-installer/resources/jails/nextcloud.sh", "finish",
                  input=json.dumps(connector_settings(runtime)), progress_label="Nextcloud document integration")

    def enable_boot(self):
        if self.config.has_office and not self.config.native_office:
            from .office_vm import publish_vm_boot_service
            publish_vm_boot_service(self)
        for name in self.config.jails:
            self.runner.run("bastille", "config", name, "set", "boot", "on")
        self.runner.run("sysrc", "bastille_enable=YES")

    def restart_jails(self):
        # Exercise mount/service persistence before announcing a new deployment.
        # This is not a substitute for a host reboot and external-network test.
        for name in reversed(self.config.jails):
            self.runner.run("bastille", "restart", name, capture=False)
            if self.runner.output("jls", "-j", name, "path") != str(self.jail_root(name)):
                raise RuntimeError("Jail failed to restart with its expected root")

    def wait_for_office(self):
        self.config.require_native_backend("ONLYOFFICE readiness")
        # Supervisor starts asynchronously; a successful jail/rc restart is not
        # proof that DocService is already accepting conversion requests.
        self.jail(self.config.onlyoffice_jail, "python3", "-c", '''import sys, time, urllib.request
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
for attempt in range(60):
    try:
        with opener.open(sys.argv[1], timeout=5) as response:
            if response.read(1024).strip()==b'true':
                raise SystemExit(0)
    except (OSError, ValueError):
        pass
    time.sleep(2)
raise SystemExit('ONLYOFFICE did not become ready after startup')
''', f"http://{self.config.onlyoffice_ip}:8081/healthcheck")

    def wait_for_vm_office(self):
        if self.config.backend != 'eurooffice':
            raise ValueError('No implemented readiness probe for the selected VM backend')
        from .office_vm import native_vm_identity, _vm_network_ready
        target = native_vm_identity(self)
        if not target['state'].startswith('Running ('):
            raise ValueError('Selected office VM is not running')
        _vm_network_ready(self,target)
        # NC -> selected private frontend, not a VM-local curl. No proxy env,
        # insecure HTTPS or arbitrary user URL. Health is not editor acceptance.
        self.jail(self.config.nextcloud_jail,'python3','-c','''import sys,time,urllib.request
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
deadline=time.monotonic()+120
while time.monotonic()<deadline:
    try:
        with opener.open(sys.argv[1],timeout=5) as response:
            if response.status==200 and response.read(1024).strip()==b'true': raise SystemExit(0)
    except (OSError,ValueError): pass
    time.sleep(2)
raise SystemExit('Selected Euro-Office frontend health deadline expired')
''','http://'+self.config.onlyoffice_ip+':8081/healthcheck',timeout=135,hide_output=True)

    def read_collabora_endpoints(self, *, expected_proof_sha256=None):
        """Read-only bounded NC->CODE discovery, not activation or saved readiness."""
        if self.config.backend!='collabora':
            raise ValueError('CODE endpoint inspection requires its selected backend')
        import base64
        import binascii
        from .office_vm import native_vm_identity, _vm_network_ready, verify_collabora_container, validate_collabora_endpoints
        target=native_vm_identity(self)
        if not target['state'].startswith('Running ('):raise ValueError('Selected CODE VM is not running')
        _vm_network_ready(self,target)
        verify_collabora_container(self)
        from .state import config_digest
        proof=private_json(self.state/'collabora-proof.json')
        if (not isinstance(proof,dict) or type(proof.get('schema_version')) is not int or proof['schema_version']!=2
                or proof.get('config_sha256')!=config_digest(self.config)
                or not isinstance(proof.get('public_key_sha256'),str) or not re.fullmatch(r'[a-f0-9]{64}',proof['public_key_sha256'])):
            raise ValueError('CODE endpoint inspection requires its provisioned public key identity')
        program='''import base64,json,time,urllib.request,urllib.error,sys
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): raise ValueError('Unexpected CODE endpoint redirect')
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
base='http://'+sys.argv[1]+':8081/collabora/hosting/'
deadline=time.monotonic()+120
while time.monotonic()<deadline:
    try:
        values={}
        for name,limit in (('discovery',1048576),('capabilities',65536)):
            with opener.open(base+name,timeout=5) as response:
                if response.status!=200: raise ValueError('Unexpected CODE endpoint status')
                body=response.read(limit+1)
            if not 0<len(body)<=limit: raise ValueError('CODE endpoint response exceeded bounds')
            values[name]=base64.b64encode(body).decode()
        print(json.dumps(values));break
    except urllib.error.HTTPError as error:
        if error.code not in (502,503,504): raise
    except OSError: pass
    time.sleep(2)
else:raise SystemExit('CODE endpoint readiness deadline expired')
'''
        response=self.jail(self.config.nextcloud_jail,'python3','-c',program,self.config.onlyoffice_ip,timeout=135,hide_output=True)
        try:
            if len(response.stdout)>2*1024**2:raise ValueError
            value=json.loads(response.stdout)
            if not isinstance(value,dict) or set(value)!={'discovery','capabilities'}:raise ValueError
            discovery=base64.b64decode(value['discovery'],validate=True)
            capabilities=base64.b64decode(value['capabilities'],validate=True)
        except (ValueError,TypeError,binascii.Error):
            raise ValueError('CODE endpoint transport returned no valid bounded response') from None
        return validate_collabora_endpoints(self.config,self.versions,discovery,capabilities,
                                            expected_proof_sha256=expected_proof_sha256,
                                            expected_public_key_sha256=proof['public_key_sha256'])

    def collabora_readiness_identity(self, *, publish=False):
        from .state import config_digest
        if self.config.backend!='collabora' or type(publish) is not bool:
            raise ValueError('CODE readiness identity requires its selected backend')
        path=self.state/'collabora-readiness.json'
        exists=path.exists() or path.is_symlink()
        if not exists and not publish:
            raise ValueError('CODE saved endpoint identity is missing; verification never publishes it')
        previous=private_json(path) if exists else None
        reference=self.versions['office_runtime']['container']['reference']
        if exists and (not isinstance(previous,dict) or type(previous.get('schema_version')) is not int
                or previous['schema_version']!=1 or previous.get('config_sha256')!=config_digest(self.config)
                or previous.get('image')!=reference or not isinstance(previous.get('proof_sha256'),str)
                or not re.fullmatch(r'[a-f0-9]{64}',previous['proof_sha256'])):
            raise ValueError('CODE saved endpoint identity changed')
        value=self.read_collabora_endpoints(expected_proof_sha256=previous['proof_sha256'] if exists else None)
        expected={'schema_version':1,'config_sha256':config_digest(self.config),'image':reference,
                  'proof_sha256':value['proof_sha256'],'public_key_sha256':value['public_key_sha256'],
                  'product_version':value['product_version'],'public_url':value['public_url']}
        if exists and previous!=expected:raise ValueError('CODE endpoint identity differs; no rotation/reselection inferred')
        if not exists:atomic_json(path,expected)
        return {**value,'state':'running','image':reference,'discovery_verified':True}

    def verify_database_configuration(self):
        result = self.jail(
            self.config.nextcloud_jail, "mariadb", "--no-defaults", "--protocol=socket",
            "--socket=/var/run/mysql/mysql.sock", "--user=root", "--batch",
            "--skip-column-names", "--execute", "SELECT @@innodb_log_file_size",
            timeout=30, hide_output=True)
        value = result.stdout.strip()
        if not re.fullmatch(r"[0-9]{1,20}", value) or int(value) < 128 * 1024 * 1024:
            raise RuntimeError("MariaDB effective innodb_log_file_size must be at least 128 MiB; "
                               "verification does not change database configuration")
        self.manifest["database_configuration"] = {"innodb_log_file_size": int(value)}

    def verify_connector_urls(self):
        c = self.config
        if c.backend=='collabora':
            from .office_vm import vm_connector_settings
            app,label='richdocuments','Collabora'
            expected={**vm_connector_settings(c)['apps']['richdocuments'],'public_wopi_url':c.public_url.rstrip('/')}
        elif c.backend=='eurooffice':
            app,label='eurooffice','Euro-Office'
        else:
            c.require_native_backend("ONLYOFFICE connector verification")
            app,label='onlyoffice','ONLYOFFICE'
        if c.backend!='collabora':
            expected = {"DocumentServerUrl": c.public_url + app + "/",
                        "DocumentServerInternalUrl": f"http://{c.onlyoffice_ip}:8081/",
                        "StorageUrl": c.storage_url}
        for key, value in expected.items():
            result = self.jail(c.nextcloud_jail, "mdo", "-u", "www", "php",
                               "/usr/local/www/nextcloud/occ", "config:app:get", app, key,
                               timeout=30, hide_output=True)
            if result.stdout.strip() != value:
                raise RuntimeError(f"{label} {key} differs from the retained configuration; "
                                   "verification never rewrites connector settings")

    def verify(self):
        c = self.config
        for name in c.jails:
            self.require_running_jail(name)
        for name, record in self.versions["packages"]["host"].items():
            if self.runner.output("pkg", "query", "%v|%o", name) != record["version"] + "|" + record["origin"]:
                raise RuntimeError("Host prerequisites differ from the retained version lock; verification never changes them")
        for name in c.jails:
            self.runner.run(f"/usr/local/libexec/{c.instance}-storage-guard", name)
        if c.native_office:
            self.wait_for_office()
            self.plugin_command("verify")
        elif c.backend=='eurooffice':
            from .office_vm import verify_eurooffice_container
            self.manifest['office_vm']=verify_eurooffice_container(self)
            self.wait_for_vm_office()
        elif c.backend=='collabora':
            self.manifest['office_vm']=self.collabora_readiness_identity()
        for service in ("mysql-server", "redis", "php_fpm", "apache24", "cron"):
            self.jail(c.nextcloud_jail, "service", service, "status", capture=False)
        if c.antivirus:
            for service in ("clamav_clamd", "clamav_freshclam"):
                self.jail(c.nextcloud_jail, "service", service, "onestatus", capture=False)
        self.verify_database_configuration()
        if c.native_office:
            self.verify_connector_urls()
            for service in ("supervisord", "nginx"):
                self.jail(c.onlyoffice_jail, "service", service, "status", capture=False)
            processes = self.jail(c.onlyoffice_jail, "supervisorctl", "status", "ds:docservice", "ds:metrics").stdout
            if any(not re.search(rf"(?m)^{name}\s+RUNNING\b", processes) for name in ("ds:docservice", "ds:metrics")):
                raise RuntimeError("Both native ONLYOFFICE processes must be RUNNING")
        elif c.backend=='eurooffice':
            self.verify_connector_urls()
            result=self.jail(c.nextcloud_jail,'mdo','-u','www','php','/usr/local/www/nextcloud/occ',
                             'eurooffice:documentserver','--check',timeout=120,hide_output=True)
            match=re.search(r'\bversion ([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?) is successfully connected\b',result.stdout)
            expected=self.versions['office_runtime']['container']['release']
            if not match or '.'.join(match[1].split('.')[:3])!=expected:
                raise RuntimeError('Euro-Office connector did not confirm the selected stable runtime version')
            self.manifest['office_vm']['reported_version']=match[1]
        elif c.backend=='collabora':
            self.verify_connector_urls()
            apps=self.jail(c.nextcloud_jail,'mdo','-u','www','php','/usr/local/www/nextcloud/occ',
                           'app:list','--output=json',timeout=30,hide_output=True).stdout
            try: enabled=json.loads(apps)['enabled']
            except (ValueError,TypeError,KeyError):raise RuntimeError('Invalid connector app inventory') from None
            if not isinstance(enabled,dict) or enabled.get('richdocuments')!=self.versions['applications']['connector']:
                raise RuntimeError('Selected richdocuments connector is not enabled at its locked version')
        self.jail(c.nextcloud_jail, "php-fpm", "-t", capture=False)
        self.jail(c.nextcloud_jail, "apachectl", "configtest", capture=False)
        if c.native_office:
            self.jail(c.onlyoffice_jail, "nginx", "-t", capture=False)
            self.jail(c.nextcloud_jail, "mdo", "-u", "www", "php", "/usr/local/www/nextcloud/occ",
                      "onlyoffice:documentserver", "--check", capture=False)
            # Test PF isolation across the routed segments, not just listener strings.
            self.jail(c.nextcloud_jail, "python3", "-c", '''import socket, sys
for port in (8000, 8126):
    sock = socket.socket()
    sock.settimeout(3)
    try:
        sock.connect((sys.argv[1], port))
    except (TimeoutError, ConnectionError, OSError):
        pass
    else:
        raise SystemExit("Unsafe access to ONLYOFFICE backend port " + str(port))
    finally:
        sock.close()
''', c.onlyoffice_ip)
        # Check public TLS/routing from each jail using the hostname (hosts entry
        # resolves to NC); an external check is still required for router/DNS ingress.
        # Host DNS may require router hairpinning. Connect directly to NC via a
        # subprocess in that jail instead; it has an explicit internal hosts entry.
        health_script = '''import json, ssl, urllib.request, urllib.error
from pathlib import Path
c=json.loads(Path('/root/cloud-installer/runtime.json').read_text())
ca=Path('/root/cloud-installer/tls/ca.pem')
ctx=ssl.create_default_context(cafile=str(ca) if ca.exists() else None)
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
for path in ('/status.php', '/onlyoffice/healthcheck'):
    with opener.open(c['storage_url'].rstrip('/')+path, timeout=30) as response:
        body=response.read(4096)
    if path.endswith('healthcheck'):
        assert body.strip()==b'true', 'Unexpected document health response'
    else:
        status=json.loads(body)
        assert status['installed'] and not status['maintenance'] and '.'.join(status['version'].split('.')[:3])==c['versions']['nextcloud']
for path in ('internal/', 'info/', 'admin/', 'example/', c['versions']['onlyoffice']+'-0/internal/', c['versions']['onlyoffice']+'-0/info/'):
    try:
        opener.open(c['storage_url']+'onlyoffice/'+path, timeout=30)
    except urllib.error.HTTPError as error:
        assert error.code == 403, 'Unexpected private endpoint response'
    else:
        raise SystemExit('A private ONLYOFFICE endpoint is exposed')
'''
        if c.backend=='eurooffice':
            health_script='''import json,ssl,urllib.request,urllib.error
from pathlib import Path
c=json.loads(Path('/root/cloud-installer/runtime.json').read_text())
ca=Path('/root/cloud-installer/tls/ca.pem')
ctx=ssl.create_default_context(cafile=str(ca) if ca.exists() else None)
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ctx))
with opener.open(c['storage_url']+'status.php',timeout=30) as response: status=json.loads(response.read(4096))
assert status.get('installed') is True and status.get('maintenance') is False and status.get('needsDbUpgrade') is False
assert '.'.join(status['version'].split('.')[:3])==c['versions']['nextcloud']
with opener.open(c['storage_url']+'eurooffice/healthcheck',timeout=30) as response:
    assert response.status==200 and response.read(1024).strip()==b'true'
for path in ('internal/','info/','admin/','example/'):
    try: opener.open(c['storage_url']+'eurooffice/'+path,timeout=30)
    except urllib.error.HTTPError as error: assert error.code==403
    else: raise SystemExit('A private Euro-Office endpoint is exposed')
'''
        elif c.backend in ("none","collabora"):
            health_script = '''import json, ssl, urllib.request
from pathlib import Path
c=json.loads(Path('/root/cloud-installer/runtime.json').read_text())
ca=Path('/root/cloud-installer/tls/ca.pem')
ctx=ssl.create_default_context(cafile=str(ca) if ca.exists() else None)
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
# Probe the jail listener, not the potentially different host/public HTTPS port.
url=('http://'+c['nextcloud_ip']+'/') if c['tls_mode']=='external' else ('https://'+c['public_hostname']+'/')
with opener.open(url.rstrip('/')+'/status.php', timeout=30) as response:
    status=json.loads(response.read(4096))
if (status.get('installed') is not True or status.get('maintenance') is not False
        or status.get('needsDbUpgrade') is not False or not isinstance(status.get('version'), str)
        or '.'.join(status['version'].split('.')[:3]) != c['versions']['nextcloud']):
    raise SystemExit('Nextcloud status is not ready at the selected version')
'''
            if c.backend=='collabora':
                health_script+='''
import xml.etree.ElementTree as ET
import urllib.error
with opener.open(url+'collabora/hosting/discovery',timeout=30) as response:
    body=response.read(1048577)
assert len(body)<=1048576 and b'<!DOCTYPE' not in body.upper() and b'<!ENTITY' not in body.upper()
discovery=ET.fromstring(body)
assert discovery.tag=='wopi-discovery' and discovery.find('proof-key') is not None
for path in ('cool/adminws','cool/getMetrics','cool/convert-to','browser/dist/admin/admin.html'):
    try:opener.open(url+'collabora/'+path,timeout=30)
    except urllib.error.HTTPError as error:assert error.code==403
    else:raise SystemExit('A private CODE endpoint is exposed')
'''
        self.jail(c.nextcloud_jail, "python3", "-c", health_script)
        packages = {name: [line for line in self.jail(name, "pkg", "query", "%n %v %o").stdout.splitlines() if line.strip()]
                    for name in c.jails}
        if any(not values for values in packages.values()):
            raise RuntimeError("A managed jail returned an empty package inventory")
        for jail in c.jails:
            group = "nextcloud" if jail == c.nextcloud_jail else "onlyoffice"
            rows = [line.split() for line in packages[jail]]
            if any(len(row) != 3 for row in rows) or len({row[0] for row in rows}) != len(rows):
                raise RuntimeError("A managed jail returned an ambiguous package inventory")
            inventory = {name: (version, origin) for name, version, origin in rows}
            base_packages = {name for name, (_, origin) in inventory.items()
                             if re.fullmatch(r"FreeBSD-[A-Za-z0-9_+.-]+", name) and origin == "base/" + name}
            if (set(inventory) - set(self.versions["packages"][group]) - base_packages - {"pkg"}
                    or any(inventory.get(name) != (item["version"], item["origin"]) for name, item in self.versions["packages"][group].items())):
                raise RuntimeError("Installed package versions differ from the retained version lock; manual upgrade assessment is required")
        status = self.jail(
            c.nextcloud_jail, "mdo", "-u", "www", "php", "/usr/local/www/nextcloud/occ",
            "status", "--output=json").stdout.strip()
        try:
            status = json.loads(status)
        except (ValueError, TypeError):
            raise RuntimeError("Nextcloud did not return a valid JSON status") from None
        if (not isinstance(status, dict) or status.get("installed") is not True
                or status.get("maintenance") is not False or status.get("needsDbUpgrade") is not False
                or not isinstance(status.get("version"), str)
                or ".".join(status["version"].split(".")[:3]) != self.versions["applications"]["nextcloud"]):
            raise RuntimeError("Nextcloud is not an installed, ready instance of the locked version")
        self.manifest.update(package_versions=packages, nextcloud_status=status)

    def apply(self):
        from .operations import configure_ssh
        from .initialization import checkpoint_initialization
        vm=self.config.has_office and not self.config.native_office
        if vm and self.config.backend not in ('eurooffice','collabora'):
            raise ValueError('The selected VM installation path is not implemented; no provisioning performed')
        if self.config.native_office and not self.config.accept_microsoft_fonts:
            raise ValueError("The reviewed ONLYOFFICE package requires Microsoft webfonts; explicit operator EULA consent is required before provisioning")
        # No dataset, package, network or service mutation precedes resolution.
        if self._versions is None:
            self.prepare_versions()
        self.versions
        self.prepare_plugins()
        self.verify_source()
        journal = Journal(self.state / "deployment.json", self.config, self.progress)
        self.validate_resume(journal)
        if vm:
            self.prepare_office_vm_image()
        self.registry.save_host(self.config)
        self.registry.set_status(self.config.instance, "installing")
        try:
            journal.run([
                ("shared ZFS hierarchy", self.create_shared_storage),
                ("host prerequisites", self.install_manager),
                ("instance ZFS storage", self.create_storage),
                ("private networking and PF", self.configure_network),
                ("VNET devfs and boot ordering", self.configure_devfs),
                ("FreeBSD jail roots", self.bootstrap_jails),
                ("persistent mounts", self.attach_storage),
                *([('Alpine VM creation',self.create_office_vm),
                   ('Alpine VM boot',self.start_office_vm),
                   ('guest Docker bootstrap',self.bootstrap_office_vm),
                   ('Collabora CODE container' if self.config.backend=='collabora' else 'Euro-Office container',self.install_vm_office)] if vm else []),
                ("public provisioning payloads", self.stage_payloads),
                ("Nextcloud prerequisites", self.install_nextcloud),
                ("Nextcloud database", lambda: self.nextcloud_phase("database", ("db_password",))),
                ("quiesced initialization checkpoint", lambda: checkpoint_initialization(self)),
                ("Nextcloud installation", lambda: self.nextcloud_phase("install", ("admin_password", "db_password"))),
                ("Nextcloud publication", lambda: self.nextcloud_phase("publish")),
                *([("ONLYOFFICE and fonts", self.install_onlyoffice)] if self.config.native_office else []),
                *([("selected ONLYOFFICE plugins", lambda: self.plugin_command("install"))]
                  if self.config.onlyoffice_plugins else []),
                ("document integration" if self.config.has_office else "Nextcloud finish", self.integrate),
                ("optional jail SSH", lambda: configure_ssh(self)),
                *([('office VM restart persistence',self.restart_office_vm)] if vm else []),
                ("jail restart persistence", self.restart_jails),
                ("readiness checks", self.initial_readiness),
                ("boot activation", self.enable_boot)], checks={"shared ZFS hierarchy": self.create_shared_storage,
                                                               "instance ZFS storage": self.create_storage,
                                                               "persistent mounts": self.ensure_running,
                                                                "readiness checks": self.verify,
                                                                 "boot activation": self.enable_boot,
                                                                 **({'Alpine VM creation':self.create_office_vm,
                                                                     'Alpine VM boot':self.start_office_vm,
                                                                     'guest Docker bootstrap':self.check_office_vm_bootstrap,
                                                                     ('Collabora CODE container' if self.config.backend=='collabora' else 'Euro-Office container'):self.continue_vm_office} if vm else {})})
            self.checkpoint()
            if vm:
                atomic_write(self.state / "complete", COMPLETE_MESSAGE)
                self.registry.set_status(self.config.instance, "ready")
            else:
                self.registry.set_status(self.config.instance, "ready")
                atomic_write(self.state / "complete", COMPLETE_MESSAGE)
        except BaseException as error:
            # Retain every dataset and this instance's recovery journal. Do not
            # stop another instance, weaken shared PF, or erase application data.
            if vm:
                from .office_vm import vm_paths, stop_native_vm, disable_vm_boot_service
                try:
                    disable_vm_boot_service(self)
                except Exception:
                    print('Could not safely disable the owned VM boot flag; inspect its retained service identity.',file=sys.stderr)
                marker=self.state/'allow-vm-start'
                if marker.exists() and not marker.is_symlink():
                    try: marker.rename(self.state/'allow-vm-start.disabled')
                    except OSError: print('Could not withdraw VM startup permission; instance is not declared ready.',file=sys.stderr)
                try:
                    paths=vm_paths(self.config)
                    receipt=self.state/(paths['name']+'.creating.json')
                    if receipt.exists() or receipt.is_symlink():
                        record=private_json(receipt)
                        if isinstance(record,dict) and 'vm_config_sha256' in record:
                            stop_native_vm(self)
                except Exception:
                    print('Cleanup could not confirm the owned VM stopped; retain its disk and inspect identity from the host console.',file=sys.stderr)
            for jail in self.config.jails:
                if (self.state / (jail + ".creating.json")).exists():
                    try:
                        configured = self.runner.run("bastille", "config", jail, "get", "path", check=False)
                        if configured.returncode or configured.stdout.strip() != str(self.jail_root(jail)):
                            raise RuntimeError("Jail root identity cannot be confirmed")
                        running = self.runner.run("jls", "-j", jail, check=False).returncode == 0
                        if running:
                            self.require_running_jail(jail)
                        self.runner.run("bastille", "config", jail, "set", "boot", "off")
                        if running:
                            self.runner.run("bastille", "stop", jail, capture=False)
                    except Exception:
                        print(f"Cleanup could not safely disable/stop {jail}; inspect its identity and retained state from the host console.", file=sys.stderr)
            try:
                self.registry.set_status(self.config.instance, "failed", error_type=type(error).__name__)
            except Exception:
                print("Failed status could not be saved; inspect retained state from the host console.", file=sys.stderr)
            raise

    def initial_readiness(self):
        self.verify()
        from .enrollment import capture_baseline, BASELINE
        # Enrollment evidence must never be reconstructed for an already
        # published/verified instance. Unsupported static layouts do not change
        # the existing installation contract: report the limitation explicitly
        # and leave enrollment unavailable, rather than inventing a baseline.
        if (self.state / BASELINE).exists() or (self.state / "enrollment-unavailable.json").exists():
            return
        if not self.config.native_office:
            atomic_json(self.state / "enrollment-unavailable.json",
                        {"schema_version": 1, "eligible": False, "office_backend": self.config.backend,
                         "reason": "Not enrolled: native lifecycle enrollment is unsupported for this backend."})
            print("NOTICE: Installation checks passed; this backend is not enrolled. Native lifecycle enrollment is unsupported.",
                  file=sys.stderr)
            return
        try:
            capture_baseline(self)
        except (ValueError, OSError, RuntimeError) as error:
            atomic_json(self.state / "enrollment-unavailable.json",
                        {"schema_version": 1, "eligible": False, "error_type": type(error).__name__,
                         "reason": "First-readiness enrollment evidence could not be established; no baseline was adopted."})
            print("NOTICE: Installation checks passed, but lifecycle enrollment evidence is unavailable. "
                  "See the private enrollment-unavailable.json record; enrollment will refuse this instance.", file=sys.stderr)

    def require_original_artifact(self):
        """Read-only maintenance gate; never create an identity for old state."""
        from .host import read_private
        path = self.registry.evidence_path(self.config.instance, "source.sha256")
        if not path.is_file() or path.is_symlink() or read_private(path) != source_digest():
            raise ValueError("Maintenance requires the original installer artifact and retained source identity; no automatic adoption is supported")

    def verify_source(self):
        path = self.state / "source.sha256"
        value = source_digest()
        if path.exists() and path.read_text() != value:
            raise ValueError("Resume requires the same installer artifact that started this instance; use its retained release/check-out")
        self.registry.write_source(self.config.instance, value)
        inputs = hashlib.sha256(json.dumps(self.secrets, sort_keys=True).encode())
        for field in ("certificate_file", "private_key_file", "ca_file", "ssh_key_file"):
            filename = getattr(self.config, field)
            if filename:
                inputs.update(field.encode() + b"\0" + Path(filename).read_bytes())
        if self.config.additional_fonts_dir:
            directory = Path(self.config.additional_fonts_dir)
            for filename in sorted(directory.rglob("*")):
                if filename.is_symlink():
                    raise ValueError("Custom font inputs must not contain symlinks")
                if filename.is_file():
                    inputs.update(str(filename.relative_to(directory)).encode() + b"\0")
                    with filename.open("rb") as stream:
                        for block in iter(lambda: stream.read(1024 * 1024), b""):
                            inputs.update(block)
        pinned = self.state / "inputs.sha256"
        value = inputs.hexdigest() + "\n"
        if pinned.exists() and pinned.read_text() != value:
            raise ValueError("Credentials/certificate/public-key/font inputs changed; resume requires the original inputs")
        atomic_write(pinned, value)

    def validate_resume(self, journal):
        """Check persisted ownership before trusting completed host phases."""
        done = {name for name, record in journal.data["steps"].items() if record["state"] == "complete"}
        c = self.config
        if c.has_office and not c.native_office:
            container='Collabora CODE container' if c.backend=='collabora' else 'Euro-Office container'
            dependencies={'Alpine VM creation':'persistent mounts','Alpine VM boot':'Alpine VM creation',
                          'guest Docker bootstrap':'Alpine VM boot',container:'guest Docker bootstrap',
                          'document integration':container,'office VM restart persistence':'document integration'}
            if any(name in done and parent not in done for name,parent in dependencies.items()):
                raise ValueError('VM installation checkpoints are inconsistent; explicit recovery assessment required')
            if 'Alpine VM creation' in done:
                from .office_vm import native_vm_identity
                native_vm_identity(self)
        if "instance ZFS storage" in done:
            for dataset in self.storage:
                if self.runner.output("zfs", "get", "-H", "-o", "value", OWNER, dataset.name) != c.instance:
                    raise ValueError("A checkpointed dataset is missing or has changed ownership")
        if "private networking and PF" in done:
            from .host import verify_managed_network
            verify_managed_network(self.registry, self.runner)
        if "FreeBSD jail roots" in done:
            for jail in c.jails:
                hostname = c.nextcloud_host if jail == c.nextcloud_jail else c.onlyoffice_host
                if (self.runner.output("bastille", "config", jail, "get", "path") != str(self.jail_root(jail))
                        or self.runner.output("bastille", "config", jail, "get", "host.hostname") != hostname
                        or self.runner.output("zfs", "get", "-H", "-o", "value", OWNER,
                                              f"{c.bastille_dataset}/jails/{jail}") != c.instance):
                    raise ValueError("A checkpointed jail identity/hostname/ownership has changed")
