"""Read-only host preflight models; no FreeBSD commands or host paths are written."""

from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
import io
import traceback
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from installer.config import Config, datasets
from installer import host
from installer.state import Registry, atomic_json, atomic_write, config_digest


GIB = 1024 ** 3


def config():
    return Config(public_hostname="cloud.example.test", admin_email="admin@example.test",
                  acme_email="admin@example.test", external_interface="igb0",
                  ingress_address="192.0.2.10", dns_server="192.0.2.53",
                  management_network="198.51.100.0/24")


def another(c):
    return replace(c, instance="second", public_hostname="second.example.test",
                   ingress_address="192.0.2.11", private_network="10.78.0.0/29",
                   nextcloud_bridge="bridge242", onlyoffice_bridge="bridge243")


def optional_config(c):
    return replace(c, storage_policy="optional", data_quota_gib=0,
                   database_quota_gib=0, temporary_quota_gib=0,
                   office_quota_gib=0, logs_quota_gib=0, system_quota_gib=0)


class HostModel:
    """An allowlist of inspection commands; a mutation/unexpected probe fails."""

    def __init__(self, c):
        self.calls = []
        self.zfs = {}
        self.free = 2000 * GIB
        self.interfaces = {c.external_interface: (
            f"{c.external_interface}: flags=8843<UP,BROADCAST,RUNNING>\n"
            "\tinet 192.0.2.10 netmask 0xffffff00 broadcast 192.0.2.255\n"
            "\tinet 192.0.2.11 netmask 0xffffffff broadcast 192.0.2.11\n")}
        self.routes = "Destination Gateway Flags Netif Expire\ndefault 192.0.2.1 UGS igb0\n"
        self.jails = "jid name path\n"
        self.listeners = "USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS\n"
        self.package = None
        self.settings = {}
        self.bastille_settings = {}
        self.sysctls = {"net.inet.ip.forwarding": "0", "net.inet.ip.fw.enable": "0"}
        self.pf = {("-s", "info"): "Status: Disabled\n", ("-s", "Anchors"): "",
                   ("-sr",): "", ("-sn",): "", ("-ss",): ""}
        self.running_pf = False

    def run(self, *args, **kwargs):
        args = tuple(map(str, args))
        self.calls.append((args, kwargs))
        code, out = 0, ""
        if args == ("zpool", "list", "-H", "-o", "health", "zroot"):
            out = "ONLINE"
        elif args[:3] == ("zfs", "list", "-H") and len(args) == 4:
            code = 0 if args[3] in self.zfs else 1
        elif args[:2] == ("zfs", "get") and len(args) == 7:
            name, property_name = args[-1], args[-2]
            out = str(self.free) if name == "zroot" and property_name == "available" else self.zfs[name][property_name]
        elif args[:2] == ("df", "-P"):
            dataset = next(name for name, props in self.zfs.items() if props["mountpoint"] == args[2])
            out = f"Filesystem 1024-blocks Used Available Capacity Mounted on\n{dataset} 100 1 99 1% {args[2]}\n"
        elif args == ("ifconfig", "-a", "inet"):
            out = "".join(self.interfaces.values())
        elif args[0] == "ifconfig" and len(args) in (2, 3):
            code, out = (0, self.interfaces[args[1]]) if args[1] in self.interfaces else (1, "")
        elif args == ("netstat", "-rn", "-f", "inet"):
            out = self.routes
        elif args[:2] == ("sysrc", "-n") and len(args) == 3:
            out = self.settings.get(args[2], "")
        elif args[:3] == ("sysrc", "-f", host.BASTILLE_CONF) and args[3] == "-n":
            out = self.bastille_settings.get(args[4], "")
        elif args[:2] == ("sysctl", "-n") and len(args) == 3:
            out = self.sysctls[args[2]]
        elif args == ("pkg", "query", "%v", "bastille"):
            code, out = (1, "") if self.package is None else (0, self.package)
        elif args == ("pfctl", "-s", "Running"):
            code = 0 if self.running_pf else 1
        elif args[0] == "pfctl":
            out = self.pf[args[1:]]
        elif args == ("jls", "-h", "jid", "name", "path"):
            out = self.jails
        elif args[:5] == ("sockstat", "-46l", "-P", "tcp", "-p"):
            out = self.listeners
        elif args == ("devfs", "rule", "-s", "13", "show"):
            out = ""
        else:
            raise AssertionError(f"Unexpected/mutating host command: {args}")
        if code and kwargs.get("check", True):
            raise RuntimeError("Modeled host inspection failed")
        return subprocess.CompletedProcess(args, code, str(out), "")

    def output(self, *args):
        return self.run(*args).stdout.strip()

    def dataset(self, name, mountpoint, instance, quota=0, used=0):
        self.zfs[name] = {"org.cloud-installer:owner": "cloud-installer",
                          "org.cloud-installer:instance": instance, "mountpoint": mountpoint,
                          "quota": str(quota), "refquota": "0", "used": str(used), "mounted": "yes",
                          "available": str(self.free)}

    def bridge(self, c, *, member=None, prefix="0xfffffffc"):
        self.interfaces[c.nextcloud_bridge] = (
            f"{c.nextcloud_bridge}: flags=8843<UP,BROADCAST,RUNNING>\n"
            f"\tinet {c.nextcloud_gateway} netmask {prefix}\n"
            + (f"\tmember: {member} flags=143\n" if member else ""))
        self.routes += f"{c.nextcloud_network} link#7 U {c.nextcloud_bridge}\n"
        self.routes += f"{c.nextcloud_gateway} link#7 UHS lo0\n"


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory(
            prefix="host-tests-")))
        self.registry = Registry(self.root)
        self.registry.initialize()
        self.c = config()
        self.facts = {"pools": ["zroot"], "memory_mb": 65536, "ssh_peer": ""}
        self.runner = HostModel(self.c)
        self.files = {}
        self.ipv4, self.ipv6 = [self.c.ingress_address], []
        exists, symlink, read_text, is_file = Path.exists, Path.is_symlink, Path.read_text, Path.is_file

        def modeled_exists(path):
            path = Path(path)
            if path == self.root or self.root in path.parents:
                return exists(path) or symlink(path)
            return str(path) in self.files

        def modeled_read(path, *args, **kwargs):
            return self.files[str(path)] if str(path) in self.files else read_text(path, *args, **kwargs)

        def prerequisite_file(path):
            return str(path).startswith(("/usr/share/zoneinfo/", "/usr/share/keys/pkgbase-15/trusted/")) or is_file(path)

        self.stack.enter_context(patch("installer.host._exists", side_effect=modeled_exists))
        self.stack.enter_context(patch.object(Path, "read_text", modeled_read))
        self.stack.enter_context(patch.object(Path, "is_file", prerequisite_file))
        self.stack.enter_context(patch("installer.host._safe_path", side_effect=lambda path, **kwargs: Path(path)))
        self.stack.enter_context(patch("installer.host.socket.getaddrinfo", side_effect=self.dns))
        self.stack.enter_context(patch("installer.host.print"))
        self.stack.enter_context(patch.object(self.registry, "initialize", side_effect=AssertionError("preflight must not initialize state")))
        self.stack.enter_context(patch("installer.host.write_private", side_effect=AssertionError("preflight must not write")))
        self.stack.enter_context(patch("installer.host.atomic_write", side_effect=AssertionError("preflight must not write")))

    def dns(self, name, port, family, kind):
        answers = []
        if family in (socket.AF_UNSPEC, socket.AF_INET):
            answers.extend((socket.AF_INET, kind, 6, "", (address, port)) for address in self.ipv4)
        if family in (socket.AF_UNSPEC, socket.AF_INET6):
            answers.extend((socket.AF_INET6, kind, 6, "", (address, port, 0, 0)) for address in self.ipv6)
        return answers

    def preflight(self, c=None, *, resume=False):
        return host.preflight(c or self.c, self.facts, self.runner, registry=self.registry, resume=resume)

    def register(self, c, *, state="configured"):
        self.registry.save_new(c, {})
        if state != "configured":
            self.registry.set_status(c.instance, state)
            atomic_json(self.registry.instance_path(c.instance) / "deployment.json", {
                "schema_version": c.schema_version, "config_sha256": config_digest(c),
                "steps": {"shared ZFS hierarchy": {"state": "complete"}}})

    def managed(self):
        self.register(self.c, state="failed")
        self.registry.save_host(self.c)
        for name, path in (("zroot/cloud-installer", "/srv/cloud-installer"),
                           ("zroot/cloud-installer/instances", "/srv/cloud-installer/instances"),
                           (self.c.bastille_dataset, self.c.bastille_root)):
            self.runner.dataset(name, path, "shared")

    def instance_storage(self, c=None, *, used=0):
        c = c or self.c
        for dataset in datasets(c):
            self.runner.dataset(dataset.name, dataset.mountpoint, c.instance, dataset.quota_gib * GIB,
                                used if dataset.name == c.dataset_root else 0)

    def jail(self, *, live=False):
        c, jail = self.c, self.c.nextcloud_jail
        path = f"{c.bastille_root}/jails/{jail}/root"
        name = f"{c.bastille_dataset}/jails/{jail}"
        atomic_json(self.registry.instance_path(c.instance) / (jail + ".creating.json"),
                    {"name": jail, "root": path, "release": c.release})
        self.runner.dataset(name, str(Path(path).parent), c.instance, c.system_quota_gib // 2 * GIB)
        self.runner.dataset(name + "/root", path, c.instance)
        if live:
            self.runner.jails += f"4 {jail} {path}\n"

    def manager(self, *, phase="complete"):
        self.files[host.BASTILLE_CONF] = "# managed configuration\n"
        self.runner.package = "1.4.4_1"
        self.runner.bastille_settings = {
            "bastille_zfs_enable": "YES", "bastille_zfs_zpool": self.c.pool,
            "bastille_zfs_prefix": "cloud-installer/bastille", "bastille_prefix": self.c.bastille_root,
            "bastille_logsdir": self.c.bastille_root + "/logs", "bastille_network_vnet_type": "if_bridge",
            "bastille_pf_conf": host.PF_FILE}
        path = self.registry.instance_path(self.c.instance) / "deployment.json"
        if path.exists():
            atomic_json(path, {"schema_version": self.c.schema_version, "config_sha256": config_digest(self.c),
                              "steps": {"shared ZFS hierarchy": {"state": "complete"},
                                        "host prerequisites": {"state": phase}}})

    def test_fresh_host_is_read_only_and_preserves_the_none_return_contract(self):
        self.assertIsNone(self.preflight())
        self.assertFalse((self.root / "host.json").exists())
        self.assertEqual(list((self.root / "instances").iterdir()), [])

    def test_single_jail_preflight_never_probes_office_or_hypervisor_resources(self):
        c = replace(optional_config(self.c), office_backend="none", private_network="10.77.0.0/30",
                    accept_microsoft_fonts=False, onlyoffice_plugins="")
        self.assertIsNone(self.preflight(c))
        commands = repr(self.runner.calls)
        for absent in (c.onlyoffice_jail, c.onlyoffice_bridge, "/office-", "bhyve", "vmm", "docker"):
            self.assertNotIn(absent, commands)
        self.assertFalse((self.root / "host.json").exists())
        self.assertEqual(list((self.root / "instances").iterdir()), [])

    def test_none_uses_actual_nc_budget_not_native_combined_eight_gib_floor(self):
        c=replace(optional_config(self.c),office_backend='none',private_network='10.77.0.0/30',
                  accept_microsoft_fonts=False,onlyoffice_plugins='',php_budget_mb=1024,db_buffer_mb=256,redis_memory_mb=64)
        self.facts['memory_mb']=4096
        self.assertIsNone(self.preflight(c))
        with self.assertRaisesRegex(ValueError,'At least 8 GiB'):
            self.preflight(self.c)

    def test_optional_caps_do_not_become_capacity_reservations_or_recommendations(self):
        c = replace(optional_config(self.c), data_quota_gib=10000)
        self.runner.free = 100 * GIB
        self.assertIsNone(self.preflight(c))

    def test_optional_storage_does_not_add_single_instance_exclusivity(self):
        optional = optional_config(self.c)
        for candidate, existing in ((optional, another(self.c)),
                                    (another(self.c), optional)):
            with self.subTest(candidate=candidate.instance), patch.object(
                    self.registry, "entries", return_value=[(existing, {"state": "configured"})]):
                self.ipv4 = [candidate.ingress_address]
                self.assertIsNone(self.preflight(candidate))

    def test_optional_resume_distinguishes_intentional_none_from_missing_caps(self):
        self.c = replace(optional_config(self.c), database_quota_gib=4)
        self.managed()
        self.instance_storage()
        self.assertIsNone(self.preflight(resume=True))
        props = self.runner.zfs[self.c.dataset_root + "/nc-database"]
        props["quota"] = "0"
        with self.assertRaisesRegex(ValueError, "no quota/refquota"):
            self.preflight(resume=True)

    def test_optional_resume_refuses_unexpected_local_cap_without_mutating_it(self):
        self.c = optional_config(self.c)
        self.managed()
        self.instance_storage()
        for name in (self.c.dataset_root, self.c.dataset_root + "/nc-data",
                     self.c.dataset_root + "/nc-database", self.c.dataset_root + "/nc-app"):
            with self.subTest(name=name):
                self.runner.zfs[name]["quota"] = str(GIB)
                with self.assertRaisesRegex(ValueError, "intentionally uncapped"):
                    self.preflight(resume=True)
                self.assertEqual(self.runner.zfs[name]["quota"], str(GIB))
                self.runner.zfs[name]["quota"] = "0"

    def test_uncapped_admission_checks_actual_parent_space_not_a_quota_budget(self):
        self.c = optional_config(self.c)
        self.managed()
        self.runner.zfs["zroot/cloud-installer/instances"]["available"] = "0"
        with self.assertRaisesRegex(ValueError, "No available space"):
            self.preflight(resume=True)
        self.runner.zfs["zroot/cloud-installer/instances"]["available"] = str(80 * GIB)
        self.assertIsNone(self.preflight(resume=True))

    def test_uncapped_jail_resume_accepts_none_but_refuses_unexpected_caps(self):
        self.c = optional_config(self.c)
        self.managed()
        self.instance_storage()
        self.jail()
        self.assertIsNone(self.preflight(resume=True))
        parent = f"{self.c.bastille_dataset}/jails/{self.c.nextcloud_jail}"
        for name, prop in ((parent, "quota"), (parent + "/root", "refquota")):
            with self.subTest(name=name, prop=prop):
                self.runner.zfs[name][prop] = str(GIB)
                with self.assertRaisesRegex(ValueError, "intentionally uncapped"):
                    self.preflight(resume=True)
                self.runner.zfs[name][prop] = "0"

    def test_configured_entries_reserve_networks_bridges_hostnames_and_ingress(self):
        cases = (({"private_network": self.c.private_network}, "network overlaps"),
                 ({"onlyoffice_bridge": self.c.nextcloud_bridge}, "Bridge name"),
                 ({"nextcloud_hostname": self.c.nextcloud_host}, "hostname"),
                 ({"public_hostname": self.c.public_hostname}, "hostname"),
                 ({"onlyoffice_hostname": self.c.public_hostname}, "hostname"),
                 ({"ingress_address": self.c.ingress_address}, "address/port"))
        for changes, message in cases:
            other = replace(another(self.c), **changes)
            with self.subTest(changes=changes), patch.object(self.registry, "entries", return_value=[(other, {"state": "configured"})]):
                with self.assertRaisesRegex(ValueError, message):
                    self.preflight()
        self.assertEqual(self.runner.calls, [])

    def test_optional_ssh_ports_are_reserved_on_the_same_ingress_address(self):
        c = replace(self.c, tls_mode="external", proxy_networks="203.0.113.2/32", http_port=8080)
        other = replace(another(c), ingress_address=c.ingress_address, http_port=8081,
                        jail_ssh=True, ssh_key_file="/root/key.pub", ssh_nextcloud_port=8080)
        self.register(other)
        with self.assertRaisesRegex(ValueError, "address/port"):
            self.preflight(c)

    def test_same_ports_on_different_aliases_and_different_repository_are_allowed(self):
        self.register(replace(another(self.c), repository="quarterly"))
        self.assertIsNone(self.preflight())

    def test_shared_settings_match_both_configured_reservations_and_host_registry(self):
        for key, value in (("pool", "tank"), ("external_interface", "igb1"),
                           ("management_network", "198.51.101.0/24"), ("management_port", 2222),
                           ("host_reserved_mb", 4096)):
            other = replace(another(self.c), **{key: value})
            with self.subTest(key=key), patch.object(self.registry, "entries", return_value=[(other, {"state": "configured"})]):
                with self.assertRaisesRegex(ValueError, key):
                    self.preflight()
        self.registry.save_host(self.c)
        with self.assertRaisesRegex(ValueError, "host_reserved_mb"):
            self.preflight(replace(self.c, host_reserved_mb=4096))

    def test_aggregate_memory_counts_host_reserve_once_and_candidate_once(self):
        self.register(self.c)
        self.register(another(self.c))
        self.facts["memory_mb"] = 2 * (self.c.memory_budget_mb - self.c.host_reserved_mb) + self.c.host_reserved_mb
        self.assertIsNone(self.preflight())
        self.facts["memory_mb"] -= 1
        with self.assertRaisesRegex(ValueError, "Aggregate memory"):
            self.preflight()

    def test_removed_entries_do_not_reserve_resources(self):
        other = replace(self.c, instance="removed")
        with patch.object(self.registry, "entries", return_value=[(other, {"state": "removed"})]):
            self.facts["memory_mb"] = self.c.memory_budget_mb
            self.assertIsNone(self.preflight())

    def test_configured_disk_reservations_are_included(self):
        self.register(another(self.c))
        self.runner.free = self.c.total_quota_gib * 2 * GIB
        with self.assertRaisesRegex(ValueError, "quota headroom plus configured reservations"):
            self.preflight()

    def test_resume_subtracts_already_used_blocks_without_counting_child_quotas_twice(self):
        self.managed()
        self.instance_storage(used=140 * GIB)
        self.runner.free = 75 * GIB
        self.assertLess(self.runner.free, self.c.total_quota_gib * GIB)
        self.assertIsNone(self.preflight(resume=True))
        self.runner.free = 60 * GIB
        with self.assertRaisesRegex(ValueError, "quota headroom"):
            self.preflight(resume=True)

    def test_dataset_requires_registered_resume_and_matching_owner_tags(self):
        self.instance_storage()
        with self.assertRaisesRegex(ValueError, "requires Resume"):
            self.preflight()
        self.managed()
        for property_name, value in (("org.cloud-installer:instance", "other"),
                                     ("org.cloud-installer:owner", "foreign"), ("mountpoint", "/foreign")):
            properties = self.runner.zfs[self.c.dataset_root]
            before = properties[property_name]
            properties[property_name] = value
            with self.subTest(property=property_name), self.assertRaisesRegex(ValueError, "ownership/mountpoint"):
                self.preflight(resume=True)
            properties[property_name] = before

    def test_resume_does_not_use_changed_or_missing_journals_as_ownership(self):
        self.managed()
        self.instance_storage()
        path = self.registry.instance_path(self.c.instance) / "deployment.json"
        atomic_json(path, {"schema_version": self.c.schema_version, "config_sha256": "wrong", "steps": {}})
        with self.assertRaisesRegex(ValueError, "ownership journal|immutable configuration"):
            self.preflight(resume=True)
        path.unlink()
        with self.assertRaisesRegex(ValueError, "registered ownership journal"):
            self.preflight(resume=True)

    def test_shared_dataset_requires_host_record_and_shared_tag(self):
        self.runner.dataset("zroot/cloud-installer", "/srv/cloud-installer", "shared")
        with self.assertRaisesRegex(ValueError, "without the managed host registry"):
            self.preflight()
        self.registry.save_host(self.c)
        self.runner.zfs["zroot/cloud-installer"]["org.cloud-installer:instance"] = self.c.instance
        with self.assertRaisesRegex(ValueError, "ownership/mountpoint"):
            self.preflight()

    def test_legacy_state_fails_without_any_host_commands(self):
        self.files["/var/db/nextcloud-jails-installer"] = "legacy"
        with self.assertRaisesRegex(ValueError, "no automatic migration"):
            self.preflight()
        self.assertEqual(self.runner.calls, [])

    def test_partial_manager_before_any_committed_network_is_legitimate(self):
        self.managed()
        self.manager()
        self.assertIsNone(self.preflight(resume=True))

    def test_manager_family_settings_and_foreign_installation_are_checked(self):
        self.manager()
        with self.assertRaisesRegex(ValueError, "no managed host registry"):
            self.preflight()
        self.managed()
        self.manager()
        self.runner.package = "1.4.5"
        self.assertIsNone(self.preflight(resume=True))
        self.runner.package = "1.5.0"
        with self.assertRaisesRegex(ValueError, "reviewed.*policy"):
            self.preflight(resume=True)
        self.runner.package = "1.4.4"
        self.runner.bastille_settings["bastille_prefix"] = "/foreign"
        with self.assertRaisesRegex(ValueError, "bastille_prefix"):
            self.preflight(resume=True)

    def test_interrupted_manager_settings_need_the_specific_durable_phase_and_owned_shared_storage(self):
        self.managed()
        self.manager(phase="running")
        self.runner.bastille_settings["bastille_zfs_enable"] = "NO"
        self.runner.bastille_settings["bastille_prefix"] = "/usr/local/bastille"
        self.assertIsNone(self.preflight(resume=True))
        self.runner.zfs["zroot/cloud-installer"]["org.cloud-installer:owner"] = "foreign"
        with self.assertRaisesRegex(ValueError, "ownership/mountpoint"):
            self.preflight(resume=True)

    def test_host_record_alone_never_owns_a_bastille_installation(self):
        self.managed()
        self.manager(phase="unstarted")
        with self.assertRaisesRegex(ValueError, "manager ownership journal"):
            self.preflight(resume=True)

    def test_another_allocated_instance_prevents_partial_manager_relaxation(self):
        self.managed()
        self.manager(phase="failed")
        self.register(another(self.c), state="ready")
        with self.assertRaisesRegex(ValueError, "manager ownership journal"):
            self.preflight(resume=True)

    def test_existing_completed_host_manager_stays_strict_during_another_failed_phase(self):
        self.managed()
        self.manager(phase="failed")
        other = another(self.c)
        self.register(other, state="ready")
        atomic_json(self.registry.instance_path(other.instance) / "deployment.json", {
            "schema_version": other.schema_version, "config_sha256": config_digest(other),
            "steps": {"shared ZFS hierarchy": {"state": "complete"}, "host prerequisites": {"state": "complete"}}})
        self.runner.bastille_settings["bastille_prefix"] = "/usr/local/bastille"
        with self.assertRaisesRegex(ValueError, "bastille_prefix"):
            self.preflight(resume=True)

    def test_removed_instance_journal_preserves_shared_manager_ownership(self):
        self.managed()
        self.manager()
        self.registry.set_status(self.c.instance, "removed")
        other = another(self.c)
        self.ipv4 = [other.ingress_address]
        self.assertIsNone(self.preflight(other))

    def test_active_or_disabled_foreign_pf_cannot_be_adopted(self):
        self.runner.pf[("-s", "info")] = "Status: Enabled\n"
        with self.assertRaisesRegex(ValueError, "without a committed"):
            self.preflight()
        self.runner.pf[("-s", "info")] = "Status: Disabled\n"
        self.runner.pf[("-s", "Anchors")] = "foreign/*\n"
        with self.assertRaisesRegex(ValueError, "ruleset/anchor/state"):
            self.preflight()

    def test_owned_exact_bridge_and_direct_routes_are_allowed_only_on_resume(self):
        self.managed()
        self.runner.bridge(self.c)
        self.assertIsNone(self.preflight(resume=True))
        with self.assertRaisesRegex(ValueError, "use Resume"):
            self.preflight()

    def test_foreign_bridge_broad_masks_members_and_routes_are_rejected(self):
        self.runner.bridge(self.c)
        with self.assertRaisesRegex(ValueError, "Bridge already exists"):
            self.preflight()
        self.managed()
        self.runner.bridge(self.c, prefix="0xfffffff8")
        with self.assertRaisesRegex(ValueError, "planned gateway/30"):
            self.preflight(resume=True)
        self.runner.bridge(self.c, member="igb0")
        with self.assertRaisesRegex(ValueError, "physical uplink"):
            self.preflight(resume=True)
        self.runner.bridge(self.c)
        self.runner.routes += "10.77.0.0/29 192.0.2.1 UGS igb0\n"
        with self.assertRaisesRegex(ValueError, "existing IPv4 route"):
            self.preflight(resume=True)

    def test_owned_interface_exception_does_not_allow_same_addresses_on_foreign_interface(self):
        self.managed()
        self.runner.bridge(self.c)
        self.runner.interfaces["vlan5"] = "vlan5: flags=1<UP>\n\tinet 10.77.0.1 netmask 0xfffffffc\n"
        with self.assertRaisesRegex(ValueError, "host interface network"):
            self.preflight(resume=True)

    def test_jail_root_and_creation_reservation_are_required_for_live_jail_and_bridge_member(self):
        self.managed()
        self.jail(live=True)
        self.runner.bridge(self.c, member="e0a_" + self.c.nextcloud_jail)
        self.assertIsNone(self.preflight(resume=True))
        (self.registry.instance_path(self.c.instance) / (self.c.nextcloud_jail + ".creating.json")).unlink()
        with self.assertRaisesRegex(ValueError, "creation reservation"):
            self.preflight(resume=True)

    def test_foreign_running_jail_root_is_not_accepted_by_name_alone(self):
        self.managed()
        self.jail(live=True)
        self.runner.jails = f"jid name path\n4 {self.c.nextcloud_jail} /foreign/root\n"
        with self.assertRaisesRegex(ValueError, "owned name/root"):
            self.preflight(resume=True)

    def test_existing_jail_root_refquota_is_inspected(self):
        self.managed()
        self.jail()
        root = f"{self.c.bastille_dataset}/jails/{self.c.nextcloud_jail}/root"
        self.runner.zfs[root]["refquota"] = str(64 * GIB)
        with self.assertRaisesRegex(ValueError, "refquota exceeds"):
            self.preflight(resume=True)

    def test_ssh_server_can_use_another_address_on_the_same_uplink(self):
        self.facts.update(ssh_peer="198.51.100.25", ssh_port=22, ssh_server="192.0.2.10")
        self.ipv4 = ["192.0.2.11"]
        self.assertIsNone(self.preflight(replace(self.c, ingress_address="192.0.2.11")))
        self.facts["ssh_server"] = "192.0.2.99"
        with self.assertRaisesRegex(ValueError, "preserve this SSH"):
            self.preflight(replace(self.c, ingress_address="192.0.2.11"))

    def test_ingress_listener_check_uses_configured_ports_and_addresses(self):
        c = replace(self.c, tls_mode="external", proxy_networks="203.0.113.2/32", http_port=8080)
        self.runner.listeners += "www httpd 42 4 tcp4 192.0.2.11:8080 *:*\n"
        self.assertIsNone(self.preflight(c))
        self.runner.listeners += "www httpd 43 4 tcp4 *:8080 *:*\n"
        with self.assertRaisesRegex(ValueError, "192.0.2.10:8080"):
            self.preflight(c)

    def test_direct_tls_refuses_round_robin_and_aaaa(self):
        self.ipv4.append("192.0.2.20")
        with self.assertRaisesRegex(ValueError, "exactly one"):
            self.preflight()
        self.ipv4.pop()
        self.ipv6 = ["2001:db8::1"]
        with self.assertRaisesRegex(ValueError, "AAAA"):
            self.preflight()

    def test_external_tls_supports_round_robin_and_ipv6_only_proxy_dns(self):
        c = replace(self.c, tls_mode="external", proxy_networks="203.0.113.2/32")
        self.ipv4 = ["203.0.113.2", "203.0.113.3"]
        self.ipv6 = ["2001:db8::1"]
        self.assertIsNone(self.preflight(c))
        self.assertIsNone(self.preflight(replace(c, dns_address="203.0.113.3")))
        self.ipv4 = []
        self.assertIsNone(self.preflight(c))
        with self.assertRaisesRegex(ValueError, "expected DNS address"):
            self.preflight(replace(c, dns_address="203.0.113.2"))
        self.ipv6 = []
        with self.assertRaisesRegex(ValueError, "at least one DNS"):
            self.preflight(c)

    def test_direct_tls_accepts_freebsd_no_address_family_but_not_dns_failures(self):
        for code in (socket.EAI_ADDRFAMILY, socket.EAI_AGAIN, socket.EAI_FAIL):
            def lookup(host, port, family, kind):
                if family == socket.AF_INET6:
                    raise socket.gaierror(code, "simulated resolver result")
                return self.dns(host, port, family, kind)
            with self.subTest(code=code), patch("installer.host.socket.getaddrinfo", side_effect=lookup):
                if code == socket.EAI_ADDRFAMILY:
                    self.assertIsNone(self.preflight())
                else:
                    with self.assertRaisesRegex(ValueError, "Could not establish"):
                        self.preflight()


class ManagedNetworkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pf-host-tests-")
        self.addCleanup(self.temp.cleanup)
        self.registry = Registry(self.temp.name)
        self.registry.initialize()
        self.transaction = self.registry.root / "transactions/first"
        self.transaction.mkdir(mode=0o700)
        self.active = self.registry.root / "network/active"
        self.active.symlink_to(self.transaction)
        atomic_write(self.transaction / "firewall-confirmed", "confirmed\n")
        self.pf_file = self.registry.root / "pf.conf"
        atomic_write(self.pf_file, "block log all\n")
        atomic_json(self.transaction / "firewall-transition.json", {
            "network": {"pf_file": str(self.pf_file), "pf_rules": self.pf_file.read_text()}})
        pf_path = patch("installer.host.PF_FILE", str(self.pf_file))
        pf_path.start()
        self.addCleanup(pf_path.stop)
        self.runner = HostModel(config())
        self.runner.running_pf = True
        self.runner.sysctls.update(host.NETWORK_SYSCTLS)
        for name, args, text in (("filter", ("-sr",), "block drop all\n"),
                                  ("nat", ("-sn",), "nat on igb0 from <cloud_jails> to any -> (igb0:0)\n"),
                                  ("jails", ("-t", "cloud_jails", "-T", "show"), "   10.77.0.2\n   10.77.0.6\n"),
                                  ("noninternet", ("-t", "cloud_noninternet", "-T", "show"), "   10.0.0.0/8\n")):
            atomic_write(self.transaction / f"pf-{name}.expected", text)
            self.runner.pf[args] = text

    def test_committed_policy_matches_exactly_except_trailing_newlines(self):
        self.runner.pf[("-sr",)] += "\n"
        self.assertEqual(host.verify_managed_network(self.registry, self.runner), self.transaction)

    def test_changed_disk_policy_is_refused_even_while_live_rules_still_match(self):
        for changed in ("", "pass all\n", "block log all\n\n"):
            atomic_write(self.pf_file, changed)
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, "disk policy differs"):
                host.verify_managed_network(self.registry, self.runner)
        self.assertFalse(self.runner.calls)

    def test_missing_or_untrusted_committed_policy_source_is_refused(self):
        for network in ({}, {"pf_file": str(self.pf_file), "pf_rules": ""},
                        {"pf_file": "/different/pf.conf", "pf_rules": "pass all\n"}):
            atomic_json(self.transaction / "firewall-transition.json", {"network": network})
            with self.subTest(network=network), self.assertRaisesRegex(ValueError, "policy source"):
                host.verify_managed_network(self.registry, self.runner)
        self.assertFalse(self.runner.calls)

    def test_leading_or_trailing_spaces_are_not_normalized(self):
        key = ("-t", "cloud_jails", "-T", "show")
        original = self.runner.pf[key]
        for altered in (original.lstrip(), original.rstrip("\n") + " \n"):
            self.runner.pf[key] = altered
            with self.subTest(altered=altered), self.assertRaisesRegex(ValueError, "jails differs"):
                host.verify_managed_network(self.registry, self.runner)

    def test_missing_confirmation_and_rolled_back_marker_fail_before_probes(self):
        marker = self.transaction / "firewall-confirmed"
        marker.unlink()
        with self.assertRaisesRegex(ValueError, "no readable committed"):
            host.verify_managed_network(self.registry, self.runner)
        atomic_write(marker, "confirmed\n")
        atomic_write(self.transaction / "firewall-rolled-back", "rolled back\n")
        with self.assertRaisesRegex(ValueError, "rolled back"):
            host.verify_managed_network(self.registry, self.runner)
        self.assertEqual(self.runner.calls, [])

    def test_outside_target_and_snapshot_symlink_are_rejected(self):
        self.active.unlink()
        self.active.symlink_to(self.registry.root / "backups")
        with self.assertRaisesRegex(ValueError, "escapes"):
            host.verify_managed_network(self.registry, self.runner)
        self.active.unlink()
        self.active.symlink_to(self.transaction)
        snapshot = self.transaction / "pf-filter.expected"
        snapshot.unlink()
        snapshot.symlink_to(self.transaction / "pf-nat.expected")
        with self.assertRaisesRegex(ValueError, "owner-only regular"):
            host.verify_managed_network(self.registry, self.runner)

    def test_non_symlink_and_dangling_active_are_not_treated_as_a_fresh_host(self):
        self.active.unlink()
        self.active.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError, "active symlink"):
            host.verify_managed_network(self.registry, self.runner)
        self.active.rmdir()
        self.active.symlink_to(self.transaction.parent / "missing")
        with self.assertRaisesRegex(ValueError, "no readable committed"):
            host.verify_managed_network(self.registry, self.runner)

    def test_stopped_pf_foreign_anchors_and_changed_sysctls_fail(self):
        self.runner.running_pf = False
        with self.assertRaisesRegex(ValueError, "not running"):
            host.verify_managed_network(self.registry, self.runner)
        self.runner.running_pf = True
        self.runner.pf[("-s", "Anchors")] = "foreign\n"
        with self.assertRaisesRegex(ValueError, "Foreign PF anchors"):
            host.verify_managed_network(self.registry, self.runner)
        self.runner.pf[("-s", "Anchors")] = ""
        for name, expected in host.NETWORK_SYSCTLS.items():
            self.runner.sysctls[name] = "0" if expected == "1" else "1"
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, name):
                host.verify_managed_network(self.registry, self.runner)
            self.runner.sysctls[name] = expected


class SecretRunnerTests(unittest.TestCase):
    def test_private_heartbeat_reports_elapsed_time_without_echoing_input_or_output(self):
        private = "synthetic-private-input"
        with patch("installer.host.subprocess.Popen") as opening, \
                patch("installer.host.time.monotonic", side_effect=[100, 100, 130, 130]), \
                patch("sys.stdout", new_callable=io.StringIO) as console:
            process = opening.return_value.__enter__.return_value
            process.communicate.side_effect = [subprocess.TimeoutExpired(["helper"], 30, output=private), (private, private)]
            process.returncode = 0
            result = host.Runner().run("helper", input=private, capture=False, progress_label="Document fonts")
        self.assertEqual(result.stdout, private)
        self.assertIn("Document fonts: still running (30s elapsed)", console.getvalue())
        self.assertNotIn(private, console.getvalue())
        self.assertEqual(process.communicate.call_args_list[0].kwargs["input"], private)
        self.assertIsNone(process.communicate.call_args_list[1].kwargs["input"])
        self.assertEqual(opening.call_args.kwargs["stdout"], subprocess.PIPE)
        self.assertTrue(opening.call_args.kwargs["start_new_session"])

    def test_private_progress_timeout_kills_only_the_owned_process_group(self):
        private = "synthetic-private-input"
        with patch("installer.host.subprocess.Popen") as opening, \
                patch("installer.host.time.monotonic", side_effect=[0, 0, 30, 31]), \
                patch("installer.host.os.killpg") as terminate, \
                patch("sys.stdout", new_callable=io.StringIO) as console:
            process = opening.return_value.__enter__.return_value
            process.pid, process.returncode = 12345, None
            process.communicate.side_effect = [subprocess.TimeoutExpired(["helper"], 30, output=private), (private, private)]
            with self.assertRaisesRegex(RuntimeError, "Private command timed out") as error:
                host.Runner().run("helper", input=private, timeout=30, progress_label="Document fonts")
        terminate.assert_called_once_with(12345, host.signal.SIGKILL)
        self.assertEqual(process.communicate.call_args.kwargs, {"timeout": 5})
        self.assertNotIn(private, str(error.exception))
        self.assertNotIn(private, console.getvalue())

    def test_stdin_forces_capture_and_failures_redact_both_output_streams(self):
        secret = "secret-password-and-JWT"
        with patch("installer.host.subprocess.run", return_value=subprocess.CompletedProcess(["tool"], 7, secret, secret)) as run:
            with self.assertRaisesRegex(RuntimeError, "exit status 7") as caught:
                host.Runner().run("tool", input=secret, capture=False)
        self.assertNotIn(secret, str(caught.exception))
        self.assertEqual(run.call_args.kwargs["input"], secret)
        self.assertEqual(run.call_args.kwargs["stdout"], subprocess.PIPE)
        self.assertEqual(run.call_args.kwargs["stderr"], subprocess.PIPE)

    def test_secret_timeout_output_does_not_reach_formatted_traceback(self):
        secret = "do-not-log-timeout-payload"
        timeout = subprocess.TimeoutExpired(["tool"], 5, output=secret, stderr=secret)
        with patch("installer.host.subprocess.run", side_effect=timeout):
            try:
                host.Runner().run("tool", input=secret)
            except RuntimeError as error:
                text = "".join(traceback.format_exception(type(error), error, error.__traceback__))
            else:
                self.fail("Expected a sanitized timeout")
        self.assertNotIn(secret, text)
        self.assertNotIn("TimeoutExpired", text)
        self.assertIn("Private command timed out", text)

    def test_hide_output_is_private_without_stdin_and_check_false_returns_captured_result(self):
        completed = subprocess.CompletedProcess(["tool"], 1, "sensitive-output", "sensitive-error")
        with patch("installer.host.subprocess.run", return_value=completed) as run:
            result = host.Runner().run("tool", hide_output=True, check=False, capture=False)
            self.assertIs(result, completed)
            with self.assertRaises(RuntimeError) as caught:
                host.Runner().run("tool", hide_output=True)
        self.assertNotIn("sensitive", str(caught.exception))
        self.assertEqual(run.call_args.kwargs["stdout"], subprocess.PIPE)

    def test_nonprivate_commands_keep_actionable_diagnostics(self):
        with patch("installer.host.subprocess.run", return_value=subprocess.CompletedProcess(["zfs"], 1, "", "pool is offline")):
            with self.assertRaisesRegex(RuntimeError, "pool is offline"):
                host.Runner().run("zfs", "list")


class HostInputTests(unittest.TestCase):
    def test_unsafe_regular_files_and_symlink_parents_are_rejected_without_opening(self):
        safe_directory = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_size=0)
        for mode, uid in ((stat.S_IFLNK | 0o777, 0), (stat.S_IFREG | 0o666, 0),
                          (stat.S_IFREG | 0o600, 1000), (stat.S_IFIFO | 0o600, 0)):
            with self.subTest(mode=mode, uid=uid):
                def info(path):
                    return SimpleNamespace(st_mode=mode, st_uid=uid, st_size=10) if path.name == "input" else safe_directory
                with patch.object(Path, "lstat", info), self.assertRaisesRegex(ValueError, "safe root-owned"):
                    host._safe_path("/root/input")
        with patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0)), self.assertRaisesRegex(ValueError, "parent directory"):
            host._safe_path("/root/input")

    def test_external_optional_ca_is_checked_and_cannot_contain_a_private_key(self):
        c = replace(config(), tls_mode="external", proxy_networks="203.0.113.2/32", ca_file="/root/ca.pem")
        runner = Mock()
        with patch("installer.host._safe_path", return_value=Path(c.ca_file)), patch.object(Path, "read_text", return_value="-----BEGIN PRIVATE KEY-----\n"):
            with self.assertRaisesRegex(ValueError, "never contain a private key"):
                host.verify_certificate(c, runner)
        runner.run.assert_not_called()

    def test_external_valid_ca_loads_trust_without_requiring_server_private_key(self):
        c = replace(config(), tls_mode="external", proxy_networks="203.0.113.2/32", ca_file="/root/ca.pem")
        with patch("installer.host._safe_path", return_value=Path(c.ca_file)), patch.object(Path, "read_text", return_value="certificate bundle"), patch("installer.host.ssl.create_default_context") as context:
            host.verify_certificate(c, Mock())
        context.assert_called_once_with(cafile=c.ca_file)


if __name__ == "__main__":
    unittest.main()
