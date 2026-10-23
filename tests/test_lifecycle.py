"""Explicit instance removal against a fake host and temporary audit registry."""

from dataclasses import replace
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, PropertyMock, call, patch

from installer.config import Config
from installer.deploy import Deployment, OWNER
from installer.lifecycle import RUNTIME_STEPS, _kernel_jail, _wait_for_jail_exit, remove_instance
from installer.state import Journal, Registry, atomic_json, atomic_write, private_json
from version_fixtures import LEGACY_CONFIG_JSON, LEGACY_CONFIG_SHA256


class FakeClock:
    def __init__(self):
        self.now = 0

    def monotonic(self):
        return self.now

    def sleep(self, delay):
        self.now += delay


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="lifecycle-tests-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        root = patch.object(Config, "bastille_root", new_callable=PropertyMock,
                            return_value=str(self.directory / "bastille"))
        root.start()
        self.addCleanup(root.stop)
        self.config = Config(public_hostname="cloud.example.test", admin_email="admin@example.test",
                             acme_email="admin@example.test", external_interface="igb0", ingress_address="192.0.2.10",
                             dns_server="192.0.2.53", management_network="198.51.100.0/24")
        self.other = replace(self.config, instance="other", private_network="10.78.0.0/29",
                             nextcloud_bridge="bridge242", onlyoffice_bridge="bridge243", ingress_address="192.0.2.11")
        self.registry = Registry(self.directory / "registry")
        self.registry.initialize()
        self.secrets = {"admin_password": "private-admin-password", "db_password": "a" * 64, "jwt_secret": "b" * 64}
        for config in (self.config, self.other):
            self.registry.save_new(config, self.secrets)
            self.registry.set_status(config.instance, "ready")
        self.runner = Mock(spec=["run", "output"])
        self.deployment = Deployment(self.config, self.secrets, self.runner, registry=self.registry, progress=Mock())
        self.datasets = {item.name: "cloud" for item in self.deployment.storage}
        self.paths = {}
        self.jail_points = {}
        self.mount_rows = {}
        self.filesystems = {}
        self.properties = {}
        self.inventory = None
        self.config_paths = {}
        self.running = set()
        self.dying = set()
        self.jids = {}
        self.bastille_targets = []
        for config in (self.config, self.other):
            self.add_jails(config)
        self.datasets[self.other.dataset_root] = "other"
        self.refuse_stop = False
        self.refuse_destroy = False
        self.mounts = ""
        self.runtime_mounts = {}
        self.bridges = {config.nextcloud_bridge: f"inet {config.nextcloud_gateway} netmask 0xfffffffc\n"
                        for config in (self.config, self.other)}
        self.bridges.update({config.onlyoffice_bridge: f"inet {config.onlyoffice_gateway} netmask 0xfffffffc\n"
                             for config in (self.config, self.other)})
        self.cloned = [*self.bridges, "unrelated0"]
        self.runner.run.side_effect = self.run_command
        self.runner.output.side_effect = self.output_command
        self.network = Mock(side_effect=self.withdraw_network)
        self.deployment.configure_network = self.network
        self.active = self.registry.root / "network/active"
        self.publish_network("initial", ["cloud", "other"])
        atomic_write(self.deployment.state / "allow-start", "allowed\n")
        self.other_before = {path: path.read_bytes() for path in self.registry.instance_path("other").iterdir()}

    def add_jails(self, config):
        for name in (config.nextcloud_jail, config.onlyoffice_jail):
            root = Path(config.bastille_root) / "jails" / name / "root"
            root.mkdir(parents=True)
            (root.parent / "jail.conf").write_text(f"{name} {{\n    path = {root};\n}}\n")
            self.paths[name] = str(root)
            self.jids[name] = len(self.jids) + 11
            self.running.add(name)
            parent = f"{config.bastille_dataset}/jails/{name}"
            for dataset, point in ((parent, root.parent), (parent + "/root", root)):
                self.datasets[dataset] = config.instance
                self.jail_points[dataset] = str(point)
                self.mount_rows[str(point)] = (dataset, "zfs")
                self.filesystems[str(point)] = dataset
            atomic_json(self.registry.instance_path(config.instance) / (name + ".creating.json"),
                        {"name": name, "root": str(root), "release": config.release})

    def named_inventory(self):
        # Bastille 1.4.4 list.sh:443-475,745-750: `list -j path` includes
        # stopped jails, but only when their jail.conf is available.
        return [{"JID": "11" if name in self.running else "-", "Name": name, "Path": path}
                for name, path in self.paths.items()
                if (Path(self.config.bastille_root) / "jails" / name / "jail.conf").is_file()]

    def resolve_target(self, name):
        names = [row["Name"] for row in self.named_inventory()]
        if name in names:
            return name
        # Match the dangerous common.sh:set_target/jail_autocomplete behavior,
        # rather than making the fake host silently accept missing exact names.
        matches = [candidate for candidate in names if candidate.startswith(name)]
        self.assertEqual(len(matches), 1, f"No unique Bastille prefix match for {name}")
        return matches[0]

    def publish_network(self, name, instances):
        transaction = self.registry.root / "transactions" / name
        transaction.mkdir(mode=0o700)
        atomic_json(transaction / "firewall-transition.json", {"instances": instances})
        atomic_write(transaction / "firewall-confirmed", "committed\n")
        if self.active.is_symlink():
            self.active.unlink()
        self.active.symlink_to(transaction)

    def withdraw_network(self, *, removing=False):
        self.assertTrue(removing)
        self.publish_network("removed-cloud", [config.instance for config in self.registry.network_configs(exclude="cloud")])

    def run_command(self, *args, **kwargs):
        stdout, returncode = "", 0
        if args[0] == "jls":
            if "--libxo" in args:
                self.assertEqual(args, ("jls", "--libxo", "json", "-d", "jid", "name", "path", "dying"))
                stdout = json.dumps({"__version": "2", "jail-information": {"jail": [
                    {"jid": str(self.jids[name]), "name": name, "path": self.paths[name],
                     "dying": "true" if name in self.dying else "false"}
                    for name in sorted(self.running | self.dying)]}})
            else:
                name = args[args.index("-j") + 1]
                returncode = 0 if name in self.running or ("-d" in args and name in self.dying) else 1
                stdout = f"{self.jids[name]} {name} {self.paths[name]}\n" if not returncode else ""
        elif args[:2] == ("bastille", "config"):
            self.assertEqual(args[3:], ("set", "boot", "off"))
            self.bastille_targets.append(("config", self.resolve_target(args[2])))
        elif args[:2] == ("bastille", "stop"):
            name = self.resolve_target(args[2])
            self.bastille_targets.append(("stop", name))
            if not self.refuse_stop:
                self.running.discard(name)
                self.runtime_mounts.pop(name, None)
        elif args[:2] == ("bastille", "destroy"):
            name = self.resolve_target(args[-1])
            self.bastille_targets.append(("destroy", name))
            if not self.refuse_destroy:
                root = Path(self.config.bastille_root) / "jails" / name / "root"
                parent = f"{self.config.bastille_dataset}/jails/{name}"
                for dataset in (parent + "/root", parent):
                    self.datasets.pop(dataset)
                    point = self.jail_points.pop(dataset)
                    self.mount_rows.pop(point)
                    self.filesystems.pop(point)
                root.rmdir()
                (root.parent / "jail.conf").unlink()
                root.parent.rmdir()
        elif args[:2] == ("zfs", "list"):
            returncode = 0 if args[-1] in self.datasets else 1
        elif args[:2] == ("zfs", "destroy"):
            if not self.refuse_destroy:
                for name in list(self.datasets):
                    if name == args[-1] or name.startswith(args[-1] + "/"):
                        del self.datasets[name]
        elif args[0] == "ifconfig":
            if len(args) == 3 and args[2] == "destroy":
                del self.bridges[args[1]]
            else:
                stdout, returncode = self.bridges.get(args[1], ""), 0 if args[1] in self.bridges else 1
        elif args[:2] == ("sysrc", "-n"):
            stdout = " ".join(self.cloned)
        elif args[0] == "sysrc" and args[1].startswith("cloned_interfaces="):
            self.cloned = args[1].partition("=")[2].split()
        elif args[:2] == ("sysrc", "-x") or args[:2] == ("pfctl", "-k"):
            pass
        else:
            self.fail(f"Unexpected mock host command: {args}")
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr="")

    def output_command(self, *args):
        if args == ("bastille", "list", "-j", "path"):
            if isinstance(self.inventory, str):
                return self.inventory
            return json.dumps(self.named_inventory() if self.inventory is None else self.inventory)
        if args[:2] == ("bastille", "config"):
            self.assertEqual(args[3:], ("get", "path"))
            name = self.resolve_target(args[2])
            return self.config_paths.get(name, self.paths[name])
        if args[:2] == ("zfs", "get"):
            key, dataset = args[-2:]
            if (dataset, key) in self.properties:
                return self.properties[(dataset, key)]
            if key == OWNER:
                return self.datasets[dataset]
            self.assertIn(dataset, self.jail_points)
            return {"org.cloud-installer:owner": "cloud-installer", "type": "filesystem",
                    "mountpoint": self.jail_points[dataset], "mounted": "yes"}[key]
        if args[:2] == ("zfs", "list"):
            return "\n".join(name for name in self.datasets if name == args[-1] or name.startswith(args[-1] + "/"))
        if args == ("mount", "-p"):
            return ("".join(f"{source} {point} {kind} rw 0 0\n"
                            for point, (source, kind) in self.mount_rows.items())
                    + "".join(self.runtime_mounts.values()) + self.mounts)
        if args[:2] == ("df", "-P"):
            return f"Filesystem 512-blocks Used Available Capacity Mounted on\n{self.filesystems[args[2]]} 1 0 1 0% {args[2]}"
        self.fail(f"Unexpected mock host query: {args}")

    def assert_no_host_mutations(self):
        self.assertEqual(self.bastille_targets, [])
        self.assertTrue(all(item.args[0] == "jls" or item.args[:2] == ("zfs", "list")
                            for item in self.runner.run.call_args_list), self.runner.run.call_args_list)
        self.network.assert_not_called()

    def reuse_network_allocations(self):
        replacement = replace(self.config, instance="newcloud", public_hostname="new.example.test")
        self.registry.save_new(replacement, self.secrets)
        self.registry.set_status("newcloud", "ready")
        self.publish_network("reused-addresses", ["other", "newcloud"])
        # Stopped replacement jails leave no bridge members to accidentally
        # rescue them from stale cleanup; the allocations still belong to B.
        self.bridges[replacement.nextcloud_bridge] = f"inet {replacement.nextcloud_gateway} netmask 0xfffffffc\n"
        self.bridges[replacement.onlyoffice_bridge] = f"inet {replacement.onlyoffice_gateway} netmask 0xfffffffc\n"
        self.cloned = list(dict.fromkeys(self.cloned + [replacement.nextcloud_bridge, replacement.onlyoffice_bridge]))
        return replacement

    def assert_only_data_commands(self):
        self.network.assert_not_called()
        for method in (self.runner.run, self.runner.output):
            self.assertTrue(all(item.args[0] == "zfs" for item in method.call_args_list), method.call_args_list)

    def destructive_commands(self):
        return [item.args for item in self.runner.run.call_args_list
                if item.args[:2] in (("zfs", "destroy"), ("bastille", "destroy"))]

    def assert_other_untouched(self):
        for path, contents in self.other_before.items():
            self.assertEqual(path.read_bytes(), contents)
        self.assertTrue({"othernc", "otheroo"} <= self.running)
        self.assertEqual(self.datasets[self.other.dataset_root], "other")
        self.assertTrue({"bridge242", "bridge243", "unrelated0"} <= set(self.cloned))
        for command in self.destructive_commands():
            self.assertNotIn(self.other.dataset_root, command)
            self.assertNotIn("othernc", command)
            self.assertNotIn("otheroo", command)

    def test_exact_confirmation_is_required_before_any_state_or_host_change(self):
        before = {path: path.read_bytes() for path in self.deployment.state.iterdir()}
        for purge, phrase in ((False, ""), (False, "REMOVE other"), (False, "remove cloud"),
                              (False, "REMOVE cloud "), (False, "PURGE cloud"), (True, "REMOVE cloud")):
            with self.subTest(purge=purge, phrase=phrase), self.assertRaisesRegex(ValueError, "exact typed confirmation"):
                remove_instance(self.deployment, purge_data=purge, confirmation=phrase)
        self.runner.run.assert_not_called()
        self.runner.output.assert_not_called()
        self.network.assert_not_called()
        self.assertEqual({path: path.read_bytes() for path in self.deployment.state.iterdir()}, before)

    def test_default_removal_destroys_jail_roots_retains_application_data_and_tombstone(self):
        app_datasets = {item.name for item in self.deployment.storage}
        remove_instance(self.deployment, confirmation="REMOVE cloud")
        self.assertEqual(self.destructive_commands(), [("bastille", "destroy", "-y", "cloudnc"),
                                                       ("bastille", "destroy", "-y", "cloudoo")])
        self.assertTrue(app_datasets <= self.datasets.keys())
        self.network.assert_called_once_with(removing=True)
        self.assertEqual([config.instance for config in self.registry.network_configs()], ["other"])
        self.assertFalse((self.deployment.state / "allow-start").exists())
        self.assertTrue((self.deployment.state / "allow-start.disabled").is_file())
        self.assertEqual(private_json(self.deployment.state / "removed.json"), {
            "data_retained": True, "dataset": self.config.dataset_root,
            "credentials_retained": True, "backups_retained": True})
        self.assertEqual(private_json(self.deployment.state / "status.json")["state"], "removed")
        self.assertEqual(private_json(self.deployment.state / "secrets.json"), self.secrets)
        self.assert_other_untouched()
        with self.assertRaisesRegex(ValueError, "already registered"):
            self.registry.save_new(self.config, self.secrets)

    def test_stop_waits_for_verified_dying_targets_before_network_or_destruction(self):
        clock = FakeClock()
        def stop_then_dying(*args, **kwargs):
            if args[:2] == ('bastille', 'destroy'):
                self.assertFalse(self.dying)
            result = self.run_command(*args, **kwargs)
            if args[:2] == ('bastille', 'stop'):
                self.dying.add(args[-1])
            return result
        def advance(delay):
            clock.sleep(delay)
            self.dying.clear()
        self.runner.run.side_effect = stop_then_dying
        with patch('installer.lifecycle.time.monotonic', side_effect=clock.monotonic), \
                patch('installer.lifecycle.time.sleep', side_effect=advance) as sleep, redirect_stdout(io.StringIO()) as output:
            remove_instance(self.deployment, confirmation='REMOVE cloud')
        self.assertEqual(sleep.call_count, 2)
        self.assertEqual(output.getvalue().count('Waiting up to 10s'), 2)
        self.assertEqual(self.bastille_targets.count(('stop', 'cloudnc')), 1)
        self.assertEqual(self.bastille_targets.count(('stop', 'cloudoo')), 1)
        self.network.assert_called_once_with(removing=True)
        self.assert_other_untouched()

    def test_teardown_deadline_keeps_roots_network_and_failed_checkpoint_then_retry(self):
        clock = FakeClock()
        before = dict(self.datasets)
        def lingering(*args, **kwargs):
            result = self.run_command(*args, **kwargs)
            if args[:2] == ('bastille', 'stop') and args[-1] == 'cloudnc':
                self.dying.add('cloudnc')
            return result
        self.runner.run.side_effect = lingering
        with patch('installer.lifecycle.time.monotonic', side_effect=clock.monotonic), \
                patch('installer.lifecycle.time.sleep', side_effect=clock.sleep), redirect_stdout(io.StringIO()) as output:
            with self.assertRaisesRegex(RuntimeError, 'cloudnc teardown timed out; roots retained'):
                remove_instance(self.deployment, confirmation='REMOVE cloud')
        self.assertEqual(clock.now, 10)
        self.assertEqual(output.getvalue().count('Waiting up to 10s'), 1)
        self.assertEqual(self.datasets, before)
        self.assertEqual(self.destructive_commands(), [])
        self.network.assert_not_called()
        journal = private_json(self.deployment.state / 'removal.json')
        self.assertEqual(journal['steps']['disable boot and stop instance']['state'], 'failed')
        def release(delay):
            clock.sleep(delay)
            self.dying.clear()
        with patch('installer.lifecycle.time.monotonic', side_effect=clock.monotonic), \
                patch('installer.lifecycle.time.sleep', side_effect=release), redirect_stdout(io.StringIO()):
            remove_instance(self.deployment, confirmation='REMOVE cloud')
        self.assertEqual(self.bastille_targets.count(('stop', 'cloudnc')), 1)
        self.assertEqual(self.bastille_targets.count(('stop', 'cloudoo')), 1)
        self.assertEqual(private_json(self.deployment.state / 'removal.json')['steps']['disable boot and stop instance']['attempt'], 2)
        self.assert_other_untouched()

    def test_immediate_stop_has_no_wait_message_or_sleep(self):
        with patch('installer.lifecycle.time.sleep') as sleep, redirect_stdout(io.StringIO()) as output:
            remove_instance(self.deployment, confirmation='REMOVE cloud')
        sleep.assert_not_called()
        self.assertEqual(output.getvalue(), '')

    def test_failed_kernel_probe_never_permits_root_destruction(self):
        def failed(*args, **kwargs):
            if '--libxo' in args:
                return SimpleNamespace(returncode=1, stdout='', stderr='fixture kernel error')
            return self.run_command(*args, **kwargs)
        self.runner.run.side_effect = failed
        with self.assertRaisesRegex(RuntimeError, 'Cannot verify kernel jail'):
            remove_instance(self.deployment, confirmation='REMOVE cloud')
        self.network.assert_not_called()
        self.assertEqual(self.destructive_commands(), [])

    def test_stop_error_propagates_without_wait_or_destruction(self):
        def failed(*args, **kwargs):
            if args[:2] == ('bastille', 'stop'):
                raise RuntimeError('fixture stop failed')
            return self.run_command(*args, **kwargs)
        self.runner.run.side_effect = failed
        with patch('installer.lifecycle._wait_for_jail_exit') as wait:
            with self.assertRaisesRegex(RuntimeError, 'fixture stop failed'):
                remove_instance(self.deployment, confirmation='REMOVE cloud')
        wait.assert_not_called()
        self.network.assert_not_called()
        self.assertEqual(self.destructive_commands(), [])

    def test_historical_removal_journal_remains_usable_without_inventing_a_version_lock(self):
        atomic_write(self.deployment.state / "config.json", LEGACY_CONFIG_JSON)
        self.assertEqual(self.registry.load("cloud"), self.config)
        atomic_json(self.deployment.state / "removal.json", {
            "schema_version": 2, "config_sha256": LEGACY_CONFIG_SHA256, "steps": {}})
        atomic_write(self.deployment.state / "source.sha256", "a" * 64 + "\n")
        before = (self.deployment.state / "source.sha256").read_bytes()
        remove_instance(self.deployment, confirmation="REMOVE cloud")
        self.assertEqual(private_json(self.deployment.state / "status.json")["state"], "removed")
        self.assertEqual((self.deployment.state / "source.sha256").read_bytes(), before)
        self.assertFalse((self.deployment.state / "versions.json").exists())
        self.assert_other_untouched()

    def test_pf_states_are_killed_only_for_removed_endpoints_in_both_directions(self):
        remove_instance(self.deployment, confirmation="REMOVE cloud")
        self.assertEqual([item.args for item in self.runner.run.call_args_list if item.args[0] == "pfctl"], [
            ("pfctl", "-k", "10.77.0.2"), ("pfctl", "-k", "0.0.0.0/0", "-k", "10.77.0.2"),
             ("pfctl", "-k", "10.77.0.6"), ("pfctl", "-k", "0.0.0.0/0", "-k", "10.77.0.6")])

    def test_later_data_purge_never_touches_reused_network_allocations(self):
        remove_instance(self.deployment, confirmation="REMOVE cloud")
        self.reuse_network_allocations()
        self.bridges["bridge240"] = "inet 10.77.0.1 netmask 0xfffffffc\nmember: e0a_newcloudnc\n"
        self.bridges["bridge241"] = "inet 10.77.0.5 netmask 0xfffffffc\nmember: e0a_newcloudoo\n"
        original = dict(self.bridges)
        active = self.active.resolve()
        self.runner.reset_mock()
        self.network.reset_mock()
        remove_instance(self.deployment, purge_data=True, confirmation="PURGE cloud")
        self.assertEqual(self.bridges, original)
        self.assertEqual(self.active.resolve(), active)
        self.assert_only_data_commands()
        self.assertEqual(self.destructive_commands(), [("zfs", "destroy", "-r", self.config.dataset_root)])
        self.assertFalse(private_json(self.deployment.state / "status.json")["data_retained"])
        self.assert_other_untouched()

    def test_failed_purge_then_remove_then_reused_addresses_promotes_stale_purge_durably(self):
        self.network.side_effect = RuntimeError("transaction rolled back")
        with self.assertRaisesRegex(RuntimeError, "rolled back"):
            remove_instance(self.deployment, purge_data=True, confirmation="PURGE cloud")
        self.assertFalse(private_json(self.deployment.state / "purge.json")["runtime_already_removed"])
        self.network.side_effect = self.withdraw_network
        remove_instance(self.deployment, confirmation="REMOVE cloud")
        self.reuse_network_allocations()
        replacement_state = self.registry.instance_path("newcloud")
        before = {path: path.read_bytes() for path in replacement_state.iterdir()}
        bridges, cloned, active = dict(self.bridges), list(self.cloned), self.active.resolve()
        # Fail the first data-only retry, so status becomes 'removing'. The
        # promoted checkpoint must be durable before any app-data operation.
        foreign = self.config.dataset_root + "/foreign"
        self.datasets[foreign] = "cloud"
        for fail in (True, False):
            if not fail:
                del self.datasets[foreign]
            self.runner.reset_mock()
            self.network.reset_mock()
            if fail:
                with self.assertRaisesRegex(ValueError, "Unexpected descendants"):
                    remove_instance(self.deployment, purge_data=True, confirmation="PURGE cloud")
                self.assertEqual(private_json(self.deployment.state / "status.json")["state"], "removing")
                self.assertEqual(self.destructive_commands(), [])
            else:
                remove_instance(self.deployment, purge_data=True, confirmation="PURGE cloud")
                self.assertEqual(self.destructive_commands(), [("zfs", "destroy", "-r", self.config.dataset_root)])
            self.assertTrue(private_json(self.deployment.state / "purge.json")["runtime_already_removed"])
            self.assert_only_data_commands()
            self.assertEqual(self.bridges, bridges)
            self.assertEqual(self.cloned, cloned)
            self.assertEqual(self.active.resolve(), active)
            self.assertEqual({path: path.read_bytes() for path in replacement_state.iterdir()}, before)
            self.assert_other_untouched()

    def test_completed_removal_journal_is_evidence_when_tombstone_publication_crashed(self):
        stale = Journal(self.deployment.state / "purge.json", self.config)
        stale.data["runtime_already_removed"] = False
        stale.save()
        with patch("installer.lifecycle.atomic_json", side_effect=OSError("tombstone write failed")):
            with self.assertRaisesRegex(OSError, "tombstone write failed"):
                remove_instance(self.deployment, confirmation="REMOVE cloud")
        self.assertEqual(private_json(self.deployment.state / "status.json")["state"], "removing")
        self.assertFalse((self.deployment.state / "removed.json").exists())
        self.reuse_network_allocations()
        self.runner.reset_mock()
        self.network.reset_mock()
        remove_instance(self.deployment, purge_data=True, confirmation="PURGE cloud")
        self.assert_only_data_commands()
        self.assertTrue(private_json(stale.path)["runtime_already_removed"])
        self.assertEqual(self.destructive_commands(), [("zfs", "destroy", "-r", self.config.dataset_root)])
        self.assert_other_untouched()

    def test_legacy_tombstone_promotes_stale_flag_even_after_status_became_removing(self):
        remove_instance(self.deployment, confirmation="REMOVE cloud")
        (self.deployment.state / "removal.json").unlink()
        self.registry.set_status("cloud", "removing", purge_data=True)
        stale = Journal(self.deployment.state / "purge.json", self.config)
        stale.data["runtime_already_removed"] = False
        stale.save()
        self.reuse_network_allocations()
        self.runner.reset_mock()
        self.network.reset_mock()
        remove_instance(self.deployment, purge_data=True, confirmation="PURGE cloud")
        self.assert_only_data_commands()
        self.assertTrue(private_json(stale.path)["runtime_already_removed"])
        self.assertEqual(self.destructive_commands(), [("zfs", "destroy", "-r", self.config.dataset_root)])
        self.assert_other_untouched()

    def test_completed_removal_evidence_requires_matching_schema_hash_and_steps(self):
        remove_instance(self.deployment, confirmation="REMOVE cloud")
        path = self.deployment.state / "removal.json"
        original = private_json(path)
        self.registry.set_status("cloud", "removing")
        for field, invalid in (("schema_version", 0), ("config_sha256", "0" * 64), ("steps", [])):
            with self.subTest(field=field):
                atomic_json(path, dict(original, **{field: invalid}))
                self.runner.reset_mock()
                self.network.reset_mock()
                with self.assertRaisesRegex(ValueError, "ownership journal"):
                    remove_instance(self.deployment, purge_data=True, confirmation="PURGE cloud")
                self.runner.run.assert_not_called()
                self.runner.output.assert_not_called()
                self.network.assert_not_called()

    def test_incomplete_other_journal_does_not_prove_runtime_removed(self):
        journal = Journal(self.deployment.state / "removal.json", self.config)
        journal.data["steps"] = {name: {"state": "complete"} for name in RUNTIME_STEPS}
        journal.data["steps"][RUNTIME_STEPS[-1]]["state"] = "failed"
        journal.save()
        self.registry.set_status("cloud", "removing")
        self.reuse_network_allocations()
        with self.assertRaisesRegex(ValueError, "allocations.*another active instance"):
            remove_instance(self.deployment, purge_data=True, confirmation="PURGE cloud")
        self.runner.run.assert_not_called()
        self.runner.output.assert_not_called()
        self.assert_no_host_mutations()

    def test_foreign_or_malformed_tombstone_cannot_skip_runtime_removal(self):
        tombstone = {"dataset": self.config.dataset_root, "data_retained": True,
                     "credentials_retained": True, "backups_retained": True}
        for field, invalid in (("dataset", self.other.dataset_root), ("data_retained", "true"),
                               ("credentials_retained", False), ("backups_retained", False)):
            with self.subTest(field=field):
                atomic_json(self.deployment.state / "removed.json", dict(tombstone, **{field: invalid}))
                with self.assertRaisesRegex(ValueError, "tombstone"):
                    remove_instance(self.deployment, purge_data=True, confirmation="PURGE cloud")
                self.runner.run.assert_not_called()
                self.runner.output.assert_not_called()
                self.assert_no_host_mutations()

    def test_reused_network_or_either_bridge_refuses_before_any_mutation_without_runtime_proof(self):
        atomic_json(self.active / "firewall-transition.json", {"instances": ["other"]})
        before = {path: path.read_bytes() for path in self.deployment.state.iterdir()}
        for collision in (replace(self.other, private_network="10.77.0.0/24"),
                          replace(self.other, onlyoffice_bridge=self.config.nextcloud_bridge),
                          replace(self.other, nextcloud_bridge=self.config.onlyoffice_bridge)):
            with self.subTest(config=collision):
                atomic_json(self.registry.instance_path("other") / "config.json", json.loads(collision.to_json()))
                with self.assertRaisesRegex(ValueError, "allocations.*another active instance"):
                    remove_instance(self.deployment, confirmation="REMOVE cloud")
                self.runner.run.assert_not_called()
                self.runner.output.assert_not_called()
                self.assert_no_host_mutations()
                self.assertEqual({path: path.read_bytes() for path in self.deployment.state.iterdir()}, before)

    def test_repeated_remove_does_not_change_an_already_purged_tombstone(self):
        remove_instance(self.deployment, purge_data=True, confirmation="PURGE cloud")
        before = private_json(self.deployment.state / "status.json")
        self.runner.reset_mock()
        remove_instance(self.deployment, confirmation="REMOVE cloud")
        self.runner.run.assert_not_called()
        self.assertEqual(private_json(self.deployment.state / "status.json"), before)

    def test_pre_network_failure_does_not_reconfigure_unrelated_active_policy(self):
        atomic_json(self.active / "firewall-transition.json", {"instances": ["other"]})
        self.registry.set_status("cloud", "failed")
        remove_instance(self.deployment, confirmation="REMOVE cloud")
        self.network.assert_not_called()
        self.assertEqual([config.instance for config in self.registry.network_configs()], ["other"])
        self.assert_other_untouched()

    def test_unreserved_or_wrong_root_jail_is_not_stopped_or_withdrawn(self):
        intent = self.deployment.state / "cloudnc.creating.json"
        contents = intent.read_text()
        intent.unlink()
        with self.assertRaisesRegex(ValueError, "unreserved"):
            remove_instance(self.deployment, confirmation="REMOVE cloud")
        self.assert_no_host_mutations()
        atomic_write(intent, contents)
        self.paths["cloudnc"] = str(self.directory / "foreign-root")
        with self.assertRaisesRegex(ValueError, "identity changed"):
            remove_instance(self.deployment, confirmation="REMOVE cloud")
        self.assert_no_host_mutations()
        self.assertEqual(self.destructive_commands(), [])

    def test_stubborn_live_jail_prevents_policy_change_or_destruction(self):
        self.refuse_stop = True
        with self.assertRaisesRegex(RuntimeError, "did not stop"):
            remove_instance(self.deployment, confirmation="REMOVE cloud")
        self.network.assert_not_called()
        self.assertEqual(self.destructive_commands(), [])
        self.assert_other_untouched()

    def test_prefix_related_stopped_jail_is_never_mutated_when_exact_config_is_unavailable(self):
        configs = [replace(self.config, instance="a", private_network="10.79.0.0/29",
                           nextcloud_bridge="bridge244", onlyoffice_bridge="bridge245", ingress_address="192.0.2.12"),
                   replace(self.config, instance="ao", private_network="10.80.0.0/29",
                           nextcloud_bridge="bridge246", onlyoffice_bridge="bridge247", ingress_address="192.0.2.13")]
        for config in configs:
            self.registry.save_new(config, self.secrets)
            self.registry.set_status(config.instance, "ready")
            self.add_jails(config)
        self.publish_network("prefix-instances", ["cloud", "other", "a", "ao"])
        a = Deployment(configs[0], self.secrets, self.runner, registry=self.registry, progress=Mock())
        a.configure_network = self.network
        self.running.difference_update(("aoo", "aooo"))
        conf = a.jail_root("aoo").parent / "jail.conf"
        contents = conf.read_text()
        before = dict(self.datasets)
        for fault in ("missing-config", "unmounted-parent", "unmounted-root"):
            with self.subTest(fault=fault):
                if fault == "missing-config":
                    conf.unlink()
                    self.assertEqual(self.resolve_target("aoo"), "aooo")
                else:
                    dataset = f"{a.config.bastille_dataset}/jails/aoo" + ("/root" if fault.endswith("root") else "")
                    self.properties[(dataset, "mounted")] = "no"
                with self.assertRaises(ValueError):
                    remove_instance(a, confirmation="REMOVE a")
                self.assert_no_host_mutations()
                self.assertEqual(self.datasets, before)
                self.assertTrue(Path(self.paths["aooo"]).is_dir())
                if fault == "missing-config":
                    conf.write_text(contents)
                self.properties.clear()
        self.assert_other_untouched()

    def test_named_json_inventory_must_contain_both_exact_jail_names_and_paths(self):
        valid = self.named_inventory()
        for inventory in ("not JSON", {}, [{"Path": self.paths["cloudnc"]}], valid + [valid[0]],
                          [row for row in valid if row["Name"] != "cloudoo"],
                          [dict(row, Path="/foreign") if row["Name"] == "cloudoo" else row for row in valid]):
            with self.subTest(inventory=inventory):
                self.inventory = inventory
                with self.assertRaises(ValueError):
                    remove_instance(self.deployment, confirmation="REMOVE cloud")
                self.assert_no_host_mutations()
                self.assertTrue((self.deployment.state / "allow-start").exists())
        self.runner.output.assert_any_call("bastille", "list", "-j", "path")
        self.assertFalse(any(item.args[:2] == ("bastille", "config") for item in self.runner.output.call_args_list))

    def test_inventory_does_not_replace_exact_configured_root_check(self):
        self.config_paths["cloudoo"] = "/foreign/root"
        with self.assertRaisesRegex(ValueError, "root identity changed"):
            remove_instance(self.deployment, confirmation="REMOVE cloud")
        self.assert_no_host_mutations()

    def test_jail_config_must_be_owned_regular_unaliased_and_not_writable_by_others(self):
        conf = Path(self.paths["cloudoo"]).parent / "jail.conf"
        saved = self.directory / "saved-jail.conf"
        conf.rename(saved)
        for kind in ("symlink", "hardlink", "directory", "writable"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    conf.symlink_to(saved)
                elif kind == "hardlink":
                    conf.hardlink_to(saved)
                elif kind == "directory":
                    conf.mkdir()
                else:
                    conf.write_text(saved.read_text())
                    conf.chmod(0o666)
                with self.assertRaisesRegex(ValueError, "owned regular file"):
                    remove_instance(self.deployment, confirmation="REMOVE cloud")
                self.assert_no_host_mutations()
                if kind == "directory":
                    conf.rmdir()
                else:
                    conf.unlink()
        saved.rename(conf)
        original_lstat = Path.lstat

        def foreign_owner(path):
            info = original_lstat(path)
            return SimpleNamespace(st_mode=info.st_mode, st_uid=os.geteuid() + 1, st_nlink=1) if path == conf else info

        with patch.object(Path, "lstat", foreign_owner), self.assertRaisesRegex(ValueError, "owned regular file"):
            remove_instance(self.deployment, confirmation="REMOVE cloud")
        self.assert_no_host_mutations()

    def test_both_parent_and_root_require_owner_properties_and_complete_mounted_zfs(self):
        parent = f"{self.config.bastille_dataset}/jails/cloudoo"
        for dataset in (parent, parent + "/root"):
            for key, value in ((OWNER, "other"), ("org.cloud-installer:owner", "foreign"),
                               ("mountpoint", "/foreign"), ("mounted", "no"), ("type", "volume")):
                with self.subTest(dataset=dataset, key=key):
                    self.properties[(dataset, key)] = value
                    with self.assertRaisesRegex(ValueError, "unowned jail dataset|changed/unmounted"):
                        remove_instance(self.deployment, confirmation="REMOVE cloud")
                    self.assert_no_host_mutations()
                    self.properties.clear()
            with self.subTest(missing=dataset):
                owner = self.datasets.pop(dataset)
                with self.assertRaisesRegex(ValueError, "Incomplete jail datasets"):
                    remove_instance(self.deployment, confirmation="REMOVE cloud")
                self.assert_no_host_mutations()
                self.datasets[dataset] = owner

    def test_foreign_or_missing_actual_mount_at_parent_or_root_refuses_all_bastille_mutation(self):
        root = Path(self.paths["cloudoo"])
        for point in (str(root.parent), str(root)):
            expected = self.mount_rows[point]
            for cover in (None, ("tmpfs", "tmpfs"), ("/foreign", "nullfs"), ("zroot/foreign", "zfs")):
                with self.subTest(point=point, cover=cover):
                    self.mount_rows.pop(point, None)
                    if cover is not None:
                        self.mount_rows[point] = cover
                    with self.assertRaisesRegex(RuntimeError, "actual uncovered ZFS mount"):
                        remove_instance(self.deployment, confirmation="REMOVE cloud")
                    self.assert_no_host_mutations()
            self.mount_rows[point] = expected
            self.filesystems[point] = "zroot/foreign"
            with self.assertRaisesRegex(RuntimeError, "actual uncovered ZFS mount"):
                remove_instance(self.deployment, confirmation="REMOVE cloud")
            self.assert_no_host_mutations()
            self.filesystems[point] = expected[0]

    def test_symlinked_mountpoint_and_unexpected_zfs_descendants_refuse_all_mutations(self):
        root = Path(self.paths["cloudoo"])
        elsewhere = self.directory / "foreign-root"
        root.rename(elsewhere)
        root.symlink_to(elsewhere)
        with self.assertRaisesRegex(ValueError, "real directory"):
            remove_instance(self.deployment, confirmation="REMOVE cloud")
        self.assert_no_host_mutations()
        root.unlink()
        elsewhere.rename(root)
        self.datasets[f"{self.config.bastille_dataset}/jails/cloudoo/foreign"] = "other"
        with self.assertRaisesRegex(ValueError, "Unexpected jail dataset descendants"):
            remove_instance(self.deployment, confirmation="REMOVE cloud")
        self.assert_no_host_mutations()

    def test_owned_application_and_devfs_mounts_are_quiesced_before_both_roots_are_destroyed(self):
        for name in (self.config.nextcloud_jail, self.config.onlyoffice_jail):
            root = self.paths[name]
            self.runtime_mounts[name] = (f"devfs {root}/dev devfs rw 0 0\n" + "".join(
                f"{item.mountpoint} {root}{item.target} nullfs rw 0 0\n"
                for item in self.deployment.storage if item.jail == name))
        remove_instance(self.deployment, confirmation="REMOVE cloud")
        actions = [item.args for item in self.runner.run.call_args_list]
        self.assertLess(actions.index(("bastille", "stop", "cloudoo")), actions.index(("bastille", "destroy", "-y", "cloudnc")))
        self.assertEqual(self.runtime_mounts, {})
        self.assert_other_untouched()

    def test_both_roots_are_revalidated_after_stop_checkpoint_before_either_destroy(self):
        def withdraw_and_lose_config(**kwargs):
            self.withdraw_network(**kwargs)
            (Path(self.paths["cloudoo"]).parent / "jail.conf").unlink()

        self.network.side_effect = withdraw_and_lose_config
        before = dict(self.datasets)
        with self.assertRaisesRegex(ValueError, "Missing owned jail.conf"):
            remove_instance(self.deployment, confirmation="REMOVE cloud")
        self.assertEqual(self.datasets, before)
        self.assertEqual(self.destructive_commands(), [])
        self.assertEqual(self.running, {"othernc", "otheroo"})
        self.runner.reset_mock()
        self.network.reset_mock()
        self.bastille_targets.clear()
        with self.assertRaisesRegex(ValueError, "Missing owned jail.conf"):
            remove_instance(self.deployment, confirmation="REMOVE cloud")
        self.assert_no_host_mutations()
        self.assertEqual(self.datasets, before)

    def test_target_is_rechecked_immediately_before_stop_after_boot_setting(self):
        def lose_config_after_boot_setting(*args, **kwargs):
            result = self.run_command(*args, **kwargs)
            if args[:3] == ("bastille", "config", "cloudnc"):
                (Path(self.paths["cloudnc"]).parent / "jail.conf").unlink()
            return result

        self.runner.run.side_effect = lose_config_after_boot_setting
        with self.assertRaisesRegex(ValueError, "Missing owned jail.conf"):
            remove_instance(self.deployment, confirmation="REMOVE cloud")
        self.assertEqual(self.bastille_targets, [("config", "cloudnc")])
        self.network.assert_not_called()
        self.assertEqual(self.destructive_commands(), [])

    def test_owned_mount_left_behind_or_dying_jail_blocks_both_destructions(self):
        item = next(item for item in self.deployment.storage if item.jail == "cloudoo")
        self.mounts = f"{item.mountpoint} {self.paths['cloudoo']}{item.target} nullfs rw 0 0\n"
        with self.assertRaisesRegex(RuntimeError, "mounts remain"):
            remove_instance(self.deployment, confirmation="REMOVE cloud")
        self.assertEqual(self.destructive_commands(), [])
        self.mounts = ""
        self.dying.add("cloudoo")
        with self.assertRaisesRegex(RuntimeError, "still dying"):
            remove_instance(self.deployment, confirmation="REMOVE cloud")
        self.assertEqual(self.destructive_commands(), [])
        self.assert_other_untouched()

    def test_network_withdrawal_failure_preserves_every_dataset_for_retry(self):
        before = dict(self.datasets)
        self.network.side_effect = RuntimeError("transaction rolled back")
        with self.assertRaisesRegex(RuntimeError, "rolled back"):
            remove_instance(self.deployment, confirmation="REMOVE cloud")
        self.assertEqual(self.datasets, before)
        self.assertEqual(self.destructive_commands(), [])
        journal = private_json(self.deployment.state / "removal.json")
        self.assertEqual(journal["steps"]["disable boot and stop instance"]["state"], "complete")
        self.assertEqual(journal["steps"]["withdraw instance firewall access"]["state"], "failed")
        self.assertEqual(private_json(self.deployment.state / "status.json")["state"], "removing")
        self.assert_other_untouched()

    def test_wrong_zfs_ownership_prevents_jail_destruction(self):
        self.datasets[f"{self.config.bastille_dataset}/jails/cloudnc"] = "other"
        with self.assertRaisesRegex(ValueError, "unowned jail dataset"):
            remove_instance(self.deployment, confirmation="REMOVE cloud")
        self.assertEqual(self.destructive_commands(), [])
        self.assert_other_untouched()

    def test_non_zfs_jail_remnants_are_retained_for_manual_review(self):
        del self.datasets[f"{self.config.bastille_dataset}/jails/cloudnc"]
        del self.datasets[f"{self.config.bastille_dataset}/jails/cloudnc/root"]
        with self.assertRaisesRegex(ValueError, "non-ZFS jail remnants"):
            remove_instance(self.deployment, confirmation="REMOVE cloud")
        self.assertEqual(self.destructive_commands(), [])
        self.assertTrue(Path(self.paths["cloudnc"]).is_dir())

    def test_nested_persistent_mount_prevents_any_jail_root_destruction(self):
        self.mounts = f"/source {self.paths['cloudnc']}/var/nc-data nullfs rw 0 0\n"
        with self.assertRaisesRegex(RuntimeError, "mounts remain"):
            remove_instance(self.deployment, confirmation="REMOVE cloud")
        self.assertEqual(self.destructive_commands(), [])
        self.assert_other_untouched()

    def test_foreign_filesystem_mount_prevents_root_destruction(self):
        self.mounts = f"tmpfs {self.paths['cloudnc']}/foreign tmpfs rw 0 0\n"
        with self.assertRaises(RuntimeError):
            remove_instance(self.deployment, confirmation="REMOVE cloud")
        self.assertEqual(self.destructive_commands(), [])

    def test_destroy_must_really_remove_jail_dataset_before_continuing(self):
        self.refuse_destroy = True
        with self.assertRaisesRegex(RuntimeError, "did not destroy"):
            remove_instance(self.deployment, confirmation="REMOVE cloud")
        self.assertEqual(self.destructive_commands(), [("bastille", "destroy", "-y", "cloudnc")])
        self.assertIn("bridge240", self.bridges)
        self.assertFalse((self.deployment.state / "removed.json").exists())

    def test_foreign_bridge_members_or_address_cannot_be_destroyed(self):
        for value in ("inet 10.77.0.1 netmask 0xfffffffc\nmember: foreign0\n", "inet 10.99.0.1 netmask 0xfffffffc\n"):
            with self.subTest(value=value):
                self.bridges["bridge240"] = value
                with self.assertRaisesRegex(ValueError, "Bridge identity"):
                    remove_instance(self.deployment, confirmation="REMOVE cloud")
                self.assertEqual(self.bridges["bridge240"], value)
                self.assertNotIn(call("ifconfig", "bridge240", "destroy"), self.runner.run.call_args_list)
                self.assert_other_untouched()

    def test_explicit_purge_accepts_owned_root_and_expected_descendants_only(self):
        remove_instance(self.deployment, purge_data=True, confirmation="PURGE cloud")
        self.assertIn(("zfs", "destroy", "-r", self.config.dataset_root), self.destructive_commands())
        self.assertFalse(any(name == self.config.dataset_root or name.startswith(self.config.dataset_root + "/")
                             for name in self.datasets))
        self.assertFalse(private_json(self.deployment.state / "removed.json")["data_retained"])
        self.assertEqual(private_json(self.deployment.state / "secrets.json"), self.secrets)
        self.assert_other_untouched()

    def test_purge_refuses_unexpected_descendant_without_recursive_destroy(self):
        foreign = self.config.dataset_root + "/foreign-data"
        self.datasets[foreign] = "cloud"
        with self.assertRaisesRegex(ValueError, "Unexpected descendants"):
            remove_instance(self.deployment, purge_data=True, confirmation="PURGE cloud")
        self.assertIn(foreign, self.datasets)
        self.assertFalse(any(args[:2] == ("zfs", "destroy") for args in self.destructive_commands()))
        self.assert_other_untouched()

    def test_purge_refuses_wrong_owner_on_expected_dataset(self):
        self.datasets[self.config.dataset_root + "/nc-data"] = "other"
        with self.assertRaisesRegex(ValueError, "Unowned dataset"):
            remove_instance(self.deployment, purge_data=True, confirmation="PURGE cloud")
        self.assertFalse(any(args[:2] == ("zfs", "destroy") for args in self.destructive_commands()))
        self.assertIn(self.config.dataset_root, self.datasets)
        self.assert_other_untouched()

    def test_completed_removal_is_not_replayed_and_can_be_followed_by_explicit_purge(self):
        remove_instance(self.deployment, confirmation="REMOVE cloud")
        self.runner.reset_mock()
        self.network.reset_mock()
        remove_instance(self.deployment, confirmation="REMOVE cloud")
        self.runner.run.assert_not_called()
        self.network.assert_not_called()
        remove_instance(self.deployment, purge_data=True, confirmation="PURGE cloud")
        self.assertEqual(self.destructive_commands(), [("zfs", "destroy", "-r", self.config.dataset_root)])
        self.assert_other_untouched()


class JailTeardownTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.enterContext(patch('installer.lifecycle.time.monotonic', side_effect=self.clock.monotonic))
        self.sleep = self.enterContext(patch('installer.lifecycle.time.sleep', side_effect=self.clock.sleep))
        self.runner = Mock()

    @staticmethod
    def inventory(*rows):
        # Captured native15.1 schema: jid/dying are strings, not int/bool.
        return SimpleNamespace(returncode=0, stderr='', stdout=json.dumps(
            {'__version': '2', 'jail-information': {'jail': list(rows)}}))

    @staticmethod
    def row(jid='11', name='cloudnc', path='/owned/root', dying='true'):
        return dict(jid=jid, name=name, path=path, dying=dying)

    def test_native_empty_live_and_dying_shapes(self):
        for rows, expected in (([], None), ([self.row(dying='false')], {'jid': 11, 'dying': False}),
                               ([self.row()], {'jid': 11, 'dying': True})):
            self.runner.run.return_value = self.inventory(*rows)
            self.assertEqual(_kernel_jail(self.runner, 'cloudnc', '/owned/root'), expected)
        self.runner.run.assert_called_with('jls', '--libxo', 'json', '-d', 'jid', 'name', 'path', 'dying', check=False, timeout=2)

    def test_malformed_ambiguous_or_changed_root_inventory_refuses(self):
        bad = ['', '{}', '{"jail-information":{}}', '{"__version":"2","__version":"2","jail-information":{"jail":[]}}',
               json.dumps({'__version': '2', 'jail-information': {'jail': {}}}),
               self.inventory(self.row(), self.row()).stdout,
               self.inventory(self.row(), self.row(name='other')).stdout,
               self.inventory(self.row(jid=11)).stdout,
               self.inventory(self.row(dying=True)).stdout,
               self.inventory(self.row(path='/changed')).stdout,
               self.inventory(self.row(jid='0')).stdout,
               self.inventory(self.row(dying='unknown')).stdout]
        for output in bad:
            with self.subTest(output=output):
                self.runner.run.return_value = SimpleNamespace(returncode=0, stdout=output, stderr='')
                with self.assertRaisesRegex(RuntimeError, 'Cannot verify kernel jail'):
                    _kernel_jail(self.runner, 'cloudnc', '/owned/root')

    def test_probe_error_diagnostic_or_timeout_never_means_absence(self):
        for result in (SimpleNamespace(returncode=1, stdout='', stderr='kernel error'),
                       SimpleNamespace(returncode=0, stdout=self.inventory().stdout, stderr='unexpected warning')):
            self.runner.run.return_value = result
            with self.assertRaisesRegex(RuntimeError, 'roots retained'):
                _kernel_jail(self.runner, 'cloudnc', '/owned/root')
        for error in (OSError('fixture failure'), subprocess.TimeoutExpired(['jls'], 2)):
            self.runner.run.side_effect = error
            with self.assertRaisesRegex(RuntimeError, 'roots retained'):
                _kernel_jail(self.runner, 'cloudnc', '/owned/root')

    def test_absence_does_not_sleep_or_announce(self):
        self.runner.run.return_value = self.inventory()
        with redirect_stdout(io.StringIO()) as output:
            _wait_for_jail_exit(self.runner, 'cloudnc', '/owned/root', 11)
        self.sleep.assert_not_called()
        self.assertEqual(output.getvalue(), '')

    def test_dying_then_absent_waits_once_and_announces_once(self):
        self.runner.run.side_effect = [self.inventory(self.row()), self.inventory(self.row()), self.inventory()]
        with redirect_stdout(io.StringIO()) as output:
            _wait_for_jail_exit(self.runner, 'cloudnc', '/owned/root', 11)
        self.assertEqual(self.clock.now, 0.5)
        self.assertEqual(output.getvalue().count('Waiting up to 10s for jail cloudnc'), 1)

    def test_live_changed_jid_or_unexpected_appearance_refuses_without_sleep(self):
        for row, expected in ((self.row(dying='false'), 11), (self.row(jid='12'), 11), (self.row(), None)):
            self.runner.run.return_value = self.inventory(row)
            with self.assertRaises(RuntimeError):
                _wait_for_jail_exit(self.runner, 'cloudnc', '/owned/root', expected)
        self.sleep.assert_not_called()

    def test_slow_probes_consume_deadline_and_timeout_budget(self):
        remaining = []
        def slow(*args, **kwargs):
            budget = 10 - self.clock.now
            self.assertGreater(kwargs['timeout'], 0)
            self.assertLessEqual(kwargs['timeout'], min(2, budget))
            remaining.append(kwargs['timeout'])
            self.clock.sleep(min(1.5, kwargs['timeout']))
            return self.inventory(self.row())
        self.runner.run.side_effect = slow
        with redirect_stdout(io.StringIO()), self.assertRaisesRegex(RuntimeError, 'timed out'):
            _wait_for_jail_exit(self.runner, 'cloudnc', '/owned/root', 11)
        self.assertEqual(self.clock.now, 10)
        self.assertLess(remaining[-1], 2)

    def test_late_absence_does_not_turn_expired_probe_into_success(self):
        def late(*args, **kwargs):
            self.clock.now = 10
            return self.inventory()
        self.runner.run.side_effect = late
        with self.assertRaisesRegex(RuntimeError, 'timed out'):
            _wait_for_jail_exit(self.runner, 'cloudnc', '/owned/root', 11)
        self.sleep.assert_not_called()

    def test_interruption_propagates(self):
        self.runner.run.return_value = self.inventory(self.row())
        self.sleep.side_effect = KeyboardInterrupt
        with redirect_stdout(io.StringIO()), self.assertRaises(KeyboardInterrupt):
            _wait_for_jail_exit(self.runner, 'cloudnc', '/owned/root', 11)


if __name__ == "__main__":
    unittest.main()
