"""NC-only initialization and removal ordering using existing fake-host fixtures."""

import os
from pathlib import Path
import unittest
from unittest.mock import Mock, PropertyMock, patch

from installer import initialization as init, lifecycle
from installer.config import Config
from installer.state import Journal, atomic_json, atomic_write, private_json
import test_initialization as initialization_fixtures
import test_lifecycle as removal_fixtures
import test_none_deployment as deployment_fixtures


class NoneInitializationTests(unittest.TestCase):
    capture = initialization_fixtures.InitializationTests.capture
    failed_install = initialization_fixtures.InitializationTests.failed_install
    recover = initialization_fixtures.InitializationTests.recover

    def setUp(self):
        deployment_fixtures.NoneDeploymentTests.setUp(self)
        self.d = self.deployment
        self.enterContext(patch.object(Config, "mount_root", new_callable=PropertyMock,
                                       return_value=str(self.directory / "data")))
        self.enterContext(patch("installer.initialization.time.sleep"))
        self.enterContext(patch("installer.operations.ROOT_UID", os.geteuid()))
        # FakeHost's legacy constructor seeds both native jails. Permit that only
        # while constructing the model, then remove the unselected office rows.
        root = Path(self.config.bastille_root) / "jails"
        with patch.object(self.d, "jail_root", side_effect=lambda name: root / name / "root"):
            self.host = initialization_fixtures.FakeHost(self.d)
        office = self.config.onlyoffice_jail
        del self.host.live[office]
        del self.host.roots[office]
        self.host.properties.pop(f"{self.config.bastille_dataset}/jails/{office}/root")
        self.d.runner = self.host
        self.d.verify_source = Mock()
        self.worker_state = self.d.jail_root(self.config.nextcloud_jail) / "var/db/cloud-installer"
        self.worker_state.mkdir(parents=True, mode=0o700)
        self.app_config = Path(self.config.mount_root) / "nc-app/config/config.php"
        self.app_config.parent.mkdir(parents=True)
        atomic_write(self.d.state / "allow-start", "owned start permission\n")
        for name in ("nextcloud-prepared", "nextcloud-database", "database-init.log"):
            atomic_write(self.worker_state / name, "retained\n")
        self.registry.set_status(self.config.instance, "installing")
        journal = Journal(self.d.state / "deployment.json", self.config)
        journal.data["steps"] = {"Nextcloud database": {"state": "complete", "attempt": 1},
                                 init.CHECKPOINT: {"state": "running", "attempt": 1}}
        journal.save()

    def test_checkpoint_and_recover_order_only_selected_jail_and_four_nc_datasets(self):
        record = self.capture()
        snapshot = self.host.commands("zfs", "snapshot")[0]
        commands = [args for args, _ in self.host.calls]
        stop = ("bastille", "stop", self.config.nextcloud_jail)
        self.assertLess(commands.index(stop), commands.index(snapshot))
        self.assertLess(commands.index(self.host.commands("jexec")[0]), commands.index(stop))
        self.assertEqual({name.split("@", 1)[0] for name in record["names"]},
                         {self.config.dataset_root + "/" + name for name in
                          ("nc-app", "nc-data", "nc-database", "nc-db-logs")})
        self.assertEqual(self.host.commands("bastille", "start"),
                         [("bastille", "start", self.config.nextcloud_jail)])
        self.failed_install("running")
        boundary = len(self.host.calls)
        self.assertEqual(self.recover(), "Resume")
        recovery = [args for args, _ in self.host.calls[boundary:]]
        rollbacks = self.host.commands("zfs", "rollback")
        self.assertEqual(rollbacks, [("zfs", "rollback", name) for name in record["names"]])
        self.assertLess(recovery.index(stop), recovery.index(rollbacks[0]))
        self.assertFalse(any(args[:2] == ("bastille", "start") for args in recovery))
        self.assertEqual(set(self.host.live), {"othernc"})
        self.assertTrue((self.d.state / "allow-start").exists())
        self.assertEqual(private_json(self.d.state / "status.json")["next_action"], "resume")
        self.assertNotIn(self.config.onlyoffice_jail, repr(self.host.calls))
        self.assertFalse(self.host.commands("zfs", "destroy"))

    def test_failed_rollback_keeps_nc_stopped_and_start_fenced(self):
        record = self.capture()
        self.failed_install()
        self.host.rollback_fault = record["names"][1]
        with self.assertRaisesRegex(RuntimeError, "retry recover-install"):
            self.recover()
        self.assertEqual(set(self.host.live), {"othernc"})
        self.assertFalse((self.d.state / "allow-start").exists())
        self.assertTrue((self.d.state / "allow-start.initialization-recovery").exists())
        self.assertEqual(self.host.commands("zfs", "rollback"),
                         [("zfs", "rollback", name) for name in record["names"][:2]])


class NoneCheckedJailsTests(unittest.TestCase):
    # Reuse the removal model's actual ZFS/mount/inventory and dangerous prefix
    # completion behavior rather than replacing _checked_jails with a mock.
    run_command = removal_fixtures.LifecycleTests.run_command
    output_command = removal_fixtures.LifecycleTests.output_command
    named_inventory = removal_fixtures.LifecycleTests.named_inventory
    resolve_target = removal_fixtures.LifecycleTests.resolve_target

    def setUp(self):
        deployment_fixtures.NoneDeploymentTests.setUp(self)
        self.datasets, self.paths, self.jail_points = {}, {}, {}
        self.mount_rows, self.filesystems, self.properties = {}, {}, {}
        self.config_paths, self.runtime_mounts = {}, {}
        self.running, self.dying = set(), set()
        self.inventory, self.mounts = None, ""
        self.bastille_targets = []
        name = self.config.nextcloud_jail
        root = self.deployment.jail_root(name)
        root.mkdir(parents=True)
        (root.parent / "jail.conf").write_text(f"{name} {{ path = {root}; }}\n")
        self.paths[name] = str(root)
        parent = f"{self.config.bastille_dataset}/jails/{name}"
        for dataset, point in ((parent, root.parent), (parent + "/root", root)):
            self.datasets[dataset] = self.config.instance
            self.jail_points[dataset] = str(point)
            self.mount_rows[str(point)] = (dataset, "zfs")
            self.filesystems[str(point)] = dataset
        atomic_json(self.deployment.state / (name + ".creating.json"),
                    {"name": name, "root": str(root), "release": self.config.release})
        self.runner.run.side_effect = self.run_command
        self.runner.output.side_effect = self.output_command

    def test_stopped_none_jail_is_checked_by_exact_inventory_and_owned_mounts(self):
        name = self.config.nextcloud_jail
        self.assertEqual(lifecycle._checked_jails(self.deployment, stopped=True),
                         [(name, f"{self.config.bastille_dataset}/jails/{name}")])
        self.runner.output.assert_any_call("bastille", "config", name, "get", "path")
        self.assertNotIn(self.config.onlyoffice_jail, repr(self.runner.mock_calls))
        self.assertEqual(self.bastille_targets, [])

    def test_missing_exact_stopped_identity_cannot_prefix_complete_to_foreign_jail(self):
        name = self.config.nextcloud_jail
        foreign = name + "x"
        root = Path(self.config.bastille_root) / "jails" / foreign / "root"
        root.mkdir(parents=True)
        (root.parent / "jail.conf").write_text(f"{foreign} {{ path = {root}; }}\n")
        self.paths[foreign] = str(root)
        exact_conf = self.deployment.jail_root(name).parent / "jail.conf"
        exact_conf.unlink()
        self.assertEqual(self.resolve_target(name), foreign)
        with self.assertRaisesRegex(ValueError, "Missing owned jail.conf"):
            lifecycle._checked_jails(self.deployment, stopped=True)
        exact_conf.write_text(f"{name} {{ path = {self.paths[name]}; }}\n")
        self.inventory = [{"Name": foreign, "Path": str(root)}]
        with self.assertRaisesRegex(ValueError, "Exact Bastille jail identity"):
            lifecycle._checked_jails(self.deployment, stopped=True)
        self.assertEqual(self.bastille_targets, [])
        self.assertFalse(any(call.args[:2] == ("bastille", "config")
                             for call in self.runner.output.call_args_list))
        self.assertTrue(root.is_dir())
