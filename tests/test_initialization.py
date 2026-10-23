"""Fault-injected recovery; commands are fake, writes use private temporary directories."""

import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, PropertyMock, patch

from installer import initialization as init
from installer.config import Config
from installer.deploy import Deployment
from installer.state import Journal, Registry, atomic_json, atomic_write, config_digest, private_json


class FakeHost:
    """An ownership/mount/snapshot model, never a subprocess wrapper."""

    def __init__(self, deployment):
        self.d = deployment
        self.calls = []
        self.live = {deployment.config.nextcloud_jail: (11, False), deployment.config.onlyoffice_jail: (12, False), "othernc": (90, False)}
        self.roots = {name: str(deployment.jail_root(name)) for name in self.live if name != "othernc"}
        self.roots["othernc"] = "/srv/other-instance/root"
        points = [(item.name, item.mountpoint) for item in init._layout(deployment)]
        points += [(f"{deployment.config.bastille_dataset}/jails/{name}/root", self.roots[name])
                   for name in (deployment.config.nextcloud_jail, deployment.config.onlyoffice_jail)]
        self.properties = {name: {init.OWNER: deployment.config.instance, "type": "filesystem", "mounted": "yes", "mountpoint": point, "guid": str(index + 100)}
                           for index, (name, point) in enumerate(points)}
        self.snapshots = {}
        self.children = {}
        self.covering = {}
        self.ready = True
        self.snapshot_fault = None
        self.rollback_fault = None
        self.after_rollback = None
        self.stop_fault = False
        self.dying_reads = 0

    def output(self, *args):
        return self.run(*args).stdout.strip()

    def run(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        text, code = "", 0
        if args[:2] == ("jls", "-d"):
            text = "\n".join(f"{jid} {name} {self.roots[name]} {str(dying).lower()}" for name, (jid, dying) in self.live.items())
            if any(dying for _, dying in self.live.values()):
                self.dying_reads -= 1
                if self.dying_reads <= 0:
                    self.live = {name: value for name, value in self.live.items() if not value[1]}
        elif args[:2] == ("jls", "-j"):
            name = args[2]
            if name in self.live and not self.live[name][1]:
                text = f"{self.live[name][0]} {name} {self.roots[name]}\n"
            else:
                code = 1
        elif args[:2] == ("mount", "-p"):
            text = "\n".join(f"{name} {prop['mountpoint']} zfs rw 0 0" for name, prop in self.properties.items())
            if self.d.config.nextcloud_jail in self.live:
                text += "\n" + "\n".join(f"{item.mountpoint} {self.roots[self.d.config.nextcloud_jail]}{item.target} nullfs rw 0 0" for item in init._layout(self.d))
        elif args[0] == "realpath":
            text = args[1]
        elif args[0] == "df":
            name = next(name for name, prop in self.properties.items() if prop["mountpoint"] == args[-1])
            text = f"Filesystem 1024-blocks Used Available Capacity Mounted on\n{self.covering.get(name, name)} 100 0 100 0% {args[-1]}\n"
        elif args[:2] == ("zfs", "get"):
            key, name = args[-2:]
            text = (self.snapshots if "@" in name else self.properties)[name][key]
        elif args[:2] == ("zfs", "list"):
            if "snapshot" in args:
                text = "\n".join(" ".join([name, meta["guid"], meta["creation"], meta["createtxg"]]) for name, meta in self.snapshots.items())
            else:
                text = "\n".join([args[-1], *self.children.get(args[-1], [])])
        elif args[:2] == ("bastille", "stop"):
            if not self.stop_fault:
                if self.dying_reads and args[-1] == self.d.config.nextcloud_jail:
                    self.live[args[-1]] = (11, True)
                else:
                    self.live.pop(args[-1], None)
        elif args[:2] == ("bastille", "start"):
            self.live[args[-1]] = (11 if args[-1] == self.d.config.nextcloud_jail else 12, False)
        elif args[0].endswith("-storage-guard"):
            if not (self.d.state / "allow-start").exists():
                raise RuntimeError("Start is blocked during initialization recovery")
        elif args[0] == "jexec":
            assert args[-1] == "checkpoint-ready"
            assert json.loads(kwargs["input"]) == {"db_password": self.d.secrets["db_password"]}
            if not self.ready:
                raise RuntimeError("Checkpoint needs an empty application/database")
        elif args[:2] == ("zfs", "snapshot"):
            assert set(self.live) == {"othernc"}, "snapshot attempted before both owned jails stopped"
            record = private_json(self.d.state / "initialization.json")
            assert record["state"] == "prepared"
            names = [arg for arg in args if "@" in arg]
            assert names == record["names"]
            if self.snapshot_fault == "before":
                raise RuntimeError("snapshot interrupted before creation")
            for index, name in enumerate(names):
                self.snapshots[name] = {"guid": str(1000 + index), "creation": "1792012345", "createtxg": "300",
                                        init.OWNER: self.d.config.instance, init.TOKEN: record["token"], "clones": "-", "userrefs": "0"}
                if self.snapshot_fault == "partial":
                    raise RuntimeError("inconsistent fake atomic snapshot")
            if self.snapshot_fault == "after":
                raise RuntimeError("snapshot succeeded before journal update was interrupted")
        elif args[:2] == ("zfs", "rollback"):
            assert set(self.live) == {"othernc"}, "rollback attempted with an owned jail alive"
            assert not (self.d.state / "allow-start").exists()
            if args[-1] == self.rollback_fault:
                raise RuntimeError("private diagnostic " + self.d.secrets["db_password"])
            if "/nc-app@" in args[-1]:
                (Path(self.d.config.mount_root) / "nc-app/config/config.php").unlink(missing_ok=True)
            if self.after_rollback:
                self.after_rollback(args[-1])
        elif args[:2] == ("test", "!"):
            path = Path(args[-1])
            code = int(path.exists() if args[2] == "-e" else path.is_symlink())
        else:
            raise AssertionError((args, kwargs))
        if code and kwargs.get("check", True):
            raise RuntimeError("Fake command failed")
        return SimpleNamespace(stdout=text, stderr="", returncode=code)

    def commands(self, *prefix):
        return [args for args, _ in self.calls if args[:len(prefix)] == prefix]


class InitializationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="initialization-tests-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        for name, value in [("bastille_root", self.root / "bastille"), ("mount_root", self.root / "data")]:
            changed = patch.object(Config, name, new_callable=PropertyMock, return_value=str(value))
            changed.start()
            self.addCleanup(changed.stop)
        uid = patch("installer.operations.ROOT_UID", os.geteuid())
        uid.start()
        self.addCleanup(uid.stop)
        sleep = patch("installer.initialization.time.sleep")
        sleep.start()
        self.addCleanup(sleep.stop)
        self.config = Config(public_hostname="cloud.example.test", admin_email="admin@example.test",
                             acme_email="admin@example.test", external_interface="igb0", ingress_address="192.0.2.10",
                             dns_server="192.0.2.53", management_network="198.51.100.0/24").validate()
        self.registry = Registry(self.root / "registry")
        self.registry.initialize()
        self.secrets = {"db_password": "database-password-" + "x" * 32, "admin_password": "admin-test-" + "y" * 32, "jwt_secret": "z" * 64}
        self.registry.save_new(self.config, self.secrets)
        self.registry.set_status(self.config.instance, "installing")
        self.d = Deployment(self.config, self.secrets, None, registry=self.registry)
        self.host = FakeHost(self.d)
        self.d.runner = self.host
        self.d.verify_source = Mock()
        for name in (self.config.nextcloud_jail, self.config.onlyoffice_jail):
            self.d.jail_root(name).mkdir(parents=True)
        self.worker_state = self.d.jail_root(self.config.nextcloud_jail) / "var/db/cloud-installer"
        self.worker_state.mkdir(parents=True, mode=0o700)
        self.app_config = Path(self.config.mount_root) / "nc-app/config/config.php"
        self.app_config.parent.mkdir(parents=True)
        atomic_write(self.d.state / "allow-start", "owned start permission\n")
        for name in ("nextcloud-prepared", "nextcloud-database", "database-init.log"):
            atomic_write(self.worker_state / name, "retained\n")
        journal = Journal(self.d.state / "deployment.json", self.config)
        journal.data["steps"] = {"Nextcloud database": {"state": "complete", "attempt": 1},
                                 init.CHECKPOINT: {"state": "running", "attempt": 1}}
        journal.save()

    def capture(self):
        record = init.checkpoint_initialization(self.d)
        journal = Journal(self.d.state / "deployment.json", self.config)
        journal.data["steps"][init.CHECKPOINT]["state"] = "complete"
        journal.save()
        return record

    def failed_install(self, state="failed"):
        journal = Journal(self.d.state / "deployment.json", self.config)
        journal.data["steps"][init.INSTALL] = {"state": state, "attempt": 4, "started": "retained-start"}
        journal.save()
        self.registry.set_status(self.config.instance, "failed")
        atomic_write(self.worker_state / "nextcloud-installed", "")
        atomic_write(self.app_config, "partial application configuration")
        self.host.ready = False

    def recover(self):
        return init.recover_initialization(self.d, confirmation="RESET-INITIALIZATION " + self.config.instance)

    def test_atomic_capture_quiesces_both_owned_jails_and_streams_only_db_secret(self):
        record = self.capture()
        commands = [args for args, _ in self.host.calls]
        snapshot = self.host.commands("zfs", "snapshot")
        self.assertEqual(len(snapshot), 1)
        self.assertEqual(snapshot[0][-4:], tuple(record["names"]))
        self.assertEqual(len(record["snapshots"]), 4)
        self.assertEqual(record["config_sha256"], config_digest(self.config))
        self.assertEqual(record["state"], "complete")
        for name in (self.config.nextcloud_jail, self.config.onlyoffice_jail):
            self.assertLess(commands.index(("bastille", "stop", name)), commands.index(snapshot[0]))
        self.assertLess(commands.index(self.host.commands("jexec")[0]), commands.index(snapshot[0]))
        self.assertEqual(self.host.commands("bastille", "start"), [("bastille", "start", name) for name in (self.config.nextcloud_jail, self.config.onlyoffice_jail)])
        self.assertEqual(set(self.host.live), {"cloudnc", "cloudoo", "othernc"})
        path = self.d.state / "initialization.json"
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        for secret in self.secrets.values():
            self.assertNotIn(secret, path.read_text() + repr(commands))
        self.d.verify_source.assert_called_once()

    def test_complete_checkpoint_retry_does_not_recheck_partially_initialized_database(self):
        original = self.capture()
        self.failed_install()
        self.host.live.pop("cloudnc")
        calls = len(self.host.commands("jexec"))
        repeated = init.checkpoint_initialization(self.d)
        self.assertEqual(repeated["snapshots"], original["snapshots"])
        self.assertEqual(len(self.host.commands("jexec")), calls)
        self.assertEqual(len(self.host.commands("zfs", "snapshot")), 1)
        self.assertIn("cloudnc", self.host.live)

    def test_unjournaled_same_name_snapshots_cannot_be_adopted(self):
        self.capture()
        (self.d.state / "initialization.json").unlink()
        count = len(self.host.calls)
        with self.assertRaisesRegex(ValueError, "without a capture intent"):
            init.checkpoint_initialization(self.d)
        self.assertFalse(any(args[:2] in (("bastille", "stop"), ("zfs", "snapshot")) for args, _ in self.host.calls[count:]))

    def test_atomic_creation_interruption_is_adopted_only_from_matching_prepared_intent(self):
        self.host.snapshot_fault = "after"
        with self.assertRaises(RuntimeError):
            init.checkpoint_initialization(self.d)
        pending = private_json(self.d.state / "initialization.json")
        self.assertEqual(pending["state"], "prepared")
        self.assertEqual(set(self.host.live), {"othernc"})
        self.host.ready = False  # Adoption must use the authenticated intent, not a new DB check.
        self.host.snapshot_fault = None
        record = init.checkpoint_initialization(self.d)
        self.assertEqual(record["state"], "complete")
        self.assertEqual(len(self.host.commands("zfs", "snapshot")), 1)
        self.assertEqual(len(self.host.commands("jexec")), 1)

    def test_prepared_intent_without_snapshots_rechecks_empty_state_before_retry(self):
        self.host.snapshot_fault = "before"
        with self.assertRaises(RuntimeError):
            init.checkpoint_initialization(self.d)
        self.host.snapshot_fault = None
        self.assertEqual(init.checkpoint_initialization(self.d)["state"], "complete")
        self.assertEqual(len(self.host.commands("jexec")), 2)
        self.assertEqual(len(self.host.snapshots), 4)

    def test_partial_atomic_snapshot_set_is_refused_without_replacement(self):
        self.host.snapshot_fault = "partial"
        with self.assertRaises(RuntimeError):
            init.checkpoint_initialization(self.d)
        self.host.snapshot_fault = None
        with self.assertRaisesRegex(ValueError, "Incomplete atomic"):
            init.checkpoint_initialization(self.d)
        self.assertEqual(len(self.host.commands("zfs", "snapshot")), 1)
        self.assertEqual(set(self.host.live), {"othernc"})
        self.assertFalse(self.host.commands("zfs", "destroy"))

    def test_waits_for_dying_jail_and_refuses_a_jail_that_will_not_stop(self):
        self.host.dying_reads = 3
        self.capture()
        self.assertEqual(self.host.dying_reads, 0)
        self.assertEqual(len(self.host.commands("zfs", "snapshot")), 1)
        # A second fixture-free attempt uses a new intent only after removing the
        # fake snapshots and journal; no real data or system commands are involved.
        self.host.snapshots.clear()
        (self.d.state / "initialization.json").unlink()
        self.host.stop_fault = True
        with self.assertRaisesRegex(RuntimeError, "did not stop completely"):
            init.checkpoint_initialization(self.d)
        self.assertEqual(len(self.host.commands("zfs", "snapshot")), 1)

    def test_owner_covering_mount_and_descendants_are_checked_before_snapshot(self):
        name = self.config.dataset_root + "/nc-data"
        for kind in ("owner", "mount", "child"):
            with self.subTest(kind=kind):
                if kind == "owner":
                    self.host.properties[name][init.OWNER] = "other"
                elif kind == "mount":
                    self.host.covering[name] = "foreign/data"
                else:
                    self.host.children[name] = [name + "/unexpected"]
                with self.assertRaises(ValueError):
                    init.checkpoint_initialization(self.d)
                self.assertFalse(self.host.commands("zfs", "snapshot"))
                self.assertFalse(self.host.commands("bastille", "stop"))
                self.host.properties[name][init.OWNER] = self.config.instance
                self.host.covering.clear()
                self.host.children.clear()

    def test_confirmation_publication_attempt_and_ready_lifecycle_gates(self):
        self.capture()
        self.failed_install()
        before = len(self.host.calls)
        with self.assertRaisesRegex(ValueError, "typed confirmation"):
            init.recover_initialization(self.d, confirmation="RESET-INITIALIZATION other")
        self.assertEqual(len(self.host.calls), before)
        for phase_state in ("failed", "running", "complete"):
            journal = Journal(self.d.state / "deployment.json", self.config)
            journal.data["steps"][init.PUBLICATION] = {"state": phase_state}
            journal.save()
            with self.assertRaisesRegex(ValueError, "no publication attempt"):
                self.recover()
        journal.data["steps"].pop(init.PUBLICATION)
        journal.save()
        for status in ("ready", "removing", "removed"):
            self.registry.set_status(self.config.instance, status)
            with self.assertRaises(ValueError):
                self.recover()
        self.assertFalse(self.host.commands("zfs", "rollback"))

    def test_completed_install_and_worker_publication_markers_refuse_reset(self):
        self.capture()
        self.failed_install("complete")
        with self.assertRaisesRegex(ValueError, "incomplete installation"):
            self.recover()
        self.failed_install()
        atomic_write(self.worker_state / "nextcloud-published", "")
        with self.assertRaisesRegex(ValueError, "publication markers"):
            self.recover()
        self.assertFalse(self.host.commands("zfs", "rollback"))

    def test_snapshot_guid_creation_owner_and_capture_token_are_pinned(self):
        record = self.capture()
        self.failed_install()
        name = record["names"][0]
        for key in ("guid", "creation", init.OWNER, init.TOKEN):
            with self.subTest(key=key):
                previous = self.host.snapshots[name][key]
                self.host.snapshots[name][key] = "999" if key in ("guid", "creation") else "other"
                with self.assertRaisesRegex(ValueError, "identity changed"):
                    self.recover()
                with self.assertRaises(ValueError):
                    init.checkpoint_initialization(self.d)
                self.host.snapshots[name][key] = previous
        self.assertFalse(self.host.commands("zfs", "rollback"))

    def test_latest_snapshot_clones_and_holds_preflight_all_four_before_any_rollback(self):
        record = self.capture()
        self.failed_install()
        last = record["names"][-1]
        newer = last.split("@", 1)[0] + "@later"
        self.host.snapshots[newer] = dict(self.host.snapshots[last], guid="9999", createtxg="301")
        with self.assertRaisesRegex(ValueError, "latest"):
            self.recover()
        del self.host.snapshots[newer]
        for key, value in (("clones", "pool/clone"), ("userrefs", "1")):
            self.host.snapshots[last][key] = value
            with self.assertRaisesRegex(ValueError, "clones or holds"):
                self.recover()
            self.host.snapshots[last][key] = "-" if key == "clones" else "0"
        self.assertFalse(self.host.commands("zfs", "rollback"))

    def test_recovery_restores_exact_four_leaves_stopped_and_preserves_attempts_and_other_state(self):
        record = self.capture()
        self.failed_install("running")
        before = len(self.host.commands("bastille", "start"))
        self.assertEqual(self.recover(), "Resume")
        self.assertEqual(self.host.commands("zfs", "rollback"), [("zfs", "rollback", name) for name in record["names"]])
        self.assertEqual(len(self.host.commands("bastille", "start")), before)
        self.assertEqual(set(self.host.live), {"othernc"})
        self.assertFalse((self.worker_state / "nextcloud-installed").exists())
        self.assertFalse(self.app_config.exists())
        for name in ("nextcloud-prepared", "nextcloud-database", "database-init.log"):
            self.assertEqual((self.worker_state / name).read_text(), "retained\n")
        self.assertEqual(private_json(self.d.state / "secrets.json"), self.secrets)
        journal = private_json(self.d.state / "deployment.json")
        self.assertEqual(journal["steps"][init.INSTALL]["state"], "failed")
        self.assertEqual(journal["steps"][init.INSTALL]["attempt"], 4)
        self.assertEqual(journal["steps"][init.INSTALL]["started"], "retained-start")
        self.assertEqual(journal["steps"][init.CHECKPOINT]["state"], "complete")
        saved = private_json(self.d.state / "initialization.json")
        self.assertEqual(saved["snapshots"], record["snapshots"])
        self.assertEqual(saved["recoveries"][-1]["state"], "complete")
        self.assertEqual(private_json(self.d.state / "status.json")["next_action"], "resume")
        self.assertTrue((self.d.state / "allow-start").exists())

    def test_partial_rollback_stays_stopped_blocks_start_and_retry_reverifies_all_guids(self):
        record = self.capture()
        self.failed_install()
        self.host.rollback_fault = record["names"][1]
        with self.assertRaisesRegex(RuntimeError, "retry recover-install") as error:
            self.recover()
        self.assertNotIn(self.secrets["db_password"], str(error.exception))
        self.assertEqual(set(self.host.live), {"othernc"})
        self.assertFalse((self.d.state / "allow-start").exists())
        self.assertTrue((self.d.state / "allow-start.initialization-recovery").exists())
        saved = private_json(self.d.state / "initialization.json")
        self.assertEqual(saved["recoveries"][-1]["restored"], record["names"][:1])
        self.assertEqual(saved["recoveries"][-1]["state"], "failed")
        for secret in self.secrets.values():
            self.assertNotIn(secret, json.dumps(saved) + (self.d.state / "status.json").read_text())
        # Ordinary resume/checkpoint cannot restart a partially restored graph.
        with self.assertRaisesRegex(RuntimeError, "Start is blocked"):
            init.checkpoint_initialization(self.d)
        self.host.rollback_fault = None
        last = record["names"][-1]
        self.host.snapshots[last]["guid"] = "9999"
        with self.assertRaises(ValueError):
            self.recover()
        self.host.snapshots[last]["guid"] = record["snapshots"][last]["guid"]
        self.assertEqual(self.recover(), "Resume")
        self.assertEqual(self.host.commands("zfs", "rollback")[-4:], [("zfs", "rollback", name) for name in record["names"]])
        self.assertEqual(set(self.host.live), {"othernc"})
        self.assertTrue((self.d.state / "allow-start").exists())

    def test_new_snapshot_mid_recovery_is_detected_before_next_dataset_rollback(self):
        record = self.capture()
        self.failed_install()
        last = record["names"][-1]
        def concurrent_snapshot(_):
            self.host.snapshots[last.split("@", 1)[0] + "@later"] = dict(self.host.snapshots[last], guid="9000", createtxg="301")
        self.host.after_rollback = concurrent_snapshot
        with self.assertRaises(RuntimeError):
            self.recover()
        self.assertEqual(len(self.host.commands("zfs", "rollback")), 1)
        self.assertEqual(set(self.host.live), {"othernc"})
        self.assertFalse((self.d.state / "allow-start").exists())

    def test_configuration_source_and_dataset_replacement_are_refused(self):
        self.capture()
        self.failed_install()
        self.d.verify_source.side_effect = ValueError("source changed")
        with self.assertRaisesRegex(ValueError, "source changed"):
            self.recover()
        self.d.verify_source.side_effect = None
        name = self.config.dataset_root + "/nc-database"
        previous = self.host.properties[name]["guid"]
        self.host.properties[name]["guid"] = "99999"
        with self.assertRaisesRegex(ValueError, "dataset identity changed"):
            self.recover()
        self.host.properties[name]["guid"] = previous
        journal = private_json(self.d.state / "deployment.json")
        journal["config_sha256"] = "0" * 64
        atomic_json(self.d.state / "deployment.json", journal)
        with self.assertRaisesRegex(ValueError, "configuration.*changed"):
            self.recover()
        self.assertFalse(self.host.commands("zfs", "rollback"))

    def test_installed_marker_symlink_cannot_delete_a_foreign_file(self):
        self.capture()
        self.failed_install()
        marker = self.worker_state / "nextcloud-installed"
        marker.unlink()
        foreign = self.root / "foreign-marker"
        atomic_write(foreign, "retain")
        marker.symlink_to(foreign)
        with self.assertRaisesRegex(ValueError, "control marker"):
            self.recover()
        self.assertEqual(foreign.read_text(), "retain")
        self.assertFalse(self.host.commands("zfs", "rollback"))


if __name__ == "__main__":
    unittest.main()
