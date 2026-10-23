"""Atomic registry/journal recovery and real process-lock exclusion, offline."""

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from installer.config import Config, SCHEMA_VERSION
from installer.state import (Journal, Registry, atomic_json, atomic_write, config_digest,
                             private_directory, private_json)
from installer.versions import FIELDS, defaults
from version_fixtures import LEGACY_CONFIG_JSON, LEGACY_CONFIG_SHA256


def configuration(**changes):
    return replace(Config(public_hostname="cloud.example.test", admin_email="admin@example.test",
                          acme_email="admin@example.test", external_interface="igb0",
                          ingress_address="192.0.2.10", dns_server="192.0.2.53",
                          management_network="198.51.100.0/24"), **changes)


class StateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="state-tests-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.registry = Registry(self.directory / "registry")
        self.registry.initialize()
        self.config = configuration()
        self.secrets = {"admin_password": "private-admin-password", "db_password": "a" * 64, "jwt_secret": "b" * 64}

    def test_atomic_replacement_is_private_and_synced_before_directory(self):
        path = self.directory / "state.json"
        atomic_json(path, {"generation": 1})
        old_inode = path.stat().st_ino
        events = []
        fsync, replace_file = os.fsync, os.replace
        def sync(fd):
            events.append("directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
            fsync(fd)
        def publish(source, target):
            self.assertEqual(private_json(path), {"generation": 1})
            self.assertEqual(Path(source).parent, path.parent)
            self.assertEqual(Path(source).stat().st_mode & 0o777, 0o600)
            events.append("replace")
            replace_file(source, target)
        with patch("installer.state.os.fsync", side_effect=sync), patch("installer.state.os.replace", side_effect=publish):
            atomic_json(path, {"generation": 2})
        self.assertEqual(events, ["file", "replace", "directory"])
        self.assertEqual(private_json(path), {"generation": 2})
        self.assertNotEqual(path.stat().st_ino, old_inode)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(self.directory.glob(".pending-*")), [])

    def test_failed_write_preserves_last_good_document_and_cleans_only_candidate(self):
        path = self.directory / "state.json"
        atomic_json(path, {"last": "good"})
        sentinel = self.directory / "unrelated"
        sentinel.write_text("preserve")
        for function in ("os.replace", "os.fsync"):
            with self.subTest(function=function), patch("installer.state." + function, side_effect=OSError("disk error")):
                with self.assertRaises(OSError):
                    atomic_json(path, {"new": "uncommitted"})
            self.assertEqual(private_json(path), {"last": "good"})
            self.assertEqual(list(self.directory.glob(".pending-*")), [])
            self.assertEqual(sentinel.read_text(), "preserve")

    def test_atomic_write_never_follows_a_state_symlink(self):
        original = self.directory / "original"
        original.write_text("keep")
        for target in (original, self.directory / "missing"):
            link = self.directory / "link"
            link.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "symlink"):
                atomic_write(link, "overwrite")
            self.assertTrue(link.is_symlink())
            link.unlink()
        self.assertEqual(original.read_text(), "keep")
        self.assertFalse((self.directory / "missing").exists())

    def test_private_read_rejects_symlink_shared_permissions_and_wrong_owner(self):
        path = self.directory / "private.json"
        atomic_json(path, {"private": True})
        link = self.directory / "link.json"
        link.symlink_to(path)
        with self.assertRaises(ValueError):
            private_json(link)
        for mode in (0o640, 0o604, 0o660, 0o666):
            path.chmod(mode)
            with self.subTest(mode=oct(mode)), self.assertRaises(ValueError):
                private_json(path)
        path.chmod(0o600)
        with patch("installer.state.os.geteuid", return_value=os.geteuid() + 1), self.assertRaises(ValueError):
            private_json(path)
        path.chmod(0o400)
        self.assertEqual(private_json(path), {"private": True})

    def test_registry_initialization_validates_existing_directories_without_adoption(self):
        for path in (self.registry.root, *(self.registry.root / name for name in
                                         ("instances", "transactions", "network", "backups", "removed"))):
            self.assertEqual(path.stat().st_mode & 0o777, 0o700)
        directory = self.directory / "unsafe"
        directory.mkdir(mode=0o755)
        # mkdir's requested mode is filtered by the caller's umask.
        directory.chmod(0o755)
        with self.assertRaises(ValueError):
            private_directory(directory)
        link = self.directory / "linked"
        link.symlink_to(self.registry.root)
        with self.assertRaises(ValueError):
            Registry(link).initialize()
        with patch("installer.state.os.geteuid", return_value=os.geteuid() + 1), self.assertRaises(ValueError):
            private_directory(self.registry.root)

    def test_empty_registry_reads_do_not_create_state(self):
        registry = Registry(self.directory / "absent")
        self.assertEqual(registry.entries(), [])
        self.assertEqual(registry.configs(), [])
        self.assertEqual(registry.network_configs(), [])
        self.assertIsNone(registry.host())
        self.assertFalse(registry.root.exists())

    def test_registration_round_trip_has_host_only_private_credentials(self):
        path = self.registry.save_new(self.config, self.secrets)
        self.assertEqual(path, self.registry.root / "instances/cloud")
        self.assertEqual(self.registry.load("cloud"), self.config)
        self.assertEqual(private_json(path / "secrets.json"), self.secrets)
        self.assertEqual(private_json(path / "status.json")["state"], "configured")
        self.assertEqual(path.stat().st_mode & 0o777, 0o700)
        for name in ("config.json", "status.json", "secrets.json"):
            self.assertEqual((path / name).stat().st_mode & 0o777, 0o600)
        for secret in self.secrets.values():
            self.assertNotIn(secret, (path / "config.json").read_text() + (path / "status.json").read_text())

    def test_legacy_configuration_keeps_original_bytes_and_digest_with_blank_version_fields(self):
        self.assertEqual(hashlib.sha256(LEGACY_CONFIG_JSON.encode()).hexdigest(), LEGACY_CONFIG_SHA256)
        restored = Config.from_json(LEGACY_CONFIG_JSON)
        self.assertEqual(restored, self.config)
        self.assertTrue(all(getattr(restored, field) == "" for field in FIELDS))
        self.assertEqual(restored.to_json(), LEGACY_CONFIG_JSON)
        self.assertEqual(config_digest(restored), LEGACY_CONFIG_SHA256)
        saved = json.loads(restored.to_json())
        self.assertTrue(set(FIELDS).isdisjoint(saved))
        self.assertIn("nextcloud_hostname", saved)
        self.assertEqual(saved["nextcloud_hostname"], "")

    def test_legacy_registry_and_removal_journals_load_without_rewriting_or_version_adoption(self):
        path = private_directory(self.registry.instance_path("cloud"))
        atomic_write(path / "config.json", LEGACY_CONFIG_JSON)
        atomic_json(path / "status.json", {"state": "removed"})
        atomic_write(path / "source.sha256", "a" * 64 + "\n")
        for filename in ("deployment.json", "removal.json", "purge.json"):
            atomic_json(path / filename, {"schema_version": 2, "config_sha256": LEGACY_CONFIG_SHA256,
                                         "steps": {"historical phase": {"state": "complete"}}})
        before = {file.name: file.read_bytes() for file in path.iterdir()}
        restored = self.registry.load("cloud")
        self.assertEqual(self.registry.entries(include_removed=True), [(restored, {"state": "removed"})])
        for filename in ("deployment.json", "removal.json", "purge.json"):
            journal = Journal(path / filename, restored)
            self.assertEqual(journal.data["config_sha256"], LEGACY_CONFIG_SHA256)
        self.assertEqual({file.name: file.read_bytes() for file in path.iterdir()}, before)
        self.assertFalse((path / "versions.json").exists())

    def test_explicit_version_constraints_are_serialized_and_bound_to_journals(self):
        selected = replace(self.config, **{**defaults(), "nextcloud_exact": "35.0.0"})
        self.assertEqual(Config.from_json(selected.to_json()), selected)
        self.assertNotEqual(config_digest(selected), LEGACY_CONFIG_SHA256)
        path = self.directory / "locked-deployment.json"
        Journal(path, selected).save()
        for changes in ({"nextcloud_exact": "35.0.1"}, {"onlyoffice_exact": "9.4.0_4"},
                        {"nextcloud_min": "35.0.1"}, {"freebsd_release": ""}):
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, "Resume refused"):
                Journal(path, replace(selected, **changes))

    def test_registered_and_removed_names_remain_reserved_without_overwrite(self):
        path = self.registry.save_new(self.config, self.secrets)
        before = (path / "secrets.json").read_bytes()
        for state in ("configured", "failed", "ready", "removed"):
            with self.subTest(state=state):
                self.registry.set_status("cloud", state)
                with self.assertRaisesRegex(ValueError, "already registered"):
                    self.registry.save_new(self.config, {**self.secrets, "admin_password": "replacement-secret"})
                self.assertEqual((path / "secrets.json").read_bytes(), before)
        self.assertEqual(self.registry.entries(), [])
        self.assertEqual([config.instance for config, _ in self.registry.entries(include_removed=True)], ["cloud"])

    def test_instance_identifiers_and_registry_identity_are_strict(self):
        for name in ("../escape", "/absolute", "cloud/other", "Cloud", "cloud-name", "abcdefghi", ""):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.registry.instance_path(name)
        with self.assertRaisesRegex(ValueError, "Unknown instance"):
            self.registry.load("missing")
        path = self.registry.save_new(self.config, self.secrets)
        atomic_json(path / "config.json", json.loads(configuration(instance="other").to_json()))
        with self.assertRaisesRegex(ValueError, "identity"):
            self.registry.load("cloud")

    def test_symlinked_instance_cannot_adopt_another_instance(self):
        path = self.registry.save_new(self.config, self.secrets)
        self.registry.instance_path("alias").symlink_to(path)
        with self.assertRaisesRegex(ValueError, "Unknown instance"):
            self.registry.load("alias")

    def test_failed_registration_cannot_break_listing_other_instances(self):
        self.registry.save_new(self.config, self.secrets)
        original = (self.registry.instance_path("cloud") / "config.json").read_bytes()
        for index, filename in enumerate(("config.json", "secrets.json", "status.json")):
            config = configuration(instance="new" + str(index))
            def write(path, value):
                if Path(path).name == filename:
                    raise OSError("simulated full filesystem")
                atomic_json(path, value)
            with self.subTest(filename=filename), patch("installer.state.atomic_json", side_effect=write):
                with self.assertRaises(OSError):
                    self.registry.save_new(config, self.secrets)
            self.assertEqual([item.instance for item, _ in self.registry.entries()], ["cloud"])
            self.assertEqual((self.registry.instance_path("cloud") / "config.json").read_bytes(), original)

    def test_status_rejects_unknown_states_without_overwriting_last_good_status(self):
        path = self.registry.save_new(self.config, self.secrets)
        before = (path / "status.json").read_bytes()
        with self.assertRaisesRegex(ValueError, "Unknown registry state"):
            self.registry.set_status("cloud", "almost-ready")
        self.assertEqual((path / "status.json").read_bytes(), before)

    def test_host_settings_are_shared_and_immutable_but_instance_fields_are_not(self):
        self.registry.save_host(self.config)
        host = self.registry.host()
        self.assertEqual(host["schema_version"], SCHEMA_VERSION)
        self.assertNotIn("public_hostname", host)
        self.registry.save_host(configuration(instance="second", public_hostname="second.example.test"))
        for field, value in (("pool", "otherpool"), ("external_interface", "igb1"), ("management_port", 2222),
                             ("management_network", "203.0.113.0/24"), ("host_reserved_mb", 4096)):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "conflicts"):
                self.registry.save_host(replace(self.config, **{field: value}))
            self.assertEqual(self.registry.host(), host)

    def test_network_membership_uses_active_manifest_not_deployment_status(self):
        for name, status in (("ready", "ready"), ("before", "failed"), ("after", "failed"), ("draft", "configured")):
            self.registry.save_new(configuration(instance=name), self.secrets)
            self.registry.set_status(name, status)
        self.assertEqual(self.registry.network_configs(), [])
        transaction = self.registry.root / "transactions/committed"
        transaction.mkdir(mode=0o700)
        atomic_json(transaction / "firewall-transition.json", {"instances": ["ready", "after"]})
        atomic_write(transaction / "firewall-confirmed", "confirmed\n")
        (self.registry.root / "network/active").symlink_to(transaction)
        self.assertEqual([config.instance for config in self.registry.network_configs()], ["ready", "after"])
        self.assertEqual([config.instance for config in self.registry.network_configs(exclude="ready")], ["after"])

    def test_lock_excludes_a_second_process_and_releases_after_failure(self):
        child = '''
import sys
from installer.state import Registry
try:
    with Registry(sys.argv[1]).locked():
        print("acquired")
except RuntimeError:
    print("busy")
'''
        def probe():
            return subprocess.run([sys.executable, "-B", "-c", child, str(self.registry.root)], text=True,
                                  capture_output=True, timeout=5, cwd=Path(__file__).resolve().parents[1])
        with self.assertRaisesRegex(RuntimeError, "operation failed"):
            with self.registry.locked():
                result = probe()
                self.assertEqual((result.returncode, result.stdout.strip()), (0, "busy"), result.stderr)
                with self.assertRaisesRegex(RuntimeError, "Another installer"):
                    with Registry(self.registry.root).locked():
                        self.fail("second lock acquired")
                raise RuntimeError("operation failed")
        result = probe()
        self.assertEqual((result.returncode, result.stdout.strip()), (0, "acquired"), result.stderr)
        self.assertEqual((self.registry.root / "operation.lock").stat().st_mode & 0o777, 0o600)

    def test_operation_lock_cannot_follow_a_symlink(self):
        outside = self.directory / "outside"
        outside.write_text("preserve")
        (self.registry.root / "operation.lock").symlink_to(outside)
        with self.assertRaises(OSError):
            with self.registry.locked():
                self.fail("symlinked lock accepted")
        self.assertEqual(outside.read_text(), "preserve")


class JournalTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="journal-tests-")
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "deployment.json"
        self.config = configuration()
        self.progress = Mock()

    def test_running_record_is_durable_before_action_and_completion_after(self):
        journal = Journal(self.path, self.config, self.progress)
        self.assertFalse(self.path.exists())
        observed = []
        journal.run([("storage", lambda: observed.append(private_json(self.path)["steps"]["storage"]["state"]))])
        self.assertEqual(observed, ["running"])
        saved = private_json(self.path)
        self.assertEqual(saved["config_sha256"], config_digest(self.config))
        self.assertEqual(saved["steps"]["storage"]["state"], "complete")
        self.assertEqual(saved["steps"]["storage"]["attempt"], 1)
        self.progress.assert_called_once_with(1, 1, "storage")

    def test_failure_records_only_error_type_and_resume_retries_failed_phase(self):
        first, last = Mock(), Mock()
        second = Mock(side_effect=RuntimeError("private credential: do-not-persist"))
        journal = Journal(self.path, self.config, self.progress)
        with self.assertRaises(RuntimeError):
            journal.run([("first", first), ("second", second), ("last", last)])
        first.assert_called_once_with()
        last.assert_not_called()
        saved = private_json(self.path)
        self.assertEqual(saved["steps"]["first"]["state"], "complete")
        self.assertEqual(saved["steps"]["second"]["state"], "failed")
        self.assertEqual(saved["steps"]["second"]["error_type"], "RuntimeError")
        self.assertNotIn("do-not-persist", self.path.read_text())
        second.side_effect = None
        resumed = Journal(self.path, self.config, self.progress)
        resumed.run([("first", first), ("second", second), ("last", last)])
        first.assert_called_once_with()
        self.assertEqual(second.call_count, 2)
        last.assert_called_once_with()
        self.assertEqual(private_json(self.path)["steps"]["second"]["attempt"], 2)

    def test_interrupt_is_a_failed_checkpoint_and_cannot_mark_later_steps_complete(self):
        journal = Journal(self.path, self.config, self.progress)
        later = Mock()
        with self.assertRaises(KeyboardInterrupt):
            journal.run([("interrupted", Mock(side_effect=KeyboardInterrupt)), ("later", later)])
        self.assertEqual(private_json(self.path)["steps"]["interrupted"]["error_type"], "KeyboardInterrupt")
        self.assertEqual(private_json(self.path)["steps"]["interrupted"]["state"], "failed")
        later.assert_not_called()

    def test_running_checkpoint_after_crash_is_retried_instead_of_skipped(self):
        journal = Journal(self.path, self.config, self.progress)
        journal.data["steps"]["in-flight"] = {"state": "running", "attempt": 4}
        journal.save()
        action = Mock()
        Journal(self.path, self.config, self.progress).run([("in-flight", action)])
        action.assert_called_once_with()
        record = private_json(self.path)["steps"]["in-flight"]
        self.assertEqual((record["state"], record["attempt"]), ("complete", 5))

    def test_resume_runs_only_designated_checks_on_completed_steps(self):
        first, second, check, not_completed = Mock(), Mock(), Mock(), Mock()
        steps = [("first", first), ("second", second)]
        journal = Journal(self.path, self.config, self.progress)
        journal.run(steps, checks={"first": check, "second": not_completed})
        check.assert_not_called()
        not_completed.assert_not_called()
        Journal(self.path, self.config, self.progress).run(steps, checks={"first": check})
        first.assert_called_once_with()
        second.assert_called_once_with()
        check.assert_called_once_with()
        self.assertTrue(any("skipped" in item.args[2] for item in self.progress.call_args_list))

    def test_failed_skip_check_prevents_any_following_action(self):
        journal = Journal(self.path, self.config, self.progress)
        action, later = Mock(), Mock()
        journal.run([("mounts", action)])
        before = self.path.read_bytes()
        with self.assertRaisesRegex(ValueError, "ownership changed"):
            Journal(self.path, self.config, self.progress).run([("mounts", action), ("provision", later)],
                checks={"mounts": Mock(side_effect=ValueError("ownership changed"))})
        action.assert_called_once_with()
        later.assert_not_called()
        self.assertEqual(self.path.read_bytes(), before)

    def test_config_or_schema_changes_are_refused_before_replay(self):
        journal = Journal(self.path, self.config, self.progress)
        journal.save()
        before = self.path.read_bytes()
        for config in (configuration(instance="other"), configuration(php_budget_mb=2048),
                       configuration(public_hostname="other.example.test")):
            with self.subTest(config=config), self.assertRaisesRegex(ValueError, "Resume refused"):
                Journal(self.path, config, self.progress)
            self.assertEqual(self.path.read_bytes(), before)
        document = private_json(self.path)
        document["schema_version"] = SCHEMA_VERSION - 1
        atomic_json(self.path, document)
        with self.assertRaisesRegex(ValueError, "Resume refused"):
            Journal(self.path, self.config, self.progress)


if __name__ == "__main__":
    unittest.main()
