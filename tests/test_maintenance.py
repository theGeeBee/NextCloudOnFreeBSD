"""M2 command/boot dispatch is offline; native execution is always mocked."""

from contextlib import ExitStack, nullcontext
from pathlib import Path
import hashlib
import json
import tempfile
import unittest
from unittest.mock import Mock, patch

from installer.maintenance import boot_check, entry_guard, executor_identity, register, recover, status
from installer.state import Registry, atomic_json, atomic_write, config_digest
from installer.generations import Store
from test_state import configuration
from version_fixtures import resolved_plan


class MaintenanceDispatchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="maintenance-")
        self.addCleanup(temporary.cleanup)
        self.registry = Registry(Path(temporary.name) / "absent")

    def test_legacy_entry_guard_is_read_only_and_does_not_initialize(self):
        for command in ("menu", "install", "configure", "resume", "verify", "remove", "mutation"):
            entry_guard(command, registry=self.registry)
        self.assertFalse(self.registry.root.exists())

    def test_read_only_status_does_not_initialize_missing_registry(self):
        self.assertEqual(status(self.registry)["lifecycle"], "legacy")
        self.assertFalse(self.registry.root.exists())

    def test_executor_covers_shell_without_changing_historical_digest(self):
        from installer.paths import PROJECT_ROOT
        original = Path.read_bytes
        def changed(path):
            value = original(path)
            return value + b"\n# entrypoint change\n" if path == PROJECT_ROOT / "install.sh" else value
        with patch("installer.deploy.source_digest", return_value="a" * 64 + "\n"):
            before = executor_identity()
            with patch.object(Path, "read_bytes", changed):
                self.assertNotEqual(executor_identity(), before)

    def test_boot_refuses_changed_executor_before_registry_lookup(self):
        with patch("installer.maintenance.Registry") as registry:
            with self.assertRaisesRegex(ValueError, "executor changed"):
                boot_check(self.registry.root, "cloud", "cloudnc", "0" * 64)
            registry.return_value.load.assert_not_called()

    def test_boot_checks_exact_jail_and_removed_state(self):
        registry = Mock()
        registry.lifecycle_enabled.return_value = False
        registry.load.return_value = Mock(nextcloud_jail="cloudnc", onlyoffice_jail="cloudoo")
        with ExitStack() as stack:
            stack.enter_context(patch("installer.maintenance.Registry", return_value=registry))
            stack.enter_context(patch("installer.maintenance.entry_guard"))
            stack.enter_context(patch("installer.maintenance.executor_identity", return_value="a" * 64))
            with self.assertRaisesRegex(ValueError, "Unregistered jail"):
                boot_check(self.registry.root, "cloud", "unrelated", "a" * 64)
            for state in ("configured", "removing", "removed"):
                registry.status.return_value = {"state": state}
                with self.subTest(state=state), self.assertRaisesRegex(ValueError, "forbids"):
                    boot_check(self.registry.root, "cloud", "cloudnc", "a" * 64)
            registry.status.return_value = {"state": "ready"}
            boot_check(self.registry.root, "cloud", "cloudnc", "a" * 64)


class EnrollmentTransitionTests(unittest.TestCase):
    def setUp(self):
        from version_fixtures import historical_maintenance_policy
        self.enterContext(historical_maintenance_policy())
        temporary = tempfile.TemporaryDirectory(prefix="enrollment-flow-")
        self.addCleanup(temporary.cleanup)
        self.registry = Registry(Path(temporary.name) / "registry")
        self.registry.initialize()
        self.config = configuration(accept_microsoft_fonts=True)
        self.path = self.registry.save_new(self.config, {"admin_password": "original-private-admin",
                                                        "db_password": "a" * 64, "jwt_secret": "b" * 64})
        self.registry.write_source("cloud", "a" * 64 + "\n")
        self.registry.set_status("cloud", "ready")
        atomic_json(self.path / "versions.json", resolved_plan(self.config))
        atomic_json(self.path / "deployment.json", {"schema_version": 2,
                    "config_sha256": config_digest(self.config), "steps": {"readiness checks": {"state": "complete"}}})
        atomic_json(self.path / "inventory.json", {})
        atomic_write(self.path / "inputs.sha256", "c" * 64 + "\n")
        atomic_write(self.path / "complete", "historical readiness\n")
        atomic_write(self.path / "allow-start", "authorized\n")
        self.original = {p.name: p.read_bytes() for p in self.path.iterdir()}
        self.evidence = {"schema": 1, "adapter": "current-schema2-ready-v1", "instance": "cloud",
                         "source_sha256": "a" * 64, "config_sha256": config_digest(self.config),
                         "eligible": True, "artifacts": {
            name: hashlib.sha256(data).hexdigest() for name, data in self.original.items() if name != "secrets.json"}}
        self.runner = Mock()
        self.enterContext(patch("installer.deploy.source_digest", return_value="a" * 64 + "\n"))
        self.enterContext(patch("installer.maintenance.executor_identity", return_value="e" * 64))
        self.check = self.enterContext(patch("installer.enrollment.check", return_value=self.evidence))
        self.original_guard = self.enterContext(patch("installer.enrollment.validate_original_guard"))
        self.install_guard = self.enterContext(patch("installer.enrollment.install_guard"))
        self.validate_guard = self.enterContext(patch("installer.enrollment.validate_guard"))
        self.recheck = self.enterContext(patch("installer.enrollment.recheck"))
        self.enterContext(patch("installer.enrollment_start.validation_starts", side_effect=lambda *args: nullcontext()))
        self.store = Store(self.registry.root)

    def enroll(self):
        register(self.registry, "cloud", self.runner, confirmation="ENROLL cloud")

    def retry(self):
        recover(self.registry, self.runner, confirmation="RECOVER-LIFECYCLE")

    def assert_enrolled(self):
        self.assertIsNone(self.store.pending())
        self.assertEqual(self.store.graph()["instances"]["cloud"]["kind"], "managed")
        self.assertEqual(self.registry.load("cloud"), self.config)
        self.assertEqual(self.registry.status("cloud")["state"], "ready")
        for name, data in self.original.items():
            retained = self.path / "secrets.json" if name == "secrets.json" else self.path / "legacy/files" / name
            self.assertEqual(retained.read_bytes(), data)
        self.assertEqual(status(self.registry)["error"], None)

    def test_full_enrollment_preserves_original_bytes_and_changes_no_applications(self):
        self.enroll()
        self.assert_enrolled()
        self.runner.run.assert_not_called()
        self.original_guard.assert_called_once()
        self.install_guard.assert_called_once()
        self.recheck.assert_called_once()
        registration = json.loads((self.path / "config.json").read_text())
        with self.assertRaises(ValueError):
            type(self.config).from_json(json.dumps(registration))
        entry_guard("mutation", registry=self.registry)
        from installer.dashboard import snapshot
        from installer.updates import check_updates
        row = snapshot(self.registry)["instances"][0]
        self.assertIsNone(row["error"])
        self.assertEqual(row["state"], "ready")
        report = check_updates(self.registry, ["cloud"])
        self.assertFalse(report["inspection_failed"])
        self.assertIsNotNone(report["instances"][0]["bindings"]["lifecycle_sha256"])

    def test_confirmation_missing_baseline_and_source_fail_before_intent(self):
        with self.assertRaisesRegex(ValueError, "confirmation"):
            register(self.registry, "cloud", self.runner, confirmation="yes")
        self.check.assert_not_called()
        self.check.return_value = {"eligible": False}
        with self.assertRaisesRegex(ValueError, "baseline"):
            self.enroll()
        self.assertFalse(self.registry.lifecycle_enabled())
        self.assertIsNone(self.store.pending())
        self.original_guard.assert_not_called()
        self.install_guard.assert_not_called()

    def test_guard_failure_leaves_immediate_pending_boot_and_mutation_fence(self):
        self.install_guard.side_effect = RuntimeError("fault between jail hooks")
        with self.assertRaises(RuntimeError):
            self.enroll()
        self.assertIsNotNone(self.store.pending())
        with self.assertRaisesRegex(ValueError, "pending"):
            entry_guard("mutation", registry=self.registry)
        with self.assertRaises(ValueError):
            self.registry.load("cloud")
        self.assertEqual(status(self.registry)["pending"]["action"], "enroll")
        self.install_guard.side_effect = None
        self.retry()
        self.assert_enrolled()

    def test_guard_failure_recovery_refuses_changed_executor(self):
        self.install_guard.side_effect = RuntimeError("fault")
        with self.assertRaises(RuntimeError):
            self.enroll()
        with patch("installer.maintenance.executor_identity", return_value="f" * 64):
            with self.assertRaisesRegex(ValueError, "original lifecycle executor"):
                self.retry()
        self.assertIsNotNone(self.store.pending())

    def test_recovery_refuses_changed_original_bytes(self):
        self.install_guard.side_effect = RuntimeError("fault")
        with self.assertRaises(RuntimeError):
            self.enroll()
        atomic_json(self.path / "inventory.json", {"changed": True})
        self.install_guard.side_effect = None
        with self.assertRaisesRegex(ValueError, "original evidence changed"):
            self.retry()
        self.assertIsNotNone(self.store.pending())

    def test_live_recheck_failure_keeps_committed_graph_closed_until_explicit_retry(self):
        self.recheck.side_effect = ValueError("live drift")
        with self.assertRaisesRegex(ValueError, "live drift"):
            self.enroll()
        self.assertEqual(self.store.graph(validate_evidence=False)["instances"]["cloud"]["kind"], "managed")
        with self.assertRaises(ValueError):
            entry_guard("boot", registry=self.registry)
        self.recheck.side_effect = None
        self.retry()
        self.assert_enrolled()

    def test_post_descriptor_and_post_commit_crashes_are_exactly_resumable(self):
        original = Store.commit
        def fail_after_commit(store, *args):
            original(store, *args)
            raise OSError("crash after active pointer")
        with patch.object(Store, "commit", fail_after_commit), self.assertRaises(OSError):
            self.enroll()
        self.assertIsNotNone(self.store.pending())
        self.retry()
        self.assert_enrolled()

    def test_managed_and_configured_legacy_readers_share_graph(self):
        other = configuration(instance="other")
        self.registry.save_new(other, {"private": "retained"})
        self.enroll()
        self.assert_enrolled()
        self.assertEqual(self.store.graph()["instances"]["other"]["kind"], "legacy")
        self.assertEqual(self.registry.load("other"), other)
        with self.registry.locked():
            self.registry.write_source("other", "a" * 64 + "\n")
            self.registry.set_status("other", "failed")
        self.assertEqual(self.registry.status("other")["state"], "failed")
        self.assertEqual(self.registry.load("cloud"), self.config)


if __name__ == "__main__":
    unittest.main()
