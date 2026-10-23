"""Offline boot dispatch: permission readers never replace exec.prepare checks."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from installer.generations import Store
from installer.maintenance import boot_check, entry_guard, require_instance_adapter
from installer.state import Registry, atomic_json


class BootDispatchTests(unittest.TestCase):
    def setUp(self):
        self.executor = "e" * 64
        self.registry = Mock(root=Path("/unused-registry"))
        self.registry.lifecycle_enabled.return_value = True
        self.enterContext(patch("installer.maintenance.Registry", return_value=self.registry))
        self.enterContext(patch("installer.maintenance.executor_identity", return_value=self.executor))
        self.store = self.enterContext(patch("installer.generations.Store")).return_value
        self.guard = self.enterContext(patch("installer.maintenance.entry_guard"))
        self.enrollment = self.enterContext(patch("installer.enrollment_start.boot_permission"))
        self.native = self.enterContext(patch("installer.maintenance_fence.boot_permission"))

    def boot(self, instance="cloud", jail="cloudnc", executor=None):
        boot_check(self.registry.root, instance, jail, self.executor if executor is None else executor)

    def test_pending_actions_dispatch_exact_arguments_for_each_pair(self):
        for action, helper, other, instances in (
                ("enroll", self.enrollment, self.native, ("cloud",)),
                ("maintenance", self.native, self.enrollment, ("cloud", "other"))):
            intent = {"action": action, "instances": ["cloud"]}
            self.store.pending.return_value = intent
            for instance in instances:
                for suffix in ("nc", "oo"):
                    with self.subTest(action=action, instance=instance, suffix=suffix):
                        helper.reset_mock()
                        other.reset_mock()
                        self.boot(instance, instance + suffix)
                        helper.assert_called_once_with(self.registry, intent, instance,
                                                       instance + suffix, self.executor)
                        other.assert_not_called()
            self.guard.assert_not_called()
            self.registry.load.assert_not_called()

    def test_permission_denial_never_falls_back_to_ordinary_or_other_permission(self):
        for action, helper, other in (("enroll", self.enrollment, self.native),
                                      ("maintenance", self.native, self.enrollment)):
            self.store.pending.return_value = {"action": action}
            helper.side_effect = ValueError("bound permission refused")
            other.reset_mock()
            with self.subTest(action=action), self.assertRaisesRegex(ValueError, "bound permission"):
                self.boot()
            other.assert_not_called()
            self.guard.assert_not_called()
            self.registry.load.assert_not_called()

    def test_other_pending_actions_fail_closed(self):
        for action in ("register", "status", "evidence", "remove", "purge", "unknown"):
            self.store.pending.return_value = {"action": action}
            with self.subTest(action=action), self.assertRaisesRegex(ValueError, "jail boot refused"):
                self.boot()
        self.enrollment.assert_not_called()
        self.native.assert_not_called()
        self.guard.assert_not_called()
        self.registry.load.assert_not_called()

    def test_wrong_executor_precedes_pending_lookup_and_permissions(self):
        self.store.pending.return_value = {"action": "maintenance"}
        with self.assertRaisesRegex(ValueError, "executor changed"):
            self.boot(executor="f" * 64)
        self.store.pending.assert_not_called()
        self.enrollment.assert_not_called()
        self.native.assert_not_called()
        self.guard.assert_not_called()
        self.registry.load.assert_not_called()

    def test_no_pending_retains_entry_guard_before_instance_lookup(self):
        self.store.pending.return_value = None
        self.guard.side_effect = ValueError("original executor required")
        with self.assertRaisesRegex(ValueError, "original executor"):
            self.boot()
        self.guard.assert_called_once_with("boot", registry=self.registry)
        self.registry.load.assert_not_called()
        self.native.assert_not_called()
        self.enrollment.assert_not_called()


class BootFenceGuardTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="boot-dispatch-")
        self.addCleanup(temporary.cleanup)
        self.registry = Registry(Path(temporary.name) / "registry")
        self.registry.initialize()
        self.store = Store(self.registry.root)
        self.store._mkdir("lifecycle")
        self.executor = "e" * 64
        self.enterContext(patch("installer.maintenance.executor_identity", return_value=self.executor))

    def test_malformed_pending_and_unknown_action_rejected_before_dispatch(self):
        self.store._mkdir("maintenance/operations/execution-test")
        path = "maintenance/operations/execution-test/intent.json"
        with patch("installer.enrollment_start.boot_permission") as enrollment, \
                patch("installer.maintenance_fence.boot_permission") as native:
            for intent in ({}, [], {"action": "maintenance"}, {"action": "enroll"},
                           {"schema_version": 1, "operation": "execution-test", "action": "unknown",
                            "instances": ["cloud"], "executor_sha256": self.executor, "base_graph": None}):
                with self.subTest(intent=intent):
                    reference = self.store._put(path, intent, replace=self.store._present(path))
                    atomic_json(self.registry.root / "maintenance/pending.json",
                                {"schema_version": 1, "state": "pending", "record": reference})
                    with self.assertRaises(ValueError):
                        boot_check(self.registry.root, "cloud", "cloudnc", self.executor)
            enrollment.assert_not_called()
            native.assert_not_called()

    def test_pending_entry_guard_keeps_mutations_closed_and_existing_inspection_routes(self):
        with patch.object(Store, "pending", return_value={"action": "maintenance"}):
            for command in ("boot", "install", "configure", "resume", "remove", "backup", "restore",
                            "add-user", "apply", "maintenance-apply", "unknown"):
                with self.subTest(command=command), self.assertRaisesRegex(ValueError, "pending"):
                    entry_guard(command, registry=self.registry)
            for command in ("menu", "list", "status", "check-updates", "check-security", "maintenance", "resolve"):
                entry_guard(command, registry=self.registry)

    def test_idle_entry_guard_retains_exact_executor_record_and_graph_validation(self):
        expected = {"source_sha256": "a" * 64, "payload_path": "/retained"}
        with patch("installer.maintenance.executor_record", return_value=expected), \
                patch.object(Store, "graph") as graph:
            for record in ({**expected, "source_sha256": "b" * 64},
                           {**expected, "payload_path": "/moved"}):
                atomic_json(self.registry.root / "lifecycle/executor.json", record)
                with self.assertRaisesRegex(ValueError, "original executor and payload path"):
                    entry_guard("boot", registry=self.registry)
            graph.assert_not_called()
            atomic_json(self.registry.root / "lifecycle/executor.json", expected)
            entry_guard("boot", registry=self.registry)
            graph.assert_called_once_with()

    def test_instance_adapter_still_requires_original_source(self):
        registry = Mock(root=self.registry.root)
        source = self.registry.root / "source.sha256"
        source.write_text("b" * 64)
        registry.evidence_path.return_value = source
        with patch("installer.deploy.source_digest", return_value="a" * 64), \
                patch.object(Store, "_read", return_value=b"b" * 64):
            with self.assertRaisesRegex(ValueError, "historical instance source"):
                require_instance_adapter(registry, "cloud")
        registry.load.assert_called_once_with("cloud")


if __name__ == "__main__":
    unittest.main()
