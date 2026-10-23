"""Public target-preparation boundary; commands/native probes are mocked."""

from contextlib import nullcontext
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from installer import maintenance_operations as operations
from installer.main import maintenance_report


class TargetPreparationCommandTests(unittest.TestCase):
    def setUp(self):
        self.registry = Mock()
        self.registry.locked.return_value = nullcontext()
        self.enterContext(patch.object(operations, "entry_guard"))
        self.enterContext(patch.object(operations, "executor_record", return_value={"source": "fixture"}))
        self.journal = Mock()
        self.journal.read.return_value = {"phase": "staged"}
        self.load = self.enterContext(patch.object(operations, "load_operation", return_value=(
            {"executor": {"source": "fixture"}, "instance": "cloud"}, {}, self.journal)))
        self.file = self.enterContext(patch("installer.nextcloud_update._file", side_effect=lambda *args: nullcontext()))
        self.state = self.enterContext(patch("installer.maintenance_state.NativeState"))
        self.state.return_value.store._bound.return_value = json.dumps({"report": {
            "status": "staging-only", "blockers": [], "private_path": "DO-NOT-PRINT"}}).encode()
        self.admission = self.enterContext(patch("installer.maintenance_admission.SourceAdmission"))
        self.deployment = self.enterContext(patch("installer.maintenance._deployment"))
        self.database = self.enterContext(patch("installer.operations._database_guard", side_effect=lambda _: nullcontext()))
        self.collect = self.enterContext(patch("installer.maintenance_candidate.collect",
            return_value=SimpleNamespace(reference={"path": "private", "sha256": "a" * 64})))

    def prepare(self, confirmation="PREPARE-TARGET maint-fixture"):
        return operations.prepare_target(self.registry, "maint-fixture", Path("/operator/public-artifacts"),
                                         Mock(), confirmation=confirmation)

    def test_local_fixed_inputs_and_no_execution_authority(self):
        report = self.prepare()
        self.assertEqual(self.file.call_count, 6)
        self.database.assert_called_once_with(self.deployment.return_value)
        self.collect.assert_called_once()
        args, kwargs = self.collect.call_args
        self.assertEqual(args, (self.deployment.return_value, "maint-fixture"))
        self.assertEqual(kwargs["connector_archive"], Path("/operator/public-artifacts/connector.archive"))
        self.assertEqual(kwargs["source_asc"], Path("/operator/public-artifacts/nextcloud-35.0.1.tar.bz2.asc"))
        self.assertFalse(report["native_execution_authorized"])
        self.assertTrue(report["saved"])
        self.assertNotIn("DO-NOT-PRINT", str(maintenance_report(report)))
        self.state.return_value.begin.assert_not_called()

    def test_confirmation_precedes_all_reads_and_writes(self):
        with self.assertRaisesRegex(ValueError, "PREPARE-TARGET"):
            self.prepare("yes")
        self.registry.locked.assert_not_called()
        self.load.assert_not_called()
        self.collect.assert_not_called()

    def test_unstaged_preparation_refuses_before_probing_or_copying(self):
        self.journal.read.return_value = {"phase": "staging"}
        with self.assertRaisesRegex(ValueError, "staged source"):
            self.prepare()
        self.file.assert_not_called()
        self.deployment.assert_not_called()
        self.collect.assert_not_called()

    def test_missing_input_refuses_before_native_source_admission(self):
        self.file.side_effect = FileNotFoundError
        with self.assertRaises(FileNotFoundError):
            self.prepare()
        self.deployment.assert_not_called()
        self.collect.assert_not_called()

if __name__ == "__main__":
    unittest.main()
