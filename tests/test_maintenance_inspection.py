"""Native operation inspection is read-only even while a mutation is pending."""

import unittest
from unittest.mock import patch

from installer.maintenance_inspection import inspect
from installer.maintenance_journal import NativeJournal, require_native_recipe
from installer import maintenance_operations
import test_maintenance_state as fixtures


class NativeInspectionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.NativeStateTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        f = self.fixture
        with f.registry.locked(recovery=True):
            f.begin()
            self.journal = NativeJournal(f.registry, f.operation,
                f.store.reference(f"maintenance/operations/{f.operation}/intent.json"), f.recipe, native=f.native)
            self.journal.initialize()

    def test_pending_history_reads_no_lock_or_native_command(self):
        f = self.fixture
        before = {str(path): path.stat().st_mtime_ns for path in f.root.rglob("*") if path.is_file()}
        with patch.object(f.registry, "locked", side_effect=AssertionError("no lock")), \
                patch("subprocess.run", side_effect=AssertionError("no command")):
            value = maintenance_operations.operation_status(f.registry, f.operation)
            recovery = maintenance_operations.assess_recovery(f.registry, f.operation)
        self.assertTrue(value["pending"])
        self.assertEqual(value["phase"], "capture")
        self.assertFalse(value["native_execution_authorized"])
        self.assertFalse(value["restore_eligible"])
        self.assertFalse(recovery["restore_eligible"])
        self.assertEqual(before, {str(path): path.stat().st_mtime_ns for path in f.root.rglob("*") if path.is_file()})

    def test_native_history_is_discoverable_beside_inert_preparation(self):
        f = self.fixture
        values = maintenance_operations.list_operations(f.registry)
        found = {item["operation"]: item for item in values}
        self.assertIn("maint-fixture", found)
        self.assertEqual(found[f.operation]["phase"], "capture")

    def test_corrupt_journal_refuses_and_overview_does_not_echo_data(self):
        f = self.fixture
        f.store._write(self.journal.path, b'{"SECRET":"corrupt"}', replace=True)
        with self.assertRaises(ValueError):
            inspect(f.registry, f.operation)
        value = next(item for item in maintenance_operations.list_operations(f.registry) if item["operation"] == f.operation)
        self.assertEqual(value["phase"], "incomplete")
        self.assertNotIn("SECRET", str(value))

    def test_changing_journal_during_read_refuses(self):
        f = self.fixture
        reference = f.store.reference(self.journal.path)
        original = type(f.store).reference
        calls = 0
        def changed(store, path):
            nonlocal calls
            result = original(store, path)
            if path == self.journal.path:
                calls += 1
                if calls > 1:
                    return {**reference, "sha256": "e" * 64}
            return result
        with patch.object(type(f.store), "reference", changed), self.assertRaisesRegex(ValueError, "changed"):
            inspect(f.registry, f.operation)

    def test_wrong_namespace_and_fake_terminal_refused(self):
        f = self.fixture
        with self.assertRaises(ValueError):
            inspect(f.registry, "maint-fixture")
        f.store._put(self.journal.terminal_path, {"phase": "complete"})
        with self.assertRaisesRegex(ValueError, "terminal"):
            inspect(f.registry, f.operation)

    def test_recipe_descriptor_or_permission_bit_is_not_catalog_authority(self):
        for value in (None, [], {"recipe": {}}, {"recipe": {"execution_authorized": True}},
                      {"recipe": "nc-35.0.1-to-35.0.2-inspection-v1", "native_execution_authorized": True}):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "no reviewed"):
                require_native_recipe(value)


if __name__ == "__main__":
    unittest.main()
