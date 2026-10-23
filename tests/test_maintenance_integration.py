"""Real M3 orchestration/staging with temporary bytes; native boundaries mocked."""

import hashlib
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from installer import maintenance_operations as operations
from installer import maintenance_staging as staging
from installer.generations import Store
from installer.state import atomic_json, atomic_write
import test_maintenance as enrollment_fixture
from version_fixtures import resolved_plan


class MaintenanceIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = enrollment_fixture.EnrollmentTransitionTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.registry = self.fixture.registry
        self.store = Store(self.registry.root)
        self.source = self.registry.root.parent / "source"
        self.source.mkdir(mode=0o700)
        for name in ("install.sh", "installer/__init__.py", "installer/main.py", *staging._RESOURCES):
            path = self.source / name
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            atomic_write(path, "synthetic public source: " + name + "\n")
        # Enrollment retains a real policy document, independently of synthetic
        # inert source files (none of the copied source is executed).
        atomic_write(self.source / "resources/versions.json",
                     (operations.PROJECT_ROOT / "resources/versions.json").read_text())
        _, source_hash, executor_hash = staging._source(self.source)
        self.enterContext(patch.object(staging, "PROJECT_ROOT", self.source))
        self.enterContext(patch.object(staging, "_ROOT_UID", os.geteuid()))
        self.enterContext(patch.object(operations, "PROJECT_ROOT", self.source))
        self.enterContext(patch("installer.maintenance.PROJECT_ROOT", self.source))
        self.enterContext(patch("installer.deploy.source_digest", return_value=source_hash + "\n"))
        self.enterContext(patch("installer.maintenance.executor_identity", return_value=executor_hash))
        self.enterContext(patch("subprocess.run", side_effect=AssertionError("no native commands")))
        self.enterContext(patch("subprocess.Popen", side_effect=AssertionError("no native commands")))
        self.packages = self.registry.root.parent / "packages"
        self.packages.mkdir(mode=0o700)
        self.versions = resolved_plan(self.fixture.config)
        for group in self.versions["packages"].values():
            for name, record in group.items():
                raw = "synthetic package: " + name
                record["checksum"] = hashlib.sha256(raw.encode()).hexdigest()
                atomic_write(self.packages / (record["checksum"] + ".pkg"), raw)
        self.registry.write_source("cloud", source_hash + "\n")
        atomic_json(self.fixture.path / "versions.json", self.versions)
        self.fixture.evidence["source_sha256"] = source_hash
        for name in ("source.sha256", "versions.json"):
            self.fixture.evidence["artifacts"][name] = hashlib.sha256(
                (self.fixture.path / name).read_bytes()).hexdigest()
        self.fixture.enroll()
        transaction = self.registry.root / "transactions/committed-test"
        transaction.mkdir(mode=0o700)
        for name in operations.NETWORK_RECORDS:
            atomic_write(transaction / name, "retained " + name + "\n")
        (self.registry.root / "network/active").symlink_to(transaction)
        report = operations.assess(self.registry, "cloud")
        self.assertEqual(report["status"], "staging-only", report)
        reference = operations.save_plan(self.registry, report["plan"], confirmation="SAVE-MAINTENANCE cloud")
        self.plan_id = Path(reference["path"]).stem

    def tearDown(self):
        self.fixture.runner.run.assert_not_called()
        self.fixture.runner.output.assert_not_called()
        self.assertIsNone(self.store.pending())

    def stage(self):
        return operations.stage_plan(self.registry, self.plan_id, self.packages,
                                     confirmation="STAGE-MAINTENANCE " + self.plan_id)

    def operation(self):
        rows = operations.list_operations(self.registry)
        self.assertEqual(len(rows), 1)
        return rows[0]["operation"]

    def directory(self, operation):
        return self.registry.root / "maintenance/operations" / operation

    def continue_staging(self, operation):
        return operations.continue_staging(self.registry, operation, self.packages,
                                           confirmation="CONTINUE-MAINTENANCE " + operation)

    def test_real_stage_status_and_cancel_authenticate_immutable_cache(self):
        result = self.stage()
        self.assertEqual(result["phase"], "staged")
        self.assertTrue(result["artifacts_authenticated"])
        operation = result["operation"]
        directory = self.directory(operation)
        before = {path: (path.stat().st_ino, path.read_bytes())
                  for path in (directory / "artifacts").rglob("*") if path.is_file()}
        with patch.object(Store, "_put", side_effect=AssertionError("status must be read-only")):
            self.assertEqual(operations.operation_status(self.registry, operation), result)
        cancelled = operations.cancel(self.registry, operation, confirmation="CANCEL-MAINTENANCE " + operation)
        self.assertEqual(cancelled["phase"], "cancelled")
        self.assertTrue(cancelled["artifacts_authenticated"])
        self.assertTrue((directory / "terminal.json").is_file())
        self.assertEqual(before, {path: (path.stat().st_ino, path.read_bytes()) for path in before})
        with patch.object(Store, "_put", side_effect=AssertionError("terminal retry must be immutable")):
            self.assertEqual(operations.cancel(self.registry, operation,
                                              confirmation="CANCEL-MAINTENANCE " + operation), cancelled)

    def test_real_continue_retains_source_temporary_and_authenticates_cache(self):
        publish = staging._publish
        retained = []
        def interrupt(path, writer):
            if path.name == "__init__.py":
                temporary = path.parent / ".pending-source-crash"
                atomic_write(temporary, "unpublished source fragment")
                retained.append((temporary, temporary.stat().st_ino, temporary.read_bytes()))
                raise KeyboardInterrupt()
            return publish(path, writer)
        with patch.object(staging, "_publish", side_effect=interrupt), self.assertRaises(KeyboardInterrupt):
            self.stage()
        operation = self.operation()
        self.assertEqual(operations.operation_status(self.registry, operation)["phase"], "staging")
        result = self.continue_staging(operation)
        self.assertEqual(result["phase"], "staged")
        self.assertTrue(result["artifacts_authenticated"])
        for path, inode, raw in retained:
            self.assertEqual((path.stat().st_ino, path.read_bytes()), (inode, raw))
        self.assertEqual(operations.operation_status(self.registry, operation), result)

    def test_corrupt_cache_does_not_misreport_durable_cancellation(self):
        operation = self.stage()["operation"]
        directory = self.directory(operation)
        path = directory / "artifacts/source/install.sh"
        atomic_write(path, "SECRET damaged cache bytes")
        cancelled = operations.cancel(self.registry, operation, confirmation="CANCEL-MAINTENANCE " + operation)
        self.assertEqual(cancelled["phase"], "cancelled")
        self.assertFalse(cancelled["artifacts_authenticated"])
        self.assertEqual(cancelled["error"], "cancelled-cache-authentication-failed")
        self.assertNotIn("SECRET", str(cancelled))
        self.assertEqual(path.read_text(), "SECRET damaged cache bytes")
        terminal = (directory / "terminal.json").read_bytes()
        self.assertEqual(operations.cancel(self.registry, operation,
                                          confirmation="CANCEL-MAINTENANCE " + operation), cancelled)
        self.assertEqual((directory / "terminal.json").read_bytes(), terminal)
        with self.assertRaises(ValueError):
            operations.operation_status(self.registry, operation)

    def test_cancel_does_not_tolerate_damaged_operation_metadata(self):
        operation = self.stage()["operation"]
        directory = self.directory(operation)
        atomic_write(directory / "operation.json", "invalid private metadata")
        with self.assertRaises(ValueError):
            operations.cancel(self.registry, operation, confirmation="CANCEL-MAINTENANCE " + operation)
        self.assertFalse((directory / "terminal.json").exists())

    def test_real_continue_after_manifest_publication_before_staged_journal(self):
        advance = operations.OperationJournal.advance
        def interrupt(journal, phase, evidence=None):
            if phase == "staged":
                manifest = self.directory(journal.operation) / "artifacts/manifest.json"
                self.assertTrue(manifest.is_file())
                raise KeyboardInterrupt()
            return advance(journal, phase, evidence)
        with patch.object(operations.OperationJournal, "advance", interrupt), self.assertRaises(KeyboardInterrupt):
            self.stage()
        operation = self.operation()
        directory = self.directory(operation)
        before = {path: (path.stat().st_ino, path.read_bytes())
                  for path in (directory / "artifacts").rglob("*") if path.is_file()}
        self.assertEqual(operations.operation_status(self.registry, operation)["phase"], "staging")
        with patch.object(staging, "_publish", side_effect=AssertionError("must retain published bytes")):
            result = self.continue_staging(operation)
        self.assertEqual(result["phase"], "staged")
        self.assertTrue(result["artifacts_authenticated"])
        self.assertEqual(before, {path: (path.stat().st_ino, path.read_bytes()) for path in before})

    def test_cache_verification_failure_cannot_publish_staged_journal(self):
        stage = staging.stage
        def corrupt(*args, **kwargs):
            receipt = stage(*args, **kwargs)
            manifest = self.registry.root / receipt["path"]
            atomic_write(manifest.parent / "source/install.sh", "corrupted after stage")
            return receipt
        with patch.object(staging, "stage", side_effect=corrupt), self.assertRaisesRegex(ValueError, "Artifact staging failed"):
            self.stage()
        operation = self.operation()
        record = operations.load_operation(self.registry, operation)[2].read()
        self.assertEqual((record["phase"], record["last_safe_phase"]), ("recovery-required", "staging"))
        self.assertNotIn("artifacts", record["evidence"])
        self.assertTrue((self.directory(operation) / "artifacts/manifest.json").is_file())


if __name__ == "__main__":
    unittest.main()
