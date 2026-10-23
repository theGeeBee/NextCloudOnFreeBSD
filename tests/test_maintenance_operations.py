"""Recovery preparation against real private state; all native calls are mocked."""

from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from installer import maintenance_operations as operations
from installer import maintenance_staging as staging
from installer.generations import Store
from installer.maintenance import boot_check, entry_guard
from installer.state import Registry, atomic_json, atomic_write
import test_maintenance as enrollment_fixture
from version_fixtures import resolved_plan


class MaintenanceOperationsTests(unittest.TestCase):
    def setUp(self):
        # Composition deliberately avoids discovering the enrollment tests twice.
        self.fixture = enrollment_fixture.EnrollmentTransitionTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.registry = self.fixture.registry
        self.store = Store(self.registry.root)
        self.packages = self.registry.root.parent / "packages"
        self.packages.mkdir(mode=0o700)
        self.versions = resolved_plan(self.fixture.config)
        for group in self.versions["packages"].values():
            for name, record in group.items():
                raw = ("synthetic archive: " + name).encode()
                record["checksum"] = hashlib.sha256(raw).hexdigest()
                atomic_write(self.packages / (record["checksum"] + ".pkg"), raw.decode())
        atomic_json(self.fixture.path / "versions.json", self.versions)
        self.fixture.evidence["artifacts"]["versions.json"] = hashlib.sha256(
            (self.fixture.path / "versions.json").read_bytes()).hexdigest()
        self.fixture.enroll()
        self.transaction = self.registry.root / "transactions/committed-test"
        self.transaction.mkdir(mode=0o700)
        for name in operations.NETWORK_RECORDS:
            atomic_write(self.transaction / name, "retained " + name + "\n")
        self.active = self.registry.root / "network/active"
        self.active.symlink_to(self.transaction)
        # Freeze public source inputs while the parent session edits implementation.
        self.source = self.registry.root.parent / "source"
        self.source.mkdir(mode=0o700)
        for spec in staging.required_artifacts(None, operations.PROJECT_ROOT):
            relative = Path(spec["path"]).relative_to("source")
            destination = self.source / relative
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            atomic_write(destination, (operations.PROJECT_ROOT / relative).read_text())
        self.enterContext(patch.object(operations, "PROJECT_ROOT", self.source))
        self.fixture.runner.reset_mock()

    def snapshot(self):
        result = {}
        for path in (self.registry.root, *self.registry.root.rglob("*")):
            info = path.lstat()
            contents = os.readlink(path) if path.is_symlink() else path.read_bytes() if path.is_file() else None
            result[str(path.relative_to(self.registry.root))] = (
                info.st_ino, info.st_mode, info.st_uid, info.st_nlink, info.st_mtime_ns, contents)
        return result

    def plan(self):
        report = operations.assess(self.registry, "cloud")
        self.assertEqual(report["status"], "staging-only", report)
        return report["plan"]

    def save(self):
        reference = operations.save_plan(self.registry, self.plan(), confirmation="SAVE-MAINTENANCE cloud")
        plan = json.loads((self.registry.root / reference["path"]).read_bytes())
        return plan, reference

    def stage_receipt(self, root, operation, specs, package_directory, source_root, **kwargs):
        self.assertTrue(self.registry._locked)
        self.assertEqual(root, self.registry.root)
        self.assertEqual(package_directory, self.packages)
        self.assertEqual(source_root, self.source)
        value, plan, _ = operations.load_operation(self.registry, operation)
        self.assertEqual(specs, plan["artifacts"])
        self.assertEqual(kwargs, dict(registry=self.registry, versions_plan=None,
                                     plan_sha256=value["plan"]["sha256"],
                                     source_sha256=value["executor"]["source_sha256"],
                                     executor_sha256=value["executor"]["executor_sha256"]))
        directory = f"maintenance/operations/{operation}/artifacts"
        self.store._mkdir(directory)
        if (self.registry.root / directory / "manifest.json").exists():
            return self.store.reference(directory + "/manifest.json")
        return self.store._put(directory + "/manifest.json", {"synthetic": "receipt"})

    def staged(self):
        plan, reference = self.save()
        with patch.object(staging, "stage", autospec=True, side_effect=self.stage_receipt) as stage, \
                patch.object(staging, "verify_stage", autospec=True):
            result = operations.stage_plan(self.registry, plan["plan_id"], self.packages,
                                           confirmation="STAGE-MAINTENANCE " + plan["plan_id"])
        stage.assert_called_once()
        return result["operation"], plan, reference

    def interrupted(self, exception=None):
        plan, reference = self.save()
        secret = "private-stage-password-DO-NOT-DISCLOSE"
        def fail(*args, **kwargs):
            self.stage_receipt(*args, **kwargs)
            raise exception if exception is not None else OSError(secret)
        with patch.object(staging, "stage", autospec=True, side_effect=fail), \
                self.assertRaises((ValueError, KeyboardInterrupt)) as caught:
            operations.stage_plan(self.registry, plan["plan_id"], self.packages,
                                  confirmation="STAGE-MAINTENANCE " + plan["plan_id"])
        self.assertNotIn(secret, str(caught.exception))
        paths = list((self.registry.root / "maintenance/operations").glob("*/operation.json"))
        self.assertEqual(len(paths), 1)
        if not isinstance(caught.exception, KeyboardInterrupt):
            self.assertIn(paths[0].parent.name, str(caught.exception))
        return paths[0].parent.name, plan, reference

    def assert_no_native(self):
        self.fixture.runner.run.assert_not_called()
        self.fixture.runner.output.assert_not_called()

    def test_assess_is_read_only_and_does_not_authorize_execution(self):
        before = self.snapshot()
        with patch.object(self.registry, "locked", side_effect=AssertionError("read-only")), \
                patch.object(Store, "_put", side_effect=AssertionError("read-only")):
            report = operations.assess(self.registry, "cloud")
        self.assertEqual(report["status"], "staging-only")
        self.assertFalse(report["execution_authorized"])
        self.assertEqual(report["native_acceptance"], "not-run")
        self.assertTrue(report["warnings"])
        plan = report["plan"]
        self.assertIsNone(plan["plan_id"])
        self.assertIsNone(plan["recipe"])
        self.assertFalse(plan["native_execution_authorized"])
        self.assertFalse(plan["upgrade_execution_authorized"])
        self.assertEqual(plan["artifacts"], staging.required_artifacts(None, self.source))
        self.assertEqual(before, self.snapshot())
        self.assert_no_native()

    def test_legacy_and_missing_registries_are_blocked_without_initialization(self):
        for initialize in (False, True):
            registry = Registry(self.registry.root.parent / ("legacy" if initialize else "absent"))
            if initialize:
                registry.initialize()
                registry.save_new(self.fixture.config, {"private": "legacy-secret"})
            with self.subTest(initialize=initialize), \
                    patch.object(registry, "locked", side_effect=AssertionError("read-only")), \
                    patch.object(Store, "_put", side_effect=AssertionError("read-only")):
                report = operations.assess(registry, "cloud")
            self.assertEqual(report["status"], "blocked")
            self.assertIsNone(report["plan"])
            self.assertFalse((registry.root / "maintenance").exists())
            self.assertEqual(registry.root.exists(), initialize)

    def test_explicit_destination_is_blocked_before_source_inspection(self):
        before = self.snapshot()
        with patch.object(operations, "bindings", side_effect=AssertionError("no destination recipe")):
            for target in ("FreeBSD-15.1-amd64", "same-source"):
                report = operations.assess(self.registry, "cloud", target=target)
                self.assertEqual(report["status"], "blocked")
                self.assertIsNone(report["plan"])
                self.assertIn("recipe", report["blockers"][0])
            for target in ("../escape", "", "x\nsecret", 7):
                with self.assertRaises(ValueError):
                    operations.assess(self.registry, "cloud", target=target)
        self.assertEqual(before, self.snapshot())

    def test_opaque_catalog_checksums_cannot_be_used_as_archive_hashes(self):
        with self.assertRaisesRegex(ValueError, "archive SHA256"):
            staging.required_artifacts(resolved_plan(self.fixture.config), self.source)
        original = operations.bindings
        def opaque(*args):
            bound, config, _ = original(*args)
            return bound, config, resolved_plan(config)
        before = self.snapshot()
        with patch.object(operations, "bindings", side_effect=opaque):
            report = operations.assess(self.registry, "cloud")
        self.assertEqual(report["status"], "staging-only")
        self.assertEqual(report["plan"]["artifacts"], staging.required_artifacts(None, self.source))
        self.assertEqual(before, self.snapshot())

    def test_network_binding_pins_exact_committed_link_and_six_private_records(self):
        bound = self.plan()["bindings"]["network"]
        self.assertEqual(bound["target"], "transactions/committed-test")
        self.assertEqual(set(bound["records"]), set(operations.NETWORK_RECORDS))
        self.assertEqual(len(bound["records"]), 6)
        for name, reference in bound["records"].items():
            self.assertEqual(reference, self.store.reference("transactions/committed-test/" + name))
            self.assertEqual((self.transaction / name).stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.transaction.stat().st_mode & 0o777, 0o700)

    def test_network_link_missing_relative_outside_or_nontransaction_is_blocked(self):
        self.active.unlink()
        for target in (None, "../transactions/committed-test", str(self.packages),
                       str(self.registry.root / "instances/cloud")):
            if target is not None:
                self.active.symlink_to(target)
            try:
                before = self.snapshot()
                with self.subTest(target=target):
                    self.assertEqual(operations.assess(self.registry, "cloud")["status"], "blocked")
                    self.assertEqual(before, self.snapshot())
            finally:
                if target is not None:
                    self.active.unlink()

    def test_each_network_record_must_be_present_private_and_single_link(self):
        for name in operations.NETWORK_RECORDS:
            path = self.transaction / name
            raw = path.read_bytes()
            for kind in ("missing", "public", "hardlink", "symlink"):
                alias = self.registry.root.parent / "network-alias"
                if kind == "missing":
                    path.unlink()
                elif kind == "public":
                    path.chmod(0o644)
                elif kind == "hardlink":
                    os.link(path, alias)
                else:
                    path.rename(alias)
                    path.symlink_to(alias)
                try:
                    with self.subTest(name=name, kind=kind):
                        self.assertEqual(operations.assess(self.registry, "cloud")["status"], "blocked")
                finally:
                    if path.exists() or path.is_symlink():
                        path.unlink()
                    if alias.exists():
                        alias.unlink()
                    atomic_write(path, raw.decode())

    def test_save_revalidates_under_lock_and_retains_immutable_original_plan(self):
        proposed = self.plan()
        original = deepcopy(proposed)
        revalidate = operations._revalidate
        def checked(registry, plan):
            self.assertTrue(registry._locked)
            return revalidate(registry, plan)
        with patch.object(operations, "_revalidate", side_effect=checked) as check:
            reference = operations.save_plan(self.registry, proposed, confirmation="SAVE-MAINTENANCE cloud")
        check.assert_called_once()
        self.assertEqual(proposed, original)
        saved = json.loads((self.registry.root / reference["path"]).read_bytes())
        loaded, loaded_ref = operations.load_plan(self.store, saved["plan_id"])
        self.assertEqual((loaded, loaded_ref), (saved, reference))
        self.assertEqual({**saved, "plan_id": None}, original)
        self.assertEqual((self.registry.root / reference["path"]).stat().st_mode & 0o777, 0o600)
        self.assertIsNone(self.store.pending())
        self.assert_no_native()

    def test_all_mutations_require_exact_confirmation_before_lock_or_write(self):
        plan, _ = self.save()
        proposed = {**plan, "plan_id": None}
        calls = (
            (lambda confirmation: operations.save_plan(self.registry, proposed, confirmation=confirmation), "SAVE-MAINTENANCE cloud"),
            (lambda confirmation: operations.stage_plan(self.registry, plan["plan_id"], self.packages, confirmation=confirmation), "STAGE-MAINTENANCE " + plan["plan_id"]),
            (lambda confirmation: operations.continue_staging(self.registry, "maint-absent", self.packages, confirmation=confirmation), "CONTINUE-MAINTENANCE maint-absent"),
            (lambda confirmation: operations.cancel(self.registry, "maint-absent", confirmation=confirmation), "CANCEL-MAINTENANCE maint-absent"),
        )
        before = self.snapshot()
        with patch.object(self.registry, "locked", side_effect=AssertionError("must confirm first")):
            for call, exact in calls:
                for confirmation in ("", "yes", exact.lower(), exact + " ", " " + exact, exact + "\n"):
                    with self.subTest(exact=exact, confirmation=confirmation), self.assertRaises(ValueError):
                        call(confirmation)
        self.assertEqual(before, self.snapshot())

    def test_stage_binds_full_stager_signature_and_status_must_rehash_every_time(self):
        operation, plan, reference = self.staged()
        value, _, journal = operations.load_operation(self.registry, operation)
        receipt = journal.read()["evidence"]["artifacts"]
        before = self.snapshot()
        with patch.object(staging, "verify_stage", autospec=True) as verify, \
                patch.object(self.registry, "locked", side_effect=AssertionError("read-only")):
            for _ in range(2):
                status = operations.operation_status(self.registry, operation)
                self.assertEqual(status["phase"], "staged")
                self.assertTrue(status["artifacts_authenticated"])
                for field in ("recovery_capture_complete", "independent_copy_verified", "writer_fencing_verified",
                              "upgrade_execution_authorized", "native_execution_authorized"):
                    self.assertFalse(status[field])
            self.assertEqual(verify.call_count, 2)
            verify.assert_called_with(self.registry.root, operation, plan["artifacts"], receipt,
                                      versions_plan=None, plan_sha256=reference["sha256"],
                                      source_sha256=value["executor"]["source_sha256"],
                                      executor_sha256=value["executor"]["executor_sha256"])
        with patch.object(staging, "verify_stage", side_effect=ValueError("artifact changed")):
            with self.assertRaisesRegex(ValueError, "artifact changed"):
                operations.operation_status(self.registry, operation)
            with self.assertRaises(ValueError):
                operations.assess_recovery(self.registry, operation)
        self.assertEqual(before, self.snapshot())

    def test_interruption_is_discoverable_bound_to_original_plan_without_boot_fence(self):
        before_graph = self.store._active()
        operation, plan, reference = self.interrupted()
        value, retained, journal = operations.load_operation(self.registry, operation)
        self.assertEqual(retained, plan)
        self.assertEqual(value["plan"], reference)
        self.assertEqual(journal.read()["last_safe_phase"], "staging")
        status = operations.operation_status(self.registry, operation)
        self.assertEqual(status["phase"], "recovery-required")
        self.assertEqual(status["error"], "staging-failed")
        self.assertFalse(status["artifacts_authenticated"])
        self.assertIsNone(self.store.pending())
        self.assertEqual(self.store._active(), before_graph)
        entry_guard("mutation", registry=self.registry)
        boot_check(self.registry.root, "cloud", self.fixture.config.nextcloud_jail, "e" * 64)
        self.assertFalse(self.registry._locked)
        self.assert_no_native()

    def test_keyboard_interrupt_preserves_unfinished_staging_for_explicit_continuation(self):
        operation, plan, _ = self.interrupted(KeyboardInterrupt())
        self.assertEqual(operations.operation_status(self.registry, operation)["phase"], "staging")
        self.assertIsNone(self.store.pending())
        with patch.object(staging, "stage", autospec=True, side_effect=self.stage_receipt), \
                patch.object(staging, "verify_stage", autospec=True):
            status = operations.continue_staging(self.registry, operation, self.packages,
                                                 confirmation="CONTINUE-MAINTENANCE " + operation)
        self.assertEqual(status["phase"], "staged")
        self.assertEqual(operations.load_operation(self.registry, operation)[1], plan)

    def test_continue_recovers_only_same_plan_and_does_not_create_another_operation(self):
        operation, plan, _ = self.interrupted()
        operation_path = self.registry.root / f"maintenance/operations/{operation}/operation.json"
        original = operation_path.stat().st_ino, operation_path.read_bytes()
        with patch.object(staging, "stage", autospec=True, side_effect=self.stage_receipt) as stage, \
                patch.object(staging, "verify_stage", autospec=True):
            status = operations.continue_staging(self.registry, operation, self.packages,
                                                 confirmation="CONTINUE-MAINTENANCE " + operation)
        stage.assert_called_once()
        self.assertEqual(status["phase"], "staged")
        self.assertEqual(original, (operation_path.stat().st_ino, operation_path.read_bytes()))
        self.assertEqual(operations.load_operation(self.registry, operation)[1], plan)
        self.assertEqual(list(operation_path.parent.parent.glob("*/operation.json")), [operation_path])

    def test_cancel_retains_partial_artifacts_and_terminal_retry_is_immutable(self):
        operation, _, reference = self.interrupted()
        directory = self.registry.root / f"maintenance/operations/{operation}"
        retained = {path: (path.stat().st_ino, path.read_bytes())
                    for path in directory.rglob("*") if path.is_file() and path.name != "journal.json"}
        plan_bytes = (self.registry.root / reference["path"]).read_bytes()
        status = operations.cancel(self.registry, operation, confirmation="CANCEL-MAINTENANCE " + operation)
        self.assertEqual(status["phase"], "cancelled")
        self.assertTrue((directory / "terminal.json").is_file())
        for path, identity in retained.items():
            self.assertEqual((path.stat().st_ino, path.read_bytes()), identity)
        self.assertEqual((self.registry.root / reference["path"]).read_bytes(), plan_bytes)
        before = self.snapshot()
        with patch.object(Store, "_put", side_effect=AssertionError("terminal retry must not rewrite")):
            self.assertEqual(operations.cancel(self.registry, operation,
                                             confirmation="CANCEL-MAINTENANCE " + operation), status)
            with self.assertRaises(ValueError):
                operations.continue_staging(self.registry, operation, self.packages,
                                            confirmation="CONTINUE-MAINTENANCE " + operation)
        self.assertEqual(before, self.snapshot())
        self.assertIsNone(self.store.pending())

    def test_cancel_staged_artifacts_still_requires_status_authentication(self):
        operation, _, _ = self.staged()
        with patch.object(staging, "verify_stage", autospec=True) as verify:
            result = operations.cancel(self.registry, operation, confirmation="CANCEL-MAINTENANCE " + operation)
        self.assertEqual(result["phase"], "cancelled")
        self.assertTrue(result["artifacts_authenticated"])
        verify.assert_called_once()

    def test_no_recipe_apply_is_blocked_before_locks_writes_or_native_calls(self):
        operation, _, _ = self.interrupted()
        before = self.snapshot()
        with patch.object(self.registry, "locked", side_effect=AssertionError("must gate before lock")), \
                patch.object(Store, "_put", side_effect=AssertionError("must gate before writes")), \
                patch("subprocess.run", side_effect=AssertionError("no native execution")), \
                patch("subprocess.Popen", side_effect=AssertionError("no native execution")):
            with self.assertRaisesRegex(ValueError, "no reviewed.*recipe"):
                operations.apply(self.registry, operation)
            report = operations.assess_recovery(self.registry, operation)
        self.assertFalse(report["restore_eligible"])
        self.assertTrue(report["blockers"])
        self.assertEqual(before, self.snapshot())
        self.assertIsNone(self.store.pending())
        self.assert_no_native()

    def test_changed_network_record_refuses_save_and_stage_without_rebase(self):
        plan, reference = self.save()
        atomic_write(self.transaction / "pf-filter.expected", "changed managed rules\n")
        before = self.snapshot()
        with patch.object(staging, "stage", side_effect=AssertionError("stale")):
            with self.assertRaisesRegex(ValueError, "stale"):
                operations.save_plan(self.registry, {**plan, "plan_id": None}, confirmation="SAVE-MAINTENANCE cloud")
            with self.assertRaisesRegex(ValueError, "stale"):
                operations.stage_plan(self.registry, plan["plan_id"], self.packages,
                                      confirmation="STAGE-MAINTENANCE " + plan["plan_id"])
        self.assertEqual(before, self.snapshot())
        self.assertEqual(operations.load_plan(self.store, plan["plan_id"]), (plan, reference))

    def test_identical_network_records_at_another_committed_target_still_stale(self):
        plan, _ = self.save()
        replacement = self.registry.root / "transactions/replacement"
        replacement.mkdir(mode=0o700)
        for name in operations.NETWORK_RECORDS:
            atomic_write(replacement / name, (self.transaction / name).read_text())
        self.active.unlink()
        self.active.symlink_to(replacement)
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, "stale"):
            operations.stage_plan(self.registry, plan["plan_id"], self.packages,
                                  confirmation="STAGE-MAINTENANCE " + plan["plan_id"])
        self.assertEqual(before, self.snapshot())

    def test_binding_change_during_stage_keeps_artifacts_but_never_marks_staged(self):
        plan, _ = self.save()
        def drift(*args, **kwargs):
            receipt = self.stage_receipt(*args, **kwargs)
            atomic_write(self.transaction / "pf-nat.expected", "changed during staging\n")
            return receipt
        with patch.object(staging, "stage", autospec=True, side_effect=drift), \
                patch.object(staging, "verify_stage", autospec=True) as verify:
            with self.assertRaisesRegex(ValueError, "Artifact staging failed"):
                operations.stage_plan(self.registry, plan["plan_id"], self.packages,
                                      confirmation="STAGE-MAINTENANCE " + plan["plan_id"])
        verify.assert_not_called()
        operation_path = next((self.registry.root / "maintenance/operations").glob("*/operation.json"))
        value, retained, journal = operations.load_operation(self.registry, operation_path.parent.name)
        self.assertEqual(retained, plan)
        self.assertEqual(journal.read()["phase"], "recovery-required")
        self.assertNotIn("artifacts", journal.read()["evidence"])
        self.assertTrue((operation_path.parent / "artifacts/manifest.json").exists())
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, "stale"):
            operations.continue_staging(self.registry, value["operation"], self.packages,
                                        confirmation="CONTINUE-MAINTENANCE " + value["operation"])
        self.assertEqual(before, self.snapshot())
        self.assertIsNone(self.store.pending())

    def test_plan_cannot_inject_recipe_authority_or_incomplete_network_bindings(self):
        plan = self.plan()
        malformed = []
        for key, value in (("recipe", "operator-supplied"), ("native_execution_authorized", True),
                           ("upgrade_execution_authorized", True), ("native_acceptance", "passed")):
            malformed.append({**plan, key: value})
        incomplete = deepcopy(plan)
        del incomplete["bindings"]["network"]["records"][operations.NETWORK_RECORDS[0]]
        malformed.append(incomplete)
        redirected = deepcopy(plan)
        redirected["bindings"]["network"]["records"][operations.NETWORK_RECORDS[0]]["path"] = "instances/cloud/secrets.json"
        malformed.append(redirected)
        before = self.snapshot()
        with patch.object(self.registry, "locked", side_effect=AssertionError("validate first")):
            for candidate in malformed:
                with self.subTest(candidate=candidate["recipe"]), self.assertRaises(ValueError):
                    operations.save_plan(self.registry, candidate, confirmation="SAVE-MAINTENANCE cloud")
        self.assertEqual(before, self.snapshot())

    def test_tampered_saved_plan_cannot_be_rebound_by_continue_cancel_or_status(self):
        operation, plan, reference = self.interrupted()
        plan["bindings"]["executor"]["source_sha256"] = "f" * 64
        atomic_json(self.registry.root / reference["path"], plan)
        before = self.snapshot()
        for call in (
                lambda: operations.operation_status(self.registry, operation),
                lambda: operations.continue_staging(self.registry, operation, self.packages,
                                                     confirmation="CONTINUE-MAINTENANCE " + operation),
                lambda: operations.cancel(self.registry, operation, confirmation="CANCEL-MAINTENANCE " + operation)):
            with self.assertRaises(ValueError):
                call()
        self.assertEqual(before, self.snapshot())

    def test_changed_executor_policy_source_and_artifact_specs_refuse_staging(self):
        plan, _ = self.save()
        changes = (
            patch("installer.maintenance.executor_identity", return_value="f" * 64),
            patch("installer.versions.policy_hash", return_value="f" * 64),
            patch("installer.deploy.source_digest", return_value="f" * 64 + "\n"),
            patch.object(staging, "required_artifacts", return_value=plan["artifacts"][:-1]),
        )
        for changed in changes:
            before = self.snapshot()
            with changed, patch.object(staging, "stage", side_effect=AssertionError("stale")), self.assertRaises(ValueError):
                operations.stage_plan(self.registry, plan["plan_id"], self.packages,
                                      confirmation="STAGE-MAINTENANCE " + plan["plan_id"])
            self.assertEqual(before, self.snapshot())

    def test_changed_graph_refuses_staging_even_when_instance_remains_ready(self):
        plan, _ = self.save()
        with self.registry.locked():
            self.registry.set_status("cloud", "ready", next_action="new graph observation")
        self.assertEqual(self.registry.status("cloud")["state"], "ready")
        self.assertNotEqual(self.store._active(), plan["bindings"]["graph"])
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, "stale"):
            operations.stage_plan(self.registry, plan["plan_id"], self.packages,
                                  confirmation="STAGE-MAINTENANCE " + plan["plan_id"])
        self.assertEqual(before, self.snapshot())

    def test_tampered_retained_versions_lock_is_not_repaired_or_staged(self):
        plan, _ = self.save()
        path = self.registry.evidence_path("cloud", "versions.json")
        changed = deepcopy(self.versions)
        next(iter(changed["packages"]["host"].values()))["checksum"] = "f" * 64
        atomic_json(path, changed)
        before = self.snapshot()
        self.assertEqual(operations.assess(self.registry, "cloud")["status"], "blocked")
        with self.assertRaises(ValueError):
            operations.stage_plan(self.registry, plan["plan_id"], self.packages,
                                  confirmation="STAGE-MAINTENANCE " + plan["plan_id"])
        self.assertEqual(before, self.snapshot())

    def test_continue_and_cancel_require_original_executor_and_preserve_failed_operation(self):
        operation, _, _ = self.interrupted()
        before = self.snapshot()
        with patch("installer.maintenance.executor_identity", return_value="f" * 64):
            with self.assertRaisesRegex(ValueError, "original executor|original retained executor"):
                operations.continue_staging(self.registry, operation, self.packages,
                                            confirmation="CONTINUE-MAINTENANCE " + operation)
            with self.assertRaisesRegex(ValueError, "original executor"):
                operations.cancel(self.registry, operation, confirmation="CANCEL-MAINTENANCE " + operation)
        self.assertEqual(before, self.snapshot())

    def test_pending_network_restore_initialization_and_lifecycle_work_block_new_plans(self):
        proposed = self.plan()
        for filename, record in (("restore.json", {"state": "running"}),
                                 ("initialization.json", {"state": "prepared"})):
            path = self.fixture.path / filename
            atomic_json(path, record)
            try:
                before = self.snapshot()
                with self.subTest(filename=filename):
                    self.assertEqual(operations.assess(self.registry, "cloud")["status"], "blocked")
                    with self.assertRaises(ValueError):
                        operations.save_plan(self.registry, proposed, confirmation="SAVE-MAINTENANCE cloud")
                    self.assertEqual(before, self.snapshot())
            finally:
                path.unlink()
        pending = self.registry.root / "transactions/pending-test"
        pending.mkdir(mode=0o700)
        atomic_json(pending / "firewall-transition.json", {"pending": True})
        self.assertEqual(operations.assess(self.registry, "cloud")["status"], "blocked")
        atomic_write(pending / "firewall-rolled-back", "rolled back\n")
        self.assertEqual(operations.assess(self.registry, "cloud")["status"], "staging-only")
        self.store.begin("pending-enroll", "enroll", ["cloud"], "e" * 64)
        before = self.snapshot()
        self.assertEqual(operations.assess(self.registry, "cloud")["status"], "blocked")
        with self.assertRaises(ValueError):
            operations.save_plan(self.registry, proposed, confirmation="SAVE-MAINTENANCE cloud")
        self.assertEqual(before, self.snapshot())

    def test_nonready_managed_instance_blocks_assessment(self):
        with self.registry.locked():
            self.registry.set_status("cloud", "failed")
        before = self.snapshot()
        report = operations.assess(self.registry, "cloud")
        self.assertEqual(report["status"], "blocked")
        self.assertIsNone(report["plan"])
        self.assertEqual(before, self.snapshot())

    def test_assessment_and_staging_diagnostics_never_echo_exception_secrets(self):
        secret = "private-database-password-DO-NOT-DISCLOSE"
        with patch.object(operations, "bindings", side_effect=ValueError(secret)), \
                patch("sys.stdout", new_callable=io.StringIO) as stdout, \
                patch("sys.stderr", new_callable=io.StringIO) as stderr:
            report = operations.assess(self.registry, "cloud")
        self.assertNotIn(secret, json.dumps(report) + stdout.getvalue() + stderr.getvalue())
        operation, _, _ = self.interrupted()
        retained = b"\n".join(path.read_bytes() for path in
                              (self.registry.root / f"maintenance/operations/{operation}").rglob("*.json"))
        self.assertNotIn(b"private-stage-password-DO-NOT-DISCLOSE", retained)


if __name__ == "__main__":
    unittest.main()
