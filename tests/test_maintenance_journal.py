"""Offline phase/crash contracts; pure records are never native authority."""

from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from installer import maintenance_journal as journal
from installer.generations import Store
from installer.state import Registry


REFERENCE = {"path": "evidence/proof.json", "sha256": "a" * 64}


def advance(record, phase):
    return journal.transition(record, phase, {key: REFERENCE for key in journal.REQUIRED.get(phase, ())})


def through(phase):
    value = journal.initial(REFERENCE)
    if phase == "staging":
        return value
    for step in ("staged", "approved", "draining", "quiesced", "recovery-ready", "validating",
                 "committed-closed", "opening", "complete"):
        value = advance(value, step)
        if phase == step:
            return value
    raise AssertionError(phase)


class PhaseTests(unittest.TestCase):
    def test_native_recipe_catalog_is_empty(self):
        self.assertEqual(journal.REVIEWED_NATIVE_RECIPES, {})
        for recipe in (None, "current", "force", "recovery-only"):
            with self.assertRaisesRegex(ValueError, "no reviewed"):
                journal.require_native_recipe({"recipe": recipe, "execution_authorized": True})

    def test_publication_marker_precedes_opening_and_survives_failure(self):
        closed = through("committed-closed")
        self.assertFalse(closed["publication_may_have_begun"])
        opened = advance(closed, "opening")
        self.assertTrue(opened["publication_may_have_begun"])
        failed = journal.failure(opened, "interrupted")
        with self.assertRaises(ValueError):
            advance(failed, "restoring")
        finished = advance(failed, "complete")
        self.assertTrue(finished["publication_may_have_begun"])
        self.assertFalse(closed["publication_may_have_begun"])

    def test_recovery_opening_can_only_finalize_not_repeat_restore(self):
        value = advance(through("recovery-ready"), "restoring")
        value = advance(value, "restored-closed")
        self.assertFalse(value["recovery_publication_may_have_begun"])
        value = advance(value, "recovery-opening")
        failed = journal.failure(value, "interrupted")
        self.assertTrue(failed["recovery_publication_may_have_begun"])
        for phase in ("restoring", "restored-closed", "recovery-opening", "cancelled"):
            with self.subTest(phase=phase), self.assertRaises(ValueError):
                advance(failed, phase)
        self.assertEqual(advance(failed, "recovered")["phase"], "recovered")

    def test_every_transition_requires_fresh_evidence(self):
        for current, destinations in journal.EDGES.items():
            record = journal.initial(REFERENCE)
            record.update(phase=current, last_safe_phase=current)
            record["publication_may_have_begun"] = current == "opening"
            record["recovery_publication_may_have_begun"] = current == "recovery-opening"
            record["evidence"] = {key: REFERENCE for key in journal.EVIDENCE_KEYS}
            for destination in destinations:
                if journal.REQUIRED.get(destination):
                    with self.subTest(current=current, destination=destination), self.assertRaisesRegex(ValueError, "evidence"):
                        journal.transition(record, destination)

    def test_cancellation_after_drain_requires_original_service_proof(self):
        value = through("quiesced")
        with self.assertRaisesRegex(ValueError, "evidence"):
            journal.transition(value, "cancelled")
        result = journal.transition(value, "cancelled", {key: REFERENCE for key in
                                    ("original_services", "consistency", "closure_removed")})
        self.assertEqual(result["phase"], "cancelled")

    def test_closure_loss_and_ambiguous_publication_cannot_roll_back(self):
        for code in ("closure-lost", "publication-uncertain"):
            value = journal.failure(through("recovery-ready"), code)
            self.assertTrue(value["publication_may_have_begun"])
            with self.assertRaisesRegex(ValueError, "Publication"):
                advance(value, "restoring")
        value = journal.failure(through("staging"), "closure-lost")
        with self.assertRaisesRegex(ValueError, "Publication"):
            journal.transition(value, "cancelled")

    def test_terminal_phases_never_replay(self):
        for phase in journal.TERMINAL:
            value = journal.initial(REFERENCE)
            value.update(phase=phase, last_safe_phase=phase,
                         publication_may_have_begun=phase == "complete",
                         recovery_publication_may_have_begun=phase == "recovered")
            with self.subTest(phase=phase), self.assertRaises(ValueError):
                journal.failure(value, "interrupted")
            with self.assertRaises(ValueError):
                advance(value, "restoring")

    def test_destructive_attempt_uncertain_not_replayed(self):
        value = journal.start_step(through("recovery-ready"), "rollback-one", replay="never", precondition=REFERENCE)
        value = journal.failure(value, "restore-failed")
        self.assertEqual(value["steps"]["rollback-one"]["state"], "uncertain")
        with self.assertRaisesRegex(ValueError, "cannot be replayed"):
            journal.start_step(value, "rollback-one", replay="never", precondition=REFERENCE)
        with self.assertRaises(ValueError):
            journal.complete_step(value, "rollback-one", REFERENCE)

    def test_idempotent_retry_and_observed_completion(self):
        value = journal.start_step(through("staging"), "copy", replay="idempotent", precondition=REFERENCE)
        value = journal.failure(value, "staging-failed")
        value = advance(value, "staging")
        value = journal.start_step(value, "copy", replay="idempotent", precondition=REFERENCE)
        self.assertEqual(value["steps"]["copy"]["attempts"], 2)
        value = journal.complete_step(value, "copy", REFERENCE)
        with self.assertRaises(ValueError):
            journal.start_step(value, "copy", replay="idempotent", precondition=REFERENCE)

    def test_running_or_uncertain_steps_prevent_open_and_commit(self):
        for current, destination in (("validating", "committed-closed"), ("committed-closed", "opening")):
            value = journal.start_step(through(current), "check", replay="never", precondition=REFERENCE)
            with self.subTest(destination=destination), self.assertRaisesRegex(ValueError, "steps"):
                advance(value, destination)

    def test_strict_fields_markers_and_redacted_error_codes(self):
        value = through("opening")
        for change in ({"schema_version": True}, {"publication_may_have_begun": False},
                       {"last_safe_phase": "staging"}, {"error": "private-secret"}, {"extra": True},
                       {"phase": []}, {"sequence": True}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                journal.validate({**value, **change})
        with self.assertRaises(ValueError):
            journal.failure(value, "credential contents")
        with self.assertRaises(ValueError):
            journal.transition(through("staging"), "staged", {"password": REFERENCE})


class PersistedJournalTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="m3-journal-")
        self.addCleanup(temporary.cleanup)
        self.registry = Registry(Path(temporary.name) / "state")
        self.registry.initialize()
        self.store = Store(self.registry.root)
        self.store._mkdir("maintenance/operations/maint-test")
        ref = self.store._put("maintenance/operations/maint-test/operation.json", {"recipe": None})
        self.journal = journal.OperationJournal(self.registry, "maint-test", ref)
        self.proof = self.store._put("maintenance/operations/maint-test/proof.json", {"verified": True})

    def test_writes_require_global_lock(self):
        with self.assertRaises(ValueError):
            self.journal.initialize()
        with self.registry.locked():
            self.journal.initialize()
        with self.assertRaises(ValueError):
            self.journal.advance("cancelled")

    def test_stage_does_not_publish_global_pending_and_native_is_blocked(self):
        with self.registry.locked():
            self.journal.initialize()
            self.journal.advance("staged", {"artifacts": self.proof})
            with self.assertRaisesRegex(ValueError, "no reviewed"):
                self.journal.advance("approved", {"approval": self.proof, "admission": self.proof})
        self.assertIsNone(self.store.pending())
        self.assertEqual(self.journal.read()["phase"], "staged")

    def test_cancelled_terminal_is_idempotent_and_immutable(self):
        with self.registry.locked():
            self.journal.initialize()
            self.journal.advance("cancelled")
            ref = self.journal.terminal()
            self.assertEqual(self.journal.terminal(), ref)
            with self.assertRaises(ValueError):
                self.journal.fail("interrupted")
        record = deepcopy(self.journal.read())
        record["sequence"] += 1
        self.store._put(self.journal.path, record, replace=True)
        with self.assertRaisesRegex(ValueError, "terminal changed"):
            self.journal.read()

    def test_crash_before_terminal_can_finalize_without_repeating_effects(self):
        with self.registry.locked():
            self.journal.initialize()
            self.journal.advance("cancelled")
        with self.registry.locked():
            self.journal.terminal()
        self.assertEqual(self.journal.read()["phase"], "cancelled")

    def test_evidence_and_step_observations_remain_hash_bound(self):
        with self.registry.locked():
            self.journal.initialize()
            self.journal.step_start("copy", replay="idempotent", precondition=self.proof)
            self.journal.step_complete("copy", self.proof)
        self.store._put(self.proof["path"], {"changed": True}, replace=True)
        with self.assertRaises(ValueError):
            self.journal.read()


def native_advance(record, phase, **evidence):
    supplied = {key: REFERENCE for key in journal.NATIVE_REQUIRED.get(phase, ())}
    supplied.update(evidence)
    return journal.native_transition(record, phase, supplied)


def native_through(phase):
    value = journal.native_initial(REFERENCE, REFERENCE, "b" * 64)
    if phase == "capture":
        return value
    for step in ("quiesced", "recovery-ready", "migrating", "validating", "committed-closed", "opening", "complete"):
        value = native_advance(value, step)
        if phase == step:
            return value
    raise AssertionError(phase)


class NativePhaseTests(unittest.TestCase):
    def test_offline_acknowledgement_is_distinct_from_automatic_drain(self):
        record = native_through("capture")
        evidence = {key: REFERENCE for key in journal.NATIVE_REQUIRED["quiesced"]}
        del evidence["offline_acknowledgement"]
        with self.assertRaisesRegex(ValueError, "evidence"):
            journal.native_transition(record, "quiesced", evidence)
        with self.assertRaisesRegex(ValueError, "evidence"):
            journal.native_transition(record, "quiesced", {**evidence, "drain": REFERENCE})
        closed = native_advance(record, "quiesced")
        self.assertIn("offline_acknowledgement", closed["evidence"])
        self.assertNotIn("drain", closed["evidence"])
        self.assertEqual(record["phase"], "capture")
        with self.assertRaises(ValueError):
            journal.validate(closed)
        with self.assertRaises(ValueError):
            journal.native_validate(through("quiesced"))

    def test_pre_capture_failure_cancels_only_after_original_services_reconciliation(self):
        for phase in ("capture", "quiesced"):
            failed = journal.native_failure(native_through(phase), "capture-failed")
            with self.assertRaises(ValueError):
                native_advance(failed, "restoring")
            with self.assertRaisesRegex(ValueError, "evidence"):
                journal.native_transition(failed, "cancelled")
            cancelled = native_advance(failed, "cancelled")
            self.assertEqual(cancelled["history"][-2]["error"], "capture-failed")
            self.assertEqual(cancelled["history"][-1]["evidence"]["original_services"], REFERENCE)

    def test_uncertain_migration_requires_restore_and_preserves_original_attempt(self):
        started = journal.native_start_step(native_through("migrating"), "migration", replay="never", precondition=REFERENCE)
        failed = journal.native_failure(started, "migration-failed")
        for phase in ("migrating", "validating", "cancelled"):
            with self.subTest(phase=phase), self.assertRaises(ValueError):
                native_advance(failed, phase)
        with self.assertRaises(ValueError):
            journal.native_start_step(failed, "migration", replay="never", precondition=REFERENCE)
        restoring = native_advance(failed, "restoring")
        with self.assertRaisesRegex(ValueError, "steps"):
            native_advance(restoring, "restored-closed")
        reconciled = journal.native_supersede_steps(restoring, REFERENCE)
        step = reconciled["steps"]["migration"]
        self.assertEqual((step["state"], step["attempts"], step["recovery"]), ("superseded", 1, REFERENCE))
        self.assertEqual(reconciled["history"][:len(started["history"])], started["history"])
        self.assertEqual(reconciled["history"][-1]["event"], "supersede")
        self.assertEqual(reconciled["history"][-3]["error"], "migration-failed")
        native_advance(reconciled, "restored-closed")

    def test_partial_restore_retries_only_pinned_members_and_observed_completion(self):
        value = native_advance(native_through("migrating"), "restoring")
        value = journal.native_start_step(value, "restore-app", replay="idempotent", precondition=REFERENCE)
        value = journal.native_complete_step(value, "restore-app", REFERENCE)
        value = journal.native_start_step(value, "restore-db", replay="idempotent", precondition=REFERENCE)
        value = journal.native_failure(value, "restore-failed")
        with self.assertRaises(ValueError):
            journal.native_complete_step(value, "restore-db", REFERENCE)
        changed = {**REFERENCE, "sha256": "c" * 64}
        with self.assertRaisesRegex(ValueError, "pinned"):
            native_advance(value, "restoring", restore_assessment=changed)
        value = native_advance(value, "restoring")
        with self.assertRaises(ValueError):
            journal.native_start_step(value, "restore-db", replay="idempotent", precondition=changed)
        with self.assertRaisesRegex(ValueError, "Incomplete restore"):
            journal.native_supersede_steps(value, REFERENCE)
        for member in ("restore-app", "restore-db"):
            value = journal.native_start_step(value, member, replay="idempotent", precondition=REFERENCE)
            with self.assertRaises(ValueError):
                journal.native_complete_step(value, member, None)
            value = journal.native_complete_step(value, member, REFERENCE)
            self.assertEqual(value["steps"][member]["attempts"], 2)
        native_advance(value, "restored-closed")
        self.assertEqual(sum(event["event"] == "step-start" for event in value["history"]), 4)

    def test_restored_validation_cannot_repeat_dataset_restore(self):
        value = native_advance(native_through("migrating"), "restoring")
        value = native_advance(value, "restored-closed")
        with self.assertRaises(ValueError):
            native_advance(value, "recovery-opening")
        failed = journal.native_failure(value, "interrupted")
        with self.assertRaises(ValueError):
            native_advance(failed, "restoring")
        validating = native_advance(failed, "recovery-validating")
        validating = journal.native_start_step(validating, "canary", replay="idempotent", precondition=REFERENCE)
        failed = journal.native_failure(validating, "validation-failed")
        with self.assertRaises(ValueError):
            native_advance(failed, "restoring")
        # Reconcile the uncertain validation attempt under the same permission.
        continued = native_advance(failed, "recovery-validating")
        continued = journal.native_start_step(continued, "canary", replay="idempotent", precondition=REFERENCE)
        continued = journal.native_complete_step(continued, "canary", REFERENCE)
        native_advance(continued, "recovery-opening")

    def test_both_publication_boundaries_are_durable_and_forbid_rollback(self):
        normal = native_through("opening")
        recovered = native_advance(native_through("migrating"), "restoring")
        for phase in ("restored-closed", "recovery-validating", "recovery-opening"):
            recovered = native_advance(recovered, phase)
        for value, marker, terminal in ((normal, "publication_may_have_begun", "complete"),
                                        (recovered, "recovery_publication_may_have_begun", "recovered")):
            self.assertTrue(value[marker])
            failed = journal.native_failure(value, "interrupted")
            for destination in ("restoring", "restored-closed", "cancelled"):
                with self.assertRaises(ValueError):
                    native_advance(failed, destination)
            self.assertTrue(native_advance(failed, terminal)[marker])
            with self.assertRaises(ValueError):
                journal.native_validate({**failed, marker: False})

    def test_history_is_bounded_not_silently_pruned_and_errors_are_codes_only(self):
        value = native_through("quiesced")
        with patch.object(journal, "MAX_NATIVE_HISTORY", len(value["history"])):
            with self.assertRaisesRegex(ValueError, "history"):
                journal.native_failure(value, "interrupted")
        with self.assertRaises(ValueError):
            journal.native_failure(value, "private command output")
        changed = deepcopy(value)
        changed["history"][0]["sequence"] = True
        with self.assertRaises(ValueError):
            journal.native_validate(changed)
        with self.assertRaises(ValueError):
            journal.native_validate({**value, "force": True})

    def test_snapshot_binding_cannot_change_during_migration(self):
        value = native_through("recovery-ready")
        changed = {**REFERENCE, "sha256": "c" * 64}
        with self.assertRaisesRegex(ValueError, "pinned"):
            native_advance(value, "migrating", recovery_set=changed)

    def test_reclosure_preserves_uncertain_migration_and_allows_only_closed_recovery(self):
        started = journal.native_start_step(native_through("migrating"), "migration", replay="never", precondition=REFERENCE)
        value = native_advance(started, "recovery-reclosing")
        self.assertEqual(value["steps"]["migration"]["state"], "uncertain")
        self.assertEqual(value["history"][:len(started["history"])], started["history"])
        value = journal.native_start_step(value, "reclose-one", replay="never", precondition=REFERENCE)
        failed = journal.native_failure(value, "reconciliation-failed")
        for target in ("migrating", "validating", "restoring", "opening", "recovery-opening"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                native_advance(failed, target)
        closed = native_advance(failed, "recovery-reclosed")
        self.assertEqual(closed["steps"]["reclose-one"]["state"], "uncertain")
        for target in ("migrating", "validating", "opening", "recovery-opening"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                native_advance(closed, target)
        restoring = native_advance(closed, "restoring")
        with self.assertRaises(ValueError):
            native_advance(restoring, "restored-closed")
        restored = journal.native_supersede_steps(restoring, REFERENCE)
        native_advance(restored, "restored-closed")
        self.assertTrue(all(step["state"] == "superseded" for step in restored["steps"].values()))

    def test_original_restore_consent_allows_discarding_failed_reclosure_only(self):
        started = journal.native_start_step(native_through("migrating"), "migration", replay="never", precondition=REFERENCE)
        value = native_advance(started, "recovery-reclosing")
        value = journal.native_start_step(value, "reclose-one", replay="never", precondition=REFERENCE)
        failed = journal.native_failure(value, "reconciliation-failed")
        with self.assertRaises(ValueError):
            native_advance(failed, "restoring")
        restoring = native_advance(failed, "restoring", original_restore_consent=REFERENCE)
        self.assertEqual(restoring["history"][:-1], failed["history"])
        self.assertTrue(all(step["state"] == "uncertain" for step in restoring["steps"].values()))
        with self.assertRaises(ValueError):
            native_advance(restoring, "restored-closed")
        restored = native_advance(journal.native_supersede_steps(restoring, REFERENCE), "restored-closed")
        for value in (restored, native_advance(restored, "recovery-validating"),
                      journal.native_failure(failed, "publication-uncertain")):
            with self.assertRaises(ValueError):
                native_advance(value, "restoring", original_restore_consent=REFERENCE)

    def test_reclosure_never_admits_uncaptured_partial_restore_or_publication(self):
        for source in ("capture", "quiesced", "restoring", "restored-closed", "recovery-validating", "opening", "recovery-opening"):
            if source in ("restoring", "restored-closed", "recovery-validating", "recovery-opening"):
                value = native_advance(native_through("migrating"), "restoring")
                path = ("restoring", "restored-closed", "recovery-validating", "recovery-opening")
                for phase in path[1:path.index(source) + 1]:
                    value = native_advance(value, phase)
            else:
                value = native_through(source)
            with self.subTest(source=source), self.assertRaises(ValueError):
                native_advance(value, "recovery-reclosing")
        for marker in ("publication_may_have_begun", "recovery_publication_may_have_begun"):
            value = native_through("migrating")
            value[marker] = True
            with self.assertRaises(ValueError):
                native_advance(value, "recovery-reclosing")


class NativePersistedJournalTests(unittest.TestCase):
    def setUp(self):
        # Exercise the real NativeState input validation, with offline fixtures.
        from test_maintenance_state import NativeStateTests
        self.fixture = NativeStateTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.registry, self.store = self.fixture.registry, self.fixture.store
        self.operation = self.fixture.operation
        with self.registry.locked(recovery=True):
            self.fixture.begin()
        self.reference = self.store.reference(f"maintenance/operations/{self.operation}/intent.json")
        self.journal = journal.NativeJournal(self.registry, self.operation, self.reference,
            self.fixture.recipe, native=self.fixture.native)
        self.proof = self.store._put(f"maintenance/operations/{self.operation}/proof.json", {"verified": True})

    def advance(self, phase):
        return self.journal.advance(phase, {key: self.proof for key in journal.NATIVE_REQUIRED.get(phase, ())})

    def test_lock_and_exact_external_recipe_are_required_without_admission_override(self):
        with self.assertRaises(ValueError):
            self.journal.initialize()
        with self.registry.locked(recovery=True):
            wrong = journal.NativeJournal(self.registry, self.operation, self.reference,
                {**self.fixture.recipe, "source_sha256": "f" * 64}, native=self.fixture.native)
            with self.assertRaisesRegex(ValueError, "recipe"):
                wrong.initialize()
            self.assertFalse(self.store._present(self.journal.path))
            self.journal.initialize()
            self.assertEqual(self.journal.read()["inputs"], self.fixture.native.read(self.operation)[0]["inputs"])
        with self.assertRaises(ValueError):
            self.journal.read()
        self.assertEqual(journal.REVIEWED_NATIVE_RECIPES, {})

    def test_fixed_implementation_descriptor_must_match_on_every_read(self):
        class Candidate:
            def __init__(self, descriptor):
                self.value = deepcopy(descriptor)

            def descriptor(self):
                return self.value

        candidate = Candidate(self.fixture.recipe)
        record = journal.NativeJournal(self.registry, self.operation, self.reference,
            candidate, native=self.fixture.native)
        with self.registry.locked(recovery=True):
            record.initialize()
            candidate.value["id"] = "changed-implementation"
            with self.assertRaisesRegex(ValueError, "recipe"):
                record.read()

    def test_native_terminal_is_separate_immutable_and_crash_repeatable(self):
        with self.registry.locked(recovery=True):
            self.journal.initialize()
            self.advance("cancelled")
        with self.registry.locked(recovery=True):
            reference = self.journal.terminal()
            self.assertEqual(self.journal.terminal(), reference)
            self.assertEqual(reference["path"], f"maintenance/operations/{self.operation}/native-terminal.json")
            self.assertFalse(self.store._present(f"maintenance/operations/{self.operation}/terminal.json"))
            with self.assertRaises(ValueError):
                self.journal.fail("interrupted")
            self.fixture.native.finish(self.operation, "cancelled")
        self.assertIsNone(self.store.pending())
        self.assertTrue(self.store._present(f"maintenance/operations/{self.operation}/terminal.json"))

    def test_changed_old_history_evidence_fails_even_after_current_evidence_is_replaced(self):
        second = self.store._put(f"maintenance/operations/{self.operation}/second.json", {"verified": "later"})
        with self.registry.locked(recovery=True):
            self.journal.initialize()
            self.journal.advance("quiesced", {**{key: second for key in journal.NATIVE_REQUIRED["quiesced"]},
                                              "closure": self.proof})
            self.journal.advance("recovery-ready", {"recovery_set": second, "closure": second})
            self.assertNotIn(self.proof, self.journal.read()["evidence"].values())
            self.store._put(self.proof["path"], {"changed": True}, replace=True)
            with self.assertRaises(ValueError):
                self.journal.read()

    def test_terminal_hash_detects_changed_checkpoint(self):
        with self.registry.locked(recovery=True):
            self.journal.initialize()
            self.advance("cancelled")
            self.journal.terminal()
            value = self.journal.read()
            value["updated"] = "changed"
            self.store._put(self.journal.path, value, replace=True)
            with self.assertRaisesRegex(ValueError, "terminal changed"):
                self.journal.read()

    def test_missing_or_changed_observation_cannot_become_a_completed_restore(self):
        with self.registry.locked(recovery=True):
            self.journal.initialize()
            for phase in ("quiesced", "recovery-ready", "migrating", "restoring"):
                self.advance(phase)
            self.journal.step_start("restore-app", replay="idempotent", precondition=self.proof)
            missing = {"path": f"maintenance/operations/{self.operation}/missing.json", "sha256": "d" * 64}
            with self.assertRaises((ValueError, OSError)):
                self.journal.step_complete("restore-app", missing)
            self.assertEqual(self.journal.read()["steps"]["restore-app"]["state"], "running")
            self.journal.step_complete("restore-app", self.proof)
            self.advance("restored-closed")
            self.assertEqual(self.journal.read()["phase"], "restored-closed")


if __name__ == "__main__":
    unittest.main()
