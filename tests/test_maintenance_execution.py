"""Offline coordinator boundaries with real stores/journals/generation schemas.

These are not disposable-FreeBSD acceptance. Archive fixtures replace native
transport; effect-order tests deliberately stop before any real host mutation.
"""

from contextlib import contextmanager
from copy import deepcopy
from dataclasses import asdict
import os
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from installer import maintenance_execution as execution, maintenance_journal as journal
from installer import maintenance_native as native, maintenance_preflight as preflight
from installer.generations import _encode, _hash, _json, descriptor
from installer.state import atomic_json, atomic_write
import test_maintenance_candidate as candidate_fixture
import test_maintenance_generations as generation_fixture


class AdmissionTests(unittest.TestCase):
    def test_every_production_entry_refuses_before_registry_or_runner_access(self):
        self.assertEqual(journal.REVIEWED_NATIVE_RECIPES, {})
        runner, confirm = Mock(), Mock()
        with patch.object(execution, "Store", side_effect=AssertionError("state access before admission")):
            for call, args in ((execution.apply, (object(), runner, "operator-json", "backup", confirm)),
                               (execution.continue_execution, (object(), runner, "execution-x", confirm)),
                               (execution.restore_original, (object(), runner, "execution-x", confirm)),
                               (execution.cancel_execution, (object(), runner, "execution-x", confirm))):
                with self.subTest(entry=call.__name__), self.assertRaisesRegex(ValueError, "no reviewed"):
                    call(*args)
        runner.assert_not_called()
        confirm.assert_not_called()

    def test_consent_is_actual_exact_text_not_a_boolean_or_generated_acknowledgement(self):
        phrase = "OFFLINE OPERATOR BOUND TEXT"
        for value in (True, False, None, "", phrase + " "):
            callback = Mock(return_value=value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                execution._answer(callback, phrase)
            callback.assert_called_once_with(phrase)
        callback = Mock(return_value=phrase)
        self.assertEqual(execution._answer(callback, phrase), phrase)

    def test_missing_backup_destination_refuses_before_source_or_intent(self):
        with patch.object(execution, "Store", side_effect=AssertionError("state access")):
            for destination in (None, "", "backup/../unrelated", "-bad"):
                with self.subTest(destination=destination), self.assertRaises(ValueError):
                    execution.acceptance_apply(object(), Mock(), "maint-invalid", destination, Mock())


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.f = candidate_fixture.CandidateTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)

    def test_load_preserves_exact_bundle_owner_and_does_not_refresh_observations(self):
        captured = self.f.collect(connector_archive=self.f.connector_archive)
        before = self.f.store._bound(captured.reference)
        calls = len(self.f.calls)
        loaded = execution.load_candidate(self.f.store, candidate_fixture.OPERATION)
        self.assertEqual(loaded, captured)
        self.assertEqual(self.f.store._bound(loaded.reference), before)
        self.assertEqual(len(self.f.calls), calls)
        self.assertEqual(loaded.bundle.operation, candidate_fixture.OPERATION)
        self.f.begin.assert_not_called()

    def test_incompatible_capture_refuses_before_first_native_begin(self):
        self.f.collect()  # Missing authenticated connector evidence is ineligible.
        def forbidden_session(registry, runner, *, harness, preparation, candidate):
            raise AssertionError("ineligible candidate reached native session")
        with patch.object(native, "acceptance_session", forbidden_session), self.assertRaises(ValueError):
            execution.acceptance_apply(self.f.registry, Mock(), candidate_fixture.OPERATION, "backup", Mock())
        self.f.begin.assert_not_called()
        self.assertIsNone(self.f.store.pending())

    def test_changed_candidate_bytes_are_not_accepted_as_the_old_receipt(self):
        captured = self.f.collect(connector_archive=self.f.connector_archive)
        value = _json(self.f.store._bound(captured.reference))
        value["bundle"]["operation"] = "execution-unowned"
        atomic_json(self.f.store.root / captured.reference["path"], value)
        with self.assertRaises(ValueError):
            execution.load_candidate(self.f.store, candidate_fixture.OPERATION)
        self.f.begin.assert_not_called()


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.f = generation_fixture.SuccessorTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.registry, self.store = self.f.registry, self.f.store
        self.enterContext(self.registry.locked(recovery=True))
        self.f.begin()
        deployment = SimpleNamespace(config=self.f.config, runner=Mock())
        self.n = native.NativeContext(self.registry, self.f.native, self.f.operation, deployment, {})
        self.n.active = True
        self.ref = self.n.record("offline-test-evidence", {"offline_schema_fixture": True})
        self.n.record("closed-profile", {"offline_schema_fixture": True})
        self.advance("quiesced", "recovery-ready", "migrating", "validating")
        self.successor = self.f.seal()
        self.path = self.registry.root / "instances/cloud/config.json"

    def advance(self, *phases):
        for phase in phases:
            self.n.journal.advance(phase, {key: self.ref for key in journal.NATIVE_REQUIRED[phase]})

    def test_descriptor_transition_precedes_real_graph_commit_preserves_original_files(self):
        before_graph = self.store._active()
        execution.reconcile_descriptor(self.n, self.successor)
        self.assertEqual(_json(self.path.read_bytes()), descriptor("cloud", self.successor))
        self.assertEqual(self.store._active(), before_graph)
        self.assertEqual(self.f.native.view(self.f.operation).load("cloud").nextcloud_exact,
                         self.f.config.nextcloud_exact)
        entries = deepcopy(self.f.entries)
        entries["cloud"]["generation"] = self.successor
        self.f.native.commit_closed(self.f.operation, "validated-closed", "execution-target", entries,
                                   expected_predecessor=before_graph)
        self.assertNotEqual(self.store._active(), before_graph)
        self.assertEqual((self.registry.root / "instances/cloud/deployment.json").read_bytes(), self.f.initial_journal)
        self.assertEqual(self.store._bound(self.store._generation("cloud", self.successor)["originals"]["config"]),
                         self.f.initial_config)

    def test_interrupted_descriptor_write_has_before_record_and_exact_retry(self):
        put = self.n.store._put
        def interrupted(path, value, **kwargs):
            if path == "instances/cloud/config.json":
                self.assertTrue(self.n.store._present(self.n.directory + "/descriptor-successor-before.json"))
                raise OSError("simulated interruption")
            return put(path, value, **kwargs)
        with patch.object(self.n.store, "_put", side_effect=interrupted), self.assertRaises(OSError):
            execution.reconcile_descriptor(self.n, self.successor)
        self.assertEqual(_json(self.path.read_bytes()), descriptor("cloud", self.f.predecessor))
        first = execution.reconcile_descriptor(self.n, self.successor)
        self.assertEqual(execution.reconcile_descriptor(self.n, self.successor), first)

    def test_descriptor_retry_refuses_third_state_and_noncanonical_bytes(self):
        execution.reconcile_descriptor(self.n, self.successor)
        for raw in (_encode({"unrelated": True}), _encode(descriptor("cloud", self.successor)) + b"\n"):
            atomic_write(self.path, raw.decode())
            with self.assertRaises(ValueError):
                execution.reconcile_descriptor(self.n, self.successor)
            self.assertEqual(self.path.read_bytes(), raw)

    def test_restore_reconciles_partial_descriptor_then_commits_new_graph(self):
        base = self.store._active()
        execution.reconcile_descriptor(self.n, self.successor)
        self.advance("restoring", "restored-closed")
        execution.reconcile_descriptor(self.n, self.f.predecessor, restored=True)
        self.assertEqual(_json(self.path.read_bytes()), descriptor("cloud", self.f.predecessor))
        self.assertEqual(self.store._active(), base)
        result = self.f.native.commit_closed(self.f.operation, "restored-closed", "execution-original",
            self.f.entries, expected_predecessor=base)
        self.assertNotEqual(result, base)
        self.assertEqual(_json(self.store._bound(result))["predecessor"], base)
        execution.reconcile_descriptor(self.n, self.f.predecessor, restored=True)

    def test_after_publication_neither_descriptor_change_nor_restore_is_permitted(self):
        self.advance("committed-closed", "opening")
        original = self.path.read_bytes()
        with self.assertRaises(ValueError):
            execution.reconcile_descriptor(self.n, self.successor)
        @contextmanager
        def session(*args, **kwargs):
            yield self.n
        with patch.object(native, "acceptance_session", session), patch.object(execution, "_harness"), \
                patch.object(self.n, "close_for_recovery") as close, self.assertRaises(ValueError):
            execution.acceptance_restore(self.registry, Mock(), self.n.operation, Mock())
        close.assert_not_called()
        self.assertEqual(self.path.read_bytes(), original)

    def test_restored_validation_never_repeats_rollback(self):
        self.advance("restoring", "restored-closed", "recovery-validating")
        @contextmanager
        def session(*args, **kwargs):
            yield self.n
        with patch.object(native, "acceptance_session", session), patch.object(execution, "_harness"), \
                patch.object(self.n, "close_for_recovery") as close, \
                patch.object(self.n, "recover") as rollback, self.assertRaises(ValueError):
            execution.acceptance_restore(self.registry, Mock(), self.n.operation, Mock())
        close.assert_not_called()
        rollback.assert_not_called()

    def test_failure_continuation_never_replays_uncertain_work(self):
        self.n.journal.step_start("reviewed-migration", replay="never", precondition=self.ref)
        self.n.journal.fail("migration-failed")
        self.assertEqual(self.n.journal.read()["steps"]["reviewed-migration"]["state"], "uncertain")
        @contextmanager
        def session(*args, **kwargs):
            yield self.n
        with patch.object(native, "acceptance_session", session), patch.object(execution, "_harness"), \
                patch.object(self.n, "migrate") as migrate, self.assertRaisesRegex(ValueError, "updater replay"):
            execution.acceptance_continue(self.registry, Mock(), self.n.operation, lambda phrase: phrase)
        migrate.assert_not_called()

    def test_opening_uses_forward_publication_session_not_general_native_check(self):
        from installer import maintenance_opening
        self.advance("committed-closed", "opening")
        publication = SimpleNamespace(context=self.n, continue_publication=Mock(return_value=dict(state="complete", ready=True)))
        @contextmanager
        def session(registry, runner, operation):
            self.assertIs(registry, self.registry)
            self.assertEqual(operation, self.n.operation)
            yield publication
        phrase = "CONTINUE-PUBLICATION " + self.n.operation
        with patch.object(maintenance_opening, "publication_session", session), \
                patch.object(native, "acceptance_session", side_effect=AssertionError("wrong continuation session")):
            result = execution.acceptance_continue(self.registry, Mock(), self.n.operation, Mock(return_value=phrase))
        publication.continue_publication.assert_called_once_with(phrase)
        self.assertEqual(result["state"], "complete")
        self.assertFalse(any("path" in key or "secret" in key for key in result))

    def test_export_retains_raw_document_and_requires_verified_rehearsal(self):
        raw = dict(root="backup/private", path="/private/export.json", sha256="a" * 64, size=100)
        verified = dict(evidencecopyverified=True, restorestream_rehearsal=False, receipt=raw)
        rehearsed = dict(verified, restorestream_rehearsal=True)
        with patch.object(execution.export, "export", return_value=raw), \
                patch.object(execution.export, "verify", return_value=verified) as verify, \
                patch.object(execution.export, "rehearse", return_value=rehearsed) as rehearse:
            reference = execution._export(self.n, "backup")
        verify.assert_called_once_with(self.n, raw)
        rehearse.assert_called_once_with(self.n, raw)
        self.assertEqual(set(reference), {"path", "sha256"})
        self.assertEqual(_json(self.store._bound(reference)), raw)
        self.assertEqual(execution._copy_receipt(self.n), reference)

    def test_failed_export_verification_retains_audit_and_cannot_supply_publication_receipt(self):
        raw = dict(root="backup/private", path="/private/export.json", sha256="a" * 64, size=100)
        with patch.object(execution.export, "export", return_value=raw), \
                patch.object(execution.export, "verify", side_effect=ValueError("verification failed")), \
                patch.object(execution.export, "rehearse") as rehearse, self.assertRaises(ValueError):
            execution._export(self.n, "backup")
        rehearse.assert_not_called()
        self.assertEqual(_json(self.store._read(self.n.directory + "/execution-export-receipt.json")), raw)
        with self.assertRaises((ValueError, OSError)):
            execution._copy_receipt(self.n)


class SuccessorProjectionTests(unittest.TestCase):
    """Real cross-module projection/storage contract; native admission is external.

    The lock-scoped check below retains real NativeState/NativeJournal checks but
    does not assert native PF/closure acceptance. Only authenticated-code capture
    and native command responses are substituted; application-manifest parsing,
    package closure, target status, candidate bindings, sealing and commits run.
    """

    def setUp(self):
        self.f = generation_fixture.SuccessorTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.registry, self.store = self.f.registry, self.f.store
        self.enterContext(self.registry.locked(recovery=True))
        # Use an actual preparation-shaped owner, retaining the fixture's exact
        # source-plan references. These offline records grant no native admission.
        self.owner = "maint-" + "a" * 32
        parent = _json(self.store._bound(self.f.preparation))
        parent["operation"] = self.owner
        self.store._mkdir("maintenance/operations/" + self.owner)
        self.f.preparation = self.store._put("maintenance/operations/" + self.owner + "/operation.json", parent)
        self.f.begin()
        deployment = SimpleNamespace(config=self.f.config, runner=Mock())
        self.n = native.NativeContext(self.registry, self.f.native, self.f.operation, deployment, {})
        self.n.active = True
        self.ref = self.n.record("offline-projection-boundary", {"native_acceptance": "not-run"})
        for phase in ("quiesced", "recovery-ready", "migrating", "validating"):
            self.n.journal.advance(phase, {key: self.ref for key in journal.NATIVE_REQUIRED[phase]})

        def checked(*, closed=False):
            self.registry._require_lock(recovery=True)
            intent, inputs = self.f.native.read(self.n.operation)
            record = self.n.journal.read()
            self.assertTrue(closed)
            self.assertFalse(record["publication_may_have_begun"])
            self.assertFalse(record["recovery_publication_may_have_begun"])
            return intent, inputs, record
        self.n.check = checked

        candidate = _json(self.f.evidence["candidate.json"])
        report = preflight.assess(self.f.config, self.f.retained, self.f.observations, self.f.repository,
                                 bindings=candidate["bindings"], now=1010)
        self.assertTrue(report["eligible"])
        self.assertEqual(report["candidate"], candidate)
        update = execution.update
        self.manifest = self.store.root / "target-code/apps/serverinfo/appinfo/info.xml"
        self.manifest.parent.mkdir(parents=True, mode=0o700)
        self.xml = b"<info><id>serverinfo</id><version>7.0.0</version></info>"
        atomic_write(self.manifest, self.xml.decode())
        inventory = update.Inventory((update.FileHash("apps/serverinfo/appinfo/info.xml", len(self.xml), _hash(self.xml)),),
                                     ("", "apps", "apps/serverinfo", "apps/serverinfo/appinfo"))
        context = SimpleNamespace(www_uid=os.geteuid(), host=lambda name:
                                  self.store.root / "target-code" / name.removeprefix(update.APP + "/"))
        bundle = update.StagedUpdate(self.owner, update.SourceReference("a" * 64, "b" * 64),
            tuple(update.FileHash(name, 1, "c" * 64) for name in (*execution.ARTIFACTS.values(), "source-core.crt")),
            inventory, inventory, "c2ln", "d" * 64)
        self.capture = dict(schema_version=1, kind="captured-maintenance-candidate", operation=self.owner,
            preparation=self.f.preparation, plan=parent["plan"], recipe=preflight.recipe(), admission=self.ref,
            bindings=candidate["bindings"], observations=deepcopy(self.f.observations), repository=deepcopy(self.f.repository),
            report=report, observations_sha256=preflight.digest(self.f.observations),
            repository_sha256=preflight.digest(self.f.repository), bundle=asdict(bundle),
            connector_receipt_sha256="e" * 64, execution_authorized=False, native_acceptance="not-run")
        self.capture_path = "maintenance/operations/" + self.owner + "/candidate.json"
        self.bind_capture()
        # Deserialization is real as well; live pre-begin revalidation belongs to
        # the separately tested session and cannot be inferred from this fixture.
        self.assertEqual(execution.load_candidate(self.store, self.owner).bundle, bundle)
        self.apps = {kind: {} for kind in ("enabled", "disabled")}
        for name, item in candidate["apps"].items():
            enabled = self.f.observations["nextcloud"]["apps"][name]["enabled"]
            self.apps["enabled" if enabled else "disabled"][name] = item["version"]
        self.status = _json(self.f.evidence["readiness.json"])["nextcloud"]
        self.packages = deepcopy(self.f.observations["packages"])
        prepared = dict(observations=dict(full_packages=deepcopy(self.packages)))
        self.code = self.enterContext(patch.object(execution.validation, "_code",
            return_value=(prepared, context, inventory, self.ref, self.ref)))
        self.n.backend.occ = Mock(side_effect=self.occ)
        self.n.backend.output = Mock(side_effect=lambda *args: self.package_rows("host", args))
        self.n.backend.jailed = Mock(side_effect=lambda jail, *args: SimpleNamespace(stdout=self.package_rows(
            "nextcloud" if jail == self.f.config.nextcloud_jail else "onlyoffice", args)))
        self.result = dict(schema_version=1, kind="nextcloud-patch-result", operation=self.n.operation,
            prepared=self.ref, receipt_sha256=bundle.receipt_sha256, target=list(update.TARGET),
            runtime=dict(full_packages=deepcopy(self.packages), apps=deepcopy(self.apps), status=deepcopy(self.status)),
            hardened_sha256="f" * 64, custom_sha256="a" * 64, appstore=dict(exists=False, value=False),
            maintenance=True, native_acceptance="not-run", publication_authorized=False)
        self.n.record("update-result", self.result)
        self.effective = _json(self.f.evidence["effective.json"])
        self.effective_ref = self.n.record("observed-effective-workers", self.effective)

    def bind_capture(self):
        self.store._put(self.capture_path, self.capture, replace=self.store._present(self.capture_path))
        reference = self.store.reference(self.capture_path)
        path = self.n.directory + "/candidate-reference.json"
        self.store._put(path, reference, replace=self.store._present(path))

    def package_rows(self, group, args):
        self.assertEqual(args, ("pkg", "query", "%n %v %o"))
        return "\n".join(" ".join(item[key] for key in ("name", "version", "origin")) for item in self.packages[group])

    def occ(self, *args):
        if args == ("status", "--output=json"):
            return _encode(self.status).decode()
        self.assertEqual(args, ("app:list", "--output=json"))
        return _encode(self.apps).decode()

    def project_and_seal(self, files=None):
        files = self.f.target if files is None else files
        evidence = execution._successor_evidence(self.n, self.f.generation, files, self.effective_ref)
        reference = execution.generations.seal_successor(self.f.native, self.n.operation, self.f.generation,
            target_files=files, validation_evidence=evidence)
        return reference, evidence

    def test_real_projection_sealing_registration_and_commit_share_exact_contract(self):
        base = self.store._active()
        reference, evidence = self.project_and_seal()
        self.assertEqual(evidence, self.f.evidence)
        self.assertEqual(set(evidence), {"candidate.json", "review.json", "effective.json", "readiness.json"})
        manifest = self.store._generation("cloud", reference)
        for name, data in evidence.items():
            self.assertIs(type(data), bytes)
            self.assertEqual(self.store._bound(manifest["evidence"][name]), data)
        self.assertEqual(_json(evidence["readiness.json"])["kind"], "nextcloud-successor-readiness")
        self.assertEqual(self.store._active(), base)
        execution.reconcile_descriptor(self.n, reference)
        entries = deepcopy(self.f.entries)
        entries["cloud"]["generation"] = reference
        graph = self.f.native.commit_closed(self.n.operation, "validated-closed", "projected-successor", entries,
                                           expected_predecessor=base)
        self.assertEqual(self.store._active(), graph)
        self.assertEqual(_json(self.store._bound(graph))["instances"]["other"], self.f.entries["other"])
        resolved = self.store._resolve_entry("cloud", entries["cloud"])
        self.assertEqual(resolved.config_document["nextcloud_exact"], "35.0.2")
        self.assertEqual(resolved.manifest, manifest)
        with self.assertRaisesRegex(ValueError, "mutation pending"):
            self.registry.load("cloud")  # Closed commit does not authorize publication.
        self.assertEqual(self.f.native.view(self.n.operation).load("cloud").to_json().encode(), self.f.initial_config)
        self.assertEqual((self.registry.root / "instances/cloud/deployment.json").read_bytes(), self.f.initial_journal)
        self.code.assert_called_once_with(self.n, True)

    def test_candidate_runtime_and_manifest_drift_refuse_before_seal_or_graph(self):
        original_capture = deepcopy(self.capture)
        original_apps, original_packages = deepcopy(self.apps), deepcopy(self.packages)
        original_result, original_status = deepcopy(self.result), deepcopy(self.status)
        descriptor_bytes = (self.registry.root / "instances/cloud/config.json").read_bytes()
        cases = ("candidate-version", "candidate-binding", "captured-source", "live-app", "live-package",
                 "updater-package", "target-status", "source-manifest", "target-manifest", "effective-worker")
        for case in cases:
            with self.subTest(case=case):
                self.capture = deepcopy(original_capture)
                self.apps, self.packages = deepcopy(original_apps), deepcopy(original_packages)
                self.result, self.status = deepcopy(original_result), deepcopy(original_status)
                files, effective = deepcopy(self.f.target), deepcopy(self.effective)
                atomic_write(self.manifest, self.xml.decode())
                candidate = self.capture["report"]["candidate"]
                if case == "candidate-version":
                    candidate["artifacts"]["nextcloud"]["version"] = "35.0.3"
                elif case == "candidate-binding":
                    candidate["bindings"]["generation_sha256"] = "f" * 64
                elif case == "captured-source":
                    self.capture["observations"]["nextcloud"]["version"] = "35.0.0.1"
                elif case == "live-app":
                    self.apps["enabled"]["serverinfo"] = "7.0.1"
                elif case == "live-package":
                    self.packages["nextcloud"][0]["version"] = "99.0.0"
                elif case == "updater-package":
                    self.result["runtime"]["full_packages"]["host"][0]["version"] = "99.0.0"
                elif case == "target-status":
                    self.status["version"] = "35.0.1.1"
                elif case == "source-manifest":
                    atomic_write(self.manifest, self.xml.decode().replace("7.0.0", "6.0.0"))
                elif case == "target-manifest":
                    target = _json(files["versions.json"])
                    target["applications"]["nextcloud"] = "35.0.3"
                    files["versions.json"] = _encode(target)
                else:
                    effective["jails"]["nextcloud"]["files"]["/usr/local/libexec/cloud-runtime-inventory.php"] = "f" * 64
                self.bind_capture()
                self.store._put(self.n.directory + "/update-result.json", self.result, replace=True)
                self.store._put(self.effective_ref["path"], effective, replace=True)
                self.effective_ref = self.store.reference(self.effective_ref["path"])
                with self.assertRaises(ValueError):
                    self.project_and_seal(files)
                self.assertFalse((self.registry.root / "instances/cloud/generations" / self.f.generation).exists())
                self.assertFalse(self.store._present(self.n.directory + "/descriptor-successor-before.json"))
                self.assertEqual(self.store._active(), self.f.base)
                self.assertEqual((self.registry.root / "instances/cloud/config.json").read_bytes(), descriptor_bytes)


class FlowTests(unittest.TestCase):
    def test_explicit_restore_closes_discarded_database_without_clean_restart_path(self):
        n = Mock()
        n.journal.read.return_value = dict(phase="migrating", publication_may_have_begun=False,
                                          recovery_publication_may_have_begun=False)
        n.backend.pair_state.return_value = "running"
        assessment = SimpleNamespace(eligible=True)
        n.assess_original_restore.return_value = assessment
        sessions = []
        @contextmanager
        def session(*args, **kwargs):
            sessions.append(kwargs["operation"])
            yield n
        operation = "execution-test"
        phrase = "RESTORE-ORIGINAL " + operation + " DISCARD-CLOSED-CHANGES"
        with patch.object(native, "acceptance_session", session), patch.object(execution, "_harness"), \
                patch.object(execution, "_validate_original", return_value={"fixture": "validated"}):
            result = execution.acceptance_restore(object(), Mock(), operation, Mock(return_value=phrase))
        self.assertEqual(sessions, [operation, operation])
        n.close_for_original_restore.assert_called_once_with(phrase)
        n.close_for_recovery.assert_not_called()
        n.restore_original.assert_called_once_with(phrase, assessment=assessment)
        self.assertEqual(result, {"fixture": "validated"})

    def test_failed_snapshot_or_export_blocks_migration_after_actual_consent(self):
        for failure in ("capture", "export"):
            events = []
            n = Mock()
            n.c.php_memory_mb = 1024
            n.c.nextcloud_jail = "cloudnc"
            n.directory = "maintenance/operations/execution-fixture"
            from pathlib import Path
            n.d.jail_root.return_value = Path("/private/jail")
            n.check.return_value = ({}, {"cache_owner": "maint-fixture"}, {"phase": "capture"})
            n.offline_phrase.return_value = "OFFLINE-BOUND-CONSENT"
            def event(name):
                def call(*args, **kwargs):
                    events.append(name)
                    if name == failure:
                        raise ValueError("injected failure")
                return call
            n.quiesce.side_effect = event("quiesce")
            n.capture.side_effect = event("capture")
            confirm = Mock(return_value="OFFLINE-BOUND-CONSENT")
            captured = SimpleNamespace(operation="maint-fixture", reference={"fixture": "reference"})
            n.store._read.return_value = _encode(captured.reference)
            with patch.object(execution.patch, "prepare", side_effect=event("prepare")) as prepare, \
                    patch.object(execution, "_export", side_effect=event("export")), self.assertRaises(ValueError):
                execution._execute(n, captured, "backup", confirm)
            self.assertEqual(events, ["prepare", "quiesce", "capture"] + (["export"] if failure == "export" else []))
            n.migrate.assert_not_called()
            confirm.assert_called_once_with("OFFLINE-BOUND-CONSENT")
            n.quiesce.assert_called_once_with("OFFLINE-BOUND-CONSENT")
            self.assertIs(prepare.call_args.kwargs["runner"], execution.bounded_process.run)
            self.assertEqual(prepare.call_args.kwargs["memory_mib"], 1024)
            self.assertIn("maint-fixture", str(prepare.call_args.kwargs["source_asc"]))


if __name__ == "__main__":
    unittest.main()
