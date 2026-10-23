"""Offline cancellation fault tests. Native commands are always mocked."""

from contextlib import nullcontext
from copy import deepcopy
from dataclasses import asdict
import fcntl
import json
import os
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from installer import enrollment, maintenance_cancellation as cancel
from installer import maintenance_journal as journal, maintenance_native as native
from installer.generations import Store, _encode, _hash, _json
import test_maintenance_fence as fence_fixtures
import test_maintenance_update as update_fixtures
import test_nextcloud_update as archive_fixtures
from installer import maintenance_update as adapter, nextcloud_update as update
from test_recovery_sets import FakeNative
from test_state import configuration


BOOT = "{ sec = 1792000000, usec = 1 } original boot"


class CancellationSourceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="cancellation-source-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "config").mkdir()
        self.config = self.root / "config/config.php"
        self.original = b"<?php\n$CONFIG = array (\n  'secret' => 'private',\n  'maintenance' => false,\n);\n"
        self.config.write_bytes(self.original)
        self.config.chmod(0o600)
        (self.root / "occ").write_bytes(b"original executable")
        self.baseline = enrollment._tree_identity(self.root, jail_root=self.root, observed_roots=(self.root,))

    def observed(self, **kwargs):
        return cancel._tree_identity(self.root, jail_root=self.root, observed_roots=(self.root,), **kwargs)

    def test_projection_uses_exact_first_readiness_format_and_only_maintenance_boolean(self):
        self.assertEqual(self.observed(maintenance=True), self.baseline)
        self.config.write_bytes(self.original.replace(b"=> false", b"=> true"))
        self.assertNotEqual(self.observed(), self.baseline)
        self.assertEqual(self.observed(maintenance=True), self.baseline)
        for changed in (self.original.replace(b"private", b"changed"),
                        self.original + b"system('untrusted');\n"):
            self.config.write_bytes(changed)
            self.assertNotEqual(self.observed(maintenance=True), self.baseline)

    def test_code_mode_added_file_and_unknown_config_are_not_adopted(self):
        for change in (lambda: (self.root / "occ").write_bytes(b"modified executable"),
                       lambda: self.config.chmod(0o640),
                       lambda: (self.root / "injected.php").write_bytes(b"code")):
            change()
            self.assertNotEqual(self.observed(maintenance=True), self.baseline)
        for data in (b"<?php require '/unknown';", self.original.replace(b"false", b"getenv('FLAG')"),
                     self.original.replace(b");", b"  'maintenance' => true,\n);")):
            self.config.write_bytes(data)
            with self.assertRaises(ValueError):
                self.observed(maintenance=True)

    def test_partial_profile_accepts_only_persisted_original_or_closed_bytes(self):
        path = self.root / "rc.conf"
        original, closed = b'cron_enable="YES"\n', b'cron_enable="NO"\n'
        path.write_bytes(original)
        baseline = self.observed()
        path.write_bytes(closed)
        self.assertEqual(self.observed(replacements={"rc.conf": (original, closed)}), baseline)
        path.write_bytes(closed + b'unknown="YES"\n')
        with self.assertRaises(ValueError):
            self.observed(replacements={"rc.conf": (original, closed)})

    def test_symlink_escape_refused_without_executing_php(self):
        (self.root / "unknown").symlink_to("/etc/passwd")
        with self.assertRaises(ValueError):
            self.observed(maintenance=True)


class CancellationBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.reference = dict(path="maintenance/operations/execution-test/intent.json", sha256="1" * 64)
        self.inputs = dict(path="maintenance/operations/execution-test/native-inputs.json", sha256="2" * 64)
        self.value = journal.native_initial(self.reference, self.inputs, "3" * 64)
        temporary = tempfile.TemporaryDirectory(prefix="cancellation-records-")
        self.addCleanup(temporary.cleanup)
        self.store = Store(temporary.name)
        self.directory = "maintenance/operations/execution-test"
        self.store._mkdir(self.directory)

    def test_failed_or_uncertain_quiesce_is_eligible_but_updater_attempt_never_is(self):
        started = journal.native_start_step(self.value, "close-writers", replay="never", precondition=self.reference)
        failed = journal.native_failure(started, "capture-failed")
        cancel._history(failed)
        for field in ("publication_may_have_begun", "recovery_publication_may_have_begun"):
            changed = deepcopy(failed)
            changed[field] = True
            with self.assertRaises(ValueError):
                cancel._history(changed)
        for phase in ("recovery-ready", "migrating", "restoring", "validating", "opening"):
            changed = deepcopy(failed)
            changed["last_safe_phase"] = phase
            with self.assertRaises(ValueError):
                cancel._history(changed)
        changed = deepcopy(failed)
        changed["history"][0]["name"] = "reviewed-migration"
        with self.assertRaises(ValueError):
            cancel._history(changed)

    def test_every_updater_attempt_publication_restore_and_successor_file_denied(self):
        for name in ("update-adapter-before.json", "update-code-writable-before.json", "update-updater-before.json",
                     "update-result.json", "native-publication.json", "publication-authorized.json",
                     "descriptor-successor-before.json", "execution-successor.json", "validated-closed.json",
                     "recovery/restore.json", "validation-started.json"):
            path = self.directory + "/" + name
            self.store._mkdir(str(Path(path).parent))
            self.store._put(path, {})
            with self.subTest(name=name), self.assertRaises(ValueError):
                cancel._no_later_effects(self.store, self.directory)
            self.store._path(path).unlink()
        self.store._put(self.directory + "/update-prepared.json", {})
        cancel._no_later_effects(self.store, self.directory)

    def test_partial_capture_retained_but_complete_capture_rejected(self):
        path = self.directory + "/recovery/manifest.json"
        self.store._mkdir(self.directory + "/recovery")
        self.store._put(path, dict(state="prepared", snapshots={"owned@partial": "audit"}))
        before = self.store._read(path)
        cancel._no_later_effects(self.store, self.directory)
        self.assertEqual(self.store._read(path), before)
        self.store._put(path, dict(state="complete"), replace=True)
        with self.assertRaises(ValueError):
            cancel._no_later_effects(self.store, self.directory)

    def test_exact_confirmation_precedes_all_reads_and_effects(self):
        n = Mock(operation="execution-test")
        for value in (None, True, "CANCEL-MAINTENANCE", "CANCEL-MAINTENANCE execution-other",
                      "CANCEL-MAINTENANCE execution-test "):
            with self.subTest(value=value), self.assertRaises(ValueError):
                cancel.cancel(n, value)
        self.assertEqual(n.mock_calls, [])

    def test_request_blocks_other_native_actions_even_if_request_is_incomplete(self):
        n = SimpleNamespace(store=self.store, directory=self.directory)
        cancel.require_no_cancellation(n)
        self.store._put(self.directory + "/cancellation-request.json", {})
        with self.assertRaises(ValueError):
            cancel.require_no_cancellation(n)

    def test_assessment_failure_is_readonly_and_redacts_native_diagnostic(self):
        n = Mock()
        with patch.object(cancel, "_preflight", side_effect=RuntimeError("SECRET")):
            result = cancel.assess(n)
        self.assertFalse(result.eligible)
        self.assertNotIn("SECRET", str(result))
        self.assertEqual(n.mock_calls, [])


class CancellationPreparedRecordsTests(unittest.TestCase):
    """Real prepare + stage_artifacts + RealAuthority.checkpoint, fake native runner."""
    def setUp(self):
        real_stage = update.stage_artifacts
        f = update_fixtures.WorkflowTests()
        f.setUp()
        self.addCleanup(f.doCleanups)
        archives = archive_fixtures.NextcloudUpdateTests()
        archives.setUp()
        self.addCleanup(archives.doCleanups)
        self.f, self.archives = f, archives
        self.enterContext(patch.object(update, "stage_artifacts", real_stage))
        # Reuse authentic-format synthetic archives and the command-only runner;
        # neither the artifact helper nor the durable checkpoint writer is mocked.
        for source, target in ((archives.zip, f.target_zip), (archives.asc, f.home / "target.asc"),
                (archives.sig, f.home / "target.sig"), (archives.source_asc, f.home / "source.asc"),
                (archives.key, f.home / "key"), (archives.context.host(update.RETAINED), f.context.host(update.RETAINED)),
                (archives.context.host(update.SHA_PROOF), f.context.host(update.SHA_PROOF))):
            f.write(target, source.read_bytes())
        for name, content in archives.files.items():
            path = f.context.host(update.APP + "/" + name)
            f.write(path, content)
            path.chmod(0o640)
            parent = path.parent
            app = f.context.host(update.APP)
            while parent == app or app in parent.parents:
                parent.chmod(0o750)
                parent = parent.parent
        f.runner.side_effect = archives.runner
        f.n.journal.reference = f.store.reference(f.n.directory + "/intent.json")
        f.store._put(f.n.directory + "/admission.json", f.n.admission)
        self.data = (f.n.directory, dict(operation=f.n.operation, intent=f.n.journal.reference,
            roots={f.n.c.nextcloud_jail: str(f.root)}), f.n.c, f.inputs, None, None, None)

    def test_actual_successful_prepare_records_and_current_bundle_are_accepted(self):
        prepared = self.f.prepare()
        directory, store = self.f.n.directory, self.f.store
        names = {path.name for path in store._path(directory).iterdir()}
        self.assertTrue({"update-import-release-key-before.json", "update-import-release-key-after.json",
                         "update-progress.json", "update-prepared.json"} <= names)
        cancel._no_later_effects(store, directory)
        cancel._prepared(store, self.data)
        self.assertTrue(all(item["executable"] is False for item in asdict(prepared.bundle)["artifacts"]))
        self.assertEqual(_json(store._bound(_json(store._read(directory + "/update-progress.json"))["effect"]))["event"],
                         "stage-artifacts")

    def test_failed_public_key_import_is_inert_but_retains_actual_attempt(self):
        self.archives.fail = lambda argv, kwargs: update.NativeResult(1) if "--import" in argv else update.NativeResult(0)
        with self.assertRaises(ValueError):
            self.f.prepare()
        store, directory = self.f.store, self.f.n.directory
        self.assertTrue(store._present(directory + "/update-import-release-key-before.json"))
        self.assertFalse(store._present(directory + "/update-import-release-key-after.json"))
        self.assertFalse(store._present(directory + "/update-prepared.json"))
        cancel._no_later_effects(store, directory)
        cancel._prepared(store, self.data)

    def test_real_progress_never_hides_an_updater_attempt(self):
        self.f.prepare()
        authority = adapter.RealAuthority(self.f.n, runner=self.f.runner)
        authority.checkpoint(authority.context, "updater", "before", "a" * 64)
        with self.assertRaises(ValueError):
            cancel._no_later_effects(self.f.store, self.f.n.directory)

    def test_progress_foreign_effect_or_broken_before_binding_refused(self):
        self.f.prepare()
        store, directory = self.f.store, self.f.n.directory
        for name, change in (("update-progress.json", lambda v: v.update(operation="execution-other")),
                ("update-progress.json", lambda v: v.update(effect=store.reference(directory + "/update-prepared.json"))),
                ("update-import-release-key-after.json", lambda v: v.update(binding="0" * 64))):
            path = directory + "/" + name
            saved = store._read(path)
            value = _json(saved)
            change(value)
            store._put(path, value, replace=True)
            with self.subTest(name=name), self.assertRaises(ValueError):
                cancel._no_later_effects(store, directory)
            store._path(path).write_bytes(saved)

    def test_executable_artifact_missing_flag_receipt_or_source_drift_refused(self):
        self.f.prepare()
        store, directory = self.f.store, self.f.n.directory
        path = directory + "/update-prepared.json"
        saved = store._read(path)
        for change in (lambda item: item.update(executable=True), lambda item: item.pop("executable")):
            value = _json(saved)
            change(value["bundle"]["artifacts"][0])
            store._put(path, value, replace=True)
            with self.assertRaises(ValueError):
                cancel._prepared(store, self.data)
        store._path(path).write_bytes(saved)
        for path in (self.f.context.host(update.SHA_PROOF),
                     self.f.context.host(update.STAGING + "/" + self.f.n.operation + "/receipt.json")):
            original = path.read_bytes()
            path.write_bytes(b"changed")
            with self.assertRaises(ValueError):
                cancel._prepared(store, self.data)
            path.write_bytes(original)


class CancellationProfileTests(unittest.TestCase):
    def setUp(self):
        fixture = fence_fixtures.MaintenanceFenceTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.f = fixture
        self.store, self.registry = fixture.store, fixture.registry
        with self.registry.locked(recovery=True):
            self.profile = fixture.capture()
        self.n = SimpleNamespace(store=self.store, registry=self.registry, directory=fixture.directory,
                                 profile=lambda: self.profile)

    def test_original_profile_restored_from_partial_application_without_publication(self):
        f = self.f
        profile = _json(self.store._bound(self.profile))
        item = profile["files"][0]
        (f.roots[item["jail"]] / item["path"]).write_bytes(self.store._bound(item["closed"]))
        with self.registry.locked(recovery=True), patch.object(cancel, "_bound", return_value=()), \
                patch.object(cancel, "_request"), patch.object(cancel, "payload"):
            cancel._restore_profile(self.n)
            cancel.fence._check_files(self.store, profile, "original")
        self.assertFalse(self.store._present(f.directory + "/native-publication.json"))
        self.assertEqual(_json(self.store._read(f.journal.path))["phase"], "capture")

    def test_unknown_profile_content_refuses_before_any_original_file_write(self):
        profile = _json(self.store._bound(self.profile))
        paths = [self.f.roots[item["jail"]] / item["path"] for item in profile["files"]]
        paths[-1].write_bytes(b"unknown configuration")
        original = [path.read_bytes() for path in paths]
        with self.registry.locked(recovery=True), patch.object(cancel, "_bound", return_value=()), \
                patch.object(cancel, "_request"), patch.object(cancel, "payload"), self.assertRaises(ValueError):
            cancel._restore_profile(self.n)
        self.assertEqual([path.read_bytes() for path in paths], original)


class CancellationBoundPermissionTests(unittest.TestCase):
    """Real Store, NativeState, journal and flock; only code/native probes mocked."""
    def setUp(self):
        f = fence_fixtures.MaintenanceFenceTests()
        f.setUp()
        self.addCleanup(f.doCleanups)
        self.f, self.store, self.registry = f, f.store, f.registry
        with self.registry.locked(recovery=True):
            self.profile = f.capture()
            baseline = self.store._put(f.directory + "/first-readiness.json", dict(observation={"trees": {}, "resources": {}}))
            admission = self.store._put(f.directory + "/source-admission.json", dict(
                kind="original-generation-admission", graph=f.intent["base_graph"], generation=f.fixture.entries["cloud"]["generation"],
                executor=f.fixture.executor, recipe=f.fixture.recipe, startup=f.context["baseline"],
                instance="cloud", first_readiness=baseline))
            self.store._put(f.directory + "/admission.json", dict(evidence=admission, startup=f.context["baseline"]))
            self.store._put(f.directory + "/source-observations.json", dict(
                status=dict(installed=True, maintenance=False, needsDbUpgrade=False), reclosure_runtime={"original": True}))
            inputs = f.fixture.native.read(f.operation)[1]
            ack = cancel.recovery.offline_acknowledgement_record(SimpleNamespace(operation_id=f.operation, config=f.config,
                source_sha256=f.fixture.executor["source_sha256"], preparation_sha256=inputs["preparation"]["sha256"]))
            self.store._put(f.directory + "/offline-acknowledgement.json", ack)
            self.saved = self.store._put(f.directory + "/cancellation-journal.json", f.journal.read())
            self.request = self.store._put(f.directory + "/cancellation-request.json", dict(schema_version=1,
                kind="native-original-cancellation", intent=f.journal.reference, journal=self.saved,
                graph=f.intent["base_graph"], profile=self.profile, boot=BOOT,
                confirmation="CANCEL-MAINTENANCE " + f.operation, inspection=f.evidence))
            self.store._put(f.directory + "/cancellation-progress.json", dict(request=self.request,
                completed=[cancel.STEPS[0]], running="original-runtime", evidence={cancel.STEPS[0]: f.evidence}))
            self.store._put(f.directory + "/cancellation-start.json", dict(request=self.request,
                journal=self.store.reference(f.journal.path)))

    def boot(self, **changes):
        f = self.f
        args = dict(registry=self.registry, intent=f.intent, instance="cloud", jail=f.config.nextcloud_jail,
                    executor=f.fixture.executor["executor_sha256"])
        args.update(changes)
        return cancel.boot_permission(**args)

    def test_original_binding_requires_graph_admission_and_actual_ack(self):
        data = cancel._bound(self.store)
        self.assertEqual(data[2], self.f.config)
        for relative, change in (("offline-acknowledgement.json", lambda v: v.update(machine_drain_verified=True)),
                                 ("source-admission.json", lambda v: v.update(generation="newer")),
                                 ("source-observations.json", lambda v: v.update(reclosure_runtime={} ))):
            path = self.f.directory + "/" + relative
            original = self.store._read(path)
            value = _json(original)
            change(value)
            self.store._put(path, value, replace=True)
            with self.subTest(relative=relative), self.assertRaises(ValueError):
                cancel._bound(self.store)
            self.store._path(path).write_bytes(original)
        with self.registry.locked(recovery=True):
            self.f.fixture.commit()
        with self.assertRaises(ValueError):
            cancel._bound(self.store)

    def test_permission_needs_distinct_live_lock_closed_profile_and_exact_request(self):
        from installer.enrollment_start import _lock_file
        f = self.f
        with self.registry.locked(recovery=True), patch.object(cancel, "payload"), \
                patch.object(cancel.fence, "_publication_boot", return_value=BOOT):
            cancel.fence.install_profile(self.registry, self.profile)
            db = _lock_file(self.store, "instances/cloud/database-operation.lock", create=True)
            start = _lock_file(self.store, f.directory + "/cancellation-start.lock", create=True)
            try:
                fcntl.flock(db, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaises(ValueError):
                    self.boot()
                fcntl.flock(start, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.assertEqual(self.boot(), f.config)
                for changes in ({"jail": "unknownnc"}, {"instance": "other"}, {"executor": "f" * 64}):
                    with self.subTest(changes=changes), self.assertRaises(ValueError):
                        self.boot(**changes)
                with patch.object(cancel.fence, "_publication_boot", return_value="{ sec = 1792100000, usec = 1 } new boot"), \
                        self.assertRaises(ValueError):
                    self.boot()
                progress = self.store._read(f.directory + "/cancellation-progress.json")
                value = _json(progress)
                value["running"] = "original-profile"
                self.store._put(f.directory + "/cancellation-progress.json", value, replace=True)
                with self.assertRaises(ValueError):
                    self.boot()
                self.store._path(f.directory + "/cancellation-progress.json").write_bytes(progress)
            finally:
                os.close(start)
                os.close(db)
            with self.assertRaises(ValueError):
                self.boot()  # Stale JSON is never live boot authority.

    def test_cancelled_terminal_can_only_reconcile_exact_saved_journal(self):
        f = self.f
        with self.registry.locked(recovery=True):
            f.journal.advance("cancelled", dict(original_services=f.evidence,
                consistency=f.evidence, closure_removed=f.evidence))
            f.journal.terminal()
            data = cancel._bound(self.store)
            self.assertEqual(data[4], self.saved)
            self.assertEqual(cancel._request(self.store, data)[0], self.request)
            saved = _json(self.store._read(f.directory + "/cancellation-journal.json"))
            saved["recipe_sha256"] = "e" * 64
            self.store._put(f.directory + "/cancellation-journal.json", saved, replace=True)
            with self.assertRaises(ValueError):
                cancel._bound(self.store)


class CancellationRuntimeTests(unittest.TestCase):
    def make(self, live):
        c = SimpleNamespace(nextcloud_jail="cloudnc", onlyoffice_jail="cloudoo", instance="cloud")
        n = SimpleNamespace(c=c, backend=Mock(), store=Mock(), registry=Mock(),
            directory="maintenance/operations/execution-test", record=Mock())
        n.store._bound.return_value = b"{}"
        n.backend.running.return_value = []
        roots = {"cloudnc": "/owned/cloudnc/root", "cloudoo": "/owned/cloudoo/root"}
        status = dict(installed=True, needsDbUpgrade=False, maintenance=True, version="35.0.1.1")
        apps, config = {"enabled": {"onlyoffice": "10.2.1"}}, {"system": {"maintenance": False}}
        original = dict(status={**status, "maintenance": False}, apps_sha256=_hash(_encode(apps)),
                        config_sha256=_hash(_encode(config)))
        data = (n.directory, dict(roots=roots, intent={}, executor={"executor_sha256": "a" * 64}), c, {}, {}, {}, original)
        n.backend.occ.side_effect = lambda command, *args: _encode({"status": status, "app:list": apps,
                                                                  "config:list": config}[command])
        commands = []
        def run(*args):
            commands.append(args)
            if args[:2] == ("bastille", "start"):
                live[args[2]] = 41 if args[2] == "cloudnc" else 42
        def jailed(jail, *args):
            commands.append((jail, *args))
            if args[0] == "service":
                n.backend.running.return_value = [(1, 0, "daemon")]
        n.backend.run.side_effect = run
        n.backend.jailed.side_effect = jailed
        return n, data, commands

    def test_stopped_and_half_stopped_pair_start_only_missing_original_jail(self):
        for live in ({}, {"cloudnc": 41}, {"cloudoo": 42}, {"cloudnc": 41, "cloudoo": 42}):
            with self.subTest(live=live.copy()):
                missing = {"cloudnc", "cloudoo"} - live.keys()
                n, data, commands = self.make(live)
                with patch.object(cancel, "cancellation_starts", return_value=nullcontext()), \
                        patch.object(cancel, "_runtime", side_effect=lambda *args: dict(live)), \
                        patch("installer.maintenance_opening._pair", side_effect=lambda _: dict(live)), \
                        patch.object(cancel.fence, "boot_permission"):
                    cancel._start_runtime(n, data)
                self.assertEqual({args[2] for args in commands if args[:2] == ("bastille", "start")}, missing)
                n.backend.database_ready.assert_called_once()
                self.assertFalse(any("zfs" in args or "rollback" in args or "destroy" in args for args in commands))

    def test_missing_dispatcher_branch_blocks_before_bastille_start(self):
        n, data, commands = self.make({})
        with patch.object(cancel, "cancellation_starts", return_value=nullcontext()), \
                patch.object(cancel, "_runtime", return_value={}), \
                patch.object(cancel.fence, "boot_permission", side_effect=ValueError("denied")), self.assertRaises(ValueError):
            cancel._start_runtime(n, data)
        self.assertEqual(commands, [])

    def test_unknown_runtime_refuses_all_restarts(self):
        n, data, commands = self.make({})
        with patch.object(cancel, "cancellation_starts", return_value=nullcontext()), \
                patch.object(cancel, "_runtime", side_effect=ValueError("unknown jail/runtime")), self.assertRaises(ValueError):
            cancel._start_runtime(n, data)
        self.assertEqual(commands, [])

    def test_unknown_database_schema_never_opens_original_application_workers(self):
        live = {"cloudnc": 41, "cloudoo": 42}
        n, data, commands = self.make(live)
        n.backend.occ.side_effect = None
        n.backend.occ.return_value = _encode(dict(installed=True, needsDbUpgrade=True,
                                                  maintenance=True, version="35.0.1.1"))
        with patch.object(cancel, "cancellation_starts", return_value=nullcontext()), \
                patch.object(cancel, "_runtime", side_effect=lambda *args: dict(live)), self.assertRaises(ValueError):
            cancel._start_runtime(n, data)
        self.assertFalse(any("php_fpm" in command or "apache24" in command for command in commands))


class CancellationPrequiesceTests(unittest.TestCase):
    """Real original-tree digests, binding, journal and finalization; fake host."""
    def setUp(self):
        from unittest.mock import PropertyMock
        from installer.maintenance_admission import STATIC_ROOTS
        f = fence_fixtures.MaintenanceFenceTests()
        f.setUp()
        self.addCleanup(f.doCleanups)
        self.f, self.store = f, f.store
        self.enterContext(patch("installer.config.Config.mount_root", new_callable=PropertyMock,
                                return_value=str(f.fixture.root / "app-fixture")))
        public = {"runtime.json": b"{}\n", "packages.lock": b"source package lock\n"}
        self.enterContext(patch("installer.maintenance_generations.public_runtime_files", return_value=public))
        real_file = cancel.fence._file
        def fixture_file(root, name):
            data, mode, gid = real_file(root, name)
            # Ordinary-user fixtures cannot chgrp wheel. Bytes/modes and every
            # tree digest remain real; only this native public-file GID is fake.
            return data, mode, 0 if name in {"root/cloud-installer/" + p for p in public} else gid
        self.enterContext(patch.object(cancel.fence, "_file", side_effect=fixture_file))
        trees = {}
        for group, jail in (("nextcloud", f.config.nextcloud_jail), ("onlyoffice", f.config.onlyoffice_jail)):
            root = f.roots[jail]
            appname = "usr/local/www/" + ("nextcloud" if group == "nextcloud" else "onlyoffice/documentserver")
            names = (*STATIC_ROOTS, appname)
            for name in names:
                (root / name).mkdir(parents=True, exist_ok=True)
            for name, content in public.items():
                path = root / "root/cloud-installer" / name
                path.write_bytes(content)
                path.chmod(0o600)
            if group == "nextcloud":
                app = root / appname
                (app / "config").mkdir()
                (app / "config/config.php").write_bytes(b"<?php\n$CONFIG = array (\n  'maintenance' => false,\n);\n")
                (app / "occ").write_bytes(b"original reviewed source code")
                self.app = Path(f.config.mount_root) / "nc-app"
                shutil.copytree(app, self.app)
            roots = tuple(root / name for name in names)
            trees[jail] = {name: enrollment._tree_identity(root / name, jail_root=root, observed_roots=roots)
                           for name in names}
        self.observations = dict(status=dict(installed=True, maintenance=False, needsDbUpgrade=False, version="35.0.1.1"),
                                 reclosure_runtime={"original": True})
        baseline = self.store._put(f.directory + "/first-readiness.json", dict(observation=dict(trees=trees, resources={})))
        admitted = self.store._put(f.directory + "/source-admission.json", dict(kind="original-generation-admission",
            graph=f.intent["base_graph"], generation=f.fixture.entries["cloud"]["generation"], executor=f.fixture.executor,
            recipe=f.fixture.recipe, instance="cloud", startup=f.context["baseline"], first_readiness=baseline))
        admission = dict(startup=f.context["baseline"], evidence=admitted)
        self.store._put(f.directory + "/admission.json", admission)
        self.store._put(f.directory + "/source-observations.json", self.observations)
        self.n = object.__new__(native.NativeContext)
        n = self.n
        n.registry, n.store, n.native = f.registry, self.store, f.fixture.native
        n.operation, n.directory, n.journal = f.operation, f.directory, f.journal
        n.c, n.admission, n.backend = f.config, admission, Mock()
        n.d = SimpleNamespace(versions={}, jail_root=lambda jail: f.roots[jail])
        self.live = {f.config.nextcloud_jail: 41, f.config.onlyoffice_jail: 42}
        self.states = {jail: {service: service != "sshd" for service in native.SERVICES[group]}
                       for group, jail in (("nextcloud", f.config.nextcloud_jail), ("onlyoffice", f.config.onlyoffice_jail))}
        configured = deepcopy(self.states)
        def jailed(jail, *args):
            self.assertEqual(args[:2], ("sysrc", "-n"))
            service = args[-1].removesuffix("_enable")
            service = "mysql-server" if service == "mysql" else service
            return SimpleNamespace(stdout="YES" if configured[jail][service] else "NO")
        n.backend.jailed.side_effect = jailed
        n.backend.service_states.side_effect = lambda: deepcopy(self.states)
        n.backend.source_observations.side_effect = lambda: deepcopy(self.observations)
        n.backend.output.side_effect = lambda *args: BOOT if args == ("sysctl", "-n", "kern.boottime") else self.fail(args)
        def check(**kwargs):
            n.registry._require_lock(recovery=True)
            intent, inputs = n.native.read(n.operation)
            return intent, inputs, n.journal.read()
        n.check = Mock(side_effect=check)
        self.enterContext(patch.object(cancel, "_runtime", side_effect=lambda *args: dict(self.live)))
        self.enterContext(patch("installer.maintenance_publication.Publication._public_status",
                                return_value=self.observations["status"]))

    def call(self):
        with self.n.registry.locked(recovery=True):
            return cancel.cancel(self.n, "CANCEL-MAINTENANCE " + self.n.operation)

    def assert_untouched_runtime(self):
        self.n.backend.run.assert_not_called()
        self.n.backend.stop.assert_not_called()
        self.n.backend.occ.assert_not_called()
        self.assertFalse(self.store._present(self.n.directory + "/offline-acknowledgement.json"))
        self.assertFalse(self.store._present(self.n.directory + "/original-services.json"))
        self.assertFalse(self.store._present(self.n.directory + "/closed-profile.json"))
        self.assertFalse(self.store._present(self.n.directory + "/cancellation-start.json"))

    def test_pre_quiesce_cancels_ready_originals_without_offline_ack_or_runtime_effects(self):
        before = self.store._active()
        result = self.call()
        self.assertTrue(result["ready"])
        self.assertFalse(result["downtime_entered"])
        self.assertEqual(self.store._active(), before)
        self.assertIsNone(self.store.pending())
        self.assert_untouched_runtime()
        proof = _json(self.store._read(self.n.directory + "/cancellation-no-closure.json"))
        self.assertEqual(proof["kind"], "closure-never-installed")
        self.assertIsNone(proof["profile"])

    def test_declined_offline_phrase_may_leave_private_evidence_without_quiescence(self):
        # offline_phrase builds the private recovery context before prompting.
        # Its directory alone is not an acknowledgement or a captured set.
        self.store._mkdir(self.n.directory + "/recovery")
        self.store._put(self.n.directory + "/tls-binding.json", {"private": "retained"})
        self.assertEqual(self.call()["state"], "cancelled")
        self.assert_untouched_runtime()

    def test_source_or_maintenance_change_rejected_before_installed_php(self):
        for relative, content in (("occ", b"unknown code"),
                                  ("config/config.php", b"<?php\n$CONFIG = array (\n  'maintenance' => true,\n);\n")):
            path = self.app / relative
            saved = path.read_bytes()
            path.write_bytes(content)
            with self.subTest(relative=relative), self.assertRaises(ValueError):
                self.call()
            self.n.backend.source_observations.assert_not_called()
            self.n.backend.jailed.assert_not_called()
            self.assertFalse(self.store._present(self.n.directory + "/cancellation-request.json"))
            path.write_bytes(saved)

    def test_missing_admission_or_ambiguous_partial_closure_is_not_inert(self):
        for name in ("admission.json", "source-observations.json"):
            path = self.store._path(self.n.directory + "/" + name)
            original = path.read_bytes()
            path.unlink()
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.call()
            self.store._write_once(self.n.directory + "/" + name, original, recover=False)
        for name in ("offline-acknowledgement.json", "original-services.json", "profile-apply.json", "initial-closure.json"):
            path = self.n.directory + "/" + name
            self.store._put(path, {})
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.call()
            self.store._path(path).unlink()
        self.n.backend.source_observations.assert_not_called()
        self.assert_untouched_runtime()

    def test_nonready_runtime_half_pair_and_changed_source_observations_refuse(self):
        self.live.pop(self.n.c.onlyoffice_jail)
        with self.assertRaises(ValueError):
            self.call()
        self.live[self.n.c.onlyoffice_jail] = 42
        self.states[self.n.c.nextcloud_jail]["mysql-server"] = False
        with self.assertRaises(ValueError):
            self.call()
        self.states[self.n.c.nextcloud_jail]["mysql-server"] = True
        self.observations["status"]["needsDbUpgrade"] = True
        with self.assertRaises(ValueError):
            self.call()
        self.assertFalse(self.store._present(self.n.directory + "/cancellation-request.json"))
        self.assert_untouched_runtime()

    def test_terminal_retry_same_boot_has_no_boot_permission_and_no_restarts(self):
        with patch.object(self.n.native, "finish", side_effect=ValueError("interrupted")), self.assertRaises(ValueError):
            self.call()
        request = _json(self.store._read(self.n.directory + "/cancellation-request.json"))
        self.assertEqual(request["kind"], "native-pre-quiesce-cancellation")
        with self.assertRaises(ValueError):
            cancel.boot_permission(self.n.registry, self.f.intent, self.n.c.instance,
                self.n.c.nextcloud_jail, self.f.fixture.executor["executor_sha256"])
        self.n.backend.output.side_effect = None
        self.n.backend.output.return_value = "{ sec = 1792100000, usec = 1 } new boot"
        with self.assertRaises(ValueError):
            self.call()
        self.assertIsNotNone(self.store.pending())
        self.n.backend.output.return_value = BOOT
        self.assertEqual(self.call()["state"], "cancelled")
        self.assert_untouched_runtime()


class CancellationNativeInventoryTests(unittest.TestCase):
    def setUp(self):
        self.c = configuration()
        self.resources = cancel.recovery.expected_resources(self.c)
        self.fake = FakeNative(SimpleNamespace(config=self.c, resources=self.resources))
        self.live = {self.c.nextcloud_jail: 41}
        self.roots = {jail: self.c.bastille_root + "/jails/" + jail + "/root"
                      for jail in (self.c.nextcloud_jail, self.c.onlyoffice_jail)}
        self.fake.live = "\n".join(f"{jid} {jail} {self.roots[jail]} false" for jail, jid in self.live.items())
        self.fake.extra_mount = "".join("\n" + f"{d.mountpoint} {self.roots[d.jail]}{d.target} nullfs rw 0 0"
                                       for d in cancel.recovery.datasets(self.c) if d.jail in self.live)
        observed = {}
        parent_names = {self.c.bastille_dataset + "/jails/" + jail for jail in self.roots}
        for r in self.resources:
            if r.name not in parent_names:
                observed[r.name] = "\n".join(key + "\t" + self.fake.props[r.name][key]
                    for key in ("guid", "mountpoint", "mounted", cancel.recovery.OWNER))
        self.baseline = observed.copy()
        def output(*args):
            if args[:2] == ("zfs", "get") and args[4] == "property,value":
                return observed[args[-1]]
            if args[:2] == ("bastille", "config"):
                return self.roots[args[2]] if args[-1] == "path" else (
                    self.c.nextcloud_host if args[2] == self.c.nextcloud_jail else self.c.onlyoffice_host)
            if args[:2] == ("jls", "-j"):
                return self.c.nextcloud_host
            return self.fake.output(*args)
        self.backend = SimpleNamespace(output=output, get=lambda name, key: self.fake.props[name][key],
            runner=Mock(), reclosure_runtime=lambda value: value, processes=Mock(return_value=[(1, 0, "init")]),
            _service_rows=lambda *args: [], jailed=Mock(return_value=SimpleNamespace(stdout=self.c.nextcloud_host)))
        self.backend.runner.run.return_value = SimpleNamespace(returncode=0)
        self.n = SimpleNamespace(c=self.c, backend=self.backend, directory="operation", store=Mock(),
            d=SimpleNamespace(storage=cancel.recovery.datasets(self.c), registry=SimpleNamespace(root=Path("/host-state")),
                jail_root=lambda jail: Path(self.roots[jail]), require_running_jail=lambda jail: self.live[jail]))
        self.n.store._present.return_value = False
        self.data = ("operation", {"roots": self.roots}, self.c, {}, {}, {"resources": self.baseline},
                     {"reclosure_runtime": {"source": True}})

    def inspect(self):
        with patch("installer.lifecycle._checked_jails", side_effect=lambda d, names, **kw: [(names[0], "owned")]), \
                patch("installer.network.storage_guard", return_value="read-only-storage-probes"):
            return cancel._runtime(self.n, self.data)

    def test_half_live_original_pair_and_guid_bound_storage_are_accepted(self):
        self.assertEqual(self.inspect(), self.live)
        self.assertFalse(self.fake.mutations())

    def test_unknown_or_dying_jail_at_original_root_refuses_before_jexec(self):
        for name, dying in (("foreign", "false"), (self.c.nextcloud_jail, "true")):
            self.fake.live = f"41 {name} {self.roots[self.c.nextcloud_jail]} {dying}"
            with self.subTest(name=name, dying=dying), self.assertRaises(ValueError):
                self.inspect()
        self.backend.jailed.assert_not_called()
        self.backend.runner.run.assert_not_called()

    def test_unknown_writer_or_changed_original_guid_refuses(self):
        self.backend.processes.return_value = [(1, 0, "init"), (9, 1, "unknown-writer")]
        with self.assertRaises(ValueError):
            self.inspect()
        self.backend.processes.return_value = [(1, 0, "init")]
        first = next(iter(self.baseline))
        self.baseline[first] += "\nunknown-guid"
        with self.assertRaises(ValueError):
            self.inspect()
        self.assertFalse(self.fake.mutations())


class CancellationCoordinatorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="cancellation-coordinator-")
        self.addCleanup(temporary.cleanup)
        self.store = Store(temporary.name)
        self.directory = "maintenance/operations/execution-test"
        self.store._mkdir(self.directory)
        self.operation = "execution-test"
        self.intent = self.store._put(self.directory + "/intent.json", {"operation": self.operation})
        self.profile = self.store._put(self.directory + "/closed-profile.json", {})
        self.original = {jail: {s: True for s in native.SERVICES[group]}
                         for group, jail in (("nextcloud", "cloudnc"), ("onlyoffice", "cloudoo"))}
        self.store._put(self.directory + "/original-services.json", dict(pair={j: "running" for j in self.original}, services=self.original))
        self.graph = dict(path="lifecycle/graphs/original.json", sha256="a" * 64)
        self.state = journal.native_initial(self.intent, dict(path="inputs.json", sha256="b" * 64), "c" * 64)
        self.journal = Mock(path=self.directory + "/native-journal.json")
        self.journal.read.side_effect = lambda: self.state
        self.store._put(self.journal.path, self.state)
        def advance(phase, evidence):
            self.state = journal.native_transition(self.state, phase, evidence)
            self.store._put(self.journal.path, self.state, replace=True)
        self.journal.advance.side_effect = advance
        self.n = SimpleNamespace(operation=self.operation, directory=self.directory, store=self.store,
            journal=self.journal, native=Mock(), backend=Mock(), profile=lambda: self.profile,
            c=SimpleNamespace(nextcloud_jail="cloudnc", onlyoffice_jail="cloudoo"))
        self.n.backend.service_states.return_value = self.original
        self.n.backend.source_observations.return_value = {}
        self.n.record = lambda name, value: self.store._write_once(self.directory + "/" + name + ".json", _encode(value), recover=True)
        self.events = []
        self.patches = []
        def mocker(target, **kwargs):
            p = patch(target, **kwargs)
            self.patches.append(p)
            self.addCleanup(p.stop)
            return p.start()
        mocker("installer.generations.Store._active", return_value=self.graph)
        def preflight(n):
            reference = self.store.reference(self.journal.path)
            if self.state["phase"] == "cancelled":
                reference = self.store.reference(self.directory + "/cancellation-journal.json")
            data = (self.directory, {"intent": self.intent, "operation": self.operation}, self.n.c, {}, reference, {}, {})
            return data, dict(boot=BOOT, journal=reference)
        self.preflight = mocker("installer.maintenance_cancellation._preflight", side_effect=preflight)
        for name in ("_close", "_start_runtime", "_restore_profile", "_services"):
            mocker("installer.maintenance_cancellation." + name,
                   side_effect=lambda *args, _name=name, **kw: self.events.append((_name, kw)))
        mocker("installer.maintenance_fence._profile", return_value=({}, None))
        mocker("installer.maintenance_fence._check_files")
        self.ready = mocker("installer.maintenance_cancellation._ready", return_value={"original": True})
        self.n.backend.occ.side_effect = lambda *args: self.events.append(("occ", args))

    def call(self):
        return cancel.cancel(self.n, "CANCEL-MAINTENANCE " + self.operation)

    def test_success_checks_original_then_removes_fence_without_graph_or_snapshot_operations(self):
        result = self.call()
        self.assertEqual(result["state"], "cancelled")
        self.assertTrue(result["ready"])
        self.assertFalse(result["machine_drain_verified"])
        self.assertEqual([event[0] for event in self.events],
                         ["_close", "_start_runtime", "occ", "_restore_profile", "_services", "_services"])
        self.n.native.finish.assert_called_once_with(self.operation, "cancelled")
        self.n.backend.run.assert_not_called()
        self.assertEqual(self.state["phase"], "cancelled")
        self.assertFalse(self.state["publication_may_have_begun"])

    def test_failed_post_open_check_keeps_fence_and_retry_is_forward_only(self):
        self.ready.side_effect = RuntimeError("SECRET diagnostic")
        with self.assertRaisesRegex(ValueError, "^" + cancel.DENIED + "$"):
            self.call()
        self.n.native.finish.assert_not_called()
        self.assertEqual(self.state["phase"], "capture")
        self.events.clear()
        self.ready.side_effect = None
        self.call()
        self.assertEqual(self.events, [("_services", {"scheduled": True})])
        self.n.backend.occ.assert_called_once_with("maintenance:mode", "--off")

    def test_terminal_failure_retries_fence_finalization_without_restart_or_journal_rewrite(self):
        self.n.native.finish.side_effect = RuntimeError("interrupted")
        with self.assertRaises(ValueError):
            self.call()
        self.assertEqual(self.state["phase"], "cancelled")
        self.events.clear()
        self.n.native.finish.side_effect = None
        self.call()
        self.assertEqual(self.events, [])
        self.journal.advance.assert_called_once()

    def test_source_or_graph_drift_blocks_before_cancellation_record(self):
        self.preflight.side_effect = ValueError("source/runtime/graph unknown")
        with self.assertRaises(ValueError):
            self.call()
        self.assertFalse(self.store._present(self.directory + "/cancellation-request.json"))
        self.assertEqual(self.events, [])
        self.n.native.finish.assert_not_called()


if __name__ == "__main__":
    unittest.main()
