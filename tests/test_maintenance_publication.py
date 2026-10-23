"""Offline fault model: real graph/journal/fence, fake native execution only."""

from contextlib import contextmanager
from copy import deepcopy
import fcntl
import json
import os
from types import SimpleNamespace
from pathlib import Path
import unittest
from unittest.mock import Mock, patch, PropertyMock

from installer import maintenance_publication as publication
from installer import maintenance_journal as journal
from installer import maintenance_fence as fence
from installer.generations import _json
from installer.maintenance_native import NativeContext, SERVICES
import test_maintenance_fence as fixtures
import test_maintenance_generations as generation_fixtures


class Validator(publication.Validator):
    def __init__(self, fixture):
        self.f = fixture
        self.missing = None
        self.fail_open = False

    def descriptor(self):
        return self.f.fixture.fixture.recipe

    def closed(self, context, generation):
        self.f.events.append("closed-checks")
        value = {name: self.f.evidence for name in publication.CLOSED_CHECKS}
        if self.missing:
            del value[self.missing]
        return value

    def post_open(self, context, generation):
        self.f.events.append("public-checks")
        if self.fail_open:
            raise RuntimeError("PRIVATE DIAGNOSTIC")
        self.f.assertFalse(self.f.maintenance)
        return {name: self.f.evidence for name in publication.OPEN_CHECKS}


class Copies(publication.CopyVerifier):
    def __init__(self, fixture):
        self.f = fixture
        self.bad_count = False
        self.calls = 0

    def recheck(self, context, manifest, receipt, validation):
        self.calls += 1
        value = _json(context.store._bound(manifest))
        return context.record("copy-recheck-" + str(self.calls), dict(manifest=manifest, receipt=receipt,
            validation=validation, datasets=len(value["datasets"]), snapshots=13 if self.bad_count else len(value["snapshots"]),
            evidence_files=len(value["evidence"])))


class TargetFenceFixture(unittest.TestCase):
    """Real strict successor plus the same original-root fence used by recovery."""
    def setUp(self):
        f = self.fixture = generation_fixtures.SuccessorTests()
        f.setUp()
        self.addCleanup(f.doCleanups)
        self.registry, self.store, self.operation = f.registry, f.store, f.operation
        self.directory = "maintenance/operations/" + self.operation
        self.enterContext(patch.object(fence, "_root_required"))
        self.enterContext(patch("installer.config.Config.bastille_root", new_callable=PropertyMock,
                                return_value=str(f.root / "jails-fixture")))
        self.store._put("lifecycle/executor.json", f.executor)
        with self.registry.locked(recovery=True):
            self.intent = f.begin()
            f.recipe = f.native.read(self.operation)[1]["recipe"]
            self.target = f.seal()
            self.config = f.native.view(self.operation).load("cloud")
            self.evidence = self.store._put(self.directory + "/test-observation.json", {"offline_fixture": True})
        self.roots = {j: Path(self.config.bastille_root) / "jails" / j / "root"
                      for j in (self.config.nextcloud_jail, self.config.onlyoffice_jail)}
        for root in self.roots.values():
            for name in (*fence.STARTUP_TREES, "etc/defaults", "usr/local/etc/apache24"):
                (root / name).mkdir(parents=True, exist_ok=True)
            for name in fence.STARTUP_FILES:
                (root / name).write_bytes(b'# reviewed original\n' if name != "etc/rc.conf" else b'cron_enable="YES"\nsshd_enable="YES"\n')
                (root / name).chmod(0o644)
            (root / "etc/rc.d/cron").write_bytes(b"# reviewed cron\n")
        self.vhost = self.roots[self.config.nextcloud_jail] / fence.VHOST
        self.vhost.write_bytes((fixtures.RESOURCES / "templates/nextcloud/https.conf").read_bytes())
        self.context = dict(config=json.loads(self.config.to_json()), roots={j: str(r) for j, r in self.roots.items()},
            baseline={j: fence.startup_inventory(r, nextcloud=j == self.config.nextcloud_jail) for j, r in self.roots.items()},
            operator_saved_closed=True)

    def closed(self):
        receipt = fence.capture_profile(self.context, self.store, self.operation)
        fence.install_profile(self.registry, receipt)
        j = journal.NativeJournal(self.registry, self.operation, self.store.reference(self.directory + "/intent.json"),
                                  self.fixture.recipe, native=self.fixture.native)
        j.initialize()
        j.advance("quiesced", {key: self.evidence for key in journal.NATIVE_REQUIRED["quiesced"]})
        return receipt


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.recovering = getattr(self, "recovering", True)
        self.fixture = (fixtures.MaintenanceFenceTests if self.recovering else TargetFenceFixture)()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        f = self.fixture
        self.store, self.registry = f.store, f.registry
        self.events, self.maintenance, self.public = [], True, False
        self.evidence = f.evidence
        self.original = {f.config.nextcloud_jail: {s: True for s in SERVICES["nextcloud"]},
                         f.config.onlyoffice_jail: {s: True for s in SERVICES["onlyoffice"]}}
        self.original[f.config.nextcloud_jail]["cron"] = False
        self.original[f.config.onlyoffice_jail]["sshd"] = False
        self.services = deepcopy(self.original)
        for services in self.services.values():
            services.update(cron=False, sshd=False)
        d = SimpleNamespace(config=f.config, registry=self.registry, runner=Mock(),
            require_running_jail=Mock(side_effect=lambda jail: 41 if jail == f.config.nextcloud_jail else 42),
            require_original_artifact=Mock())
        with self.registry.locked(recovery=True):
            self.profile = f.closed()
            self.n = NativeContext(self.registry, f.fixture.native, f.operation, d, {})
            self.n.active = True
            self.n.record("original-services", dict(pair={j: "running" for j in self.original}, services=self.original))
            self.manifest = self.n.record("recovery-manifest-fixture", dict(
                datasets={str(i): {} for i in range(14)}, snapshots={str(i): {} for i in range(14)},
                evidence={"private-source": {}}))
            phases = ("recovery-ready", "migrating", "validating")
            if self.recovering:
                phases += ("restoring", "restored-closed", "recovery-validating")
            for phase in phases:
                evidence = {key: self.evidence for key in journal.NATIVE_REQUIRED[phase]}
                if phase == "recovery-ready":
                    evidence["recovery_set"] = self.manifest
                self.n.journal.advance(phase, evidence)
            if self.recovering:
                self.n.journal.step_start("data-fingerprint", replay="never", precondition=self.evidence)
                self.n.journal.step_complete("data-fingerprint", self.evidence)
        self.n.backend = Mock()
        self.n.backend.output.return_value = "boot-one"
        self.n.backend.pair_state.return_value = "running"
        self.n.backend.running.side_effect = lambda jail, service: self.services[jail][service]
        self.n.backend.service_states.side_effect = lambda: deepcopy(self.services)
        self.n.backend.occ.side_effect = self.occ
        self.n.backend.jailed.side_effect = self.jailed
        self.n.backend.stop.side_effect = self.stop
        self.n.backend.runner.run.side_effect = self.command
        self.n._recovery_context = Mock()
        self.validator, self.copies = Validator(self), Copies(self)
        self.p = publication.Publication(self.n, validator=self.validator, copies=self.copies)
        self.generation = f.fixture.entries["cloud"]["generation"] if self.recovering else f.target
        for target, kwargs in (
                ("installer.host.verify_managed_network", {}),
                ("installer.recovery_sets.validate_manifest", {"side_effect": lambda context, value: value})):
            mocker = patch(target, **kwargs)
            mocker.start()
            self.addCleanup(mocker.stop)

    @contextmanager
    def locked(self):
        with self.registry.locked(recovery=True):
            path = self.store.root / "instances/cloud/database-operation.lock"
            fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                yield
            finally:
                os.close(fd)

    def status(self):
        return dict(installed=True, maintenance=self.maintenance, needsDbUpgrade=False,
                    version="35.0.1.1" if self.recovering else "35.0.2.2")

    def effect(self, name):
        value = self.n.journal.read()
        self.assertIn(value["phase"], ("recovery-opening", "recovered") if self.recovering else ("opening", "complete"))
        self.assertTrue(value["recovery_publication_may_have_begun"] if self.recovering else value["publication_may_have_begun"])
        self.events.append(name)

    def occ(self, *args):
        if args == ("maintenance:mode", "--off"):
            self.effect("maintenance-off")
            self.maintenance = False
        elif args != ("status", "--output=json"):
            raise AssertionError(args)
        return json.dumps(self.status())

    def jailed(self, jail, *args):
        self.effect("service-command")
        if args[0] == "service":
            self.assertEqual(args[2], "onestart")
            self.services[jail][args[1]] = True
            if args[1] in ("cron", "sshd"):
                self.assertTrue(self.public)
        elif args == ("/usr/local/sbin/apachectl", "-k", "graceful"):
            self.public = True
        elif args != ("/usr/local/sbin/apachectl", "configtest"):
            raise AssertionError(args)
        return SimpleNamespace(returncode=0, stdout="")

    def stop(self, jail, service):
        self.effect("stop-" + service)
        self.services[jail][service] = False

    def command(self, *args, **kwargs):
        self.assertEqual(args[0], "curl")
        self.assertNotIn("--insecure", args)
        self.assertTrue(kwargs["hide_output"])
        self.assertTrue(self.public)
        profile, _ = fence._profile(self.store, self.profile)
        fence._check_files(self.store, profile, "publication-either")
        return SimpleNamespace(returncode=0, stdout=json.dumps(self.status()))

    def ready(self):
        return self.p.validate_closed(self.generation, copy_receipt=self.evidence, copy_validation=self.evidence)

    def committed(self):
        readiness = self.ready()
        if not self.recovering:
            from installer.generations import descriptor
            from installer.state import atomic_json
            atomic_json(self.store.root / "instances/cloud/config.json", descriptor("cloud", self.generation))
        return self.p.commit_closed(readiness)

    def test_recovery_commits_all_original_entries_then_opens_and_finishes(self):
        with self.locked():
            original_network = deepcopy(self.fixture.fixture.native.read(self.n.operation)[1]["network"])
            commitment = self.committed()
            self.assertEqual(self.store.graph(validate_evidence=False)["instances"], self.fixture.fixture.entries)
            self.assertEqual(self.n.journal.read()["phase"], "recovery-validating")
            self.assertGreaterEqual(self.copies.calls, 2)
            result = self.p.open(commitment)
            self.assertEqual(result["state"], "recovered")
            self.assertFalse(result["machine_drain_verified"])
            self.assertEqual(result["frontend_probe"], "host-direct-frontend")
            self.assertFalse(result["external_ingress_verified"])
            self.assertEqual(self.services, self.original)
            self.assertIsNone(self.store.pending())
            self.assertEqual(self.events.index("maintenance-off"), 3)
            self.assertTrue(self.store._present(self.n.directory + "/native-terminal.json"))
            from installer.maintenance_operations import _network_binding
            self.assertEqual(_network_binding(self.store), original_network)

    def test_missing_integration_or_copy_counts_cannot_mint_readiness(self):
        with self.locked():
            for name in publication.CLOSED_CHECKS:
                self.validator.missing = name
                with self.assertRaises(ValueError):
                    self.ready()
            self.validator.missing = None
            self.copies.bad_count = True
            with self.assertRaises(ValueError):
                self.ready()
            self.assertEqual(self.store._active(), self.fixture.fixture.base)
            self.assertNotIn("maintenance-off", self.events)

    def test_boolean_json_foreign_context_and_stale_journal_are_not_readiness(self):
        with self.locked():
            proof = self.ready()
            foreign = publication.Publication(self.n, validator=self.validator, copies=self.copies)
            for value in (True, {"ready": True}, proof.reference):
                with self.assertRaises(ValueError):
                    self.p.commit_closed(value)
            with self.assertRaises(ValueError):
                foreign.commit_closed(proof)
            self.n.journal.step_start("later-work", replay="never", precondition=self.evidence)
            with self.assertRaises(ValueError):
                self.p.commit_closed(proof)

    def test_original_generation_cannot_be_used_as_target_successor(self):
        with self.locked():
            inputs = self.n.native.read(self.n.operation)[1]
            with self.assertRaises(ValueError):
                self.p._generation(inputs, self.generation, False)

    def test_partial_profile_restore_resumes_forward_without_reclosing(self):
        real = fence._replace
        calls = []

        def interrupted(root, item, data):
            calls.append(item["path"])
            if len(calls) == 2:
                raise OSError("PRIVATE DIAGNOSTIC")
            return real(root, item, data)

        with self.locked():
            commitment = self.committed()
            with patch.object(fence, "_replace", side_effect=interrupted):
                with self.assertRaisesRegex(ValueError, publication.DENIED) as caught:
                    self.p.open(commitment)
            self.assertNotIn("PRIVATE", str(caught.exception))
            self.assertEqual(self.n.journal.read()["phase"], "recovery-opening")
            progress = _json(self.store._read(self.n.directory + "/publication-progress.json"))
            self.assertEqual(progress["running"], "original-profile")
            with self.assertRaises(ValueError):
                self.n.check()
            with self.assertRaises(ValueError):
                self.n.journal.advance("restoring", {key: self.evidence for key in journal.NATIVE_REQUIRED["restoring"]})
            self.assertEqual(self.p.open()["state"], "recovered")
            self.assertEqual(self.events.count("maintenance-off"), 1)

    def test_profile_drift_refuses_retry_and_never_rolls_back(self):
        with self.locked():
            commitment = self.committed()
            with patch.object(fence, "publication_profile", side_effect=OSError()):
                with self.assertRaises(ValueError):
                    self.p.open(commitment)
            self.fixture.vhost.write_bytes(b"unrelated drift\n")
            with self.assertRaises(ValueError):
                self.p.open()
            self.assertEqual(self.fixture.vhost.read_bytes(), b"unrelated drift\n")
            self.assertTrue(self.n.journal.read()["recovery_publication_may_have_begun"])

    def test_public_failure_keeps_pending_and_retry_preserves_original_stopped_services(self):
        with self.locked():
            commitment = self.committed()
            self.validator.fail_open = True
            with self.assertRaises(ValueError):
                self.p.open(commitment)
            self.assertIsNotNone(self.store.pending())
            self.assertFalse(self.store._present(self.n.directory + "/native-terminal.json"))
            self.validator.fail_open = False
            self.assertEqual(self.p.open()["state"], "recovered")
            self.assertEqual(self.services, self.original)

    def test_opening_reboot_or_stopped_jail_never_acquires_start_permission(self):
        with self.locked():
            commitment = self.committed()
            with patch.object(fence, "publication_profile", side_effect=OSError()):
                with self.assertRaises(ValueError):
                    self.p.open(commitment)
            for field, value in (("pair_state", "stopped"), ("output", "boot-two")):
                method = getattr(self.n.backend, field)
                previous = method.return_value
                method.return_value = value
                with self.assertRaises(ValueError):
                    self.p.open()
                method.return_value = previous
            self.n.backend.run.assert_not_called()
            with self.assertRaises(ValueError):
                self.fixture.boot()

    def test_finish_interruption_after_native_terminal_rechecks_then_releases_pending(self):
        with self.locked():
            commitment = self.committed()
            with patch.object(self.n.native, "finish", side_effect=OSError()):
                with self.assertRaises(ValueError):
                    self.p.open(commitment)
            self.assertEqual(self.n.journal.read()["phase"], "recovered")
            self.assertIsNotNone(self.store.pending())
            self.assertEqual(self.p.open()["state"], "recovered")
            self.assertIsNone(self.store.pending())

    def test_catalog_remains_disabled_and_adapters_are_not_json(self):
        self.assertEqual(journal.REVIEWED_NATIVE_RECIPES, {})
        with self.assertRaises(ValueError):
            publication.Publication(self.n, validator={"ready": True}, copies=self.copies)

    def test_host_direct_frontend_preserves_public_https_authority_port_and_ca(self):
        self.n.c.public_https_port = 8443
        self.n.c.ca_file = "/private/retained-ca.pem"
        good = dict(installed=True, maintenance=False, needsDbUpgrade=False, version="35.0.1.1")
        with patch.object(self.n.backend.runner, "run", return_value=SimpleNamespace(returncode=0, stdout=json.dumps(good))) as run:
            self.assertEqual(self.p._public_status("35.0.1.1"), good)
            args = run.call_args.args
            self.assertIn("--connect-to", args)
            self.assertIn(f"{self.n.c.public_hostname}:8443:{self.n.c.nextcloud_ip}:443", args)
            self.assertEqual(args[-1], f"https://{self.n.c.public_hostname}:8443/status.php")
            self.assertIn("/private/retained-ca.pem", args)
            self.assertFalse(any(arg in args for arg in ("--insecure", "-k", "--header", "--resolve")))
            run.return_value.returncode = 22
            with self.assertRaises(ValueError):
                self.p._public_status("35.0.1.1")
            run.return_value.returncode = 0
            run.return_value.stdout = json.dumps(dict(good, maintenance=True))
            with self.assertRaises(ValueError):
                self.p._public_status("35.0.1.1")

    def test_default_adapters_are_concrete_fixed_implementations(self):
        from installer.maintenance_validation import FixedValidator, RecoveryCopyVerifier
        actual = publication.Publication(self.n)
        self.assertIsInstance(actual.validator, FixedValidator)
        self.assertIsInstance(actual.copies, RecoveryCopyVerifier)

    def test_copy_loss_between_commit_and_open_blocks_marker(self):
        with self.locked():
            commitment = self.committed()
            self.copies.bad_count = True
            with self.assertRaises(ValueError):
                self.p.open(commitment)
            self.assertFalse(self.n.journal.read()["recovery_publication_may_have_begun"])
            self.assertTrue(self.maintenance)

    def test_graph_commit_interruption_retries_exact_original_selection(self):
        with self.locked():
            proof = self.ready()
            original_record = self.n.record

            def fail_commit_record(name, value):
                if name == "publication-commit-restored-closed":
                    raise OSError("simulated controller interruption after graph commit")
                return original_record(name, value)

            with patch.object(self.n, "record", side_effect=fail_commit_record):
                with self.assertRaises(OSError):
                    self.p.commit_closed(proof)
            active = self.store._active()
            # A fresh process-local proof is allowed only for the pinned selection.
            commitment = self.p.commit_closed(self.ready())
            self.assertEqual(self.store._active(), active)
            self.assertEqual(_json(self.store._bound(commitment))["readiness"], proof.reference)
            self.assertEqual(self.p.open(commitment)["state"], "recovered")

    def test_pending_network_or_live_identity_drift_blocks_opening_retry(self):
        with self.locked():
            commitment = self.committed()
            with patch.object(fence, "publication_profile", side_effect=OSError()):
                with self.assertRaises(ValueError):
                    self.p.open(commitment)
            with patch("installer.maintenance_operations._network_binding", return_value={"changed": True}):
                with self.assertRaises(ValueError):
                    self.p.open()
            with patch.object(self.n.d, "require_running_jail", return_value=99):
                with self.assertRaises(ValueError):
                    self.p.open()
            self.assertEqual(self.n.journal.read()["phase"], "recovery-opening")


class TargetCommitTests(unittest.TestCase):
    def test_preopening_record_interruptions_allow_whole_original_restoration_and_publication(self):
        for failed in ("publication-writers-stopped-target", "publication-authorized-target"):
            with self.subTest(failed=failed):
                f = PublicationTests()
                f.recovering = False
                f.setUp()
                try:
                    with f.locked():
                        commitment = f.committed()
                        record = f.n.record
                        def interrupt_record(name, value):
                            result = record(name, value)  # Actual immutable Store write first.
                            if name == failed:
                                raise OSError("simulated controller interruption before publication marker")
                            return result
                        with patch.object(f.n, "record", side_effect=interrupt_record):
                            with self.assertRaises(ValueError):
                                f.p.open(commitment)
                        failed_ref = f.store.reference(f.n.directory + "/" + failed + ".json")
                        saved = f.store._bound(failed_ref)
                        self.assertEqual(f.n.journal.read()["phase"], "committed-closed")
                        self.assertFalse(f.n.journal.read()["publication_may_have_begun"])
                        self.assertNotIn("maintenance-off", f.events)
                        # Model complete original-member ZFS restoration, retaining
                        # host journals/markers outside that snapshot set.
                        for phase in ("restoring", "restored-closed"):
                            f.n.journal.advance(phase, {key: f.evidence for key in journal.NATIVE_REQUIRED[phase]})
                        profile, _ = fence._profile(f.store, f.profile)
                        for item in profile["files"]:
                            (f.fixture.roots[item["jail"]] / item["path"]).write_bytes(f.store._bound(item["original"]))
                        original = f.fixture.fixture.predecessor
                        from installer.generations import descriptor
                        from installer.state import atomic_json
                        atomic_json(f.store.root / "instances/cloud/config.json", descriptor("cloud", original))
                        fence.install_profile(f.registry, f.profile)
                        f.n.journal.advance("recovery-validating", {key: f.evidence for key in journal.NATIVE_REQUIRED["recovery-validating"]})
                        f.n.journal.step_start("data-fingerprint", replay="never", precondition=f.evidence)
                        f.n.journal.step_complete("data-fingerprint", f.evidence)
                        f.recovering, f.generation = True, original
                        self.assertTrue(f.p.open(f.committed())["ready"])
                        self.assertEqual(f.store._bound(failed_ref), saved)
                        self.assertTrue(f.store._present(f.n.directory + "/publication-writers-stopped-original.json"))
                        self.assertTrue(f.store._present(f.n.directory + "/publication-authorized-original.json"))
                        self.assertIsNone(f.store.pending())
                finally:
                    f.doCleanups()

    def test_real_strict_successor_commit_retains_every_other_entry(self):
        f = generation_fixtures.SuccessorTests()
        f.setUp()
        self.addCleanup(f.doCleanups)
        with f.registry.locked(recovery=True):
            f.begin()
            target = f.seal()
            d = SimpleNamespace(config=f.config, runner=Mock(), require_running_jail=lambda jail: 41)
            n = NativeContext(f.registry, f.native, f.operation, d, {})
            evidence = n.record("offline-observation", {"test": "not native acceptance"})
            for phase in ("quiesced", "recovery-ready", "migrating", "validating"):
                n.journal.advance(phase, {key: evidence for key in journal.NATIVE_REQUIRED[phase]})
            states = {f.config.nextcloud_jail: {s: True for s in SERVICES["nextcloud"]},
                      f.config.onlyoffice_jail: {s: True for s in SERVICES["onlyoffice"]}}
            n.record("original-services", dict(pair={jail: "running" for jail in states}, services=states))
            n.backend = Mock()
            n.backend.running.return_value = False
            n.backend.pair_state.return_value = "running"
            n.backend.output.return_value = "test-boot"
            n.backend.occ.return_value = json.dumps(dict(installed=True, maintenance=True,
                                                          needsDbUpgrade=False, version="35.0.2.2"))
            n.check = lambda **kwargs: (*f.native.read(f.operation), n.journal.read())

            class TargetValidator(publication.Validator):
                def descriptor(self):
                    return f.native.read(f.operation)[1]["recipe"]

                def closed(self, context, generation):
                    return {key: evidence for key in publication.CLOSED_CHECKS}

                def post_open(self, context, generation):
                    raise AssertionError("target test is closed only")

            class TargetCopies(publication.CopyVerifier):
                def recheck(self, *args):
                    raise AssertionError("copy backend exercised separately")

            p = publication.Publication(n, validator=TargetValidator(), copies=TargetCopies())
            copy = n.record("copy-fixture", dict(manifest=evidence, receipt=evidence, validation=evidence))
            with patch.object(p, "_copy", return_value=copy):
                proof = p.validate_closed(target, copy_receipt=evidence, copy_validation=evidence)
                # Parent reconciliation owns this exact descriptor, never publication.
                from installer.generations import descriptor
                from installer.state import atomic_json
                atomic_json(f.root / "instances/cloud/config.json", descriptor("cloud", target))
                commitment = p.commit_closed(proof)
            graph = _json(f.store._bound(_json(f.store._bound(commitment))["graph"]))
            self.assertEqual(graph["instances"]["cloud"]["generation"], target)
            self.assertEqual(graph["instances"]["other"], f.entries["other"])
            self.assertEqual(graph["predecessor"], f.base)
            self.assertEqual(n.journal.read()["phase"], "committed-closed")
            self.assertFalse(n.journal.read()["publication_may_have_begun"])


if __name__ == "__main__":
    unittest.main()
