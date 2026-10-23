"""Simulated publication/boot interruptions: real locks/fence/graph, no native execution."""

from copy import deepcopy
import os
from pathlib import Path
import re
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from installer import maintenance_opening as opening, maintenance_fence as fence
from installer import maintenance_publication as publication
from installer.generations import _json
from installer.maintenance_native import NativeContext
import test_maintenance_publication as fixtures
import test_maintenance_validation as validation_fixtures


class PublicationStartupFixture(fixtures.TargetFenceFixture):
    """Complete source rc inputs before capture, for the independent boot model."""

    def setUp(self):
        super().setUp()
        services = {
            self.config.nextcloud_jail: ("apache24", "php_fpm", "mysql", "redis"),
            self.config.onlyoffice_jail: ("nginx", "supervisord"),
        }
        for jail, names in services.items():
            path = self.roots[jail] / "etc/rc.conf"
            path.write_bytes(path.read_bytes() + "".join(f'{name}_enable="YES"\n' for name in names).encode())
        self.context["baseline"] = {
            jail: fence.startup_inventory(root, nextcloud=jail == self.config.nextcloud_jail)
            for jail, root in self.roots.items()}


class OpeningTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.PublicationTests()
        self.f.recovering = getattr(self, "recovering", True)
        with patch.object(fixtures, "TargetFenceFixture", PublicationStartupFixture):
            self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.n, self.p, self.store = self.f.n, self.f.p, self.f.store
        self.boot = "{ sec = 100, usec = 0 } original"
        self.live = {self.n.c.nextcloud_jail: 41, self.n.c.onlyoffice_jail: 42}
        self.next_jid = 70
        self.starts, self.storage_checks = [], []
        self.fail_start = None
        self.failure_after_start = False
        self.payload_drift = False
        self.n.d.state = self.store.root / "instances" / self.n.c.instance
        self.n.d.jail_root = lambda jail: self.f.fixture.roots[jail]
        self.n.d.require_running_jail.side_effect = lambda jail: self.live[jail]
        self.n.backend.output.side_effect = self.output
        self.n.backend.pair_state.side_effect = lambda: "running" if len(self.live) == 2 else "stopped" if not self.live else "partial"
        self.n.backend.run.side_effect = self.start
        self.enterContext(patch.object(opening, "payload", side_effect=self.inspect))
        self.enterContext(patch.object(opening, "storage", side_effect=self.inspect_storage))
        self.enterContext(patch.object(fence, "_publication_boot", side_effect=lambda: self.boot))

    def output(self, *args):
        if args == ("sysctl", "-n", "kern.boottime"):
            return self.boot
        if args == ("jls", "-d", "jid", "name", "path", "dying"):
            return "\n".join(f"{jid} {jail} {self.n.d.jail_root(jail)} false" for jail, jid in self.live.items())
        raise AssertionError(args)

    def inspect(self, store, config, inputs, journal, proof):
        profile, _ = fence._profile(store, self.n.profile())
        fence._check_files(store, profile, "publication-either")
        if self.payload_drift:
            raise ValueError("static drift")
        return dict(generation=proof["generation"], static_files="changed" if self.payload_drift else "reviewed")

    def inspect_storage(self, n, inputs, journal, live):
        self.assertEqual(live, self.live)
        self.assertTrue(journal["recovery_publication_may_have_begun"] if self.f.recovering else journal["publication_may_have_begun"])
        self.storage_checks.append(deepcopy(live))
        return self.f.manifest

    def boot_guard(self, jail=None):
        return fence.boot_permission(self.f.registry, self.f.fixture.intent, self.n.c.instance,
            jail or self.n.c.nextcloud_jail, self.f.fixture.fixture.executor["executor_sha256"])

    def start(self, *args):
        self.assertEqual(args[:2], ("bastille", "start"))
        jail = args[2]
        self.assertNotIn(jail, self.live)
        self.boot_guard(jail)  # Actual exec.prepare branch under real permission flock.
        request = _json(self.store._read(self.n.directory + "/opening-active.json"))["request"]
        progress = _json(self.store._read(self.n.directory + "/opening-progress-" + request["sha256"] + ".json"))
        self.assertEqual(progress["states"][jail]["state"], "starting")
        self.starts.append(jail)
        if jail == self.fail_start and not self.failure_after_start:
            raise RuntimeError("PRIVATE native failure")
        self.next_jid += 1
        self.live[jail] = self.next_jid
        # Model application startup; the exact derived rc profile fences writers.
        profile, _ = fence._profile(self.store, self.n.profile())
        fence._check_files(self.store, profile, "publication")
        # Independent oracle for these controlled rc fixtures: do not use the
        # production projection to decide whether startup permits writers.
        data = Path(profile["roots"][jail], "etc/rc.conf").read_bytes()
        def assignments(raw):
            return dict(re.findall(rb'^([a-z0-9_]+)="([^"]*)"$', raw, re.MULTILINE))
        flags = assignments(data)
        self.assertEqual(flags[b"cron_enable"], b"NO")
        self.assertEqual(flags[b"sshd_enable"], b"NO")
        original = next(item for item in profile["files"]
                        if item["jail"] == jail and item["path"] == "etc/rc.conf")
        original_flags = assignments(self.store._bound(original["original"]))
        self.assertEqual({key: value for key, value in flags.items()
                          if key not in (b"cron_enable", b"sshd_enable")},
                         {key: value for key, value in original_flags.items()
                          if key not in (b"cron_enable", b"sshd_enable")})
        keys = {"mysql-server": "mysql"}
        self.f.services[jail] = {
            service: flags[(keys.get(service, service) + "_enable").encode()] == b"YES"
            for service in self.f.services[jail]}
        if jail == self.n.c.nextcloud_jail:
            self.f.public = True
        if jail == self.fail_start and self.failure_after_start:
            raise RuntimeError("PRIVATE native failure after live start")
        return SimpleNamespace(returncode=0)

    def arm(self):
        commitment = self.f.committed()
        self.n.record("admission", dict(evidence=self.f.evidence))
        with patch.object(fence, "publication_profile", side_effect=OSError("simulated controller interruption")):
            with self.assertRaises(ValueError):
                self.p.open(commitment)
        self.original_readiness = self.n.journal.read()["evidence"]["readiness"]
        self.original_bytes = self.store._bound(self.original_readiness)
        self.original_publication = self.store.reference(self.n.directory + "/native-publication.json")

    def reboot(self, second=200):
        self.boot = f"{{ sec = {second}, usec = 0 }} new boot"
        self.live.clear()
        for services in self.f.services.values():
            services.update({service: False for service in services})
        self.f.public = False

    @property
    def confirmation(self):
        return "CONTINUE-PUBLICATION " + self.n.operation

    def test_explicit_new_boot_finishes_without_rewriting_old_readiness_or_progress(self):
        with self.f.locked():
            self.arm()
            old_progress = self.store._read(self.n.directory + "/publication-progress.json")
            copies = self.f.copies.calls
            self.reboot()
            with self.assertRaises(ValueError):
                self.p.open()
            result = self.p.continue_publication(self.confirmation)
            self.assertEqual(result["state"], "recovered")
            self.assertTrue(result["ready"])
            self.assertIsNone(self.store.pending())
            self.assertEqual(self.f.services, self.f.original)
            self.assertEqual(self.store._bound(self.original_readiness), self.original_bytes)
            self.assertEqual(self.store.reference(self.n.directory + "/native-publication.json"), self.original_publication)
            self.assertEqual(self.store._read(self.n.directory + "/publication-progress.json"), old_progress)
            self.assertEqual(self.f.copies.calls, copies)  # No closed-copy/rollback gate after new user writes.
            request = _json(self.store._read(self.n.directory + "/opening-active.json"))["request"]
            identity = _json(self.store._read(self.n.directory + "/opening-identity-" + request["sha256"] + ".json"))
            self.assertEqual(identity["jids"], self.live)
            self.assertEqual(identity["boot"], self.boot)
            self.assertEqual(identity["readiness"], self.original_readiness)
            self.assertEqual(self.starts, [self.n.c.nextcloud_jail, self.n.c.onlyoffice_jail])

    def test_confirmation_and_stopped_pair_are_required_before_new_request(self):
        with self.f.locked():
            self.arm()
            self.reboot()
            for phrase in ("", "KEEP", "CONTINUE-PUBLICATION other"):
                with self.assertRaises(ValueError):
                    self.p.continue_publication(phrase)
            self.live[self.n.c.nextcloud_jail] = 99
            with self.assertRaisesRegex(ValueError, "stopped-pair"):
                self.p.continue_publication(self.confirmation)
            self.assertFalse(self.store._present(self.n.directory + "/opening-active.json"))
            self.assertFalse(self.starts)

    def test_explicit_same_boot_resume_never_requests_jail_start(self):
        with self.f.locked():
            self.arm()
            result = self.p.open(confirmation=self.confirmation)
            self.assertTrue(result["ready"])
            self.assertFalse(self.starts)
            self.assertFalse(self.store._present(self.n.directory + "/opening-active.json"))

    def test_same_boot_rc_or_payload_drift_refuses_before_any_jailed_command(self):
        with self.f.locked():
            self.arm()
            self.n.backend.occ.reset_mock()
            self.n.backend.jailed.reset_mock()
            script = self.f.fixture.roots[self.n.c.nextcloud_jail] / "etc/rc.d/cron"
            original = script.read_bytes()
            script.write_bytes(b"unreviewed startup")
            with self.assertRaises(ValueError):
                self.p.open(confirmation=self.confirmation)
            self.n.backend.occ.assert_not_called()
            self.n.backend.jailed.assert_not_called()
            script.write_bytes(original)
            self.payload_drift = True
            with self.assertRaises(ValueError):
                self.p.open(confirmation=self.confirmation)
            self.n.backend.occ.assert_not_called()
            self.n.backend.jailed.assert_not_called()
            self.assertFalse(self.starts)

    def test_interruption_after_start_observes_existing_jid_without_stopping_or_repeating_it(self):
        with self.f.locked():
            self.arm()
            self.reboot()
            self.fail_start, self.failure_after_start = self.n.c.nextcloud_jail, True
            with self.assertRaises(ValueError) as caught:
                self.p.continue_publication(self.confirmation)
            self.assertNotIn("PRIVATE", str(caught.exception))
            first = dict(self.live)
            with self.assertRaises(ValueError):
                self.boot_guard()  # Stale JSON after context failure grants nothing.
            self.fail_start = None
            result = self.p.continue_publication(self.confirmation)
            self.assertTrue(result["ready"])
            self.assertEqual(self.live[self.n.c.nextcloud_jail], first[self.n.c.nextcloud_jail])
            self.assertEqual(self.starts.count(self.n.c.nextcloud_jail), 1)
            request = _json(self.store._read(self.n.directory + "/opening-active.json"))["request"]
            progress = _json(self.store._read(self.n.directory + "/opening-progress-" + request["sha256"] + ".json"))
            observed = _json(self.store._bound(progress["states"][self.n.c.nextcloud_jail]["observation"]))
            self.assertEqual(observed["classification"], "observed-after-interruption")

    def test_observed_jid_replacement_refuses_instead_of_adopting_or_restarting(self):
        with self.f.locked():
            self.arm()
            self.reboot()
            self.fail_start = self.n.c.onlyoffice_jail
            with self.assertRaises(ValueError):
                self.p.continue_publication(self.confirmation)
            self.live[self.n.c.nextcloud_jail] = 199
            count = len(self.starts)
            self.fail_start = None
            with self.assertRaises(ValueError):
                self.p.continue_publication(self.confirmation)
            self.assertEqual(len(self.starts), count)
            self.assertEqual(self.live[self.n.c.nextcloud_jail], 199)

    def test_second_simulated_boot_chains_new_request_and_keeps_uncertain_first_attempt(self):
        with self.f.locked():
            self.arm()
            self.reboot()
            self.fail_start, self.failure_after_start = self.n.c.nextcloud_jail, True
            with self.assertRaises(ValueError):
                self.p.continue_publication(self.confirmation)
            first = _json(self.store._read(self.n.directory + "/opening-active.json"))["request"]
            before = self.store._read(self.n.directory + "/opening-progress-" + first["sha256"] + ".json")
            self.reboot(300)
            self.fail_start = None
            self.assertTrue(self.p.continue_publication(self.confirmation)["ready"])
            last = _json(self.store._read(self.n.directory + "/opening-active.json"))["request"]
            self.assertEqual(_json(self.store._bound(last))["previous"], first)
            self.assertEqual(self.store._read(self.n.directory + "/opening-progress-" + first["sha256"] + ".json"), before)

    def test_permission_is_separate_live_lock_exact_boot_graph_and_original_profile(self):
        with self.f.locked():
            self.arm()
            self.reboot()
            opening.continue_publication(self.p, self.confirmation)
            with self.assertRaises(ValueError):
                self.boot_guard()
            data = opening.bound(self.store)
            request, _ = opening.chain(self.store, data)[0]
            with fence.publication_starts(self.f.registry, self.f.fixture.intent, self.n.profile(), request):
                self.assertEqual(fence._publication_permission(self.store, self.f.fixture.intent,
                    self.n.c.instance, self.n.c.nextcloud_jail,
                    self.f.fixture.fixture.executor["executor_sha256"], attempt=False), self.n.c)
                with self.assertRaises(ValueError):
                    self.boot_guard()  # Already observed; this request cannot restart it.
                self.boot = "{ sec = 999, usec = 0 } different boot"
                with self.assertRaises(ValueError):
                    self.boot_guard()
                self.boot = "{ sec = 200, usec = 0 } new boot"
                self.payload_drift = True
                with self.assertRaises(ValueError):
                    self.boot_guard()
            self.payload_drift = False
            self.assertEqual(self.n.journal.read()["phase"], "recovery-opening")
            with self.assertRaises(ValueError):
                self.n.check()

    def test_unknown_profile_bytes_and_helper_drift_refuse_new_starts(self):
        with self.f.locked():
            self.arm()
            self.reboot()
            self.f.fixture.vhost.write_bytes(b"unknown vhost drift")
            with self.assertRaises(ValueError):
                self.p.continue_publication(self.confirmation)
            self.assertFalse(self.starts)

    def test_own_database_lock_is_required_and_other_instance_boot_stays_separate(self):
        with self.f.locked():
            self.arm()
            self.reboot()
        with self.f.registry.locked(recovery=True):
            with self.assertRaises(ValueError):
                self.p.continue_publication(self.confirmation)
        self.assertFalse(self.starts)

    def test_publication_session_uses_exact_pending_view_without_general_check(self):
        with self.f.locked():
            self.arm()
            self.reboot()
        with patch("installer.maintenance._deployment", return_value=self.n.d), \
                patch("installer.operations.ROOT_UID", os.geteuid()), \
                patch("installer.maintenance_validation.FixedValidator.descriptor", return_value=self.f.fixture.fixture.recipe), \
                patch.object(NativeContext, "check", side_effect=AssertionError("general check must remain closed")):
            with publication.publication_session(self.f.registry, self.n.d.runner, self.n.operation) as active:
                self.assertTrue(active.context.active)
                self.assertEqual(active.context.journal.read()["phase"], "recovery-opening")
                self.f.registry._require_lock(recovery=True)
            self.assertFalse(active.context.active)


class ScheduledWriterBoundaryTests(unittest.TestCase):
    def fixture(self, recovering):
        f = OpeningTests()
        f.recovering = recovering
        f.setUp()
        self.addCleanup(f.doCleanups)
        return f

    def assert_fenced(self, f):
        profile, _ = fence._profile(f.store, f.n.profile())
        fence._check_files(f.store, profile, "publication")
        for jail in f.live:
            self.assertFalse(f.f.services[jail]["cron"])
            self.assertFalse(f.f.services[jail]["sshd"])

    def test_both_outcomes_second_start_failure_keeps_scheduled_writers_fenced(self):
        for recovering in (False, True):
            with self.subTest(recovering=recovering):
                f = self.fixture(recovering)
                with f.f.locked():
                    f.arm()  # Real maintenance-off, interrupted before profile application.
                    self.assertFalse(f.f.maintenance)
                    pending = f.store.pending()
                    f.reboot()
                    f.fail_start = f.n.c.onlyoffice_jail
                    with self.assertRaises(ValueError):
                        f.p.continue_publication(f.confirmation)
                    self.assertEqual(set(f.live), {f.n.c.nextcloud_jail})
                    self.assert_fenced(f)
                    self.assertEqual(f.store.pending(), pending)
                    with self.assertRaises(ValueError):
                        f.boot_guard()  # Persisted permission is inert without its lock.
                    f.fail_start = None
                    self.assertTrue(f.p.continue_publication(f.confirmation)["ready"])
                    self.assertEqual(f.f.services, f.f.original)

    def test_both_outcomes_public_status_failure_prevents_flag_and_process_release(self):
        for recovering in (False, True):
            with self.subTest(recovering=recovering):
                f = self.fixture(recovering)
                with f.f.locked():
                    f.arm()
                    f.reboot()
                    with patch.object(f.p, "_public_status", side_effect=ValueError("not ready")):
                        with self.assertRaises(ValueError):
                            f.p.continue_publication(f.confirmation)
                    self.assert_fenced(f)
                    progress = f.p._progress(f.store.reference(f.n.directory + "/native-publication.json"))
                    self.assertEqual(progress["completed"], list(publication.STEPS[:3]))
                    self.assertEqual(progress["running"], "public-status")
                    self.assertTrue(f.p.continue_publication(f.confirmation)["ready"])

    def test_release_requires_current_progress_and_original_bytes_cannot_boot(self):
        f = self.fixture(True)
        with f.f.locked():
            f.arm()
            f.reboot()
            opening.continue_publication(f.p, f.confirmation)
            pub = f.store.reference(f.n.directory + "/native-publication.json")
            old = f.store.reference(f.n.directory + "/publication-progress.json")
            with self.assertRaises(ValueError):
                fence.publication_profile(f.f.registry, f.n.profile(), publication=pub, progress=old)
            self.assert_fenced(f)
            data = opening.bound(f.store)
            request, _ = opening.chain(f.store, data)[0]
            with fence.publication_starts(f.f.registry, f.f.fixture.intent, f.n.profile(), request):
                profile, _ = fence._profile(f.store, f.n.profile())
                item = profile["files"][0]
                path = f.n.d.jail_root(item["jail"]) / item["path"]
                saved = path.read_bytes()
                path.write_bytes(f.store._bound(item["original"]))
                with self.assertRaises(ValueError):
                    fence._publication_permission(f.store, f.f.fixture.intent, f.n.c.instance,
                        f.n.c.nextcloud_jail, f.f.fixture.fixture.executor["executor_sha256"], attempt=False)
                path.write_bytes(saved)

    def test_both_outcomes_all_six_effect_checkpoint_interruptions_resume_forward(self):
        for recovering in (False, True):
            for step in publication.STEPS:
                with self.subTest(recovering=recovering, step=step):
                    f = self.fixture(recovering)
                    with f.f.locked():
                        commitment = f.f.committed()
                        put = f.p.store._put
                        def interrupt(path, value, **kwargs):
                            if (path == f.n.directory + "/publication-progress.json"
                                    and value.get("completed", [])[-1:] == [step] and value.get("running") is None):
                                raise OSError("effect before checkpoint")
                            return put(path, value, **kwargs)
                        with patch.object(f.p.store, "_put", side_effect=interrupt), self.assertRaises(ValueError):
                            f.p.open(commitment)
                        if step in publication.STEPS[:4]:
                            for services in f.f.services.values():
                                self.assertFalse(services["cron"])
                                self.assertFalse(services["sshd"])
                        f.reboot()
                        self.assertTrue(f.p.continue_publication(f.confirmation)["ready"])
                        self.assertEqual(f.f.services, f.f.original)


class TerminalContinuationTests(unittest.TestCase):
    def test_presealed_transition_retries_after_reboot_without_new_terminal_metadata(self):
        f = OpeningTests()
        f.setUp()
        self.addCleanup(f.doCleanups)
        with f.f.locked():
            commitment = f.f.committed()
            write = f.n.journal._write
            def fail_before_terminal(value, **kwargs):
                if value["phase"] == "recovered":
                    raise OSError("simulated controller interruption after sealing before terminal journal")
                return write(value, **kwargs)
            with patch.object(f.n.journal, "_write", side_effect=fail_before_terminal), self.assertRaises(ValueError):
                f.p.open(commitment)
            self.assertEqual(f.n.journal.read()["phase"], "recovery-opening")
            sealed = f.store._read(f.n.directory + "/publication-finalization.json")
            f.reboot()
            self.assertTrue(f.p.open(confirmation=f.confirmation)["ready"])
            self.assertEqual(f.store._read(f.n.directory + "/publication-finalization.json"), sealed)
            self.assertEqual(f.store.reference(f.n.journal.path), _json(sealed)["journal"])

    def test_terminal_pending_partial_start_is_observed_without_restarting_live_jail(self):
        f = OpeningTests()
        f.setUp()
        self.addCleanup(f.doCleanups)
        with f.f.locked():
            commitment = f.f.committed()
            with patch.object(f.n.native, "finish", side_effect=OSError()), self.assertRaises(ValueError):
                f.p.open(commitment)
            terminal = f.store._read(f.n.journal.path)
            f.reboot()
            f.fail_start, f.failure_after_start = f.n.c.nextcloud_jail, True
            with self.assertRaises(ValueError):
                f.p.open(confirmation=f.confirmation)
            jid = f.live[f.n.c.nextcloud_jail]
            f.fail_start = None
            self.assertTrue(f.p.open(confirmation=f.confirmation)["ready"])
            self.assertEqual(f.live[f.n.c.nextcloud_jail], jid)
            self.assertEqual(f.starts.count(f.n.c.nextcloud_jail), 1)
            self.assertEqual(f.store._read(f.n.journal.path), terminal)

    def test_both_outcomes_reboot_at_each_terminal_write_boundary_and_finish_forward(self):
        for recovering in (False, True):
            for boundary in ("journal", "native-terminal", "lifecycle-terminal"):
                with self.subTest(recovering=recovering, boundary=boundary):
                    f = OpeningTests()
                    f.recovering = recovering
                    f.setUp()
                    try:
                        n, p, store = f.n, f.p, f.store
                        with f.f.locked():
                            commitment = f.f.committed()
                            if boundary == "journal":
                                write = n.journal._write
                                def failed(value, **kwargs):
                                    result = write(value, **kwargs)
                                    if value["phase"] in ("complete", "recovered"):
                                        raise OSError("simulated controller interruption after journal")
                                    return result
                                fault = patch.object(n.journal, "_write", side_effect=failed)
                            elif boundary == "native-terminal":
                                finish = n.journal.terminal
                                def failed():
                                    finish()
                                    raise OSError("simulated controller interruption after native terminal")
                                fault = patch.object(n.journal, "terminal", side_effect=failed)
                            else:
                                put = n.native.store._put
                                def failed(path, value, **kwargs):
                                    if path == "maintenance/pending.json" and value.get("state") == "idle":
                                        raise OSError("simulated controller interruption before idle")
                                    return put(path, value, **kwargs)
                                fault = patch.object(n.native.store, "_put", side_effect=failed)
                            with fault, self.assertRaises(ValueError):
                                p.open(commitment)
                            outcome = "recovered" if recovering else "complete"
                            self.assertEqual(n.journal.read()["phase"], outcome)
                            self.assertIsNotNone(store.pending())
                            saved = {name: store._read(n.directory + "/" + name + ".json") for name in
                                     ("native-journal", "opening-journal", "native-publication", "publication-finalization")}
                            f.reboot()
                            with self.assertRaises(ValueError):
                                f.boot_guard()
                            result = p.open(confirmation=f.confirmation)
                            self.assertEqual(result["state"], outcome)
                            self.assertTrue(result["ready"])
                            self.assertIsNone(store.pending())
                            self.assertEqual(f.f.services, f.f.original)
                            for name, data in saved.items():
                                self.assertEqual(store._read(n.directory + "/" + name + ".json"), data)
                            self.assertEqual(f.starts, [n.c.nextcloud_jail, n.c.onlyoffice_jail])
                            request = _json(store._read(n.directory + "/opening-active.json"))["request"]
                            self.assertEqual(_json(store._bound(request))["terminal"],
                                             store.reference(n.directory + "/publication-finalization.json"))
                    finally:
                        f.doCleanups()

    def test_changed_terminal_journal_is_not_reinterpreted_as_opening(self):
        f = OpeningTests()
        f.setUp()
        self.addCleanup(f.doCleanups)
        with f.f.locked():
            commitment = f.f.committed()
            with patch.object(f.n.journal, "terminal", side_effect=OSError()), self.assertRaises(ValueError):
                f.p.open(commitment)
            value = f.n.journal.read()
            value["updated"] = "2030-01-01T00:00:00Z"
            f.store._put(f.n.journal.path, value, replace=True)
            f.reboot()
            f.n.backend.occ.reset_mock()
            f.n.backend.jailed.reset_mock()
            with self.assertRaises(ValueError):
                f.p.open(confirmation=f.confirmation)
            self.assertFalse(f.starts)
            f.n.backend.occ.assert_not_called()
            f.n.backend.jailed.assert_not_called()


class PayloadTests(unittest.TestCase):
    def test_profile_projection_matches_original_for_closed_and_partial_known_bytes(self):
        from installer import enrollment
        f = fixtures.fixtures.MaintenanceFenceTests()
        f.setUp()
        self.addCleanup(f.doCleanups)
        with f.registry.locked(recovery=True):
            reference = f.capture()
            profile, _ = fence._profile(f.store, reference)
            replacements = {f.roots[item["jail"]] / item["path"]:
                (f.store._bound(item["original"]), f.store._bound(item["closed"])) for item in profile["files"]}
            trees = [(root / name, root) for root in f.roots.values() for name in ("etc", "usr/local/etc")]
            def identity(tree, root, *, projected):
                options = dict(jail_root=root, observed_roots=(root / "etc", root / "usr/local/etc"))
                return (opening._profile_tree(tree, replacements=replacements, **options) if projected else
                        enrollment._tree_identity(tree, **options))
            original = [identity(tree, root, projected=False) for tree, root in trees]
            fence.install_profile(f.registry, reference)
            for index, item in enumerate(profile["files"]):
                fence._check_files(f.store, profile, "either")
                self.assertEqual([identity(tree, root, projected=True) for tree, root in trees], original)
                (f.roots[item["jail"]] / item["path"]).write_bytes(f.store._bound(item["original"]))
            f.vhost.write_bytes(b"unknown partial public profile")
            with self.assertRaises(ValueError):
                identity(f.vhost.parent.parent, f.roots[f.config.nextcloud_jail], projected=True)

    def test_stopped_target_uses_nc_app_dataset_and_preserves_dynamic_configuration(self):
        from installer import enrollment, maintenance_generations as generations, maintenance_validation as validation
        from installer.maintenance_admission import STATIC_ROOTS
        from installer.generations import _hash
        f = validation_fixtures.AuthenticatedCodeTests()
        f.setUp()
        self.addCleanup(f.doCleanups)
        f.prepared_code(target=True)
        n = f.n
        _, _, _, code, _ = validation._code(n, True)
        # Model a stopped jail: no NC nullfs mount, actual code remains in nc-app.
        root = f.home / "bastille"
        mount = f.home / "instances/cloud"
        mount.mkdir(parents=True)
        f.app.rename(mount / "nc-app")
        for jail, old in f.roots.items():
            new = root / "jails" / jail / "root"
            new.parent.mkdir(parents=True)
            old.rename(new)
            f.roots[jail] = new
        config = SimpleNamespace(instance=n.c.instance, bastille_root=str(root), mount_root=str(mount),
            nextcloud_jail=n.c.nextcloud_jail, onlyoffice_jail=n.c.onlyoffice_jail)
        f.inputs["operation"] = n.operation
        helpers = {"resources/jails/runtime-inventory.php": _hash(b"reviewed runtime helper")}
        baseline = {}
        raw = n.store._bound(f.inputs["originals"][n.c.instance]["files"]["config.json"]["retained"])
        target = generations.target_configuration(raw)
        plan = generations.target_plan(raw, f.plan)
        for group, jail in validation._roles(n):
            jailroot = f.roots[jail]
            names = (*STATIC_ROOTS, "usr/local/www/" + ("nextcloud" if group == "nextcloud" else "onlyoffice/documentserver"))
            for name in names:
                (jailroot / name).mkdir(parents=True, exist_ok=True)
            f.write(jailroot / "etc/passwd", f"www:*:{os.geteuid()}:{os.getegid()}:Web:/nonexistent:/usr/sbin/nologin\n".encode())
            for name, data in generations.public_runtime_files(target, plan, group).items():
                f.write(jailroot / "root/cloud-installer" / name, data)
            f.write(jailroot / "root/cloud-installer/resources/jails/runtime-inventory.php", b"reviewed runtime helper")
            if group == "nextcloud":
                f.write(jailroot / "usr/local/libexec/cloud-runtime-inventory.php", b"reviewed runtime helper")
            baseline[jail] = {name: enrollment._tree_identity(jailroot / name, jail_root=jailroot,
                observed_roots=tuple(jailroot / p for p in names)) for name in names}
        baseline_ref = n.record("opening-test-baseline", dict(observation=dict(trees=baseline)))
        admission = n.record("opening-test-admission", dict(generation=f.inputs["entries"][n.c.instance]["generation"],
            executor=f.inputs["executor"], first_readiness=baseline_ref))
        n.record("admission", dict(evidence=admission))
        n.record("closed-profile", dict(roots={j: str(r) for j, r in f.roots.items()}, files=[]))
        proof = dict(checks=dict(code=code), recovering=False, generation=f.ref)
        with patch.object(generations, "source_hashes", return_value=helpers), \
                patch.object(opening, "ROOT_GID", os.getegid()), \
                patch.object(fence, "_profile", return_value=(_json(n.store._read(n.directory + "/closed-profile.json")), config)), \
                patch.object(fence, "_check_files"):
            first = opening.payload(n.store, config, f.inputs, n.journal.read(), proof)
            # New public writes may update config.php; only its ownership/mode are pinned.
            (mount / "nc-app/config/config.php").write_bytes(b"new valid dynamic application settings")
            self.assertEqual(opening.payload(n.store, config, f.inputs, n.journal.read(), proof), first)
            # Enter the actual same-boot resume gate with real authenticated code
            # and public files. Host graph/locks are exercised by OpeningTests.
            resume_proof = dict(proof, boot="{ sec = 100, usec = 0 } same boot",
                                jids={config.nextcloud_jail: 41, config.onlyoffice_jail: 42})
            resumed_journal = dict(n.journal.read(), phase="opening", evidence=dict(readiness=f.ref))
            data = (n.directory, {}, config, f.inputs, resumed_journal, resume_proof, f.ref, f.ref, {})
            pub = Mock(context=n)
            pub._publication_context.return_value = (resumed_journal, resume_proof)
            pub._publication_record.return_value = f.ref
            def resume():
                n.backend.occ.reset_mock()
                n.backend.jailed.reset_mock()
                with patch.object(n, "c", config), patch.object(opening, "bound", return_value=data), \
                        patch.object(opening, "chain", return_value=(None, None)), \
                        patch.object(opening, "_pair", return_value=resume_proof["jids"]), \
                        patch.object(opening, "storage"), \
                        patch.object(n.backend, "output", return_value=resume_proof["boot"]):
                    return opening.continue_publication(pub, "CONTINUE-PUBLICATION " + n.operation)
            self.assertEqual(resume()["jids"], resume_proof["jids"])
            path = mount / "nc-app/lib/core.php"
            path.chmod(0o750)  # Signed non-executable file may not gain execute permission.
            with self.assertRaises(ValueError):
                resume()
            n.backend.occ.assert_not_called()
            n.backend.jailed.assert_not_called()
            path.chmod(0o640)
            original_code = path.read_bytes()
            path.write_bytes(b"changed core bytes")
            with self.assertRaises(ValueError):
                resume()
            n.backend.occ.assert_not_called()
            n.backend.jailed.assert_not_called()
            path.write_bytes(original_code)
            worker = f.roots[n.c.onlyoffice_jail] / "root/cloud-installer/runtime.json"
            worker.write_bytes(b"unknown runtime payload")
            with self.assertRaises(ValueError):
                resume()
            n.backend.occ.assert_not_called()
            n.backend.jailed.assert_not_called()
        self.assertFalse(any("bastille" in command for command in f.commands))


if __name__ == "__main__":
    unittest.main()
