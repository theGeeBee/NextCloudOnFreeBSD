"""Offline persistent closure and real flock checks; no native execution."""

import copy
import fcntl
import json
import multiprocessing
import os
from pathlib import Path
import unittest
from unittest.mock import patch, PropertyMock

from installer import maintenance_fence as fence
from installer.config import Config
from installer.maintenance_journal import NativeJournal, NATIVE_REQUIRED
from installer.paths import RESOURCES
from installer.state import Registry, atomic_json, atomic_write
import test_maintenance_state as fixtures


def _holder(root, intent, receipt, connection):
    registry = Registry(root)
    with registry.locked(recovery=True), fence.validation_starts(registry, intent, receipt, phase="validating"):
        connection.send("held")
        connection.recv()
        os._exit(0)


class MaintenanceFenceTests(unittest.TestCase):
    def setUp(self):
        fixture = fixtures.NativeStateTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.registry, self.store = fixture.registry, fixture.store
        self.operation = fixture.operation
        self.directory = "maintenance/operations/" + self.operation
        for target, kwargs in (
                ("installer.maintenance_fence._root_required", {}),
                ("installer.maintenance.executor_record", {"return_value": fixture.executor}),
                ("installer.config.Config.bastille_root", {"new_callable": PropertyMock,
                                                          "return_value": str(fixture.root / "jails-fixture")})):
            mocker = patch(target, **kwargs)
            mocker.start()
            self.addCleanup(mocker.stop)
        self.store._put("lifecycle/executor.json", fixture.executor,
                        replace=self.store._present("lifecycle/executor.json"))
        with self.registry.locked(recovery=True):
            # Add a ready, current-source neighboring legacy entry before the
            # execution snapshot, using the normal graph publication writer.
            self.store.begin("register-neighbor", "register", ["other"], fixture.executor["executor_sha256"])
            atomic_json(self.store.root / "instances/other/status.json", {"state": "ready"})
            atomic_write(self.store.root / "instances/other/source.sha256", fixture.executor["source_sha256"])
            fixture.entries["other"] = self.store.legacy_entry("other")
            self.store.commit("graph-neighbor", fixture.entries, "register-neighbor")
            self.store.finish("register-neighbor")
            fixture.base = self.store._active()
            preparation = json.loads(self.store._bound(fixture.preparation))
            plan = json.loads(self.store._bound(preparation["plan"]))
            plan.update(plan_id="plan-neighbor")
            plan["bindings"]["graph"] = fixture.base
            preparation["plan"] = self.store._put("maintenance/plans/plan-neighbor.json", plan)
            preparation["operation"] = "maint-neighbor"
            self.store._mkdir("maintenance/operations/maint-neighbor")
            fixture.preparation = self.store._put("maintenance/operations/maint-neighbor/operation.json", preparation)
            self.intent = fixture.begin()
            self.config = fixture.native.view(self.operation).load("cloud")
            self.journal = NativeJournal(self.registry, self.operation,
                self.store.reference(self.directory + "/intent.json"), fixture.recipe, native=fixture.native)
            self.journal.initialize()
            self.evidence = self.store._put(self.directory + "/test-observation.json", {"offline_fixture": True})
        self.roots = {jail: Path(self.config.bastille_root, "jails", jail, "root")
                      for jail in (self.config.nextcloud_jail, self.config.onlyoffice_jail)}
        for jail, root in self.roots.items():
            for directory in (*fence.STARTUP_TREES, "etc/defaults", "usr/local/etc/apache24"):
                (root / directory).mkdir(parents=True, exist_ok=True)
            for name in fence.STARTUP_FILES:
                data = b'# reviewed test baseline\n' if name != "etc/rc.conf" else (
                    b'hostname="original.example.test"\ncron_enable="YES"\nsshd_enable="YES"\n'
                    b'apache24_enable="YES"\nphp_fpm_enable="YES"\nmysql_enable="YES"\n'
                    b'redis_enable="YES"\nnginx_enable="YES"\nsupervisord_enable="YES"\n')
                (root / name).write_bytes(data)
                (root / name).chmod(0o644)
            (root / "etc/rc.d/cron").write_bytes(b"# reviewed cron script\n")
            (root / "etc/rc.d/cron").chmod(0o644)
        self.vhost = self.roots[self.config.nextcloud_jail] / fence.VHOST
        self.vhost.write_bytes((RESOURCES / "templates/nextcloud/https.conf").read_bytes())
        self.vhost.chmod(0o644)
        (self.vhost.parent / "cloud-onlyoffice.conf").write_text(
            '<Location /onlyoffice/>\n    Require all granted\n</Location>\n')
        (self.vhost.parent / "cloud-onlyoffice.conf").chmod(0o644)
        self.context = dict(config=json.loads(self.config.to_json()),
            roots={name: str(root) for name, root in self.roots.items()},
            baseline={jail: fence.startup_inventory(root, nextcloud=jail == self.config.nextcloud_jail)
                      for jail, root in self.roots.items()}, operator_saved_closed=True)

    def capture(self):
        return fence.capture_profile(self.context, self.store, self.operation)

    def closed(self):
        receipt = self.capture()
        fence.install_profile(self.registry, receipt)
        self.phase("quiesced")
        return receipt

    def phase(self, target):
        path = ["capture", "quiesced", "recovery-ready", "migrating", "validating"]
        if target in ("restored-closed", "recovery-validating", "recovery-opening"):
            path += ["restoring", "restored-closed", "recovery-validating", "recovery-opening"]
        else:
            path += ["committed-closed", "opening", "complete"]
        current = self.journal.read()["phase"]
        for phase in path[path.index(current) + 1:path.index(target) + 1]:
            self.journal.advance(phase, {key: self.evidence for key in NATIVE_REQUIRED[phase]})

    def boot(self, **changes):
        args = dict(registry=Registry(self.registry.root), intent=self.intent, instance="cloud",
                    jail=self.config.nextcloud_jail, executor=self.fixture.executor["executor_sha256"])
        args.update(changes)
        return fence.boot_permission(**args)

    def test_capture_close_restore_reapply_preserves_exact_bytes_modes_and_pf(self):
        network = copy.deepcopy(self.store._active())
        pf = {name: self.store._bound(ref) for name, ref in
              self.fixture.native._inputs(self.intent)["network"]["records"].items()}
        with self.registry.locked(recovery=True):
            receipt = self.closed()
            profile = json.loads(self.store._bound(receipt))
            self.assertEqual(self.capture(), receipt)
            self.assertEqual(fence.install_profile(self.registry, receipt), receipt)
            self.assertEqual(fence.verify_closed(self.store, receipt), self.config)
            for item in profile["files"]:
                path = self.roots[item["jail"]] / item["path"]
                self.assertEqual(path.stat().st_mode & 0o777, 0o644)
                self.assertEqual((self.store.root / item["original"]["path"]).stat().st_mode & 0o777, 0o600)
                original = self.store._bound(item["original"])
                if item["path"] == "etc/rc.conf":
                    role = "nextcloud" if item["jail"] == self.config.nextcloud_jail else "onlyoffice"
                    for service in fence.SERVICES[role]:
                        self.assertIn(f'{service}_enable="NO"'.encode(), path.read_bytes())
                path.write_bytes(original)  # Simulated exact ZFS original restoration.
            with self.assertRaises(ValueError):
                fence.verify_closed(self.store, receipt)
            fence.install_profile(self.registry, receipt)
            self.assertEqual(fence.verify_closed(self.store, receipt), self.config)
        self.assertEqual(self.store._active(), network)
        self.assertEqual(pf, {name: self.store._bound(ref) for name, ref in
                         self.fixture.native._inputs(self.intent)["network"]["records"].items()})

    def test_server_rewrite_precedes_redirects_includes_and_location_grants(self):
        for mode, filename, count in (("provided", "https.conf", 2), ("external", "external.conf", 1)):
            config = copy.copy(self.config)
            config.tls_mode = mode
            original = (RESOURCES / "templates/nextcloud" / filename).read_bytes()
            closed = fence._closed_vhost(original, config).decode()
            self.assertEqual(closed.count("RewriteRule ^ - [R=503,END]"), count)
            for body in closed.split("<VirtualHost ")[1:]:
                lines = body.splitlines()
                self.assertEqual(lines[1].strip(), "# Installer maintenance CLOSED: actual connection peer only.")
                self.assertEqual(lines[6].strip(), "RewriteRule ^ - [R=503,END]")
                self.assertNotIn("REMOTE_ADDR}", "\n".join(lines[:7]).replace("CONN_REMOTE_ADDR}", ""))
                self.assertNotIn("X-Forwarded", "\n".join(lines[:7]))
                self.assertLess(body.index("[R=503,END]"), body.index("IncludeOptional") if "IncludeOptional" in body else len(body))
            for malformed in (original.replace(b"*:80", b"*:8080"), original + b"<VirtualHost *:80>\n",
                              original.replace(b"<VirtualHost *:80>", b"<VirtualHost *:80 *:81>")):
                with self.assertRaises(ValueError):
                    fence._closed_vhost(malformed, config)

    def test_malformed_cancellation_request_cannot_fall_through_live_validation_permission(self):
        from installer import maintenance_cancellation as cancellation
        with self.registry.locked(recovery=True):
            receipt = self.closed()
            self.phase("validating")
            with fence.validation_starts(self.registry, self.intent, receipt, phase="validating"):
                self.assertEqual(self.boot(), self.config)
                self.store._put(self.directory + "/cancellation-request.json", {"forged": True})
                with patch.object(cancellation, "boot_permission", wraps=cancellation.boot_permission) as routed, \
                        patch.object(fence, "_publication_permission") as publication:
                    with self.assertRaises(ValueError):
                        self.boot()
                    routed.assert_called_once()
                    publication.assert_not_called()
                # Even a cancellation route error cannot fall back to an active
                # old permission. An unaffected neighbor uses its separate path.
                with patch.object(cancellation, "boot_permission", side_effect=ValueError("denied")) as routed:
                    with self.assertRaises(ValueError):
                        self.boot()
                    other = self.boot(instance="other", jail="othernc")
                    self.assertEqual(other.instance, "other")
                    self.assertEqual(routed.call_count, 1)

    def test_unsafe_rc_syntax_and_override_files_refused(self):
        for text in (b'. /etc/evil\n', b'x="$(touch /tmp/evil)"\n', b'rc_conf_files="/etc/other"\n',
                     b'local_startup="/other"\n', b'cron_enable="NO"; cron_enable="YES"\n', b'x=`id`\n'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                fence._closed_rc(text, fence.SERVICES["nextcloud"])
        root = self.roots[self.config.nextcloud_jail]
        for name in (*fence.OVERRIDES, "etc/rc.conf.d/cron", "usr/local/etc/rc.conf.d/apache24"):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"")
            try:
                with self.subTest(name=name), self.registry.locked(recovery=True), self.assertRaises(ValueError):
                    self.capture()
            finally:
                path.unlink()

    def test_unreviewed_startup_and_drift_refuse_before_any_write(self):
        with self.registry.locked(recovery=True):
            receipt = self.capture()
            before = self.vhost.read_bytes()
            path = self.roots[self.config.onlyoffice_jail] / "etc/rc.conf"
            path.write_bytes(path.read_bytes() + b'cron_enable="NO"\n')
            with self.assertRaises(ValueError):
                fence.install_profile(self.registry, receipt)
            self.assertEqual(self.vhost.read_bytes(), before)
        path.write_bytes(self.store._bound(json.loads(self.store._bound(receipt))["files"][2]["original"]))
        rogue = path.parent / "rc.d/unreviewed"
        rogue.write_bytes(b"# new startup script\n")
        with self.registry.locked(recovery=True), self.assertRaises(ValueError):
            fence.install_profile(self.registry, receipt)

    def test_context_original_root_config_and_operator_confirmation_required(self):
        for key, value in (("operator_saved_closed", False), ("roots", {}), ("config", {}), ("baseline", {})):
            context = {**self.context, key: value}
            with self.registry.locked(recovery=True), self.subTest(key=key), self.assertRaises(ValueError):
                fence.capture_profile(context, self.store, self.operation)
        with self.assertRaises(ValueError):
            self.capture()

    def test_live_permissions_stale_record_and_phase_revocation(self):
        with self.registry.locked(recovery=True):
            receipt = self.closed()
            for phase in ("quiesced", "recovery-ready", "migrating", "validating", "restored-closed", "recovery-validating"):
                self.phase(phase)
                with fence.validation_starts(self.registry, self.intent, receipt, phase=phase):
                    self.assertEqual(self.boot(), self.config)
                    self.assertEqual(self.boot(jail=self.config.onlyoffice_jail), self.config)
                    for changes in ({"instance": "other"}, {"jail": "othernc"}, {"executor": "f" * 64},
                                    {"intent": {**self.intent, "action": "enroll"}}):
                        with self.assertRaisesRegex(ValueError, fence.DENIED):
                            self.boot(**changes)
                with self.assertRaisesRegex(ValueError, fence.DENIED):
                    self.boot()
            for phase in ("opening", "recovery-opening", "completed", "unknown"):
                with self.assertRaises(ValueError), fence.validation_starts(self.registry, self.intent, receipt, phase=phase):
                    self.fail("opening permission granted")
            with fence.validation_starts(self.registry, self.intent, receipt, phase="recovery-validating"):
                phase_path = self.store.root / self.directory / "native-phase.json"
                value = json.loads(phase_path.read_bytes())
                value["phase"] = "migrating"
                atomic_json(phase_path, value)
                with self.assertRaisesRegex(ValueError, fence.DENIED):
                    self.boot()

    def test_source_profile_permission_and_namespace_corruption(self):
        with self.registry.locked(recovery=True):
            receipt = self.closed()
            self.phase("validating")
            with fence.validation_starts(self.registry, self.intent, receipt, phase="validating"):
                for relative in (receipt["path"], self.directory + "/native-start.json",
                                 self.directory + "/native-inputs.json", "lifecycle/executor.json"):
                    path = self.store.root / relative
                    saved = path.read_bytes()
                    value = json.loads(saved)
                    value["unknown"] = "private-never-print"
                    atomic_json(path, value)
                    with self.assertRaisesRegex(ValueError, "^" + fence.DENIED + "$"):
                        self.boot()
                    path.write_bytes(saved)
                with patch("installer.maintenance.executor_record", return_value={**self.fixture.executor, "payload_path": "/changed"}):
                    with self.assertRaisesRegex(ValueError, fence.DENIED):
                        self.boot()
                path = self.store.root / self.directory / "native-start.json"
                value = json.loads(path.read_bytes())
                value["kind"] = "enrollment-start"
                atomic_json(path, value)
                with self.assertRaisesRegex(ValueError, fence.DENIED):
                    self.boot()

    def test_native_journal_update_revokes_until_context_reissued(self):
        with self.registry.locked(recovery=True):
            receipt = self.closed()
            with self.assertRaises(ValueError), fence.validation_starts(self.registry, self.intent, receipt, phase="validating"):
                self.fail("caller phase overrode actual native journal")
            self.phase("validating")
            with fence.validation_starts(self.registry, self.intent, receipt, phase="validating"):
                self.journal.step_start("closed-probe", replay="idempotent", precondition=self.evidence)
                with self.assertRaisesRegex(ValueError, fence.DENIED):
                    self.boot()
            with fence.validation_starts(self.registry, self.intent, receipt, phase="validating"):
                self.assertEqual(self.boot(), self.config)
            path = self.store.root / self.journal.path
            saved = path.read_bytes()
            from installer.maintenance_journal import initial
            atomic_json(path, initial(self.store.reference(self.directory + "/intent.json")))
            with self.assertRaises(ValueError), fence.validation_starts(self.registry, self.intent, receipt, phase="validating"):
                self.fail("preparation journal authorized native boot")
            path.write_bytes(saved)
            self.journal.fail("closure-lost")
            with self.assertRaises(ValueError), fence.validation_starts(self.registry, self.intent, receipt, phase="validating"):
                self.fail("publication-uncertain failure authorized boot")

    def test_reclosure_permission_requires_bound_request_database_lock_and_exact_journal(self):
        with self.registry.locked(recovery=True):
            receipt = self.closed()
            manifest = self.store._put(self.directory + "/recovery-fixture.json", {"cold_boundary": "a" * 64})
            self.journal.advance("recovery-ready", {"recovery_set": manifest, "closure": self.evidence})
            prior = self.journal.read()
            priorref = self.store._put(self.directory + "/prior-reclosure.json", prior)
            request = self.store._put(self.directory + "/request-reclosure.json", dict(schema_version=1,
                kind="native-reclosure-request", operation=self.operation, confirmation="REQUIESCE-MAINTENANCE " + self.operation,
                prior_phase=prior["phase"], prior_last_safe_phase=prior["last_safe_phase"], prior_journal=priorref,
                boot="{ sec = 1792100000, usec = 2 } current boot", old_shutdown=self.evidence,
                capture_anchor_sha256="a" * 64, manifest=manifest, runtime=self.evidence,
                assessment_sha256="b" * 64, profile=receipt))
            self.journal.advance("recovery-reclosing", {"reclosure_request": request, "closure": self.evidence})
            with self.assertRaises(ValueError):
                self.boot()
            with self.assertRaises(ValueError), fence.validation_starts(self.registry, self.intent, receipt, phase="recovery-reclosing"):
                self.fail("database lock missing")
            fd = fence._lock_file(self.store, "instances/cloud/database-operation.lock", create=True)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with fence.validation_starts(self.registry, self.intent, receipt, phase="recovery-reclosing"):
                    self.assertEqual(self.boot(), self.config)
                    self.assertEqual(self.boot(jail=self.config.onlyoffice_jail), self.config)
                    self.journal.step_start("reclose-one", replay="never", precondition=request)
                    with self.assertRaises(ValueError):
                        self.boot()
                with fence.validation_starts(self.registry, self.intent, receipt, phase="recovery-reclosing"):
                    self.assertEqual(self.boot(), self.config)
                    fcntl.flock(fd, fcntl.LOCK_UN)
                    with self.assertRaises(ValueError):
                        self.boot()
            finally:
                os.close(fd)
            with self.assertRaises(ValueError):
                self.boot()

    def test_interrupted_install_replays_only_sealed_bytes(self):
        with self.registry.locked(recovery=True):
            receipt = self.capture()
            replace = fence._replace
            count = 0

            def interrupted(*args):
                nonlocal count
                count += 1
                if count == 2:
                    raise RuntimeError("injected interruption")
                return replace(*args)

            with patch.object(fence, "_replace", side_effect=interrupted), self.assertRaises(RuntimeError):
                fence.install_profile(self.registry, receipt)
            journal = json.loads(self.store._read(self.directory + "/profile-apply.json"))
            self.assertEqual(journal["state"], "applying")
            self.assertEqual(journal["index"], 1)
            fence.install_profile(self.registry, receipt)
            self.assertEqual(fence.verify_closed(self.store, receipt), self.config)

    def test_both_exclusive_locks_required_and_nested_holder_refused(self):
        with self.registry.locked(recovery=True):
            receipt = self.closed()
            with fence.validation_starts(self.registry, self.intent, receipt, phase="quiesced"):
                with self.assertRaises(BlockingIOError), fence.validation_starts(self.registry, self.intent, receipt, phase="validating"):
                    self.fail("nested permission")
                with self.assertRaises(BlockingIOError):
                    fence.install_profile(self.registry, receipt)
            # Reapplying/capturing a profile must not revive the inert start
            # record left by the earlier, now-ended validation context.
            with fence._exclusive(self.store, self.directory):
                with self.assertRaisesRegex(ValueError, fence.DENIED):
                    self.boot()
        lock = self.store.root / self.directory / "native-start.lock"
        with lock.open("rb") as permission, (self.store.root / "operation.lock").open("rb") as global_lock:
            fcntl.flock(permission, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(ValueError):
                self.boot()
            fcntl.flock(global_lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            with self.assertRaises(ValueError):
                self.boot()
            fcntl.flock(global_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(permission, fcntl.LOCK_SH | fcntl.LOCK_NB)
            with self.assertRaises(ValueError):
                self.boot()

    def test_process_crash_revokes_permission_despite_json(self):
        with self.registry.locked(recovery=True):
            receipt = self.closed()
            self.phase("validating")
        ctx = multiprocessing.get_context("fork")
        parent, child = ctx.Pipe()
        process = ctx.Process(target=_holder, args=(self.registry.root, self.intent, receipt, child))
        process.start()
        child.close()
        try:
            self.assertTrue(parent.poll(20))
            self.assertEqual(parent.recv(), "held")
            self.assertEqual(self.boot(), self.config)
            parent.send("crash")
            process.join(20)
            self.assertEqual(process.exitcode, 0)
            with self.assertRaisesRegex(ValueError, fence.DENIED):
                self.boot()
        finally:
            if process.is_alive():
                process.kill()
                process.join()
            parent.close()

    def test_unaffected_ready_pair_can_boot_without_locks_or_profile(self):
        other = Config.from_json((self.store.root / "instances/other/config.json").read_text())
        for jail in (other.nextcloud_jail, other.onlyoffice_jail):
            self.assertEqual(self.boot(instance="other", jail=jail), other)
        for changes in ({"instance": "other", "jail": "cloudnc"},
                        {"instance": "unknown", "jail": "unknownnc"},
                        {"instance": "retired", "jail": "retirednc"},
                        {"instance": "other", "jail": other.nextcloud_jail, "executor": "f" * 64}):
            with self.assertRaisesRegex(ValueError, fence.DENIED):
                self.boot(**changes)
        with self.assertRaisesRegex(ValueError, fence.DENIED):
            self.boot()  # The affected pair remains cold after reboot.
        source = self.store.root / "instances/other/source.sha256"
        source.write_text("f" * 64)
        with self.assertRaisesRegex(ValueError, fence.DENIED):
            self.boot(instance="other", jail=other.nextcloud_jail)

    def test_unaffected_boot_refuses_changed_active_entry_or_original_snapshot(self):
        with self.registry.locked(recovery=True):
            # A normal, operation-authorized closed successor keeps neighbors
            # available even with no validation permission currently held.
            self.fixture.commit()
            self.assertEqual(self.boot(instance="other", jail="othernc").instance, "other")
        graph_ref = self.store._active()
        graph_path = self.store.root / graph_ref["path"]
        graph = json.loads(graph_path.read_bytes())
        graph["instances"]["other"] = graph["instances"]["cloud"]
        atomic_json(graph_path, graph)
        with self.assertRaisesRegex(ValueError, fence.DENIED):
            self.boot(instance="other", jail="othernc")

    def test_reopening_requires_bound_publication_and_prior_closed_profile(self):
        with self.registry.locked(recovery=True):
            receipt = self.capture()
            profile = json.loads(self.store._bound(receipt))
            self.phase("opening")
            marker = self.store._put(self.directory + "/publication-evidence.json", {"native_fixture": True})
            proof = dict(schema_version=1, kind="native-publication-proof", intent=profile["intent"],
                profile=receipt, phase="opening", journal=self.store.reference(self.journal.path), markers={name: marker for name in
                    ("closed_validation", "writers_stopped", "publication_authorized")})
            publication = self.store._put(self.directory + "/native-publication.json", proof)
            with self.assertRaises(ValueError):
                fence.restore_profile(self.registry, receipt, publication=publication)
            fence.install_profile(self.registry, receipt)
            with self.assertRaises(ValueError):
                fence.restore_profile(self.registry, receipt, publication=None)
            with self.assertRaises(ValueError):
                fence.restore_profile(self.registry, receipt, publication=publication)
            for item in profile["files"]:
                self.assertEqual((self.roots[item["jail"]] / item["path"]).read_bytes(), self.store._bound(item["closed"]))
            fence.verify_closed(self.store, receipt)

    def test_symlink_hardlink_modes_and_changed_closed_bytes_refused(self):
        with self.registry.locked(recovery=True):
            receipt = self.closed()
            profile = json.loads(self.store._bound(receipt))
            for item in profile["files"]:
                path = self.roots[item["jail"]] / item["path"]
                saved = path.read_bytes()
                path.chmod(0o666)
                with self.assertRaises(ValueError):
                    fence.verify_closed(self.store, receipt)
                path.chmod(0o644)
                other = path.with_name("hardlink-test")
                os.link(path, other)
                with self.assertRaises(ValueError):
                    fence.verify_closed(self.store, receipt)
                other.unlink()
                path.rename(other)
                path.symlink_to(other.name)
                with self.assertRaises((OSError, ValueError)):
                    fence.verify_closed(self.store, receipt)
                path.unlink()
                other.rename(path)
                path.write_bytes(saved + b"# drift\n")
                with self.assertRaises(ValueError):
                    fence.install_profile(self.registry, receipt)
                path.write_bytes(saved)
            closed_path = self.store.root / profile["files"][0]["closed"]["path"]
            closed_path.write_bytes(b"# changed retained profile\n")
            with self.assertRaises(ValueError):
                fence.verify_closed(self.store, receipt)


if __name__ == "__main__":
    unittest.main()
