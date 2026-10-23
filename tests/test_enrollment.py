"""Enrollment proof limits and crash-safe boot fencing; no native execution."""

import hashlib
import json
import os
import io
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, PropertyMock, patch

from installer import enrollment
from installer.config import Config
from installer.deploy import Deployment
from installer.network import storage_guard
from installer.state import Registry, atomic_json, atomic_write, config_digest
from version_fixtures import resolved_plan


class EnrollmentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="enrollment-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.registry = Registry(self.root / "state")
        self.registry.initialize()
        self.config = Config(public_hostname="cloud.example.test", admin_email="admin@example.test",
                             acme_email="admin@example.test", external_interface="igb0",
                             ingress_address="192.0.2.10", dns_server="192.0.2.53",
                             management_network="198.51.100.0/24", accept_microsoft_fonts=True)
        self.secrets = {"admin_password": "DO-NOT-DISCLOSE", "db_password": "a" * 64, "jwt_secret": "b" * 64}
        self.state = self.registry.save_new(self.config, self.secrets)
        self.registry.set_status(self.config.instance, "ready")
        root = patch.object(Config, "bastille_root", new_callable=PropertyMock,
                            return_value=str(self.root / "bastille"))
        root.start()
        self.addCleanup(root.stop)
        self.runner = Mock(spec=["run", "output"])
        self.deployment = Deployment(self.config, self.secrets, self.runner, registry=self.registry)
        self.plan = resolved_plan(self.config)
        atomic_json(self.state / "versions.json", self.plan)
        self.packages = {}
        for jail, group in ((self.config.nextcloud_jail, "nextcloud"), (self.config.onlyoffice_jail, "onlyoffice")):
            self.packages[jail] = sorted(f"{name} {record['version']} {record['origin']}"
                                         for name, record in self.plan["packages"][group].items())
        atomic_json(self.state / "inventory.json", {"package_versions": self.packages})
        atomic_json(self.state / "deployment.json", {
            "schema_version": 2, "config_sha256": config_digest(self.config),
            "steps": {name: {"state": "complete"} for name in (
                "instance ZFS storage", "private networking and PF", "FreeBSD jail roots",
                "persistent mounts", "Nextcloud publication", "readiness checks", "boot activation")}})
        atomic_write(self.state / "inputs.sha256", hashlib.sha256(json.dumps(self.secrets, sort_keys=True).encode()).hexdigest() + "\n")
        atomic_write(self.state / "source.sha256", "a" * 64 + "\n")
        atomic_write(self.state / "complete", "ready\n")
        atomic_write(self.state / "allow-start", "original boot permission\n")
        self.plugin_root = self.deployment.jail_root(self.config.onlyoffice_jail) / "usr/local/www/onlyoffice/documentserver/sdkjs-plugins"
        self.plugin_root.mkdir(parents=True)
        (self.plugin_root / "base.js").write_text("packaged\n")
        self.hooks = {}
        self.runner.run.side_effect = self.run_command
        self.runner.output.side_effect = self.output_command
        source = patch.object(enrollment, "_source", return_value="a" * 64)
        source.start()
        self.addCleanup(source.stop)
        self.source_patch = source
        ownership = patch.object(self.deployment, "validate_resume")
        ownership.start()
        self.addCleanup(ownership.stop)

    def run_command(self, *args, **kwargs):
        if args[:2] == ("jls", "-j"):
            return SimpleNamespace(returncode=0, stdout=f"11 {args[2]} {self.deployment.jail_root(args[2])}\n")
        if args[0] == "jexec":
            command = args[2:]
            if command[:3] == ("pkg", "query", "%n %v %o"):
                # Deployment checks jls around every invocation; both test JIDs
                # can be equal as jail identity is still explicitly checked.
                jail = self.runner.run.call_args_list[-2].args[2]
                return SimpleNamespace(returncode=0, stdout="\n".join(self.packages[jail]))
            if command == ("pkg", "query", "%Fp", "onlyoffice-documentserver"):
                return SimpleNamespace(returncode=0, stdout="/usr/local/www/onlyoffice/documentserver/sdkjs-plugins/base.js\n")
        if args[:2] == ("bastille", "config") and args[3:5] == ("set", "exec.prepare"):
            self.hooks[args[2]] = args[5]
            return SimpleNamespace(returncode=0, stdout="")
        self.fail(f"Unexpected native command: {args}")

    def output_command(self, *args):
        if args[:3] == ("pkg", "query", "%v|%o"):
            record = self.plan["packages"]["host"][args[3]]
            return record["version"] + "|" + record["origin"]
        if args[:2] == ("bastille", "config"):
            if args[3:] == ("get", "path"):
                return str(self.deployment.jail_root(args[2]))
            if args[3:] == ("get", "exec.prepare"):
                return self.hooks[args[2]]
        self.fail(f"Unexpected native query: {args}")

    def test_initial_readiness_explicitly_records_unavailable_enrollment_without_retrofit(self):
        with patch.object(self.deployment, "verify") as verify, \
                patch.object(enrollment, "capture_baseline", side_effect=ValueError("unreviewed layout")) as capture, \
                patch("installer.deploy.sys.stderr", new_callable=io.StringIO) as output:
            self.deployment.initial_readiness()
            self.assertIn("enrollment evidence is unavailable", output.getvalue())
            record = json.loads((self.state / "enrollment-unavailable.json").read_text())
            self.assertFalse(record["eligible"])
            self.assertNotIn("unreviewed layout", json.dumps(record))
            self.deployment.initial_readiness()
            self.assertEqual(verify.call_count, 2)
            capture.assert_called_once_with(self.deployment)
        self.assertFalse((self.state / enrollment.BASELINE).exists())

    def test_non_tree_component_preserves_every_other_probe_and_ordinary_observe_scans(self):
        d = self.deployment
        guard = self.root / "guard"
        def output(*args, **kwargs):
            if args == ("mount", "-p"):
                text = "pool/root " + str(d.jail_root(self.config.nextcloud_jail)) + " zfs rw 0 0\n"
            else:
                text = "fixture\n"
            return SimpleNamespace(returncode=0, stdout=text)
        def jail(jail, *args, **kwargs):
            if "app:list" in args:
                text = json.dumps(dict(enabled={"onlyoffice": "10.2.1"}, disabled={}))
            elif "config:list" in args:
                text = json.dumps(dict(system={}, apps={"onlyoffice": {}}))
            else:
                text = "fixture\n"
            return SimpleNamespace(returncode=0, stdout=text)
        with patch.object(enrollment, "_guard_paths", return_value=(guard, guard)), \
                patch.object(enrollment, "storage_guard", return_value="guard"), \
                patch.object(enrollment, "_bytes", side_effect=lambda path, **kw: b"guard" if path == guard else b"fstab"), \
                patch.object(d, "require_running_jail", return_value=11) as running, \
                patch.object(d, "jail", side_effect=jail) as jailed, \
                patch.object(d.runner, "run", side_effect=output) as host, \
                patch.object(enrollment, "_tree_identity", return_value="a" * 64) as tree:
            full = enrollment._observe(d)
            self.assertEqual(tree.call_count, 2 * (len(enrollment.STATIC_ROOTS) + 1))
            calls = (running.call_args_list[:], jailed.call_args_list[:], host.call_args_list[:])
            for mock in (running, jailed, host, tree):
                mock.reset_mock()
            component = enrollment._observe_non_tree(d)
            tree.assert_not_called()
            self.assertNotIn("trees", component)
            self.assertEqual(component, {key: value for key, value in full.items() if key != "trees"})
            self.assertEqual(calls, (running.call_args_list, jailed.call_args_list, host.call_args_list))
            enrollment._observe(d)
            self.assertEqual(tree.call_count, 2 * (len(enrollment.STATIC_ROOTS) + 1))

    def test_unavailable_marker_refuses_even_if_baseline_was_published_before_fsync_failure(self):
        atomic_json(self.state / enrollment.BASELINE, {"observation": "must not be adopted"})
        atomic_json(self.state / "enrollment-unavailable.json", {"eligible": False})
        with self.assertRaisesRegex(ValueError, "was unavailable"):
            enrollment.check(self.deployment)
        self.runner.run.assert_not_called()

    def test_original_readiness_failure_is_not_suppressed_by_baseline_collection(self):
        with patch.object(self.deployment, "verify", side_effect=RuntimeError("not ready")), \
                patch.object(enrollment, "capture_baseline") as capture:
            with self.assertRaisesRegex(RuntimeError, "not ready"):
                self.deployment.initial_readiness()
            capture.assert_not_called()
        self.assertFalse((self.state / "enrollment-unavailable.json").exists())

    def test_retained_evidence_is_not_a_fabricated_live_baseline(self):
        before = {p: p.read_bytes() for p in self.state.iterdir() if p.is_file()}
        with patch.object(self.deployment, "verify") as verify, patch.object(self.deployment, "verify_source") as source:
            evidence = enrollment.check(self.deployment)
        verify.assert_not_called()
        source.assert_not_called()
        self.deployment.validate_resume.assert_called_once()
        self.assertFalse(evidence["eligible"])
        self.assertIn("missing-original-first-readiness-baseline", evidence["blockers"])
        self.assertNotIn(self.secrets["admin_password"], json.dumps(evidence))
        self.assertNotIn("secrets.json", evidence["artifacts"])
        self.assertEqual(before, {p: p.read_bytes() for p in self.state.iterdir() if p.is_file()})

    def test_historical_source_refused_without_creating_identity(self):
        self.source_patch.stop()
        before = (self.state / "source.sha256").read_bytes()
        with self.assertRaisesRegex(ValueError, "original installer artifact"):
            enrollment.check(self.deployment)
        self.assertEqual(before, (self.state / "source.sha256").read_bytes())
        self.runner.run.assert_not_called()

    def test_missing_lock_refused_before_native_queries(self):
        (self.state / "versions.json").unlink()
        with self.assertRaises(FileNotFoundError):
            enrollment.check(self.deployment)
        self.runner.run.assert_not_called()

    def test_changed_inputs_are_not_rewritten(self):
        atomic_write(self.state / "inputs.sha256", "b" * 64 + "\n")
        with self.assertRaisesRegex(ValueError, "original inputs changed"):
            enrollment.check(self.deployment)
        self.assertEqual((self.state / "inputs.sha256").read_text(), "b" * 64 + "\n")
        self.runner.run.assert_not_called()

    def test_unselected_plugin_is_drift_even_with_empty_selection(self):
        extra = self.plugin_root / "diagnostic-plugin"
        extra.mkdir()
        (extra / "config.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "unselected"):
            enrollment.check(self.deployment)

    def test_package_addition_is_not_enrolled(self):
        self.packages[self.config.nextcloud_jail].append("extra 1.0 misc/extra")
        with self.assertRaisesRegex(ValueError, "package inventory drift"):
            enrollment.check(self.deployment)

    def test_pending_restore_recovery_or_maintenance_refused(self):
        for filename, contents in (("restore.json", {}), ("initialization.json", {"state": "prepared"}),
                                   ("allow-start.initialization-recovery", {})):
            with self.subTest(filename=filename):
                atomic_json(self.state / filename, contents)
                with self.assertRaises(ValueError):
                    enrollment.check(self.deployment)
                (self.state / filename).unlink()
        from installer.generations import Store
        Store(self.registry.root).begin("register-1", "enroll", [self.config.instance], "a" * 64)
        with self.assertRaisesRegex(ValueError, "pending maintenance"):
            enrollment.check(self.deployment)
        self.runner.run.assert_not_called()

    def test_pending_network_transaction_refused(self):
        with patch.object(enrollment.firewall, "pending_transactions", return_value=(self.root,)):
            with self.assertRaisesRegex(ValueError, "unresolved network"):
                enrollment.check(self.deployment)
        self.runner.run.assert_not_called()

    def test_symlink_and_hardlink_evidence_refused(self):
        path = self.state / "inventory.json"
        saved = path.read_bytes()
        path.unlink()
        target = self.state / "other.json"
        target.write_bytes(saved)
        target.chmod(0o600)
        path.symlink_to(target)
        with self.assertRaises(OSError):
            enrollment.check(self.deployment)
        path.unlink()
        import os
        os.link(target, path)
        with self.assertRaisesRegex(ValueError, "Unsafe enrollment evidence"):
            enrollment.check(self.deployment)

    def test_fence_is_durable_idempotent_and_preserves_bytes(self):
        original = (self.state / "allow-start").read_bytes()
        with patch.object(enrollment, "_sync", wraps=enrollment._sync) as sync:
            first = enrollment.fence_start(self.deployment, operation="register-1")
            second = enrollment.fence_start(self.deployment, operation="register-1")
        self.assertEqual(sync.call_count, 2)
        self.assertEqual(first, second)
        self.assertFalse((self.state / "allow-start").exists())
        self.assertEqual((self.state / first["marker"]).read_bytes(), original)
        self.runner.run.assert_not_called()
        enrollment.restore_start(self.deployment, operation="register-1")
        self.assertEqual((self.state / "allow-start").read_bytes(), original)

    def test_fence_ambiguity_never_overwrites(self):
        enrollment.fence_start(self.deployment, operation="first")
        with self.assertRaisesRegex(ValueError, "Another enrollment"):
            enrollment.fence_start(self.deployment, operation="second")
        atomic_write(self.state / "allow-start", "unexpected\n")
        with self.assertRaisesRegex(ValueError, "Ambiguous"):
            enrollment.fence_start(self.deployment, operation="first")
        with self.assertRaisesRegex(ValueError, "overwrite"):
            enrollment.restore_start(self.deployment, operation="first")
        self.assertEqual((self.state / "allow-start").read_text(), "unexpected\n")

    def prepare_guards(self):
        libexec = self.root / "libexec"
        libexec.mkdir()
        patcher = patch.object(enrollment, "LIBEXEC", libexec)
        patcher.start()
        self.addCleanup(patcher.stop)
        source_root = self.root / "artifact"
        (source_root / "installer").mkdir(parents=True)
        dispatcher = source_root / "installer/maintenance.py"
        dispatcher.write_text("raise SystemExit(0)\n")
        patcher = patch.object(enrollment, "PROJECT_ROOT", source_root)
        patcher.start()
        self.addCleanup(patcher.stop)
        original, wrapper = enrollment._guard_paths(self.deployment)
        atomic_write(original, storage_guard(self.config, self.deployment.storage, self.registry.root), mode=0o700)
        for jail in (self.config.nextcloud_jail, self.config.onlyoffice_jail):
            self.hooks[jail] = f"{original} {jail}"
        from installer.generations import Store
        from installer.maintenance import executor_identity
        self.intent = Store(self.registry.root).begin("register-1", "enroll", [self.config.instance], executor_identity())
        enrollment.fence_start(self.deployment, operation="register-1")
        return original, wrapper, dispatcher

    def test_guard_install_is_separate_source_pinned_and_retryable(self):
        original, wrapper, dispatcher = self.prepare_guards()
        before = original.read_bytes()
        for _ in range(2):
            evidence = enrollment.install_guard(self.deployment, dispatcher=dispatcher,
                                                intent=self.intent, operation="register-1")
        self.assertEqual(original.read_bytes(), before)
        self.assertEqual(evidence["storage_guard_sha256"], hashlib.sha256(before).hexdigest())
        text = wrapper.read_text()
        self.assertIn("python3 -I -B", text)
        self.assertIn("digest.hexdigest()", text)
        self.assertIn("boot_check", text)
        self.assertIn("guard.read_bytes()", text)
        self.assertFalse((self.state / "allow-start").exists())
        subprocess.run(["sh", "-n", str(wrapper)], check=True, capture_output=True)
        self.assertEqual(set(self.hooks.values()), {f"{wrapper} {jail}" for jail in self.hooks})

    def test_partial_install_keeps_fence_and_retries_same_artifact(self):
        original, wrapper, dispatcher = self.prepare_guards()
        method = self.deployment.install_prepare_guard
        attempts = 0
        def fail_second(jail, script):
            nonlocal attempts
            attempts += 1
            if attempts == 2:
                raise RuntimeError("mock interruption")
            method(jail, script)
        with patch.object(self.deployment, "install_prepare_guard", side_effect=fail_second):
            with self.assertRaisesRegex(RuntimeError, "mock interruption"):
                enrollment.install_guard(self.deployment, dispatcher=dispatcher, intent=self.intent, operation="register-1")
        self.assertFalse((self.state / "allow-start").exists())
        self.assertTrue((self.state / "allow-start.enrollment-register-1").exists())
        self.assertEqual(self.hooks[self.config.onlyoffice_jail], f"{original} {self.config.onlyoffice_jail}")
        enrollment.install_guard(self.deployment, dispatcher=dispatcher, intent=self.intent, operation="register-1")
        self.assertEqual(self.hooks[self.config.onlyoffice_jail], f"{wrapper} {self.config.onlyoffice_jail}")

    def test_changed_storage_guard_or_intent_refused_before_hook_mutation(self):
        original, wrapper, dispatcher = self.prepare_guards()
        with self.assertRaisesRegex(ValueError, "exact durable"):
            enrollment.install_guard(self.deployment, dispatcher=dispatcher, intent={}, operation="register-1")
        atomic_write(original, "#!/bin/sh\nexit 0\n", mode=0o700)
        with self.assertRaisesRegex(ValueError, "source-bound rendering"):
            enrollment.install_guard(self.deployment, dispatcher=dispatcher, intent=self.intent, operation="register-1")
        self.assertFalse(wrapper.exists())
        self.runner.run.assert_not_called()

    def first_readiness(self):
        self.registry.set_status(self.config.instance, "installing")
        (self.state / "complete").unlink()
        journal = json.loads((self.state / "deployment.json").read_text())
        del journal["steps"]["boot activation"]
        journal["steps"]["readiness checks"] = {"state": "running", "attempt": 1}
        atomic_json(self.state / "deployment.json", journal)
        self.deployment.manifest = {"package_versions": self.packages}
        return journal

    def test_baseline_only_seals_first_readiness_and_does_not_retrofit(self):
        observation = {"trees": {"config": "b" * 64}, "app:list": "c" * 64}
        with patch.object(enrollment, "_observe", return_value=observation):
            with self.assertRaisesRegex(ValueError, "first installation readiness"):
                enrollment.capture_baseline(self.deployment)
            self.first_readiness()
            evidence = enrollment.capture_baseline(self.deployment)
            original = (self.state / enrollment.BASELINE).read_bytes()
            self.assertEqual(evidence["baseline_sha256"], hashlib.sha256(original).hexdigest())
            with self.assertRaisesRegex(ValueError, "immutable"):
                enrollment.capture_baseline(self.deployment)
            self.assertEqual(original, (self.state / enrollment.BASELINE).read_bytes())
        self.assertNotIn(self.secrets["admin_password"], original.decode())

    def test_missing_baseline_on_resumed_readiness_is_never_created(self):
        journal = self.first_readiness()
        journal["steps"]["readiness checks"]["attempt"] = 2
        atomic_json(self.state / "deployment.json", journal)
        with self.assertRaisesRegex(ValueError, "first installation readiness"):
            enrollment.capture_baseline(self.deployment)
        self.assertFalse((self.state / enrollment.BASELINE).exists())

    def test_baseline_bindings_and_observation_must_both_match(self):
        original_journal = (self.state / "deployment.json").read_text()
        observation = {"trees": {"config": "b" * 64}, "app:list": "c" * 64}
        self.first_readiness()
        with patch.object(enrollment, "_observe", return_value=observation):
            enrollment.capture_baseline(self.deployment)
            atomic_write(self.state / "deployment.json", original_journal)
            atomic_write(self.state / "complete", "ready\n")
            self.registry.set_status(self.config.instance, "ready")
            evidence = enrollment.check(self.deployment)
            self.assertTrue(evidence["eligible"])
            self.assertEqual(evidence["blockers"], [])
        with patch.object(enrollment, "_observe", return_value={"trees": {"config": "changed"}}):
            with self.assertRaisesRegex(ValueError, "configuration drift"):
                enrollment.check(self.deployment)
        baseline = json.loads((self.state / enrollment.BASELINE).read_text())
        baseline["source_sha256"] = "e" * 64
        atomic_json(self.state / enrollment.BASELINE, baseline)
        with self.assertRaisesRegex(ValueError, "baseline provenance"):
            enrollment.check(self.deployment)

    def test_unstable_first_observation_is_not_sealed(self):
        self.first_readiness()
        with patch.object(enrollment, "_observe", side_effect=[{"code": "a"}, {"code": "b"}]):
            with self.assertRaisesRegex(ValueError, "not stable"):
                enrollment.capture_baseline(self.deployment)
        self.assertFalse((self.state / enrollment.BASELINE).exists())

    def test_jail_absolute_links_are_observed_in_jail_namespace(self):
        root = self.state / "link-jail"
        etc, share = root / "etc", root / "usr/share"
        etc.mkdir(parents=True)
        share.mkdir(parents=True)
        (share / "zone").write_text("original timezone")
        (etc / "localtime").symlink_to("/usr/share/zone")
        roots = (etc, share)
        before = enrollment._tree_identity(etc, jail_root=root, observed_roots=roots)
        self.assertEqual(before, enrollment._tree_identity(etc, jail_root=root, observed_roots=roots))
        with self.assertRaises(ValueError):
            enrollment._tree_identity(etc, jail_root=root, observed_roots=(etc,))
        (etc / "loop").symlink_to("/etc/loop")
        with self.assertRaises(ValueError):
            enrollment._tree_identity(etc, jail_root=root, observed_roots=roots)

    def test_reviewed_os_release_link_binds_only_the_exact_runtime_identity(self):
        root = self.state / "release-jail"
        etc, run = root / "etc", root / "var/run"
        etc.mkdir(parents=True)
        run.mkdir(parents=True)
        (run / "os-release").write_text('NAME=FreeBSD\nVERSION="15.1-RELEASE"\n')
        (etc / "os-release").symlink_to("../var/run/os-release")
        before = enrollment._tree_identity(etc, jail_root=root, observed_roots=(etc,))
        (run / "os-release").write_text('NAME=FreeBSD\nVERSION="15.1-RELEASE-p1"\n')
        self.assertNotEqual(before, enrollment._tree_identity(etc, jail_root=root, observed_roots=(etc,)))
        (run / "unrelated").write_text("mutable runtime")
        (etc / "unreviewed").symlink_to("../var/run/unrelated")
        with self.assertRaises(ValueError):
            enrollment._tree_identity(etc, jail_root=root, observed_roots=(etc,))

    def test_reviewed_runtime_motd_and_inert_ghostscript_links_are_narrow(self):
        root = self.state / "reviewed-links-jail"
        etc = root / "etc"
        fonts = root / "usr/local/share/ghostscript/fonts"
        etc.mkdir(parents=True)
        fonts.mkdir(parents=True)
        (etc / "motd").symlink_to("/var/run/motd")
        (fonts / "Ryumin-Light").symlink_to("/usr/local/share/fonts/std.ja_JP/Ryumin-Light")
        self.assertRegex(enrollment._tree_identity(etc, jail_root=root, observed_roots=(etc,)), r"^[a-f0-9]{64}$")
        self.assertRegex(enrollment._tree_identity(fonts, jail_root=root, observed_roots=(fonts,)), r"^[a-f0-9]{64}$")
        (fonts / "unknown").symlink_to("/usr/local/share/fonts/missing")
        with self.assertRaises(ValueError):
            enrollment._tree_identity(fonts, jail_root=root, observed_roots=(fonts,))
        (fonts / "unknown").unlink()
        target = root / "usr/local/share/fonts/std.ja_JP/Ryumin-Light"
        target.parent.mkdir(parents=True)
        target.write_text("now installed")
        with self.assertRaises(ValueError):
            enrollment._tree_identity(fonts, jail_root=root, observed_roots=(fonts,))

    def test_native_static_hardlink_count_and_contents_are_bound(self):
        tree = self.state / "base-tools"
        tree.mkdir()
        (tree / "test").write_text("base program")
        before = enrollment._tree_identity(tree)
        os.link(tree / "test", tree / "[")
        after = enrollment._tree_identity(tree)
        self.assertNotEqual(before, after)
        self.assertEqual(after, enrollment._tree_identity(tree))
        (tree / "[").write_text("changed via alias")
        self.assertNotEqual(after, enrollment._tree_identity(tree))

    def test_static_tree_identity_detects_code_config_mode_and_added_files(self):
        tree = self.root / "static"
        tree.mkdir()
        path = tree / "config.php"
        path.write_text("secret-first")
        path.chmod(0o644)  # The subsequent mode-change assertion must not depend on umask.
        before = enrollment._tree_identity(tree)
        path.write_text("secret-second")
        self.assertNotEqual(before, enrollment._tree_identity(tree))
        path.write_text("secret-first")
        self.assertEqual(before, enrollment._tree_identity(tree))
        path.chmod(0o600)
        self.assertNotEqual(before, enrollment._tree_identity(tree))
        path.chmod(0o644)
        (tree / "plugin").mkdir()
        self.assertNotEqual(before, enrollment._tree_identity(tree))
        (tree / "outside").symlink_to("../state")
        with self.assertRaisesRegex(ValueError, "escaping"):
            enrollment._tree_identity(tree)

    def test_current_pending_aware_guard_allows_install_without_marker_rename(self):
        original, wrapper, dispatcher = self.prepare_guards()
        enrollment.restore_start(self.deployment, operation="register-1")
        before = (self.state / "allow-start").read_bytes()
        evidence = enrollment.validate_original_guard(self.deployment)
        self.assertEqual(evidence["storage_guard_sha256"], hashlib.sha256(original.read_bytes()).hexdigest())
        enrollment.install_guard(self.deployment, dispatcher=dispatcher, intent=self.intent)
        self.assertEqual((self.state / "allow-start").read_bytes(), before)
        self.assertTrue(wrapper.exists())


if __name__ == "__main__":
    unittest.main()
