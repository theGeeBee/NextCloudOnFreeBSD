"""Graph-authoritative registry mutations and exact-byte crash recovery, offline."""

import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from installer.generations import Store, descriptor
from installer.state import Registry, atomic_json, atomic_write, config_digest, private_json, recover_registry
from test_state import configuration


SOURCE = "a" * 64
EXECUTOR = "e" * 64


class RegistryLifecycleTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="registry-lifecycle-")
        self.addCleanup(temporary.cleanup)
        self.registry = Registry(Path(temporary.name) / "registry")
        self.registry.initialize()
        self.store = Store(self.registry.root)
        self.config = configuration()
        self.path = self.registry.save_new(self.config, {"password": "private-credential-sentinel"})
        self.registry.write_source("cloud", SOURCE + "\n")
        self.registry.set_status("cloud", "ready")
        self.guard = self.enterContext(patch("installer.maintenance.entry_guard"))
        self.enterContext(patch("installer.maintenance.executor_identity", return_value=EXECUTOR))
        self.enterContext(patch("installer.deploy.source_digest", return_value=SOURCE + "\n"))
        with self.registry.locked():
            self.store.begin("initial", "register", ["cloud"], EXECUTOR)
            self.store.commit("initial", {"cloud": self.store.build_entry("cloud")}, "initial")
            self.store.finish("initial")

    def recover(self):
        pending = self.store.pending()
        with self.registry.locked(recovery=True):
            recover_registry(self.registry, pending)
        self.assertIsNone(self.store.pending())
        return pending

    def managed(self):
        atomic_json(self.path / "versions.json", {"fixture": "original lock"})
        atomic_json(self.path / "deployment.json", {"config_sha256": config_digest(self.config)})
        with self.registry.locked():
            self.store.begin("enroll", "enroll", ["cloud"], EXECUTOR)
            archive = self.store.archive_legacy("cloud", "enroll")
            generation = self.store.seal_generation("cloud", "generation", "enroll", archive=archive,
                                                    evidence={"policy.json": (Path(__file__).resolve().parents[1] / "resources/versions.json").read_bytes(),
                                                              "resources.json": b"{}\n"})
            atomic_json(self.path / "config.json", descriptor("cloud", generation))
            entry = {"kind": "managed", "generation": generation, "status": {"state": "ready"}}
            self.store.commit("enrolled", {"cloud": entry}, "enroll")
            self.store.finish("enroll")
        return generation

    def test_effective_managed_reads_ignore_lookup_and_status_projection(self):
        self.managed()
        atomic_json(self.path / "status.json", {"state": "failed"})
        self.assertEqual(self.registry.load("cloud"), self.config)
        self.assertEqual(self.registry.status("cloud"), {"state": "ready"})
        self.assertEqual(self.registry.entries(), [(self.config, {"state": "ready"})])
        self.assertEqual(self.registry.lifecycle_names(), ["cloud"])
        self.assertEqual(self.registry.evidence_path("cloud", "config.json"), self.path / "generations/generation/config.json")
        self.assertEqual(self.registry.evidence_path("cloud", "versions.json"), self.path / "generations/generation/versions.json")
        self.assertEqual(self.registry.evidence_path("cloud", "source.sha256"), self.path / "legacy/files/source.sha256")

    def test_mutations_require_lock_and_lock_flag_is_restored_on_failure(self):
        for action in (lambda: self.registry.set_status("cloud", "failed"),
                       lambda: self.registry.write_source("cloud", SOURCE + "\n"),
                       lambda: self.registry.save_new(configuration(instance="other"), {}),
                       lambda: self.registry.save_host(self.config)):
            with self.assertRaisesRegex(ValueError, "global operation lock"):
                action()
        with self.assertRaisesRegex(RuntimeError, "injected"):
            with self.registry.locked():
                self.assertTrue(self.registry._locked)
                raise RuntimeError("injected")
        self.assertFalse(self.registry._locked)
        self.guard.assert_called_with("mutation", registry=self.registry)
        with patch("installer.maintenance.entry_guard", side_effect=ValueError("guard")):
            with self.assertRaisesRegex(ValueError, "guard"):
                with self.registry.locked():
                    self.fail("guard was bypassed")
        self.assertFalse(self.registry._locked)

    def test_registration_inputs_precede_fence_and_publication_is_fenced(self):
        previous = copy.deepcopy(self.store.graph()["instances"]["cloud"])
        original = atomic_json
        events = []
        def write(path, value):
            if Path(path).name == "secrets.json":
                self.assertIsNone(self.store.pending())
                self.assertFalse(self.registry.instance_path("other").exists())
                events.append("staged")
            return original(path, value)
        rename = os.rename
        def publish(source, target):
            if Path(target) == self.registry.instance_path("other"):
                pending = self.store.pending()
                self.assertEqual(pending["action"], "register")
                self.assertTrue((self.registry.root / "maintenance/operations" / pending["operation"] / "registry-inputs.json").is_file())
                events.append("fenced")
            return rename(source, target)
        with self.registry.locked(), patch("installer.state.atomic_json", side_effect=write), patch("installer.state.os.rename", side_effect=publish):
            path = self.registry.save_new(configuration(instance="other"), {"password": "new-private-sentinel"})
        self.assertEqual(events, ["staged", "fenced"])
        self.assertEqual(self.store.graph()["instances"]["cloud"], previous)
        self.assertEqual(self.registry.status("other")["state"], "configured")
        self.assertEqual(private_json(path / "secrets.json"), {"password": "new-private-sentinel"})
        for file in self.registry.root.rglob("*"):
            if file.is_file() and file.name != "secrets.json":
                self.assertNotIn(b"new-private-sentinel", file.read_bytes())
        self.assertEqual((path / "secrets.json").stat().st_mode & 0o777, 0o600)

    def test_source_and_status_commits_preserve_other_instances(self):
        with self.registry.locked():
            self.registry.save_new(configuration(instance="other"), {})
            self.registry.write_source("other", SOURCE + "\n")
            self.registry.set_status("other", "installing")
        self.assertEqual(self.registry.status("other")["state"], "installing")
        self.assertEqual(self.registry.status("cloud")["state"], "ready")
        self.assertIsNone(self.store.pending())
        self.assertEqual(self.store.resolve("other")["provenance"]["source_sha256"], SOURCE)

    def test_recovery_inputs_failure_never_publishes_pending_intent(self):
        before = self.registry.status("cloud")
        with self.registry.locked(), patch.object(self.registry, "_payload", side_effect=OSError("crash before recovery inputs")):
            with self.assertRaises(OSError):
                self.registry.set_status("cloud", "failed")
        self.assertIsNone(self.store.pending())
        self.assertEqual(self.registry.status("cloud"), before)
        with self.registry.locked():
            self.registry.set_status("cloud", "failed")
        self.assertEqual(self.registry.status("cloud")["state"], "failed")

    def test_configured_only_retirement_preserves_absent_source(self):
        with self.registry.locked():
            self.registry.save_new(configuration(instance="draft"), {})
            self.registry.set_status("draft", "removing", purge_data=False)
            self.registry.set_status("draft", "removed", data_retained=True)
        self.assertEqual(self.registry.status("draft")["state"], "removed")
        self.assertIsNone(self.store.resolve("draft")["provenance"]["source_sha256"])
        self.assertFalse((self.registry.instance_path("draft") / "source.sha256").exists())

    def test_source_publication_recovers_exact_bytes_and_rejects_unbound_file(self):
        with self.registry.locked():
            self.registry.save_new(configuration(instance="other"), {})
        with self.registry.locked(), patch("installer.generations.Store.commit", side_effect=OSError("injected")):
            with self.assertRaises(OSError):
                self.registry.write_source("other", SOURCE + "\n")
        self.recover()
        self.assertEqual(self.store.resolve("other")["provenance"]["source_sha256"], SOURCE)
        with self.registry.locked():
            self.registry.save_new(configuration(instance="unbound"), {})
            atomic_write(self.registry.instance_path("unbound") / "source.sha256", SOURCE + "\n")
            with self.assertRaisesRegex(ValueError, "Unbound|binding"):
                self.registry.write_source("unbound", SOURCE + "\n")
        self.assertIsNone(self.store.pending())

    def test_first_pending_intent_and_dangling_fence_prevent_legacy_fallback(self):
        registry = Registry(self.registry.root.parent / "first")
        registry.initialize()
        registry.save_new(self.config, {})
        store = Store(registry.root)
        with registry.locked():
            store.begin("first-enrollment", "enroll", ["cloud"], EXECUTOR)
        self.assertFalse((registry.root / "lifecycle").exists())
        self.assertTrue(registry.lifecycle_enabled())
        for action in (lambda: registry.load("cloud"), lambda: registry.status("cloud"), lambda: registry.entries()):
            with self.assertRaises(ValueError):
                action()
        # A dangling fence is malformed managed state, never a legacy registry.
        fence = registry.root / "maintenance/pending.json"
        fence.unlink()
        fence.symlink_to("missing.json")
        self.assertTrue(registry.lifecycle_enabled())
        with self.assertRaises(ValueError):
            registry.entries()

    def test_managed_removal_retains_generation_and_tombstone(self):
        generation = self.managed()
        with self.registry.locked():
            self.registry.set_status("cloud", "removed", data_retained=True)
        entry = self.store.graph()["instances"]["cloud"]
        self.assertEqual(entry["kind"], "removed")
        self.assertEqual(entry["retained"]["generation"], generation)
        self.assertTrue(self.registry.status("cloud")["data_retained"])
        self.assertEqual(self.registry.entries(), [])
        self.assertEqual(len(self.registry.entries(include_removed=True)), 1)
        with self.registry.locked():
            with self.assertRaisesRegex(ValueError, "reserved"):
                self.registry.set_status("cloud", "ready")
            with self.assertRaisesRegex(ValueError, "already registered"):
                self.registry.save_new(self.config, {})
            self.registry.set_status("cloud", "removed", data_retained=False)
        self.assertEqual(self.store.graph()["instances"]["cloud"]["retained"]["generation"], generation)

    def test_legacy_tombstone_can_record_later_purge_without_reviving_name(self):
        with self.registry.locked():
            self.registry.set_status("cloud", "removed", data_retained=True)
            self.registry.set_status("cloud", "removed", data_retained=False)
        self.assertEqual(self.store.graph()["instances"]["cloud"]["kind"], "removed")
        self.assertFalse(self.registry.status("cloud")["data_retained"])

    def test_managed_removal_recovery_keeps_generation_authoritative(self):
        generation = self.managed()
        with self.registry.locked(), patch("installer.generations.Store.commit", side_effect=OSError("injected")):
            with self.assertRaises(OSError):
                self.registry.set_status("cloud", "removed", data_retained=True)
        self.recover()
        entry = self.store.graph()["instances"]["cloud"]
        self.assertEqual(entry["kind"], "removed")
        self.assertEqual(entry["retained"]["generation"], generation)
        self.assertEqual(private_json(self.path / "status.json"), self.registry.status("cloud"))

    def test_status_crashes_before_write_before_commit_and_after_commit_are_recoverable(self):
        for boundary in ("write", "commit", "finish"):
            with self.subTest(boundary=boundary):
                target = {"write": "installer.state.atomic_write", "commit": "installer.generations.Store.commit",
                          "finish": "installer.generations.Store.finish"}[boundary]
                with self.registry.locked(), patch(target, side_effect=OSError("injected")):
                    with self.assertRaises(OSError):
                        self.registry.set_status("cloud", "failed", error_type=boundary)
                pending = self.store.pending()
                self.assertIsNotNone(pending)
                with self.assertRaises(ValueError):
                    self.registry.status("cloud")
                with self.assertRaises(ValueError):
                    with self.registry.locked():
                        self.fail("pending fence was bypassed")
                self.assertFalse(self.registry._locked)
                self.recover()
                self.assertEqual(self.registry.status("cloud")["error_type"], boundary)
                directory = self.registry.root / "maintenance/operations" / pending["operation"]
                self.assertTrue((directory / "intent.json").exists())
                self.assertTrue((directory / "registry.json").exists())
                self.assertTrue((directory / "terminal.json").exists())

    def test_registration_recovers_before_and_after_directory_publication(self):
        for name, target in (("before", "installer.state.os.rename"), ("after", "installer.generations.Store.commit")):
            with self.subTest(name=name):
                rename = os.rename
                def fail_publication(source, destination):
                    if Path(destination) == self.registry.instance_path(name):
                        raise OSError("injected before registration publication")
                    return rename(source, destination)
                effect = fail_publication if name == "before" else OSError("injected")
                with self.registry.locked(), patch(target, side_effect=effect):
                    with self.assertRaises(OSError):
                        self.registry.save_new(configuration(instance=name), {"password": "retain-me"})
                self.recover()
                self.assertEqual(self.registry.status(name)["state"], "configured")
                self.assertEqual(private_json(self.registry.instance_path(name) / "secrets.json")["password"], "retain-me")

    def test_sealed_graph_and_terminal_before_pointer_crashes_are_recoverable(self):
        original = Store._put
        for boundary in ("lifecycle/active.json", "maintenance/pending.json"):
            def write(store, path, value, **kwargs):
                if path == boundary and (boundary != "maintenance/pending.json" or value.get("state") == "idle"):
                    raise OSError("injected pointer failure")
                return original(store, path, value, **kwargs)
            with self.subTest(boundary=boundary):
                with self.registry.locked(), patch.object(Store, "_put", write):
                    with self.assertRaises(OSError):
                        self.registry.set_status("cloud", "failed", next_action="recover")
                self.recover()
                self.assertEqual(self.registry.status("cloud")["next_action"], "recover")

    def test_recovery_does_not_write_when_an_unrelated_instance_has_drifted(self):
        with self.registry.locked():
            self.registry.save_new(configuration(instance="other"), {})
        original = (self.path / "status.json").read_bytes()
        with self.registry.locked(), patch("installer.state.atomic_write", side_effect=OSError("injected")):
            with self.assertRaises(OSError):
                self.registry.set_status("cloud", "failed")
        atomic_json(self.registry.instance_path("other") / "status.json", {"state": "failed"})
        with self.registry.locked(recovery=True):
            with self.assertRaises(ValueError):
                recover_registry(self.registry, self.store.pending())
        self.assertEqual((self.path / "status.json").read_bytes(), original)

    def test_recovery_refuses_drift_wrong_executor_and_missing_private_inputs(self):
        with self.registry.locked(), patch("installer.generations.Store.commit", side_effect=OSError("injected")):
            with self.assertRaises(OSError):
                self.registry.set_status("cloud", "failed")
        pending = self.store.pending()
        with self.registry.locked(recovery=True):
            with patch("installer.maintenance.executor_identity", return_value="f" * 64):
                with self.assertRaisesRegex(ValueError, "original executor"):
                    recover_registry(self.registry, pending)
            atomic_json(self.path / "status.json", {"state": "removing"})
            with self.assertRaisesRegex(ValueError, "exact retained"):
                recover_registry(self.registry, pending)
        self.assertEqual(self.store.pending(), pending)
        with self.assertRaisesRegex(ValueError, "global operation lock"):
            recover_registry(self.registry, pending)

    def test_changed_retained_payload_cannot_authorize_recovery(self):
        original = (self.path / "status.json").read_bytes()
        with self.registry.locked(), patch("installer.state.atomic_write", side_effect=OSError("injected")):
            with self.assertRaises(OSError):
                self.registry.set_status("cloud", "failed")
        pending = self.store.pending()
        path = self.registry.root / "maintenance/operations" / pending["operation"] / "registry.json"
        payload = private_json(path)
        payload["credentials"] = "a" * 64
        atomic_json(path, payload)
        with self.registry.locked(recovery=True):
            with self.assertRaisesRegex(ValueError, "referenced content changed"):
                recover_registry(self.registry, pending)
        self.assertEqual((self.path / "status.json").read_bytes(), original)

    def test_unjournaled_drift_is_never_adopted(self):
        atomic_json(self.path / "status.json", {"state": "failed"})
        for action in (lambda: self.registry.load("cloud"), lambda: self.registry.entries(),
                       lambda: self.registry.status("cloud")):
            with self.assertRaises(ValueError):
                action()
        with self.registry.locked():
            with self.assertRaises(ValueError):
                self.registry.set_status("cloud", "ready")
        self.assertIsNone(self.store.pending())

    def test_unbound_partial_registration_is_retained_and_not_inferred(self):
        with self.registry.locked(), patch("installer.state.atomic_json", side_effect=OSError("injected")):
            with self.assertRaises(OSError):
                self.registry.save_new(configuration(instance="partial"), {})
        pending = self.store.pending()
        self.assertIsNone(pending)  # Only unpublished private staging was touched.
        with self.registry.locked(recovery=True):
            with self.assertRaises(ValueError):
                recover_registry(self.registry, pending)
        self.assertEqual(self.store.pending(), pending)
        self.assertFalse(self.registry.instance_path("partial").exists())
        self.assertEqual(self.registry.status("cloud")["state"], "ready")


if __name__ == "__main__":
    unittest.main()
