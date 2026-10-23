"""Offline native metadata boundaries; no recipe or host execution is admitted."""

from copy import deepcopy
import json
import unittest
from unittest.mock import patch

from installer.generations import Store, descriptor, _encode, _hash
from installer.maintenance_operations import NETWORK_RECORDS
from installer.maintenance_state import NativeState
from installer.paths import RESOURCES
from installer.state import Registry, atomic_json, atomic_write
import test_generations as fixtures
from test_state import configuration


class NativeStateTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.GenerationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root, self.store = self.fixture.root, self.fixture.store
        self.registry = Registry(self.root)
        self.registry.initialize()
        self.fixture.instance()
        self.fixture.instance("other", state="configured", source=False)
        self.fixture.instance("retired", state="removed")
        for name in ("cloud", "other", "retired"):
            atomic_write(self.root / "instances" / name / "config.json", configuration(instance=name).to_json())
        self.store.begin("enroll-one", "enroll", ["cloud"], fixtures.EXECUTOR)
        archive = self.store.archive_legacy("cloud", "enroll-one")
        generation = self.store.seal_generation("cloud", "initial", "enroll-one", archive=archive,
            evidence={"policy.json": (RESOURCES / "versions.json").read_bytes(), "resources.json": b"{}"})
        atomic_json(self.root / "instances/cloud/config.json", descriptor("cloud", generation))
        self.entries = {
            "cloud": dict(kind="managed", generation=generation, status={"state": "ready"}),
            "other": self.store.legacy_entry("other"),
            "retired": dict(kind="removed", retained=self.store.legacy_entry("retired"), status={"state": "removed"})}
        self.fixture.publish(self.entries)
        self.base = self.store._active()
        self.executor = dict(schema_version=1, source_sha256=fixtures.SOURCE, executor_sha256=fixtures.EXECUTOR,
                             payload_path="/retained/source", policy_sha256="d" * 64)
        transaction = self.store._mkdir("transactions/original")
        records = {}
        for name in NETWORK_RECORDS:
            data = _encode({"instances": ["cloud"]}) if name == "firewall-transition.json" else b"original network\n"
            records[name] = self.store._write("transactions/original/" + name, data)
        (self.root / "network/active").symlink_to(transaction)
        manifest = self.store._generation("cloud", generation)
        plan = dict(schema_version=1, kind="recovery-preparation-plan", plan_id="plan-fixture", instance="cloud",
                    bindings=dict(graph=self.base, generation=generation, versions=manifest["versions"],
                                  executor=self.executor, network=dict(target="transactions/original", records=records)),
                    artifacts=[dict(kind="source", path="source/install.sh", sha256="c" * 64, size=0)],
                    recipe=None, upgrade_execution_authorized=False, native_execution_authorized=False,
                    native_acceptance="not-run")
        self.store._mkdir("maintenance/plans")
        plan_ref = self.store._put("maintenance/plans/plan-fixture.json", plan)
        self.store._mkdir("maintenance/operations/maint-fixture")
        self.preparation = self.store._put("maintenance/operations/maint-fixture/operation.json", dict(
            schema_version=1, kind="recovery-preparation-operation", operation="maint-fixture", instance="cloud",
            plan=plan_ref, executor=self.executor, recipe=None, effects=["private-artifact-staging"]))
        self.native = NativeState(self.registry, self.executor)
        self.operation = "execution-fixture"
        self.recipe = {"id": "fixture-only", "descriptor_version": 1, "source_sha256": fixtures.SOURCE}

    def begin(self):
        return self.native.begin(self.operation, "cloud", preparation=self.preparation, recipe=self.recipe)

    def initial_records(self):
        return {"admission.json": {"startup": {"cloudnc": {}, "cloudoo": {}}, "evidence": self.preparation},
                "source-observations.json": {"source": self.executor["source_sha256"]},
                "candidate-reference.json": self.preparation}

    def test_initial_receipts_are_immutable_and_present_before_intent_activation(self):
        records = self.initial_records()
        activate = self.native.store.activate_intent
        directory = "maintenance/operations/" + self.operation

        def observed_activate(intent):
            self.assertIsNone(self.store.pending())
            for name, value in records.items():
                path = directory + "/" + name
                self.assertEqual(self.store._read(path), _encode(value))
                self.assertEqual((self.root / path).stat().st_mode & 0o777, 0o600)
                with self.assertRaises(ValueError):
                    self.store._write_once(path, b"changed", recover=False)
            return activate(intent)

        with self.registry.locked(recovery=True), patch.object(self.native.store, "activate_intent", side_effect=observed_activate) as activation:
            self.native.begin(self.operation, "cloud", preparation=self.preparation, recipe=self.recipe, initial_records=records)
            activation.assert_called_once()
            self.native.read(self.operation)

    def test_invalid_initial_receipts_refuse_before_any_execution_directory(self):
        good = self.initial_records()
        invalid = [[], {}, {name: value for name, value in good.items() if name != "admission.json"},
                   {name: value for name, value in good.items() if name != "source-observations.json"},
                   {**good, "../escape.json": {}}, {**good, "intent.json": {}},
                   {**good, "admission.json": {}}, {**good, "source-observations.json": []},
                   {**good, "source-observations.json": {"invalid": object()}},
                   {**good, "source-observations.json": {"invalid": float("nan")}},
                   {**good, "candidate-reference.json": None},
                   {**good, "candidate-reference.json": {**self.preparation, "sha256": "f" * 64}},
                   {**good, "admission.json": {**good["admission.json"], "startup": {"wrong": {}}}},
                   {**good, "admission.json": {**good["admission.json"], "evidence": {**self.preparation, "sha256": "f" * 64}}}]
        with self.registry.locked(recovery=True), \
                patch.object(self.native.store, "_mkdir", side_effect=AssertionError("No execution writes permitted")), \
                patch.object(self.native.store, "activate_intent", side_effect=AssertionError("No activation permitted")):
            for records in invalid:
                with self.subTest(records=records), self.assertRaises(ValueError):
                    self.native.begin(self.operation, "cloud", preparation=self.preparation, recipe=self.recipe, initial_records=records)
            with patch("installer.maintenance_state.MAX_FILE_BYTES", 1024), self.assertRaisesRegex(ValueError, "byte limit"):
                self.native.begin(self.operation, "cloud", preparation=self.preparation, recipe=self.recipe,
                                  initial_records={**good, "source-observations.json": {"large": "x" * 1025}})
        self.assertIsNone(self.store.pending())
        self.assertFalse((self.root / "maintenance/operations" / self.operation).exists())

    def test_initial_receipt_write_failure_never_activates_partial_execution(self):
        records = self.initial_records()
        write = self.native.store._write_once
        with self.registry.locked(recovery=True):
            for index, name in enumerate(records):
                operation = "execution-write-failure-" + str(index)
                directory = "maintenance/operations/" + operation

                def fail_receipt(path, data, *, recover):
                    if path == directory + "/" + name:
                        raise OSError("simulated receipt write failure")
                    return write(path, data, recover=recover)

                with self.subTest(receipt=name), patch.object(self.native.store, "_write_once", side_effect=fail_receipt), \
                        patch.object(self.native.store, "activate_intent") as activation:
                    with self.assertRaises(OSError):
                        self.native.begin(operation, "cloud", preparation=self.preparation, recipe=self.recipe, initial_records=records)
                    activation.assert_not_called()
                self.assertIsNone(self.store.pending())
                self.assertFalse((self.root / directory / "intent.json").exists())
                with self.assertRaisesRegex(ValueError, "already exists"):
                    self.native.begin(operation, "cloud", preparation=self.preparation, recipe=self.recipe, initial_records=records)

    def commit(self, stage="validated-closed", predecessor=None, entries=None):
        return self.native.commit_closed(self.operation, stage, "graph-" + stage,
            self.entries if entries is None else entries,
            expected_predecessor=self.base if predecessor is None else predecessor)

    def test_distinct_intent_inert_parent_and_strict_generic_store(self):
        before = self.store._bound(self.preparation)
        with self.registry.locked(recovery=True):
            intent = self.begin()
            self.assertEqual(intent["schema_version"], 2)
            self.assertEqual(intent["action"], "maintenance")
            self.assertEqual(self.store.pending(), intent)
            inputs = self.native.read(self.operation)[1]
            self.assertEqual(inputs["cache_owner"], "maint-fixture")
            self.assertEqual(inputs["recipe_sha256"], _hash(_encode(self.recipe)))
            self.assertEqual(inputs["entries"], self.entries)
            self.assertEqual(self.store._bound(self.preparation), before)
            self.assertIsNone(json.loads(before)["recipe"])
            for action in (lambda: self.store.graph(), lambda: self.registry.load("cloud"),
                           lambda: self.store.commit("bypass", self.entries, self.operation),
                           lambda: self.store.archive_legacy("cloud", self.operation),
                           lambda: self.store.seal_generation("cloud", "bypass", self.operation, archive={}, evidence={})):
                with self.assertRaises(ValueError):
                    action()
            with self.assertRaises(ValueError):
                self.native.read("execution-other")

    def test_requires_actual_registry_lock_on_every_view_and_mutation(self):
        with self.assertRaises(ValueError):
            self.begin()
        with self.registry.locked(recovery=True):
            self.begin()
            view = self.native.view(self.operation)
        for action in (lambda: self.native.read(self.operation), lambda: view.status("cloud"),
                       lambda: self.commit(), lambda: self.native.finish(self.operation, "cancelled")):
            with self.assertRaises(ValueError):
                action()

    def test_original_view_survives_destination_graph_and_network_pointer(self):
        with self.registry.locked(recovery=True):
            self.begin()
            view = self.native.view(self.operation)
            before = view.evidence_path("cloud", "versions.json").read_bytes()
            changed = deepcopy(self.entries)
            changed["cloud"]["status"] = {"state": "failed"}
            destination = self.commit(entries=changed)
            (self.root / "network/active").unlink()
            destination_network = self.store._mkdir("transactions/destination")
            atomic_json(destination_network / "firewall-transition.json", {"instances": ["other"]})
            (self.root / "network/active").symlink_to(destination_network)
            self.assertEqual(view.status("cloud"), {"state": "ready"})
            self.assertEqual(view.evidence_path("cloud", "versions.json").read_bytes(), before)
            self.assertEqual([c.instance for c in view.network_configs()], ["cloud"])
            self.assertEqual(view.load("cloud").instance, "cloud")
            restored = self.commit("restored-closed", destination)
            self.assertEqual(json.loads(self.store._bound(restored))["predecessor"], destination)
            self.assertEqual(self.store.graph(validate_evidence=False)["instances"], self.entries)
            self.native.finish(self.operation, "recovered")
        self.assertIsNone(self.store.pending())
        self.assertEqual(self.store.graph()["instances"], self.entries)

    def test_view_refuses_unrecorded_files_and_returns_independent_status(self):
        with self.registry.locked(recovery=True):
            self.begin()
            view = self.native.view(self.operation)
            value = view.status("cloud")
            value["state"] = "removed"
            self.assertEqual(view.status("cloud")["state"], "ready")
            self.assertEqual(json.loads(view.evidence_path("cloud", "status.json").read_bytes()), {"state": "ready"})
            self.assertEqual([config.instance for config, _ in view.entries()], ["cloud", "other"])
            for action in (lambda: view.load("unknown"), lambda: view.evidence_path("cloud", "secrets.json"),
                           lambda: view.evidence_path("cloud", "../config.json")):
                with self.assertRaises(ValueError):
                    action()
            self.assertFalse(hasattr(view, "set_status"))
            self.assertFalse(hasattr(view, "locked"))

    def test_unknown_actions_and_intent_schemas_fail_closed(self):
        with self.registry.locked(recovery=True):
            intent = self.begin()
            for change in ({"action": "future"}, {"schema_version": 1}, {"schema_version": True},
                           {"operation": "maint-fixture"}, {"instances": ["cloud", "other"]},
                           {"inputs": self.preparation}, {"unexpected": True}):
                with self.subTest(change=change), self.assertRaises(ValueError):
                    self.store._intent({**intent, **change})

    def test_exact_executor_source_and_instance_are_required_before_writes(self):
        with self.registry.locked(recovery=True):
            for change in ({"source_sha256": "f" * 64}, {"executor_sha256": "f" * 64},
                           {"payload_path": "/different"}, {"policy_sha256": "f" * 64}):
                native = NativeState(self.registry, {**self.executor, **change})
                with self.subTest(change=change), self.assertRaises(ValueError):
                    native.begin(self.operation, "cloud", preparation=self.preparation, recipe=self.recipe)
            with self.assertRaises(ValueError):
                self.native.begin(self.operation, "other", preparation=self.preparation, recipe=self.recipe)
            self.assertFalse((self.root / "maintenance/operations" / self.operation).exists())
            self.begin()
            with self.assertRaises(ValueError):
                NativeState(self.registry, {**self.executor, "executor_sha256": "f" * 64}).read(self.operation)

    def test_corrupt_original_refs_inputs_recipe_and_network_fail_closed(self):
        with self.registry.locked(recovery=True):
            intent = self.begin()
            inputs = self.native.read(self.operation)[1]
            refs = [intent["inputs"], self.preparation, inputs["originals"]["cloud"]["files"]["config.json"]["retained"],
                    inputs["network"]["records"]["pf-filter.expected"], self.entries["cloud"]["generation"]]
            for ref in refs:
                path = self.root / ref["path"]
                before = path.read_bytes()
                atomic_write(path, "corrupt")
                with self.subTest(path=path), self.assertRaises(ValueError):
                    self.native.view(self.operation)
                atomic_write(path, before.decode())
            self.native.read(self.operation)

    def test_rehashed_inputs_still_require_exact_original_refs_and_recipe_digest(self):
        with self.registry.locked(recovery=True):
            intent = self.begin()
            original = self.store._bound(intent["inputs"])
            value = json.loads(original)
            wrong_ref = deepcopy(value)
            wrong_ref["originals"]["cloud"]["files"]["config.json"]["original"] = self.preparation
            wrong_recipe = deepcopy(value)
            wrong_recipe["recipe"]["id"] = "changed"
            wrong_entries = deepcopy(value)
            wrong_entries["entries"]["retired"]["status"]["data_retained"] = True
            for inputs in (wrong_ref, wrong_recipe, wrong_entries):
                atomic_json(self.root / intent["inputs"]["path"], inputs)
                changed_intent = {**intent, "inputs": self.store.reference(intent["inputs"]["path"])}
                with self.assertRaises(ValueError):
                    self.native._inputs(changed_intent)
            atomic_write(self.root / intent["inputs"]["path"], original.decode())
            self.native.read(self.operation)

    def test_original_view_does_not_follow_changed_target_descriptor(self):
        with self.registry.locked(recovery=True):
            self.begin()
            view = self.native.view(self.operation)
            original = view.evidence_path("cloud", "config.json").read_bytes()
            path = self.root / "instances/cloud/config.json"
            saved = path.read_bytes()
            atomic_json(path, {"fixture": "interrupted destination descriptor"})
            self.assertEqual(view.evidence_path("cloud", "config.json").read_bytes(), original)
            self.assertEqual(view.load("cloud").instance, "cloud")
            with self.assertRaises(ValueError):
                self.commit()
            atomic_write(path, saved.decode())
            self.commit()

    def test_unaffected_mixed_entries_and_directory_coverage_cannot_change(self):
        with self.registry.locked(recovery=True):
            self.begin()
            for name in ("other", "retired"):
                changed = deepcopy(self.entries)
                changed.pop(name)
                with self.assertRaises(ValueError):
                    self.commit(entries=changed)
            changed = deepcopy(self.entries)
            changed["retired"]["status"]["data_retained"] = True
            with self.assertRaises(ValueError):
                self.commit(entries=changed)
            atomic_write(self.root / "instances/other/versions.json", "changed")
            with self.assertRaises(ValueError):
                self.native.read(self.operation)
            atomic_write(self.root / "instances/other/versions.json", '{ "fixture": "original lock" }\n')
            self.fixture.instance("unknown")
            with self.assertRaises(ValueError):
                self.native.read(self.operation)

    def test_chain_requires_exact_predecessor_and_restores_exact_original(self):
        with self.registry.locked(recovery=True):
            self.begin()
            destination = self.commit()
            with self.assertRaises(ValueError):
                self.commit("restored-closed", self.base)
            changed = deepcopy(self.entries)
            changed["cloud"]["status"] = {"state": "failed"}
            with self.assertRaises(ValueError):
                self.commit("restored-closed", destination, changed)
            self.commit("restored-closed", destination)
            with self.assertRaises(ValueError):
                self.commit()
            with self.assertRaises(ValueError):
                self.native.finish(self.operation, "complete")

    def test_arbitrary_active_graph_is_not_a_pending_bypass(self):
        with self.registry.locked(recovery=True):
            self.begin()
            graph = json.loads(self.store._bound(self.base))
            graph.update(graph_id="unrelated", operation="unrelated")
            ref = self.store._put("lifecycle/graphs/unrelated.json", graph)
            self.store._put("lifecycle/active.json", {"schema_version": 1, "graph": ref}, replace=True)
            with self.assertRaises(ValueError):
                self.native.read(self.operation)

    def test_graph_and_step_and_pointer_crashes_retry_exact_bytes(self):
        for boundary in ("graph", "step", "pointer"):
            with self.subTest(boundary=boundary):
                # Use a fresh registry for each distinct crash boundary.
                fixture = NativeStateTests()
                fixture.setUp()
                try:
                    with fixture.registry.locked(recovery=True):
                        fixture.begin()
                        write = fixture.native.store._write
                        def interrupt(relative, data, **kwargs):
                            result = write(relative, data, **kwargs)
                            if ((boundary == "graph" and relative == "lifecycle/graphs/graph-validated-closed.json")
                                    or (boundary == "step" and relative.endswith("/validated-closed.json"))
                                    or (boundary == "pointer" and relative == "lifecycle/active.json")):
                                raise OSError("injected publication crash")
                            return result
                        with patch.object(fixture.native.store, "_write", side_effect=interrupt), self.assertRaises(OSError):
                            fixture.commit()
                        self.assertIsNotNone(fixture.store.pending())
                        ref = fixture.commit()
                        self.assertEqual(fixture.commit(), ref)
                        fixture.native.finish(fixture.operation)
                        self.assertIsNone(fixture.store.pending())
                finally:
                    fixture.doCleanups()

    def test_terminal_crash_retains_fence_and_distinct_journal_terminal(self):
        with self.registry.locked(recovery=True):
            self.begin()
            self.commit()
            directory = f"maintenance/operations/{self.operation}"
            journal_terminal = self.store._put(directory + "/native-terminal.json", {"fixture": "native journal"})
            write = self.native.store._write
            def interrupt(relative, data, **kwargs):
                if relative == "maintenance/pending.json":
                    raise OSError("injected idle pointer failure")
                return write(relative, data, **kwargs)
            with patch.object(self.native.store, "_write", side_effect=interrupt), self.assertRaises(OSError):
                self.native.finish(self.operation)
            self.assertIsNotNone(self.store.pending())
            terminal = self.store._read(directory + "/terminal.json")
            self.native.finish(self.operation)
            self.assertEqual(self.store._read(directory + "/terminal.json"), terminal)
            self.assertEqual(json.loads(self.store._bound(journal_terminal)), {"fixture": "native journal"})
        self.assertIsNone(self.store.pending())
        with self.assertRaises(ValueError):
            self.store.graph(validate_evidence=False)

    def test_restore_before_destination_is_explicit(self):
        with self.registry.locked(recovery=True):
            self.begin()
            self.commit("restored-closed")
            self.native.finish(self.operation, "recovered")
        self.assertIsNone(self.store.pending())

    def test_cancelled_idle_uses_lifecycle_terminal_and_revokes_view(self):
        with self.registry.locked(recovery=True):
            self.begin()
            view = self.native.view(self.operation)
            self.native.finish(self.operation, "cancelled")
            self.assertIsNone(self.store.pending())
            self.assertEqual(self.store._active(), self.base)
            with self.assertRaises(ValueError):
                view.load("cloud")


if __name__ == "__main__":
    unittest.main()
