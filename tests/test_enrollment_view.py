"""Mixed enrollment snapshots use real sealed offline successor fixtures."""

from copy import deepcopy
import json
import unittest
from unittest.mock import Mock, patch

from installer.deploy import Deployment
from installer.generations import Store, descriptor
from installer.maintenance import _EnrollmentView
from installer.state import atomic_json, config_digest
from version_fixtures import historic_policy as load_policy
from installer import maintenance_generations as successors
import test_maintenance_generations as fixtures


class EnrollmentViewTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.SuccessorTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.registry, self.store = self.fixture.registry, self.fixture.store
        with self.registry.locked(recovery=True):
            self.fixture.begin()
            self.successor = self.fixture.seal()
            self.fixture.commit(self.successor)
            self.fixture.native.finish(self.fixture.operation)
        self.directory = "maintenance/operations/enroll-other"
        self.store._mkdir(self.directory)
        originals = {}
        for config, status in self.registry.entries(include_removed=True):
            name = config.instance
            originals[name] = {
                "config": self.store._write(self.directory + "/" + name + "-config.json",
                                            self.registry.evidence_path(name, "config.json").read_bytes()),
                "status": self.store._put(self.directory + "/" + name + "-status.json", status)}
        self.plan = dict(schema_version=1, operation="enroll-other", instance="other",
                         executor=self.fixture.executor, generation="initial-other", graph="graph-other",
                         originals=originals, entries=self.store.graph()["instances"],
                         assessment={}, evidence={})
        ref = self.store._put(self.directory + "/enrollment.json", self.plan)
        self.store._put(self.directory + "/enrollment-inputs.json", {"schema_version": 1, "plan": ref})
        self.store.begin("enroll-other", "enroll", ["other"], self.fixture.executor["executor_sha256"])

    def view(self, plan=None):
        return _EnrollmentView(self.registry, self.store, self.plan if plan is None else plan)

    def test_mixed_policy_versions_and_original_journal_binding_while_pending(self):
        with self.assertRaisesRegex(ValueError, "pending"):
            self.registry.load("cloud")
        with patch.object(Store, "resolve", side_effect=AssertionError("current resolution forbidden")), \
                patch.object(Store, "graph", side_effect=AssertionError("current graph forbidden")), \
                patch.object(Store, "_active", side_effect=AssertionError("active pointer forbidden")), \
                patch("installer.resolution.resolve", side_effect=AssertionError("reselection forbidden")):
            view = self.view()
            self.assertEqual(view.load("cloud").nextcloud_exact, "35.0.2")
            self.assertEqual(view.version_policy("cloud"), successors.destination_policy())
            self.assertEqual(view.version_policy("other"), load_policy())
            self.assertEqual(view.deployment_config_digest("cloud"), config_digest(self.fixture.config))
            self.assertNotEqual(view.deployment_config_digest("cloud"), config_digest(view.load("cloud")))
            self.assertEqual(view.deployment_config_digest("other"), config_digest(view.load("other")))
            runner = Mock()
            deployment = Deployment(view.load("cloud"), {}, runner, registry=view)
            self.assertEqual(deployment.versions, json.loads(self.fixture.target["versions.json"]))
            runner.run.assert_not_called()
            self.assertEqual([config.instance for config, _ in view.entries()], ["cloud", "other"])
        self.assertEqual((self.registry.root / "instances/cloud/deployment.json").read_bytes(),
                         self.fixture.initial_journal)

    def test_selected_generation_survives_live_descriptor_change(self):
        atomic_json(self.registry.root / "instances/cloud/config.json", descriptor("cloud", self.fixture.predecessor))
        view = self.view()
        self.assertEqual(view.load("cloud").nextcloud_exact, "35.0.2")
        self.assertEqual(view.version_policy("cloud"), successors.destination_policy())
        self.assertEqual(view.evidence_path("cloud", "versions.json").read_bytes(),
                         self.fixture.target["versions.json"])
        self.assertEqual(view.evidence_path("cloud", "source.sha256").read_bytes(),
                         (self.registry.root / "instances/cloud/legacy/files/source.sha256").read_bytes())

    def test_initial_managed_generation_retains_base_policy(self):
        plan = deepcopy(self.plan)
        plan["entries"]["cloud"]["generation"] = self.fixture.predecessor
        plan["originals"]["cloud"]["config"] = self.store._write(
            self.directory + "/initial-config.json", self.fixture.initial_config)
        view = self.view(plan)
        self.assertEqual(view.load("cloud").to_json().encode(), self.fixture.initial_config)
        self.assertEqual(view.version_policy("cloud"), load_policy())
        self.assertEqual(view.deployment_config_digest("cloud"), config_digest(self.fixture.config))

    def test_managed_snapshot_config_status_and_generation_must_match(self):
        substitutions = (
            ("config", self.store._write(self.directory + "/wrong-config.json", self.fixture.initial_config)),
            ("status", self.store._put(self.directory + "/wrong-status.json", {"state": "removed"})))
        for key, reference in substitutions:
            plan = deepcopy(self.plan)
            plan["originals"]["cloud"][key] = reference
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "managed entry"):
                self.view(plan)
        plan = deepcopy(self.plan)
        plan["entries"]["cloud"]["generation"] = self.fixture.predecessor
        with self.assertRaisesRegex(ValueError, "managed entry"):
            self.view(plan)
        plan["entries"]["cloud"]["generation"] = {**self.successor, "sha256": "f" * 64}
        with self.assertRaises(ValueError):
            self.view(plan)

    def test_successor_source_and_original_journal_are_revalidated(self):
        with patch("installer.maintenance.executor_record", return_value={
                **self.fixture.executor, "source_sha256": "f" * 64}), self.assertRaises(ValueError):
            self.view()
        journal = json.loads(self.fixture.initial_journal)
        journal["config_sha256"] = config_digest(self.view().load("cloud"))
        atomic_json(self.registry.root / "instances/cloud/deployment.json", journal)
        with self.assertRaises(ValueError):
            self.view()

    def test_legacy_snapshot_mismatch_and_unknown_fields_stay_strict(self):
        plan = deepcopy(self.plan)
        original = json.loads(self.store._bound(plan["originals"]["other"]["config"]))
        for change in ({"instance": "cloud"}, {"unreviewed_policy": {}}):
            plan["originals"]["other"]["config"] = self.store._put(
                self.directory + "/legacy-altered.json", {**original, **change},
                replace=self.store._present(self.directory + "/legacy-altered.json"))
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.view(plan)
            # The legacy-only path still uses the strict Config reader even if
            # no managed entry/provenance was supplied by an older caller.
            plan["entries"].pop("other", None)
            with self.assertRaises(ValueError):
                self.view(plan)

    def test_reads_return_independent_configs_statuses_and_policies(self):
        view = self.view()
        expected = {name: (view.load(name), view.status(name), view.version_policy(name))
                    for name in ("cloud", "other")}
        for name in expected:
            view.load(name).nextcloud_exact = "99.0.0"
            view.status(name)["state"] = "removed"
            view.version_policy(name)["profiles"][0]["applications"]["nextcloud"] = {"exact": "99.0.0"}
        for config, status in view.entries(include_removed=True):
            config.nextcloud_exact = "99.0.0"
            status["state"] = "removed"
        view.network_configs()[0].nextcloud_exact = "99.0.0"
        self.plan["entries"]["cloud"]["status"]["state"] = "removed"
        for name, (config, status, policy) in expected.items():
            self.assertEqual(view.load(name), config)
            self.assertEqual(view.status(name), status)
            self.assertEqual(view.version_policy(name), policy)
        for method in (view.load, view.status, view.version_policy, view.deployment_config_digest):
            with self.subTest(method=method.__name__), self.assertRaises(ValueError):
                method("unknown")


if __name__ == "__main__":
    unittest.main()
