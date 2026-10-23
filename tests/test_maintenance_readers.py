"""Mixed original/successor reader regressions; all receipts are offline fixtures."""

from copy import deepcopy
from dataclasses import replace
import io
import hashlib
import json
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from installer import dashboard, host, lifecycle, maintenance_operations, updates
from installer import maintenance_generations as successors
from installer import maintenance_preflight
from installer.deploy import Deployment
from installer.generations import descriptor
from installer.main import show_status
from installer.maintenance_journal import REVIEWED_NATIVE_RECIPES
from installer.paths import RESOURCES
from installer.state import atomic_json, atomic_write, config_digest
from installer.versions import policy_hash
import test_maintenance_generations as successor_fixture
from version_fixtures import (historic_policy as load_policy, historical_maintenance_policy,
                              discovery_metadata, resolved_plan)


class MixedReaderTests(unittest.TestCase):
    @staticmethod
    def checksums(packages):
        for name, record in packages.items():
            record["checksum"] = hashlib.sha256(name.encode()).hexdigest()

    def setUp(self):
        self.enterContext(historical_maintenance_policy())
        self.fixture = successor_fixture.SuccessorTests()
        self.addCleanup(self.fixture.doCleanups)
        # Staging requires SHA256 archive identities, unlike the general pkg
        # fixtures' alternative checksum encoding. Keep all bound copies equal.
        inputs = successor_fixture.inspection_fixture()
        _, retained, observations, repository, bindings = inputs
        for packages in retained["packages"].values():
            self.checksums(packages)
        self.checksums(repository["packages"])
        repository["available_packages"] = {name: item["checksum"] for name, item in repository["packages"].items()}
        bindings["versions_sha256"] = maintenance_preflight.digest(retained)
        observations["bindings"] = deepcopy(bindings)
        repository["bindings"] = deepcopy(bindings)
        with patch.object(successor_fixture, "inspection_fixture", return_value=inputs):
            self.fixture.setUp()
        f = self.fixture
        self.registry, self.store = f.registry, f.store
        self.enterContext(patch("installer.deploy.source_digest", return_value=f.executor["source_sha256"] + "\n"))
        self.enterContext(patch.object(maintenance_operations, "PROJECT_ROOT", f.source))
        self.enterContext(patch.object(maintenance_operations, "executor_record", return_value=deepcopy(f.executor)))
        self.store._put("lifecycle/executor.json", f.executor)
        # The other instance remains at the exact reviewed original version.
        self.other = replace(f.config, instance="other", public_hostname="other.example.test", nextcloud_exact="35.0.1")
        self.other_plan = resolved_plan(self.other, nextcloud="35.0.1")
        for packages in self.other_plan["packages"].values():
            self.checksums(packages)
        self.store.begin("enroll-other", "enroll", ["other"], f.executor["executor_sha256"])
        path = self.registry.instance_path("other")
        atomic_write(path / "config.json", self.other.to_json())
        atomic_write(path / "source.sha256", f.executor["source_sha256"] + "\n")
        atomic_json(path / "status.json", {"state": "ready"})
        atomic_json(path / "versions.json", self.other_plan)
        atomic_json(path / "deployment.json", dict(schema_version=2, config_sha256=config_digest(self.other),
                                                  steps={"readiness checks": {"state": "complete"}}))
        archive = self.store.archive_legacy("other", "enroll-other")
        generation = self.store.seal_generation("other", "initial", "enroll-other", archive=archive,
            evidence={"policy.json": (RESOURCES / "versions.json").read_bytes(), "resources.json": b"{}"})
        atomic_json(path / "config.json", descriptor("other", generation))
        f.entries["other"] = dict(kind="managed", generation=generation, status={"state": "ready"})
        f.fixture.publish(f.entries, "enroll-other", "graph-mixed")
        f.base = self.store._active()
        f.preparation = self.preparation("cloud", "maint-mixed")
        with self.registry.locked(recovery=True):
            f.begin()
            f.commit(f.seal())
            f.native.finish(f.operation)

    def preparation(self, name, operation):
        f = self.fixture
        template = json.loads(self.store._read("maintenance/plans/plan-fixture.json"))
        entry = self.store.graph()["instances"][name]
        template.update(instance=name, plan_id="plan-" + operation)
        template["bindings"].update(graph=self.store._active(), generation=entry["generation"],
                                    versions=self.store._generation(name, entry["generation"])["versions"])
        ref = self.store._put("maintenance/plans/" + template["plan_id"] + ".json", template)
        self.store._mkdir("maintenance/operations/" + operation)
        return self.store._put("maintenance/operations/" + operation + "/operation.json", dict(
            schema_version=1, kind="recovery-preparation-operation", operation=operation, instance=name,
            plan=ref, executor=f.executor, recipe=None, effects=["private-artifact-staging"]))

    def test_mixed_reports_list_status_and_maintenance_plans(self):
        with patch("subprocess.run", side_effect=AssertionError("native execution")):
            result = updates.check_updates(self.registry, ["cloud", "other"])
            self.assertFalse(result["inspection_failed"], result)
            reports = {row["instance"]: row for row in result["instances"]}
            self.assertEqual(reports["cloud"]["installed_applications"]["nextcloud"], "35.0.2")
            self.assertEqual(reports["other"]["installed_applications"]["nextcloud"], "35.0.1")
            self.assertEqual(reports["cloud"]["bindings"]["policy_sha256"], policy_hash(successors.destination_policy()))
            self.assertEqual(reports["other"]["bindings"]["policy_sha256"], policy_hash(load_policy()))
            self.assertTrue(all(row["provenance"]["original_policy_available"] for row in reports.values()))
            view = dashboard.snapshot(self.registry)
            self.assertFalse(view["errors"], view)
            self.assertEqual([(row["instance"], row["state"]) for row in view["instances"]],
                             [("cloud", "ready"), ("other", "ready")])
            with patch("sys.stdout", new_callable=io.StringIO) as output:
                show_status(self.registry)
                show_status(self.registry, "cloud")
            self.assertIn("other", output.getvalue())
            self.assertIn("readiness checks", output.getvalue())
            for name in ("cloud", "other"):
                report = maintenance_operations.assess(self.registry, name)
                self.assertEqual(report["status"], "staging-only", report)
                self.assertEqual(report["plan"]["bindings"]["executor"], self.fixture.executor)
                self.assertFalse(report["execution_authorized"])
        self.assertEqual(REVIEWED_NATIVE_RECIPES, {})

    def test_refresh_save_and_cache_use_each_effective_policy(self):
        def discover(config, runner, *, policy):
            self.assertEqual(policy, self.registry.version_policy(config.instance))
            metadata = discovery_metadata(config, nextcloud=config.nextcloud_exact)
            self.checksums(metadata["packages"])
            return metadata
        with patch("installer.discovery.discover", side_effect=discover):
            report = updates.check_updates(self.registry, ["cloud", "other"], refresh=True,
                                           save_report=True, runner=Mock())
        self.assertFalse(report["inspection_failed"], report)
        self.assertTrue(all(row["saved"] for row in report["instances"]))
        with patch("installer.discovery.discover", side_effect=AssertionError("cached read discovery")), \
                patch.object(self.registry, "locked", side_effect=AssertionError("cached read lock")):
            cached = updates.check_updates(self.registry, ["cloud", "other"])
        self.assertFalse(cached["inspection_failed"], cached)
        self.assertTrue(all(row["freshness"] == "fresh" for row in cached["instances"]))
        self.assertEqual(load_policy()["profiles"][0]["applications"]["nextcloud"]["max_exclusive"], "35.0.2")

    def test_native_original_view_includes_unaffected_already_upgraded_instance(self):
        f = self.fixture
        preparation = self.preparation("other", "maint-second")
        with self.registry.locked(recovery=True):
            f.native.begin("execution-second", "other", preparation=preparation, recipe={"id": "offline-fixture"})
            view = f.native.view("execution-second")
            self.assertEqual(view.version_policy("cloud"), successors.destination_policy())
            self.assertEqual(view.version_policy("other"), load_policy())
            self.assertEqual(view.deployment_config_digest("cloud"), config_digest(f.config))
            self.assertEqual(view.deployment_config_digest("other"), config_digest(self.other))
            for name in ("cloud", "other"):
                config = view.load(name)
                self.assertTrue(host._ownership_journal(view, config, view.status(name)))
                deployment = Deployment(config, {}, Mock(), registry=view)
                self.assertEqual(deployment.versions["applications"]["nextcloud"], config.nextcloud_exact)
            runner = Mock()
            self.assertEqual(host._manager_ownership(view.load("other"), view, view.entries(),
                                                    {"cloud", "other"}, False, runner), (False, False))
            runner.run.assert_not_called()
            atomic_json(self.registry.instance_path("other") / "config.json", {"interrupted": True})
            self.assertEqual(view.deployment_config_digest("other"), config_digest(self.other))
            self.assertEqual(view.version_policy("cloud"), successors.destination_policy())
        with self.assertRaises(ValueError):
            view.version_policy("cloud")

    def test_original_journal_binding_is_preserved_and_tampering_is_refused(self):
        f = self.fixture
        path = self.registry.instance_path("cloud") / "deployment.json"
        self.assertEqual(path.read_bytes(), f.initial_journal)
        atomic_json(path.parent / "initialization.json", dict(schema_version=1, instance="cloud", state="complete",
                    config_sha256=config_digest(f.config), recoveries=[]))
        updates._save_conflicts(self.registry)
        original = json.loads(path.read_bytes())
        original["config_sha256"] = config_digest(self.registry.load("cloud"))
        atomic_json(path, original)
        self.assertTrue(updates.check_updates(self.registry, ["cloud"])["inspection_failed"])
        view = dashboard.snapshot(self.registry)
        self.assertTrue(view["errors"] or any(row["state"] == "inspection-error" for row in view["instances"]))
        self.assertEqual(maintenance_operations.assess(self.registry, "cloud")["status"], "blocked")

    def test_removal_journal_binds_effective_configuration(self):
        config = self.registry.load("cloud")
        path = self.registry.instance_path("cloud")
        deployment = SimpleNamespace(config=config, state=path)
        journal = dict(schema_version=2, config_sha256=config_digest(config),
                       steps={step: {"state": "complete"} for step in lifecycle.RUNTIME_STEPS})
        atomic_json(path / "removal.json", journal)
        self.assertTrue(lifecycle._runtime_removed(deployment, {"state": "ready"}))
        updates._save_conflicts(self.registry)
        journal["config_sha256"] = self.registry.deployment_config_digest("cloud")
        atomic_json(path / "removal.json", journal)
        with self.assertRaises(ValueError):
            lifecycle._runtime_removed(deployment, {"state": "ready"})
        with self.assertRaises(ValueError):
            updates._save_conflicts(self.registry)

    def test_different_source_reader_refuses_successor(self):
        executor = {**self.fixture.executor, "source_sha256": "f" * 64}
        with patch("installer.maintenance.executor_record", return_value=executor):
            with self.assertRaises(ValueError):
                self.registry.load("cloud")
            report = updates.check_updates(self.registry, ["cloud"])
            self.assertTrue(report["inspection_failed"])
            self.assertIn("Unsupported inspection", report["instances"][0]["errors"][0]["message"])
            self.assertEqual(maintenance_operations.assess(self.registry, "cloud")["status"], "blocked")
        with patch("installer.deploy.source_digest", return_value="f" * 64 + "\n"):
            self.assertEqual(maintenance_operations.assess(self.registry, "other")["status"], "blocked")


if __name__ == "__main__":
    unittest.main()
