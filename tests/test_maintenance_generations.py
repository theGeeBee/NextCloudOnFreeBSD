"""Offline successor storage/readers; synthetic receipts are not native acceptance."""

from copy import deepcopy
import json
import shutil
import unittest
from unittest.mock import Mock, patch

from installer import maintenance_generations as successors, maintenance_preflight as preflight
from installer.config import Config
from installer.deploy import Deployment
from installer.generations import Store, _encode, _hash, descriptor
from installer.maintenance_operations import NETWORK_RECORDS
from installer.maintenance_staging import _source
from installer.maintenance_state import NativeState
from installer.paths import PROJECT_ROOT, RESOURCES
from installer.resolution import assess_upgrade, validate_plan
from installer.state import Registry, atomic_json, atomic_write, config_digest
from installer.versions import policy_hash
import test_generations as storage_fixture
from test_maintenance_preflight import inputs as inspection_fixture
from test_state import configuration
from version_fixtures import historic_policy as load_policy, historical_maintenance_policy, resolved_plan


class HistoricalPolicyBoundaryTests(unittest.TestCase):
    def test_current_policy_is_not_the_original_maintenance_artifact(self):
        from installer import versions

        current = versions.load_policy()
        original = load_policy()
        self.assertEqual(policy_hash(original),
                         "daa55a823bbe3f895504a8e5e6b0f274b6d02feb81d2a6835f2a8104bbc60efe")
        self.assertNotEqual(policy_hash(current), policy_hash(original))
        with patch.object(successors, "load_policy", return_value=current):
            with self.assertRaisesRegex(ValueError, "Maintenance base profile changed"):
                successors.destination_policy()
        with historical_maintenance_policy():
            config, retained, observed, repository, bindings = inspection_fixture()
            self.assertEqual(retained["policy_sha256"], policy_hash(original))
            self.assertEqual(successors.destination_policy()["profiles"][0]["applications"]["nextcloud"],
                             {"exact": "35.0.2"})
            self.assertTrue(preflight.assess(config, retained, observed, repository,
                            bindings=bindings, now=1010)["eligible"])
        # Restoring the current loaders must not authorize this historical lock.
        report = preflight.assess(config, retained, observed, repository, bindings=bindings, now=1010)
        self.assertFalse(report["eligible"])
        self.assertIn("source-plan-incompatible", report["blockers"])
        self.assertEqual(versions.load_policy(), current)


class SuccessorTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(historical_maintenance_policy())
        self.fixture = storage_fixture.GenerationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root, self.store = self.fixture.root, self.fixture.store
        self.registry = Registry(self.root)
        self.registry.initialize()
        # Freeze exact public bytes while other slices edit the shared checkout.
        self.source = self.root / "public-source"
        self.source.mkdir(mode=0o700)
        for name in ("installer", "resources"):
            shutil.copytree(PROJECT_ROOT / name, self.source / name,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        shutil.copyfile(PROJECT_ROOT / "install.sh", self.source / "install.sh")
        _, source, executor = _source(self.source)
        self.executor = dict(schema_version=1, source_sha256=source, executor_sha256=executor,
                             payload_path=str(self.source), policy_sha256=policy_hash(load_policy()))
        self.enterContext(patch("installer.maintenance.executor_record", return_value=deepcopy(self.executor)))
        self.enterContext(patch.object(successors, "PROJECT_ROOT", self.source))
        self.config, self.retained, self.observations, self.repository, _ = inspection_fixture()
        instance = self.fixture.instance()
        atomic_write(instance / "config.json", self.config.to_json())
        atomic_write(instance / "source.sha256", source + "\n")
        atomic_json(instance / "versions.json", self.retained)
        atomic_json(instance / "deployment.json", dict(schema_version=2, config_sha256=config_digest(self.config),
                                                       steps={"readiness checks": {"state": "complete"}}))
        self.initial_config = (instance / "config.json").read_bytes()
        self.initial_journal = (instance / "deployment.json").read_bytes()
        other = self.fixture.instance("other", state="configured", source=False)
        atomic_write(other / "config.json", configuration(instance="other").to_json())
        self.store.begin("enroll-one", "enroll", ["cloud"], executor)
        archive = self.store.archive_legacy("cloud", "enroll-one")
        self.predecessor = self.store.seal_generation("cloud", "initial", "enroll-one", archive=archive,
            evidence={"policy.json": (RESOURCES / "versions.json").read_bytes(), "resources.json": b"{}"})
        atomic_json(instance / "config.json", descriptor("cloud", self.predecessor))
        self.entries = {"cloud": dict(kind="managed", generation=self.predecessor, status={"state": "ready"}),
                        "other": self.store.legacy_entry("other")}
        self.fixture.publish(self.entries)
        self.base = self.store._active()
        transaction = self.store._mkdir("transactions/original")
        records = {name: self.store._write("transactions/original/" + name,
                   _encode({"instances": ["cloud"]}) if name == "firewall-transition.json" else b"original\n")
                   for name in NETWORK_RECORDS}
        (self.root / "network/active").symlink_to(transaction)
        previous = self.store._generation("cloud", self.predecessor)
        plan = dict(schema_version=1, kind="recovery-preparation-plan", plan_id="plan-fixture", instance="cloud",
                    bindings=dict(graph=self.base, generation=self.predecessor, versions=previous["versions"],
                                  executor=self.executor, network=dict(target="transactions/original", records=records)),
                    artifacts=[dict(kind="source", path="source/install.sh", sha256="c" * 64, size=0)],
                    recipe=None, upgrade_execution_authorized=False, native_execution_authorized=False, native_acceptance="not-run")
        self.store._mkdir("maintenance/plans")
        plan_ref = self.store._put("maintenance/plans/plan-fixture.json", plan)
        self.store._mkdir("maintenance/operations/maint-fixture")
        self.preparation = self.store._put("maintenance/operations/maint-fixture/operation.json", dict(
            schema_version=1, kind="recovery-preparation-operation", operation="maint-fixture", instance="cloud",
            plan=plan_ref, executor=self.executor, recipe=None, effects=["private-artifact-staging"]))
        self.native = NativeState(self.registry, self.executor)
        self.operation, self.generation = "execution-successor", "nextcloud-patch"
        self.target = successors.proposed_files(self.initial_config, self.retained)

    def begin(self):
        intent = self.native.begin(self.operation, "cloud", preparation=self.preparation, recipe=preflight.recipe())
        inputs = self.native.read(self.operation)[1]
        ref = self.store.reference(f"maintenance/operations/{self.operation}/intent.json")
        bindings = successors.inspection_bindings(self.store, self.predecessor, intent, inputs, self.initial_config, self.retained)
        self.observations["bindings"] = deepcopy(bindings)
        self.repository["bindings"] = deepcopy(bindings)
        report = preflight.assess(self.config, self.retained, self.observations, self.repository, bindings=bindings, now=1010)
        self.assertTrue(report["eligible"], report)
        candidate = report["candidate"]
        hashes = {key: _hash(data) for key, data in self.target.items()}
        review = dict(schema_version=1, kind="nextcloud-successor-review", operation=self.operation, instance="cloud",
                      predecessor=self.predecessor, intent=ref, recipe_sha256=inputs["recipe_sha256"],
                      original_config_sha256=_hash(self.initial_config), target_files=hashes,
                      candidate_sha256=_hash(_encode(candidate)))
        workers = successors.source_hashes(self.executor)
        jails = {}
        for group, jail in (("nextcloud", self.config.nextcloud_jail), ("onlyoffice", self.config.onlyoffice_jail)):
            files = {"/root/cloud-installer/" + name: sha for name, sha in workers.items()}
            files.update({"/root/cloud-installer/" + name: hashes[group + "/" + name] for name in successors.PUBLIC_FILES})
            if group == "nextcloud":
                files["/usr/local/libexec/cloud-runtime-inventory.php"] = workers["resources/jails/runtime-inventory.php"]
            jails[group] = dict(name=jail, files=files)
        effective = dict(schema_version=1, kind="effective-public-worker-receipt", operation=self.operation,
                         instance="cloud", generation=self.generation, executor_sha256=self.executor["executor_sha256"],
                         target_files=hashes, jails=jails)
        readiness = dict(schema_version=1, kind="nextcloud-successor-readiness", operation=self.operation, instance="cloud",
                         config_sha256=hashes["config.json"], versions_sha256=hashes["versions.json"],
                         nextcloud=dict(installed=True, maintenance=True, needsDbUpgrade=False, version="35.0.2.2", versionstring="35.0.2"),
                         packages_sha256=preflight.digest(self.retained["packages"]),
                         apps={name: value["version"] for name, value in candidate["apps"].items()})
        self.evidence = {"candidate.json": _encode(candidate), "review.json": _encode(review),
                         "effective.json": _encode(effective), "readiness.json": _encode(readiness)}
        return intent

    def seal(self, **kwargs):
        return successors.seal_successor(self.native, self.operation, self.generation,
            target_files=kwargs.pop("target_files", self.target), validation_evidence=kwargs.pop("validation_evidence", self.evidence), **kwargs)

    def commit(self, reference):
        atomic_json(self.root / "instances/cloud/config.json", descriptor("cloud", reference))
        entries = deepcopy(self.entries)
        entries["cloud"]["generation"] = reference
        return self.native.commit_closed(self.operation, "validated-closed", "graph-successor", entries,
                                         expected_predecessor=self.base)

    def vendor_source_label(self):
        self.observations['nextcloud']['apps']['files']=dict(version='3.0.0-dev.0',enabled=True,provenance='shipped')
        self.repository['apps']['files']=dict(source_version='3.0.0-dev.0',version='3.0.0',delivery='shipped',
            phpVersionSpec='>=8.3.0 <8.6.0',platformVersionSpec='>=35.0.0 <36.0.0',artifact_sha256='c'*64)

    def test_successor_seals_authenticated_original_vendor_label_with_stable_destination(self):
        self.vendor_source_label()
        with self.registry.locked(recovery=True):
            self.begin()
            reference=self.seal()
            self.assertTrue(self.store._bound(reference))

    def test_successor_refuses_unknown_source_labels_and_destination_prereleases(self):
        self.vendor_source_label()
        with self.registry.locked(recovery=True):
            self.begin()
            original=json.loads(self.evidence['candidate.json'])
            review=json.loads(self.evidence['review.json'])
            for field,value in (('source_version','3.0.0-dev.1'),('version','3.0.0-dev.0')):
                with self.subTest(field=field):
                    candidate=deepcopy(original);candidate['apps']['files'][field]=value
                    evidence=dict(self.evidence);evidence['candidate.json']=_encode(candidate)
                    evidence['review.json']=_encode(dict(review,candidate_sha256=_hash(evidence['candidate.json'])))
                    with self.assertRaises(ValueError):
                        self.seal(validation_evidence=evidence)

    def test_exact_derivative_keeps_installation_bounds_and_packages(self):
        raw = (RESOURCES / "versions.json").read_bytes()
        target = json.loads(self.target["versions.json"])
        config = Config.from_json(self.target["config.json"].decode())
        policy = successors.destination_policy()
        self.assertEqual(target["applications"], {**self.retained["applications"], "nextcloud": "35.0.2"})
        for field in ("packages", "roots", "roles", "connector", "target", "repository", "fonts_unavailable", "warnings"):
            self.assertEqual(target[field], self.retained[field])
        self.assertEqual(config.nextcloud_exact, "35.0.2")
        self.assertEqual(validate_plan(config, target, policy=policy), target)
        with self.assertRaises(ValueError):
            validate_plan(config, target)
        self.assertEqual(policy["profiles"][0]["applications"]["nextcloud"], {"exact": "35.0.2"})
        self.assertEqual(load_policy()["profiles"][0]["applications"]["nextcloud"]["max_exclusive"], "35.0.2")
        self.assertEqual((RESOURCES / "versions.json").read_bytes(), raw)
        assessment = assess_upgrade(self.retained, target)
        self.assertFalse(assessment["blockers"])

    def test_explicit_source_pin_proposes_only_reviewed_exact_target_change(self):
        self.config.nextcloud_exact = "35.0.1"
        raw = self.config.to_json().encode()
        source = resolved_plan(self.config, nextcloud="35.0.1")
        target = successors.target_configuration(raw)
        self.assertEqual(target.nextcloud_exact, "35.0.2")
        expected = json.loads(raw)
        expected["nextcloud_exact"] = "35.0.2"
        self.assertEqual(json.loads(target.to_json()), expected)
        self.assertEqual(successors.target_plan(raw, source)["constraints"]["nextcloud_exact"], "35.0.2")
        self.assertEqual(json.loads(raw)["nextcloud_exact"], "35.0.1")

    def test_ready_successor_registry_and_deployment_read_without_reselection(self):
        with self.registry.locked(recovery=True):
            self.begin()
            reference = self.seal()
            manifest = self.store._generation("cloud", reference)
            self.assertEqual(manifest["schema_version"], 2)
            self.assertEqual(manifest["predecessor"], self.predecessor)
            self.commit(reference)
            self.native.finish(self.operation)
        with patch("installer.resolution.resolve", side_effect=AssertionError("selection forbidden")):
            config = self.registry.load("cloud")
            self.assertEqual(config.nextcloud_exact, "35.0.2")
            self.assertEqual(self.registry.deployment_config_digest("cloud"), config_digest(self.config))
            self.assertEqual(self.registry.version_policy("cloud"), successors.destination_policy())
            runner = Mock()
            deployment = Deployment(config, {}, runner, registry=self.registry)
            self.assertEqual(deployment.versions, json.loads(self.target["versions.json"]))
            runner.run.assert_not_called()
            self.assertEqual(self.registry.load("other").instance, "other")
            self.assertEqual(self.registry.version_policy("other"), load_policy())
            self.assertEqual([config.instance for config, _ in self.registry.entries()], ["cloud", "other"])
        self.assertEqual((self.root / "instances/cloud/deployment.json").read_bytes(), self.initial_journal)
        self.assertEqual(self.store._bound(manifest["originals"]["config"]), self.initial_config)
        self.assertEqual(self.store._bound(manifest["originals"]["versions"]), _encode(self.retained))
        self.assertEqual(self.store.graph()["instances"]["other"], self.entries["other"])

    def test_recovery_publishes_original_generation_in_new_graph(self):
        with self.registry.locked(recovery=True):
            self.begin()
            view = self.native.view(self.operation)
            successor = self.seal()
            destination = self.commit(successor)
            self.assertEqual(view.evidence_path("cloud", "config.json").read_bytes(), self.initial_config)
            atomic_json(self.root / "instances/cloud/config.json", descriptor("cloud", self.predecessor))
            restored = self.native.commit_closed(self.operation, "restored-closed", "graph-restored", self.entries,
                                                 expected_predecessor=destination)
            self.assertNotEqual(restored, self.base)
            self.assertEqual(json.loads(self.store._bound(restored))["predecessor"], destination)
            self.native.finish(self.operation, "recovered")
        self.assertEqual(self.registry.load("cloud").to_json().encode(), self.initial_config)
        self.assertEqual(self.registry.version_policy("cloud"), load_policy())

    def test_target_file_changes_cannot_reinterpret_policy_config_or_lock(self):
        with self.registry.locked(recovery=True):
            self.begin()
            for filename, mutation in (
                ("config.json", lambda value: value.update(php_memory_mb=1024)),
                ("config.json", lambda value: value.update(nextcloud_exact="35.0.3")),
                ("policy.json", lambda value: value["profiles"][0]["applications"].update(nextcloud={"min": "35.0.0", "max_exclusive": "36.0.0"})),
                ("versions.json", lambda value: value["packages"]["nextcloud"]["php85"].update(checksum="f" * 64)),
                ("nextcloud/runtime.json", lambda value: value.update(db_password="forbidden"))):
                changed = deepcopy(self.target)
                document = json.loads(changed[filename])
                mutation(document)
                changed[filename] = _encode(document)
                with self.subTest(filename=filename), self.assertRaises(ValueError):
                    self.seal(target_files=changed)
            self.assertFalse((self.root / "instances/cloud/generations" / self.generation).exists())

    def test_exact_recipe_and_source_executor_are_required(self):
        with self.registry.locked(recovery=True):
            self.begin()
            for change in ({"source_sha256": "f" * 64}, {"executor_sha256": "f" * 64}, {"payload_path": "/different"}):
                with patch("installer.maintenance.executor_record", return_value={**self.executor, **change}), self.assertRaises(ValueError):
                    self.seal()
            altered = deepcopy(preflight.recipe())
            altered["destination"]["public"] = "35.0.3"
            with patch.object(preflight, "recipe", return_value=altered), self.assertRaises(ValueError):
                self.seal()
            reference = self.seal()
            with patch("installer.maintenance.executor_record", return_value={**self.executor, "source_sha256": "f" * 64}), self.assertRaises(ValueError):
                self.store._generation("cloud", reference)

    def test_complete_effective_worker_helpers_runtime_and_readiness_are_required(self):
        with self.registry.locked(recovery=True):
            self.begin()
            for filename, mutation in (
                ("effective.json", lambda value: value["jails"]["nextcloud"]["files"].pop("/usr/local/libexec/cloud-runtime-inventory.php")),
                ("effective.json", lambda value: value["jails"]["onlyoffice"]["files"].pop("/root/cloud-installer/installer/version_runtime.py")),
                ("effective.json", lambda value: value["jails"]["nextcloud"]["files"].update({"/root/cloud-installer/runtime.json": "f" * 64})),
                ("readiness.json", lambda value: value["nextcloud"].update(version="35.0.2.1")),
                ("readiness.json", lambda value: value["nextcloud"].update(maintenance=False)),
                ("review.json", lambda value: value["target_files"].update({"config.json": "f" * 64})),
                ("candidate.json", lambda value: value["packages"]["nextcloud"]["php85"].update(version="8.6.0"))):
                changed = deepcopy(self.evidence)
                document = json.loads(changed[filename])
                mutation(document)
                changed[filename] = _encode(document)
                with self.subTest(filename=filename), self.assertRaises(ValueError):
                    self.seal(validation_evidence=changed)
            self.assertFalse((self.root / "instances/cloud/generations" / self.generation).exists())

    def test_strict_successor_schema_and_corrupt_retained_refs(self):
        with self.registry.locked(recovery=True):
            self.begin()
            reference = self.seal()
            path = self.root / reference["path"]
            original = path.read_bytes()
            manifest = json.loads(original)
            for change in ({"schema_version": True}, {"schema_version": 1}, {"extra": True}, {"entity_id": "other"},
                           {"operation": "execution-other"}, {"predecessor": reference}, {"plugins": self.preparation},
                           {"originals": {**manifest["originals"], "config": manifest["config"]}}):
                atomic_json(path, {**manifest, **change})
                with self.subTest(change=change), self.assertRaises(ValueError):
                    self.store._generation("cloud", self.store.reference(reference["path"]))
            atomic_write(path, original.decode())
            target = self.root / manifest["runtime"]["nextcloud"]["runtime.json"]["path"]
            saved = target.read_bytes()
            atomic_json(target, {"forged": True})
            with self.assertRaises(ValueError):
                self.store._generation("cloud", reference)
            atomic_write(target, saved.decode())
            self.store._generation("cloud", reference)

    def test_original_deployment_journal_is_not_rebased_to_effective_config(self):
        with self.registry.locked(recovery=True):
            self.begin()
            reference = self.seal()
            self.commit(reference)
            self.native.finish(self.operation)
        path = self.root / "instances/cloud/deployment.json"
        journal = json.loads(self.initial_journal)
        journal["config_sha256"] = config_digest(Config.from_json(self.target["config.json"].decode()))
        atomic_json(path, journal)
        with self.assertRaises(ValueError):
            self.registry.load("cloud")
        atomic_write(path, self.initial_journal.decode())
        self.registry.load("cloud")

    def test_pending_graph_cannot_adopt_another_operations_successor(self):
        with self.registry.locked(recovery=True):
            self.begin()
            reference = self.seal()
            self.native.finish(self.operation, "cancelled")
            self.operation = "execution-other"
            self.native.begin(self.operation, "cloud", preparation=self.preparation, recipe=preflight.recipe())
            with self.assertRaises(ValueError):
                self.commit(reference)
            self.assertEqual(self.store._active(), self.base)

    def test_generic_status_commit_cannot_publish_a_successor(self):
        with self.registry.locked(recovery=True):
            self.begin()
            reference = self.seal()
            self.native.finish(self.operation, "cancelled")
            self.store.begin("status-other", "status", ["cloud"], self.executor["executor_sha256"])
            atomic_json(self.root / "instances/cloud/config.json", descriptor("cloud", reference))
            entries = deepcopy(self.entries)
            entries["cloud"]["generation"] = reference
            with self.assertRaisesRegex(ValueError, "native maintenance graph chain"):
                self.store.commit("bypass", entries, "status-other")
            self.assertEqual(self.store._active(), self.base)

    def test_partial_seal_retry_requires_identical_retained_bytes(self):
        with self.registry.locked(recovery=True):
            self.begin()
            write = self.native.store._write
            def interrupt(relative, data, **kwargs):
                if relative == f"instances/cloud/generations/{self.generation}/versions.json":
                    raise OSError("interrupted successor copy")
                return write(relative, data, **kwargs)
            with patch.object(self.native.store, "_write", side_effect=interrupt), self.assertRaises(OSError):
                self.seal()
            path = self.root / f"instances/cloud/generations/{self.generation}/config.json"
            inode = path.stat().st_ino
            altered = deepcopy(self.target)
            altered["config.json"] += b"\n"
            with self.assertRaises(ValueError):
                self.seal(target_files=altered, recover=True)
            reference = self.seal(recover=True)
            self.assertEqual(path.stat().st_ino, inode)
            self.assertEqual(self.seal(recover=True), reference)
            self.assertEqual(self.store._active(), self.base)

    def test_sealing_requires_global_lock_pending_owner_and_remains_non_executable(self):
        with self.registry.locked(recovery=True):
            self.begin()
        with self.assertRaises(ValueError):
            self.seal()
        from installer.maintenance_journal import REVIEWED_NATIVE_RECIPES, require_native_recipe
        self.assertEqual(REVIEWED_NATIVE_RECIPES, {})
        with self.assertRaises(ValueError):
            require_native_recipe({"recipe": preflight.RECIPE_ID})


if __name__ == "__main__":
    unittest.main()
