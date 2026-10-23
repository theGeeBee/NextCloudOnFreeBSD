"""Offline update-report and cache boundaries; never provision or query a host."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from installer import discovery, lifecycle, resolution, updates, versions
from installer.state import Registry, atomic_json, atomic_write, config_digest
from test_state import configuration as state_configuration
from test_versions import catalog, change_version


def configuration(**changes):
    return state_configuration(accept_microsoft_fonts=True, **changes)


class UpdateReportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="updates-tests-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.registry = Registry(self.directory / "registry")
        self.registry.initialize()
        self.config = configuration()
        self.metadata = catalog(config=self.config)
        self.plan = resolution.resolve(self.config, self.metadata)
        self.source = patch("installer.deploy.source_digest", return_value="a" * 64 + "\n")
        self.source.start()
        self.addCleanup(self.source.stop)
        self.register(self.config)

    def register(self, config):
        path = self.registry.save_new(config, {"admin_password": "NEVER-READ-SECRET"})
        self.registry.set_status(config.instance, "ready")
        atomic_json(path / "versions.json", self.plan)
        atomic_write(path / "source.sha256", "a" * 64 + "\n")
        atomic_json(path / "deployment.json", {"schema_version": 2, "config_sha256": config_digest(config),
                                               "steps": {"installation": {"state": "complete"}}})
        return path

    @property
    def state(self):
        return self.registry.instance_path(self.config.instance)

    @property
    def cache(self):
        return self.registry.root / "update-reports" / (self.config.instance + ".json")

    def check(self, **kwargs):
        return updates.check_updates(self.registry, [self.config.instance], **kwargs)

    def refresh(self, **kwargs):
        with patch.object(discovery, "discover", return_value=deepcopy(self.metadata)):
            return self.check(refresh=True, **kwargs)

    def tree(self):
        return {str(path.relative_to(self.registry.root)): path.read_bytes()
                for path in self.registry.root.rglob("*") if path.is_file()}

    def test_requires_explicit_nonempty_distinct_names(self):
        for names in (None, [], "cloud", ["cloud", "cloud"], ["../cloud"], ["UPPER"], [2]):
            with self.subTest(names=names), self.assertRaises(ValueError):
                updates.check_updates(self.registry, names)

    def test_family_constraints_remain_bound_in_read_only_reports(self):
        self.registry = Registry(self.directory / "family-registry")
        self.registry.initialize()
        self.config = configuration(version_families={"nextcloud": "35", "php": "8.5"})
        self.metadata = catalog(config=self.config)
        self.plan = resolution.resolve(self.config, self.metadata)
        self.register(self.config)
        result = self.refresh(save_report=True)
        self.assertFalse(result["inspection_failed"])
        self.assertEqual(result["instances"][0]["constraints"]["version_families"], self.config.version_families)
        cached = self.check()
        self.assertFalse(cached["inspection_failed"])
        self.assertEqual(cached["instances"][0]["constraints"], self.plan["constraints"])
        self.assertFalse(cached["instances"][0]["execution_authorized"])

    def test_default_cache_miss_has_no_writes_locks_host_or_secret_reads(self):
        before = self.tree()
        read = updates._read
        def guarded(path):
            self.assertNotEqual(path.name, "secrets.json")
            return read(path)
        with patch.object(self.registry, "locked", side_effect=AssertionError("lock")), \
                patch.object(self.registry, "initialize", side_effect=AssertionError("initialize")), \
                patch.object(discovery, "discover", side_effect=AssertionError("discovery")), \
                patch("subprocess.run", side_effect=AssertionError("host execution")), \
                patch("socket.socket", side_effect=AssertionError("network")), \
                patch.object(updates, "_read", side_effect=guarded):
            result = self.check()
        item = result["instances"][0]
        self.assertEqual((item["status"], item["freshness"]), ("unknown", "missing"))
        self.assertFalse(result["inspection_failed"])
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["migration_supported"])
        self.assertIsNone(result["checked_at"])
        self.assertEqual(before, self.tree())
        self.assertNotIn("NEVER-READ-SECRET", json.dumps(result))

    def test_nonexistent_registry_is_never_initialized_even_with_save(self):
        registry = Registry(self.directory / "absent")
        with patch.object(registry, "locked", side_effect=AssertionError("lock")):
            result = updates.check_updates(registry, ["cloud"], refresh=True, save_report=True)
        self.assertTrue(result["inspection_failed"])
        self.assertFalse(registry.root.exists())

    def test_refresh_exposes_outside_policy_upstream_without_authorizing(self):
        before = self.tree()
        with patch.object(self.registry, "locked", side_effect=AssertionError("lock")), \
                patch.object(discovery, "probe_packages", side_effect=AssertionError("fresh solver")):
            result = self.refresh()
        item = result["instances"][0]
        self.assertEqual(item["status"], "available-unreviewed")
        self.assertEqual(item["upstream_newer"], {"nextcloud": ["35.0.2", "36.0.0"], "onlyoffice": ["10.0.0"]})
        self.assertEqual(item["installed_applications"], item["candidate_applications"])
        self.assertEqual(before, self.tree())
        self.assertEqual(item["freshness"], "fresh")
        self.assertFalse(result["inspection_failed"])

    def test_current_is_explicitly_within_constraints_not_security_health(self):
        self.metadata["nextcloud"] = ["35.0.1"]
        self.metadata["onlyoffice"] = ["9.4.0"]
        item = self.refresh()["instances"][0]
        self.assertEqual(item["status"], "current-within-reviewed-policy")
        self.assertTrue(any("configured minimum/exact pins" in text for text in item["warnings"]))
        self.assertTrue(any("security" in text for text in item["warnings"]))

    def test_explicit_pins_remain_effective_and_upstream_is_visible(self):
        config = configuration(nextcloud_exact="35.0.0", onlyoffice_exact="9.4.0_4")
        metadata = catalog(config=config)
        plan = resolution.resolve(config, metadata)
        atomic_json(self.state / "config.json", json.loads(config.to_json()))
        atomic_json(self.state / "versions.json", plan)
        atomic_json(self.state / "deployment.json", {"schema_version": 2, "config_sha256": config_digest(config),
                                                    "steps": {"installation": {"state": "complete"}}})
        item = self.refresh()["instances"][0]
        self.assertEqual(item["constraints"]["nextcloud_exact"], "35.0.0")
        self.assertEqual(item["candidate_applications"]["nextcloud"], "35.0.0")
        self.assertIn("36.0.0", item["upstream_newer"]["nextcloud"])

    def test_supported_destination_has_no_path_and_checksum_rebuild_is_blocked(self):
        change_version(self.metadata, "bastille", "1.4.4_2")
        item = self.refresh()["instances"][0]
        self.assertEqual(item["status"], "destination-supported-path-unavailable")
        self.assertFalse(item["execution_authorized"])
        change_version(self.metadata, "bastille", "1.4.4_1")
        self.metadata["packages"]["bastille"]["checksum"] = "2$" + "b" * 103
        item = self.refresh()["instances"][0]
        self.assertEqual(item["status"], "blocked")
        self.assertTrue(any("Same-version package checksum" in b for b in item["blockers"]))

    def test_no_compatible_destination_keeps_upstream_evidence(self):
        change_version(self.metadata, "onlyoffice-documentserver", "10.0.0")
        result = self.refresh()
        item = result["instances"][0]
        self.assertEqual(item["status"], "available-unreviewed")
        self.assertFalse(item["candidate_applications"])
        self.assertTrue(item["blockers"])
        self.assertFalse(result["inspection_failed"])

    def test_discovery_failure_never_current_and_diagnostics_do_not_leak(self):
        for error in (discovery.DiscoveryError("NEVER-READ-SECRET"), OSError("NEVER-READ-SECRET")):
            with self.subTest(error=error), patch.object(discovery, "discover", side_effect=error):
                result = self.check(refresh=True)
            self.assertTrue(result["inspection_failed"])
            self.assertEqual(result["instances"][0]["status"], "unknown")
            self.assertEqual(result["instances"][0]["errors"][0]["code"], "discovery-failed")
            self.assertNotIn("NEVER-READ-SECRET", json.dumps(result))

    def test_incomplete_discovered_metadata_is_failed_inspection(self):
        for field in ("packages", "connectors", "nextcloud"):
            metadata = deepcopy(self.metadata)
            metadata.pop(field)
            with self.subTest(field=field), patch.object(discovery, "discover", return_value=metadata):
                result = self.check(refresh=True)
            self.assertTrue(result["inspection_failed"])
            self.assertEqual(result["instances"][0]["status"], "unknown")

    def test_corrupt_or_missing_historical_lock_is_not_reconstructed(self):
        self.state.joinpath("versions.json").unlink()
        with patch.object(discovery, "discover", side_effect=AssertionError("no discovery")):
            self.assertTrue(self.check(refresh=True)["inspection_failed"])
        for value in ({"applications": self.plan["applications"]}, {**self.plan, "policy_sha256": "missing"}):
            atomic_json(self.state / "versions.json", value)
            result = self.check()
            self.assertTrue(result["inspection_failed"])
            self.assertEqual(result["instances"][0]["status"], "unknown")

    def test_historical_policy_mismatch_is_structural_only_and_disclosed(self):
        old = deepcopy(self.plan)
        old["policy_sha256"] = "b" * 64
        atomic_json(self.state / "versions.json", old)
        with patch.object(resolution, "validate_plan", side_effect=AssertionError("must not validate historical policy")):
            result = self.refresh()
        item = result["instances"][0]
        self.assertFalse(result["inspection_failed"])
        self.assertEqual(item["installed_applications"], old["applications"])
        self.assertFalse(item["provenance"]["original_policy_available"])
        self.assertTrue(any("Original policy provenance is unavailable" in w for w in item["warnings"]))
        with self.assertRaisesRegex(ValueError, "policy changed"):
            resolution.validate_plan(self.config, old)

    def test_current_config_reader_rejection_is_explicitly_unsupported(self):
        value = json.loads(self.config.to_json())
        value["freebsd_release"] = "14.3-RELEASE"
        atomic_json(self.state / "config.json", value)
        result = self.refresh()
        self.assertTrue(result["inspection_failed"])
        self.assertIn("Unsupported inspection", result["instances"][0]["errors"][0]["message"])

    def test_save_is_private_separate_cache_and_default_reads_it_without_lock(self):
        before = self.tree()
        result = self.refresh(save_report=True)
        self.assertFalse(result["inspection_failed"], result)
        self.assertTrue(result["instances"][0]["saved"])
        self.assertEqual(self.cache.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.cache.parent.stat().st_mode & 0o777, 0o700)
        after = self.tree()
        self.assertTrue(all(after[path] == data for path, data in before.items()))
        with patch.object(discovery, "discover", side_effect=AssertionError("discovery")), \
                patch.object(self.registry, "locked", side_effect=AssertionError("lock")):
            cached = self.check()
        self.assertEqual(cached["instances"][0]["status"], "available-unreviewed")
        self.assertEqual(cached["instances"][0]["freshness"], "fresh")
        self.assertEqual(after, self.tree())

    def test_saved_discovery_failure_remains_failed_on_cache_read(self):
        with patch.object(discovery, "discover", side_effect=discovery.DiscoveryError("offline")):
            result = self.check(refresh=True, save_report=True)
        self.assertTrue(result["instances"][0]["saved"], result)
        cached = self.check()
        self.assertTrue(cached["inspection_failed"])
        self.assertEqual(cached["instances"][0]["status"], "unknown")

    def test_api_save_requires_refresh_even_with_valid_cache_without_reads_or_writes(self):
        self.refresh(save_report=True)
        before = self.tree()
        with patch.object(updates, "_context", side_effect=AssertionError("evidence read")), \
                patch.object(discovery, "discover", side_effect=AssertionError("discovery")), \
                patch.object(self.registry, "locked", side_effect=AssertionError("lock")):
            with self.assertRaisesRegex(ValueError, "requires explicit refresh"):
                self.check(save_report=True)
        self.assertEqual(self.tree(), before)

    def test_all_bindings_and_age_make_saved_result_stale(self):
        self.refresh(save_report=True)
        original = json.loads(self.cache.read_text())
        for field in sorted(updates.BINDINGS):
            value = deepcopy(original)
            value["report"]["bindings"][field] = "b" * 64
            atomic_json(self.cache, value)
            with self.subTest(field=field):
                result = self.check()["instances"][0]
                self.assertEqual(result["freshness"], "stale")
                self.assertIn(field, result["stale_reasons"])
        value = deepcopy(original)
        value["report"]["checked_at"] = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
        atomic_json(self.cache, value)
        result = self.check()["instances"][0]
        self.assertEqual(result["freshness"], "stale")
        self.assertIn("older-than-24-hours", result["stale_reasons"])

    def test_actual_status_source_policy_and_lock_changes_make_cache_stale(self):
        self.refresh(save_report=True)
        self.registry.set_status(self.config.instance, "failed")
        atomic_write(self.state / "source.sha256", "b" * 64 + "\n")
        old = deepcopy(self.plan)
        old["policy_sha256"] = "b" * 64
        atomic_json(self.state / "versions.json", old)
        policy = versions.load_policy()
        policy["defaults"]["nextcloud_min"] = "35.0.1"
        with patch.object(versions, "load_policy", return_value=policy), \
                patch("installer.deploy.source_digest", return_value="c" * 64 + "\n"):
            item = self.check()["instances"][0]
        self.assertEqual(item["freshness"], "stale")
        self.assertTrue({"status_sha256", "source_sha256", "versions_sha256", "policy_sha256",
                         "inspector_source_sha256"}.issubset(item["stale_reasons"]))

    def test_changed_valid_config_and_matching_journal_make_cache_stale(self):
        self.refresh(save_report=True)
        config = configuration(admin_email="changed@example.test")
        atomic_json(self.state / "config.json", json.loads(config.to_json()))
        atomic_json(self.state / "deployment.json", {"schema_version": 2, "config_sha256": config_digest(config),
                                                    "steps": {"installation": {"state": "complete"}}})
        result = self.check()
        self.assertFalse(result["inspection_failed"])
        self.assertEqual(result["instances"][0]["freshness"], "stale")
        self.assertIn("config_sha256", result["instances"][0]["stale_reasons"])

    def test_save_refuses_corrupt_completed_restore_and_journals(self):
        for name, record in (("restore.json", {"state": "complete"}),
                             ("removal.json", {"steps": {"remove": {"state": "complete"}}})):
            with self.subTest(name=name):
                atomic_json(self.state / name, record)
                try:
                    result = self.refresh(save_report=True)
                    self.assertTrue(result["inspection_failed"])
                    self.assertFalse(self.cache.exists())
                finally:
                    (self.state / name).unlink()

    def test_historical_cache_keeps_null_graph_binding_without_implicit_write(self):
        self.refresh(save_report=True)
        value = json.loads(self.cache.read_text())
        value["schema_version"] = 1
        value["report"]["bindings"].pop("lifecycle_sha256")
        atomic_json(self.cache, value)
        before = self.cache.read_bytes()
        self.assertFalse(self.check()["inspection_failed"])
        self.assertEqual(self.cache.read_bytes(), before)
        for report in (None, [], "invalid"):
            atomic_json(self.cache, {"schema_version": 1, "report": report})
            self.assertTrue(self.check()["inspection_failed"])

    def test_corrupt_incomplete_or_future_cache_is_an_error(self):
        self.refresh(save_report=True)
        original = json.loads(self.cache.read_text())
        for mutate in (lambda v: v.update(schema_version=3),
                       lambda v: v["report"].pop("bindings"),
                       lambda v: v["report"].update(execution_authorized=True),
                       lambda v: v["report"].update(status="reviewed-path-available"),
                       lambda v: v.update(generated_at="2099-01-01T00:00:00+00:00")):
            value = deepcopy(original)
            mutate(value)
            atomic_json(self.cache, value)
            with self.subTest(mutate=mutate):
                self.assertTrue(self.check()["inspection_failed"])
        atomic_write(self.cache, '{"schema_version": 1, "schema_version": 1}')
        self.assertTrue(self.check()["inspection_failed"])

    def test_malformed_cached_packages_are_isolated_per_instance(self):
        self.register(configuration(instance="other"))
        with patch.object(discovery, "discover", return_value=deepcopy(self.metadata)):
            saved = updates.check_updates(self.registry, ["cloud", "other"], refresh=True, save_report=True)
        self.assertFalse(saved["inspection_failed"])
        original = json.loads(self.cache.read_text())
        for group in ("installed", "candidate"):
            for package in (None, [], ["package"], {}, {"abi": None},
                            {**self.plan["packages"]["host"]["bastille"], "abi": None},
                            {**self.plan["packages"]["host"]["bastille"], "abi": []}):
                value = deepcopy(original)
                inventory = value["report"]["shared_prerequisites"][group]
                inventory[next(iter(inventory))] = package
                atomic_json(self.cache, value)
                before = self.tree()
                with self.subTest(group=group, package=package), \
                        patch.object(discovery, "discover", side_effect=AssertionError("discovery")), \
                        patch.object(self.registry, "locked", side_effect=AssertionError("lock")):
                    result = updates.check_updates(self.registry, ["cloud", "other"])
                    self.assertTrue(result["inspection_failed"])
                    self.assertEqual(result["instances"][0]["status"], "unknown")
                    self.assertEqual(result["instances"][0]["errors"][0]["code"], "inspection-failed")
                    self.assertEqual(result["instances"][1]["status"], "available-unreviewed")
                    self.assertFalse(result["instances"][1]["errors"])
                    self.assertEqual(self.tree(), before)

    def test_private_evidence_permissions_links_owner_and_size_are_validated(self):
        self.refresh(save_report=True)
        for path in (self.cache, self.state / "versions.json", self.state / "config.json"):
            original = path.read_bytes()
            with self.subTest(path=path):
                path.chmod(0o644)
                self.assertTrue(self.check()["inspection_failed"])
                path.chmod(0o600)
                link = path.with_suffix(".link")
                os.link(path, link)
                self.assertTrue(self.check()["inspection_failed"])
                link.unlink()
                path.rename(link)
                path.symlink_to(link)
                self.assertTrue(self.check()["inspection_failed"])
                path.unlink()
                link.rename(path)
                with patch.object(updates, "MAX_BYTES", 1):
                    self.assertTrue(self.check()["inspection_failed"])
                self.assertEqual(path.read_bytes(), original)
        with patch.object(updates.os, "geteuid", return_value=os.geteuid() + 1):
            self.assertTrue(self.check()["inspection_failed"])
        self.cache.parent.chmod(0o755)
        self.assertTrue(self.check()["inspection_failed"])

    def test_race_during_discovery_is_failed_and_not_saved(self):
        def discover(*args, **kwargs):
            self.registry.set_status(self.config.instance, "installing")
            return self.metadata
        with patch.object(discovery, "discover", side_effect=discover), \
                patch.object(self.registry, "locked", side_effect=AssertionError("must fail before lock")):
            result = self.check(refresh=True, save_report=True)
        self.assertTrue(result["inspection_failed"])
        self.assertTrue(any("changed during" in e["message"] for e in result["instances"][0]["errors"]))
        self.assertFalse(self.cache.exists())

    def test_save_revalidates_inside_short_lock_after_discovery(self):
        from contextlib import contextmanager
        called = []
        def discover(*args, **kwargs):
            called.append("discovery")
            return self.metadata
        @contextmanager
        def locked():
            self.assertEqual(called, ["discovery"])
            called.append("lock")
            atomic_write(self.state / "source.sha256", "b" * 64 + "\n")
            yield
        with patch.object(discovery, "discover", side_effect=discover), patch.object(self.registry, "locked", locked):
            result = self.check(refresh=True, save_report=True)
        self.assertTrue(result["inspection_failed"])
        self.assertIn("bindings changed", result["instances"][0]["errors"][-1]["message"])
        self.assertFalse(self.cache.exists())

    def test_save_refuses_pending_network_restore_removal_and_installation(self):
        for pending in ("network", "restore", "removal", "installation"):
            with self.subTest(pending=pending):
                if pending == "network":
                    transaction = self.registry.root / "transactions/one"
                    transaction.mkdir(mode=0o700)
                    atomic_json(transaction / "firewall-transition.json", {})
                    cleanup = lambda: (transaction.joinpath("firewall-transition.json").unlink(), transaction.rmdir())
                elif pending == "restore":
                    atomic_json(self.state / "restore.json", {"state": "pending"})
                    cleanup = lambda: self.state.joinpath("restore.json").unlink()
                elif pending == "removal":
                    atomic_json(self.state / "removal.json", {"steps": {"remove": {"state": "running"}}})
                    cleanup = lambda: self.state.joinpath("removal.json").unlink()
                else:
                    self.registry.set_status(self.config.instance, "installing")
                    cleanup = lambda: self.registry.set_status(self.config.instance, "ready")
                try:
                    with patch.object(self.registry, "locked", side_effect=AssertionError("preflight rejects")):
                        result = self.refresh(save_report=True)
                    self.assertTrue(result["inspection_failed"])
                    self.assertFalse(self.cache.exists())
                finally:
                    cleanup()

    def removed_failed_install(self):
        config = configuration(instance="old")
        state = self.register(config)
        self.registry.set_status(config.instance, "failed")
        atomic_json(state / "deployment.json", {"schema_version": 2, "config_sha256": config_digest(config),
                                               "steps": {"installation": {"state": "failed"}}})
        before = (state / "deployment.json").read_bytes()
        runner = Mock()
        runner.run.return_value = SimpleNamespace(returncode=1, stdout="")
        deployment = SimpleNamespace(config=config, state=state, registry=self.registry, runner=runner, progress=Mock())
        # Exercise supported removal with mocked absent jail/bridge resources;
        # it publishes the real removal journal, tombstone and terminal status.
        with patch.object(lifecycle, "_checked_jails", return_value=[]), \
                patch.object(lifecycle, "_check_network_allocations"):
            lifecycle.remove_instance(deployment, confirmation="REMOVE old")
        self.assertEqual(json.loads((state / "status.json").read_text())["state"], "removed")
        self.assertEqual((state / "deployment.json").read_bytes(), before)
        return config, state

    def test_successful_removal_supersedes_failed_install_for_unrelated_save(self):
        _, state = self.removed_failed_install()
        before = {path.name: path.read_bytes() for path in state.iterdir()}
        result = self.refresh(save_report=True)
        self.assertFalse(result["inspection_failed"], result)
        self.assertTrue(result["instances"][0]["saved"])
        self.assertEqual({path.name: path.read_bytes() for path in state.iterdir()}, before)

    def test_removed_install_with_pending_purge_still_blocks_save(self):
        config, state = self.removed_failed_install()
        atomic_json(state / "purge.json", {"schema_version": 2, "config_sha256": config_digest(config),
                                          "runtime_already_removed": True,
                                          "steps": {"permanently destroy instance data and snapshots": {"state": "failed"}}})
        before = self.tree()
        result = self.refresh(save_report=True)
        self.assertTrue(result["inspection_failed"])
        self.assertFalse(self.cache.exists())
        self.assertEqual(self.tree(), before)

    def test_removed_status_without_valid_runtime_evidence_cannot_supersede_failure(self):
        _, state = self.removed_failed_install()
        for name in ("removed.json", "removal.json"):
            original = (state / name).read_text()
            atomic_json(state / name, {})
            with self.subTest(name=name):
                result = self.refresh(save_report=True)
                self.assertTrue(result["inspection_failed"])
                self.assertFalse(self.cache.exists())
            atomic_write(state / name, original)

    def test_pending_initialization_recovery_blocks_save_until_completed(self):
        record = {"schema_version": 1, "instance": self.config.instance,
                  "config_sha256": config_digest(self.config), "state": "complete",
                  "recoveries": [{"state": "failed"}]}
        for state in ("running", "failed"):
            record["recoveries"][-1]["state"] = state
            atomic_json(self.state / "initialization.json", record)
            with self.subTest(state=state):
                self.assertTrue(self.refresh(save_report=True)["inspection_failed"])
                self.assertFalse(self.cache.exists())
        record["recoveries"].append({"state": "complete"})
        atomic_json(self.state / "initialization.json", record)
        self.assertFalse(self.refresh(save_report=True)["inspection_failed"])

    def test_multiple_instances_keep_errors_and_host_summary_is_selected_only(self):
        other = configuration(instance="other")
        self.register(other)
        self.register(configuration(instance="unused"))
        def discover(config, *args, **kwargs):
            if config.instance == "other":
                raise discovery.DiscoveryError("unavailable")
            return self.metadata
        with patch.object(discovery, "discover", side_effect=discover):
            result = updates.check_updates(self.registry, ["cloud", "other"], refresh=True)
        self.assertTrue(result["inspection_failed"])
        self.assertEqual([r["status"] for r in result["instances"]], ["available-unreviewed", "unknown"])
        host = result["host"]
        self.assertEqual(host["selected_instances"], ["cloud", "other"])
        self.assertEqual(host["os_update_health"], "not-assessed")
        self.assertEqual({r["name"] for r in host["prerequisites"]}, set(self.plan["packages"]["host"]))
        self.assertNotIn("unused", json.dumps(result))

    def test_explicit_native_refresh_uses_disposable_catalog_not_registry(self):
        runner = Mock()
        runner.run.return_value.returncode = 0
        packages = self.metadata["packages"]
        records = "\n".join("|".join((p["name"], p["version"], p["origin"], p["abi"],
                                       str(len(p["dependencies"])), p["checksum"])) for p in packages.values())
        dependencies = "\n".join("|".join((p["name"], name, d["version"], d["origin"]))
                                 for p in packages.values() for name, d in p["dependencies"].items())
        temporary_paths = []
        def output(*args):
            native = {("uname", "-s"): "FreeBSD", ("uname", "-m"): "amd64", ("uname", "-U"): "1501000",
                      ("freebsd-version", "-r"): "15.1-RELEASE", ("freebsd-version", "-u"): "15.1-RELEASE"}
            if args in native:
                return native[args]
            db = next(arg.split("=", 1)[1] for arg in args if arg.startswith("PKG_DBDIR="))
            temporary_paths.append(Path(db).parent)
            self.assertFalse(Path(db).is_relative_to(self.registry.root))
            self.assertTrue(Path(db).exists())
            return dependencies if args[-1] == "%n|%dn|%dv|%do" else records
        runner.output.side_effect = output
        responses = {discovery.NEXTCLOUD_RELEASES: '<a href="nextcloud-35.0.1.tar.bz2">release</a><a href="nextcloud-35.0.1.tar.bz2.asc">sig</a>',
                     discovery.ONLYOFFICE_RELEASES: json.dumps([{"tag_name": "v9.4.0", "prerelease": False, "draft": False}]),
                     discovery.CONNECTORS.format(version="35.0.1"): json.dumps([{
                         "id": "onlyoffice", "certificate": "fixture-certificate",
                         "releases": self.metadata["connectors"]["35.0.1"]}])}
        original = discovery.discover
        with patch.object(discovery, "discover", side_effect=lambda config, runner, **kwargs:
                          original(config, runner, fetch=responses.__getitem__, **kwargs)):
            result = self.check(refresh=True, runner=runner)
        self.assertFalse(result["inspection_failed"], result)
        self.assertEqual(result["instances"][0]["status"], "current-within-reviewed-policy")
        self.assertTrue(temporary_paths)
        self.assertTrue(all(not p.exists() for p in temporary_paths))
        self.assertTrue(any("update" in call.args for call in runner.run.call_args_list))
        self.assertFalse(any("install" in call.args for call in runner.run.call_args_list))


if __name__ == "__main__":
    unittest.main()
