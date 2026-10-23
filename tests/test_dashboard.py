"""Dashboard reads public retained state only; never touches host services."""

from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from installer.config import Config
from installer.dashboard import instance_names, render, snapshot
from installer.state import Registry, atomic_json, config_digest


class DashboardTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.registry = Registry(self.root / "registry")
        self.config = Config(public_hostname="cloud.example.test", admin_email="admin@example.test",
                             acme_email="admin@example.test", external_interface="igb0",
                             ingress_address="192.0.2.10", dns_server="192.0.2.53",
                             management_network="198.51.100.0/24")

    def register(self, name="cloud", state="ready"):
        self.registry.initialize()
        config = replace(self.config, instance=name)
        path = self.registry.save_new(config, {"password": "not-for-display"})
        self.registry.set_status(name, state)
        return path, config

    def test_missing_registry_does_not_create_or_lock_anything(self):
        with patch.object(self.registry, "initialize") as initialize, patch.object(self.registry, "locked") as locked:
            view = snapshot(self.registry)
        self.assertEqual(view["instances"], [])
        self.assertEqual(view["errors"], [])
        self.assertFalse(self.registry.root.exists())
        initialize.assert_not_called()
        locked.assert_not_called()
        self.assertIn("No registered instances", render(view))

    def test_dashboard_never_reads_credentials_or_claims_ready_is_healthy(self):
        path, _ = self.register()
        before = {p: p.read_bytes() for p in path.iterdir()}
        from installer import dashboard
        original = dashboard._read
        reads = []
        def read(path, **kwargs):
            reads.append(path.name)
            self.assertNotEqual(path.name, "secrets.json")
            return original(path, **kwargs)
        with patch.object(dashboard, "_read", side_effect=read):
            view = snapshot(self.registry)
        self.assertEqual(view["instances"][0]["state"], "ready")
        text = render(view, host_release="15.1-RELEASE-p1")
        self.assertIn("Host userland: 15.1-RELEASE-p1", text)
        self.assertIn("Live health: not checked", text)
        self.assertIn("unknown (historical)", text)
        self.assertIn("dedicated cloudoo", text)
        self.assertNotIn("not-for-display", text)
        self.assertEqual({p: p.read_bytes() for p in path.iterdir()}, before)
        self.assertFalse((self.registry.root / "operation.lock").exists())

    def test_timestamp_is_readiness_evidence_not_inventory_mtime(self):
        path, config = self.register()
        atomic_json(path / "deployment.json", {"schema_version": 2, "config_sha256": config_digest(config),
                    "steps": {"readiness checks": {"state": "complete", "completed": "2026-10-15T10:00:00Z"}}})
        atomic_json(path / "inventory.json", {"PRIVATE": "never-display-inventory-content"})
        view = snapshot(self.registry)
        self.assertEqual(view["instances"][0]["last_installation_check"], "2026-10-15T10:00:00+00:00")
        self.assertIn("historical", render(view))
        self.assertNotIn("PRIVATE", render(view))

    def test_pending_restore_and_failed_initialization_are_explicit(self):
        path, _ = self.register()
        atomic_json(path / "restore.json", {"state": "pending", "phase": "validated", "error": "secret-payload"})
        atomic_json(path / "initialization.json", {"state": "complete", "recoveries": [{"state": "failed"}]})
        row = snapshot(self.registry)["instances"][0]
        self.assertEqual(row["pending"], ["database restore", "initialization recovery"])
        self.assertNotIn("secret-payload", json.dumps(row))

    def test_pending_network_is_detected_without_mutation(self):
        self.registry.initialize()
        path = self.registry.root / "transactions/pending"
        path.mkdir(mode=0o700)
        atomic_json(path / "firewall-transition.json", {"instances": []})
        view = snapshot(self.registry)
        self.assertEqual(view["pending_network"], ["pending"])
        self.assertIn("unresolved network", render(view))
        self.assertFalse((self.registry.root / "operation.lock").exists())

    def test_broken_instance_remains_visible_beside_healthy_record(self):
        path, _ = self.register("cloud")
        self.register("other")
        atomic_json(path / "config.json", {"private": "do-not-echo"})
        view = snapshot(self.registry)
        self.assertEqual([row["state"] for row in view["instances"]], ["inspection-error", "ready"])
        self.assertNotIn("do-not-echo", render(view))

    def test_symlink_shared_hardlink_and_large_records_fail_closed(self):
        path, _ = self.register()
        status = path / "status.json"
        original = status.read_bytes()
        status.chmod(0o644)
        self.assertTrue(snapshot(self.registry)["instances"][0]["error"])
        status.chmod(0o600)
        link = self.root / "hardlink"
        os.link(status, link)
        self.assertTrue(snapshot(self.registry)["instances"][0]["error"])
        link.unlink()
        status.unlink()
        other = self.root / "private"
        other.write_bytes(original)
        other.chmod(0o600)
        status.symlink_to(other)
        self.assertTrue(snapshot(self.registry)["instances"][0]["error"])
        status.unlink()
        status.write_bytes(original)
        status.chmod(0o600)
        with patch("installer.dashboard.MAX_RECORD", 10):
            self.assertTrue(snapshot(self.registry)["instances"][0]["error"])

    def test_symlinked_instances_directory_and_foreign_entry_are_not_adopted(self):
        self.registry.root.mkdir(mode=0o700)
        (self.registry.root / "instances").symlink_to(self.root)
        self.assertTrue(snapshot(self.registry)["errors"])
        (self.registry.root / "instances").unlink()
        (self.registry.root / "instances").mkdir(mode=0o700)
        (self.registry.root / "instances/NOT-AN-INSTANCE").mkdir(mode=0o700)
        self.assertTrue(snapshot(self.registry)["errors"])

    def test_unpublished_registration_directory_is_not_an_instance(self):
        self.registry.initialize()
        (self.registry.root / "instances/.pending-incomplete").mkdir(mode=0o700)
        self.assertEqual(instance_names(self.registry), [])

    def test_mutating_status_is_reported_as_inconsistent(self):
        self.register()
        from installer import dashboard
        original = dashboard._read
        calls = 0
        def read(path, **kwargs):
            nonlocal calls
            value = original(path, **kwargs)
            if path.name == "status.json":
                calls += 1
                if calls == 2:
                    value = {**value, "state": "removing"}
            return value
        with patch.object(dashboard, "_read", side_effect=read):
            row = snapshot(self.registry)["instances"][0]
        self.assertEqual(row["state"], "inspection-error")

    def test_unknown_journal_schema_and_binding_do_not_claim_health(self):
        path, config = self.register()
        for schema, digest in ((99, config_digest(config)), (2, "wrong")):
            atomic_json(path / "deployment.json", {"schema_version": schema, "config_sha256": digest, "steps": {}})
            self.assertTrue(snapshot(self.registry)["instances"][0]["error"])


if __name__ == "__main__":
    unittest.main()
