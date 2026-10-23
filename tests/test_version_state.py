"""Version-lock integration and historical state boundaries, entirely offline."""

from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from installer.config import Config
from installer import versions
from installer.deploy import Deployment
from installer.state import Registry, atomic_json, private_json
from test_versions import catalog


class VersionStateTests(unittest.TestCase):
    def test_historical_target_is_explicit_and_not_the_future_default(self):
        policy = versions.load_policy()
        future = deepcopy(policy["targets"][0])
        future.update(release="16.0-RELEASE", abi="FreeBSD:16:amd64")
        policy["targets"].append(future)
        policy["defaults"]["freebsd_release"] = "16.0-RELEASE"
        old = Config()
        old._legacy_target = policy["legacy_target"]
        with patch("installer.versions.load_policy", return_value=policy):
            self.assertEqual(old.release, "15.1-RELEASE")
            self.assertEqual(versions.constraints(old, policy)["freebsd_release"], old.release)
            self.assertEqual(Config().release, "16.0-RELEASE")


class ResolutionBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.registry = Registry(Path(self.temporary.name) / "state")
        self.registry.initialize()
        self.config = Config(public_hostname="cloud.example.test", admin_email="admin@example.test",
                             external_interface="igb0", ingress_address="192.0.2.10", dns_server="192.0.2.53",
                             management_network="198.51.100.0/24", tls_mode="external",
                             proxy_networks="203.0.113.2/32", font_profile="standard", accept_microsoft_fonts=True)
        self.state = self.registry.save_new(self.config, {})
        self.runner = Mock()
        self.runner.run.return_value = SimpleNamespace(returncode=1, stdout="")
        self.deployment = Deployment(self.config, {}, self.runner, registry=self.registry)
        self.discovery = patch("installer.discovery.discover", return_value=catalog(config=self.config)).start()
        self.probe = patch("installer.discovery.probe_packages").start()
        self.addCleanup(patch.stopall)

    def test_selection_is_saved_once_and_resume_never_rediscovers(self):
        selected = self.deployment.prepare_versions()
        self.assertEqual(private_json(self.state / "versions.json"), selected)
        self.discovery.assert_called_once()
        self.discovery.side_effect = AssertionError("Resume must not select newer versions")
        resumed = Deployment(self.config, {}, self.runner, registry=self.registry)
        self.assertEqual(resumed.prepare_versions(), selected)
        self.assertEqual(self.probe.call_count, 2)  # Same lock, live availability/solver recheck.
        self.assertTrue(all(call.args[:2] == ("pkg", "query") for call in self.runner.run.call_args_list))

    def test_old_deployment_without_lock_is_not_adopted(self):
        atomic_json(self.state / "deployment.json", {"steps": {}})
        with self.assertRaisesRegex(ValueError, "original artifact"):
            self.deployment.prepare_versions()
        self.discovery.assert_not_called()
        self.probe.assert_not_called()
        self.runner.run.assert_not_called()

    def test_solver_rejection_precedes_any_provisioning_or_lock_publication(self):
        self.probe.side_effect = ValueError("dependency conflict")
        with patch.object(self.deployment, "create_shared_storage") as storage, \
                patch.object(self.deployment, "configure_network") as network, \
                self.assertRaisesRegex(ValueError, "dependency conflict"):
            self.deployment.apply()
        storage.assert_not_called()
        network.assert_not_called()
        self.assertFalse((self.state / "versions.json").exists())
        self.assertFalse((self.state / "source.sha256").exists())
        self.assertEqual(private_json(self.state / "status.json")["state"], "configured")

    def test_shared_host_package_upgrade_or_origin_change_is_rejected_before_apply(self):
        for identity in ("1.4.5|sysutils/bastille", "1.4.4_1|foreign/bastille"):
            self.runner.run.return_value = SimpleNamespace(returncode=0, stdout=identity)
            with self.subTest(identity=identity), self.assertRaisesRegex(ValueError, "host maintenance"):
                self.deployment.prepare_versions()
            self.assertFalse((self.state / "versions.json").exists())

    def test_changed_constraints_cannot_reuse_an_existing_lock(self):
        self.deployment.prepare_versions()
        changed = Deployment(replace(self.config, nextcloud_min="35.0.1"), {}, self.runner, registry=self.registry)
        self.probe.reset_mock()
        with self.assertRaisesRegex(ValueError, "constraints"):
            changed.prepare_versions()
        self.probe.assert_not_called()
