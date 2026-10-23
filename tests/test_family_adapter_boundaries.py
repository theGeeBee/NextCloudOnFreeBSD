"""Fresh-install families must not widen immutable inputs or upgrade authority."""

from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from installer import plugins, upgrade_packages
from installer.deploy import Deployment
from installer.versions import load_policy
from test_upgrade_packages import Target


class PluginFamilyBoundaries(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        owner = patch.object(plugins, "ROOT_UID", os.geteuid())
        owner.start()
        self.addCleanup(owner.stop)
        self.record = {"name": "Fixture", "guid": "asc.{11111111-1111-1111-1111-111111111111}",
                       "version": "1.0.0", "format": "files", "tree": {}, "artifacts": []}
        self.manifest = {"guid": self.record["guid"], "version": "1.0.0", "minVersion": "9.3.0"}

    def payload(self, **changes):
        manifest = dict(self.manifest, **changes)
        data = json.dumps(manifest).encode()
        digest = hashlib.sha256(data).hexdigest()
        record = deepcopy(self.record)
        record["tree"] = {"config.json": digest}
        record["artifacts"] = [{"path": "config.json", "size": len(data), "sha256": digest,
            "url": "https://raw.githubusercontent.com/ONLYOFFICE/onlyoffice.github.io/"
                   + "a" * 40 + "/sdkjs-plugins/content/fixture/config.json"}]
        catalog = {"schema": 1, "docs_version": "9.4.0", "source_commit": "a" * 40,
                   "plugins": {"fixture": record}}
        lock = plugins.make_lock("fixture", catalog)
        cache = self.base / "cache"
        plugins.prepare(lock, cache, lambda url: io.BytesIO(data))
        return lock, cache, catalog

    def test_future_patch_uses_manifest_without_rewriting_catalog_or_receipts(self):
        lock, cache, catalog = self.payload(minVersion="9.4.1")
        original = deepcopy(lock)
        with self.assertRaisesRegex(ValueError, "does not support"):
            plugins.check_payloads(lock, cache)
        plugins.check_payloads(lock, cache, docs_version="9.4.1")
        root, state = self.base / "plugins", self.base / "receipts"
        root.mkdir(mode=0o755)
        root.chmod(0o755)
        plugins.install(lock, cache, root, state, docs_version="9.4.1")
        plugins.verify(lock, root, state, docs_version="9.4.1")
        plugins.install(lock, cache, root, state, docs_version="9.4.1")
        with self.assertRaisesRegex(ValueError, "does not support"):
            plugins.verify(lock, root, state)
        self.assertEqual(lock, original)
        plugins.validate_lock(lock, "fixture", catalog)

    def test_manifest_minimum_and_explicit_maximum_are_enforced(self):
        for change in ({"minVersion": "9.4.2"}, {"maxVersion": "9.4.0"}):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "does not support"):
                plugins._manifest(json.dumps(dict(self.manifest, **change)), self.record, "9.4.1")
        for selected in ("9.5.0", "10.0.0", "9.4.1rc1", "9.4.1_2", "9.4.1,1"):
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                plugins._manifest(json.dumps(self.manifest), self.record, selected)

    def test_future_patch_does_not_relax_payload_hashes(self):
        lock, cache, _ = self.payload()
        (cache / "fixture/config.json").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "integrity"):
            plugins.check_payloads(lock, cache, docs_version="9.4.1")

    def deployment(self, version):
        deployment = object.__new__(Deployment)
        deployment.config = SimpleNamespace(instance="cloud", onlyoffice_plugins="zotero",
                                            onlyoffice_jail="cloudoo")
        deployment.state = self.base
        path = self.base / "plugins.json"
        path.touch(mode=0o600)
        deployment.registry = SimpleNamespace(evidence_path=lambda *args: path)
        deployment._versions = {"packages": {"onlyoffice": {
            "onlyoffice-documentserver": {"version": version}}}}
        return deployment

    def test_deploy_accepts_epoch_revision_and_future_patch_but_not_other_family(self):
        lock = plugins.make_lock("zotero")
        for version in ("9.4.0", "9.4.0,1", "9.4.0_4,1", "9.4.1_2,1"):
            deployment = self.deployment(version)
            with self.subTest(version=version), patch("installer.deploy.private_json", return_value=lock):
                self.assertEqual(deployment.plugin_lock, lock)
                with patch.object(plugins, "prepare"), patch.object(plugins, "check_payloads") as check:
                    deployment.prepare_plugins()
                check.assert_called_once_with(lock, self.base / "plugin-artifacts",
                                              docs_version=version.split("_", 1)[0].split(",", 1)[0])
                deployment.jail_root = lambda name: self.base
                deployment.jail = lambda *args: setattr(deployment, "command", args)
                deployment.plugin_command("install")
                index = deployment.command.index("--docs-version")
                self.assertEqual(deployment.command[index + 1],
                                 version.split("_", 1)[0].split(",", 1)[0])
                self.assertEqual(deployment._versions["packages"]["onlyoffice"]
                                 ["onlyoffice-documentserver"]["version"], version)
        with patch("installer.deploy.private_json", return_value=lock), self.assertRaises(ValueError):
            self.deployment("9.5.0").plugin_lock


class UpgradeFamilyBoundaries(unittest.TestCase):
    def widened_policy(self):
        policy = deepcopy(load_policy())
        profile = policy["profiles"][0]
        profile["applications"]["nextcloud"] = {"family": "35"}
        profile["applications"]["onlyoffice"] = {"family": "9.4"}
        profile["roles"]["onlyoffice"]["range"] = {"family": "9.4"}
        profile["roles"]["manager"]["range"] = {"family": "1.4"}
        profile["connector"]["version"] = {"family": "10.2"}
        return policy

    def test_fresh_policy_cannot_authorize_docs_patch_upgrade(self):
        target = Target()
        target.upgrade(target.office, "onlyoffice-documentserver", "9.4.1_1")
        with patch.object(upgrade_packages, "load_policy", self.widened_policy), \
                self.assertRaisesRegex(upgrade_packages.PackageUpgradeError, "Docs 9.4.0 only"):
            upgrade_packages.plan(target)
        self.assertFalse(any("upgrade" in call[1] and "-n" not in call[1] for call in target.calls))

    def test_native_docs_revisions_and_existing_php_database_patches_remain_allowed(self):
        target = Target()
        target.upgrade(target.office, "onlyoffice-documentserver", "9.4.0_5,1")
        target.upgrade(target.nc, "php85", "8.5.12")
        target.upgrade(target.nc, "mariadb123-server", "12.3.9")
        with patch.object(upgrade_packages, "load_policy", self.widened_policy):
            plan = upgrade_packages.plan(target)
        self.assertEqual(plan["status"], "changes-available")
        self.assertEqual(set(plan["jails"]), {"nextcloud", "onlyoffice"})

    def test_fresh_policy_cannot_authorize_new_nextcloud_upgrade_steps(self):
        for source, path in (("35.0.1", ("35.0.3",)), ("35.0.3", ("35.0.3",))):
            target = Target()
            target.source = source
            with self.subTest(source=source), patch.object(upgrade_packages, "load_policy", self.widened_policy), \
                    self.assertRaisesRegex(upgrade_packages.PackageUpgradeError, "reviewed NC35"):
                upgrade_packages.plan(target, nextcloud_path=path)

    def test_bastille_is_still_outside_application_dependency_closure(self):
        item = {"version": "1.4.5", "origin": "sysutils/bastille", "abi": "FreeBSD:15:amd64",
                "dependencies": {}}
        with self.assertRaisesRegex(upgrade_packages.PackageUpgradeError, "outside application upgrades"):
            upgrade_packages._closure({"bastille": item}, ["bastille"], "FreeBSD:15:amd64")
