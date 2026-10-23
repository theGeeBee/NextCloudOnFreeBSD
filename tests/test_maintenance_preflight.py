"""Synthetic trusted captures: offline compatibility, never native acceptance."""

from copy import deepcopy
import json
import unittest
from unittest.mock import patch

from installer import maintenance_preflight as preflight
from installer import resolution
from installer.config import Config
from installer.versions import policy_hash
from version_fixtures import historic_policy as load_policy, historical_maintenance_policy, resolved_plan


def inputs():
    config = Config(accept_microsoft_fonts=True, public_hostname="cloud.example.test",
                    admin_email="admin@example.test", acme_email="admin@example.test",
                    external_interface="igb0", ingress_address="192.0.2.10",
                    dns_server="192.0.2.53", management_network="198.51.100.0/24")
    with historical_maintenance_policy():
        retained = resolved_plan(config, nextcloud="35.0.1")
    bindings = {key: "a" * 64 for key in preflight.BINDING_FIELDS}
    bindings.update(config_sha256=preflight.digest(json.loads(config.to_json())),
                    versions_sha256=preflight.digest(retained))
    modules = preflight.required_modules()
    observations = {
        "schema_version": 1, "captured_at": 1000, "bindings": deepcopy(bindings),
        "packages": {group: [{key: item[key] for key in ("name", "version", "origin")}
                             for item in packages.values()]
                     for group, packages in retained["packages"].items()},
        "php": {context: {"version": "8.5.11", "integer_size": 8,
                          "sapi": "cli" if context == "cli" else "fpm-fcgi",
                          "loaded_modules": list(modules)} for context in preflight.PHP_CONTEXTS},
        "database": {"vendor": "MariaDB", "version": "12.3.3", "isolation": "READ-COMMITTED", "engines": ["InnoDB"]},
        "nextcloud": {"installed": True, "maintenance": False, "needsDbUpgrade": False,
                      "version": "35.0.1.1", "versionstring": "35.0.1",
                      "apps": {"onlyoffice": {"version": "10.2.1", "enabled": True, "provenance": "appstore", "artifact_sha256": "d" * 64},
                               "serverinfo": {"version": "7.0.0", "enabled": True, "provenance": "shipped"}}},
        "integrations": {"external_storage": False, "unmanaged_integrations": False},
    }
    packages = {name: deepcopy(item) for group in retained["packages"].values() for name, item in group.items()}
    repository = {
        "schema_version": 1, "captured_at": 1000, "bindings": deepcopy(bindings),
        "target": deepcopy(retained["target"]), "repository": config.repository,
        "catalog_sha256": "b" * 64, "trust": "native-pkg-signed-catalog", "packages": packages,
        "available_packages": {name: item["checksum"] for name, item in packages.items()},
        "artifacts": {
            "nextcloud": {"version": "35.0.2", "internal_version": "35.0.2.2", "sha256": "c" * 64,
                          "available_sha256": "c" * 64, "provenance": "authenticated-release"},
            "connector": {"version": "10.2.1", "sha256": "d" * 64, "available_sha256": "d" * 64,
                          "provenance": "appstore-sha512-signature"}},
        "apps": {
            "onlyoffice": {"source_version": "10.2.1", "version": "10.2.1", "delivery": "retained",
                           "phpVersionSpec": ">=8.2.0 <8.6.0", "platformVersionSpec": ">=33.0.0 <36.0.0", "artifact_sha256": "d" * 64},
            "serverinfo": {"source_version": "7.0.0", "version": "7.0.0", "delivery": "shipped",
                           "phpVersionSpec": ">=8.3.0 <8.6.0", "platformVersionSpec": ">=35.0.0 <36.0.0", "artifact_sha256": "c" * 64}},
        "package_transaction": [], "solver_receipt": None,
    }
    return config, retained, observations, repository, bindings


class MaintenancePreflightTests(unittest.TestCase):
    def test_original_vendor_build_labels_do_not_allow_prerelease_targets(self):
        self.observed['nextcloud']['apps']['files'] = dict(version='3.0.0-dev.0', enabled=True, provenance='shipped')
        self.repository['apps']['files'] = dict(source_version='3.0.0-dev.0', version='3.0.0', delivery='shipped',
            phpVersionSpec='>=8.3.0 <8.6.0', platformVersionSpec='>=35.0.0 <36.0.0', artifact_sha256='c'*64)
        self.assertTrue(self.assess()['eligible'])
        self.repository['apps']['files']['version'] = '3.0.0-dev.0'
        self.assertFalse(self.assess()['eligible'])
        self.repository['apps']['files']['version'] = '3.0.0'
        self.observed['nextcloud']['apps']['files']['version'] = '3.0.0-dev.1'
        self.repository['apps']['files']['source_version'] = '3.0.0-dev.1'
        self.assertFalse(self.assess()['eligible'])

    def test_build_label_reader_is_exact_and_source_only(self):
        self.assertEqual(len(preflight.SOURCE_SHIPPED_BUILD_LABELS), 31)
        for name, value in preflight.SOURCE_SHIPPED_BUILD_LABELS.items():
            self.assertTrue(preflight.source_app_label(name, value))
        for name, value in (('unknown', '3.0.0-dev.0'), ('files', '3.0.0-beta.0'),
                            ('dav', '2.0.0-dev.0'), ('onlyoffice', '10.2.1-dev.0')):
            self.assertFalse(preflight.source_app_label(name, value))

    def test_fpm_cgi_marker_does_not_relax_cli_or_module_requirements(self):
        for kind in ('main_fpm', 'callback_fpm'):
            value = self.observed['php'][kind]
            value['loaded_modules'] = sorted(value['loaded_modules'] + ['cgi-fcgi'])
        self.assertTrue(self.assess()['eligible'])
        value = self.observed['php']['cli']
        value['loaded_modules'] = sorted(value['loaded_modules'] + ['cgi-fcgi'])
        self.assertFalse(self.assess()['eligible'])
        value['loaded_modules'].remove('cgi-fcgi')
        self.observed['php']['main_fpm']['loaded_modules'].append('unexpectedmodule')
        self.assertFalse(self.assess()['eligible'])

    def setUp(self):
        self.enterContext(historical_maintenance_policy())
        self.config, self.retained, self.observed, self.repository, self.bindings = inputs()

    def assess(self, **kwargs):
        return preflight.assess(self.config, self.retained, self.observed, self.repository,
                                bindings=self.bindings, now=kwargs.pop("now", 1010), **kwargs)

    def blocked(self, code=None, **kwargs):
        report = self.assess(**kwargs)
        self.assertFalse(report["eligible"], report)
        self.assertFalse(report["execution_authorized"])
        self.assertIsNone(report["candidate"])
        self.assertEqual(report["blockers"], sorted(set(report["blockers"])))
        if code:
            self.assertIn(code, report["blockers"])
        return report

    def test_exact_candidate_is_staging_only_and_inputs_are_unchanged(self):
        before = deepcopy((self.retained, self.observed, self.repository, self.bindings))
        report = self.assess()
        self.assertTrue(report["eligible"], report)
        self.assertEqual(report["status"], "staging-only")
        self.assertFalse(report["execution_authorized"])
        self.assertEqual(report["execution_blockers"], ["native-recipe-unaccepted"])
        candidate = report["candidate"]
        self.assertFalse(candidate["execution_authorized"])
        self.assertFalse(candidate["recipe"]["execution_authorized"])
        self.assertEqual(candidate["recipe"]["destination"]["internal"], "35.0.2.2")
        self.assertEqual(candidate["packages"], self.retained["packages"])
        self.assertEqual(candidate["package_transaction"], [])
        self.assertEqual(before, (self.retained, self.observed, self.repository, self.bindings))
        self.assertEqual(preflight.revalidate(candidate, self.config, self.retained, self.observed,
                         self.repository, bindings=self.bindings, now=1020), report)

    def test_installation_policy_is_not_widened(self):
        before = policy_hash(load_policy())
        self.assess()
        self.assertEqual(policy_hash(load_policy()), before)
        self.assertEqual(load_policy()["profiles"][0]["applications"]["nextcloud"]["max_exclusive"], "35.0.2")
        changed = deepcopy(self.retained)
        changed["applications"]["nextcloud"] = "35.0.2"
        with self.assertRaises(ValueError):
            resolution.validate_plan(self.config, changed)

    def test_unreviewed_target_and_source_are_blocked(self):
        for target in ("35.0.3", "36.0.0", "35.0.2rc1", None):
            with self.subTest(target=target):
                self.blocked("unreviewed-destination", target=target)
        self.retained["applications"]["nextcloud"] = "35.0.0"
        self.blocked("source-plan-incompatible")

    def test_exact_source_pin_allows_only_reviewed_non_executable_proposal(self):
        self.config.nextcloud_exact = "35.0.1"
        self.retained = resolved_plan(self.config, nextcloud="35.0.1")
        self.bindings.update(config_sha256=preflight.digest(json.loads(self.config.to_json())),
                             versions_sha256=preflight.digest(self.retained))
        self.observed["bindings"] = deepcopy(self.bindings)
        self.repository["bindings"] = deepcopy(self.bindings)
        before = self.config.to_json(), deepcopy(self.retained), load_policy()
        result = self.assess()
        self.assertTrue(result["eligible"], result)
        self.assertFalse(result["execution_authorized"])
        self.assertEqual(result["candidate"]["recipe"]["destination"]["public"], "35.0.2")
        self.assertEqual(before, (self.config.to_json(), self.retained, load_policy()))
        self.blocked("unreviewed-destination", target="35.0.3")

    def test_source_constraints_are_validated_before_compiling_target(self):
        self.config.nextcloud_exact = "35.0.2"
        self.blocked("source-plan-incompatible")
        self.config.nextcloud_exact = "35.0.1"
        self.retained = resolved_plan(self.config, nextcloud="35.0.1")
        self.retained["constraints"]["nextcloud_exact"] = ""
        self.blocked("source-plan-incompatible")

    def test_installed_extensions_are_not_loaded_modules(self):
        self.assertIn("php85-curl", self.retained["packages"]["nextcloud"])
        for context in preflight.PHP_CONTEXTS:
            with self.subTest(context=context):
                modules = self.observed["php"][context]["loaded_modules"]
                modules.remove("curl")
                self.blocked("php-runtime-incompatible")
                modules.append("curl")

    def test_required_builtins_are_explicit_and_not_package_name_guesses(self):
        for module in ("hash", "json", "openssl", "libxml", "zend opcache"):
            self.assertIn(module, preflight.required_modules())
            modules = self.observed["php"]["cli"]["loaded_modules"]
            modules.remove(module)
            self.blocked("php-runtime-incompatible")
            modules.append(module)

    def test_unsupported_or_different_fpm_versions_and_modules_fail(self):
        for version in ("8.2.29", "8.3.1", "8.5.10", "8.6.0", "9.0.0", "8.5.11RC1"):
            with self.subTest(version=version):
                self.observed["php"]["callback_fpm"]["version"] = version
                self.blocked("php-runtime-incompatible")
        self.observed["php"]["callback_fpm"]["version"] = "8.5.11"
        self.observed["php"]["callback_fpm"]["loaded_modules"].append("unexpected")
        self.blocked("php-runtime-incompatible")

    def test_cli_cannot_substitute_for_a_running_fpm_observation(self):
        self.observed["php"]["main_fpm"] = deepcopy(self.observed["php"]["cli"])
        self.blocked("php-runtime-incompatible")

    def test_database_native_state_is_required(self):
        original = deepcopy(self.observed["database"])
        for key, value in (("version", "12.4.0"), ("vendor", "MySQL"),
                           ("isolation", "REPEATABLE-READ"), ("engines", ["InnoDB", "MyISAM"])):
            self.observed["database"] = {**original, key: value}
            self.blocked("database-runtime-incompatible")

    def test_nextcloud_ready_and_exact_internal_version_are_observed(self):
        original = deepcopy(self.observed["nextcloud"])
        for key, value in (("installed", 1), ("maintenance", True), ("needsDbUpgrade", True),
                           ("version", "35.0.1.2"), ("versionstring", "35.0.0")):
            self.observed["nextcloud"] = {**original, key: value}
            self.blocked("nextcloud-not-ready-or-drifted")

    def test_complete_actual_inventory_detects_extra_missing_and_changed_packages(self):
        original = deepcopy(self.observed["packages"]["nextcloud"])
        mutations = [original[:-1], [{**original[0], "version": "999"}, *original[1:]],
                     original + [{"name": "unknown", "version": "1", "origin": "misc/unknown"}],
                     original + [original[0]]]
        for rows in mutations:
            self.observed["packages"]["nextcloud"] = rows
            self.blocked("installed-package-drift")

    def test_pkgbase_is_distinct_from_locked_ports_and_remains_bound(self):
        candidate = self.assess()["candidate"]
        self.observed["packages"]["nextcloud"].extend([
            {"name": "FreeBSD-runtime", "version": "15.1", "origin": "base/FreeBSD-runtime"},
            {"name": "pkg", "version": "2.3", "origin": "ports-mgmt/pkg"}])
        self.assertTrue(self.assess()["eligible"])
        with self.assertRaises(ValueError):
            preflight.revalidate(candidate, self.config, self.retained, self.observed,
                                 self.repository, bindings=self.bindings, now=1010)
        self.observed["packages"]["nextcloud"][-2]["origin"] = "misc/FreeBSD-runtime"
        self.blocked("installed-package-drift")

    def test_metadata_identity_does_not_mean_archive_availability(self):
        del self.repository["available_packages"]["php85"]
        self.blocked("repository-or-artifact-unavailable")

    def test_changed_checksum_or_dependency_closure_is_not_an_unchanged_package(self):
        original = deepcopy(self.repository)
        self.repository["packages"]["php85"]["checksum"] = "e" * 64
        self.repository["available_packages"]["php85"] = "e" * 64
        self.blocked("repository-or-artifact-unavailable")
        self.repository = original
        self.repository["packages"]["php85"]["dependencies"] = {}
        self.blocked("repository-or-artifact-unavailable")

    def test_install_removal_and_forged_solver_permission_are_blocked(self):
        for transaction in ([{"install": "php86"}], [{"remove": "php85"}], {}, None):
            self.repository["package_transaction"] = transaction
            self.blocked("package-transaction-unsupported")
        self.repository["package_transaction"] = []
        self.repository["solver_receipt"] = {"success": True, "execution_authorized": True}
        self.blocked("package-transaction-unsupported")

    def test_capture_and_catalog_freshness_and_bindings(self):
        self.blocked("observations-missing-stale-or-unbound", now=1301)
        self.blocked("observations-missing-stale-or-unbound", now=999)
        self.repository["captured_at"] = 0
        self.observed["captured_at"] = 4000
        self.blocked("repository-or-artifact-unavailable", now=4000)
        self.repository["captured_at"] = 4000
        self.observed["bindings"]["graph_sha256"] = "e" * 64
        self.blocked("observations-missing-stale-or-unbound", now=4000)

    def test_source_binding_is_recomputed(self):
        self.bindings["versions_sha256"] = "e" * 64
        self.blocked("source-binding-mismatch")

    def test_artifact_identity_and_internal_target_are_exact(self):
        artifact = self.repository["artifacts"]["nextcloud"]
        artifact["internal_version"] = "35.0.2.1"
        self.blocked("repository-or-artifact-unavailable")
        artifact["internal_version"] = "35.0.2.2"
        artifact["available_sha256"] = "f" * 64
        self.blocked("repository-or-artifact-unavailable")

    def test_unknown_custom_disabled_and_incompatible_apps_fail_closed(self):
        original = deepcopy(self.observed["nextcloud"]["apps"])
        self.observed["nextcloud"]["apps"]["custom"] = {"version": "1.0.0", "enabled": False, "provenance": "custom"}
        self.blocked("application-compatibility-unknown")
        self.observed["nextcloud"]["apps"] = original
        self.repository["apps"]["serverinfo"]["phpVersionSpec"] = ">=8.6.0 <8.7.0"
        self.blocked("application-compatibility-unknown")

    def test_target_shipped_serverinfo_version_is_reviewed(self):
        self.repository["apps"]["serverinfo"]["version"] = "7.0.1"
        self.blocked("application-compatibility-unknown")

    def test_connector_authenticated_artifact_must_remain_identical(self):
        self.observed["nextcloud"]["apps"]["onlyoffice"]["artifact_sha256"] = "e" * 64
        self.blocked("application-compatibility-unknown")

    def test_external_storage_and_integrations_require_a_separate_recipe(self):
        for key in self.observed["integrations"]:
            self.observed["integrations"][key] = True
            self.blocked("unsupported-integration")
            self.observed["integrations"][key] = False

    def test_strict_schemas_and_malformed_inputs_do_not_leak_values(self):
        secret = "secret-environment-app-value"
        self.observed["php"]["cli"]["environment"] = {"PASSWORD": secret}
        self.repository["apps"]["serverinfo"]["version"] = secret
        report = self.blocked("php-runtime-incompatible")
        self.assertNotIn(secret, json.dumps(report))
        self.assertNotIn("PASSWORD", json.dumps(report))
        for observed in (None, {}, {"schema_version": True}):
            self.observed = observed
            self.blocked("observations-missing-stale-or-unbound")

    def test_saved_true_bits_never_authorize_execution(self):
        candidate = self.assess()["candidate"]
        candidate["execution_authorized"] = True
        with self.assertRaisesRegex(ValueError, "inputs changed"):
            preflight.revalidate(candidate, self.config, self.retained, self.observed,
                                 self.repository, bindings=self.bindings, now=1010)

    def test_assessment_has_no_network_or_native_execution(self):
        with patch("subprocess.run", side_effect=AssertionError("native call")), \
                patch("urllib.request.urlopen", side_effect=AssertionError("network call")):
            self.assertTrue(self.assess()["eligible"])


if __name__ == "__main__":
    unittest.main()
