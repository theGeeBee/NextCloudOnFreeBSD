"""Focused family configuration, version review and approval-contract checks."""

from contextlib import ExitStack
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from installer.config import Config
from installer.main import main, version_review
from installer.state import Registry, config_digest
from installer.versions import load_policy, selected_profiles
from installer.wizard import select_version_families
from version_fixtures import LEGACY_CONFIG_JSON, LEGACY_CONFIG_SHA256, resolved_plan


class FamilyConfigTests(unittest.TestCase):
    def test_empty_family_map_preserves_historical_serialization_and_digest(self):
        config = Config.from_json(LEGACY_CONFIG_JSON)
        self.assertEqual(config.version_families, {})
        self.assertNotIn("version_families", config.to_dict())
        self.assertEqual(config_digest(config), LEGACY_CONFIG_SHA256)
        explicit = json.loads(LEGACY_CONFIG_JSON)
        explicit["version_families"] = {}
        self.assertEqual(Config.from_json(json.dumps(explicit)).to_json(), config.to_json())

    def test_family_key_order_is_canonical_across_atomic_registry_and_journal(self):
        from itertools import permutations
        from installer.state import atomic_json
        pairs = (("nextcloud", "35"), ("php", "8.5"), ("database", "12.3"))
        baseline = None
        for order in permutations(pairs):
            config = Config.from_json(LEGACY_CONFIG_JSON)
            config.version_families = dict(order)
            original_order = list(config.version_families)
            encoded = config.to_json()
            if baseline is None:
                baseline = encoded
            self.assertEqual(encoded, baseline)
            self.assertEqual(list(config.version_families), original_order)
            with tempfile.TemporaryDirectory() as directory:
                registry = Registry(Path(directory) / "registry")
                registry.initialize()
                path = registry.save_new(config, {"admin_password": "synthetic-only"})
                atomic_json(path / "deployment.json", {"schema_version": 2,
                            "config_sha256": config_digest(config), "steps": {}})
                reread = registry.load(config.instance)
                self.assertEqual(config_digest(reread), config_digest(config))
                self.assertEqual(reread.to_json(), encoded)
                changed = reread.to_dict()
                changed["version_families"]["php"] = "8.6"
                atomic_json(path / "config.json", changed)
                with self.assertRaisesRegex(ValueError, "immutable configuration"):
                    registry.load(config.instance)

    def test_default_map_is_not_shared_and_serialization_is_a_copy(self):
        first, second = Config(), Config()
        first.version_families["php"] = "8.5"
        self.assertEqual(second.version_families, {})
        serialized = first.to_dict()
        serialized["version_families"]["php"] = "8.4"
        self.assertEqual(first.version_families, {"php": "8.5"})

    def test_family_only_recipe_is_new_style_but_empty_or_omitted_map_remains_legacy(self):
        value = json.loads(LEGACY_CONFIG_JSON)
        self.assertTrue(hasattr(Config.from_json(json.dumps(value)), "_legacy_target"))
        value["version_families"] = {}
        self.assertTrue(hasattr(Config.from_json(json.dumps(value)), "_legacy_target"))
        value["version_families"] = {"nextcloud": "35"}
        config = Config.from_json(json.dumps(value))
        self.assertFalse(hasattr(config, "_legacy_target"))
        self.assertEqual(config.release, load_policy()["defaults"]["freebsd_release"])
        self.assertFalse(hasattr(Config.from_json(config.to_json()), "_legacy_target"))

    def test_json_family_map_and_legacy_pins_round_trip(self):
        value = json.loads(LEGACY_CONFIG_JSON)
        value.update(version_families={"nextcloud": "35", "php": "8.5", "nginx": "1.28"},
                     nextcloud_min="35.0.0", nextcloud_exact="35.0.1")
        config = Config.from_json(json.dumps(value))
        self.assertEqual(config.version_families, value["version_families"])
        self.assertEqual(config.nextcloud_exact, "35.0.1")
        self.assertEqual(Config.from_json(config.to_json()).to_json(), config.to_json())

    def test_bad_map_types_and_unstable_family_values_are_rejected(self):
        for families in (None, [], "35", True, {"php": 8.5}, {"php": "8.5.1"},
                         {"php": "8.5-rc1"}, {"php": "8.5\n"}, {"php": ""}):
            with self.subTest(families=families):
                value = json.loads(LEGACY_CONFIG_JSON)
                value["version_families"] = families
                with self.assertRaises(ValueError):
                    Config.from_json(json.dumps(value))


class FamilyWizardTests(unittest.TestCase):
    def test_defaults_are_derived_from_selected_policy_for_each_backend(self):
        policy = load_policy()
        for backend in ("onlyoffice", "none", "eurooffice", "collabora"):
            with self.subTest(backend=backend):
                config = Config(office_backend=backend)
                ui = Mock()
                ui.input.side_effect = lambda label, default: default
                select_version_families(config, ui=ui, policy=policy)
                profile = selected_profiles(config, policy)[0]
                rule = profile["roles"]["php"]["range"]
                self.assertEqual(config.version_families["php"],
                                 rule.get("family", ".".join(rule.get("min", rule.get("exact", "")).split(".")[:2])))
                self.assertEqual("onlyoffice" in config.version_families, backend == "onlyoffice")
                self.assertEqual("connector" in config.version_families, backend != "none")
                self.assertEqual(len(ui.input.call_args_list), 5 if backend == "onlyoffice" else 3 if backend == "none" else 4)

    def test_existing_choices_and_other_package_keys_survive_and_clear_is_explicit(self):
        config = Config(version_families={"nextcloud": "35", "php": "8.5", "nginx": "1.28"},
                        nextcloud_min="35.0.0", nextcloud_exact="35.0.1")
        ui = Mock()
        ui.input.side_effect = lambda label, default: "-" if label == "PHP version family" else default
        select_version_families(config, ui=ui)
        self.assertNotIn("php", config.version_families)
        self.assertEqual(config.version_families["nginx"], "1.28")
        self.assertEqual(config.nextcloud_min, "35.0.0")
        self.assertEqual(config.nextcloud_exact, "35.0.1")

    def test_invalid_family_is_reprompted_without_a_secret_input_channel(self):
        config = Config(office_backend="none")
        ui = Mock()
        ui.input.side_effect = ["35.0.1", "35", "8.5", "12.3"]
        select_version_families(config, ui=ui)
        self.assertEqual(config.version_families, {"nextcloud": "35", "php": "8.5", "database": "12.3"})
        self.assertTrue(any("Invalid value" in call.args[0] for call in ui.message.call_args_list))
        ui.secret.assert_not_called()


class VersionReviewTests(unittest.TestCase):
    def test_omitted_family_map_shows_selected_policy_defaults_without_changing_plan(self):
        config = Config(accept_microsoft_fonts=True)
        selected = resolved_plan(config)
        original = json.dumps(selected, sort_keys=True)
        summary = version_review(config, selected)
        self.assertIn("Selected policy defaults (" + selected["profile"] + "):", summary)
        self.assertIn("nextcloud family 35", summary)
        self.assertIn("onlyoffice family 9.4", summary)
        self.assertIn("connector family 10.2", summary)
        self.assertIn("php >=8.5.0 <8.6.0", summary)
        self.assertIn("database >=12.3.0 <12.4.0", summary)
        self.assertIn("Configured families: none", summary)
        self.assertNotIn("version_families", config.to_dict())
        self.assertEqual(json.dumps(selected, sort_keys=True), original)

    def test_synthetic_policy_formats_exact_packages_and_unknown_profiles_are_unavailable(self):
        policy = {"profiles": [{"id": "fixture", "applications": {"nextcloud": {"family": "36", "min": "36.0.2"}},
                               "roles": {"vm_firmware": {"version_exact": "g202508_3"}}}]}
        summary = version_review(Config(), {"profile": "fixture"}, policy=policy)
        self.assertIn("nextcloud family 36 >=36.0.2", summary)
        self.assertIn("vm_firmware exact g202508_3", summary)
        summary = version_review(Config(), {"profile": "absent"}, policy=policy)
        self.assertIn("Selected policy defaults: unavailable", summary)

    def test_resolved_summary_has_apps_roles_repository_families_and_warnings(self):
        config = Config(accept_microsoft_fonts=True, version_families={"php": "8.5"})
        selected = resolved_plan(config)
        selected["constraints"]["version_families"] = {"php": "8.5"}
        selected["warnings"].append("Unverified combination: native acceptance not run.")
        summary = version_review(config, selected)
        self.assertIn("Nextcloud: " + selected["applications"]["nextcloud"], summary)
        self.assertIn("ONLYOFFICE: " + selected["applications"]["onlyoffice"], summary)
        self.assertIn("Office connector: onlyoffice", summary)
        self.assertIn("Repository: FreeBSD-ports " + selected["repository"], summary)
        for role, label in (("php", "PHP"), ("database", "Database"), ("web", "Web server"),
                            ("cache", "Cache"), ("manager", "Jail manager")):
            self.assertIn(label + ": " + selected["roles"][role], summary)
        self.assertIn("Configured families: php 8.5", summary)
        self.assertIn("Effective family constraints: php 8.5", summary)
        self.assertIn("Compatibility: configured application/package checks passed", summary)
        self.assertIn("WARNING: Unverified combination", summary)

    def test_vm_runtime_release_and_significant_packages_not_native_office(self):
        config = Config(office_backend="collabora")
        selected = {"applications": {"nextcloud": "35.0.1", "connector": "12.0.1"},
                    "connector_app": "richdocuments", "office_runtime": {"container": {"release": "26.04.5.1.1"}},
                    "roles": {"vm_manager": "vm-bhyve", "vm_image_tools": "qemu-tools", "vm_firmware": "edk2-bhyve"},
                    "packages": {"host": {"vm-bhyve": {"version": "1.7.5"},
                                          "qemu-tools": {"version": "11.1.2_1"},
                                          "edk2-bhyve": {"version": "g202508_3"}}}}
        summary = version_review(config, selected)
        self.assertIn("Pinned VM office runtime release: 26.04.5.1.1", summary)
        self.assertIn("Office connector: richdocuments 12.0.1", summary)
        self.assertIn("VM image tools: qemu-tools 11.1.2_1", summary)
        self.assertIn("VM firmware: edk2-bhyve g202508_3", summary)
        self.assertNotIn("ONLYOFFICE:", summary)

    def test_none_has_no_office_release_or_connector(self):
        summary = version_review(Config(office_backend="none"), {"applications": {"nextcloud": "35.0.1"}})
        self.assertNotIn("Office connector:", summary)
        self.assertNotIn("Pinned VM office runtime", summary)
        self.assertIn("Selected policy defaults: unavailable", summary)


class FamilyApprovalTests(unittest.TestCase):
    def test_yes_does_not_bypass_validation_and_keeps_existing_approval_contract(self):
        for rejected in (False, True):
            with self.subTest(rejected=rejected), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                config = Config.from_json(LEGACY_CONFIG_JSON)
                config.accept_microsoft_fonts = True
                recipe = Path(directory) / "recipe.json"
                recipe.write_text(config.to_json())
                argv = ["install", "--config", str(recipe), "--yes", "--accept-acme-terms"]
                registry = Registry(Path(directory) / "registry")
                registry.initialize()
                terminal = Mock(wraps=io.StringIO())
                terminal.isatty.return_value = True
                ui = Mock()
                deployment = Mock()
                deployment.prepare_versions.return_value = resolved_plan(config)
                if rejected:
                    deployment.prepare_versions.side_effect = ValueError("Family compatibility failed")
                for target, value in (("sys.stdin", terminal), ("sys.stdout", terminal), ("TerminalUI", Mock(return_value=ui)),
                                      ("Registry", Mock(return_value=registry)), ("Runner", Mock()),
                                      ("require_host", Mock()), ("inspect_host", Mock(return_value={})),
                                      ("preflight", Mock()), ("configure", Mock(return_value=config)),
                                      ("create_secrets", Mock(return_value={"admin_password": "not-a-log-value", "db_password": "a" * 64, "jwt_secret": "b" * 64})),
                                      ("Deployment", Mock(return_value=deployment))):
                    stack.enter_context(patch("installer.main." + target, value))
                if rejected:
                    with self.assertRaisesRegex(ValueError, "Family compatibility failed"):
                        main(argv)
                    deployment.apply.assert_not_called()
                    self.assertFalse(any("Selected software" in call.args[0] for call in ui.message.call_args_list))
                else:
                    self.assertEqual(main(argv), 0)
                    deployment.apply.assert_called_once()
                    ui.input.assert_not_called()
                    messages = "\n".join(call.args[0] for call in ui.message.call_args_list)
                    self.assertIn("--yes approves APPLY", messages)
                    self.assertIn("KEEP remains mandatory", messages)
                    self.assertIn("Selected software", messages)
                    self.assertNotIn("not-a-log-value", messages)


if __name__ == "__main__":
    unittest.main()
