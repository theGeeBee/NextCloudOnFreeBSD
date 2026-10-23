"""Initial selection and owned integration decisions, not upstream app feature tests."""

from dataclasses import replace
import json
import unittest
from unittest.mock import patch

from installer.config import (ANTIVIRUS_MEMORY_MB, DEFAULT_NEXTCLOUD_APPS,
                              Config, deployment_plan, validate_nextcloud_apps)
from installer.compatibility import package_roots
from installer import resolution
from installer.network import pf_rules
from installer.versions import load_policy
from installer.wizard import configure, select_nextcloud_apps
from test_ui import ScriptedUI, host_facts, registered_config
from test_versions import catalog


class AppSelectionTests(unittest.TestCase):
    def test_legacy_and_explicit_none_round_trip_without_defaulting_to_consent(self):
        c = registered_config(host_facts())
        original = c.to_json()
        self.assertNotIn('"nextcloud_apps"', original)
        self.assertEqual(Config.from_json(original).to_json(), original)
        self.assertEqual(c.selected_nextcloud_apps, ())
        explicit = replace(c, nextcloud_apps="none")
        self.assertEqual(Config.from_json(explicit.to_json()).nextcloud_apps, "none")
        self.assertEqual(explicit.selected_nextcloud_apps, ())
        self.assertEqual(explicit.memory_budget_mb, c.memory_budget_mb)

    def test_allowlist_rejects_duplicates_unknowns_injection_and_wrong_types(self):
        for value in (True, None, [], "mail,calendar", "mail,mail", "calendar,", "calendar,none",
                      "mail;id", "Mail", "unknown", "mail\nspreed", " mail"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_nextcloud_apps(value)
        self.assertEqual(validate_nextcloud_apps("calendar,mail,spreed"), ("calendar", "mail", "spreed"))

    def test_new_wizard_defaults_all_but_existing_omission_keeps_none(self):
        ui = ScriptedUI(menus={"HTTPS termination": "external"})
        ui.menus.pop("Nextcloud apps")  # Exercise the real menu default, not a scripted selection.
        with patch("sys.stdin.isatty", return_value=True), patch("sys.stdout.isatty", return_value=True), \
                patch("subprocess.run") as run:
            c = configure(host_facts(), ui=ui)
        run.assert_not_called()
        self.assertEqual(ui.defaults["Nextcloud apps"], "all")
        self.assertEqual(c.nextcloud_apps, DEFAULT_NEXTCLOUD_APPS)
        self.assertEqual(c.antivirus_memory_mb, ANTIVIRUS_MEMORY_MB)
        self.assertLessEqual(c.memory_budget_mb, host_facts()["memory_mb"])
        self.assertIn("mail", c.selected_nextcloud_apps)
        self.assertIn("spreed", c.selected_nextcloud_apps)
        existing = registered_config(host_facts())
        ui = ScriptedUI(menus={"HTTPS termination": "external"})
        ui.menus.pop("Nextcloud apps")
        with patch("sys.stdin.isatty", return_value=True), patch("sys.stdout.isatty", return_value=True):
            result = configure(host_facts(65536), existing, ui=ui)
        self.assertEqual(ui.defaults["Nextcloud apps"], "none")
        self.assertEqual(result.nextcloud_apps, "")

    def test_all_none_and_custom_selection_preserve_explicit_choices(self):
        self.assertEqual(select_nextcloud_apps(DEFAULT_NEXTCLOUD_APPS,
                         ui=ScriptedUI(menus={"Nextcloud apps": "none"})), "none")
        ui = ScriptedUI(menus={"Nextcloud apps": "custom",
                              "Choose individual Nextcloud apps": ["none", "mail", "spreed", "done"]})
        self.assertEqual(select_nextcloud_apps(DEFAULT_NEXTCLOUD_APPS, ui=ui), "mail,spreed")
        ui = ScriptedUI(menus={"Nextcloud apps": "custom",
                              "Choose individual Nextcloud apps": ["none", "done"]})
        self.assertEqual(select_nextcloud_apps("mail", ui=ui), "none")

    def test_antivirus_contributes_to_existing_aggregate_capacity_accounting(self):
        base = registered_config(host_facts())
        av = replace(base, nextcloud_apps="files_antivirus")
        self.assertEqual(av.memory_budget_mb - base.memory_budget_mb, ANTIVIRUS_MEMORY_MB)
        plan = deployment_plan(av)
        self.assertIn("log-only (not upload blocking/deletion)", plan)
        self.assertIn("Scan stream limit 100 MiB", plan)
        self.assertIn("3072 MiB", plan)

    def test_clamav_is_selected_in_native_package_policy_only_with_antivirus(self):
        c = registered_config(host_facts())
        self.assertNotIn("security/clamav", package_roots(c)["nextcloud"])
        av = replace(c, nextcloud_apps="files_antivirus")
        roots = package_roots(av)
        self.assertIn("security/clamav", roots["nextcloud"])
        self.assertNotIn("security/clamav", roots["host"] + roots["onlyoffice"])
        old = load_policy()
        old["profiles"][0]["optional_roots"].pop("antivirus")
        self.assertNotIn("security/clamav", package_roots(c, old)["nextcloud"])
        with self.assertRaisesRegex(ValueError, "no reviewed package roots"):
            package_roots(av, old)

    def test_mail_egress_is_secure_public_outbound_nextcloud_only_and_opt_in(self):
        first = registered_config(host_facts())
        legacy = pf_rules([first])
        self.assertNotIn("465, 587, 993", legacy)
        mail = replace(first, nextcloud_apps="mail,spreed")
        expected = (f"pass in quick on {mail.nextcloud_bridge} inet proto tcp from {mail.nextcloud_ip} "
                    "to ! <cloud_noninternet> port { 465, 587, 993 } flags S/SA keep state")
        rules = pf_rules([mail])
        self.assertIn(expected, rules)
        new_lines = set(rules.splitlines()) - set(legacy.splitlines())
        self.assertEqual(len(new_lines), 2)  # One comment and exactly one rule.
        self.assertFalse(any("rdr" in line or "proto udp" in line or "port 25" in line for line in new_lines))
        self.assertIn("10.0.0.0/8", rules)  # Mail cannot reach private callbacks/other instances via this exception.
        no_mail = replace(mail, nextcloud_apps="spreed")
        self.assertEqual(pf_rules([no_mail]), legacy)

    def test_mail_selection_does_not_open_another_instances_mail_access(self):
        first = replace(registered_config(host_facts()), nextcloud_apps="mail")
        second = replace(first, instance="other", private_network="10.77.1.0/29",
                         nextcloud_bridge="bridge242", onlyoffice_bridge="bridge243", nextcloud_apps="none")
        rules = pf_rules([first, second])
        mail_rules = [line for line in rules.splitlines() if "465, 587, 993" in line]
        self.assertEqual(len(mail_rules), 1)
        self.assertIn(f"from {first.nextcloud_ip}", mail_rules[0])
        self.assertNotIn(second.nextcloud_ip, mail_rules[0])

    def test_antivirus_package_is_in_resolved_closure_without_host_installation(self):
        c = replace(registered_config(host_facts()), nextcloud_apps="files_antivirus", accept_microsoft_fonts=True)
        metadata = catalog(config=c)
        plan = resolution.resolve(c, metadata)
        self.assertIn("clamav", plan["packages"]["nextcloud"])
        self.assertNotIn("clamav", plan["packages"]["host"])
        self.assertEqual(plan["packages"]["nextcloud"]["clamav"]["origin"], "security/clamav")

    def test_mail_plan_distinguishes_mailboxes_from_system_notifications(self):
        c = replace(registered_config(host_facts()), nextcloud_apps="mail,spreed")
        text = deployment_plan(c)
        self.assertIn("outbound public TCP 993/465/587 only", text)
        self.assertIn("system notification SMTP remains disabled", text)
        self.assertIn("No local TURN/HPB or new media ports", text)
        self.assertEqual(json.loads(c.to_json())["nextcloud_apps"], "mail,spreed")


if __name__ == "__main__":
    unittest.main()
