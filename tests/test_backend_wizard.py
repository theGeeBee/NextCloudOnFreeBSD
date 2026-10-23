"""Offline fresh-profile wizard, allocation and credential contracts."""

from dataclasses import replace
import hashlib
import json
import unittest
from unittest.mock import Mock, patch

from installer.config import Config, DEFAULT_NEXTCLOUD_APPS, NO_OFFICE_FIELDS, QUOTA_FIELDS
from installer.wizard import configure, create_secrets, initial_config, resource_review, used_ports
from test_ui import ScriptedUI, host_facts


BACKEND_MENU = "Office backend (fresh installation)"


class BackendWizardTests(unittest.TestCase):
    def run_wizard(self, ui, *, facts=None, existing=None, registered=()):
        with patch("sys.stdin.isatty", return_value=True), patch("sys.stdout.isatty", return_value=True), \
                patch("subprocess.run") as run:
            result = configure(facts or host_facts(), existing, registered, ui=ui)
        run.assert_not_called()
        return result

    def none_ui(self, *, inputs=None, menus=None, confirmed=False):
        return ScriptedUI(inputs=inputs, menus={BACKEND_MENU: "none", "HTTPS termination": "external",
                                               "Nextcloud apps": "all", **(menus or {})}, confirmed=confirmed)

    def test_native_initial_config_retains_pre_backend_serialized_bytes(self):
        # Captured from HEAD's initial_config before the backend wizard change.
        digests = {
            6592: "aea05ba5e79bc627c454e8df9a8f638af689f1cbcccfcfe7cc9c99c8722281cd",
            8192: "7e78028cd334bd62c168f3a6d28e3c3982eb2c30bb8e8b9fbd1ab65c283b9413",
            16384: "715dda3eef0ef7dc6e2596fb8518ad33dc40a60a8a7511d379941d527bd6557a",
            32768: "84c387d91fd11bd99556373dbef6d63edfcb21120c4b92ac48900c6804495e8f",
        }
        for memory, digest in digests.items():
            with self.subTest(memory=memory):
                legacy = initial_config(host_facts(memory)).to_json()
                explicit = initial_config(host_facts(memory), office_backend="onlyoffice").to_json()
                self.assertEqual(hashlib.sha256(legacy.encode()).hexdigest(), digest)
                self.assertEqual(explicit, legacy)
                self.assertNotIn("office_backend", json.loads(legacy))

    def test_backend_choice_precedes_initial_sizing_and_defaults_to_native(self):
        ui = ScriptedUI(menus={"HTTPS termination": "external"})
        choices = {}
        menu = ui.menu

        def inspect_menu(title, items, default=None):
            if title == BACKEND_MENU:
                choices.update(items)
                self.assertEqual(default, "onlyoffice")
            return menu(title, items, default)

        def size(*args, **kwargs):
            self.assertEqual(ui.questions[0], BACKEND_MENU)
            return initial_config(*args, **kwargs)

        ui.menu = inspect_menu
        with patch("installer.wizard.initial_config", side_effect=size):
            config = self.run_wizard(ui)
        self.assertEqual(tuple(choices), ("onlyoffice", "eurooffice", "collabora", "none"))
        self.assertIn("dedicated", choices["eurooffice"])
        self.assertIn("dedicated", choices["collabora"])
        self.assertTrue(config.native_office)
        self.assertNotIn("office_backend", json.loads(config.to_json()))

    def test_none_skips_all_office_prompts_even_with_advanced_settings(self):
        ui = self.none_ui(inputs={"Absolute path to PUBLIC": "/root/operator.pub"}, menus={
            "Storage limits": "caps", "Resource budgets": "edit", "SSH into the Nextcloud jail": "on",
            "Jail SSH privileges": "admin"}, confirmed=True)
        config = self.run_wizard(ui)
        self.assertEqual(config.backend, "none")
        self.assertEqual(config.nextcloud_apps, DEFAULT_NEXTCLOUD_APPS)
        self.assertEqual(config.storage_policy, "optional")
        self.assertTrue(all(getattr(config, name) == 0 for name in QUOTA_FIELDS))
        self.assertEqual(config.network.prefixlen, 30)
        self.assertEqual(config.jails, (config.nextcloud_jail,))
        self.assertEqual(config.bridges, (config.nextcloud_bridge,))
        self.assertEqual(config.ingress_ports, [config.http_port, config.ssh_nextcloud_port])
        self.assertTrue(config.ssh_admin)
        self.assertIn("Unused private IPv4 /30 block", ui.questions)
        questions = "\n".join(ui.questions[1:] + ui.confirmations).lower()
        for forbidden in ("onlyoffice", "office budget", "fonts", "plugins", "webfonts", "both jails", "/29"):
            self.assertNotIn(forbidden, questions)
        self.assertFalse(set(NO_OFFICE_FIELDS) & json.loads(config.to_json()).keys())
        self.assertNotIn("corefonts.sourceforge.net", "\n".join(ui.messages))

    def test_none_minimum_has_two_web_workers_and_no_office_memory(self):
        facts = host_facts(4032)
        config = initial_config(facts, office_backend="none", nextcloud_apps="calendar,contacts")
        config.public_hostname = "cloud.example.test"
        config.admin_email = config.acme_email = "admin@example.test"
        config.validate_provisioning()
        self.assertEqual(config.memory_budget_mb, facts["memory_mb"])
        self.assertEqual((config.office_memory_mb, config.php_children, config.php_callback_children), (0, 2, 0))
        self.assertEqual(config.nextcloud_apps, "calendar,contacts")
        review = resource_review(facts, config, ())
        self.assertIn("2 workers (web only)", review)
        self.assertNotIn("invalid worker", review)
        self.assertNotIn("ONLYOFFICE", review)
        self.assertNotIn("office callback", review)
        with self.assertRaisesRegex(ValueError, "at least 1984 MiB"):
            initial_config(host_facts(4031), office_backend="none")

    def test_none_low_ram_guides_app_selection_using_its_own_floor(self):
        ui = self.none_ui(menus={"Nextcloud apps": "custom",
                                "Choose individual Nextcloud apps": ["files_antivirus", "done"]})
        config = self.run_wizard(ui, facts=host_facts(4032))
        self.assertEqual(set(config.selected_nextcloud_apps), set(DEFAULT_NEXTCLOUD_APPS.split(",")) - {"files_antivirus"})
        self.assertEqual(config.memory_budget_mb, 4032)
        self.assertEqual(ui.questions.count("Nextcloud apps"), 1)
        self.assertLess(ui.questions.index("Nextcloud apps"),
                        ui.questions.index("Instance name (1–8 lowercase letters/digits, starting with a letter)"))
        self.assertIn("need at least 5056 MiB", "\n".join(ui.messages))

    def test_none_sizing_keeps_app_allowance_and_host_capacity(self):
        for memory in (7104, 8192, 16384, 32768):
            with self.subTest(memory=memory):
                config = initial_config(host_facts(memory), office_backend="none", nextcloud_apps=DEFAULT_NEXTCLOUD_APPS)
                self.assertEqual(config.antivirus_memory_mb, 3072)
                self.assertEqual(config.office_memory_mb, 0)
                self.assertLessEqual(config.memory_budget_mb, memory)
                self.assertGreaterEqual(config.php_children, 2)
                self.assertEqual(config.php_callback_children, 0)

    def test_registered_none_reserves_only_actual_bridges_and_ports(self):
        facts = host_facts()
        first = initial_config(facts, office_backend="none")
        first = replace(first, jail_ssh=True, onlyoffice_bridge="bridge241", ssh_onlyoffice_port=2202)
        self.assertEqual(used_ports([first], first.ingress_address, first.management_port), {22, 80, 443, 2201})
        second = initial_config(facts, [first], office_backend="none")
        self.assertEqual(second.private_network, "10.77.0.4/30")
        self.assertEqual(second.nextcloud_bridge, "bridge241")
        self.assertEqual(second.ssh_nextcloud_port, 2202)
        self.assertFalse(set(first.bridges) & set(second.bridges))
        self.assertFalse(first.network.overlaps(second.network))
        # The native profile still reserves two real bridges, jails and SSH ports.
        native = initial_config(facts, [first])
        self.assertEqual(native.private_network, "10.77.0.8/29")
        self.assertEqual(native.bridges, ("bridge241", "bridge242"))

    def test_none_existing_edits_keep_backend_apps_and_budget_without_reselection(self):
        config = self.run_wizard(self.none_ui(menus={"Nextcloud apps": "custom",
                                                   "Choose individual Nextcloud apps": ["none", "calendar", "done"]}))
        config = replace(config, php_budget_mb=1024)
        before = config.to_json()
        ui = self.none_ui(menus={BACKEND_MENU: "onlyoffice", "Nextcloud apps": "custom",
                                "Choose individual Nextcloud apps": "done"})
        edited = self.run_wizard(ui, existing=config)
        self.assertNotIn(BACKEND_MENU, ui.questions)
        self.assertEqual(edited.backend, "none")
        self.assertEqual(edited.nextcloud_apps, "calendar")
        self.assertEqual(edited.php_budget_mb, 1024)
        self.assertEqual(config.to_json(), before)

    def test_vm_choices_size_guest_and_skip_native_office_questions(self):
        for backend in ("eurooffice", "collabora"):
            with self.subTest(backend=backend):
                ui = ScriptedUI(menus={BACKEND_MENU: backend,'HTTPS termination':'external','Resource budgets':'edit'})
                c=self.run_wizard(ui, facts=host_facts(32768))
                self.assertEqual(c.backend,backend)
                self.assertEqual((c.office_vm_cpus,c.office_memory_mb,c.office_vm_disk_gib),(2,4096,16))
                self.assertEqual(len(c.jails),1);self.assertEqual(len(c.bridges),2)
                self.assertIn('Dedicated office VM vCPU count',ui.questions)
                self.assertNotIn('ONLYOFFICE jail hostname (short name or FQDN)',ui.questions)
                self.assertFalse(c.onlyoffice_plugins)
                self.assertNotIn('corefonts.sourceforge.net','\n'.join(ui.messages))
                edit=ScriptedUI(menus={'HTTPS termination':'external'})
                self.assertEqual(self.run_wizard(edit,existing=c,facts=host_facts(32768)).backend,backend)
                self.assertNotIn(BACKEND_MENU,edit.questions)

    def test_vm_low_ram_refuses_before_resource_mutation(self):
        for backend in ('eurooffice','collabora'):
            with self.assertRaisesRegex(ValueError,'at least 6592 MiB'):
                initial_config(host_facts(8192),office_backend=backend)

    def test_none_credentials_omit_jwt_and_native_generation_is_unchanged(self):
        for backend, expected_calls in (("none", 1), ("onlyoffice", 2), ("", 2)):
            with self.subTest(backend=backend):
                ui = Mock()
                with patch("installer.wizard.secrets.token_urlsafe", return_value="synthetic-admin"), \
                        patch("installer.wizard.secrets.token_hex", side_effect=["synthetic-db", "synthetic-jwt"]) as token:
                    credentials = create_secrets(ui=ui, generate=True, backend=backend)
                expected = {"admin_password": "synthetic-admin", "db_password": "synthetic-db"}
                if backend != "none":
                    expected["jwt_secret"] = "synthetic-jwt"
                self.assertEqual(credentials, expected)
                self.assertEqual(token.call_count, expected_calls)
                ui.secret.assert_not_called()
                for value in credentials.values():
                    self.assertNotIn(value, repr(ui.message.call_args_list))


if __name__ == "__main__":
    unittest.main()
