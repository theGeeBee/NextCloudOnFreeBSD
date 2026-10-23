"""Offline terminal, cancellation, password and multi-instance wizard checks."""

from contextlib import redirect_stdout
from dataclasses import replace
import getpass
import io
import os
from pathlib import Path
import pty
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import warnings

from installer.config import Config, DEFAULT_NEXTCLOUD_APPS, PLUGIN_CHOICES, QUOTA_FIELDS, deployment_plan
from installer.ui import TerminalUI
from installer.versions import constraints, defaults, load_policy
from installer.wizard import configure, create_secrets, initial_config, select_onlyoffice_plugins, service_memory


ROOT = Path(__file__).resolve().parents[1]


class TerminalTests(unittest.TestCase):
    def test_numbered_menu_validation_default_and_cancellation(self):
        ui = TerminalUI(plain=True)
        choices = [("install", "Install an instance"), ("list", "List instances")]
        with patch("builtins.input", side_effect=["invalid", "2"]), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(ui.menu("Actions", choices, "install"), "list")
        self.assertIn("1. Install an instance (default)", output.getvalue())
        self.assertIn("0. Cancel", output.getvalue())
        for answer, expected in (("", "list"), ("install", "install")):
            with patch("builtins.input", return_value=answer), redirect_stdout(io.StringIO()):
                self.assertEqual(ui.menu("Actions", choices, "list"), expected)
        for answer in ("0", "\x1b"):
            with patch("builtins.input", return_value=answer), redirect_stdout(io.StringIO()):
                with self.assertRaises(KeyboardInterrupt):
                    ui.menu("Actions", choices)
        with patch("builtins.input", side_effect=EOFError), redirect_stdout(io.StringIO()):
            with self.assertRaises(KeyboardInterrupt):
                ui.menu("Actions", choices)

    def test_plain_input_and_confirmation(self):
        ui = TerminalUI(plain=True)
        with patch("builtins.input", return_value=""):
            self.assertEqual(ui.input("Hostname", "cloud.example.test"), "cloud.example.test")
            self.assertFalse(ui.confirm("Continue?"))
        with patch("builtins.input", side_effect=["possibly", "YES"]), redirect_stdout(io.StringIO()):
            self.assertTrue(ui.confirm("Continue?"))
        with patch("builtins.input", side_effect=EOFError):
            with self.assertRaises(KeyboardInterrupt):
                ui.input("Hostname")

    def test_missing_utility_plain_mode_and_bad_terms_fall_back(self):
        with patch.dict(os.environ, {"TERM": "xterm", "CLOUD_INSTALLER_PLAIN": "0"}), \
                patch("sys.stdin.isatty", return_value=True), patch("sys.stdout.isatty", return_value=True), \
                patch("installer.ui.shutil.which", return_value=None):
            self.assertIsNone(TerminalUI().dialog)
        for term in ("", "dumb", "unknown"):
            with patch.dict(os.environ, {"TERM": term, "CLOUD_INSTALLER_PLAIN": "0"}), \
                    patch("installer.ui.subprocess.run") as run:
                self.assertIsNone(TerminalUI().dialog)
                run.assert_not_called()
        with patch.dict(os.environ, {"CLOUD_INSTALLER_PLAIN": "1"}):
            self.assertIsNone(TerminalUI().dialog)
        with patch("installer.ui.shutil.which") as which:
            self.assertIsNone(TerminalUI(plain=True).dialog)
            which.assert_not_called()

    def test_supported_term_uses_base_dialog_and_unknown_terminfo_falls_back(self):
        import curses
        with patch.dict(os.environ, {"TERM": "xterm", "CLOUD_INSTALLER_PLAIN": "0"}), \
                patch("sys.stdin.isatty", return_value=True), patch("sys.stdout.isatty", return_value=True), \
                patch("sys.stdout.fileno", return_value=1), \
                patch("installer.ui.shutil.which", return_value="/usr/bin/bsddialog"), \
                patch("installer.ui.shutil.get_terminal_size", return_value=os.terminal_size((80, 24))), \
                patch("curses.setupterm") as setup:
            self.assertEqual(TerminalUI().dialog, "/usr/bin/bsddialog")
            setup.side_effect = curses.error("unknown terminal")
            self.assertIsNone(TerminalUI().dialog)

    def test_dialog_response_channel_and_foreground_stdout(self):
        ui = TerminalUI(plain=True)
        ui.dialog = "/usr/bin/bsddialog"
        result = subprocess.CompletedProcess([], 0, stderr="install\n")
        with patch("installer.ui.subprocess.run", return_value=result) as run:
            self.assertEqual(ui.menu("Actions", [("install", "Install")], "install"), "install")
        arguments, options = run.call_args
        command = arguments[0]
        self.assertEqual(command[command.index("--output-fd") + 1], "2")
        self.assertEqual(options["stderr"], subprocess.PIPE)
        self.assertNotIn("stdout", options)
        self.assertNotIn("stdin", options)
        self.assertNotIn("capture_output", options)
        self.assertEqual(command[command.index("--esc-exit-code") + 1], "5")

    def test_dialog_runs_with_live_tty_and_response_is_not_displayed(self):
        # A fake dialog exercises actual fd inheritance in a pseudo-terminal;
        # the only child executable writes fixed synthetic public test strings.
        with tempfile.TemporaryDirectory(prefix="ui-pty-") as directory:
            dialog = Path(directory) / "dialog"
            dialog.write_text("#!/bin/sh\n[ -t 0 ] && [ -t 1 ] || exit 99\nprintf 'DIALOG_ON_TTY\\n'\nprintf 'install\\n' >&2\n")
            dialog.chmod(0o700)
            program = """
import sys
sys.path.insert(0, sys.argv[1])
from installer.ui import TerminalUI
ui = TerminalUI(plain=True)
ui.dialog = sys.argv[2]
print('RESULT:' + ui.menu('Actions', [('install', 'Install')]), flush=True)
"""
            master, slave = pty.openpty()
            try:
                result = subprocess.run([sys.executable, "-I", "-B", "-c", program, str(ROOT), str(dialog)],
                                        stdin=slave, stdout=slave, stderr=subprocess.PIPE, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                visible = os.read(master, 65536).decode()
            finally:
                os.close(master)
                os.close(slave)
            self.assertIn("DIALOG_ON_TTY", visible)
            self.assertIn("RESULT:install", visible)
            self.assertNotIn("\r\ninstall\r\n", visible)

    def test_cancel_escape_and_no_are_distinct(self):
        for status in (1, 5, 130, -2):
            ui = TerminalUI(plain=True)
            ui.dialog = "/usr/bin/bsddialog"
            result = subprocess.CompletedProcess([], status, stderr="")
            with patch("installer.ui.subprocess.run", return_value=result):
                with self.assertRaises(KeyboardInterrupt):
                    ui.input("Hostname", "default.example.test")
                if status == 1:
                    self.assertFalse(ui.confirm("Proceed?"))
                else:
                    with self.assertRaises(KeyboardInterrupt):
                        ui.confirm("Proceed?")

    def test_dialog_failure_retries_with_plain_prompts(self):
        for failure in (OSError("utility unavailable"), subprocess.CompletedProcess([], 255, stderr="curses error")):
            ui = TerminalUI(plain=True)
            ui.dialog = "/usr/bin/bsddialog"
            options = {"side_effect": failure} if isinstance(failure, Exception) else {"return_value": failure}
            with patch("installer.ui.subprocess.run", **options), patch("builtins.input", return_value="host"), \
                    redirect_stdout(io.StringIO()) as output:
                self.assertEqual(ui.input("Hostname"), "host")
            self.assertIsNone(ui.dialog)
            self.assertIn("numbered terminal", output.getvalue())

    def test_secrets_use_getpass_without_subprocess_or_echo_fallback(self):
        ui = TerminalUI(plain=True)
        ui.dialog = "/usr/bin/bsddialog"
        with patch("installer.ui.getpass.getpass", return_value=" synthetic secret ") as hidden, \
                patch("installer.ui.subprocess.run") as run:
            self.assertEqual(ui.secret("Password"), " synthetic secret ")
            hidden.assert_called_once_with("Password: ")
            run.assert_not_called()

        def echo_fallback(*args):
            warnings.warn("no echo control", getpass.GetPassWarning)
            self.fail("Echoing input must not be attempted")

        with patch("installer.ui.getpass.getpass", side_effect=echo_fallback):
            with self.assertRaisesRegex(ValueError, "hidden input"):
                ui.secret("Password")

    def test_progress_is_clamped_step_count_without_fake_percentages(self):
        ui = TerminalUI(plain=True)
        with redirect_stdout(io.StringIO()) as output:
            for current, total in ((-5, 8), (3, 8), (100, 8), (2, 0)):
                ui.progress(current, total, "Working")
        self.assertEqual(output.getvalue().splitlines(),
                         ["[0/8] Working", "[3/8] Working", "[8/8] Working", "[0/0] Working"])


def host_facts(memory=16384):
    return {"memory_mb": memory, "pools": ["tank", "zroot"], "available_gib": {"tank": 1024, "zroot": 1024},
            "interface": "em0", "address": "192.0.2.10", "dns": "192.0.2.53",
            "management_network": "198.51.100.0/24", "ssh_port": 22, "ssh_peer": ""}


def registered_config(facts):
    config = replace(initial_config(facts), storage_policy="",
                     **{name: getattr(Config(), name) for name in QUOTA_FIELDS})
    config.public_hostname = "first.example.test"
    config.admin_email = config.acme_email = "admin@example.test"
    return config.validate()


class ScriptedUI:
    def __init__(self, *, inputs=None, menus=None, confirmed=False):
        self.inputs = {"Public Nextcloud": "cloud.example.test", "Administrator email": "admin@example.test",
                       "Trusted reverse-proxy": "192.0.2.20/32", **(inputs or {})}
        self.menus = {"Review configuration": "accept", "Required Microsoft webfonts license": "accept",
                      "Nextcloud apps": "none",
                      "Choose individual ONLYOFFICE plugins": "done", **(menus or {})}
        self.confirmed = confirmed
        self.questions, self.messages, self.confirmations, self.defaults = [], [], [], {}

    def input(self, label, default=""):
        self.questions.append(label)
        self.defaults[label] = default
        for prefix, answer in self.inputs.items():
            if label.startswith(prefix):
                return answer.pop(0) if isinstance(answer, list) else answer
        return str(default)

    def menu(self, title, choices, default=None):
        self.questions.append(title)
        self.defaults[title] = default
        answer = self.menus.get(title, default)
        return answer.pop(0) if isinstance(answer, list) else answer

    def confirm(self, message):
        self.confirmations.append(message)
        return self.confirmed

    def message(self, text):
        self.messages.append(text)


class WizardTests(unittest.TestCase):
    def run_wizard(self, ui, *, facts=None, existing=None, registered=()):
        with patch("sys.stdin.isatty", return_value=True), patch("sys.stdout.isatty", return_value=True):
            return configure(facts or host_facts(), existing, registered, ui=ui)

    def test_storage_limits_default_explicit_cap_and_retained_retry(self):
        ui = ScriptedUI(menus={"HTTPS termination": "external", "Review configuration": ["edit", "accept"]})
        c = self.run_wizard(ui)
        self.assertEqual(ui.defaults["Storage limits"], "none")
        self.assertEqual(c.storage_policy, "optional")
        self.assertTrue(all(getattr(c, name) == 0 for name in QUOTA_FIELDS))
        self.assertEqual(ui.questions.count("Storage limits"), 2)
        caps_ui = ScriptedUI(inputs={"Nextcloud user data": "75"}, menus={"Storage limits": "caps"})
        capped = self.run_wizard(caps_ui, existing=c)
        self.assertEqual((capped.storage_policy, capped.data_quota_gib), ("optional", 75))
        for name in ("MariaDB data", "Upload/temporary data", "Each ONLYOFFICE working-data dataset",
                     "Each service/database log dataset", "Combined jail-root cap"):
            self.assertEqual(caps_ui.defaults[name + " (GiB; 0 = no quota)"], 0)
        retained = self.run_wizard(ScriptedUI(), existing=capped)
        self.assertEqual(retained.data_quota_gib, 75)
        self.assertEqual(c.data_quota_gib, 0)

    def test_explicit_no_quotas_clears_all_caps_and_retries_retain_entries(self):
        ui = ScriptedUI(inputs={"Nextcloud user data": "75", "MariaDB data": "9"},
                        menus={"HTTPS termination": "external", "Storage limits": ["caps", "none"],
                               "Review configuration": ["edit", "accept"]})
        c = self.run_wizard(ui)
        self.assertEqual(c.storage_policy, "optional")
        self.assertTrue(all(getattr(c, name) == 0 for name in QUOTA_FIELDS))
        existing = registered_config(host_facts())
        retry_ui = ScriptedUI(menus={"HTTPS termination": "external"})
        retained = self.run_wizard(retry_ui, existing=existing)
        self.assertEqual(retry_ui.defaults["Storage limits"], "caps")
        self.assertEqual((retained.data_quota_gib, retained.system_quota_gib), (100, 32))
        self.assertEqual(retained.storage_policy, "")
        cleared = self.run_wizard(ScriptedUI(menus={"HTTPS termination": "external", "Storage limits": "none"}),
                                  existing=existing)
        self.assertEqual(cleared.storage_policy, "optional")
        self.assertTrue(all(getattr(cleared, name) == 0 for name in QUOTA_FIELDS))

    def test_additional_instances_have_optional_limits_without_profiles(self):
        first = registered_config(host_facts())
        ui = ScriptedUI()
        menu = ui.menu
        def bounded_menu(title, choices, default=None):
            if title == "Storage limits":
                self.assertEqual([key for key, _ in choices], ["none", "caps"])
            return menu(title, choices, default)
        ui.menu = bounded_menu
        c = self.run_wizard(ui, registered=[first])
        self.assertEqual(c.storage_policy, "optional")
        self.assertTrue(all(getattr(c, name) == 0 for name in QUOTA_FIELDS))
        self.assertNotIn("Storage profile", ui.questions)

    def test_optional_caps_survive_validation_retry_without_capacity_recalculation(self):
        ui = ScriptedUI(inputs={"Nextcloud user data": "75", "MariaDB data": ["-1", "7"],
                                "Combined jail-root cap": "2"},
                        menus={"HTTPS termination": "external", "Storage limits": "caps"})
        c = self.run_wizard(ui)
        self.assertEqual((c.data_quota_gib, c.database_quota_gib, c.system_quota_gib), (75, 7, 2))
        self.assertEqual(c.storage_policy, "optional")
        self.assertEqual(ui.questions.count("Storage limits"), 2)
        self.assertEqual(ui.defaults["Nextcloud user data (GiB; 0 = no quota)"], 75)
        self.assertTrue(any("Configuration needs correction" in message for message in ui.messages))

    def test_native_storage_facts_precede_recommendations_without_summing_ancestors(self):
        facts = host_facts()
        gib = 1024 ** 3
        facts["available_gib"]["tank"] = 60
        properties = {"used": 20 * gib, "available": 60 * gib, "referenced": 10 * gib,
                      "usedbysnapshots": 3 * gib, "quota": 80 * gib, "refquota": 0,
                      "reservation": 0, "refreservation": 0}
        facts["storage"] = {"tank": {"health": "ONLINE", "size": 100 * gib, "allocated": 40 * gib,
                                     "free": 60 * gib, "datasets": {"tank": properties,
                                     "tank/cloud-installer": properties}}}
        ui = ScriptedUI(menus={"HTTPS termination": "external"})
        menu = ui.menu
        def inspected_menu(title, choices, default=None):
            if title == "Storage limits":
                self.assertIn("Native storage inspection", ui.messages[-2])
                self.assertIn("actual destination storage", ui.messages[-1])
                self.assertIn("not a quota recommendation or a fit guarantee", ui.messages[-1])
                self.assertIn("jail bases, packages, fonts, database, uploads, updates and snapshots", ui.messages[-1])
                self.assertNotIn("Finite service planning allowance", "\n".join(ui.messages))
            return menu(title, choices, default)
        ui.menu = inspected_menu
        self.run_wizard(ui, facts=facts)
        messages = "\n".join(ui.messages)
        for text in ("health ONLINE", "free 60.0 GiB", "quota=80.0 GiB", "snapshots 3.0 GiB",
                     "do not sum"):
            self.assertIn(text, messages)
        self.assertNotIn("snapshots 6.0 GiB", messages)
        self.assertNotIn("14.1/16 GiB", messages)
        self.assertNotIn("48 GiB service root allowance", messages)
        fallback = ScriptedUI(menus={"HTTPS termination": "external"})
        self.run_wizard(fallback)
        self.assertTrue(any("inspection unavailable" in message for message in fallback.messages))
        self.assertFalse(any("Native storage inspection:" in message for message in fallback.messages))

    def test_new_instance_defaults_respect_registered_allocations_and_capacity(self):
        facts = host_facts()
        first = registered_config(facts)
        first.jail_ssh = True
        second = initial_config(facts, [first])
        self.assertNotEqual(first.instance, second.instance)
        self.assertFalse(first.network.overlaps(second.network))
        self.assertFalse({first.nextcloud_bridge, first.onlyoffice_bridge} & {second.nextcloud_bridge, second.onlyoffice_bridge})
        self.assertFalse(set(first.ingress_ports) & set(second.ingress_ports))
        self.assertNotIn(second.ssh_nextcloud_port, first.ingress_ports)
        self.assertNotIn(second.ssh_onlyoffice_port, first.ingress_ports)
        self.assertEqual(second.tls_mode, "external")
        self.assertGreaterEqual(second.http_port, 8080)
        self.assertEqual(second.pool, first.pool)
        self.assertLessEqual(first.host_reserved_mb + service_memory(first) + service_memory(second), facts["memory_mb"])
        with self.assertRaisesRegex(ValueError, "remains"):
            initial_config(facts, [first, second])

    def test_new_wizard_freezes_reviewed_version_defaults_in_saved_configuration(self):
        ui = ScriptedUI(menus={"HTTPS termination": "external"})
        config = self.run_wizard(ui)
        selected = defaults()
        for field in ("freebsd_release", "architecture", "nextcloud_min", "onlyoffice_min"):
            self.assertEqual(getattr(config, field), selected[field])
        self.assertEqual(config.nextcloud_exact, "")
        self.assertEqual(config.onlyoffice_exact, "")
        self.assertEqual(config.selected_onlyoffice_plugins,
                         tuple(slug for slug, _, _ in PLUGIN_CHOICES if slug != "wordpress"))
        self.assertEqual(ui.defaults["ONLYOFFICE plugins"], "standard")
        self.assertEqual(ui.defaults["Minimum Nextcloud stable version"], selected["nextcloud_min"])
        self.assertEqual(ui.defaults["Minimum ONLYOFFICE stable version"], selected["onlyoffice_min"])
        before = config.to_json()
        policy = load_policy()
        policy["defaults"]["nextcloud_min"] = "35.0.1"
        with patch("installer.versions.load_policy", return_value=policy):
            self.assertEqual(constraints(config)["nextcloud_min"], selected["nextcloud_min"])
            self.assertEqual(config.validate().to_json(), before)

    def test_initial_sizing_boundaries_keep_shared_policy_and_callback_capacity(self):
        for memory, expected in ((6592, (2048, 256, 64, 1536)),
                                 (8191, (2048, 256, 64, 1536)),
                                 (8192, (3072, 768, 128, 1536)),
                                 (16384, (3072, 768, 128, 1536)),
                                 (32768, (4096, 2048, 256, 3072))):
            with self.subTest(memory=memory):
                c = initial_config(host_facts(memory))
                self.assertEqual((c.office_memory_mb, c.db_buffer_mb, c.redis_memory_mb, c.php_budget_mb), expected)
                self.assertLessEqual(c.memory_budget_mb, memory)
                self.assertGreaterEqual(c.php_children - c.php_callback_children, 2)
                self.assertGreaterEqual(c.php_callback_children, 1)
        with self.assertRaisesRegex(ValueError, "at least 4544 MiB"):
            initial_config(host_facts(6591))

    def test_initial_sizing_accounts_for_selected_apps_without_changing_legacy_defaults(self):
        facts = host_facts(11000)
        legacy = initial_config(facts)
        selected = initial_config(facts, nextcloud_apps=DEFAULT_NEXTCLOUD_APPS)
        self.assertEqual(legacy.nextcloud_apps, "")
        self.assertEqual(Config().nextcloud_apps, "")
        self.assertEqual(selected.nextcloud_apps, DEFAULT_NEXTCLOUD_APPS)
        self.assertEqual((selected.office_memory_mb, selected.db_buffer_mb,
                          selected.redis_memory_mb, selected.php_budget_mb), (2048, 256, 64, 1536))
        self.assertEqual(selected.antivirus_memory_mb, 3072)
        self.assertLessEqual(selected.memory_budget_mb, facts["memory_mb"])
        self.assertGreaterEqual(selected.php_children, 3)
        with self.assertRaisesRegex(ValueError, "at least 4544 MiB"):
            initial_config(host_facts(8192), nextcloud_apps=DEFAULT_NEXTCLOUD_APPS)

    def test_8gib_wizard_guides_explicit_app_adjustment_before_sizing_without_quotas(self):
        ui = ScriptedUI(menus={"HTTPS termination": "external", "Nextcloud apps": ["all", "custom"],
                               "Choose individual Nextcloud apps": ["files_antivirus", "done"]})
        c = self.run_wizard(ui, facts=host_facts(8192))
        self.assertEqual(set(c.selected_nextcloud_apps), set(DEFAULT_NEXTCLOUD_APPS.split(",")) - {"files_antivirus"})
        self.assertEqual(c.antivirus_memory_mb, 0)
        self.assertEqual(c.memory_budget_mb, 8192)
        self.assertEqual(c.storage_policy, "optional")
        self.assertTrue(all(getattr(c, name) == 0 for name in QUOTA_FIELDS))
        self.assertEqual(ui.questions.count("Nextcloud apps"), 2)  # Repeated all needs explicit correction.
        self.assertLess(ui.questions.index("Nextcloud apps"),
                        ui.questions.index("Instance name (1–8 lowercase letters/digits, starting with a letter)"))
        self.assertTrue(any("No apps will be deselected automatically" in text for text in ui.messages))
        self.assertFalse(any("Configuration needs correction" in text for text in ui.messages))

    def test_sufficient_host_keeps_all_default_apps_with_one_normal_chooser(self):
        for memory in (11000, 16384, 32768):
            with self.subTest(memory=memory):
                ui = ScriptedUI(menus={"HTTPS termination": "external", "Nextcloud apps": "all"})
                c = self.run_wizard(ui, facts=host_facts(memory))
                self.assertEqual(c.nextcloud_apps, DEFAULT_NEXTCLOUD_APPS)
                self.assertEqual(c.antivirus_memory_mb, 3072)
                self.assertLessEqual(c.memory_budget_mb, memory)
                self.assertEqual(ui.defaults["Nextcloud apps"], "all")
                self.assertEqual(ui.questions.count("Nextcloud apps"), 1)
                self.assertGreater(ui.questions.index("Nextcloud apps"), ui.questions.index("ONLYOFFICE plugins"))

    def test_early_app_selection_survives_retry_and_existing_selections_are_not_replaced(self):
        ui = ScriptedUI(menus={"HTTPS termination": "external", "Nextcloud apps": "custom",
                               "Choose individual Nextcloud apps": ["files_antivirus", "done", "done"],
                               "Review configuration": ["edit", "accept"]})
        c = self.run_wizard(ui, facts=host_facts(8192))
        self.assertNotIn("files_antivirus", c.selected_nextcloud_apps)
        self.assertEqual(len(c.selected_nextcloud_apps), 7)
        self.assertEqual(ui.defaults["Nextcloud apps"], "custom")
        self.assertEqual(ui.questions.count("Nextcloud apps"), 2)
        for apps in ("calendar,contacts", "none", ""):
            with self.subTest(apps=apps):
                existing = replace(c, nextcloud_apps=apps)
                before = existing.to_json()
                # For the legacy omission, choosing None keeps its historical empty encoding.
                retained_ui = ScriptedUI(menus={"Nextcloud apps": "custom" if apps else "none",
                                               "Choose individual Nextcloud apps": "done"})
                retained = self.run_wizard(retained_ui, facts=host_facts(8192), existing=existing)
                self.assertEqual(retained.nextcloud_apps, apps)
                self.assertEqual(existing.to_json(), before)
                self.assertEqual(retained_ui.questions.count("Nextcloud apps"), 1)

    def test_storage_defaults_are_uncapped_independent_of_destination_capacity(self):
        for available in (1, 60, 90, 1024, 100_000):
            with self.subTest(available=available):
                facts = host_facts()
                facts["available_gib"] = {"tank": available, "zroot": available}
                c = initial_config(facts)
                self.assertEqual(c.font_profile, "comprehensive")
                self.assertEqual(c.storage_policy, "optional")
                self.assertTrue(all(getattr(c, name) == 0 for name in QUOTA_FIELDS))
                ui = ScriptedUI(menus={"HTTPS termination": "external"})
                configured = self.run_wizard(ui, facts=facts)
                self.assertTrue(all(getattr(configured, name) == 0 for name in QUOTA_FIELDS))

    def test_old_small_comprehensive_config_is_readable_but_not_a_new_provisioning_plan(self):
        old = replace(registered_config(host_facts()), system_quota_gib=24)
        text = old.to_json()
        loaded = Config.from_json(text)
        self.assertEqual(loaded.to_json(), text)  # Never retrofit saved configs/digests.
        with self.assertRaisesRegex(ValueError, "at least 32 GiB"):
            loaded.validate_provisioning()
        self.assertIsNotNone(replace(loaded, font_profile="standard").validate_provisioning())

    def test_initial_review_can_keep_budgets_without_advanced_questions_or_host_commands(self):
        ui = ScriptedUI(menus={"HTTPS termination": "external"})
        with patch("subprocess.run") as run:
            c = self.run_wizard(ui)
        run.assert_not_called()
        self.assertEqual(ui.defaults["Resource budgets"], "keep")
        for label in ("Host and ZFS ARC reserve", "ONLYOFFICE budget", "PHP worker pool budget", "PHP upload chunk limit"):
            self.assertNotIn(label, ui.questions)
        messages = "\n".join(ui.messages)
        for text in ("16384 MiB detected RAM", "4096 MiB host/ZFS reserve",
                     "0 MiB reserved by 0 other instance(s)", "selected 6144 MiB",
                     "6144 MiB left unallocated", "3 workers (2 web + 1 office callback)",
                     "not enforced memory limits", "Upload chunk limit: 1024 MiB",
                       "no installer quotas", "not a full growth bound", "temporary-data quota: no quota", "before first startup"):
            self.assertIn(text, messages)
        self.assertEqual(c.php_budget_mb, 1536)

    def test_advanced_initial_budgets_are_reviewed_and_round_trip_without_new_schema(self):
        ui = ScriptedUI(inputs={"Host and ZFS ARC reserve": "5120", "PHP worker pool budget": "3072",
                                "PHP per-request memory limit": "768", "PHP upload chunk limit": "2048"},
                        menus={"HTTPS termination": "external", "Resource budgets": "edit"})
        c = self.run_wizard(ui)
        saved = Config.from_json(c.to_json())
        self.assertEqual((saved.host_reserved_mb, saved.php_budget_mb, saved.php_memory_mb, saved.upload_max_mb),
                         (5120, 3072, 768, 2048))
        messages = "\n".join(ui.messages)
        for text in ("5120 MiB host/ZFS reserve", "selected 7680 MiB", "3584 MiB left unallocated",
                     "4 workers (2 web + 2 office callback)", "Upload chunk limit: 2048 MiB"):
            self.assertIn(text, messages)

    def test_existing_draft_keeps_saved_budgets_and_font_selection_on_larger_host(self):
        existing = registered_config(host_facts())
        existing.font_profile = "standard"
        existing.php_budget_mb, existing.php_memory_mb, existing.upload_max_mb = 3072, 768, 2048
        before = existing.to_json()
        ui = ScriptedUI(menus={"HTTPS termination": "external"})
        c = self.run_wizard(ui, facts=host_facts(65536), existing=existing)
        self.assertEqual((c.php_budget_mb, c.php_memory_mb, c.upload_max_mb), (3072, 768, 2048))
        self.assertEqual(c.font_profile, "standard")
        self.assertEqual(ui.defaults["Font packages"], "standard")
        self.assertEqual(existing.to_json(), before)

    def test_invalid_retained_budget_can_be_corrected_without_review_division_by_zero(self):
        ui = ScriptedUI(inputs={"PHP per-request memory limit": ["0", "512"]},
                        menus={"HTTPS termination": "external", "Resource budgets": "edit"})
        c = self.run_wizard(ui)
        self.assertEqual(c.php_memory_mb, 512)
        self.assertTrue(any("Configuration needs correction" in text for text in ui.messages))
        self.assertTrue(any("invalid worker budget/limit" in text for text in ui.messages))

    def test_wizard_preserves_explicit_constraints_and_clears_pins_only_on_request(self):
        existing = registered_config(host_facts())
        existing.nextcloud_min, existing.onlyoffice_min = "35.0.0", "9.4.0"
        existing.nextcloud_exact, existing.onlyoffice_exact = "35.0.1", "9.4.0_4"
        preserved = self.run_wizard(ScriptedUI(menus={"HTTPS termination": "external"}), existing=existing)
        self.assertEqual(preserved.nextcloud_exact, "35.0.1")
        self.assertEqual(preserved.onlyoffice_exact, "9.4.0_4")
        cleared = self.run_wizard(ScriptedUI(inputs={"Optional exact Nextcloud": "-",
                                                   "Optional exact ONLYOFFICE": "-"}), existing=preserved)
        self.assertEqual(cleared.nextcloud_exact, "")
        self.assertEqual(cleared.onlyoffice_exact, "")
        self.assertEqual(existing.nextcloud_exact, "35.0.1")
        self.assertEqual(existing.onlyoffice_exact, "9.4.0_4")

    def test_detected_networks_and_bridge_names_are_avoided(self):
        facts = host_facts()
        facts["networks"] = ["10.77.0.0/16", "2001:db8::/64"]
        facts["bridges"] = ["bridge240", "bridge241"]
        config = initial_config(facts)
        self.assertTrue(config.private_network.startswith("172.30."))
        self.assertEqual((config.nextcloud_bridge, config.onlyoffice_bridge), ("bridge242", "bridge243"))

    def test_removed_names_stay_reserved_while_shared_host_settings_are_reused(self):
        facts = host_facts()
        facts["reserved_instances"] = ["cloud", "cloud2"]
        facts["managed_host"] = {"pool": "zroot", "external_interface": "em1", "management_network": "203.0.113.0/24",
                                 "management_port": 2222, "host_reserved_mb": 2048}
        config = initial_config(facts)
        self.assertEqual(config.instance, "cloud3")
        self.assertEqual((config.external_interface, config.management_port, config.host_reserved_mb), ("em1", 2222, 2048))

    def test_additional_instance_reuses_shared_settings_and_optional_external_dns(self):
        facts = host_facts()
        first = registered_config(facts)
        changed_facts = {**facts, "interface": "em1", "management_network": "203.0.113.0/24", "ssh_port": 2222}
        ui = ScriptedUI(inputs={"Nextcloud jail hostname": "team-nc.example.test", "ONLYOFFICE jail hostname": "team-office",
                                "Public HTTPS port": "8443"})
        config = self.run_wizard(ui, facts=changed_facts, registered=[first])
        self.assertEqual((config.pool, config.external_interface, config.management_network, config.management_port),
                         (first.pool, first.external_interface, first.management_network, first.management_port))
        self.assertEqual((config.nextcloud_hostname, config.onlyoffice_hostname), ("team-nc.example.test", "team-office"))
        self.assertEqual(config.dns_address, "")
        self.assertEqual(config.public_url, "https://cloud.example.test:8443/")
        for label in ("Existing ZFS pool", "Host uplink interface", "IPv4 CIDR allowed to SSH to the host", "Host SSH port"):
            self.assertNotIn(label, ui.questions)
        self.assertTrue(any("6144 MiB remains" in text for text in ui.messages))

    def test_another_assigned_ipv4_defaults_to_direct_acme(self):
        facts = host_facts()
        first = registered_config(facts)
        ui = ScriptedUI(inputs={"IPv4 on the host uplink": "192.0.2.11"}, confirmed=True)
        config = self.run_wizard(ui, facts=facts, registered=[first])
        self.assertEqual((config.tls_mode, config.http_port, config.https_port), ("acme", 80, 443))
        self.assertEqual(config.dns_address, "192.0.2.11")

    def test_ssh_is_unprivileged_by_default_and_admin_requires_consent(self):
        for privileges, consent, expected in (("user", False, False), ("admin", False, False), ("admin", True, True)):
            ui = ScriptedUI(inputs={"Jail SSH username": "cloudops", "Absolute path to PUBLIC": "/root/operator.pub"},
                            menus={"HTTPS termination": "external", "SSH into both jails": "on", "Jail login shell": "zsh",
                                   "Jail SSH privileges": privileges}, confirmed=consent)
            config = self.run_wizard(ui)
            self.assertTrue(config.jail_ssh)
            self.assertEqual(config.ssh_admin, expected)
            self.assertEqual(config.ssh_shell, "zsh")
            self.assertEqual(ui.defaults["Jail SSH privileges"], "user")
            self.assertEqual(any("doas" in question for question in ui.confirmations), privileges == "admin")

    def test_disabling_ssh_clears_admin_and_does_not_mutate_existing_config(self):
        existing = registered_config(host_facts())
        existing.jail_ssh, existing.ssh_admin, existing.ssh_key_file = True, True, "/root/operator.pub"
        ui = ScriptedUI(menus={"HTTPS termination": "external", "SSH into both jails": "off"})
        config = self.run_wizard(ui, existing=existing)
        self.assertFalse(config.jail_ssh)
        self.assertFalse(config.ssh_admin)
        self.assertEqual(config.ssh_key_file, "")
        self.assertTrue(existing.jail_ssh)
        self.assertTrue(existing.ssh_admin)

    def test_aggregate_overcommit_is_corrected_before_accepting(self):
        facts = host_facts()
        first = registered_config(facts)
        ui = ScriptedUI(inputs={"PHP worker pool budget": ["20000", "1024", "1536"]},
                        menus={"Resource budgets": "edit"})
        config = self.run_wizard(ui, registered=[first])
        self.assertEqual(config.php_budget_mb, 1536)
        self.assertTrue(any("at least 3 PHP workers" in text for text in ui.messages))
        self.assertTrue(any("exceed installed RAM" in text for text in ui.messages))

    def test_fonts_and_optional_paths_are_saved(self):
        ui = ScriptedUI(inputs={"Optional absolute directory": "/root/company fonts"},
                        menus={"HTTPS termination": "external", "Font packages": "standard"})
        config = self.run_wizard(ui)
        self.assertEqual(config.font_profile, "standard")
        self.assertTrue(config.accept_microsoft_fonts)
        self.assertEqual(config.additional_fonts_dir, "/root/company fonts")
        ui = ScriptedUI(inputs={"Optional absolute directory": "-"}, menus={"HTTPS termination": "external"})
        self.assertEqual(self.run_wizard(ui, existing=config).additional_fonts_dir, "")

    def test_font_default_cost_guidance_is_dated_optional_and_not_a_live_quote(self):
        ui = ScriptedUI(menus={"HTTPS termination": "external"})
        c = self.run_wizard(ui)
        self.assertEqual(c.font_profile, "comprehensive")
        self.assertEqual(ui.defaults["Font packages"], "comprehensive")
        for text in ("optional", "2026-10-18", "2 GiB download / 4 GiB", "not an exact cost", "both profiles"):
            self.assertTrue(any(text in message for message in ui.messages), text)
        self.assertIn("Dated estimate", deployment_plan(c))
        c.font_profile = "standard"
        self.assertNotIn("Dated estimate", deployment_plan(c))
        self.assertIn("NOT accepted", deployment_plan(replace(c, accept_microsoft_fonts=False)))

    def test_font_choice_labels_show_static_measured_size(self):
        ui = ScriptedUI(menus={"HTTPS termination": "external"})
        original = ui.menu
        labels = {}
        def menu(title, choices, default=None):
            if title == "Font packages":
                labels.update(choices)
            return original(title, choices, default)
        ui.menu = menu
        self.run_wizard(ui)
        self.assertEqual(labels, {
            "comprehensive": "Comprehensive: wider script and document coverage (~+4 GiB installed vs standard)",
            "standard": "Standard: smaller font set (baseline)",
        })

    def test_plugins_all_custom_and_none_round_trip_through_wizard(self):
        ui = ScriptedUI(menus={"HTTPS termination": "external", "ONLYOFFICE plugins": "all"})
        config = self.run_wizard(ui)
        self.assertEqual(config.selected_onlyoffice_plugins, tuple(slug for slug, _, _ in PLUGIN_CHOICES))
        self.assertEqual(len(config.selected_onlyoffice_plugins), 10)
        self.assertTrue(any("External providers may receive selected content" in text for text in ui.messages))
        ui = ScriptedUI(menus={"ONLYOFFICE plugins": "custom",
                              "Choose individual ONLYOFFICE plugins": ["none", "zotero", "ocr", "zotero", "youtube", "done"]})
        custom = self.run_wizard(ui, existing=config)
        self.assertEqual(custom.onlyoffice_plugins, "ocr,youtube")
        self.assertEqual(len(config.selected_onlyoffice_plugins), 10)
        preserved = self.run_wizard(ScriptedUI(), existing=custom)
        self.assertEqual(preserved.onlyoffice_plugins, "ocr,youtube")
        cleared = self.run_wizard(ScriptedUI(menus={"ONLYOFFICE plugins": "none"}), existing=custom)
        self.assertEqual(cleared.onlyoffice_plugins, "")

    def test_standard_plugins_default_without_changing_saved_empty_selection(self):
        config = self.run_wizard(ScriptedUI(menus={"HTTPS termination": "external"}))
        self.assertEqual(len(config.selected_onlyoffice_plugins), 9)
        self.assertNotIn("wordpress", config.selected_onlyoffice_plugins)
        self.assertNotIn("macros", config.selected_onlyoffice_plugins)
        self.assertNotIn("easybib", config.selected_onlyoffice_plugins)
        cleared = self.run_wizard(ScriptedUI(menus={"ONLYOFFICE plugins": "none"}), existing=config)
        ui = ScriptedUI()
        saved = self.run_wizard(ui, existing=cleared)
        self.assertEqual(saved.onlyoffice_plugins, "")
        self.assertEqual(ui.defaults["ONLYOFFICE plugins"], "none")

    def test_individual_plugin_toggles_work_in_plain_ui_and_can_cancel(self):
        ui = TerminalUI(plain=True)
        with patch("builtins.input", side_effect=["custom", "ocr", "youtube", "ocr", "done"]), \
                redirect_stdout(io.StringIO()) as output:
            self.assertEqual(select_onlyoffice_plugins(ui=ui), "youtube")
        self.assertIn("[ ] OCR", output.getvalue())
        self.assertIn("[x] OCR", output.getvalue())
        self.assertIn("[x] YouTube", output.getvalue())
        with patch("builtins.input", side_effect=["custom", "all", "done"]), redirect_stdout(io.StringIO()):
            self.assertEqual(len(select_onlyoffice_plugins(ui=ui).split(",")), 10)
        for answers in (["0"], ["custom", "ocr", "0"]):
            with patch("builtins.input", side_effect=answers), redirect_stdout(io.StringIO()):
                with self.assertRaises(KeyboardInterrupt):
                    select_onlyoffice_plugins(ui=ui)

    def test_required_font_license_defaults_to_decline_and_can_cancel(self):
        ui = ScriptedUI(menus={"HTTPS termination": "external", "Required Microsoft webfonts license": "decline"})
        with self.assertRaises(KeyboardInterrupt):
            self.run_wizard(ui)
        self.assertEqual(ui.defaults["Required Microsoft webfonts license"], "decline")
        self.assertNotIn("Review configuration", ui.questions)

    def test_secret_schema_stays_private_and_invalid_passwords_retry(self):
        ui = Mock()
        ui.secret.side_effect = ["short", "long-but-mismatched-1", "long-but-mismatched-2", "valid synthetic password", "valid synthetic password"]
        credentials = create_secrets(ui=ui)
        self.assertEqual(set(credentials), {"admin_password", "db_password", "jwt_secret"})
        self.assertEqual(credentials["admin_password"], "valid synthetic password")
        self.assertRegex(credentials["db_password"], r"^[0-9a-f]{64}$")
        self.assertRegex(credentials["jwt_secret"], r"^[0-9a-f]{64}$")
        self.assertNotIn("valid synthetic password", str(ui.message.call_args_list))
        ui.secret.side_effect = [""]
        self.assertGreaterEqual(len(create_secrets(ui=ui)["admin_password"]), 24)

    def test_generated_credentials_need_no_password_prompt_and_are_not_displayed(self):
        ui = Mock()
        first = create_secrets(ui=ui, generate=True)
        second = create_secrets(ui=ui, generate=True)
        ui.secret.assert_not_called()
        self.assertNotEqual(first, second)
        self.assertGreaterEqual(len(first["admin_password"]), 24)
        self.assertEqual(len(first["db_password"]), 64)
        self.assertEqual(len(first["jwt_secret"]), 64)
        for value in first.values():
            self.assertNotIn(value, repr(ui.message.call_args_list))


if __name__ == "__main__":
    unittest.main()
