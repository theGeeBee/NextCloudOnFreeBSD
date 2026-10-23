"""CLI state transitions and approval gates with mocked terminal/host execution."""

from contextlib import ExitStack
from dataclasses import replace
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from installer.config import Config
from installer.host import require_host
from installer.main import load_config_file, load_secrets, main, menu, show_status, launch_selected_install
from installer.state import Registry, atomic_json, atomic_write, private_json, config_digest
from version_fixtures import (LEGACY_CONFIG_JSON, LEGACY_CONFIG_SHA256,
                              discovery_metadata, resolved_plan)


class Terminal(io.StringIO):
    def __init__(self, interactive=True):
        super().__init__()
        self.interactive = interactive

    def isatty(self):
        return self.interactive


class MainTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="main-tests-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.registry = Registry(self.directory / "registry")
        self.registry.initialize()
        self.config = Config(public_hostname="cloud.example.test", admin_email="admin@example.test",
                             acme_email="admin@example.test", external_interface="igb0", ingress_address="192.0.2.10",
                             dns_server="192.0.2.53", management_network="198.51.100.0/24")
        self.secrets = {"admin_password": "private-admin-password", "db_password": "a" * 64, "jwt_secret": "b" * 64}
        self.runner = Mock(spec=["run", "output"])
        self.ui = Mock()
        self.ui.confirm.return_value = False
        self.ui.input.return_value = ""
        self.stdin, self.stdout = Terminal(), Terminal()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch("installer.main.sys.stdin", self.stdin))
        self.stack.enter_context(patch("installer.main.sys.stdout", self.stdout))
        self.runner_factory = self.stack.enter_context(patch("installer.main.Runner", return_value=self.runner))
        self.host = self.stack.enter_context(patch("installer.main.require_host"))
        self.registry_factory = self.stack.enter_context(patch("installer.main.Registry", return_value=self.registry))
        self.ui_factory = self.stack.enter_context(patch("installer.main.TerminalUI", return_value=self.ui))
        self.inspect = self.stack.enter_context(patch("installer.main.inspect_host", return_value={"ssh_connection": None}))
        self.preflight = self.stack.enter_context(patch("installer.main.preflight"))
        self.configure = self.stack.enter_context(patch("installer.main.configure", return_value=self.config))
        self.create_secrets = self.stack.enter_context(patch("installer.main.create_secrets", return_value=self.secrets))
        self.factory = self.stack.enter_context(patch("installer.main.Deployment"))
        self.deployment = self.factory.return_value
        self.deployment.prepare_versions.return_value = {"applications": {"nextcloud": "35.0.0", "onlyoffice": "9.4.0_4"}}

    def register(self, state="configured", config=None):
        config = config or self.config
        path = self.registry.save_new(config, self.secrets)
        self.registry.set_status(config.instance, state)
        return path

    def recipe(self, **changes):
        path = self.directory / "recipe with spaces.json"
        path.write_text(replace(self.config, **changes).to_json())
        return path

    def test_vm_recipes_dispatch_install_resume_verify_and_keep_native_backup_fence(self):
        for backend,instance in (('eurooffice','euro'),('collabora','code')):
            with self.subTest(backend=backend):
                self.create_secrets.reset_mock();self.deployment.reset_mock()
                self.ui.message.reset_mock()
                credentials={k:v for k,v in self.secrets.items() if backend=='eurooffice' or k!='jwt_secret'}
                self.create_secrets.return_value=credentials
                path=self.recipe(office_backend=backend,instance=instance,storage_policy='optional',
                                 office_memory_mb=4096,office_vm_cpus=2,office_vm_disk_gib=16)
                self.assertEqual(main(['install','--config',str(path),'--yes','--accept-acme-terms']),0)
                self.create_secrets.assert_called_once_with(ui=self.ui,generate=True,backend=backend)
                self.deployment.apply.assert_called_once()
                saved=self.registry.load(instance)
                self.assertEqual(saved.backend,backend);self.assertEqual(saved.jails,(saved.nextcloud_jail,))
                self.assertEqual(load_secrets(self.registry.instance_path(instance)/'secrets.json',backend=backend),credentials)
                messages='\n'.join(call.args[0] for call in self.ui.message.call_args_list)
                self.assertIn('dedicated office VM',messages)
                self.assertNotIn('no integrated document server',messages)
                self.assertNotIn(credentials['admin_password'],messages)
                self.deployment.reset_mock()
                self.ui.input.return_value='APPLY'
                self.assertEqual(main(['resume',instance]),0)
                self.deployment.apply.assert_called_once()
                self.registry.set_status(instance,'ready')
                self.deployment.reset_mock()
                self.assertEqual(main(['verify',instance]),0)
                self.deployment.verify.assert_called_once();self.deployment.apply.assert_not_called()
                with self.assertRaisesRegex(ValueError,'not yet supported'),patch('installer.operations.backup_database') as backup:
                    main(['backup',instance])
                backup.assert_not_called()

    def test_none_recipe_install_uses_one_jail_without_font_consent_or_jwt(self):
        path = self.recipe(office_backend="none", private_network="10.77.0.0/30",
                           storage_policy="optional", accept_microsoft_fonts=False)
        credentials = {key: self.secrets[key] for key in ("admin_password", "db_password")}
        self.create_secrets.return_value = credentials
        self.assertEqual(main(["install", "--config", str(path), "--yes", "--accept-acme-terms"]), 0)
        self.create_secrets.assert_called_once_with(ui=self.ui, generate=True, backend="none")
        self.preflight.assert_called_once()
        self.deployment.apply.assert_called_once()
        saved = self.registry.load("cloud")
        self.assertEqual(saved.backend, "none")
        self.assertEqual(saved.jails, (saved.nextcloud_jail,))
        self.assertEqual(load_secrets(self.registry.instance_path("cloud") / "secrets.json", backend="none"), credentials)
        messages = "\n".join(call.args[0] for call in self.ui.message.call_args_list)
        self.assertNotIn("Microsoft", messages)
        self.assertNotIn("two jails", messages)
        self.assertIn("one Nextcloud jail", messages)
        self.assertIn("configure your own external server manually later", messages)

    def test_none_native_backup_refuses_before_credentials_or_deployment(self):
        config = replace(self.config, office_backend="none", private_network="10.77.0.0/30",
                         storage_policy="optional")
        self.register(state="ready", config=config)
        with patch("installer.main.load_secrets") as credentials:
            with self.assertRaisesRegex(ValueError, "not yet supported"):
                main(["backup", "cloud"])
        credentials.assert_not_called()
        self.factory.assert_not_called()

    def test_none_saved_commands_load_jwt_free_credentials_and_dispatch_only_requested_action(self):
        config = replace(self.config, office_backend="none", private_network="10.77.0.0/30",
                         storage_policy="optional")
        credentials = {key: self.secrets[key] for key in ("admin_password", "db_password")}
        state = self.registry.save_new(config, credentials)
        for command in ("resume", "verify", "add-user", "remove"):
            with self.subTest(command=command):
                self.registry.set_status("cloud", "configured" if command == "resume" else "ready")
                self.ui.input.return_value = "APPLY" if command == "resume" else "REMOVE cloud"
                self.factory.reset_mock()
                self.deployment.reset_mock()
                with patch("installer.main.add_user") as add_user, \
                        patch("installer.lifecycle.remove_instance") as remove:
                    self.assertEqual(main([command, "cloud"]), 0)
                selected, loaded = self.factory.call_args.args[:2]
                self.assertEqual(selected.backend, "none")
                self.assertEqual(loaded, credentials)
                if command == "resume":
                    self.deployment.apply.assert_called_once()
                elif command == "verify":
                    self.deployment.verify.assert_called_once()
                    self.deployment.apply.assert_not_called()
                elif command == "add-user":
                    add_user.assert_called_once_with(self.ui, self.deployment)
                    self.deployment.prepare_versions.assert_not_called()
                else:
                    remove.assert_called_once_with(self.deployment, purge_data=False, confirmation="REMOVE cloud")
        self.assertEqual(load_secrets(state / "secrets.json", backend="none"), credentials)

    def test_recipe_configure_uses_file_authoritatively_and_shared_preflight(self):
        path = self.recipe(accept_microsoft_fonts=True, font_profile="standard")
        self.ui.confirm.return_value = True  # ACME terms only, not the wizard.
        self.assertEqual(main(["configure", "--config", str(path)]), 0)
        self.configure.assert_not_called()
        self.preflight.assert_called_once()
        selected = self.preflight.call_args.args[0]
        self.assertEqual(selected.font_profile, "standard")
        self.assertEqual(self.registry.load(selected.instance).to_json(), selected.to_json())
        self.create_secrets.assert_called_once_with(ui=self.ui)
        self.factory.assert_not_called()
        self.assertEqual(path.read_text(), replace(self.config, accept_microsoft_fonts=True, font_profile="standard").to_json())

    def test_recipe_yes_generates_credentials_and_approves_apply_not_optional_user(self):
        path = self.recipe()
        self.assertEqual(main(["install", "--yes", "--accept-licenses", "--config", str(path),
                               "--accept-acme-terms"]), 0)
        self.configure.assert_not_called()
        self.ui.input.assert_not_called()
        self.ui.confirm.assert_not_called()
        self.create_secrets.assert_called_once_with(ui=self.ui, generate=True)
        self.deployment.apply.assert_called_once_with()
        self.assertTrue(self.preflight.call_args.args[0].accept_microsoft_fonts)
        messages = "\n".join(call.args[0] for call in self.ui.message.call_args_list)
        self.assertIn("corefonts.sourceforge.net/eula.htm", messages)
        self.assertIn("letsencrypt.org/repository", messages)
        self.assertIn("KEEP", messages)
        self.assertFalse(load_config_file(path).accept_microsoft_fonts)

    def test_recipe_missing_legal_consent_fails_before_saving_or_password(self):
        for fonts, flags, expected in ((False, [], "webfonts"),
                                      (True, [], "ACME")):
            with self.subTest(fonts=fonts):
                path = self.recipe(accept_microsoft_fonts=fonts)
                with self.assertRaisesRegex(ValueError, expected):
                    main(["install", "--config", str(path), "--yes", *flags])
        self.create_secrets.assert_not_called()
        self.preflight.assert_not_called()
        self.factory.assert_not_called()
        self.ui.confirm.assert_not_called()
        self.assertEqual(self.registry.entries(), [])

    def test_recipe_interactive_legal_decline_never_saves(self):
        path = self.recipe()
        with self.assertRaisesRegex(ValueError, "consent declined"):
            main(["configure", "--config", str(path)])
        self.configure.assert_not_called()
        self.create_secrets.assert_not_called()
        self.assertEqual(self.registry.entries(), [])

    def test_recipe_preflight_error_does_not_return_to_wizard(self):
        path = self.recipe(accept_microsoft_fonts=True)
        self.preflight.side_effect = ValueError("Host collision")
        self.ui.confirm.return_value = True
        with self.assertRaisesRegex(ValueError, "Host collision"):
            main(["configure", "--config", str(path)])
        self.configure.assert_not_called()
        self.create_secrets.assert_not_called()
        self.assertEqual(self.registry.entries(), [])

    def test_recipe_yes_still_requires_terminal(self):
        path = self.recipe(accept_microsoft_fonts=True)
        self.stdin.interactive = False
        with self.assertRaisesRegex(ValueError, "interactive terminal"):
            main(["install", "--config", str(path), "--yes", "--accept-acme-terms"])
        self.create_secrets.assert_not_called()
        self.factory.assert_not_called()

    def test_recipe_yes_does_not_authorize_ssh_administration(self):
        path = self.recipe(accept_microsoft_fonts=True, jail_ssh=True, ssh_admin=True,
                           ssh_key_file=str(self.directory / "authorized.pub"))
        with self.assertRaisesRegex(ValueError, "SSH administration consent declined"):
            main(["install", "--config", str(path), "--yes", "--accept-acme-terms"])
        self.ui.confirm.assert_called_once_with("Grant the selected SSH key root administration in both jails through doas?")
        self.create_secrets.assert_not_called()
        self.assertEqual(self.registry.entries(), [])

    def test_recipe_loader_retains_legacy_omission_semantics(self):
        path = self.directory / "legacy.json"
        path.write_text(LEGACY_CONFIG_JSON)
        self.assertEqual(load_config_file(path).to_json(), Config.from_json(LEGACY_CONFIG_JSON).to_json())

    def test_recipe_invalid_inputs_are_bounded_safe_and_precede_host_state(self):
        path = self.directory / "bad.json"
        sentinel = "PRIVATE-DO-NOT-ECHO"
        cases = ("[]", "{", '{"' + sentinel + '": true}',
                 '{"instance":"' + sentinel + '"}',
                 '{"instance":"cloud","instance":"' + sentinel + '"}',
                 " " * (1024 * 1024 + 1))
        for text in cases:
            path.write_text(text)
            with self.subTest(length=len(text)), self.assertRaises(ValueError) as caught:
                main(["install", "--config", str(path)])
            self.assertNotIn(sentinel, str(caught.exception))
        path.unlink()
        for target in (path, self.directory):
            with self.assertRaisesRegex(ValueError, "Cannot load configuration"):
                main(["configure", "--config", str(target)])
        self.host.assert_not_called()
        self.registry_factory.assert_not_called()
        self.runner_factory.assert_not_called()
        self.configure.assert_not_called()

    def test_recipe_reader_refuses_symlink_fifo_and_writable_file(self):
        import os
        path = self.recipe()
        link = self.directory / "link.json"
        link.symlink_to(path)
        fifo = self.directory / "fifo"
        os.mkfifo(fifo)
        for target in (link, fifo):
            with self.assertRaises(ValueError):
                load_config_file(target)
        path.chmod(0o666)
        with self.assertRaises(ValueError):
            load_config_file(path)

    def test_recipe_flag_scope_and_duplicates_fail_before_state(self):
        cases = (["install", "--yes"], ["install", "--accept-licenses"],
                 ["install", "--accept-acme-terms"], ["configure", "--yes"],
                 ["remove", "cloud", "--yes"],
                 ["install", "--config", "one", "--config", "two"],
                 ["install", "--yes", "--yes"])
        for args in cases:
            with self.subTest(args=args), patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit):
                main(args)
        self.host.assert_not_called()
        self.registry_factory.assert_not_called()

    def test_offline_plan_and_legacy_alias_bypass_host_and_state_on_linux(self):
        path = self.directory / "config with spaces.json"
        path.write_text(self.config.to_json())
        self.stdin.interactive = self.stdout.interactive = False
        before = {entry.relative_to(self.registry.root): entry.stat().st_mtime_ns
                  for entry in self.registry.root.rglob("*")}
        for command in ("plan", "--plan"):
            with self.subTest(command=command):
                self.assertEqual(main(["--plain", command, str(path)]), 0)
        self.assertIn("cloudnc", self.stdout.getvalue())
        self.assertIn("cloudoo", self.stdout.getvalue())
        self.host.assert_not_called()
        self.runner_factory.assert_not_called()
        self.registry_factory.assert_not_called()
        self.ui_factory.assert_not_called()
        self.factory.assert_not_called()
        self.assertEqual({entry.relative_to(self.registry.root): entry.stat().st_mtime_ns
                          for entry in self.registry.root.rglob("*")}, before)

    def test_lifecycle_status_is_noninteractive_and_does_not_lock_or_initialize(self):
        self.stdin.interactive = self.stdout.interactive = False
        with patch.object(self.registry, "locked") as locked, patch.object(self.registry, "initialize") as initialize:
            self.assertEqual(main(["maintenance", "status"]), 0)
        locked.assert_not_called()
        initialize.assert_not_called()
        self.factory.assert_not_called()
        self.runner.run.assert_not_called()
        self.assertIn('"lifecycle": "legacy"', self.ui.message.call_args.args[0])

    def test_enrollment_requires_terminal_and_exact_confirmation_before_any_change(self):
        self.stdin.interactive = self.stdout.interactive = False
        with self.assertRaisesRegex(ValueError, "interactive terminal"):
            main(["maintenance", "register", "cloud"])
        self.stdin.interactive = self.stdout.interactive = True
        with patch.object(self.registry, "locked") as locked:
            with self.assertRaisesRegex(ValueError, "ENROLL NAME"):
                main(["maintenance", "register", "cloud"])
        locked.assert_not_called()
        self.factory.assert_not_called()
        self.runner.run.assert_not_called()

    def test_pending_first_enrollment_blocks_all_current_native_mutations(self):
        from installer.generations import Store
        self.register("ready")
        Store(self.registry.root).begin("pending-enrollment", "enroll", ["cloud"], "e" * 64)
        for command in (["install"], ["configure"], ["resume", "cloud"], ["remove", "cloud"],
                        ["verify", "cloud"], ["backup", "cloud"], ["restore", "cloud", "/trusted/backup"],
                        ["add-user", "cloud"], ["recover-install", "cloud"], ["recover-network"]):
            with self.subTest(command=command), self.assertRaisesRegex(ValueError, "pending"):
                main(command)
        self.factory.assert_not_called()
        self.configure.assert_not_called()
        self.inspect.assert_not_called()
        self.runner.run.assert_not_called()

    def test_help_and_invalid_plan_never_probe_host_or_initialize_state(self):
        for args in (["--help"], ["install", "--help"], ["--plain", "remove", "--help"]):
            with self.subTest(args=args), self.assertRaises(SystemExit) as caught:
                main(args)
            self.assertEqual(caught.exception.code, 0)
        bad = self.directory / "invalid.json"
        bad.write_text("[]")
        with self.assertRaises(ValueError):
            main(["plan", str(bad)])
        self.host.assert_not_called()
        self.registry_factory.assert_not_called()
        self.runner_factory.assert_not_called()

    def test_offline_resolve_validates_complete_metadata_without_host_or_registration(self):
        config = replace(self.config, accept_microsoft_fonts=True)
        path, metadata = self.directory / "config.json", self.directory / "catalog.json"
        path.write_text(config.to_json())
        metadata.write_text(json.dumps(discovery_metadata(config)))
        self.stdin.interactive = self.stdout.interactive = False
        before = {entry: entry.stat().st_mtime_ns for entry in self.registry.root.rglob("*")}
        with patch("installer.discovery.discover") as discover, patch("installer.discovery.probe_packages") as probe:
            self.assertEqual(main(["resolve", str(path), "--metadata", str(metadata)]), 0)
        self.assertEqual(json.loads(self.stdout.getvalue()), resolved_plan(config))
        discover.assert_not_called()
        probe.assert_not_called()
        self.host.assert_not_called()
        self.runner_factory.assert_not_called()
        self.registry_factory.assert_not_called()
        self.ui_factory.assert_not_called()
        self.factory.assert_not_called()
        self.assertEqual({entry: entry.stat().st_mtime_ns for entry in self.registry.root.rglob("*")}, before)

    def test_offline_upgrade_assessment_never_authorizes_or_executes_changes(self):
        config = replace(self.config, accept_microsoft_fonts=True)
        path, metadata, installed = (self.directory / name for name in ("config.json", "catalog.json", "installed.json"))
        path.write_text(config.to_json())
        metadata.write_text(json.dumps(discovery_metadata(config, nextcloud="35.0.1")))
        installed.write_text(json.dumps(resolved_plan(config)))
        before = installed.read_bytes()
        self.assertEqual(main(["resolve", str(path), "--metadata", str(metadata), "--installed", str(installed)]), 0)
        report = json.loads(self.stdout.getvalue())
        self.assertEqual(report["plan"]["applications"]["nextcloud"], "35.0.1")
        self.assertFalse(report["upgrade_assessment"]["execution_authorized"])
        self.assertFalse(report["upgrade_assessment"]["migration_supported"])
        self.assertIn({"component": "applications.nextcloud", "from": "35.0.0", "to": "35.0.1"},
                      report["upgrade_assessment"]["changes"])
        self.assertEqual(installed.read_bytes(), before)
        self.host.assert_not_called()
        self.runner_factory.assert_not_called()
        self.registry_factory.assert_not_called()
        self.factory.assert_not_called()

    def test_live_resolve_checks_host_and_obtainability_without_registering_or_applying(self):
        config = replace(self.config, accept_microsoft_fonts=True)
        path = self.directory / "config.json"
        path.write_text(config.to_json())
        self.stdin.interactive = self.stdout.interactive = False
        with patch("installer.discovery.discover", return_value=discovery_metadata(config)) as discover, \
                patch("installer.discovery.probe_packages") as probe:
            self.assertEqual(main(["resolve", str(path)]), 0)
        self.host.assert_called_once_with(self.runner)
        discover.assert_called_once_with(config, self.runner)
        probe.assert_called_once_with(config, resolved_plan(config), self.runner)
        self.registry_factory.assert_not_called()
        self.ui_factory.assert_not_called()
        self.factory.assert_not_called()
        self.runner.run.assert_not_called()

    def test_invalid_offline_resolution_stops_without_live_fallback(self):
        config = replace(self.config, accept_microsoft_fonts=True)
        path, metadata = self.directory / "config.json", self.directory / "catalog.json"
        path.write_text(config.to_json())
        metadata.write_text("{}")
        with patch("installer.discovery.discover") as discover, self.assertRaises(ValueError):
            main(["resolve", str(path), "--metadata", str(metadata)])
        discover.assert_not_called()
        self.host.assert_not_called()
        self.runner_factory.assert_not_called()
        self.registry_factory.assert_not_called()

    def test_mutating_commands_require_freebsd_before_ui_secrets_or_state(self):
        self.host.side_effect = require_host
        self.runner.output.return_value = "Linux"
        for args in (["install"], ["configure"], ["resume", "cloud"], ["remove", "cloud"],
                     ["backup", "cloud"], ["restore", "cloud", "backup"], ["add-user", "cloud"],
                     ["recover-network"], ["recover-install", "cloud"]):
            with self.subTest(args=args), patch("installer.host.os.geteuid", return_value=0), \
                    self.assertRaisesRegex(ValueError, "FreeBSD host"):
                main(args)
        self.registry_factory.assert_not_called()
        self.ui_factory.assert_not_called()
        self.create_secrets.assert_not_called()
        self.factory.assert_not_called()
        self.runner.run.assert_not_called()

    def test_configuration_and_destructive_commands_require_both_terminal_streams(self):
        self.register("ready")
        for input_tty, output_tty in ((False, True), (True, False), (False, False)):
            self.stdin.interactive, self.stdout.interactive = input_tty, output_tty
            for args in ([], ["install"], ["configure"], ["--configure-only"], ["resume", "cloud"],
                         ["remove", "cloud"], ["restore", "cloud", "backup"], ["add-user", "cloud"],
                         ["recover-network"], ["recover-install", "cloud"]):
                with self.subTest(args=args, input_tty=input_tty, output_tty=output_tty), \
                        patch("installer.operations.backup_database") as backup, \
                        self.assertRaisesRegex(ValueError, "interactive terminal"):
                    main(args)
                backup.assert_not_called()
        self.configure.assert_not_called()
        self.create_secrets.assert_not_called()
        self.factory.assert_not_called()

    def test_backup_supports_scheduled_host_root_execution_without_a_terminal(self):
        self.register("ready")
        self.stdin.interactive = self.stdout.interactive = False
        with patch("installer.operations.backup_database", return_value=self.directory / "backup") as backup:
            self.assertEqual(main(["backup", "cloud"]), 0)
        backup.assert_called_once_with(self.deployment, None)
        self.host.assert_called_once_with(self.runner)
        self.assertTrue((self.registry.root / "operation.lock").exists())
        self.create_secrets.assert_not_called()
        self.configure.assert_not_called()
        self.ui.input.assert_not_called()

    def test_configure_only_saves_private_state_after_successful_preflight(self):
        self.assertEqual(main(["--plain", "--configure-only"]), 0)
        self.ui_factory.assert_called_once_with(plain=True)
        self.preflight.assert_called_once_with(self.config, {"ssh_connection": None}, self.runner, registry=self.registry)
        self.assertEqual(self.registry.load("cloud"), self.config)
        self.assertEqual(private_json(self.registry.instance_path("cloud") / "secrets.json"), self.secrets)
        self.factory.assert_not_called()
        self.ui.input.assert_not_called()

    def test_failed_preflight_does_not_generate_secrets_register_or_deploy(self):
        self.preflight.side_effect = ValueError("resource collision")
        self.assertEqual(main(["install"]), 1)
        self.create_secrets.assert_not_called()
        self.factory.assert_not_called()
        self.assertEqual(self.registry.entries(), [])
        self.ui.input.assert_not_called()

    def test_preflight_retry_preserves_values_and_requires_success_before_saving(self):
        self.preflight.side_effect = [ValueError("port unavailable"), None]
        self.ui.confirm.return_value = True
        self.assertEqual(main(["configure"]), 0)
        self.assertEqual(self.configure.call_count, 2)
        self.assertIsNone(self.configure.call_args_list[0].args[1])
        self.assertIs(self.configure.call_args_list[1].args[1], self.config)
        self.assertEqual(self.preflight.call_count, 2)
        self.create_secrets.assert_called_once_with(ui=self.ui)
        self.assertEqual(self.registry.load("cloud"), self.config)

    def test_install_declined_apply_retains_configuration_without_provisioning(self):
        self.ui.input.return_value = "apply"
        self.assertEqual(main(["install"]), 0)
        self.deployment.apply.assert_not_called()
        self.deployment.prepare_versions.assert_called_once_with()
        self.assertEqual(private_json(self.registry.instance_path("cloud") / "status.json")["state"], "configured")
        self.ui.input.assert_called_once_with("Type APPLY to proceed")
        self.assertTrue(any("Saved only" in item.args[0] for item in self.ui.message.call_args_list))

    def test_install_requires_exact_runtime_apply_and_never_prints_credentials(self):
        events = []
        self.deployment.prepare_versions.side_effect = lambda: events.append("resolve") or {"resolved": "public plan"}
        self.ui.input.side_effect = lambda _: events.append("approval") or "APPLY"
        self.deployment.apply.side_effect = lambda: events.append("apply")
        self.assertEqual(main(["install"]), 0)
        self.assertEqual(events, ["resolve", "approval", "apply"])
        self.deployment.apply.assert_called_once_with()
        args, kwargs = self.factory.call_args
        self.assertEqual(args[:3], (self.config, self.secrets, self.runner))
        self.assertIs(kwargs["registry"], self.registry)
        messages = self.stdout.getvalue() + repr(self.ui.message.call_args_list)
        for secret in self.secrets.values():
            self.assertNotIn(secret, messages)
        self.assertIn(str(self.registry.instance_path("cloud") / "secrets.json"), messages)

    def test_failed_version_resolution_cannot_request_apply_or_provision(self):
        self.deployment.prepare_versions.side_effect = ValueError("No compatible obtainable package set")
        with self.assertRaisesRegex(ValueError, "No compatible"):
            main(["install"])
        self.deployment.apply.assert_not_called()
        self.ui.input.assert_not_called()
        self.assertEqual(private_json(self.registry.instance_path("cloud") / "status.json")["state"], "configured")

    def test_resume_loads_original_credentials_and_rechecks_host_before_apply(self):
        self.register("failed")
        self.ui.input.return_value = "APPLY"
        self.assertEqual(main(["resume", "cloud"]), 0)
        self.preflight.assert_called_once_with(self.config, {"ssh_connection": None}, self.runner,
                                               registry=self.registry, resume=True)
        self.create_secrets.assert_not_called()
        self.configure.assert_not_called()
        self.deployment.apply.assert_called_once_with()
        self.deployment.prepare_versions.assert_called_once_with()
        self.assertEqual(self.factory.call_args.args[1], self.secrets)

    def test_resume_preflight_failure_cannot_provision_or_request_apply(self):
        self.register("failed")
        self.preflight.side_effect = ValueError("ownership changed")
        with self.assertRaisesRegex(ValueError, "ownership changed"):
            main(["resume", "cloud"])
        self.deployment.apply.assert_not_called()
        self.ui.input.assert_not_called()

    def test_state_gates_block_replay_and_ready_only_operations(self):
        self.register()
        for state, args in (("ready", ["resume", "cloud"]), ("configured", ["verify", "cloud"]),
                            ("failed", ["backup", "cloud"]), ("failed", ["restore", "cloud", "backup"]),
                            ("installing", ["add-user", "cloud"]), ("removed", ["resume", "cloud"]),
                            ("removing", ["verify", "cloud"])):
            self.registry.set_status("cloud", state)
            with self.subTest(state=state, args=args), self.assertRaises(ValueError):
                main(args)
        self.factory.assert_not_called()
        self.preflight.assert_not_called()
        self.create_secrets.assert_not_called()

    def test_verify_is_read_only_host_workflow_and_does_not_resume(self):
        self.register("ready")
        self.stdin.interactive = self.stdout.interactive = False
        self.assertEqual(main(["--verify", "cloud"]), 0)
        self.deployment.verify.assert_called_once_with()
        self.deployment.checkpoint.assert_called_once_with()
        self.deployment.apply.assert_not_called()
        self.preflight.assert_not_called()
        self.inspect.assert_not_called()
        self.create_secrets.assert_not_called()
        self.ui.input.assert_not_called()

    def test_list_and_status_do_not_read_credentials_or_create_operation_lock(self):
        path = self.register("failed")
        atomic_json(path / "deployment.json", {"config_sha256": config_digest(self.config),
                                               "steps": {"phase": {"state": "failed", "error_type": "PRIVATE ERROR"}}})
        (path / "secrets.json").unlink()  # Inspection still works when private credentials need manual recovery.
        self.stdin.interactive = self.stdout.interactive = False
        before = {entry: entry.read_bytes() for entry in path.iterdir()}
        for args in (["list"], ["status", "cloud"]):
            self.assertEqual(main(args), 0)
        self.assertIn("failed", self.stdout.getvalue())
        self.assertIn("phase", self.stdout.getvalue())
        self.assertNotIn("PRIVATE ERROR", self.stdout.getvalue())
        self.assertFalse((self.registry.root / "operation.lock").exists())
        self.assertEqual({entry: entry.read_bytes() for entry in path.iterdir()}, before)
        self.factory.assert_not_called()
        self.inspect.assert_not_called()
        self.ui.input.assert_not_called()

    def test_show_status_is_secret_free_including_removed_tombstones(self):
        path = self.register("removed")
        atomic_json(path / "deployment.json", {"config_sha256": config_digest(self.config),
                                               "steps": {"database": {"state": "failed", "error": self.secrets["db_password"]}}})
        show_status(self.registry, "cloud")
        text = self.stdout.getvalue()
        self.assertIn("removed", text)
        self.assertIn("cloudnc", text)
        self.assertIn("database", text)
        for secret in self.secrets.values():
            self.assertNotIn(secret, text)
        with self.assertRaisesRegex(ValueError, "Unknown instance"):
            show_status(self.registry, "missing")

    def test_status_loads_historical_config_and_journal_without_a_version_lock(self):
        path = self.register("removed")
        atomic_json(path / "config.json", json.loads(LEGACY_CONFIG_JSON))
        atomic_json(path / "removal.json", {"schema_version": 2, "config_sha256": LEGACY_CONFIG_SHA256, "steps": {}})
        (path / "secrets.json").unlink()
        before = {entry: entry.read_bytes() for entry in path.iterdir()}
        self.assertEqual(main(["status", "cloud"]), 0)
        self.assertIn("removed", self.stdout.getvalue())
        self.assertEqual({entry: entry.read_bytes() for entry in path.iterdir()}, before)
        self.factory.assert_not_called()
        self.assertFalse((path / "versions.json").exists())

    def test_empty_list_does_not_initialize_registry(self):
        missing = Registry(self.directory / "missing")
        self.registry_factory.return_value = missing
        self.assertEqual(main(["list"]), 0)
        self.assertFalse(missing.root.exists())
        self.assertIn("No registered instances", self.stdout.getvalue())

    def test_menu_removal_defaults_to_retention_and_uses_exact_instance_selection(self):
        self.register("ready")
        self.register("ready", replace(self.config, instance="other"))
        self.ui.menu.side_effect = ["remove", "cloud", "retain"]
        args = menu(self.ui, self.registry)
        self.assertEqual((args.command, args.instance, args.purge_data), ("remove", "cloud", False))
        self.assertEqual(self.ui.menu.call_args.args[2], "retain")
        choices = self.ui.menu.call_args_list[1].args[1]
        self.assertEqual([name for name, _ in choices], ["cloud", "other"])

    def test_no_argument_menu_routes_status_without_deployment(self):
        self.register("removed")
        self.ui.menu.side_effect = ["status", "cloud"]
        self.assertEqual(main([]), 0)
        self.assertIn("removed", self.stdout.getvalue())
        self.factory.assert_not_called()
        self.create_secrets.assert_not_called()
        self.assertFalse((self.registry.root / "operation.lock").exists())

    def test_empty_dashboard_cancel_never_initializes_or_locks_state(self):
        missing = Registry(self.directory / "missing")
        self.registry_factory.return_value = missing
        self.ui.menu.side_effect = KeyboardInterrupt
        with patch.object(missing, "locked") as locked, self.assertRaises(KeyboardInterrupt):
            main([])
        locked.assert_not_called()
        self.assertFalse(missing.root.exists())
        self.factory.assert_not_called()
        self.inspect.assert_not_called()

    def test_dashboard_install_selection_defers_shell_bootstrap_before_lock(self):
        self.ui.menu.return_value = "install"
        with patch("installer.main.launch_selected_install", return_value=0) as launch, \
                patch.object(self.registry, "locked") as locked:
            self.assertEqual(main(["--plain"]), 0)
        self.assertEqual(launch.call_args.args[0].command, "install")
        self.assertTrue(launch.call_args.kwargs["plain"])
        locked.assert_not_called()
        self.preflight.assert_not_called()
        self.create_secrets.assert_not_called()

    def test_deferred_bootstrap_uses_current_absolute_entrypoint_and_argv(self):
        from argparse import Namespace
        with patch("installer.main.os.execv", side_effect=SystemExit(0)) as execute, self.assertRaises(SystemExit):
            launch_selected_install(Namespace(command="resume", instance="cloud"), plain=True)
        program, args = execute.call_args.args
        self.assertEqual(program, "/bin/sh")
        self.assertTrue(Path(args[1]).is_absolute())
        self.assertEqual(Path(args[1]).name, "install.sh")
        self.assertEqual(args[2:], ["--plain", "resume", "cloud"])

    def test_dashboard_filters_ready_actions_and_prioritizes_pending_network(self):
        self.register("configured")
        self.ui.menu.return_value = "list"
        menu(self.ui, self.registry)
        choices = dict(self.ui.menu.call_args.args[1])
        self.assertIn("resume", choices)
        self.assertNotIn("verify", choices)
        pending = self.registry.root / "transactions/pending"
        pending.mkdir(mode=0o700)
        atomic_json(pending / "firewall-transition.json", {"instances": ["cloud"]})
        menu(self.ui, self.registry)
        choices = dict(self.ui.menu.call_args.args[1])
        self.assertIn("recover-network", choices)
        self.assertNotIn("install", choices)
        self.assertNotIn("resume", choices)

    def test_update_cli_cached_read_is_noninteractive_without_secrets_or_lock(self):
        self.register("ready")
        self.stdin.interactive = self.stdout.interactive = False
        report = {"schema_version": 1, "instances": [{"instance": "cloud", "status": "unknown"}],
                  "inspection_failed": False, "execution_authorized": False}
        with patch("installer.updates.check_updates", return_value=report) as updates, \
                patch.object(self.registry, "locked") as locked:
            self.assertEqual(main(["check-updates", "cloud", "--json"]), 0)
        updates.assert_called_once_with(self.registry, ["cloud"], refresh=False, save_report=False, runner=self.runner)
        locked.assert_not_called()
        self.assertEqual(json.loads(self.stdout.getvalue()), report)
        self.factory.assert_not_called()
        self.inspect.assert_not_called()

    def test_update_refresh_and_save_are_explicit_and_failures_return_nonzero(self):
        self.register("ready")
        self.stdin.interactive = self.stdout.interactive = False
        report = {"instances": [{"instance": "cloud", "status": "unknown", "errors": ["Discovery failed"]}],
                  "inspection_failed": True}
        with patch("installer.updates.check_updates", return_value=report) as updates:
            self.assertEqual(main(["check-updates", "--all", "--refresh", "--save-report"]), 1)
        updates.assert_called_once_with(self.registry, ["cloud"], refresh=True, save_report=True, runner=self.runner)
        self.factory.assert_not_called()

    def test_update_scope_required_noninteractively_and_flags_are_validated(self):
        self.register("ready")
        self.stdin.interactive = self.stdout.interactive = False
        with self.assertRaisesRegex(ValueError, "instance or --all"):
            main(["check-updates"])
        for args in (["cloud", "--all"], ["../cloud"], ["cloud", "--save-report"]):
            with self.subTest(args=args), patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit):
                main(["check-updates", *args])
        self.factory.assert_not_called()
        self.assertFalse((self.registry.root / "operation.lock").exists())

    def test_empty_all_update_check_does_not_create_state(self):
        missing = Registry(self.directory / "missing")
        self.registry_factory.return_value = missing
        self.stdin.interactive = self.stdout.interactive = False
        with patch("installer.updates.check_updates") as updates:
            self.assertEqual(main(["check-updates", "--all", "--json"]), 0)
        self.assertFalse(missing.root.exists())
        updates.assert_not_called()
        self.assertEqual(json.loads(self.stdout.getvalue())["instances"], [])

    def test_menu_check_updates_defaults_to_cached_and_no_write(self):
        self.register("ready")
        self.ui.menu.side_effect = ["check-updates", "cached"]
        args = menu(self.ui, self.registry)
        self.assertFalse(args.refresh)
        self.assertFalse(args.save_report)
        self.assertIsNone(args.instance)
        self.assertFalse(args.all)
        self.ui.confirm.assert_not_called()

    def test_corrupt_dashboard_records_cannot_select_install(self):
        path = self.register("ready")
        atomic_json(path / "config.json", {"invalid": "private-do-not-echo"})
        self.ui.menu.return_value = "install"
        with self.assertRaisesRegex(ValueError, "Unavailable dashboard action"):
            menu(self.ui, self.registry)
        self.assertNotIn("private-do-not-echo", repr(self.ui.menu.call_args))

    def test_malformed_cached_prerequisite_does_not_prevent_dashboard_menu(self):
        from installer.updates import check_updates
        config = replace(self.config, accept_microsoft_fonts=True)
        path = self.register("ready", config)
        atomic_json(path / "versions.json", resolved_plan(config))
        atomic_write(path / "source.sha256", "a" * 64 + "\n")
        with patch("installer.discovery.discover", return_value=discovery_metadata(config)):
            result = check_updates(self.registry, ["cloud"], refresh=True, runner=self.runner)
        self.assertFalse(result["inspection_failed"])
        report = result["instances"][0]
        report["shared_prerequisites"]["installed"]["bastille"]["abi"] = None
        directory = self.registry.root / "update-reports"
        directory.mkdir(mode=0o700)
        atomic_json(directory / "cloud.json", {"schema_version": 1,
                    "generated_at": result["generated_at"], "report": report})
        self.ui.menu.side_effect = ["status", "cloud"]
        with patch("installer.discovery.discover") as discover, patch.object(self.registry, "locked") as locked:
            self.assertEqual(main([]), 0)
        self.assertIn("Updates: unknown", self.ui.message.call_args_list[0].args[0])
        self.assertIn("ready", self.stdout.getvalue())
        discover.assert_not_called()
        locked.assert_not_called()
        self.factory.assert_not_called()

    def test_text_update_output_includes_changes_upstream_and_host_summary(self):
        report = {"instances": [{"instance": "cloud", "status": "blocked",
                   "upstream_newer": {"nextcloud": ["35.0.2"]},
                   "changes": [{"component": "host.bastille.checksum", "from": "old", "to": "new"}],
                   "stale_reasons": ["older-than-24-hours"],
                   "errors": [{"code": "test", "message": "Inspection failed"}]}],
                  "host": {"prerequisites": [{"name": "bastille", "candidate": [],
                           "installed": [{"instance": "cloud", "version": "1.4.4", "freshness": "stale"}]}]},
                  "inspection_failed": True}
        with patch("installer.updates.check_updates", return_value=report):
            self.assertEqual(main(["check-updates", "cloud"]), 1)
        text = "\n".join(call.args[0] for call in self.ui.message.call_args_list)
        for expected in ("35.0.2", "host.bastille.checksum", "older-than-24-hours",
                         "Inspection failed", "bastille installed: cloud=1.4.4 (stale)"):
            self.assertIn(expected, text)

    def test_remove_forwards_default_or_explicit_purge_and_raw_confirmation(self):
        self.register("ready")
        for purge in (False, True):
            phrase = ("PURGE " if purge else "REMOVE ") + "cloud"
            self.ui.input.return_value = phrase
            with self.subTest(purge=purge), patch("installer.lifecycle.remove_instance") as remove:
                self.assertEqual(main(["remove", "cloud", *(["--purge-data"] if purge else [])]), 0)
                remove.assert_called_once_with(self.deployment, purge_data=purge, confirmation=phrase)
            self.ui.input.assert_called_with("Type " + phrase + " to continue")
        self.deployment.apply.assert_not_called()

    def test_restore_forwards_typed_confirmation_and_explicit_backup_path(self):
        self.register("ready")
        self.ui.input.return_value = "RESTORE cloud"
        backup = self.directory / "trusted backup"
        with patch("installer.operations.restore_database") as restore:
            self.assertEqual(main(["restore", "cloud", str(backup)]), 0)
        restore.assert_called_once_with(self.deployment, backup, confirmation="RESTORE cloud")
        self.deployment.apply.assert_not_called()

    def test_locked_operation_fails_before_inspection_or_secret_prompt(self):
        with self.registry.locked(), self.assertRaisesRegex(RuntimeError, "Another installer"):
            main(["install"])
        self.inspect.assert_not_called()
        self.configure.assert_not_called()
        self.create_secrets.assert_not_called()
        self.factory.assert_not_called()

    def test_pending_restore_blocks_other_maintenance_without_running_workers(self):
        path = self.register("ready")
        atomic_json(path / "restore.json", {"state": "pending", "phase": "validated"})
        for command in ("verify", "backup", "add-user"):
            with self.subTest(command=command), self.assertRaisesRegex(ValueError, "database restore is pending"):
                main([command, "cloud"])
        self.factory.assert_not_called()
        self.runner.run.assert_not_called()

    def test_status_discloses_pending_restore_without_reading_backup_or_credentials(self):
        path = self.register("ready")
        atomic_json(path / "restore.json", {"state": "pending", "phase": "validated"})
        (path / "secrets.json").unlink()
        self.assertEqual(main(["status", "cloud"]), 0)
        self.assertIn("Database restore pending", self.stdout.getvalue())
        self.factory.assert_not_called()

    def test_initialization_recovery_uses_original_artifact_and_explicit_phrase(self):
        self.register("failed")
        self.ui.input.return_value = "RESET-INITIALIZATION cloud"
        with patch("installer.initialization.recover_initialization", return_value="Resume") as recovery:
            self.assertEqual(main(["recover-install", "cloud"]), 0)
        self.deployment.verify_source.assert_called_once_with()
        recovery.assert_called_once_with(self.deployment, confirmation="RESET-INITIALIZATION cloud")
        self.deployment.apply.assert_not_called()

    def test_pending_network_transaction_blocks_install_before_configuration(self):
        pending = self.registry.root / "transactions/interrupted"
        pending.mkdir(mode=0o700)
        atomic_json(pending / "firewall-transition.json", {"instances": ["cloud"]})
        with self.assertRaisesRegex(ValueError, "unconfirmed network transaction"):
            main(["install"])
        self.inspect.assert_not_called()
        self.configure.assert_not_called()
        self.create_secrets.assert_not_called()
        self.factory.assert_not_called()

    def test_network_recovery_requires_exact_runtime_confirmation(self):
        pending = self.registry.root / "transactions/interrupted"
        pending.mkdir(mode=0o700)
        atomic_json(pending / "firewall-transition.json", {"instances": ["cloud"]})
        for answer, accepted in (("", False), ("recover", False), ("RECOVER", True)):
            self.ui.input.return_value = answer
            self.runner.output.return_value = "current-boot-identity"
            with self.subTest(answer=answer), patch("installer.firewall.recover_pending") as recover:
                self.assertEqual(main(["recover-network"]), 0)
                if accepted:
                    recover.assert_called_once_with(pending, "current-boot-identity")
                else:
                    recover.assert_not_called()
        self.factory.assert_not_called()
        self.configure.assert_not_called()

    def test_invalid_resume_credentials_cannot_reach_deployment(self):
        path = self.register("failed")
        atomic_json(path / "secrets.json", {**self.secrets, "db_password": "unsafe;value"})
        with self.assertRaises(ValueError):
            main(["resume", "cloud"])
        self.factory.assert_not_called()
        self.inspect.assert_not_called()
        self.ui.input.assert_not_called()


class CredentialsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="credential-tests-")
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "secrets.json"
        self.secrets = {"admin_password": "private-admin-password", "db_password": "a" * 64, "jwt_secret": "b" * 64}

    def test_valid_credentials_load_only_from_owner_private_file(self):
        atomic_json(self.path, self.secrets)
        self.assertEqual(load_secrets(self.path), self.secrets)
        self.path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "owner-only"):
            load_secrets(self.path)

    def test_credential_schema_formats_and_password_limits_are_strict(self):
        values = [[], None, {}, {**self.secrets, "extra": "unexpected"}]
        values += [{**self.secrets, "admin_password": password} for password in
                   ([], None, 123, "short", "valid-length-but\ncontrol", "x" * 1025, "é" * 513)]
        values += [{**self.secrets, key: value} for key in ("db_password", "jwt_secret")
                   for value in ("a" * 63, "a" * 65, "G" * 64, "a;" * 32, 123)]
        for value in values:
            with self.subTest(value=value):
                atomic_json(self.path, value)
                with self.assertRaises(ValueError):
                    load_secrets(self.path)

    def test_symlinked_credentials_are_rejected_without_following_target(self):
        atomic_json(self.path, self.secrets)
        link = self.path.with_name("linked.json")
        link.symlink_to(self.path)
        with self.assertRaises(ValueError):
            load_secrets(link)


if __name__ == "__main__":
    unittest.main()
