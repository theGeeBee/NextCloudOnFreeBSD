"""Upgrade CLI consent/dispatch boundaries; no native host or provisioning calls."""

from contextlib import ExitStack, contextmanager
import io
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from installer.main import main, menu
from installer.upgrade_native import LiveTarget
from test_installer import HOST_PROBES, entry_functions


class Terminal(io.StringIO):
    def __init__(self, interactive=True):
        super().__init__()
        self.interactive = interactive

    def isatty(self):
        return self.interactive


class UpgradeCLITests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.events = []
        self.registry = Mock(root=Path("/unused/registry"))
        self.registry.lifecycle_enabled.return_value = False
        self.registry.locked.side_effect = lambda: self.guard("host-lock")
        self.target = Mock()
        self.target.verify.return_value = {"nextcloud": {"version": "35.0.2"}, "verification": {"services": True}}
        self.ui, self.runner = Mock(), Mock()
        self.ui.input.return_value = "UPGRADE cloud"
        self.stdin, self.stdout, self.stderr = Terminal(), Terminal(), io.StringIO()
        for name, value in (("sys.stdin", self.stdin), ("sys.stdout", self.stdout), ("sys.stderr", self.stderr),
                            ("Registry", Mock(return_value=self.registry)), ("TerminalUI", Mock(return_value=self.ui))):
            self.stack.enter_context(patch("installer.main." + name, value))
        self.old_runner = self.mock("installer.main.Runner")
        self.native_runner = self.mock("installer.upgrade_native.UpgradeRunner", return_value=self.runner)
        self.host = self.mock("installer.main.require_host", side_effect=lambda runner: self.events.append("host"))
        self.entry_guard = self.mock("installer.maintenance.entry_guard", side_effect=lambda *a, **k: self.events.append("entry"))
        self.pending = self.mock("installer.firewall.pending_transactions", return_value=[])
        self.factory = self.mock("installer.upgrade_native.LiveTarget", return_value=self.target)
        self.database_guard = self.mock("installer.operations._database_guard", side_effect=lambda target: self.guard("database-lock"))
        self.selected = {"schema_version": 1, "instance": "cloud", "source_nextcloud": "35.0.1", "target_nextcloud": "35.0.2"}
        self.selected.update(packages=None, backup="One local ZFS snapshot set", recovery="Restore snapshots on failure")
        self.plan = self.mock("installer.upgrade.plan", return_value=self.selected)
        self.execute = self.mock("installer.upgrade.execute", side_effect=self.execute_confirmed)
        self.deployment = self.mock("installer.main.Deployment")
        self.secrets = self.mock("installer.main.load_secrets")
        self.preflight = self.mock("installer.main.preflight")
        self.inspection = self.mock("installer.main.inspect_host")
        self.legacy_backup = self.mock("installer.operations.backup_database")

    def mock(self, name, **kwargs):
        return self.stack.enter_context(patch(name, **kwargs))

    @contextmanager
    def guard(self, name):
        self.events.append(name)
        try:
            yield
        finally:
            self.events.append("release-" + name)

    def execute_confirmed(self, target, selected, *, confirm):
        self.assertEqual(self.events[-2:], ["host-lock", "database-lock"])
        accepted = confirm("UPGRADE cloud")
        return {"state": "complete" if accepted else "cancelled", "changed": accepted}

    def noninteractive(self):
        self.stdin.interactive = self.stdout.interactive = False

    def assert_no_legacy(self):
        for mocked in (self.old_runner, self.deployment, self.secrets, self.preflight,
                       self.inspection, self.legacy_backup):
            mocked.assert_not_called()
        self.target.private_config.assert_not_called()

    def test_plan_is_noninteractive_live_and_serialized_without_legacy_loading(self):
        self.noninteractive()
        self.assertEqual(main(["upgrade", "cloud", "--plan"]), 0)
        self.host.assert_called_once_with(self.runner)
        self.entry_guard.assert_called_once_with("upgrade", registry=self.registry)
        self.factory.assert_called_once_with(self.registry, self.runner, "cloud")
        self.database_guard.assert_called_once_with(self.target)
        self.plan.assert_called_once_with(self.target, nextcloud="35.0.2", packages=True)
        self.assertEqual(json.loads(self.stdout.getvalue()), self.selected)
        self.assertIn("refresh signed native pkg metadata", self.stderr.getvalue())
        self.assertEqual(self.events, ["host", "entry", "host-lock", "database-lock",
                                       "release-database-lock", "release-host-lock"])
        self.execute.assert_not_called()
        self.ui.input.assert_not_called()
        self.assert_no_legacy()

    def test_verify_uses_current_live_state_without_target_version_or_package_plan(self):
        self.noninteractive()
        self.assertEqual(main(["upgrade", "cloud", "--verify"]), 0)
        self.target.verify.assert_called_once_with()
        self.assertEqual(json.loads(self.stdout.getvalue())["nextcloud"]["version"], "35.0.2")
        self.plan.assert_not_called()
        self.execute.assert_not_called()
        self.ui.input.assert_not_called()
        self.database_guard.assert_called_once_with(self.target)
        self.assert_no_legacy()

    def test_execute_gets_one_exact_consent_under_both_locks(self):
        self.assertEqual(main(["upgrade", "cloud"]), 0)
        self.ui.input.assert_called_once_with("Type UPGRADE cloud to continue")
        text = "\n".join(call.args[0] for call in self.ui.message.call_args_list)
        for phrase in ("Save and close", "downtime", "ZFS snapshot", "restore command", "not disaster-recovery", "operator"):
            self.assertIn(phrase, text)
        self.assertEqual(json.loads(self.stdout.getvalue())["state"], "complete")
        self.assert_no_legacy()

    def test_nonexact_confirmation_cancels(self):
        for phrase in ("yes", "UPGRADE other", "upgrade cloud", "UPGRADE cloud ", ""):
            with self.subTest(phrase=phrase):
                self.stdout.seek(0)
                self.stdout.truncate()
                self.ui.input.return_value = phrase
                self.assertEqual(main(["upgrade", "cloud"]), 0)
                self.assertEqual(json.loads(self.stdout.getvalue()), {"state": "cancelled", "changed": False})

    def test_execute_requires_both_terminal_streams_before_live_work(self):
        for stdin, stdout in ((False, True), (True, False), (False, False)):
            self.stdin.interactive, self.stdout.interactive = stdin, stdout
            with self.assertRaisesRegex(ValueError, "interactive terminal"):
                main(["upgrade", "cloud"])
        self.factory.assert_not_called()
        self.execute.assert_not_called()

    def test_selected_target_and_package_opt_out_are_forwarded(self):
        self.assertEqual(main(["upgrade", "cloud", "--nextcloud", "35.0.2", "--skip-packages", "--plan"]), 0)
        self.plan.assert_called_once_with(self.target, nextcloud="35.0.2", packages=False)

    def test_restore_is_separate_and_explicitly_confirmed(self):
        self.ui.input.return_value = "RESTORE cloud"
        def restore(target, path, *, confirm):
            self.assertIs(target, self.target)
            self.assertEqual(path, Path("/private/snapshot/report.json"))
            self.assertEqual(self.events[-2:], ["host-lock", "database-lock"])
            self.assertTrue(confirm("RESTORE cloud"))
            return {"state": "restored"}
        with patch("installer.upgrade.restore_snapshot", side_effect=restore) as restore_call:
            self.assertEqual(main(["upgrade", "cloud", "--restore", "/private/snapshot/report.json"]), 0)
            restore_call.assert_called_once()
        self.ui.input.assert_called_once_with("Type RESTORE cloud to continue")
        self.plan.assert_not_called()
        self.execute.assert_not_called()

    def test_restore_requires_terminal_before_live_work(self):
        self.noninteractive()
        with patch("installer.upgrade.restore_snapshot") as restore_call:
            with self.assertRaisesRegex(ValueError, "interactive terminal"):
                main(["upgrade", "cloud", "--restore", "/private/snapshot/report.json"])
            restore_call.assert_not_called()
        self.factory.assert_not_called()
        self.plan.assert_not_called()
        self.execute.assert_not_called()

    def test_unsupported_transition_is_adapter_decision_not_silent_fallback(self):
        self.plan.side_effect = ValueError("Unsupported native transition")
        with self.assertRaisesRegex(ValueError, "Unsupported native transition"):
            main(["upgrade", "cloud", "--nextcloud", "36.0.0"])
        self.plan.assert_called_once_with(self.target, nextcloud="36.0.0", packages=True)
        self.execute.assert_not_called()
        self.ui.input.assert_not_called()

    def test_no_change_report_does_not_force_confirmation_or_pause(self):
        self.execute.side_effect = None
        self.execute.return_value = {"state": "unchanged", "changed": False}
        self.assertEqual(main(["upgrade", "cloud"]), 0)
        self.ui.input.assert_not_called()
        self.target.run_jail.assert_not_called()

    def test_failed_upgrade_with_successful_rollback_is_nonzero(self):
        self.execute.side_effect = None
        self.execute.return_value = {"state": "failed", "rollback": {"state": "complete"}}
        self.assertEqual(main(["upgrade", "cloud"]), 1)
        self.assertEqual(json.loads(self.stdout.getvalue())["state"], "failed")

    def test_plan_blockers_are_nonzero_and_never_execute(self):
        self.selected["blockers"] = ["Unsupported package combination"]
        self.assertEqual(main(["upgrade", "cloud", "--plan"]), 1)
        self.execute.assert_not_called()

    def test_invalid_cli_and_removed_experimental_options_fail_before_host(self):
        for tail in (("../cloud",), ("cloud", "--yes"), ("cloud", "--plan", "--verify"),
                     ("cloud", "--backup-only"), ("cloud", "--backup-path", "/backup"),
                     ("cloud", "--restore"),
                     ("cloud", "--restore", "/private/report.json", "--plan"),
                     ("cloud", "--restore", "/private/report.json", "--verify")):
            with self.subTest(tail=tail), self.assertRaises(SystemExit) as error:
                main(["upgrade", *tail])
            self.assertEqual(error.exception.code, 2)
        self.host.assert_not_called()
        self.factory.assert_not_called()

    def test_host_guard_failure_precedes_registry_and_inspection(self):
        self.host.side_effect = ValueError("Run on the FreeBSD host")
        with self.assertRaisesRegex(ValueError, "FreeBSD host"):
            main(["upgrade", "cloud", "--plan"])
        self.entry_guard.assert_not_called()
        self.pending.assert_not_called()
        self.factory.assert_not_called()

    def test_lifecycle_entry_guard_is_not_bypassed_by_plan(self):
        self.entry_guard.side_effect = ValueError("Lifecycle mutation pending")
        with self.assertRaisesRegex(ValueError, "Lifecycle mutation pending"):
            main(["upgrade", "cloud", "--plan"])
        self.pending.assert_not_called()
        self.factory.assert_not_called()

    def test_live_target_refuses_enrolled_even_when_entry_guard_passes(self):
        self.factory.side_effect = LiveTarget
        self.registry.lifecycle_enabled.return_value = True
        with self.assertRaisesRegex(ValueError, "unenrolled"):
            main(["upgrade", "cloud", "--verify"])
        self.registry.load.assert_not_called()
        self.database_guard.assert_not_called()
        self.assert_no_legacy()

    def test_pending_pf_refuses_all_modes_before_target_or_database_work(self):
        self.pending.return_value = [Path("/unused/transaction")]
        for tail in ([], ["--plan"], ["--verify"], ["--restore", "/private/snapshot/report.json"]):
            with self.subTest(tail=tail), self.assertRaisesRegex(ValueError, "unconfirmed network"):
                main(["upgrade", "cloud", *tail])
        self.factory.assert_not_called()
        self.database_guard.assert_not_called()

    def test_menu_has_complete_upgrade_defaults(self):
        self.ui.menu.side_effect = ["upgrade", "cloud"]
        view = {"errors": [], "pending_network": [], "instances": [
            {"instance": "cloud", "state": "ready", "error": None, "pending": [], "public_url": "https://cloud.test"}]}
        args = menu(self.ui, self.registry, view=view)
        self.assertEqual(vars(args), {"command": "upgrade", "instance": "cloud", "nextcloud": "35.0.2",
                                      "plan": False, "verify": False, "skip_packages": False})

    def test_menu_upgrade_rechecks_entry_guard_and_uses_bounded_runner(self):
        import argparse
        self.old_runner.return_value.output.return_value = "15.1-RELEASE"
        self.mock("installer.dashboard.snapshot", return_value={"instances": []})
        self.mock("installer.dashboard.render", return_value="dashboard")
        self.mock("installer.main.menu", return_value=argparse.Namespace(
            command="upgrade", instance="cloud", nextcloud="35.0.2", plan=False, verify=False, skip_packages=False))
        self.assertEqual(main([]), 0)
        self.assertEqual([call.args[0] for call in self.entry_guard.call_args_list], ["menu", "upgrade"])
        self.factory.assert_called_once_with(self.registry, self.runner, "cloud")
        self.native_runner.assert_called_once_with()


class UpgradeShellTests(unittest.TestCase):
    def test_upgrade_modes_require_host_and_existing_python_without_bootstrap(self):
        script = """
require_host() { printf 'host-checked\\n'; }
require_python() { printf 'existing-python\\n'; }
bootstrap_python() { fail 'unexpected bootstrap'; }
bootstrap_archive() { fail 'unexpected archive'; }
launch_python() { printf 'launch:%s\\n' "$*"; }
main "$@"
"""
        for tail in ([], ["--plan"], ["--verify"], ["--restore", "/private/snapshot report.json"],
                     ["--nextcloud", "35.0.2", "--skip-packages"]):
            with self.subTest(tail=tail):
                result = entry_functions(script, "upgrade", "cloud", *tail)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines(), ["host-checked", "existing-python",
                                                             "launch:" + " ".join(["upgrade", "cloud", *tail])])

    def test_upgrade_plan_cannot_take_offline_plan_bypass(self):
        environment = {"TEST_UID": "0", "TEST_OS": "FreeBSD", "TEST_ARCH": "amd64",
                       "TEST_VERSION": "15.1-RELEASE", "TEST_JAILED": "0"}
        script = HOST_PROBES + """
require_python() { fail 'unexpected Python launch'; }
bootstrap_python() { fail 'unexpected bootstrap'; }
launch_python() { fail 'unexpected execution'; }
main "$@"
"""
        for overrides, message in (({"TEST_UID": "1000"}, "root"), ({"TEST_OS": "Linux"}, "FreeBSD host"),
                                   ({"TEST_JAILED": "1"}, "outside any jail"),
                                   ({"TEST_VERSION": "14.3-RELEASE"}, "compatibility policy")):
            with self.subTest(overrides=overrides):
                result = entry_functions(script, "upgrade", "cloud", "--plan",
                                         env={**environment, **overrides}, mock_flua=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertNotIn("unexpected", result.stderr)

    def test_missing_upgrade_instance_usage_includes_snapshot_restore(self):
        result = entry_functions("""
require_host() { fail 'unexpected host probe'; }
main "$@"
""", "upgrade")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--plan | --verify | --restore SNAPSHOT_REPORT", result.stderr)
        self.assertNotIn("unexpected", result.stderr)

    def test_upgrade_archive_dispatch_and_invalid_identity_fail_before_host(self):
        script = """
require_host() { fail 'unexpected host probe'; }
bootstrap_archive() { fail 'unexpected archive'; }
main "$@"
"""
        for args in (("upgrade", "../cloud"), ("upgrade",),
                     ("--archive", "fixture.tgz", "--sha256", "a" * 64, "upgrade", "cloud")):
            with self.subTest(args=args):
                result = entry_functions(script, *args)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("unexpected", result.stderr)


if __name__ == "__main__":
    unittest.main()
