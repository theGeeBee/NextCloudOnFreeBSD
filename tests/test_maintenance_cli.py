"""M3 CLI routing/approval tests; every host and native boundary is mocked."""

import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from installer.main import dispatch_maintenance, main, menu
from installer.state import Registry


class Terminal(io.StringIO):
    interactive = False

    def isatty(self):
        return self.interactive


class MaintenanceCLITests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="maintenance-cli-")
        self.addCleanup(temporary.cleanup)
        self.registry = Registry(Path(temporary.name) / "absent")
        self.runner, self.ui = Mock(), Mock()
        self.stdin, self.stdout = Terminal(), Terminal()
        self.enterContext(patch("installer.main.sys.stdin", self.stdin))
        self.enterContext(patch("installer.main.sys.stdout", self.stdout))
        self.enterContext(patch("installer.main.sys.stderr", io.StringIO()))
        self.host = self.enterContext(patch("installer.main.require_host"))
        self.enterContext(patch("installer.main.Runner", return_value=self.runner))
        self.enterContext(patch("installer.main.Registry", return_value=self.registry))
        self.enterContext(patch("installer.main.TerminalUI", return_value=self.ui))
        self.locked = self.enterContext(patch.object(self.registry, "locked", side_effect=AssertionError("unexpected CLI lock")))
        self.initialize = self.enterContext(patch.object(self.registry, "initialize", side_effect=AssertionError("unexpected initialization")))
        self.plan = {"schema_version": 1, "kind": "recovery-preparation-plan", "plan_id": None,
                     "instance": "cloud", "recipe": None, "native_execution_authorized": False,
                     "upgrade_execution_authorized": False, "native_acceptance": "not-run",
                     "bindings": {"executor": {"payload_path": "/private/executor"},
                                  "evidence": {"path": "instances/cloud/secrets.json", "sha256": "e" * 64}},
                     "credentials": {"jwt_secret": "private-credential-marker"},
                     "artifacts": [
                         {"kind": "package", "path": "packages/" + "a" * 64 + ".pkg",
                          "sha256": "a" * 64, "packages": ["php85-8.5.0", "php85-alias-8.5.0"]},
                         {"kind": "source", "path": "installer/main.py", "sha256": "b" * 64, "size": 10},
                         {"kind": "package", "path": "packages/" + "c" * 64 + ".pkg",
                          "sha256": "c" * 64, "packages": ["redis-8.0.0"]},
                         {"kind": "source", "path": "install.sh", "sha256": "d" * 64, "size": 25}]}
        self.report = {"schema_version": 1, "instance": "cloud", "status": "staging-only",
                       "plan": self.plan, "blockers": [], "warnings": ["Preparation only"],
                       "execution_authorized": False}
        self.status = {"schema_version": 1, "operation": "maint-one", "instance": "cloud",
                       "phase": "staged", "error": None, "native_execution_authorized": False,
                       "publication_may_have_begun": False, "recovery_publication_may_have_begun": False}

    def tearDown(self):
        self.locked.assert_not_called()
        self.initialize.assert_not_called()
        self.assertFalse(self.registry.root.exists())
        self.assertEqual(self.runner.mock_calls, [])

    def interactive(self, phrase):
        self.stdin.interactive = self.stdout.interactive = True
        self.ui.input.return_value = phrase

    def test_target_preparation_requires_confirmation_and_preserves_public_boundary(self):
        self.interactive("PREPARE-TARGET maint-one")
        with patch("installer.maintenance_operations.prepare_target", return_value=self.status) as prepare:
            self.assertEqual(main(["maintenance", "prepare-target", "maint-one", "--artifacts", "/public", "--json"]), 0)
        prepare.assert_called_once_with(self.registry, "maint-one", Path("/public"), self.runner,
                                        confirmation="PREPARE-TARGET maint-one")
        self.assertFalse(json.loads(self.stdout.getvalue())["native_execution_authorized"])

    def test_read_only_plan_is_noninteractive_and_redacts_private_bindings(self):
        with patch("installer.maintenance_operations.assess", return_value=self.report) as assess:
            self.assertEqual(main(["maintenance", "plan", "--instance", "cloud", "--recovery-only", "--json"]), 0)
        assess.assert_called_once_with(self.registry, "cloud", target=None)
        public = json.loads(self.stdout.getvalue())
        self.assertEqual(public["plan"]["instance"], "cloud")
        self.assertNotIn("bindings", public["plan"])
        self.assertNotIn("artifacts", public["plan"])
        self.assertEqual(public["plan"]["package_archives"], [
            {"sha256": "a" * 64, "packages": ["php85-8.5.0", "php85-alias-8.5.0"]},
            {"sha256": "c" * 64, "packages": ["redis-8.0.0"]}])
        self.assertEqual(public["plan"]["source_files"], 2)
        self.assertEqual(public["plan"]["source_bytes"], 35)
        for private in ("/private", "payload_path", "credentials", "private-credential-marker",
                        "secrets.json", "e" * 64, "b" * 64, "d" * 64, "installer/main.py"):
            self.assertNotIn(private, self.stdout.getvalue())
        self.ui.input.assert_not_called()

    def test_blocked_target_assessment_never_prompts_or_saves(self):
        with patch("installer.maintenance_operations.save_plan") as save:
            self.assertEqual(main(["maintenance", "plan", "--instance", "cloud", "--target", "future",
                                   "--save", "--json"]), 1)
        report = json.loads(self.stdout.getvalue())
        self.assertEqual(report["status"], "blocked")
        self.assertIsNone(report["plan"])
        self.assertNotIn("package_archives", self.stdout.getvalue())
        self.assertFalse(report["execution_authorized"])
        self.ui.input.assert_not_called()
        save.assert_not_called()

    def test_save_prompts_exact_phrase_and_passes_original_plan(self):
        self.interactive("SAVE-MAINTENANCE cloud")
        with patch("installer.maintenance_operations.assess", return_value=self.report), \
                patch("installer.maintenance_operations.save_plan", return_value={
                    "path": "maintenance/plans/plan-one.json", "sha256": "a" * 64}) as save:
            self.assertEqual(main(["maintenance", "plan", "--instance", "cloud", "--recovery-only", "--save", "--json"]), 0)
        self.ui.input.assert_called_once_with("Type SAVE-MAINTENANCE cloud to continue")
        save.assert_called_once_with(self.registry, self.plan, confirmation="SAVE-MAINTENANCE cloud")
        public = json.loads(self.stdout.getvalue())
        self.assertTrue(public["saved"])
        self.assertEqual(public["plan"]["plan_id"], "plan-one")
        self.assertIsNone(self.plan["plan_id"])

    def test_unsaved_plan_artifact_review_precedes_save_confirmation(self):
        self.interactive("SAVE-MAINTENANCE cloud")

        def confirm(prompt):
            self.assertEqual(prompt, "Type SAVE-MAINTENANCE cloud to continue")
            self.ui.message.assert_called_once()
            review = json.loads(self.ui.message.call_args.args[0])
            self.assertIsNone(review["plan"]["plan_id"])
            self.assertNotIn("saved", review)
            self.assertEqual(review["plan"]["package_archives"][0]["sha256"], "a" * 64)
            self.assertNotIn("bindings", review["plan"])
            return "SAVE-MAINTENANCE cloud"

        self.ui.input.side_effect = confirm
        with patch("installer.maintenance_operations.assess", return_value=self.report), \
                patch("installer.maintenance_operations.save_plan", return_value={
                    "path": "maintenance/plans/plan-one.json", "sha256": "a" * 64}):
            self.assertEqual(main(["maintenance", "plan", "--instance", "cloud", "--recovery-only", "--save"]), 0)
        self.assertEqual(self.ui.message.call_count, 2)
        self.assertTrue(json.loads(self.ui.message.call_args.args[0])["saved"])

    def test_staging_and_cancel_forward_operator_confirmation_verbatim(self):
        for action, identity, function, prefix in (
                ("stage", "plan-one", "stage_plan", "STAGE"),
                ("continue", "maint-one", "continue_staging", "CONTINUE"),
                ("cancel", "maint-one", "cancel", "CANCEL")):
            with self.subTest(action=action):
                self.ui.reset_mock()
                self.interactive("operator supplied text")
                args = ["maintenance", action, identity]
                expected = [self.registry, identity]
                if action != "cancel":
                    args += ["--artifacts", "/local archives"]
                    expected.append(Path("/local archives"))
                with patch("installer.maintenance_operations." + function, return_value=self.status) as call:
                    self.assertEqual(main(args), 0)
                self.ui.input.assert_called_once_with(f"Type {prefix}-MAINTENANCE {identity} to continue")
                call.assert_called_once_with(*expected, confirmation="operator supplied text")

    def test_wrong_confirmations_reach_api_and_fail_before_lock(self):
        self.interactive("yes")
        for command in (["stage", "plan-one", "--artifacts", "/local"],
                        ["continue", "maint-one", "--artifacts", "/local"], ["cancel", "maint-one"]):
            with self.subTest(command=command), self.assertRaisesRegex(ValueError, "exact .* confirmation"):
                main(["maintenance", *command])

    def test_mutations_require_terminal_before_api_call(self):
        for command, function in ((["stage", "plan-one", "--artifacts", "/local"], "stage_plan"),
                                  (["continue", "maint-one", "--artifacts", "/local"], "continue_staging"),
                                  (["cancel", "maint-one"], "cancel"),
                                  (["plan", "--instance", "cloud", "--recovery-only", "--save"], "save_plan")):
            with self.subTest(command=command), patch("installer.maintenance_operations.assess", return_value=self.report), \
                    patch("installer.maintenance_operations." + function) as call:
                with self.assertRaisesRegex(ValueError, "interactive terminal"):
                    main(["maintenance", *command])
                call.assert_not_called()

    def test_operation_status_and_recovery_assessment_are_read_only(self):
        for command, function in ((["status", "maint-one"], "operation_status"),
                                  (["recover", "maint-one", "--assess"], "assess_recovery")):
            with self.subTest(command=command), patch("installer.maintenance_operations." + function,
                                                     return_value={**self.status, "bindings": "never print"}) as call:
                self.stdout.seek(0)
                self.stdout.truncate()
                self.assertEqual(main(["maintenance", *command, "--json"]), 0)
                self.assertEqual(json.loads(self.stdout.getvalue()), self.status)
                call.assert_called_once_with(self.registry, "maint-one")
        self.ui.input.assert_not_called()

    def test_recovery_assessment_returns_blocked_without_recovery_execution(self):
        with patch("installer.maintenance_operations.operation_status", return_value=self.status), \
                patch("installer.maintenance.recover") as recover:
            self.assertEqual(main(["maintenance", "recover", "maint-one", "--assess", "--json"]), 1)
        self.assertFalse(json.loads(self.stdout.getvalue())["restore_eligible"])
        recover.assert_not_called()

    def test_apply_uses_real_hard_gate_without_prompt_or_lock(self):
        with patch("installer.maintenance_operations.load_operation", return_value=({"recipe": None}, None, None)) as load:
            with self.assertRaises(ValueError):
                main(["maintenance", "apply", "maint-one"])
        load.assert_not_called()
        self.ui.input.assert_not_called()

    def test_native_continuation_and_original_restore_keep_acceptance_gate(self):
        for command in (["continue", "execution-one"],
                        ["cancel", "execution-one"],
                        ["recover", "execution-one", "--restore-original"],
                        ["apply", "maint-one", "--backup-dataset", "backup/maintenance"]):
            with self.subTest(command=command), self.assertRaisesRegex(ValueError, "no reviewed"):
                main(["maintenance", *command])
        self.ui.input.assert_not_called()

    def test_native_routing_passes_actual_confirmation_callback_and_safe_summary(self):
        for command, function, phrase in (
            (["continue", "execution-one"], "continue_execution", "CONTINUE-MAINTENANCE execution-one"),
            (["cancel", "execution-one"], "cancel_execution", "CANCEL-MAINTENANCE execution-one"),
            (["recover", "execution-one", "--restore-original"], "restore_original",
             "RESTORE-ORIGINAL execution-one DISCARD-CLOSED-CHANGES"),
        ):
            with self.subTest(command=command):
                self.interactive("actual operator text")
                self.stdout.seek(0)
                self.stdout.truncate()
                def execute(registry, runner, operation, confirm):
                    self.assertIs(registry, self.registry)
                    self.assertIs(runner, self.runner)
                    self.assertEqual(operation, "execution-one")
                    self.assertEqual(confirm(phrase), "actual operator text")
                    return dict(operation=operation, state="recovered", ready=True,
                                machine_drain_verified=False, unsaved_editor_work_covered=False,
                                credentials="never print")
                with patch("installer.maintenance_execution." + function, side_effect=execute):
                    self.assertEqual(main(["maintenance", *command, "--json"]), 0)
                public = json.loads(self.stdout.getvalue())
                self.assertEqual(public["state"], "recovered")
                self.assertTrue(public["ready"])
                self.assertFalse(public["machine_drain_verified"])
                self.assertNotIn("credentials", public)

    def test_continuation_artifact_scope_and_restore_identity_are_explicit(self):
        for command in (["continue", "maint-one"],
                        ["continue", "execution-one", "--artifacts", "/untrusted"],
                        ["recover", "maint-one", "--restore-original"],
                        ["recover", "execution-one", "--assess", "--restore-original"]):
            with self.subTest(command=command), self.assertRaises(SystemExit):
                main(["maintenance", *command])
        self.host.assert_not_called()

    def test_existing_noid_lifecycle_routes_are_preserved(self):
        with patch("installer.maintenance.dispatch", return_value=0) as dispatch:
            for action in ("status", "recover"):
                self.assertEqual(main(["maintenance", action]), 0)
                self.assertEqual(dispatch.call_args.args[0].action, action)
                self.assertIsNone(dispatch.call_args.args[0].operation)
        self.assertEqual(main(["maintenance", "status", "--json"]), 0)
        self.assertEqual(json.loads(self.stdout.getvalue())["lifecycle"], "legacy")

    def test_noid_status_includes_preparation_operations_in_text_json_and_menu(self):
        report = {"schema_version": 1, "lifecycle": "initialized", "pending": None,
                  "graph": {"instances": ["cloud"]}, "error": None, "execution_authorized": False,
                  "preparation_operations": [self.status]}
        with patch("installer.maintenance.status", return_value=report):
            self.assertEqual(main(["maintenance", "status"]), 0)
            self.assertEqual(json.loads(self.ui.message.call_args.args[0]), report)
            self.assertEqual(main(["maintenance", "status", "--json"]), 0)
            self.assertEqual(json.loads(self.stdout.getvalue()), report)
            self.ui.menu.return_value = "maintenance-status"
            with patch.object(self.registry, "lifecycle_enabled", return_value=True):
                args = menu(self.ui, self.registry, view={"instances": [], "errors": [], "pending_network": []})
            self.assertEqual(dispatch_maintenance(args, self.registry, self.runner, self.ui), 0)
            self.assertEqual(json.loads(self.ui.message.call_args.args[0]), report)
        self.ui.input.assert_not_called()

    def test_noid_recover_keeps_enrollment_confirmation_and_runner(self):
        self.interactive("RECOVER-LIFECYCLE")
        with patch("installer.maintenance.recover") as recover:
            self.assertEqual(main(["maintenance", "recover"]), 0)
        self.ui.input.assert_called_once_with("Type RECOVER-LIFECYCLE to continue")
        recover.assert_called_once_with(self.registry, self.runner, confirmation="RECOVER-LIFECYCLE")

    def test_invalid_shapes_fail_before_host_access(self):
        commands = (["plan", "--instance", "cloud"],
                    ["plan", "--instance", "cloud", "--recovery-only", "--target", "future"],
                    ["plan", "--instance", "../bad", "--recovery-only"],
                    ["stage", "plan-one"], ["continue", "maint-one"], ["cancel"], ["apply"],
                    ["recover", "maint-one"], ["recover", "--assess"],
                    ["status", "../private"], ["apply", "maint-one", "--force"])
        for command in commands:
            with self.subTest(command=command), self.assertRaises(SystemExit) as raised:
                main(["maintenance", *command])
            self.assertEqual(raised.exception.code, 2)
        self.host.assert_not_called()

    def test_menu_exposes_read_only_recovery_plan(self):
        self.ui.menu.return_value = "maintenance-plan"
        self.ui.input.return_value = "cloud"
        with patch.object(self.registry, "lifecycle_enabled", return_value=True):
            args = menu(self.ui, self.registry, view={"instances": [], "errors": [], "pending_network": []})
        self.assertEqual((args.command, args.action, args.instance), ("maintenance", "plan", "cloud"))
        self.assertTrue(args.recovery_only)
        self.assertFalse(args.save)
        self.assertIsNone(args.target)


if __name__ == "__main__":
    unittest.main()
