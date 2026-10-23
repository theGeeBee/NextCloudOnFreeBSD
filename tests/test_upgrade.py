"""Simple snapshot/upgrade/rollback sequencing; no native commands executed."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from installer import upgrade


class Target:
    def __init__(self, root):
        self.state = root
        self.config = SimpleNamespace(instance="cloud")
        self.nc, self.office = "cloudnc", "cloudoo"
        self.nc_root, self.office_root = root / "nc", root / "oo"
        self.version = "35.0.1"
        self.active = {self.nc: True, self.office: True}
        self.services = {(getattr(self, role), name): True for role, name in
                         (*upgrade.WEB_SERVICES, *upgrade.DATA_SERVICES)}
        self.settings = {"system": {"maintenance": False, "dbname": "nextcloud",
                                    "dbpassword": "PRIVATE-NOT-IN-REPORT"},
                         "apps": {"onlyoffice": {"jwt_secret": "PRIVATE-JWT"}}}
        self.events = []
        self.runner = SimpleNamespace(output=self.output, run=self.host)

    def inspect(self):
        return dict(nextcloud=dict(version=self.version), php=dict(version="8.5.8"),
                    database=dict(version="12.3.3"), office=dict(upstream="9.4.0"))

    def private_config(self):
        return deepcopy(self.settings)

    def verify(self, expected_nextcloud=None):
        if expected_nextcloud is not None and expected_nextcloud != self.version:
            raise ValueError("Wrong live version")
        return dict(ready=True, nextcloud=self.version)

    def output(self, *args):
        if args == ("jls", "-d", "jid", "name", "path", "dying"):
            return "\n".join(f"1 {name} {root} false" for name, root in
                ((self.nc, self.nc_root), (self.office, self.office_root)) if self.active[name])
        assert args[:2] == ("bastille", "config")
        return str(self.nc_root if args[2] == self.nc else self.office_root)

    def host(self, *args, **kwargs):
        if args[0] == "jls":
            jail = args[2]
            root = self.nc_root if jail == self.nc else self.office_root
            return SimpleNamespace(returncode=0 if self.active[jail] else 1,
                                   stdout=f"1 {jail} {root}" if self.active[jail] else "", stderr="")
        assert args[0] == "bastille"
        self.events.append(args)
        self.active[args[2]] = args[1] == "start"
        for key in self.services:
            if key[0] == args[2]:
                self.services[key] = args[1] == "start"
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    def run_jail(self, jail, *args, **kwargs):
        assert self.active[jail]
        if args[0] == "service":
            key = jail, args[1]
            if args[2] in ("onestop", "onestart"):
                self.services[key] = args[2] == "onestart"
            code = int(not self.services.get(key, True)) if args[2] == "onestatus" else 0
            return SimpleNamespace(returncode=code, stdout="", stderr="")
        return SimpleNamespace(returncode=1 if args[0] == "pgrep" else 0,
                               stdout="1" if args[0].endswith("mariadb") else "", stderr="")

    def occ(self, *args, **kwargs):
        assert self.active[self.nc]
        self.events.append(args)
        if args[0] == "maintenance:mode":
            self.settings["system"]["maintenance"] = args[1] == "--on"
        return SimpleNamespace(returncode=0, stdout="", stderr="")


class UpgradeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="upgrade-run-")
        self.addCleanup(temporary.cleanup)
        self.target = Target(Path(temporary.name))
        self.selected = upgrade.plan(self.target, packages=False)

    def mocks(self, fail=None):
        from contextlib import ExitStack
        stack = ExitStack()
        self.addCleanup(stack.close)
        def snapshot(target, directory):
            self.assertFalse(any(target.active.values()))
            self.assertTrue(target.settings["system"]["maintenance"])
            target.events.append(("snapshot",))
            if fail == "snapshot":
                raise ValueError("snapshot failure")
            return {"snapshots": ["owned@before"]}
        def restore(target, record):
            self.assertFalse(any(target.active.values()))
            target.events.append(("rollback",))
            if fail == "rollback":
                raise ValueError("rollback failure")
            target.version = "35.0.1"
        def apply(target, prepared, checkpoint):
            self.assertIn(("snapshot",), target.events)
            self.assertTrue(target.settings["system"]["maintenance"])
            self.assertFalse(any(target.services[(getattr(target, role), name)]
                                 for role, name in upgrade.WEB_SERVICES))
            target.version = "35.0.2"
            if fail in ("update", "rollback"):
                raise RuntimeError("native update failure")
            return {"version": target.version}
        return {name: stack.enter_context(patch(path, **kwargs)) for name, path, kwargs in (
            ("prepare", "installer.upgrade_nextcloud.prepare", dict(return_value=SimpleNamespace(summary={"authenticated": True}))),
            ("apply", "installer.upgrade_nextcloud.apply", dict(side_effect=apply)),
            ("snapshot", "installer.upgrade_backup.create", dict(side_effect=snapshot)),
            ("restore", "installer.upgrade_backup.restore", dict(side_effect=restore)))}

    def test_snapshot_precedes_mutation_and_success_preserves_settings(self):
        calls = self.mocks()
        result = upgrade.execute(self.target, self.selected, confirm=lambda phrase: phrase == "UPGRADE cloud")
        self.assertEqual(result["state"], "complete")
        self.assertEqual(self.target.version, "35.0.2")
        self.assertFalse(self.target.settings["system"]["maintenance"])
        self.assertTrue(all(self.target.services.values()))
        calls["snapshot"].assert_called_once()
        calls["restore"].assert_not_called()
        self.assertNotIn("PRIVATE", json.dumps(result))

    def test_failed_upgrade_offers_restore_without_rolling_back(self):
        calls = self.mocks("update")
        result = upgrade.execute(self.target, self.selected, confirm=lambda _: True)
        self.assertEqual(result["state"], "failed")
        self.assertIn("--restore", result["restore_command"])
        self.assertEqual(self.target.version, "35.0.2")
        self.assertFalse(any(self.target.active.values()))
        calls["restore"].assert_not_called()
        calls["apply"].assert_called_once()

    def diagnostic_storage_failure(self, phase):
        calls = self.mocks("update" if phase == "migration" else None)
        if phase == "verification":
            self.target.verify = Mock(side_effect=RuntimeError("verification failure"))
        original = upgrade.atomic_json

        def write(path, value):
            if path.name == "failure.json" or value.get("state") == "failed":
                # Both recovery and the original failure remain independent of
                # an unwritable diagnostic/report directory.
                self.assertFalse(any(self.target.active.values()))
                raise OSError("private-diagnostic-write-error")
            return original(path, value)

        with patch.object(upgrade, "atomic_json", side_effect=write):
            report = upgrade.execute(self.target, self.selected, confirm=lambda _: True)
        self.assertEqual(report["state"], "failed")
        self.assertEqual(report["error_type"], "RuntimeError")
        self.assertTrue(report["diagnostics_incomplete"])
        self.assertFalse(report["report_saved"])
        self.assertFalse(any(self.target.active.values()))
        self.assertIn("--restore", report["restore_command"])
        self.assertNotIn("private-diagnostic", json.dumps(report))
        calls["restore"].assert_not_called()
        calls["apply"].assert_called_once()

    def test_diagnostic_failure_after_migration_cannot_skip_containment(self):
        self.diagnostic_storage_failure("migration")

    def test_diagnostic_failure_after_reopening_cannot_skip_containment(self):
        self.diagnostic_storage_failure("verification")

    def test_logging_failure_before_snapshot_does_not_prevent_original_service_recovery(self):
        calls = self.mocks("snapshot")
        original = upgrade.atomic_json

        def write(path, value):
            if path.name == "failure.json" or value.get("state") == "failed":
                raise OSError("private-storage-error")
            return original(path, value)

        with patch.object(upgrade, "atomic_json", side_effect=write):
            report = upgrade.execute(self.target, self.selected, confirm=lambda _: True)
        self.assertEqual(report["state"], "failed")
        self.assertIn("original services restored", report["recovery"])
        self.assertTrue(all(self.target.active.values()))
        self.assertTrue(all(self.target.services.values()))
        self.assertFalse(self.target.settings["system"]["maintenance"])
        calls["apply"].assert_not_called()
        calls["restore"].assert_not_called()

    def test_logging_failure_does_not_mask_failed_containment(self):
        self.mocks("update")
        original_jails, original_write = upgrade._jails, upgrade.atomic_json

        def jails(target, action):
            if action == "stop" and target.version == "35.0.2":
                raise RuntimeError("private-stop-error")
            return original_jails(target, action)

        def write(path, value):
            if path.name == "failure.json" or value.get("state") == "failed":
                raise OSError("private-storage-error")
            return original_write(path, value)

        with patch.object(upgrade, "_jails", side_effect=jails), patch.object(upgrade, "atomic_json", side_effect=write):
            report = upgrade.execute(self.target, self.selected, confirm=lambda _: True)
        self.assertEqual(report["state"], "failed")
        self.assertIn("operator attention", report["recovery"])
        self.assertNotIn("Jails stopped", report["recovery"])
        self.assertNotIn("restore_command", report)
        self.assertNotIn("private-", json.dumps(report))

    def test_restore_containment_precedes_diagnostics_even_after_reopening(self):
        calls = self.mocks()
        self.target.verify = Mock(side_effect=RuntimeError("private-verify-error"))
        path = self.target.state / "report.json"
        path.write_text(json.dumps({"instance": "cloud", "state": "captured"})); path.chmod(0o600)

        def write(path, value):
            self.assertFalse(any(self.target.active.values()))
            raise OSError("private-diagnostic-error")

        with patch.object(upgrade, "atomic_json", side_effect=write):
            with self.assertRaisesRegex(RuntimeError, "Affected jails are stopped") as caught:
                upgrade.restore_snapshot(self.target, path, confirm=lambda _: True)
        self.assertIn("report could not be saved", str(caught.exception))
        self.assertNotIn("private-", str(caught.exception))
        self.assertFalse(any(self.target.active.values()))
        calls["restore"].assert_called_once()

    def test_restore_never_claims_stopped_if_containment_failed(self):
        self.mocks()
        self.target.verify = Mock(side_effect=RuntimeError("private-verify-error"))
        path = self.target.state / "report.json"
        path.write_text(json.dumps({"instance": "cloud", "state": "captured"})); path.chmod(0o600)
        original = upgrade._jails

        def jails(target, action):
            if action == "stop" and self.target.verify.called:
                raise RuntimeError("private-stop-error")
            return original(target, action)

        with patch.object(upgrade, "_jails", side_effect=jails), patch.object(upgrade, "atomic_json", side_effect=OSError):
            with self.assertRaisesRegex(RuntimeError, "Could not confirm affected jails stopped") as caught:
                upgrade.restore_snapshot(self.target, path, confirm=lambda _: True)
        self.assertNotIn("private-", str(caught.exception))

    def test_interrupted_restore_attempts_containment_even_if_logging_fails(self):
        self.mocks()
        self.target.verify = Mock(side_effect=KeyboardInterrupt)
        path = self.target.state / "report.json"
        path.write_text(json.dumps({"instance": "cloud", "state": "captured"})); path.chmod(0o600)
        with patch.object(upgrade, "atomic_json", side_effect=OSError):
            with self.assertRaises(KeyboardInterrupt):
                upgrade.restore_snapshot(self.target, path, confirm=lambda _: True)
        self.assertFalse(any(self.target.active.values()))

    def test_selected_scanner_services_stop_before_snapshot_and_restart_before_web(self):
        self.target.config.antivirus = True
        for name in ("clamav_freshclam", "clamav_clamd"):
            self.target.services[self.target.nc, name] = True
        mocks = self.mocks()
        original_snapshot = mocks["snapshot"].side_effect
        def snapshot(target, directory):
            for name in ("clamav_freshclam", "clamav_clamd"):
                self.assertFalse(target.services[target.nc, name])
            return original_snapshot(target, directory)
        mocks["snapshot"].side_effect = snapshot
        with patch.object(self.target, "run_jail", wraps=self.target.run_jail) as run:
            result = upgrade.execute(self.target, self.selected, confirm=lambda _: True)
        self.assertEqual(result["state"], "complete")
        self.assertTrue(all(self.target.services.values()))
        starts = [call.args[2] for call in run.call_args_list
                  if call.args[1] == "service" and call.args[3] == "onestart"]
        self.assertLess(starts.index("clamav_clamd"), starts.index("php_fpm"))
        self.assertLess(starts.index("clamav_clamd"), starts.index("clamav_freshclam"))
        mocks["restore"].assert_not_called()

    def test_explicit_restore_requires_consent_and_failure_keeps_jails_stopped(self):
        calls = self.mocks("rollback")
        record = {"instance": "cloud", "state": "captured"}
        path = self.target.state / "report.json"
        path.write_text(json.dumps(record)); path.chmod(0o600)
        self.assertEqual(upgrade.restore_snapshot(self.target, path, confirm=lambda _: False)["state"], "cancelled")
        calls["restore"].assert_not_called()
        with self.assertRaisesRegex(RuntimeError, "restore did not complete"):
            upgrade.restore_snapshot(self.target, path, confirm=lambda phrase: phrase == "RESTORE cloud")
        self.assertFalse(any(self.target.active.values()))

    def test_snapshot_failure_never_starts_upgrade(self):
        calls = self.mocks("snapshot")
        result = upgrade.execute(self.target, self.selected, confirm=lambda _: True)
        self.assertEqual(result["state"], "failed")
        calls["apply"].assert_not_called()
        calls["restore"].assert_not_called()
        self.assertFalse(self.target.settings["system"]["maintenance"])

    def test_explicit_restore_verifies_original_and_updates_fingerprint(self):
        calls = self.mocks()
        self.target.version = "35.0.2"
        path = self.target.state / "report.json"
        path.write_text(json.dumps({"instance": "cloud", "state": "captured"})); path.chmod(0o600)
        result = upgrade.restore_snapshot(self.target, path, confirm=lambda phrase: phrase == "RESTORE cloud")
        self.assertEqual(result["state"], "restored")
        self.assertEqual(result["verification"]["nextcloud"], "35.0.1")
        self.assertIn(("maintenance:data-fingerprint",), self.target.events)
        calls["restore"].assert_called_once()

    def test_cancel_and_changed_configuration_have_no_mutation(self):
        calls = self.mocks()
        self.assertEqual(upgrade.execute(self.target, self.selected, confirm=lambda _: False)["state"], "cancelled")
        self.target.settings["system"]["custom"] = "changed"
        with self.assertRaises(ValueError):
            upgrade.execute(self.target, self.selected, confirm=lambda _: True)
        calls["snapshot"].assert_not_called()
        self.assertFalse(self.target.events)

    def test_noop_has_no_downtime_or_snapshot(self):
        self.target.version = "35.0.2"
        selected = upgrade.plan(self.target, packages=False)
        calls = self.mocks()
        result = upgrade.execute(self.target, selected, confirm=Mock(side_effect=AssertionError("No consent needed")))
        self.assertFalse(result["changed"])
        calls["snapshot"].assert_not_called()
        self.assertFalse(self.target.events)

    def test_package_failure_offers_restore_and_never_runs_nc_updater(self):
        calls = self.mocks()
        self.selected["packages"] = {"jails": {"nextcloud": {"actions": [{"name": "php85"}]}}}
        with patch("installer.upgrade_packages.revalidate"), patch("installer.upgrade_packages.apply", return_value={"status": "failed"}):
            result = upgrade.execute(self.target, self.selected, confirm=lambda _: True)
        self.assertIn("--restore", result["restore_command"])
        calls["restore"].assert_not_called()
        calls["apply"].assert_not_called()

    def test_stop_waits_for_dying_jail_without_killing_or_restarting_it(self):
        original = self.target.output
        observations = iter([f"7 cloudnc {self.target.nc_root} true", ""])
        def output(*args):
            return next(observations) if args[0] == "jls" else original(*args)
        self.target.runner.output = output
        with patch.object(upgrade.time, "sleep") as sleep:
            upgrade._jails(self.target, "stop")
        sleep.assert_called_once_with(0.2)
        self.assertEqual(self.target.events, [("bastille", "stop", "cloudoo"), ("bastille", "stop", "cloudnc")])

    def test_dying_jail_timeout_and_malformed_output_refuse(self):
        original = self.target.output
        self.target.runner.output = lambda *args: f"7 cloudnc {self.target.nc_root} true" if args[0] == "jls" else original(*args)
        with patch.object(upgrade.time, "monotonic", side_effect=[0, 121]):
            with self.assertRaisesRegex(RuntimeError, "teardown"):
                upgrade._jails(self.target, "stop")
        self.target.runner.output = lambda *args: "unrecognized" if args[0] == "jls" else original(*args)
        with self.assertRaisesRegex(RuntimeError, "Invalid live/dying"):
            upgrade._jails(self.target, "stop")

    def test_failure_details_are_private_not_in_public_report(self):
        calls = self.mocks()
        calls["snapshot"].side_effect = ValueError("PRIVATE fixture diagnostic")
        result = upgrade.execute(self.target, self.selected, confirm=lambda _: True)
        self.assertNotIn("PRIVATE", json.dumps(result))
        detail = Path(result["diagnostic_file"])
        self.assertEqual(detail.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(detail.read_text())["message"], "PRIVATE fixture diagnostic")


if __name__ == "__main__":
    unittest.main()
