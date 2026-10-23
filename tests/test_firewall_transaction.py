"""PF transaction tests with private scratch files and mocked native commands."""

import fcntl
import json
import io
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from installer import firewall


SCRATCH = Path(tempfile.gettempdir())
PREVIOUS_SSH = "pass out quick inet proto tcp from 192.0.2.10 port 22 to 198.51.100.5 port 50222 flags any keep state\n"
PF_EXPECTED = {("-sr",): "block drop all\n" + PREVIOUS_SSH,
               ("-sn",): "nat on igb0 inet from <cloud_jails> to any -> (igb0:0)\n",
               ("-t", "cloud_jails", "-T", "show"): "   10.77.0.2\n   10.77.0.6\n",
               ("-t", "cloud_noninternet", "-T", "show"): "   10.0.0.0/8\n"}


def native_result(args, *, returncode=0, **kwargs):
    output = PF_EXPECTED.get(tuple(args[1:]), "") if args[0] == "/sbin/pfctl" else ""
    if tuple(args) == ("/sbin/ifconfig", "-l"):
        output = "igb0 lo0 bridge240 bridge241 bridge242 bridge243\n"
    elif args[0] == "/sbin/ifconfig" and len(args) == 2 and args[1].startswith("bridge"):
        address = {"bridge242": "10.78.0.1", "bridge243": "10.78.0.5"}.get(args[1], "10.77.0.1")
        output = f"{args[1]}: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500\n\tinet {address} netmask 0xfffffffc\n"
    return SimpleNamespace(returncode=returncode, stdout=output)


class FirewallTransactionTests(unittest.TestCase):
    def transaction(self, state):
        settings = {"deadline": 200, "forwarding": "0", "bridge_sysctls": {
            "net.link.bridge.pfil_member": "0", "net.link.bridge.pfil_bridge": "0"},
                    "bridges": ["bridge240", "bridge241"], "backups": {}}
        firewall.exclusive_file(state / "firewall-transition.json", json.dumps(settings))
        firewall.exclusive_file(state / "firewall.lock", "")
        return settings

    def network_transaction(self, root, *, previous=True):
        transactions = root / "transactions"
        transactions.mkdir(mode=0o700)
        state = transactions / "pending"
        state.mkdir(mode=0o700)
        settings = self.transaction(state)
        active = root / "network" / "active"
        active.parent.mkdir(mode=0o700)
        previous_state = transactions / "previous" if previous else None
        if previous_state:
            previous_state.mkdir(mode=0o700)
            firewall.exclusive_file(previous_state / "firewall-confirmed", "previous commit\n")
            active.symlink_to(previous_state)
        pf_file, sysctl_file = root / "pf.conf", root / "sysctl.conf"
        sysctls = {"net.link.bridge.pfil_member": "0", "net.link.bridge.pfil_bridge": "1",
                   "net.link.bridge.pfil_local_phys": "0", "net.link.bridge.pfil_onlyip": "1"}
        sysctl_file.write_text("# Preserve foreign settings.\nkern.maxfiles=12345\n")
        if previous:
            pf_file.write_text("# previous managed policy\nblock all\n" + PREVIOUS_SSH)
            firewall.exclusive_file(previous_state / "firewall-transition.json", json.dumps({
                "network": {"pf_file": str(pf_file), "pf_rules": pf_file.read_text()}}))
            for name, args in firewall.PF_SNAPSHOTS:
                firewall.exclusive_file(previous_state / f"pf-{name}.expected", PF_EXPECTED[args])
            # Recognize the original installer's block, which had no end marker.
            with sysctl_file.open("a") as stream:
                stream.write(f"\n{firewall.SYSCTL_BEGIN}\n")
                stream.write("".join(f"{name}={value}\n" for name, value in sysctls.items()))
        rc_file = root / "rc.conf"
        loader_file = root / "loader.conf"
        rc_file.write_text('cloned_interfaces="bridge240 bridge241"\n')
        loader_file.write_text('if_bridge_load="YES"\n')
        backups = {}
        for path in (pf_file, sysctl_file, rc_file, loader_file):
            backups[str(path)] = path.name + ".before" if path.exists() else None
            if path.exists():
                firewall.exclusive_file(state / backups[str(path)], path.read_text())
        settings.update({"boot_identity": "boot-before", "forwarding": "1" if previous else "0", "bridge_sysctls": sysctls,
                         "bridges": ["bridge242", "bridge243"], "backups": backups,
                         "previous_pf_enabled": previous,
                         "previous_pf_file": str(state / "pf.conf.before") if previous else None,
                         "active_link": str(active), "previous_active": str(previous_state) if previous else None,
                         "network": {"bridge_addresses": {"bridge242": "10.78.0.1", "bridge243": "10.78.0.5"},
                                     "bridge_sysctls": sysctls, "pf_file": str(pf_file),
                                     "pf_rules": "# all reviewed instances\nblock all\n"}})
        (state / "firewall-transition.json").write_text(json.dumps(settings))
        return SimpleNamespace(state=state, settings=settings, active=active, previous=previous_state,
                               pf_file=pf_file, sysctl_file=sysctl_file, rc_file=rc_file, loader_file=loader_file)

    def test_pending_scan_is_readonly_and_ignores_resolved_or_unarmed_diagnostics(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-pending-") as directory:
            root = Path(directory)
            self.assertEqual(firewall.pending_transactions(root / "absent"), ())
            self.assertFalse((root / "absent").exists())
            self.assertEqual(firewall.pending_transactions(root), ())
            self.assertFalse((root / "transactions").exists())
            transactions = root / "transactions"
            transactions.mkdir(mode=0o700)
            for name in ("z-pending", "a-pending", "confirmed", "rolled-back", "empty", "diagnostics"):
                state = transactions / name
                state.mkdir(mode=0o700)
                if name in ("empty", "diagnostics"):
                    if name == "diagnostics":
                        firewall.exclusive_file(state / "rc.conf.before", "retained pre-arm backup\n")
                    continue
                self.transaction(state)
                if name in ("confirmed", "rolled-back"):
                    firewall.exclusive_file(state / f"firewall-{name}", "resolved\n")
            with patch("installer.firewall.subprocess.run") as run, patch("installer.firewall.time.monotonic") as clock:
                self.assertEqual(firewall.pending_transactions(root),
                                 (transactions / "a-pending", transactions / "z-pending"))
            run.assert_not_called()
            clock.assert_not_called()  # A pending record blocks new work even after its deadline.

    def test_pending_scan_rejects_symlinks_at_every_state_boundary(self):
        for location in ("root", "transactions", "state", "json", "marker", "backup"):
            with self.subTest(location=location), tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-unsafe-") as directory:
                root = Path(directory) / "registry"
                root.mkdir(mode=0o700)
                fixture = self.network_transaction(root)
                if location == "root":
                    target = root
                elif location == "transactions":
                    target = root / "transactions"
                elif location == "state":
                    target = fixture.state
                elif location == "json":
                    target = fixture.state / "firewall-transition.json"
                elif location == "backup":
                    target = fixture.state / "pf.conf.before"
                else:
                    target = fixture.state / "firewall-confirmed"
                    firewall.exclusive_file(target, "not really committed\n")
                moved = Path(directory) / "outside"
                target.rename(moved)
                target.symlink_to(moved)
                with self.assertRaisesRegex(ValueError, "Unsafe private network state"):
                    firewall.pending_transactions(root)

    def test_pending_scan_rejects_foreign_owners_public_files_and_hardlinks(self):
        for failure in ("root-mode", "directory-mode", "json-mode", "backup-mode", "marker-mode", "hardlink", "owner"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-unsafe-") as directory:
                root = Path(directory)
                fixture = self.network_transaction(root)
                if failure == "root-mode":
                    root.chmod(0o755)
                elif failure == "directory-mode":
                    fixture.state.chmod(0o750)
                elif failure == "json-mode":
                    (fixture.state / "firewall-transition.json").chmod(0o644)
                elif failure == "backup-mode":
                    (fixture.state / "pf.conf.before").chmod(0o640)
                elif failure == "marker-mode":
                    firewall.exclusive_file(fixture.state / "firewall-rolled-back", "unsafe marker\n")
                    (fixture.state / "firewall-rolled-back").chmod(0o644)
                elif failure == "hardlink":
                    os.link(fixture.state / "firewall-transition.json", root / "other-json")
                expected_owner = os.geteuid() + 1 if failure == "owner" else os.geteuid()
                with patch("installer.firewall.os.geteuid", return_value=expected_owner), \
                        self.assertRaisesRegex(ValueError, "Unsafe private network state"):
                    firewall.pending_transactions(root)

    def test_reboot_recovery_ignores_old_monotonic_deadline_and_restores_fresh_or_repeat_state(self):
        for previous in (False, True):
            with self.subTest(previous=previous), tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-recovery-") as directory:
                root = Path(directory)
                fixture = self.network_transaction(root, previous=previous)
                fixture.settings["deadline"] = 10 ** 12  # Uptime from a different boot is not comparable.
                (fixture.state / "firewall-transition.json").write_text(json.dumps(fixture.settings))
                fixture.pf_file.write_text("unconfirmed on-disk policy after reboot\n")
                fixture.rc_file.write_text("unconfirmed boot settings\n")
                firewall.active_pointer(fixture.state, fixture.settings)
                self.assertEqual(firewall.pending_transactions(root), (fixture.state,))
                with patch("installer.firewall.time.monotonic", side_effect=AssertionError("old-boot clock comparison")), \
                        patch("installer.firewall.time.sleep") as sleep, patch("installer.firewall.os.kill") as kill, \
                        patch("installer.firewall.os.killpg") as killpg, \
                        patch("installer.firewall.subprocess.run", side_effect=native_result) as run:
                    self.assertIsNone(firewall.recover_pending(fixture.state, "boot-after"))
                sleep.assert_not_called()
                kill.assert_not_called()
                killpg.assert_not_called()
                self.assertEqual(firewall.pending_transactions(root), ())
                self.assertTrue((fixture.state / "firewall-rolled-back").exists())
                self.assertEqual(fixture.rc_file.read_text(), (fixture.state / "rc.conf.before").read_text())
                commands = [tuple(call.args[0]) for call in run.call_args_list]
                self.assertEqual(commands[:2], [("/sbin/kldstat", "-q", "-m", "pf"),
                                                ("/sbin/kldstat", "-q", "-m", "if_bridge")])
                self.assertFalse(any(command[0] == "/sbin/kldload" for command in commands))
                if previous:
                    self.assertEqual(fixture.active.readlink(), fixture.previous)
                    self.assertEqual(fixture.pf_file.read_text(), (fixture.state / "pf.conf.before").read_text())
                    self.assertIn(("/sbin/pfctl", "-nf", fixture.settings["previous_pf_file"]), commands)
                    self.assertIn(("/sbin/pfctl", "-f", fixture.settings["previous_pf_file"]), commands)
                    self.assertFalse(any(command[:2] in (("/sbin/pfctl", "-d"), ("/sbin/pfctl", "-F")) for command in commands))
                else:
                    self.assertFalse(fixture.active.is_symlink())
                    self.assertEqual(fixture.pf_file.read_text(), "")
                    self.assertIn(("/sbin/pfctl", "-d"), commands)
                with patch("installer.firewall.subprocess.run") as repeated:
                    firewall.recover_pending(fixture.state, "boot-after")
                    firewall.rollback(fixture.state)  # A surviving supervisor also observes the marker.
                repeated.assert_not_called()
                with patch("installer.firewall.time.monotonic", return_value=100), self.assertRaises(RuntimeError):
                    with firewall.mutation(fixture.state):
                        self.fail("Recovered state must never resume applying")

    def test_recovery_autoloads_missing_modules_under_lock_before_any_network_rollback(self):
        for previous in (False, True):
            with self.subTest(previous=previous), tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-modules-") as directory:
                fixture = self.network_transaction(Path(directory), previous=previous)
                fixture.settings["deadline"] = 10 ** 12
                (fixture.state / "firewall-transition.json").write_text(json.dumps(fixture.settings))
                def native(args, **kwargs):
                    if args[0] in ("/sbin/kldstat", "/sbin/kldload"):
                        with (fixture.state / "firewall.lock").open("r+") as contender, self.assertRaises(BlockingIOError):
                            fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        return native_result(args, returncode=1 if args[0] == "/sbin/kldstat" else 0)
                    return native_result(args)
                with patch("installer.firewall.subprocess.run", side_effect=native) as run, \
                        patch("installer.firewall.time.monotonic", side_effect=AssertionError("old-boot clock comparison")):
                    firewall.recover_pending(fixture.state, "boot-after")
                commands = [tuple(call.args[0]) for call in run.call_args_list]
                self.assertEqual(commands[:4], [("/sbin/kldstat", "-q", "-m", "pf"), ("/sbin/kldload", "pf"),
                                                ("/sbin/kldstat", "-q", "-m", "if_bridge"), ("/sbin/kldload", "if_bridge")])
                self.assertEqual(commands[4][0], "/sbin/pfctl" if previous else "/sbin/sysctl")
                self.assertTrue((fixture.state / "firewall-rolled-back").exists())

    def test_module_loading_failure_does_not_attempt_policy_rollback_or_mark_success(self):
        for previous in (False, True):
            for module in ("pf", "if_bridge"):
                with self.subTest(previous=previous, module=module), \
                        tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-modules-") as directory:
                    root = Path(directory)
                    fixture = self.network_transaction(root, previous=previous)
                    def native(args, **kwargs):
                        if tuple(args) == ("/sbin/kldload", module):
                            raise subprocess.CalledProcessError(1, args)
                        return native_result(args, returncode=1 if args[0] == "/sbin/kldstat" else 0)
                    with patch("installer.firewall.subprocess.run", side_effect=native) as run, \
                            self.assertRaisesRegex(RuntimeError, "could not prepare module " + module):
                        firewall.recover_pending(fixture.state, "boot-after")
                    self.assertTrue(all(call.args[0][0] in ("/sbin/kldstat", "/sbin/kldload") for call in run.call_args_list))
                    self.assertEqual(firewall.pending_transactions(root), (fixture.state,))

    def test_same_boot_recovery_requires_expiry_without_waiting_or_native_calls(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-recovery-") as directory:
            root = Path(directory)
            fixture = self.network_transaction(root)
            with patch("installer.firewall.time.monotonic", return_value=199), \
                    patch("installer.firewall.time.sleep") as sleep, patch("installer.firewall.subprocess.run") as run, \
                    self.assertRaisesRegex(RuntimeError, "deadline to expire"):
                firewall.recover_pending(fixture.state, "boot-before")
            sleep.assert_not_called()
            run.assert_not_called()
            self.assertEqual(firewall.pending_transactions(root), (fixture.state,))
            with patch("installer.firewall.time.monotonic", return_value=200), \
                    patch("installer.firewall.subprocess.run", side_effect=native_result):
                firewall.recover_pending(fixture.state, "boot-before")
            self.assertEqual(firewall.pending_transactions(root), ())

    def test_recovery_refuses_a_held_lock_nonblocking_without_signalling_its_owner(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-recovery-") as directory:
            root = Path(directory)
            fixture = self.network_transaction(root)
            with (fixture.state / "firewall.lock").open("r+") as owner:
                fcntl.flock(owner, fcntl.LOCK_EX)
                actual_flock = fcntl.flock
                def nonblocking(lock, operation):
                    self.assertEqual(operation, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    actual_flock(lock, operation)
                with patch("installer.firewall.fcntl.flock", side_effect=nonblocking) as flock, \
                        patch("installer.firewall.time.monotonic", return_value=201), \
                        patch("installer.firewall.time.sleep") as sleep, patch("installer.firewall.os.killpg") as killpg, \
                        patch("installer.firewall.subprocess.run") as run, self.assertRaisesRegex(RuntimeError, "lock is busy"):
                    firewall.recover_pending(fixture.state, "boot-before")
                flock.assert_called_once()
                sleep.assert_not_called()
                killpg.assert_not_called()
                run.assert_not_called()
            self.assertEqual(firewall.pending_transactions(root), (fixture.state,))

    def test_recovery_of_resolved_markers_is_idempotent_even_before_expiry(self):
        for marker in ("firewall-confirmed", "firewall-rolled-back"):
            with self.subTest(marker=marker), tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-recovery-") as directory:
                fixture = self.network_transaction(Path(directory))
                firewall.exclusive_file(fixture.state / marker, "already resolved\n")
                with patch("installer.firewall.time.monotonic") as clock, patch("installer.firewall.subprocess.run") as run:
                    self.assertIsNone(firewall.recover_pending(fixture.state, "boot-before"))
                clock.assert_not_called()
                run.assert_not_called()
                self.assertEqual((fixture.state / marker).read_text(), "already resolved\n")

    def test_recovery_rechecks_resolution_after_acquiring_the_lock(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-recovery-") as directory:
            fixture = self.network_transaction(Path(directory))
            actual_flock = fcntl.flock
            def resolved_before_lock(lock, operation):
                firewall.exclusive_file(fixture.state / "firewall-rolled-back", "supervisor finished\n")
                actual_flock(lock, operation)
            with patch("installer.firewall.fcntl.flock", side_effect=resolved_before_lock) as flock, \
                    patch("installer.firewall.subprocess.run") as run:
                firewall.recover_pending(fixture.state, "boot-after")
            flock.assert_called_once()
            run.assert_not_called()
            self.assertEqual((fixture.state / "firewall-rolled-back").read_text(), "supervisor finished\n")

    def test_explicit_recovery_handles_a_record_written_before_the_watchdog_was_armed(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-recovery-") as directory:
            root = Path(directory)
            fixture = self.network_transaction(root, previous=False)
            (fixture.state / "firewall.lock").unlink()
            self.assertEqual(firewall.pending_transactions(root), (fixture.state,))
            def native(args, **kwargs):
                return native_result(args, returncode=0 if kwargs.get("check") else 1)
            with patch("installer.firewall.subprocess.run", side_effect=native):
                firewall.recover_pending(fixture.state, "boot-after")
            self.assertEqual((fixture.state / "firewall.lock").stat().st_mode & 0o777, 0o600)
            self.assertEqual(firewall.pending_transactions(root), ())

    def test_recovery_refuses_an_unrelated_active_pointer_before_changing_live_pf(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-recovery-") as directory:
            fixture = self.network_transaction(Path(directory))
            fixture.active.unlink()
            fixture.active.symlink_to(Path(directory) / "another-transaction")
            with patch("installer.firewall.subprocess.run") as run, \
                    self.assertRaisesRegex(ValueError, "outside this transaction"):
                firewall.recover_pending(fixture.state, "boot-after")
            run.assert_not_called()
            self.assertFalse((fixture.state / "firewall-rolled-back").exists())

    def test_recovery_refuses_missing_boot_identity_new_fields_and_unsafe_backups(self):
        for failure in ("boot_identity", "previous_pf_enabled", "previous_pf_file", "previous_active", "active_link",
                        "network", "empty-boot", "invalid-current-boot", "nan-deadline", "symlink-backup", "escaped-backup"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-recovery-") as directory:
                fixture = self.network_transaction(Path(directory))
                current_boot = "boot-before"
                if failure in fixture.settings:
                    del fixture.settings[failure]
                elif failure == "empty-boot":
                    fixture.settings["boot_identity"] = ""
                elif failure == "invalid-current-boot":
                    current_boot = None
                elif failure == "nan-deadline":
                    fixture.settings["deadline"] = float("nan")
                elif failure == "escaped-backup":
                    fixture.settings["backups"][str(fixture.rc_file)] = "../rc.conf.before"
                else:
                    backup = fixture.state / "rc.conf.before"
                    backup.unlink()
                    backup.symlink_to(fixture.rc_file)
                (fixture.state / "firewall-transition.json").write_text(json.dumps(fixture.settings))
                with patch("installer.firewall.time.monotonic", return_value=1000), \
                        patch("installer.firewall.subprocess.run") as run, self.assertRaises(ValueError):
                    firewall.recover_pending(fixture.state, current_boot)
                run.assert_not_called()
                self.assertFalse((fixture.state / "firewall-rolled-back").exists())

    def test_recovery_failure_stays_pending_without_disabling_prior_pf(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-recovery-") as directory:
            root = Path(directory)
            fixture = self.network_transaction(root)
            def native(args, **kwargs):
                if tuple(args)[:2] == ("/sbin/pfctl", "-f"):
                    raise subprocess.CalledProcessError(1, args)
                return native_result(args)
            with patch("installer.firewall.subprocess.run", side_effect=native) as run, \
                    self.assertRaisesRegex(RuntimeError, "PF was NOT disabled or flushed"):
                firewall.recover_pending(fixture.state, "boot-after")
            self.assertFalse(any(tuple(call.args[0])[:2] in (("/sbin/pfctl", "-d"), ("/sbin/pfctl", "-F"))
                                 for call in run.call_args_list))
            self.assertEqual(firewall.pending_transactions(root), (fixture.state,))

    def test_commit_persists_boot_policy_and_marker_last(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-test-") as directory:
            state = Path(directory)
            self.transaction(state)
            runner = Mock()
            runner.run.return_value.stdout = "   10.77.0.2\n   10.77.0.6\n"
            actual_write = firewall.exclusive_file
            writes = []
            def write(path, contents):
                writes.append(path.name)
                if path.name == "firewall-confirmed":
                    self.assertIn(("sysctl", "net.inet.ip.forwarding=1"), [call.args for call in runner.run.call_args_list])
                actual_write(path, contents)
            with patch("installer.firewall.time.monotonic", return_value=100), patch("installer.firewall.exclusive_file", write):
                firewall.commit(state, runner, "/etc/pf.cloud-installer.conf")
            self.assertEqual(writes[-1], "firewall-confirmed")
            self.assertEqual((state / "pf-jails.expected").read_text(), "   10.77.0.2\n   10.77.0.6\n")
            self.assertEqual((state / "firewall-confirmed").stat().st_mode & 0o777, 0o600)

    def test_expired_confirmation_never_activates_boot_policy(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-test-") as directory:
            state = Path(directory)
            self.transaction(state)
            runner = Mock()
            with patch("installer.firewall.time.monotonic", return_value=201), self.assertRaises(RuntimeError):
                firewall.commit(state, runner, "not-used")
            runner.run.assert_not_called()
            self.assertFalse((state / "firewall-confirmed").exists())

    def test_commit_durably_publishes_pending_pointer_before_final_confirmation(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-commit-") as directory:
            fixture = self.network_transaction(Path(directory))
            runner = Mock()
            runner.run.return_value.stdout = "snapshot\n"
            events = []
            actual_write, actual_sync = firewall.exclusive_file, firewall.fsync_directory
            def sync(path):
                actual_sync(path)
                events.append(("sync", Path(path)))
            def write(path, contents):
                if path.name == "firewall-confirmed":
                    self.assertEqual(fixture.active.readlink(), fixture.state)
                    self.assertFalse(path.exists())
                    self.assertEqual(events[-1], ("sync", fixture.active.parent))
                    for name in ("filter", "nat", "jails", "noninternet"):
                        self.assertEqual((fixture.active / f"pf-{name}.expected").read_text(), "snapshot\n")
                events.append(("write", path.name))
                actual_write(path, contents)
            with patch("installer.firewall.time.monotonic", return_value=100), \
                    patch("installer.firewall.fsync_directory", sync), patch("installer.firewall.exclusive_file", write):
                firewall.commit(fixture.state, runner, str(fixture.pf_file))
            self.assertEqual(events[-2:], [("write", "firewall-confirmed"), ("sync", fixture.state)])
            self.assertEqual(fixture.active.readlink(), fixture.state)
            self.assertTrue((fixture.active / "firewall-confirmed").exists())
            with patch("installer.firewall.time.monotonic", return_value=100):
                runner.reset_mock()
                with self.assertRaises(RuntimeError):
                    firewall.commit(fixture.state, runner, str(fixture.pf_file))
                runner.run.assert_not_called()

    def test_partial_commit_deadline_or_io_failure_restores_previous_active_pointer(self):
        for failure in ("deadline", "pointer-fsync", "confirmation", "confirmation-fsync"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-partial-") as directory:
                fixture = self.network_transaction(Path(directory))
                runner = Mock()
                runner.run.return_value.stdout = "snapshot\n"
                now = [100]
                actual_pointer, actual_write = firewall.active_pointer, firewall.exclusive_file
                actual_sync = firewall.fsync_directory
                def pointer(*args, **kwargs):
                    actual_pointer(*args, **kwargs)
                    if failure == "deadline":
                        now[0] = 201
                def write(path, contents):
                    if failure == "confirmation" and path.name == "firewall-confirmed":
                        raise OSError("confirmation write fixture")
                    actual_write(path, contents)
                def sync(path):
                    if failure == "pointer-fsync" and path == fixture.active.parent:
                        raise OSError("pointer fsync fixture")
                    if (failure == "confirmation-fsync" and path == fixture.state
                            and (fixture.state / "firewall-confirmed").exists()):
                        raise OSError("confirmation fsync fixture")
                    actual_sync(path)
                with patch("installer.firewall.time.monotonic", side_effect=lambda: now[0]), \
                        patch("installer.firewall.active_pointer", pointer), patch("installer.firewall.exclusive_file", write), \
                        patch("installer.firewall.fsync_directory", sync), self.assertRaises((RuntimeError, OSError)):
                    firewall.commit(fixture.state, runner, str(fixture.pf_file))
                self.assertEqual(fixture.active.readlink(), fixture.state)
                self.assertFalse((fixture.active / "firewall-confirmed").exists())
                with patch("installer.firewall.subprocess.run", side_effect=native_result):
                    firewall.rollback(fixture.state)
                self.assertEqual(fixture.active.readlink(), fixture.previous)
                self.assertTrue((fixture.state / "firewall-rolled-back").exists())

    def test_fresh_partial_commit_removes_its_own_active_pointer(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-pointer-") as directory:
            fixture = self.network_transaction(Path(directory), previous=False)
            firewall.active_pointer(fixture.state, fixture.settings)
            self.assertEqual(fixture.active.readlink(), fixture.state)
            with patch("installer.firewall.subprocess.run", side_effect=native_result):
                firewall.rollback(fixture.state)
            self.assertFalse(fixture.active.is_symlink())
            self.assertTrue((fixture.state / "firewall-rolled-back").exists())

    def test_rollback_refuses_foreign_relative_or_regular_active_pointer(self):
        for destination in ("foreign", "relative", "regular"):
            with self.subTest(destination=destination), tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-pointer-") as directory:
                fixture = self.network_transaction(Path(directory), previous=False)
                if destination == "regular":
                    fixture.active.write_text("unrelated file\n")
                else:
                    fixture.active.symlink_to(Path(directory) / "foreign" if destination == "foreign" else "../pending")
                with patch("installer.firewall.subprocess.run", side_effect=native_result), \
                        self.assertRaisesRegex(RuntimeError, "pointer"):
                    firewall.rollback(fixture.state)
                if destination == "regular":
                    self.assertEqual(fixture.active.read_text(), "unrelated file\n")
                else:
                    self.assertEqual(str(fixture.active.readlink()),
                                     str(Path(directory) / "foreign") if destination == "foreign" else "../pending")
                self.assertFalse((fixture.state / "firewall-rolled-back").exists())

    def test_rollback_does_not_touch_a_committed_transaction(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-test-") as directory:
            state = Path(directory)
            self.transaction(state)
            firewall.exclusive_file(state / "firewall-confirmed", "confirmed\n")
            with patch("installer.firewall.subprocess.run") as run:
                firewall.rollback(state)
            run.assert_not_called()

    def test_final_notification_closes_broken_buffer_without_masking_other_errors(self):
        from unittest.mock import Mock
        stream = Mock()
        stream.flush.side_effect = BrokenPipeError("departed caller")
        stream.close.side_effect = BrokenPipeError("buffer reflush")
        firewall.notify_final(stream, "ROLLED_BACK")
        stream.write.assert_called_once_with("ROLLED_BACK\n")
        stream.close.assert_called_once_with()
        stream = Mock()
        stream.write.side_effect = ValueError("not a disconnected pipe")
        with self.assertRaises(ValueError):
            firewall.notify_final(stream, "COMMITTED")

    def test_unconfirmed_rollback_restores_configuration_not_application_data(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-test-") as directory:
            state = Path(directory)
            settings = self.transaction(state)
            original = state / "rc.conf.before"
            target = state / "rc.conf.simulated"
            original.write_text('sshd_enable="YES"\n')
            target.write_text('pf_enable="YES"\n')
            settings["backups"] = {str(target): original.name}
            (state / "firewall-transition.json").write_text(json.dumps(settings))
            with patch("installer.firewall.subprocess.run") as run:
                run.return_value.returncode = 0
                firewall.rollback(state)
            self.assertEqual(target.read_text(), original.read_text())
            commands = [call.args[0] for call in run.call_args_list]
            self.assertEqual(commands[0], ("/sbin/sysctl", "net.inet.ip.forwarding=0"))
            self.assertIs(run.call_args_list[0].kwargs["stdout"], firewall.sys.stderr)
            self.assertIn(("/sbin/pfctl", "-d"), commands)
            self.assertIn(("/sbin/pfctl", "-f", "/dev/null"), commands)
            self.assertIn(("/sbin/pfctl", "-F", "states"), commands)
            self.assertLess(commands.index(("/sbin/pfctl", "-d")), commands.index(("/sbin/pfctl", "-f", "/dev/null")))
            self.assertTrue((state / "firewall-rolled-back").exists())
            self.assertNotIn("zfs", repr(commands))
            self.assertNotIn("rm", repr(commands))

    def test_repeat_rollback_restores_previous_policy_and_only_new_bridges(self):
        for partial_commit in (False, True):
            with self.subTest(partial_commit=partial_commit), \
                    tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-repeat-") as directory:
                fixture = self.network_transaction(Path(directory))
                for path in (fixture.pf_file, fixture.sysctl_file, fixture.rc_file, fixture.loader_file):
                    path.write_text("unconfirmed replacement\n")
                if partial_commit:
                    firewall.active_pointer(fixture.state, fixture.settings)
                events = []
                def native(args, **kwargs):
                    events.append(tuple(args))
                    if args[:2] == ("/sbin/pfctl", "-nf"):
                        self.assertEqual(fixture.pf_file.read_text(), "unconfirmed replacement\n")
                    if args[:2] == ("/sbin/pfctl", "-f"):
                        self.assertEqual(fixture.pf_file.read_text(), Path(args[2]).read_text())
                    result = native_result(args)
                    if tuple(args[1:]) in PF_EXPECTED:
                        self.assertTrue(kwargs["capture_output"])
                        self.assertTrue(kwargs["text"])
                        self.assertEqual(fixture.rc_file.read_text(), "unconfirmed replacement\n")
                        result.stdout = result.stdout.rstrip("\n") + "\n\n"
                    return result
                with patch("installer.firewall.subprocess.run", side_effect=native):
                    firewall.rollback(fixture.state)
                previous_pf = fixture.settings["previous_pf_file"]
                self.assertLess(events.index(("/sbin/pfctl", "-nf", previous_pf)),
                                events.index(("/sbin/pfctl", "-f", previous_pf)))
                self.assertIn(("/sbin/sysctl", "net.inet.ip.forwarding=1"), events)
                for _, args in firewall.PF_SNAPSHOTS:
                    self.assertLess(events.index(("/sbin/pfctl", *args)),
                                    events.index(("/sbin/sysctl", "net.inet.ip.forwarding=1")))
                    self.assertLess(events.index(("/sbin/pfctl", *args)),
                                    events.index(("/sbin/ifconfig", "bridge242", "destroy")))
                self.assertEqual([event for event in events if event[-1] == "destroy"], [
                    ("/sbin/ifconfig", "bridge242", "destroy"), ("/sbin/ifconfig", "bridge243", "destroy")])
                self.assertFalse(any(event[0] == "/sbin/pfctl" and event[1] in ("-d", "-e", "-F") for event in events))
                for target, backup in fixture.settings["backups"].items():
                    self.assertEqual(Path(target).read_text(), (fixture.state / backup).read_text())
                self.assertEqual(fixture.active.readlink(), fixture.previous)
                self.assertTrue((fixture.state / "firewall-rolled-back").exists())

    def test_new_bridge_addresses_are_withdrawn_before_reloading_self_expanding_policy(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-self-") as directory:
            fixture = self.network_transaction(Path(directory))
            addresses = {"bridge242": "10.78.0.1", "bridge243": "10.78.0.5"}
            events = []
            def native(args, **kwargs):
                args = tuple(args)
                events.append(args)
                result = native_result(args)
                if args[-1] == "-alias":
                    self.assertEqual(args[3], addresses.pop(args[1]))
                elif args == ("/sbin/pfctl", "-sr") and addresses:
                    # Native FreeBSD expands self to every current host address.
                    result.stdout += "block drop inet from any to 10.78.0.1\n"
                return result
            with patch("installer.firewall.subprocess.run", side_effect=native):
                firewall.rollback(fixture.state)
            self.assertEqual(addresses, {})
            reload = events.index(("/sbin/pfctl", "-f", fixture.settings["previous_pf_file"]))
            for bridge, address in (("bridge242", "10.78.0.1"), ("bridge243", "10.78.0.5")):
                self.assertLess(events.index(("/sbin/ifconfig", bridge, "inet", address, "-alias")), reload)
                self.assertGreater(events.index(("/sbin/ifconfig", bridge, "destroy")), reload)
            self.assertTrue((fixture.state / "firewall-rolled-back").exists())

    def test_foreign_new_bridge_members_or_addresses_refuse_before_any_alias_withdrawal(self):
        for foreign in ("\tmember: foreign0 flags=143<LEARNING>\n",
                        "\tinet 10.99.0.1 netmask 0xffffff00\n"):
            with self.subTest(foreign=foreign), tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
                fixture = self.network_transaction(Path(directory))
                def native(args, **kwargs):
                    result = native_result(args)
                    if tuple(args) == ("/sbin/ifconfig", "bridge243"):
                        result.stdout += foreign
                    return result
                with patch("installer.firewall.subprocess.run", side_effect=native) as run, \
                        self.assertRaisesRegex(RuntimeError, "foreign members or IPv4"):
                    firewall.rollback(fixture.state)
                commands = [tuple(call.args[0]) for call in run.call_args_list]
                self.assertFalse(any(command[-1] in ("-alias", "destroy") for command in commands))
                self.assertNotIn(("/sbin/pfctl", "-f", fixture.settings["previous_pf_file"]), commands)
                self.assertFalse((fixture.state / "firewall-rolled-back").exists())

    def test_alias_withdrawal_retry_accepts_already_absent_addresses_without_guessing(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            fixture = self.network_transaction(Path(directory))
            def native(args, **kwargs):
                result = native_result(args)
                if tuple(args) == ("/sbin/ifconfig", "-l"):
                    result.stdout = "igb0 lo0 bridge242\n"  # Other newly-created bridge already absent.
                elif tuple(args) == ("/sbin/ifconfig", "bridge242"):
                    result.stdout = "bridge242: flags=1008843<UP,BROADCAST,RUNNING> metric 0 mtu 1500\n"
                return result
            with patch("installer.firewall.subprocess.run", side_effect=native) as run:
                firewall.rollback(fixture.state)
            self.assertFalse(any(call.args[0][-1] == "-alias" for call in run.call_args_list))
            self.assertTrue((fixture.state / "firewall-rolled-back").exists())

    def test_alias_withdrawal_failure_cannot_publish_previous_policy_or_destroy_bridges(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            fixture = self.network_transaction(Path(directory))
            def native(args, **kwargs):
                if args[-1] == "-alias":
                    raise subprocess.CalledProcessError(1, args)
                return native_result(args)
            with patch("installer.firewall.subprocess.run", side_effect=native) as run, self.assertRaises(RuntimeError):
                firewall.rollback(fixture.state)
            commands = [tuple(call.args[0]) for call in run.call_args_list]
            self.assertFalse(any(command[-1] == "destroy" for command in commands))
            self.assertNotIn(("/sbin/pfctl", "-f", fixture.settings["previous_pf_file"]), commands)
            self.assertFalse((fixture.state / "firewall-rolled-back").exists())

    def test_unreadable_empty_or_ambiguous_interface_inventory_refuses_recovery(self):
        for output in ('', 'bridge242 bridge242\n'):
            with self.subTest(output=output), tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
                fixture = self.network_transaction(Path(directory))
                def native(args, **kwargs):
                    result = native_result(args)
                    if tuple(args) == ('/sbin/ifconfig', '-l'):
                        result.stdout = output
                    return result
                with patch('installer.firewall.subprocess.run', side_effect=native) as run, self.assertRaises(RuntimeError):
                    firewall.rollback(fixture.state)
                self.assertFalse(any(call.args[0][-1] in ('-alias', 'destroy') for call in run.call_args_list))
                self.assertFalse((fixture.state / 'firewall-rolled-back').exists())

    def test_malformed_bridge_recovery_addresses_are_refused_before_native_commands(self):
        for address in ('-alias', 'not-ip', '10.78.0.1\n', None):
            with self.subTest(address=address), tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
                fixture = self.network_transaction(Path(directory))
                fixture.settings['network']['bridge_addresses']['bridge242'] = address
                (fixture.state / 'firewall-transition.json').write_text(json.dumps(fixture.settings))
                with patch('installer.firewall.subprocess.run') as run, self.assertRaises(ValueError):
                    firewall.recover_pending(fixture.state, 'new-boot')
                run.assert_not_called()

    def test_drifted_previous_pf_copy_is_rejected_before_any_native_commands(self):
        for recover in (False, True):
            for drift in ("empty", "ssh", "newline"):
                with self.subTest(recover=recover, drift=drift), \
                        tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-drift-") as directory:
                    fixture = self.network_transaction(Path(directory))
                    source = Path(fixture.settings["previous_pf_file"])
                    original = source.read_text()
                    source.write_text("" if drift == "empty" else original.replace("50222", "50333") if drift == "ssh" else original + "\n")
                    with patch("installer.firewall.subprocess.run") as run, \
                            self.assertRaisesRegex(ValueError if recover else RuntimeError, "differs from the committed policy"):
                        if recover:
                            firewall.recover_pending(fixture.state, "boot-after")
                        else:
                            firewall.rollback(fixture.state)
                    run.assert_not_called()
                    self.assertEqual(fixture.pf_file.read_text(), original)
                    self.assertFalse((fixture.state / "firewall-rolled-back").exists())

    def test_previous_commit_and_snapshots_must_be_private_and_not_symlinked(self):
        for failure in ("record-link", "snapshot-link", "directory-link", "snapshot-mode", "missing-confirmed"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-drift-") as directory:
                root = Path(directory)
                fixture = self.network_transaction(root)
                if failure == "missing-confirmed":
                    (fixture.previous / "firewall-confirmed").unlink()
                elif failure == "snapshot-mode":
                    (fixture.previous / "pf-filter.expected").chmod(0o644)
                else:
                    target = fixture.previous if failure == "directory-link" else fixture.previous / (
                        "firewall-transition.json" if failure == "record-link" else "pf-filter.expected")
                    saved = root / "foreign"
                    target.rename(saved)
                    target.symlink_to(saved)
                with patch("installer.firewall.subprocess.run") as run, self.assertRaises(RuntimeError):
                    firewall.rollback(fixture.state)
                run.assert_not_called()
                self.assertFalse((fixture.state / "firewall-rolled-back").exists())

    def test_live_snapshot_drift_or_query_failure_blocks_cleanup_and_success_marker(self):
        for name, args in firewall.PF_SNAPSHOTS:
            for drift in ("empty", "leading-space", "trailing-space", "query-error"):
                with self.subTest(snapshot=name, drift=drift), \
                        tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-live-drift-") as directory:
                    fixture = self.network_transaction(Path(directory))
                    fixture.rc_file.write_text("unconfirmed boot policy\n")
                    firewall.active_pointer(fixture.state, fixture.settings)
                    def native(command, **kwargs):
                        result = native_result(command)
                        if tuple(command) == ("/sbin/pfctl", *args):
                            if drift == "query-error":
                                raise subprocess.CalledProcessError(1, command)
                            result.stdout = ("" if drift == "empty" else " " + result.stdout if drift == "leading-space"
                                             else result.stdout.rstrip("\n") + " \n")
                        return result
                    with patch("installer.firewall.subprocess.run", side_effect=native) as run, \
                            self.assertRaisesRegex(RuntimeError, "PF was NOT disabled or flushed"):
                        firewall.rollback(fixture.state)
                    commands = [tuple(call.args[0]) for call in run.call_args_list]
                    self.assertIn(("/sbin/pfctl", "-f", fixture.settings["previous_pf_file"]), commands)
                    self.assertFalse(any(command[0] == "/sbin/sysctl" or command[-1] == "destroy" for command in commands))
                    self.assertTrue(all(command[1] in ("-l", "bridge242", "bridge243")
                                        for command in commands if command[0] == "/sbin/ifconfig"))
                    self.assertFalse(any(command[:2] in (("/sbin/pfctl", "-d"), ("/sbin/pfctl", "-F"), ("/sbin/pfctl", "-e"))
                                         for command in commands))
                    self.assertEqual(fixture.rc_file.read_text(), "unconfirmed boot policy\n")
                    self.assertEqual(fixture.active.readlink(), fixture.state)
                    self.assertFalse((fixture.state / "firewall-rolled-back").exists())

    def test_failed_previous_policy_restore_never_disables_or_flushes_pf(self):
        for failure in ("-nf", "-f", "-s"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-failure-") as directory:
                fixture = self.network_transaction(Path(directory))
                fixture.pf_file.write_text("unconfirmed policy\n")
                def native(args, **kwargs):
                    if args[:2] == ("/sbin/pfctl", failure):
                        raise subprocess.CalledProcessError(1, args)
                    return native_result(args)
                with patch("installer.firewall.subprocess.run", side_effect=native) as run, \
                        self.assertRaisesRegex(RuntimeError, "PF was NOT disabled or flushed"):
                    firewall.rollback(fixture.state)
                commands = [tuple(call.args[0]) for call in run.call_args_list]
                self.assertFalse(any(command[0] == "/sbin/pfctl" and command[1] in ("-d", "-e", "-F")
                                     for command in commands))
                if failure == "-nf":
                    self.assertEqual(fixture.pf_file.read_text(), "unconfirmed policy\n")
                    self.assertNotIn(("/sbin/pfctl", "-f", fixture.settings["previous_pf_file"]), commands)
                self.assertFalse((fixture.state / "firewall-rolled-back").exists())

    def test_rollback_marker_requires_successful_runtime_and_file_restoration(self):
        for failure in ("sysctl", "destroy", "backup"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-failure-") as directory:
                fixture = self.network_transaction(Path(directory))
                if failure == "backup":
                    (fixture.state / "rc.conf.before").unlink()
                def native(args, **kwargs):
                    if ((failure == "sysctl" and args[0] == "/sbin/sysctl")
                            or (failure == "destroy" and args[-1] == "destroy")):
                        raise subprocess.CalledProcessError(1, args)
                    return native_result(args)
                with patch("installer.firewall.subprocess.run", side_effect=native), self.assertRaises(RuntimeError):
                    firewall.rollback(fixture.state)
                self.assertFalse((fixture.state / "firewall-rolled-back").exists())

    def test_repeated_apply_validates_then_atomically_replaces_pf_without_duplicate_settings(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-repeat-") as directory:
            fixture = self.network_transaction(Path(directory))
            runner = Mock()
            validated = []
            old_policy = fixture.pf_file.read_text()
            def native(*args, **kwargs):
                if args == ("sysrc", "-n", "cloned_interfaces"):
                    return SimpleNamespace(stdout="lo1 bridge240 bridge241 bridge242 bridge242\n")
                if args[:2] == ("pfctl", "-nf"):
                    candidate = Path(args[2])
                    self.assertNotEqual(candidate, fixture.pf_file)
                    self.assertEqual(candidate.parent, fixture.pf_file.parent)
                    self.assertEqual(candidate.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(fixture.pf_file.read_text(), old_policy)
                    self.assertEqual(candidate.read_text(), fixture.settings["network"]["pf_rules"])
                    validated.append(str(candidate))
                if args[:2] == ("pfctl", "-f"):
                    self.assertTrue(validated)
                    self.assertEqual(fixture.pf_file.read_text(), fixture.settings["network"]["pf_rules"])
                return SimpleNamespace(stdout="", returncode=0)
            runner.run.side_effect = native
            with patch("installer.firewall.SYSCTL_FILE", fixture.sysctl_file), \
                    patch("installer.firewall.time.monotonic", return_value=100):
                with fixture.pf_file.open() as original:
                    firewall.apply_network(fixture.state, runner)
                    self.assertEqual(original.read(), old_policy)  # Old inode was not truncated.
                commands = [call.args for call in runner.run.call_args_list]
                self.assertIn(("sysrc", "cloned_interfaces=lo1 bridge240 bridge241 bridge242 bridge243"), commands)
                self.assertFalse(any(command[:2] == ("ifconfig", "bridge240") or
                                     command[:2] == ("ifconfig", "bridge241") for command in commands))
                self.assertFalse(any(command[0] == "sysrc" and command[1].startswith(("ifconfig_bridge240=", "ifconfig_bridge241="))
                                     for command in commands))
                self.assertNotIn(("pfctl", "-e"), commands)
                first_sysctls = fixture.sysctl_file.read_text()
                self.assertIn("kern.maxfiles=12345\n", first_sysctls)
                for name, value in fixture.settings["network"]["bridge_sysctls"].items():
                    self.assertEqual(first_sysctls.count(f"{name}={value}\n"), 1)
                # A subsequent removal replaces the existing policy again but
                # leaves bridge cleanup to the parent after commit.
                removal = Path(directory) / "removal"
                removal.mkdir(mode=0o700)
                old_policy = fixture.pf_file.read_text()
                fixture.settings["network"]["pf_rules"] = "# remaining instances\nblock all\n"
                fixture.settings["network"]["bridge_addresses"] = {}
                fixture.settings["bridges"] = []
                (removal / "firewall-transition.json").write_text(json.dumps(fixture.settings))
                runner.reset_mock()
                firewall.apply_network(removal, runner)
            self.assertEqual(len(validated), 2)
            self.assertEqual(fixture.sysctl_file.read_text(), first_sysctls)
            commands = [call.args for call in runner.run.call_args_list]
            self.assertFalse(any(command[0] in ("ifconfig", "sysrc") for command in commands))
            self.assertNotIn(("pfctl", "-e"), commands)
            self.assertFalse(any(command[0] == "pfctl" and command[1] in ("-d", "-F") for command in commands))

    def test_fresh_apply_enables_pf_after_loading_validated_policy(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-fresh-") as directory:
            fixture = self.network_transaction(Path(directory), previous=False)
            runner = Mock()
            runner.run.return_value = SimpleNamespace(stdout="", returncode=0)
            with patch("installer.firewall.SYSCTL_FILE", fixture.sysctl_file), \
                    patch("installer.firewall.time.monotonic", return_value=100):
                firewall.apply_network(fixture.state, runner)
            commands = [call.args for call in runner.run.call_args_list]
            self.assertEqual(commands[-2:], [("pfctl", "-f", str(fixture.pf_file)), ("pfctl", "-e")])

    def test_invalid_candidate_leaves_the_previous_pf_file_intact(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-candidate-") as directory:
            fixture = self.network_transaction(Path(directory))
            old_inode = fixture.pf_file.stat().st_ino
            def native(*args, **kwargs):
                if args[:2] == ("pfctl", "-nf"):
                    raise RuntimeError("invalid candidate fixture")
                return SimpleNamespace(stdout="", returncode=0)
            runner = Mock()
            runner.run.side_effect = native
            with patch("installer.firewall.SYSCTL_FILE", fixture.sysctl_file), \
                    patch("installer.firewall.time.monotonic", return_value=100), \
                    self.assertRaisesRegex(RuntimeError, "invalid candidate"):
                firewall.apply_network(fixture.state, runner)
            self.assertEqual(fixture.pf_file.stat().st_ino, old_inode)
            self.assertEqual(fixture.pf_file.read_text(), Path(fixture.settings["previous_pf_file"]).read_text())
            self.assertFalse(any(call.args[:2] in (("pfctl", "-f"), ("pfctl", "-e")) for call in runner.run.call_args_list))
            self.assertFalse(list(Path(directory).glob(".pf.conf.*")))

    def test_foreign_changed_or_invalid_sysctl_is_rejected_before_mutation(self):
        for failure in ("foreign", "changed", "unknown-key"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-sysctl-") as directory:
                fixture = self.network_transaction(Path(directory))
                if failure == "foreign":
                    fixture.sysctl_file.write_text("net.link.bridge.pfil_bridge=1\n")
                elif failure == "changed":
                    fixture.sysctl_file.write_text(f"{firewall.SYSCTL_BEGIN}\nnet.link.bridge.pfil_bridge=0\n")
                else:
                    fixture.settings["network"]["bridge_sysctls"]["kern.unreviewed"] = "1"
                    (fixture.state / "firewall-transition.json").write_text(json.dumps(fixture.settings))
                runner = Mock()
                with patch("installer.firewall.SYSCTL_FILE", fixture.sysctl_file), \
                        patch("installer.firewall.time.monotonic", return_value=100), self.assertRaises(RuntimeError):
                    firewall.apply_network(fixture.state, runner)
                runner.run.assert_not_called()

    def test_applying_cannot_resume_after_watchdog_rolls_back(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-test-") as directory:
            state = Path(directory)
            self.transaction(state)
            with patch("installer.firewall.subprocess.run") as run:
                run.return_value.returncode = 1  # no bridges were created yet
                firewall.rollback(state)
            with patch("installer.firewall.time.monotonic", return_value=100), self.assertRaises(RuntimeError):
                with firewall.mutation(state):
                    self.fail("An applying process must not mutate/re-enable PF after rollback")

    def test_rollback_before_pf_enable_does_not_report_already_disabled_as_failure(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-test-") as directory:
            state = Path(directory)
            self.transaction(state)
            with patch("installer.firewall.subprocess.run") as run:
                run.return_value.returncode = 1  # PF not running; bridges absent
                firewall.rollback(state)
            commands = [call.args[0] for call in run.call_args_list]
            self.assertNotIn(("/sbin/pfctl", "-d"), commands)
            self.assertTrue((state / "firewall-rolled-back").exists())

    def test_rollback_waits_for_applying_lock_then_blocks_later_mutations(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-test-") as directory:
            state = Path(directory)
            self.transaction(state)
            entered = threading.Event()
            completed = threading.Event()
            errors = []
            def watchdog():
                entered.set()
                try:
                    firewall.rollback(state)
                except Exception as error:
                    errors.append(error)
                finally:
                    completed.set()
            with patch("installer.firewall.subprocess.run") as run, \
                    patch("installer.firewall.time.monotonic", return_value=100):
                run.return_value.returncode = 1  # absent bridges; native commands are all mocked
                with firewall.mutation(state) as pending:
                    pending()
                    thread = threading.Thread(target=watchdog)
                    thread.start()
                    self.assertTrue(entered.wait(2))
                    self.assertFalse(completed.is_set())
                thread.join(2)
                self.assertFalse(thread.is_alive())
                self.assertFalse(errors)
                self.assertTrue((state / "firewall-rolled-back").exists())
                with self.assertRaises(RuntimeError):
                    with firewall.mutation(state):
                        self.fail("A late parent must not resurrect PF")

    def test_native_calls_cannot_outlive_the_transition_deadline(self):
        runner = firewall.NativeRunner(deadline=110)
        with patch("installer.firewall.time.monotonic", return_value=100), patch("installer.firewall.subprocess.run") as run:
            run.return_value.returncode = 0
            runner.run("pfctl", "-e")
        self.assertEqual(run.call_args.kwargs["timeout"], 10)
        with patch("installer.firewall.time.monotonic", return_value=111), patch("installer.firewall.subprocess.run") as run:
            with self.assertRaises(TimeoutError):
                runner.run("pfctl", "-e")
            run.assert_not_called()

    def test_terminate_worker_kills_its_process_group_before_reaping(self):
        process = Mock(pid=12345)
        events = []
        process.wait.side_effect = lambda **_: events.append("reaped")
        with patch("installer.firewall.os.killpg", lambda pid, sig: events.append((pid, sig))):
            firewall.terminate_worker(process)
        self.assertEqual(events, [(12345, signal.SIGKILL), "reaped"])

    def run_supervisor_fixture(self, *, phase, confirm):
        """Real harmless child processes; all native rollback commands are mocked.

        SIGSTOP the worker while it holds the real flock. The supervisor must
        kill/reap its private process group before rollback can acquire the lock.
        No installer, PF, sysrc, ifconfig or other provisioning command is run.
        """
        child = '''import fcntl, json, os, signal, sys
from pathlib import Path
state=Path(sys.argv[1])
phase=sys.argv[2]
(state/'worker-pgid').write_text(str(os.getpgrp()))
lock=(state/'firewall.lock').open('a')
def stop_locked():
    fcntl.flock(lock, fcntl.LOCK_EX)
    os.kill(os.getpid(), signal.SIGSTOP)
if phase=='apply':
    stop_locked()
if phase=='broken-pipe':
    os.close(0)
    print('APPLIED', flush=True)
    signal.pause()
print('APPLIED', flush=True)
assert sys.stdin.readline().strip()=='KEEP'
if phase=='commit':
    stop_locked()
if phase in ('pending-link', 'confirmed-link'):
    fcntl.flock(lock, fcntl.LOCK_EX)
    active=Path(json.loads((state/'firewall-transition.json').read_text())['active_link'])
    candidate=active.with_name('pending-test-link')
    candidate.symlink_to(state)
    os.replace(candidate, active)
    if phase=='pending-link':
        os.kill(os.getpid(), signal.SIGSTOP)
(state/'firewall-confirmed').write_text('confirmed test fixture\\n')
if phase=='confirmed-link':
    os.kill(os.getpid(), signal.SIGSTOP)
print('COMMITTED', flush=True)
sys.stdin.read()
'''
        with tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-process-test-") as directory:
            state = Path(directory)
            fixture = None
            if phase in ("pending-link", "confirmed-link"):
                fixture = self.network_transaction(state)
                state, settings = fixture.state, fixture.settings
            else:
                settings = self.transaction(state)
            settings["deadline"] = time.monotonic() + 2
            (state / "firewall-transition.json").write_text(json.dumps(settings))
            read_fd, write_fd = os.pipe()
            with os.fdopen(read_fd, "r") as request, os.fdopen(write_fd, "w") as answer:
                class Response(io.StringIO):
                    def write(self, value):
                        result = super().write(value)
                        if confirm and value == "APPLIED\n":
                            answer.write("KEEP\n")
                            answer.flush()
                        return result
                response = Response()
                actual_terminate = firewall.terminate_worker
                terminated = []
                def terminate(process):
                    actual_terminate(process)
                    terminated.append((process.pid, process.returncode))
                # Only the native rollback commands use subprocess.run. The
                # fixture itself uses Popen, actual pipes/flock/SIGSTOP/SIGKILL.
                def native(args, **kwargs):
                    return native_result(args, returncode=0 if kwargs.get("check") else 1)
                with patch("installer.firewall.subprocess.run", side_effect=native) as run, \
                        patch("installer.firewall.terminate_worker", terminate):
                    result = firewall.supervise(state, request, response,
                                                worker_command=[sys.executable, "-c", child, str(state), phase])
            self.assertEqual(len(terminated), 1)
            self.assertEqual(terminated[0][1], -signal.SIGKILL)
            self.assertEqual(int((state / "worker-pgid").read_text()), terminated[0][0])
            self.assertNotEqual(terminated[0][0], os.getpgrp())
            if phase in ("complete", "confirmed-link"):
                self.assertEqual(result, 0)
                self.assertEqual(response.getvalue(), "APPLIED\nCOMMITTED\n")
                self.assertFalse((state / "firewall-rolled-back").exists())
            else:
                self.assertEqual(result, 1)
                self.assertTrue(response.getvalue().endswith("ROLLED_BACK\n"))
                self.assertTrue((state / "firewall-rolled-back").exists())
            if fixture:
                self.assertEqual(fixture.active.readlink(), state if phase == "confirmed-link" else fixture.previous)
                self.assertFalse(any(tuple(call.args[0])[:2] in (("/sbin/pfctl", "-d"), ("/sbin/pfctl", "-F"))
                                     for call in run.call_args_list))

    def test_suspended_applying_worker_cannot_block_watchdog_rollback(self):
        self.run_supervisor_fixture(phase="apply", confirm=False)

    def test_suspended_committing_worker_cannot_block_watchdog_rollback(self):
        self.run_supervisor_fixture(phase="commit", confirm=True)

    def test_supervised_commit_needs_confirmation_and_completes(self):
        self.run_supervisor_fixture(phase="complete", confirm=True)

    def test_suspended_worker_after_active_pointer_swap_restores_previous_commit(self):
        self.run_supervisor_fixture(phase="pending-link", confirm=True)

    def test_suspended_worker_after_confirmation_retains_new_active_pointer(self):
        self.run_supervisor_fixture(phase="confirmed-link", confirm=True)

    def test_broken_confirmation_pipe_cannot_bypass_rollback_during_cleanup(self):
        self.run_supervisor_fixture(phase="broken-pipe", confirm=True)

    def test_cancelling_with_a_broken_pipe_still_waits_for_recovery(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH, prefix="pf-test-") as directory:
            state = Path(directory)
            self.transaction(state)
            process = Mock()
            process.stdin.closed = False
            process.stdin.close.side_effect = BrokenPipeError("fixture pipe closed")
            firewall.Controller(state, process).cancel()
            process.wait.assert_called_once_with(timeout=120)
            process.stdout.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
