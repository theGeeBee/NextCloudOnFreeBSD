"""Offline FreeBSD 15.1 utility contracts; never execute native commands.

Fixtures follow releng/15.1 ps(1), stat(1), mount(8), and sysctl(8),
not the workstation's implementations. See docs/freebsd-utilities.md.
"""
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from installer import maintenance_native as native
from installer import recovery_export, recovery_sets


class FreeBSDUtilityContracts(unittest.TestCase):
    def setUp(self):
        # Fail immediately if a regression accidentally reaches subprocesses.
        for name in ("run", "Popen", "check_output", "check_call", "call"):
            guard = patch("subprocess." + name, side_effect=AssertionError("native execution forbidden"))
            guard.start()
            self.addCleanup(guard.stop)

    def backend(self, output):
        backend = object.__new__(native.NativeBackend)
        backend.jailed = Mock(return_value=SimpleNamespace(stdout=output, returncode=0))
        return backend

    def test_process_columns_use_separate_freebsd_header_overrides(self):
        backend = self.backend("  1  0 init\n 42  1 mariadbd\n 83  1 ps\n")
        self.assertEqual(backend.processes("testnc"), [(1, 0, "init"), (42, 1, "mariadbd"), (83, 1, "ps")])
        backend.jailed.assert_called_once_with(
            "testnc", "ps", "-ax", "-o", "pid=", "-o", "ppid=", "-o", "comm=")

    def test_wrapper_columns_use_separate_freebsd_header_overrides(self):
        backend = self.backend(" 41 1 sh /bin/sh /usr/local/bin/mariadbd-safe --datadir=/var/db/mysql\n")
        self.assertEqual(backend._service_rows("testnc", "mysql-server", [(41, 1, "sh")]), [(41, 1, "sh")])
        backend.jailed.assert_called_once_with(
            "testnc", "ps", "-ww", "-p", "41", "-o", "pid=", "-o", "ppid=", "-o", "comm=", "-o", "args=")

    def test_freebsd_comma_header_output_is_not_writer_closure(self):
        # keyword.c consumes everything after '=' as the header for that field.
        backend = self.backend(",ppid=,comm=\n             1\n            42\n")
        with self.assertRaises(ValueError):
            backend.processes("testnc")

    def test_empty_duplicate_and_malformed_process_inventory_refused(self):
        for text in ("", "1 0 init\n1 0 init\n", "PID PPID COMMAND\n", "0 0 init\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.backend(text).processes("testnc")

    def test_wrapper_args_do_not_authorize_unrelated_shell(self):
        backend = self.backend("41 1 sh /bin/sh /usr/local/bin/unrelated\n")
        self.assertEqual(backend._service_rows("testnc", "mysql-server", [(41, 1, "sh")]), [])

    def test_freebsd_boot_timeval_and_not_linux_epoch(self):
        value = "{ sec = 1792233600, usec = 123456 } Sat Oct 17 08:00:00 2026"
        self.assertEqual(native._boot(value), value)
        for bad in ("1792233600", "{ sec = 1792233600, usec = 1000000 }", value + "\nextra"):
            with self.subTest(value=bad), self.assertRaises(ValueError):
                native._boot(bad)

    def test_mounted_identity_uses_bsd_stat_device_inode(self):
        runner = Mock()
        runner.output.side_effect = ["/srv/test\n", "18446744073709551600:34\n"]
        backend = recovery_sets.NativeBackend(runner)
        self.assertEqual(backend.mounted_identity("/srv/test"), ("/srv/test", (18446744073709551600, 34)))
        self.assertEqual(runner.output.call_args_list[-1].args, ("stat", "-f", "%d:%i", "/srv/test"))

    def test_mounted_identity_rejects_human_stat_output(self):
        runner = Mock()
        runner.output.side_effect = ["/srv/test", '  File: "/srv/test"\n  Size: 34']
        with self.assertRaises(recovery_sets.RecoveryError):
            recovery_sets.NativeBackend(runner).mounted_identity("/srv/test")

    def test_export_stream_argv_preserves_properties_and_unmounted_receive(self):
        streams = recovery_export.NativeStreams()
        streams._pipe = Mock()
        streams.send("pool/source@cold", 99, 4096)
        streams._pipe.assert_called_with(("zfs", "send", "-p", "pool/source@cold"), 99, 4096, sending=True)
        streams.receive("backup/rehearsal", 98, 4096, ("org.cloud-installer:instance=test",))
        streams._pipe.assert_called_with(
            ("zfs", "receive", "-u", "-o", "canmount=off", "-o", "mountpoint=none",
             "-o", "org.cloud-installer:instance=test", "backup/rehearsal"), 98, 4096, sending=False)

    def test_php_cron_inventory_uses_independent_header_overrides(self):
        source = (Path(__file__).resolve().parents[1] / "resources/jails/nextcloud-cron-fence.php").read_text()
        self.assertIn("['/bin/ps', '-ax', '-o', 'pid=', '-o', 'ppid=', '-o', 'uid=', '-o', 'comm=']", source)
        self.assertNotIn("pid=,ppid=", source)


if __name__ == "__main__":
    unittest.main()
