"""Offline live-upgrade transport contracts; no VM, pkg or Git execution."""

import json
import os
from pathlib import Path
import stat
import subprocess
import traceback
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from installer import upgrade_native as native


READY = dict(installed=True, maintenance=False, needsDbUpgrade=False,
             version="35.0.2.0", versionstring="35.0.2", secret="not-public")


class Registry:
    def __init__(self):
        self.enrolled = False
        self.ready = "ready"
        self.config = SimpleNamespace(instance="cloud", nextcloud_jail="cloudnc", onlyoffice_jail="cloudoo",
                                      bastille_root="/srv/cloud-installer/bastille", antivirus=False)
        self.load = Mock(return_value=self.config)

    def lifecycle_enabled(self):
        return self.enrolled

    def status(self, instance):
        return {"state": self.ready}

    def instance_path(self, instance):
        return Path("/var/db/cloud-installer/instances") / instance


class Runner:
    def __init__(self):
        self.calls = []
        self.jids = {"cloudnc": 17, "cloudoo": 18}
        self.status = dict(READY)
        self.config = dict(system={"overwrite.cli.url": "https://manually-changed.example.test/cloud/",
                                   "dbpassword": "private-password"},
                           apps={"onlyoffice": {"DocumentServerUrl": "https://office.example.test/",
                                                "jwt_secret": "private-jwt"}})
        self.command_hook = None
        self.identity_hook = None
        self.php_fpm = "PHP 8.5.3 (fpm-fcgi) (built: Oct 1 2026)\nCopyright"
        self.database = "12.3.2-MariaDB"
        self.office = "onlyoffice-documentserver|9.4.0_2,1|www/onlyoffice-documentserver"

    def run(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        output, code = "", 0
        if args[0] == "bastille":
            output = "/srv/cloud-installer/bastille/jails/" + args[2] + "/root\n"
        elif args[0] == "jls":
            jail = args[2]
            output = f"{self.jids[jail]} {jail} /srv/cloud-installer/bastille/jails/{jail}/root\n"
            if self.identity_hook:
                output = self.identity_hook(output)
        elif args[0] == "freebsd-version":
            output = "15.1-RELEASE-p1\n"
        elif args[:3] == native.PKG:
            output = "FreeBSD:15:amd64\n"
        elif args[0] == "jexec":
            command = args[2:]
            if self.command_hook:
                result = self.command_hook(command)
                if result is not None:
                    return result
            if command[0] == "/usr/bin/id":
                output = "80\n"
            elif command[:3] == native.PKG:
                output = self.office
            elif command[0] == "/usr/local/bin/php":
                output = "8.5.3"
            elif command[:2] == ("/usr/local/sbin/php-fpm", "-v"):
                output = self.php_fpm
            elif command[0] == "/usr/local/bin/mariadb":
                output = self.database
            elif command[0] == "/usr/local/bin/supervisorctl":
                output = "ds:docservice RUNNING pid 35, uptime 1:10:00\nds:metrics RUNNING pid 36, uptime 1:10:00\n"
            elif command[0] == "/usr/local/bin/curl":
                output = json.dumps(self.status) if command[-1].endswith("status.php") else "true\n"
            elif "status" in command and native.APP + "/occ" in command:
                output = json.dumps(self.status)
            elif "config:list" in command:
                output = json.dumps(self.config)
        else:
            raise AssertionError("Unexpected host command")
        return subprocess.CompletedProcess(args, code, output, "")


class LiveTargetTests(unittest.TestCase):
    def setUp(self):
        self.registry, self.runner = Registry(), Runner()
        self.directory_check = patch.object(native, "_directories", side_effect=lambda p: Path(p)).start()
        self.account_check = patch.object(native.LiveTarget, "_account", return_value={"uid": 80, "gid": 80}).start()
        self.addCleanup(patch.stopall)
        self.target = native.LiveTarget(self.registry, self.runner, "cloud")

    def test_interface_needs_no_deployment_artifact_or_secrets(self):
        self.assertIs(self.target.config, self.registry.config)
        self.assertIs(self.target.registry, self.registry)
        self.assertEqual(self.target.state, Path("/var/db/cloud-installer/instances/cloud"))
        self.assertEqual(self.target.nc, "cloudnc")
        self.assertEqual(self.target.office, "cloudoo")
        self.assertEqual(self.runner.calls, [])

    def test_enrollment_refused_before_registry_load(self):
        self.registry.enrolled = True
        self.registry.load.reset_mock()
        with self.assertRaisesRegex(ValueError, "unenrolled"):
            native.LiveTarget(self.registry, self.runner, "cloud")
        self.registry.load.assert_not_called()

    def test_ready_and_unenrolled_rechecked_before_mutator(self):
        for enrolled, ready in ((True, "ready"), (False, "failed"), (False, "removed")):
            with self.subTest(enrolled=enrolled, ready=ready):
                self.registry.enrolled, self.registry.ready = enrolled, ready
                with self.assertRaises(ValueError):
                    self.target.run_jail(self.target.nc, "service", "apache24", "restart")
                self.assertFalse(self.runner.calls)

    def test_numeric_jid_and_private_stdin_transport(self):
        result = self.target.run_jail(self.target.nc, "some-helper", input="private-input", timeout=55)
        calls = [(args, opts) for args, opts in self.runner.calls if args[0] == "jexec"]
        self.assertEqual(calls[0][0], ("jexec", "17", "some-helper"))
        self.assertEqual(calls[0][1], dict(input="private-input", timeout=55, check=False, capture=True, hide_output=True))
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "", ""))
        self.assertEqual(sum(args[0] == "jls" for args, _ in self.runner.calls), 2)

    def test_streaming_identity_interface_checks_eligibility(self):
        self.assertEqual(self.target.require_running_jail(self.target.nc), 17)
        self.registry.enrolled = True
        with self.assertRaises(ValueError):
            self.target.require_running_jail(self.target.nc)

    def test_unrelated_jail_never_executes(self):
        with self.assertRaisesRegex(ValueError, "unrelated"):
            self.target.run_jail("other", "true")
        self.assertFalse(self.runner.calls)

    def test_identity_formats_and_roots_fail_closed(self):
        for row in ("", "0 cloudnc /wrong", "17 cloudnc /wrong", "17 other /wrong",
                    "jid name path\n17 cloudnc /srv/cloud-installer/bastille/jails/cloudnc/root"):
            with self.subTest(row=row):
                self.runner.calls.clear()
                self.runner.identity_hook = lambda original, row=row: row
                with self.assertRaises(RuntimeError):
                    self.target.run_jail(self.target.nc, "true")
                self.assertFalse(any(args[0] == "jexec" for args, _ in self.runner.calls))

    def test_failed_command_still_checks_identity_and_hides_output(self):
        self.runner.command_hook = lambda argv: subprocess.CompletedProcess(argv, 7, "private-password", "private-jwt")
        with self.assertRaises(RuntimeError) as caught:
            self.target.run_jail(self.target.nc, "failure")
        self.assertNotIn("private-", str(caught.exception))
        self.assertEqual(sum(args[0] == "jls" for args, _ in self.runner.calls), 2)

    def test_timeout_still_checks_identity_and_suppresses_exception_chain(self):
        def fail(argv):
            raise subprocess.TimeoutExpired("private-command", 1, output="private-password", stderr="private-jwt")
        self.runner.command_hook = fail
        with self.assertRaises(RuntimeError) as caught:
            self.target.run_jail(self.target.nc, "failure")
        self.assertTrue(caught.exception.__suppress_context__)
        self.assertNotIn("private-", str(caught.exception))
        self.assertEqual(sum(args[0] == "jls" for args, _ in self.runner.calls), 2)

    def test_replacement_detected_even_when_command_failed_unchecked(self):
        def replaced(argv):
            self.runner.jids[self.target.nc] = 99
            return subprocess.CompletedProcess(argv, 1, "", "")
        self.runner.command_hook = replaced
        with self.assertRaisesRegex(RuntimeError, "restarted"):
            self.target.run_jail(self.target.nc, "failure", check=False)

    def test_unchecked_failure_returns_text_and_status(self):
        self.runner.command_hook = lambda argv: subprocess.CompletedProcess(argv, 9, "out", "err")
        result = self.target.run_jail(self.target.nc, "failure", check=False)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (9, "out", "err"))

    def test_occ_has_www_cwd_absolute_script_and_positional_arguments(self):
        marker = "value; $(not-a-command)"
        self.target.occ("config:system:get", marker, check=False, timeout=48)
        args, opts = next((a, o) for a, o in self.runner.calls if a[0] == "jexec")
        self.assertEqual(args[2:6], ("mdo", "-u", "www", "/bin/sh"))
        self.assertEqual(args[7], 'cd /usr/local/www/nextcloud && exec "$@"')
        self.assertEqual(args[-2:], ("config:system:get", marker))
        self.assertIn(native.APP + "/occ", args)
        self.assertEqual(opts["timeout"], 48)

    def test_private_config_is_actual_memory_only(self):
        result = self.target.private_config()
        self.assertEqual(result, self.runner.config)
        self.assertNotIn("private-password", repr(self.runner.calls))
        self.assertNotIn("private-jwt", repr(self.runner.calls))

    def test_inspection_normalizes_live_versions_and_allowlists_public_fields(self):
        report = self.target.inspect()
        self.assertEqual(report["nextcloud"]["version"], "35.0.2")
        self.assertEqual(report["nextcloud"]["internal_version"], "35.0.2.0")
        self.assertEqual(report["office"], dict(package="onlyoffice-documentserver", package_name="onlyoffice-documentserver", version="9.4.0_2,1", upstream="9.4.0"))
        self.assertEqual(report["nextcloud"]["status"]["version"], "35.0.2.0")
        self.assertEqual(report["database"]["version"], "12.3.2")
        self.assertEqual(report["php"]["fpm_version"], "8.5.3")
        self.assertEqual(report["ABI"], "FreeBSD:15:amd64")
        self.assertNotIn("secret", json.dumps(report))
        self.assertNotIn("not-public", json.dumps(report))

    def test_inspection_requires_ready_stable_nextcloud(self):
        for change in ({"maintenance": True}, {"installed": False}, {"needsDbUpgrade": True},
                       {"maintenance": 0}, {"version": "35.0.2rc1"}, {"version": "35.0.2.0-beta"},
                       {"versionstring": "35.0.2rc1"}):
            with self.subTest(change=change):
                self.runner.status = {**READY, **change}
                with self.assertRaises(ValueError):
                    self.target.inspect()

    def test_fpm_cli_mismatch_is_rejected(self):
        self.runner.php_fpm = "PHP 8.4.5 (fpm-fcgi)"
        with self.assertRaisesRegex(ValueError, "FPM"):
            self.target.inspect()

    def test_office_package_and_database_output_are_validated(self):
        self.runner.office = "onlyoffice-documentserver|9.4.0|unrelated/origin"
        with self.assertRaises(ValueError):
            self.target.inspect()
        self.runner.office = "onlyoffice-documentserver|9.4.0|www/onlyoffice-documentserver"
        self.runner.database = "12.3.2-MariaDB\nprivate-password"
        with self.assertRaises(ValueError) as caught:
            self.target.inspect()
        self.assertNotIn("private-password", str(caught.exception))

    def test_verify_uses_live_manual_urls_without_modifying_configuration(self):
        report = self.target.verify(expected_nextcloud="35.0.2")
        self.assertTrue(report["verification"]["connector"])
        commands = [args[2:] for args, _ in self.runner.calls if args[0] == "jexec"]
        curls = [args for args in commands if args[0] == "/usr/local/bin/curl"]
        self.assertEqual([args[-1] for args in curls], ["https://manually-changed.example.test/cloud/status.php",
                                                       "https://office.example.test/healthcheck"])
        self.assertTrue(all("--insecure" not in args and "-k" not in args for args in curls))
        self.assertFalse(any(word in ("start", "stop", "restart", "config:system:set", "config:app:set")
                             for args in commands for word in args))
        self.assertTrue(any("onlyoffice:documentserver" in args and "--check" in args for args in commands))
        self.assertNotIn("private-", json.dumps(report))

    def test_verify_rejects_wrong_target_and_http_status_drift(self):
        with self.assertRaisesRegex(ValueError, "target"):
            self.target.verify(expected_nextcloud="35.0.1")
        def drift(argv):
            if argv[0] == "/usr/local/bin/curl" and argv[-1].endswith("status.php"):
                return subprocess.CompletedProcess(argv, 0, json.dumps({**READY, "version": "35.0.1.0", "versionstring": "35.0.1"}), "")
        self.runner.command_hook = drift
        with self.assertRaisesRegex(RuntimeError, "HTTP and CLI"):
            self.target.verify()

    def test_selected_scanner_services_are_read_only_readiness_checks(self):
        self.registry.config.antivirus = True
        self.target.verify()
        commands = [args[2:] for args, _ in self.runner.calls if args[0] == "jexec"]
        for name in ("clamav_clamd", "clamav_freshclam"):
            self.assertIn(("service", name, "onestatus"), commands)
        self.assertFalse(any("onestart" in args or "onestop" in args for args in commands))

    def test_verify_propagates_connector_failure_without_output(self):
        def fail(argv):
            if "onlyoffice:documentserver" in argv:
                return subprocess.CompletedProcess(argv, 1, "private-jwt", "private-password")
        self.runner.command_hook = fail
        with self.assertRaises(RuntimeError) as caught:
            self.target.verify()
        self.assertNotIn("private-", str(caught.exception))

    def test_bounded_and_text_output_contract(self):
        for stdout, stderr in ((b"binary", ""), ("", None)):
            self.runner.command_hook = lambda argv: subprocess.CompletedProcess(argv, 0, stdout, stderr)
            with self.assertRaisesRegex(RuntimeError, "output"):
                self.target.run_jail(self.target.nc, "helper")
        self.runner.command_hook = lambda argv: subprocess.CompletedProcess(argv, 0, "12345", "")
        with patch.object(native, "OUTPUT_LIMIT", 4), self.assertRaisesRegex(RuntimeError, "output"):
            # Direct helper avoids applying the tiny fixture limit to jls itself.
            self.target._run("jexec", "17", "helper")
        for timeout in (0, -1, float("inf"), float("nan")):
            with self.assertRaises(ValueError):
                self.target._run("helper", timeout=timeout)


class FilesystemAndUrlTests(unittest.TestCase):
    def test_directory_guard_rejects_symlink_wrong_owner_and_writable_path(self):
        for mode, uid in ((stat.S_IFLNK | 0o755, 0), (stat.S_IFDIR | 0o775, 0), (stat.S_IFDIR | 0o755, 80)):
            with self.subTest(mode=mode, uid=uid), patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=mode, st_uid=uid)):
                with self.assertRaises(ValueError):
                    native._directories(Path("/srv/jail"))

    def test_account_guard_uses_live_www_ids_and_config_ownership(self):
        target = native.LiveTarget(Registry(), Runner(), "cloud")
        target.run_jail = Mock(side_effect=lambda *a, **kw: SimpleNamespace(stdout="1234\n"))
        def info(path):
            return SimpleNamespace(st_mode=(stat.S_IFREG | 0o600) if path.name == "config.php" else (stat.S_IFDIR | 0o750),
                                   st_uid=1234, st_nlink=1)
        with patch.object(native, "_directories"), patch.object(Path, "lstat", info):
            self.assertEqual(target._account(), dict(uid=1234, gid=1234))
        with patch.object(native, "_directories"), patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=stat.S_IFDIR | 0o750, st_uid=80)):
            with self.assertRaisesRegex(ValueError, "application directory"):
                target._account()

    def test_config_file_symlinks_and_public_readability_are_refused(self):
        target = native.LiveTarget(Registry(), Runner(), "cloud")
        target.run_jail = Mock(return_value=SimpleNamespace(stdout="80\n"))
        for mode in (stat.S_IFLNK | 0o600, stat.S_IFREG | 0o644):
            def info(path):
                return SimpleNamespace(st_mode=mode if path.name == "config.php" else (stat.S_IFDIR | 0o750), st_uid=80, st_nlink=1)
            with patch.object(native, "_directories"), patch.object(Path, "lstat", info):
                with self.assertRaisesRegex(ValueError, "configuration file"):
                    target._account()

    def test_https_urls_cannot_include_credentials_or_disable_tls(self):
        for url in (None, "http://example.test/", "https://user:private@example.test/", "https://example.test/?secret=x",
                    "https://example.test/#secret", "https://example.test:99999/", "https://example.test/\n"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                native._https_url(url)
        self.assertEqual(native._https_url("https://example.test:444/cloud"), "https://example.test:444/cloud/")


class UpgradeRunnerTests(unittest.TestCase):
    def setUp(self):
        self.run = patch.object(native.bounded_process, "run", return_value=SimpleNamespace(returncode=0, stdout=b"value\n", stderr=b"")).start()
        self.addCleanup(patch.stopall)
        self.runner = native.UpgradeRunner()

    def test_delegates_limits_and_clean_environment_without_inherited_secrets(self):
        with patch.dict(os.environ, {"PATH": "/untrusted/bin", "PRIVATE_TOKEN": "private-secret"}):
            result = self.runner.run("/usr/sbin/jexec", "17", "helper", input="private-input", timeout=37,
                                     capture=False, hide_output=False)
        self.run.assert_called_once_with(("/usr/sbin/jexec", "17", "helper"), stdin=b"private-input",
            env={"PATH": "/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin", "LC_ALL": "C"},
            timeout=37, output_limit=16 * 1024 * 1024, capture_stderr=True)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "value\n", ""))

    def test_native_basename_lookup_uses_only_clean_path_without_shell(self):
        self.assertEqual(self.runner.output("uname", "-s"), "value")
        self.assertEqual(self.run.call_args.args[0], ("/usr/bin/env", "uname", "-s"))
        self.assertEqual(self.run.call_args.kwargs["stdin"], b"")
        self.runner.run("mdo", "-u", "www", "literal;$(command)", input=b"bytes")
        self.assertEqual(self.run.call_args.args[0][-1], "literal;$(command)")
        self.assertEqual(self.run.call_args.kwargs["stdin"], b"bytes")

    def test_timeout_and_oversized_stream_failures_are_delegated_and_suppressed(self):
        for error in (subprocess.TimeoutExpired("private-argv", 1, output="private-stdout", stderr="private-stderr"),
                      RuntimeError("private-output-limit-diagnostic")):
            with self.subTest(error=type(error).__name__):
                self.run.side_effect = error
                with self.assertRaises(RuntimeError) as caught:
                    self.runner.run("/usr/sbin/jexec", "17", "helper", timeout=1)
                rendered = "".join(traceback.format_exception(caught.exception))
                self.assertNotIn("private-", rendered)
                self.assertTrue(caught.exception.__suppress_context__)
                self.assertEqual(self.run.call_args.kwargs["timeout"], 1)
                self.assertEqual(self.run.call_args.kwargs["output_limit"], native.OUTPUT_LIMIT)

    def test_failed_exit_is_generic_or_returned_as_text_when_unchecked(self):
        self.run.return_value = SimpleNamespace(returncode=9, stdout=b"private-output", stderr=b"private-stderr")
        with self.assertRaisesRegex(RuntimeError, "output suppressed") as caught:
            self.runner.run("/usr/bin/false")
        self.assertNotIn("private-output", str(caught.exception))
        self.assertNotIn("private-stderr", "".join(traceback.format_exception(caught.exception)))
        result = self.runner.run("/usr/bin/false", check=False)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (9, "private-output", "private-stderr"))

    def test_invalid_output_and_nonbounded_requests_fail_without_diagnostics(self):
        for stdout in (b"\xffprivate-output", "private-output"):
            self.run.return_value = SimpleNamespace(returncode=0, stdout=stdout, stderr=b"")
            with self.assertRaisesRegex(RuntimeError, "output suppressed"):
                self.runner.run("/usr/bin/true")
        self.run.return_value = SimpleNamespace(returncode=0, stdout=b"123", stderr=b"45")
        with patch.object(native, "OUTPUT_LIMIT", 4), self.assertRaises(RuntimeError):
            self.runner.run("/usr/bin/true")
        for stderr in ("private-stderr", b"\xffprivate-stderr"):
            self.run.return_value = SimpleNamespace(returncode=0, stdout=b"", stderr=stderr)
            with self.assertRaisesRegex(RuntimeError, "output suppressed"):
                self.runner.run("/usr/bin/true")
        self.run.reset_mock()
        for argv, kwargs in ((("../untrusted",), {}), (("-S",), {}), (("true",), {"timeout": 3601}),
                             (("true",), {"timeout": float("nan")}), (("true",), {"input": object()})):
            with self.subTest(argv=argv), self.assertRaises(RuntimeError):
                self.runner.run(*argv, **kwargs)
        self.run.assert_not_called()

    def test_cancellation_cleanup_remains_owned_by_shared_transport(self):
        # The bounded helper's own tests cover killing/reaping its owned group;
        # this adapter must preserve cancellation rather than rerun the command.
        self.run.side_effect = KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            self.runner.run("/usr/bin/true")
        self.run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
