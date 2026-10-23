"""Native adapter fault model: fake command execution, real logs/journal/ZFS model."""

from contextlib import ExitStack, contextmanager, nullcontext
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from installer import maintenance_native as native, maintenance_journal as journal, recovery_sets as rs
from installer.config import Config
from installer.deploy import Deployment
from installer.generations import Store
from test_recovery_sets import FakeNative

BOOT1 = "{ sec = 1792000000, usec = 1 } original boot"
BOOT2 = "{ sec = 1792100000, usec = 2 } current boot"


class ServiceRunner:
    """Exercises real Deployment.jail numeric-JID checks on both sides."""
    def __init__(self, root):
        self.root = root
        self.calls = []
        self.jids = {"cloudnc": 41, "cloudoo": 42}
        self.process = {"cloudnc": [(10, 1, "mariadbd"), (20, 1, "httpd"), (30, 1, "php-fpm")],
                        "cloudoo": []}
        self.log = root / "nc-db-logs/mysqld.err"
        self.log.parent.mkdir()
        self.log.write_bytes(b"old mysqld: Shutdown complete\n")
        self.log.chmod(0o640)
        self.shutdown = b"2026-10-15 0 [Note] /usr/local/libexec/mariadbd: Shutdown complete\n"
        self.busy = set()
        self.failure = None
        self.changed_jid = False
        self.rotate = False
        self.argv = {}
        self.ready_output = "12.3.2-MariaDB\t0\t1\n"

    def run(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if args[:2] == ("jls", "-j"):
            jail = args[2]
            return SimpleNamespace(returncode=0, stdout=f"{self.jids[jail]} {jail} {self.root}/{jail}/root", stderr="")
        if args[0] == "jexec":
            jail = next(name for name, jid in self.jids.items() if str(jid) == args[1])
            command = args[2:]
            if command == self.failure:
                return SimpleNamespace(returncode=1, stdout="SECRET", stderr="SECRET")
            output = ""
            if command[:3] == ("ps", "-ww", "-p"):
                row = next(row for row in self.process[jail] if row[0] == int(command[3]))
                output = " ".join(map(str, row)) + " " + self.argv[row[0]]
            elif command[:1] == ("ps",):
                output = "1 0 init\n" + "\n".join(" ".join(map(str, row)) for row in self.process[jail])
            elif command == ("cat", "/var/run/php-fpm.pid"):
                output = "30"
            elif command == ("id", "-u", "mysql"):
                output = str(os.geteuid())
            elif command == ("/usr/local/bin/my_print_defaults", "mysqld"):
                output = "--log-error=/var/log/mysql/mysqld.err\n"
            elif command[0] == "/usr/local/bin/mariadb" and command[-1] == "SELECT @@global.log_error, @@global.pid_file":
                output = "/var/log/mysql/mysqld.err\t/var/db/mysql/cloudnc.pid\n"
            elif command[0] == "/usr/local/bin/mariadb" and command[-1] == "SELECT VERSION(), @@global.innodb_force_recovery, 1":
                output = self.ready_output
            elif command == ("cat", "/var/db/mysql/cloudnc.pid"):
                output = "10"
            elif command[0] in ("service", "kill", "/usr/local/sbin/apachectl"):
                service = command[1] if command[0] == "service" else "php_fpm" if command[0] == "kill" else "apache24"
                if service not in self.busy:
                    self.process[jail] = [row for row in self.process[jail] if row[2] not in native.PROCESSES[service]
                        and not (service == "mysql-server" and "/usr/local/bin/mariadbd-safe " in self.argv.get(row[0], ""))
                        and not (service == "supervisord" and "/usr/local/bin/supervisord " in self.argv.get(row[0], ""))]
                if service == "mysql-server":
                    if self.rotate:
                        self.log.rename(self.log.with_suffix(".old"))
                        self.log.write_bytes(self.shutdown)
                    else:
                        with self.log.open("ab") as stream:
                            stream.write(self.shutdown)
            else:
                raise AssertionError(command)
            if self.changed_jid:
                self.jids[jail] += 10
            return SimpleNamespace(returncode=0, stdout=output, stderr="")
        if args[0] == "curl":
            return SimpleNamespace(returncode=0, stdout="503", stderr="")
        raise AssertionError(args)

    def output(self, *args):
        if args[0] == "realpath":
            return args[1]
        raise AssertionError(args)


class NativeServiceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="native-services-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.runner = ServiceRunner(self.root)
        self.d = object.__new__(Deployment)
        self.d.config = SimpleNamespace(nextcloud_jail="cloudnc", onlyoffice_jail="cloudoo",
            jails=("cloudnc", "cloudoo"),
            bastille_root=str(self.root), mount_root=str(self.root), tls_mode="acme", ca_file="",
            public_hostname="cloud.example.test", public_https_port=8443, nextcloud_ip="10.0.0.2")
        # Deployment computes bastille_root/jails/name/root; match that exact root.
        self.d.jail_root = lambda name: self.root / name / "root"
        self.d.runner = self.runner
        ticks = iter(range(10000))
        self.backend = native.NativeBackend(self.d, timeout=3, clock=lambda: next(ticks), sleep=lambda _: None)
        # Host storage/PF ownership is tested by the real recovery backend model
        # below; service tests exercise only verified-JID/process/log semantics.
        self.backend.owned_live = Mock()

    def test_apache_and_fpm_drain_gracefully_with_pinned_numeric_jid(self):
        self.backend.stop("cloudnc", "apache24")
        self.backend.stop("cloudnc", "php_fpm")
        args = [call[0] for call in self.runner.calls]
        self.assertIn(("jexec", "41", "/usr/local/sbin/apachectl", "-k", "graceful-stop"), args)
        self.assertIn(("jexec", "41", "kill", "-QUIT", "30"), args)
        self.assertFalse(any("-KILL" in call or "-TERM" in call for call in args))
        for index, call in enumerate(args):
            if call[0] == "jexec":
                self.assertEqual(args[index - 1][:3], ("jls", "-j", "cloudnc"))
                self.assertEqual(args[index + 1][:3], ("jls", "-j", "cloudnc"))

    def test_busy_requests_timeout_without_escalation(self):
        self.runner.busy.add("apache24")
        with self.assertRaises(ValueError):
            self.backend.stop("cloudnc", "apache24")
        commands = [args for args, _ in self.runner.calls if args[0] == "jexec"]
        self.assertEqual([args for args in commands if args[2] != "ps"],
                         [("jexec", "41", "/usr/local/sbin/apachectl", "-k", "graceful-stop")])

    def test_orphaned_cron_php_or_unknown_editor_writer_is_not_daemon_closure(self):
        self.runner.process["cloudnc"] = [(10, 1, "mariadbd"), (50, 1, "php")]
        with self.assertRaises(ValueError):
            self.backend.wait_writer_closure(database_running=True)
        self.assertFalse(any(args[0] == "jexec" and args[2] == "kill" for args, _ in self.runner.calls))

    def test_freebsd_interpreter_names_require_exact_port_script_and_database_parent(self):
        self.runner.process["cloudnc"] = [(9, 1, "sh"), (10, 9, "mariadbd")]
        self.runner.argv[9] = "/bin/sh /usr/local/bin/mariadbd-safe --user=mysql"
        self.backend.wait_writer_closure(database_running=True)
        self.assertEqual(len(self.backend.running("cloudnc", "mysql-server")), 2)
        self.backend.clean_mysql_stop()
        self.backend.wait_writer_closure(database_running=False)
        # A supervisor with no node children must still be found and stopped.
        self.runner.process["cloudoo"] = [(40, 1, "python3.11")]
        self.runner.argv[40] = "/usr/local/bin/python3.11 /usr/local/bin/supervisord -u root"
        self.assertEqual(self.backend.running("cloudoo", "supervisord"), [(40, 1, "python3.11")])
        self.backend.stop("cloudoo", "supervisord")
        self.backend.wait_writer_closure(database_running=False)

    def test_other_shell_python_and_detached_database_wrapper_are_not_allowed(self):
        for command, argv, rows in (
                ("sh", "/bin/sh /tmp/writer.sh", [(10, 9, "mariadbd")]),
                ("sh", "/bin/sh /usr/local/bin/mariadbd-safe --user=mysql", [(10, 1, "mariadbd")]),
                ("python3.11", "/usr/local/bin/python3.11 /tmp/writer.py", [])):
            with self.subTest(argv=argv, rows=rows):
                self.runner.process["cloudnc"] = [(9, 1, command), *rows]
                self.runner.argv[9] = argv
                with self.assertRaises(ValueError):
                    self.backend.wait_writer_closure(database_running=True)

    def test_pid_replacement_or_command_failure_refuses_without_output(self):
        self.runner.changed_jid = True
        with self.assertRaisesRegex(ValueError, "Native maintenance refused") as error:
            self.backend.processes("cloudnc")
        self.assertNotIn("SECRET", str(error.exception))
        self.runner.changed_jid = False
        self.runner.failure = ("/usr/local/sbin/apachectl", "-k", "graceful-stop")
        with self.assertRaises(ValueError):
            self.backend.stop("cloudnc", "apache24")

    def test_clean_shutdown_requires_new_log_marker_and_gone_server(self):
        proof = self.backend.clean_mysql_stop()
        self.assertEqual(proof["pid"], 10)
        self.assertGreater(proof["offset"], 0)
        self.assertEqual(proof["segment_sha256"], hashlib.sha256(self.runner.shutdown).hexdigest())
        self.assertFalse(self.backend.running("cloudnc", "mysql-server"))

    def test_old_marker_process_gone_is_not_clean_shutdown(self):
        self.runner.shutdown = b""
        with self.assertRaises(ValueError):
            self.backend.clean_mysql_stop()
        self.assertFalse(self.backend.running("cloudnc", "mysql-server"))

    def test_rotated_log_or_live_server_refuses(self):
        self.runner.rotate = True
        with self.assertRaises(ValueError):
            self.backend.clean_mysql_stop()
        self.runner.rotate = False
        self.runner.process["cloudnc"].append((10, 1, "mariadbd"))
        self.runner.busy.add("mysql-server")
        with self.assertRaises(ValueError):
            self.backend.clean_mysql_stop()

    def test_source_observation_accepts_reviewed_loopback_database_hosts_only(self):
        from installer import enrollment, runtime_inventory
        from test_maintenance_preflight import inputs
        config,versions,observed,repository,bindings=inputs()
        self.d._versions=versions;self.d.state=self.root
        self.backend.jailed=Mock(return_value=SimpleNamespace(stdout='12.3.3-MariaDB-log'))
        status=dict(installed=True,maintenance=False,needsDbUpgrade=False,version='35.0.1.1')
        current=['127.0.0.1']
        def occ(command,*args):
            if command=='status':return json.dumps(status)
            if command=='app:list':return json.dumps(dict(enabled={'onlyoffice':'10.2.1'},disabled={}))
            return json.dumps(dict(system=dict(datadirectory='/var/nc-data',dbtype='mysql',dbhost=current[0]),apps={}))
        self.backend.occ=Mock(side_effect=occ)
        with patch.object(enrollment,'_source',return_value={}),patch.object(enrollment,'_inputs'), \
                patch.object(enrollment,'_packages',return_value={}),patch.object(enrollment,'_json',return_value={}), \
                patch.object(runtime_inventory,'collect_php',return_value=observed['php']) as php, \
                patch.object(self.backend,'reclosure_runtime',return_value={'fixture': 'runtime'}) as runtime:
            for host in ('127.0.0.1','localhost','localhost:/var/run/mysql/mysql.sock'):
                current[0]=host
                runtime.reset_mock()
                result=self.backend.source_observations()
                self.assertEqual(result['database'],'12.3.3-MariaDB-log')
                self.assertEqual(result['reclosure_runtime'],{'fixture': 'runtime'})
                runtime.assert_called_once_with()
            php.reset_mock();runtime.reset_mock();current[0]='192.0.2.44'
            with self.assertRaises(ValueError):self.backend.source_observations()
            php.assert_not_called()
            runtime.assert_not_called()

    def test_host_deny_probe_preserves_tls_identity_and_never_disables_verification(self):
        self.backend.deny_probe()
        args, _ = self.runner.calls[-1]
        self.assertIn("cloud.example.test:443:10.0.0.2", args)
        self.assertIn("Host: cloud.example.test:8443", args)
        self.assertNotIn("--insecure", args)
        self.assertNotIn("-k", args)
        self.d.config.tls_mode = "external"
        before = len(self.runner.calls)
        with self.assertRaises(ValueError):
            self.backend.deny_probe()
        self.assertEqual(len(self.runner.calls), before)

    def ingress_clock(self):
        current = [0.0]
        self.backend.clock = lambda: current[0]
        self.backend.sleep = lambda seconds: current.__setitem__(0, current[0] + seconds)
        self.backend.timeout = 0.5
        return current

    def test_ingress_wait_handles_delayed_graceful_reload_with_rechecks(self):
        self.ingress_clock()
        recheck = Mock()
        with patch.object(self.d, 'require_running_jail', return_value=41), \
                patch.object(self.backend, '_deny_status', side_effect=['200','503']) as probe:
            self.backend.wait_deny_probe(recheck)
        self.assertEqual(probe.call_count, 2)
        self.assertEqual(recheck.call_count, 4)

    def test_ingress_wait_refuses_persistent_old_response(self):
        self.ingress_clock()
        with patch.object(self.d, 'require_running_jail', return_value=41), \
                patch.object(self.backend, '_deny_status', return_value='200'):
            with self.assertRaises(ValueError):
                self.backend.wait_deny_probe(Mock())

    def test_ingress_wait_never_retries_tls_or_transport_failure(self):
        self.ingress_clock()
        with patch.object(self.d, 'require_running_jail', return_value=41), \
                patch.object(self.runner, 'run', return_value=SimpleNamespace(returncode=60,stdout='000')) as request:
            with self.assertRaises(ValueError):
                self.backend.wait_deny_probe(Mock())
        request.assert_called_once()
        self.assertNotIn('--insecure', request.call_args.args)

    def test_ingress_wait_refuses_jail_identity_drift(self):
        self.ingress_clock()
        with patch.object(self.d, 'require_running_jail', side_effect=[41,42]), \
                patch.object(self.backend, '_deny_status', return_value='503'):
            with self.assertRaises(ValueError):
                self.backend.wait_deny_probe(Mock())

    def test_ingress_wait_rechecks_operation_after_http_response(self):
        self.ingress_clock()
        with patch.object(self.d, 'require_running_jail', return_value=41), \
                patch.object(self.backend, '_deny_status', return_value='503'):
            with self.assertRaisesRegex(ValueError, 'closure changed'):
                self.backend.wait_deny_probe(Mock(side_effect=[None,ValueError('closure changed')]))

    def test_ingress_wait_refuses_late_success(self):
        clock = self.ingress_clock()
        def late(*_):
            clock[0] = 1.0
            return '503'
        with patch.object(self.d, 'require_running_jail', return_value=41), \
                patch.object(self.backend, '_deny_status', side_effect=late):
            with self.assertRaises(ValueError):
                self.backend.wait_deny_probe(Mock())

    def test_database_recovery_command_contract_is_exact_version_no_force_and_socket_only(self):
        self.d._versions = {"roles": {"database": "mariadb123-server"},
                            "packages": {"nextcloud": {"mariadb123-server": {"version": "12.3.2"}}}}
        proof = self.backend.database_ready()
        self.assertEqual(proof["innodb_force_recovery"], 0)
        queries = [args for args, _ in self.runner.calls if "SELECT VERSION(), @@global.innodb_force_recovery, 1" in args]
        self.assertEqual(len(queries), 1)
        self.assertIn("--protocol=socket", queries[0])
        self.assertIn("--user=root", queries[0])
        for output in ("", "12.4.1-MariaDB\t0\t1", "12.3.2-MariaDB\t1\t1", "12.3.2-MariaDB\t0"):
            self.runner.ready_output = output
            with self.subTest(output=output), self.assertRaises(ValueError):
                self.backend.database_ready()


class ReclosureRuntimeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="reclosure-runtime-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.config = SimpleNamespace(nextcloud_jail="cloudnc", onlyoffice_jail="cloudoo", mount_root=str(self.root / "data"))
        package = lambda name, origin, deps: dict(name=name, version="12.3.2", origin=origin, dependencies=deps,
                                                 checksum="a" * 64)
        self.plan = dict(roles={"database": "mariadb123-server"}, packages={
            "nextcloud": {"mariadb123-server": package("mariadb123-server", "databases/mariadb123-server", {"mariadb123-client": {}}),
                          "mariadb123-client": package("mariadb123-client", "databases/mariadb123-client", {})},
            "onlyoffice": {"onlyoffice-documentserver": package("onlyoffice-documentserver", "www/onlyoffice-documentserver", {})}})
        self.inventory, self.package_files = {}, {}
        for jail, group in (("cloudnc", "nextcloud"), ("cloudoo", "onlyoffice")):
            root = self.root / jail
            for path in ("bin", "sbin", "usr/bin", "usr/sbin", "lib", "libexec", "etc", "root",
                         "usr/local/bin", "usr/local/libexec", "usr/local/etc/mysql", "var/db/pkg"):
                (root / path).mkdir(parents=True, exist_ok=True)
            (root / "var/db/pkg/local.sqlite").write_bytes(b"original native pkg database fixture\n")
            self.inventory[jail] = "\n".join(f"{name} {item['version']} {item['origin']}"
                                             for name, item in self.plan["packages"][group].items())
            self.inventory[jail] += "\npkg 2.8.4 ports-mgmt/pkg"
            for name, item in self.plan["packages"][group].items():
                paths = (["/usr/local/libexec/mariadbd", "/usr/local/bin/mariadbd-safe"] if name.endswith("-server") else
                         ["/usr/local/bin/mariadb"] if name.endswith("-client") else [])
                for path in paths:
                    (root / path.lstrip("/")).write_bytes(b"original reviewed package file\n")
                self.package_files[(jail, name)] = paths
            (root / "bin/sh").write_bytes(b"original base executable\n")
            (root / "usr/local/etc/mysql/my.cnf").write_bytes(b"original database configuration\n")
        self.runner = Mock()
        data = Path(self.config.mount_root) / "nc-database"
        (data / "mysql").mkdir(parents=True)
        for path in ("mysql/global_priv.frm", "mysql/global_priv.MAD", "mysql/global_priv.MAI", "ibdata1", "ib_logfile0"):
            (data / path).write_bytes(b"existing MariaDB storage\n")
        d = SimpleNamespace(config=self.config, versions=self.plan, runner=self.runner, jail_root=lambda jail: self.root / jail)
        self.pkg_config = {"READ_LOCK": "no", "PLUGINS": "", "PKG_DBDIR": "/var/db/pkg"}
        def jailed(jail, *args, **kwargs):
            inspect = ("pkg", "-o", "PKG_ENABLE_PLUGINS=false")
            query = (*inspect, "-o", "READ_LOCK=false", "query")
            if args[:4] == (*inspect, "config") and len(args) == 5:
                output = self.pkg_config[args[4]]
            elif args == (*query, "%n %v %o"):
                output = self.inventory[jail]
            elif args[:7] == (*query, "%Fp") and len(args) == 8:
                output = "\n".join(self.package_files[(jail, args[7])])
            else:
                raise AssertionError(args)
            return SimpleNamespace(returncode=0, stdout=output)
        d.jail = Mock(side_effect=jailed)
        self.backend = native.NativeBackend(d)

    def test_native_readonly_pkgdb_and_runtime_inventory_detects_code_config_and_version_drift(self):
        original = self.backend.reclosure_runtime()
        self.backend.d.jail.reset_mock()
        self.assertEqual(self.backend.reclosure_runtime(original), original)
        self.runner.run.assert_not_called()
        self.runner.output.assert_not_called()
        for name in ("usr/local/libexec/mariadbd", "usr/local/etc/mysql/my.cnf", "bin/sh"):
            path = self.root / "cloudnc" / name
            saved = path.read_bytes()
            path.write_bytes(b"unreviewed changed bytes\n")
            self.assertNotEqual(self.backend.reclosure_runtime(original), original)
            path.write_bytes(saved)
        (self.root / "cloudnc/var/db/pkg/local.sqlite").write_bytes(b"changed package database\n")
        with self.assertRaises(ValueError):
            self.backend.reclosure_runtime(original)
        self.backend.d.jail.assert_not_called()
        # Initial observation must also match the original signed version lock.
        self.inventory["cloudnc"] = self.inventory["cloudnc"].replace("12.3.2", "12.4.1")
        with self.assertRaises(ValueError):
            self.backend.reclosure_runtime()

    def test_pkgdb_journal_and_linked_parent_cannot_become_cold_package_proof(self):
        original = self.backend.reclosure_runtime()
        self.backend.d.jail.reset_mock()
        wal = self.root / "cloudnc/var/db/pkg/local.sqlite-wal"
        wal.write_bytes(b"uncheckpointed WAL")
        with self.assertRaises(ValueError):
            self.backend.reclosure_runtime(original)
        wal.unlink()
        library = self.root / "cloudnc/usr/local/libexec"
        library.rename(library.with_name("saved-libexec"))
        library.symlink_to("saved-libexec", target_is_directory=True)
        with self.assertRaises(ValueError):
            self.backend.reclosure_runtime(original)
        self.backend.d.jail.assert_not_called()

    def test_reviewed_pam_reader_is_merged_without_losing_package_membership(self):
        from installer import maintenance_pkg_layout as layout
        name = self.plan["roles"]["database"]
        self.plan["packages"]["nextcloud"][name]["version"] = "12.3.3"
        self.inventory["cloudnc"] = self.inventory["cloudnc"].replace(
            "mariadb123-server 12.3.2", "mariadb123-server 12.3.3")
        self.package_files[("cloudnc", name)].append(layout.PAMFILE)
        evidence = {layout.PAMDIR: dict(type="directory", uid=88, gid=0, mode=0o700),
                    layout.PAMFILE: dict(type="file", uid=0, gid=0, mode=0o4755,
                                         size=10, sha256="a" * 64),
                    layout.PASSWD: dict(type="file", uid=0, gid=0, mode=0o644,
                                        size=20, sha256="b" * 64)}
        with patch.object(layout, "capture_mariadb_pam", return_value=evidence) as capture:
            original = self.backend.reclosure_runtime()
            capture.assert_called_once_with(self.root / "cloudnc", package_name=name,
                package_version="12.3.3", package_origin="databases/mariadb123-server")
            self.assertIn(layout.PAMFILE, original["database_files"])
            self.assertTrue(all(original["files"][key] == value for key, value in evidence.items()))
            self.backend.d.jail.reset_mock()
            self.assertEqual(self.backend.reclosure_runtime(original), original)
            self.backend.d.jail.assert_not_called()
            changed = deepcopy(evidence)
            changed[layout.PAMDIR]["mode"] = 0o750
            capture.return_value = changed
            self.assertNotEqual(self.backend.reclosure_runtime(original), original)
        with patch.object(layout, "capture_mariadb_pam", side_effect=ValueError("unsupported layout")):
            with self.assertRaises(ValueError):
                self.backend.reclosure_runtime()

    def test_empty_wal_and_shm_are_transient_and_cold_queries_remain_forbidden(self):
        root = self.root / "cloudnc"
        db = root / "var/db/pkg/local.sqlite"
        absent = self.backend.reclosure_runtime()
        Path(str(db) + "-wal").touch()
        shm = Path(str(db) + "-shm")
        shm.write_bytes(b"a" * 32768)
        original = self.backend.reclosure_runtime()
        self.assertEqual(original, absent)  # Existing serialized shape and bytes.
        self.assertEqual(set(original["package_databases"]["cloudnc"]), {"/var/db/pkg/local.sqlite"})
        self.backend.d.jail.reset_mock()
        with native._pkg_database_identity(root):
            shm.write_bytes(b"b" * 32768)
            os.utime(shm, ns=(1, 2))
        self.assertEqual(self.backend.reclosure_runtime(original), original)
        self.backend.d.jail.assert_not_called()

    def test_empty_wal_ctime_only_change_keeps_main_receipt_identical(self):
        root = self.root / "cloudnc"
        wal = root / "var/db/pkg/local.sqlite-wal"
        wal.touch()
        before = self.backend.reclosure_runtime()
        original = self.backend.d.jail.side_effect
        def touched(jail, *args, **kwargs):
            result = original(jail, *args, **kwargs)
            # Same-mode chmod models the ctime-only metadata effect of SQLite's
            # root same-owner fchown without requiring privileged test chown.
            wal.chmod(stat.S_IMODE(wal.stat().st_mode))
            return result
        with patch.object(self.backend.d, "jail", side_effect=touched):
            self.assertEqual(self.backend.reclosure_runtime(), before)
        self.backend.d.jail.reset_mock()
        self.assertEqual(self.backend.reclosure_runtime(before), before)
        self.backend.d.jail.assert_not_called()

    def test_wal_ctime_exception_does_not_ignore_other_fields_or_main_ctime(self):
        root = self.root / "cloudnc"
        wal = root / "var/db/pkg/local.sqlite-wal"
        wal.touch()
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                  "st_size", "st_mtime_ns", "st_ctime_ns")
        real_stat, real_fstat = os.stat, os.fstat
        for field in fields:
            inode = real_stat(wal).st_ino
            changed = False
            def observation(info):
                if changed and info.st_ino == inode:
                    values = {key: getattr(info, key) for key in fields}
                    values[field] += 1
                    return SimpleNamespace(**values)
                return info
            with self.subTest(field=field), \
                    patch.object(native.os, "stat", side_effect=lambda *a, **k: observation(real_stat(*a, **k))), \
                    patch.object(native.os, "fstat", side_effect=lambda *a, **k: observation(real_fstat(*a, **k))):
                expected = nullcontext() if field == "st_ctime_ns" else self.assertRaises(ValueError)
                with expected:
                    with native._pkg_database_identity(root):
                        changed = True
        # The WAL exception must not affect the main DB's ctime guard.
        main_inode = (root / "var/db/pkg/local.sqlite").stat().st_ino
        changed = False
        def main_observation(info):
            if changed and info.st_ino == main_inode:
                values = {key: getattr(info, key) for key in fields}
                values["st_ctime_ns"] += 1
                return SimpleNamespace(**values)
            return info
        with patch.object(native.os, "stat", side_effect=lambda *a, **k: main_observation(real_stat(*a, **k))), \
                patch.object(native.os, "fstat", side_effect=lambda *a, **k: main_observation(real_fstat(*a, **k))):
            with self.assertRaises(ValueError):
                with native._pkg_database_identity(root):
                    changed = True

    def test_config_inspection_suppresses_plugins_without_masking_read_lock(self):
        self.backend.reclosure_runtime()
        calls = [call.args[1:] for call in self.backend.d.jail.call_args_list]
        inspect = ("pkg", "-o", "PKG_ENABLE_PLUGINS=false")
        for key in self.pkg_config:
            self.assertIn((*inspect, "config", key), calls)
        self.assertTrue(all(args[:3] == inspect for args in calls))
        self.assertTrue(all(args[3:6] == ("-o", "READ_LOCK=false", "query")
                            for args in calls if "query" in args))

    def test_unsupported_config_refuses_before_any_inventory_query(self):
        for key, bad in (("READ_LOCK", "yes"), ("READ_LOCK", ""), ("PLUGINS", "audit"),
                         ("PKG_DBDIR", "/tmp/other")):
            with self.subTest(key=key, bad=bad):
                saved = self.pkg_config[key]
                self.pkg_config[key] = bad
                self.backend.d.jail.reset_mock()
                with self.assertRaises(ValueError):
                    self.backend.reclosure_runtime()
                self.assertFalse(any("query" in call.args for call in self.backend.d.jail.call_args_list))
                self.pkg_config[key] = saved

    def test_unreviewed_pkg_identity_refuses_before_file_queries(self):
        original = self.inventory["cloudnc"]
        for bad in ("pkg 2.6.2 ports-mgmt/pkg", "pkg 2.8.4_1 ports-mgmt/pkg", "pkg 2.8.4 other/pkg", "pkg broken"):
            with self.subTest(bad=bad):
                self.inventory["cloudnc"] = original.replace("pkg 2.8.4 ports-mgmt/pkg", bad)
                self.backend.d.jail.reset_mock()
                with self.assertRaises(ValueError):
                    self.backend.reclosure_runtime()
                self.assertFalse(any("%Fp" in call.args for call in self.backend.d.jail.call_args_list))

    def test_package_identity_brackets_the_last_file_query(self):
        base = self.backend.d.jail.side_effect
        db = self.root / "cloudnc/var/db/pkg/local.sqlite"
        for suffix in ("", "-wal", "-journal", "-shm"):
            saved = db.read_bytes()
            def changed(jail, *args, **kwargs):
                result = base(jail, *args, **kwargs)
                if jail == "cloudnc" and args[-2:] == ("%Fp", "mariadb123-server"):
                    Path(str(db) + suffix).write_bytes(b"changed")
                return result
            with self.subTest(suffix=suffix), patch.object(self.backend.d, "jail", side_effect=changed):
                with self.assertRaises(ValueError):
                    self.backend.reclosure_runtime()
            if suffix:
                Path(str(db) + suffix).unlink()
            else:
                db.write_bytes(saved)

    def test_sidecar_and_main_unsafe_types_modes_and_owner_refuse_at_entry(self):
        root = self.root / "cloudnc"
        db = root / "var/db/pkg/local.sqlite"
        for suffix in ("", "-wal", "-shm"):
            path = Path(str(db) + suffix)
            if not suffix:
                path.rename(path.with_name("saved-main"))
            for kind in ("symlink", "fifo", "directory", "hardlink", "writable", "owner"):
                with self.subTest(suffix=suffix, kind=kind):
                    if kind == "symlink":
                        path.symlink_to("saved-main")
                    elif kind == "fifo":
                        os.mkfifo(path)
                    elif kind == "directory":
                        path.mkdir()
                    elif kind == "hardlink":
                        os.link(root / "bin/sh", path)
                    else:
                        path.touch()
                        path.chmod(0o666 if kind == "writable" else 0o600)
                    owner = patch.object(native.os, "geteuid", return_value=os.geteuid() + 1) if kind == "owner" else nullcontext()
                    with owner, self.assertRaises(ValueError):
                        with native._pkg_database_identity(root):
                            self.fail("unsafe entry admitted")
                    if kind == "directory":
                        path.rmdir()
                    else:
                        path.unlink()
            if not suffix:
                path.with_name("saved-main").rename(path)

    def test_sidecar_size_journal_and_absent_creation_refuse(self):
        root = self.root / "cloudnc"
        db = root / "var/db/pkg/local.sqlite"
        for suffix, content in (("-wal", b"x"), ("-shm", b"x" * 32769), ("-journal", b"")):
            path = Path(str(db) + suffix)
            path.write_bytes(content)
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                with native._pkg_database_identity(root):
                    self.fail("unsafe sidecar admitted")
            path.unlink()
        for suffix in ("-wal", "-shm", "-journal"):
            path = Path(str(db) + suffix)
            with self.subTest(created=suffix), self.assertRaises(ValueError):
                with native._pkg_database_identity(root):
                    path.touch()
            path.unlink()

    def test_present_file_replacement_and_last_boundary_drift_refuse(self):
        root = self.root / "cloudnc"
        db = root / "var/db/pkg/local.sqlite"
        for suffix in ("", "-wal", "-shm"):
            path = Path(str(db) + suffix)
            if suffix:
                path.touch()
            for action in ("replace", "symlink", "chmod", "grow", "remove"):
                saved = path.read_bytes()
                with self.subTest(suffix=suffix, action=action), self.assertRaises(ValueError):
                    with native._pkg_database_identity(root):
                        if action in ("replace", "symlink", "remove"):
                            path.rename(path.with_name("saved-file"))
                            if action == "replace":
                                path.write_bytes(saved)
                            elif action == "symlink":
                                path.symlink_to("saved-file")
                        elif action == "chmod":
                            path.chmod(0o666)
                        else:
                            path.write_bytes(saved + b"x")
                if os.path.lexists(path):
                    path.unlink()
                if path.with_name("saved-file").exists():
                    path.with_name("saved-file").rename(path)
                else:
                    path.write_bytes(saved)
                path.chmod(0o600)
            if suffix:
                path.unlink()

    def test_parent_replacement_and_open_time_file_race_refuse(self):
        root = self.root / "cloudnc"
        directory = root / "var/db/pkg"
        with self.assertRaises(ValueError):
            with native._pkg_database_identity(root):
                directory.rename(directory.with_name("saved-pkg"))
                directory.symlink_to("saved-pkg", target_is_directory=True)
        directory.unlink()
        directory.with_name("saved-pkg").rename(directory)
        original_open = os.open
        def raced(name, flags, *args, **kwargs):
            if name == "local.sqlite":
                path = directory / name
                path.rename(directory / "saved-main")
                path.write_bytes((directory / "saved-main").read_bytes())
            return original_open(name, flags, *args, **kwargs)
        with patch.object(native.os, "open", side_effect=raced), self.assertRaises(ValueError):
            with native._pkg_database_identity(root):
                self.fail("replacement between stat and open was admitted")

    def test_cold_sidecar_change_after_final_main_hash_refuses_without_queries(self):
        original = self.backend.reclosure_runtime()
        self.backend.d.jail.reset_mock()
        real_files = native._runtime_files
        calls = 0
        def changed(root, names):
            nonlocal calls
            result = real_files(root, names)
            if names == ["/var/db/pkg/local.sqlite"]:
                calls += 1
                if calls == 2:
                    (root / "var/db/pkg/local.sqlite-wal").write_bytes(b"uncheckpointed")
            return result
        with patch.object(native, "_runtime_files", side_effect=changed), self.assertRaises(ValueError):
            self.backend.reclosure_runtime(original)
        self.backend.d.jail.assert_not_called()

    def test_leaf_owner_is_checked_at_first_and_last_boundaries(self):
        root = self.root / "cloudnc"
        real_stat = os.stat
        for boundary in (1, 2):
            count = 0
            def changed(name, *args, **kwargs):
                nonlocal count
                info = real_stat(name, *args, **kwargs)
                if name == "local.sqlite":
                    count += 1
                    if count == boundary:
                        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                                  "st_size", "st_mtime_ns", "st_ctime_ns")
                        values = {key: getattr(info, key) for key in fields}
                        values["st_uid"] += 1
                        return SimpleNamespace(**values)
                return info
            with self.subTest(boundary=boundary), patch.object(native.os, "stat", side_effect=changed):
                with self.assertRaises(ValueError):
                    with native._pkg_database_identity(root):
                        pass

    def test_missing_datadir_system_tables_cannot_trigger_rc_database_initialization(self):
        original = self.backend.reclosure_runtime()
        self.backend.d.jail.reset_mock()
        data = Path(self.config.mount_root) / "nc-database"
        (data / "mysql").rename(data / "missing-mysql")
        with self.assertRaises(OSError):
            self.backend.reclosure_runtime(original)
        self.runner.run.assert_not_called()
        self.backend.d.jail.assert_not_called()


class MemoryJournal:
    """Real pure phase validation, with Store's private atomic persistence."""
    def __init__(self, store, directory, reference):
        self.store, self.path = store, directory + "/native-journal.json"
        self.value = journal.native_initial(reference, reference, "c" * 64)
        self.save()

    def save(self):
        self.store._put(self.path, self.value, replace=self.store._present(self.path))

    def read(self):
        return journal.native_validate(json.loads(json.dumps(self.value)))

    def advance(self, phase, evidence):
        self.value = journal.native_transition(self.value, phase, evidence)
        self.save()

    def step_start(self, name, **kwargs):
        self.value = journal.native_start_step(self.value, name, **kwargs)
        self.save()

    def step_complete(self, name, reference):
        self.value = journal.native_complete_step(self.value, name, reference)
        self.save()

    def fail(self, error):
        self.value = journal.native_failure(self.value, error)
        self.save()

    def supersede_steps(self, reference):
        self.value = journal.native_supersede_steps(self.value, reference)
        self.save()


class ControllerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="native-controller-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        store = Store(root)
        self.n = object.__new__(native.NativeContext)
        self.n.store, self.n.operation = store, "execution-test"
        self.n.directory = "maintenance/operations/execution-test"
        self.n.registry = SimpleNamespace(root=root)
        store._mkdir(self.n.directory + "/recovery")
        self.n.c = Config(public_hostname="cloud.example.test", admin_email="admin@example.test",
            acme_email="admin@example.test", external_interface="igb0", ingress_address="192.0.2.10",
            dns_server="192.0.2.53", management_network="198.51.100.0/24").validate()
        evidence = []
        for role in sorted(rs.ROLES):
            ref = store._write(self.n.directory + "/" + role, role.encode())
            evidence.append(rs.Evidence(role, role, root / ref["path"], ref["sha256"]))
        self.ref = self.n.record("test-binding", {"scope": "fake-host"})
        self.n.journal = MemoryJournal(store, self.n.directory, self.ref)
        self.n.journal.advance("quiesced", {key: self.ref for key in journal.NATIVE_REQUIRED["quiesced"]})
        self.n.check = self.check
        self.n.profile = lambda: self.ref
        self.n.record("native-inputs", {"recipe": "fixture"})
        self.n.record("original-services", {"pair": {self.n.c.nextcloud_jail: "running", self.n.c.onlyoffice_jail: "running"}})
        self.c = rs.RecoveryContext(self.n.c, "execution-test", *(char * 64 for char in "abcde"),
            root / self.n.directory / "recovery", tuple(evidence), cold_boundary=self.n.cold_boundary,
            checkpoint=self.n.checkpoint, schema_version=2, quiescence_mode=rs.OPERATOR_OFFLINE,
            preparation_sha256="f" * 64)
        ack = self.n.record("offline-acknowledgement", rs.offline_acknowledgement_record(self.c))
        self.c = replace(self.c, offline_acknowledgement=rs.OfflineAcknowledgement(root / ack["path"], ack["sha256"]))
        self.n._recovery_context = lambda **kwargs: self.c
        self.runner = FakeNative(self.c)
        self.runner.overrides[("sysctl", "-n", "kern.boottime")] = BOOT1
        self.n.backend = native.NativeBackend(SimpleNamespace(config=self.n.c, runner=self.runner))
        with patch.object(self.n.backend, "clean_mysql_stop", return_value={
                "pid": 123, "offset": 10, "end": 40, "segment_sha256": "1" * 64}):
            self.n._stop_database()
        self.events = []
        self.n._start_closed = lambda phase: self.events.append("controlled-start")

    def check(self, **kwargs):
        value = self.n.journal.read()
        native._require(not value["publication_may_have_begun"] and not value["recovery_publication_may_have_begun"])
        return {}, {"recipe": {"id": "fixture"}}, value

    def adapter(self, *, fail=False):
        parent = self

        class Adapter(native.MigrationAdapter):
            def descriptor(self):
                return {"id": "fixture"}

            def execute(self, context):
                parent.events.append("migration")
                parent.assertEqual(len(parent.runner.snapshots), 14)
                parent.assertEqual(context.journal.read()["steps"]["reviewed-migration"]["state"], "running")
                if fail:
                    raise RuntimeError("SECRET")
                return parent.ref

        return Adapter()

    def test_real_capture_all14_precedes_migration_callback(self):
        result = self.n.capture()
        self.assertFalse(result["independent_copy_verified"])
        self.assertFalse(result["machine_drain_verified"])
        with patch.object(native.fence, "validation_starts", return_value=nullcontext()):
            result = self.n.migrate(self.adapter())
        self.assertEqual(self.events, ["controlled-start", "migration"])
        self.assertEqual(len(self.runner.snapshots), 14)
        self.assertFalse(result["ready"])

    def test_snapshot_failure_or_controller_interruption_prevents_updater(self):
        for failure in ("before", "partial", "after"):
            with self.subTest(failure=failure):
                self.runner.snapshots.clear()
                manifest = self.c.directory / "manifest.json"
                if manifest.exists():
                    manifest.unlink()
                self.runner.snapshot_fault = failure
                with self.assertRaises(rs.RecoveryError):
                    self.n.capture()
                with self.assertRaises(ValueError):
                    self.n.migrate(self.adapter())
                self.assertEqual(self.events, [])

    def test_updater_exception_is_uncertain_and_never_replayed(self):
        self.n.capture()
        with patch.object(native.fence, "validation_starts", return_value=nullcontext()):
            with self.assertRaisesRegex(ValueError, "Native maintenance refused"):
                self.n.migrate(self.adapter(fail=True))
        state = self.n.journal.read()
        self.assertEqual(state["phase"], "recovery-required")
        self.assertEqual(state["steps"]["reviewed-migration"]["state"], "uncertain")
        with self.assertRaises(ValueError):
            self.n.migrate(self.adapter())
        self.assertEqual(self.events.count("migration"), 1)

    def test_boundary_is_fresh_offline_false_drain_and_checks_real_cold_storage(self):
        self.n.capture()
        first = self.n.cold_boundary(self.c, "capture")
        second = self.n.cold_boundary(self.c, "capture")
        self.assertFalse(first.office_drained)
        self.assertEqual(first.original_services, (("cloudnc", "running"), ("cloudoo", "running")))
        self.assertNotEqual(first.evidence_sha256, second.evidence_sha256)
        self.assertNotEqual(first.evidence_sha256, first.capture_anchor_sha256)
        self.runner.live = f"41 cloudnc {self.n.c.bastille_root}/jails/cloudnc/root true"
        with self.assertRaises(rs.RecoveryError):
            self.n.cold_boundary(self.c, "capture")

    def test_start_or_reboot_invalidates_clean_shutdown_proof(self):
        self.n.record("validation-started", {"attempt": self.ref})
        with self.assertRaises(ValueError):
            self.n.cold_boundary(self.c, "capture")
        with patch.object(self.n.backend, "clean_mysql_stop", return_value={"new": "bounded-log-proof"}):
            self.n._stop_database()
        self.n.cold_boundary(self.c, "capture")
        self.runner.overrides[("sysctl", "-n", "kern.boottime")] = BOOT2
        with self.assertRaises(ValueError):
            self.n.cold_boundary(self.c, "capture")

    def test_recover_supersedes_only_after_all_restored_and_never_repeats_after_canary(self):
        self.n.capture()
        with patch.object(native.fence, "validation_starts", return_value=nullcontext()):
            with self.assertRaises(ValueError):
                self.n.migrate(self.adapter(fail=True))
        with patch.object(native.fence, "install_profile"):
            result = self.n.recover()
        self.assertEqual(result["state"], "datasets-restored")
        self.assertEqual(self.n.journal.read()["steps"]["reviewed-migration"]["state"], "superseded")
        commands = list(self.runner.mutations())
        self.runner.written[next(iter(self.runner.written))] = "999"  # Later canary write.
        result = self.n.recover()
        self.assertFalse(result["rollback_repeated"])
        self.assertEqual(self.runner.mutations(), commands)

    def test_failed_rollback_never_claims_restored_or_supersedes(self):
        self.n.capture()
        self.runner.rollback_fault = self.c.resources[1].name
        with self.assertRaises(rs.RecoveryError):
            self.n.recover()
        self.assertEqual(self.n.journal.read()["phase"], "restoring")
        self.assertNotIn("restored_set", self.n.journal.read()["evidence"])

    def test_catalog_gate_has_no_effect_and_json_is_not_harness(self):
        with self.assertRaisesRegex(ValueError, "no reviewed"):
            native.production_admission({"recipe": "anything", "execution_authorized": True})
        self.assertEqual(journal.REVIEWED_NATIVE_RECIPES, {})
        registry = Mock()
        with self.assertRaises(ValueError):
            with native.acceptance_session(registry, Mock(), harness={"approved": True}):
                self.fail("JSON entered native harness")
        registry.locked.assert_not_called()

    def test_start_closed_only_manually_starts_allowlisted_services(self):
        context = object.__new__(native.NativeContext)
        context.c, context.d, context.store = self.n.c, Mock(), self.n.store
        context.directory, context.profile = self.n.directory, self.n.profile
        context.record, context.check = self.n.record, self.n.check
        backend = context.backend = Mock()
        backend.pair_state.return_value = "stopped"
        backend.running.side_effect = lambda jail, name: False if name in ("cron", "sshd") else (len([
            call for call in backend.jailed.call_args_list if call.args == (jail, "service", name, "onestart")]) > 0)
        with patch("installer.lifecycle._require_jail"):
            context._start_closed("validating")
        starts = [(call.args[0], call.args[2]) for call in backend.jailed.call_args_list]
        self.assertEqual(starts, [("cloudnc", "mysql-server"), ("cloudnc", "redis"), ("cloudnc", "php_fpm"),
                                  ("cloudnc", "apache24"), ("cloudoo", "supervisord"), ("cloudoo", "nginx")])
        self.assertFalse(any(name in ("cron", "sshd") for _, name in starts))

    def test_migration_start_keeps_php_http_and_editor_writers_stopped(self):
        context = object.__new__(native.NativeContext)
        context.c, context.d, context.store = self.n.c, Mock(), self.n.store
        context.directory, context.profile = self.n.directory, self.n.profile
        context.record, context.check = self.n.record, self.n.check
        backend = context.backend = Mock()
        backend.pair_state.return_value = "stopped"
        backend.running.side_effect = lambda jail, name: any(
            call.args == (jail, "service", name, "onestart") for call in backend.jailed.call_args_list)
        with patch("installer.lifecycle._require_jail"):
            context._start_closed("migrating")
        self.assertEqual([call.args for call in backend.jailed.call_args_list], [
            ("cloudnc", "service", "mysql-server", "onestart"), ("cloudnc", "service", "redis", "onestart")])
        self.assertEqual(backend.wait_writer_closure.call_count, 2)
        backend.deny_probe.assert_not_called()
        # A failed CLI migration can close the database without starting Apache
        # merely to obtain an HTTP response from an intentionally stopped server.
        context.check = lambda **kwargs: ({}, {}, {"phase": "migrating"})
        context._stop_database = Mock()
        context._recovery_context = Mock()
        context.close_for_recovery()
        context._stop_database.assert_called_once_with()
        backend.stop_pair.assert_called_once_with()
        backend.deny_probe.assert_not_called()


class ReclosureTests(unittest.TestCase):
    def setUp(self):
        fixture = ControllerTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.n, self.runner, self.ref = fixture.n, fixture.runner, fixture.ref
        runtime = self.n.record("source-observations", {"reclosure_runtime": {"original-packages-and-db-files": True}})
        fixture.c = replace(fixture.c, evidence=fixture.c.evidence + (
            rs.Evidence("source-observations", "metadata", self.n.store.root / runtime["path"], runtime["sha256"]),))
        self.c = fixture.c
        self.n.capture()
        self.captured_journal = self.n.journal.read()
        self.n.journal.advance("migrating", {key: self.ref for key in journal.NATIVE_REQUIRED["migrating"]})
        self.n.journal.step_start("migration", replay="never", precondition=self.ref)
        self.n.journal.fail("migration-failed")
        self.runner.overrides[("sysctl", "-n", "kern.boottime")] = BOOT2
        self.backend = self.n.backend
        self.n.d = self.backend.d
        self.backend.d.jail_root = lambda name: Path(self.n.c.bastille_root) / "jails" / name / "root"
        self.backend.identity = Mock()
        self.backend.owned_live = Mock()
        self.backend.closed_flags = Mock()
        self.backend.wait_writer_closure = Mock()
        self.backend.reclosure_runtime = Mock(return_value={"original-packages-and-db-files": True})
        self.n._verify_reclosure_stage = Mock()
        self.backend.database_ready = Mock(return_value={"version": "12.3.2-MariaDB", "innodb_force_recovery": 0})
        self.backend.clean_mysql_stop = Mock(return_value={"pid": 10, "offset": 200, "end": 300, "segment_sha256": "e" * 64})
        self.backend.jailed = Mock(return_value=SimpleNamespace(returncode=0, stdout=""))
        self.events, self.started = [], set()
        original_run = self.backend.run

        def run(*args):
            if args[:2] == ("bastille", "start"):
                self.events.append(args)
                self.started.add(args[2])
                self.runner.live = "\n".join(f"{40 + index} {name} {self.backend.d.jail_root(name)} false"
                                             for index, name in enumerate(sorted(self.started)))
            else:
                return original_run(*args)

        def stop_pair():
            self.events.append(("stop-pair",))
            self.started.clear()
            self.runner.live = "90 othernc /srv/other/root false"

        self.backend.run = Mock(side_effect=run)
        self.backend.stop_pair = Mock(side_effect=stop_pair)

    def requiesce(self, **kwargs):
        with patch.object(native.fence, "validation_starts", return_value=nullcontext()), \
                patch("installer.lifecycle._require_jail"):
            return self.n.requiesce("REQUIESCE-MAINTENANCE " + self.n.operation, **kwargs)

    def test_crossboot_database_only_closure_then_separate_verified_rollback(self):
        before = self.n.journal.read()
        old = json.loads(self.n.store._read(self.n.directory + "/current-shutdown.json"))["proof"]
        result = self.requiesce()
        self.assertEqual(result["state"], "recovery-reclosed")
        self.assertFalse(result["rollback_started"])
        self.assertEqual(self.events, [("bastille", "start", "cloudnc"), ("bastille", "start", "cloudoo"), ("stop-pair",)])
        self.backend.jailed.assert_called_once_with("cloudnc", "service", "mysql-server", "onestart")
        self.backend.database_ready.assert_called_once_with()
        self.backend.clean_mysql_stop.assert_called_once_with()
        after = self.n.journal.read()
        self.assertEqual(after["steps"]["migration"]["state"], "uncertain")
        self.assertEqual(after["history"][:len(before["history"])], before["history"])
        new = json.loads(self.n.store._read(self.n.directory + "/current-shutdown.json"))["proof"]
        self.assertNotEqual(old, new)
        self.assertEqual(json.loads(self.n.store._bound(old))["boot"], BOOT1)
        proof = json.loads(self.n.store._bound(new))
        self.assertEqual(proof["boot"], BOOT2)
        manifest = json.loads(self.n.store._bound(after["evidence"]["recovery_set"]))
        self.assertEqual(proof["reclosure"]["capture_anchor_sha256"], manifest["cold_boundary"])
        self.assertTrue(self.n.assess().eligible)
        self.assertFalse(any(args[:2] == ("zfs", "rollback") for args in self.runner.calls))
        with patch.object(native.fence, "install_profile"):
            self.n.recover()
        self.assertEqual(self.n.journal.read()["steps"]["migration"]["state"], "superseded")
        self.assertEqual(len([args for args in self.runner.calls if args[:2] == ("zfs", "rollback")]), 14)

    def test_sameboot_invalidated_start_is_reclosed_but_valid_historical_stop_is_not_reused(self):
        self.runner.overrides[("sysctl", "-n", "kern.boottime")] = BOOT1
        self.assertFalse(self.n.assess_requiescence().eligible)
        with self.assertRaises(ValueError):
            self.requiesce()
        self.assertEqual(self.events, [])
        self.n.record("validation-started", {"attempt": self.ref})
        self.requiesce()
        self.backend.clean_mysql_stop.assert_called_once_with()

    def test_reboot_after_original_clean_capture_still_performs_new_clean_stop(self):
        self.n.journal.value = self.captured_journal
        self.n.journal.save()
        self.requiesce()
        self.backend.database_ready.assert_called_once_with()
        self.backend.clean_mysql_stop.assert_called_once_with()
        self.assertEqual(self.n.journal.read()["phase"], "recovery-reclosed")

    def test_assessment_is_read_only_and_all14_identity_or_package_drift_blocks_before_starts(self):
        before = {str(p): p.read_bytes() for p in self.n.store.root.rglob("*") if p.is_file()}
        self.assertTrue(self.n.assess_requiescence().eligible)
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.n.store.root.rglob("*") if p.is_file()})
        snapshot = next(iter(self.runner.snapshots.values()))
        for key, bad in (("guid", "999999"), (rs.OWNER, "other"), ("clones", "other/clone"), ("userrefs", "1")):
            original = snapshot[key]
            snapshot[key] = bad
            with self.subTest(key=key):
                self.assertFalse(self.n.assess_requiescence().eligible)
                with self.assertRaises((ValueError, rs.RecoveryError)):
                    self.requiesce()
            snapshot[key] = original
        self.backend.reclosure_runtime.return_value = {"changed-package-db": True}
        self.assertFalse(self.n.assess_requiescence().eligible)
        self.assertEqual(self.events, [])
        self.backend.jailed.assert_not_called()

    def test_invalid_boot_identity_confirmation_and_publication_refuse_without_starts(self):
        for boot in ("", "false", "0", "{ sec = 0, usec = 0 }", "{ sec = 1, usec = 1000000 }", False, None):
            self.runner.overrides[("sysctl", "-n", "kern.boottime")] = boot
            with self.subTest(boot=boot):
                self.assertFalse(self.n.assess_requiescence().eligible)
        self.runner.overrides[("sysctl", "-n", "kern.boottime")] = BOOT2
        with self.assertRaises(ValueError):
            self.n.requiesce("REQUIESCE-MAINTENANCE other")
        for marker in ("publication_may_have_begun", "recovery_publication_may_have_begun"):
            self.n.journal.value[marker] = True
            self.n.journal.save()
            before = list(self.runner.calls)
            with self.assertRaises(ValueError):
                self.requiesce()
            self.assertEqual(self.runner.calls, before)
            self.n.journal.value[marker] = False
        self.assertEqual(self.events, [])

    def test_interrupted_halfboot_never_restarts_and_cold_retry_needs_fresh_assessment(self):
        run = self.backend.run.side_effect
        def fail_second(*args):
            if args == ("bastille", "start", "cloudoo"):
                raise RuntimeError("private failure")
            run(*args)
        self.backend.run.side_effect = fail_second
        with self.assertRaises(ValueError):
            self.requiesce()
        first = self.n.journal.read()
        self.assertEqual(first["last_safe_phase"], "recovery-reclosing")
        self.assertFalse(self.n.assess_requiescence().eligible)
        events = list(self.events)
        with self.assertRaises(ValueError):
            self.requiesce()
        self.assertEqual(events, self.events)
        # External/manual shutdown is only a cold prerequisite, never clean proof.
        self.backend.stop_pair()
        self.backend.run.side_effect = run
        assessment = self.n.assess_requiescence()
        self.assertTrue(assessment.eligible)
        with self.assertRaises(ValueError):
            self.requiesce()
        self.n.journal.fail("interrupted")
        with self.assertRaises(ValueError):
            self.requiesce(assessment=assessment)
        self.requiesce(assessment=self.n.assess_requiescence())
        state = self.n.journal.read()
        self.assertEqual(state["steps"]["migration"]["state"], "uncertain")
        self.assertTrue(any(step["phase"] == "recovery-reclosing" and step["state"] == "uncertain"
                            for step in state["steps"].values()))
        with patch.object(native.fence, "install_profile"):
            self.n.recover()
        self.assertTrue(all(step["state"] == "superseded" for step in self.n.journal.read()["steps"].values()))

    def test_interrupted_after_clean_stop_reconciles_exact_proof_without_second_start(self):
        with patch.object(self.n, "_finish_reclosure", side_effect=RuntimeError("interrupted")):
            with self.assertRaises(ValueError):
                self.requiesce()
        self.assertFalse(self.n.assess().eligible)
        assessment = self.n.assess_requiescence()
        self.assertTrue(assessment.eligible)
        events = list(self.events)
        self.requiesce(assessment=assessment)
        self.assertEqual(events, self.events)
        self.backend.clean_mysql_stop.assert_called_once_with()
        self.assertTrue(self.n.assess().eligible)

    def test_failed_native_recovery_never_creates_new_shutdown_or_restore_authority(self):
        old = self.n.store._read(self.n.directory + "/current-shutdown.json")
        self.backend.database_ready.side_effect = ValueError("simulated database readiness failure")
        with self.assertRaises(ValueError):
            self.requiesce()
        self.assertEqual(self.n.store._read(self.n.directory + "/current-shutdown.json"), old)
        self.backend.clean_mysql_stop.assert_not_called()
        self.assertFalse(self.n.assess().eligible)
        self.assertFalse(self.n.assess_requiescence().eligible)

    def test_complete_closure_receipt_before_phase_commit_is_readonly_assessed_then_explicitly_restored(self):
        advance = self.n.journal.advance
        def fail_commit(phase, evidence):
            if phase == "recovery-reclosed":
                raise RuntimeError("simulated controller interruption before closed phase commit")
            return advance(phase, evidence)
        with patch.object(self.n.journal, "advance", side_effect=fail_commit):
            with self.assertRaises(RuntimeError):
                self.requiesce()
        self.assertEqual(self.n.journal.read()["phase"], "recovery-reclosing")
        before = {str(p): p.read_bytes() for p in self.n.store.root.rglob("*") if p.is_file()}
        self.assertTrue(self.n.assess().eligible)
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.n.store.root.rglob("*") if p.is_file()})
        events = list(self.events)
        with patch.object(native.fence, "install_profile"):
            self.n.recover()
        self.assertEqual(self.events, events)
        self.assertEqual(self.n.journal.read()["phase"], "restored-closed")


class NativeBindingTests(unittest.TestCase):
    """Real NativeState/NativeJournal/lock path, with host probes mocked only."""

    def setUp(self):
        import test_maintenance_state as fixtures
        self.fixture = fixtures.NativeStateTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    @contextmanager
    def candidate_gate(self):
        from installer.maintenance_admission import SourceAdmission
        from installer import maintenance_candidate as candidates
        from installer.maintenance_operations import load_operation
        fixture, events = self.fixture, []
        manifest = fixture.store._generation("cloud", fixture.entries["cloud"]["generation"])
        config = Config.from_json(fixture.store._bound(manifest["config"]).decode())
        with fixture.registry.locked(recovery=True):
            _, _, staged = load_operation(fixture.registry, "maint-fixture")
            staged.initialize()
            staged.advance("staged", {"artifacts": fixture.preparation})
        harness = SourceAdmission(fixture.native)
        now = int(native.time.time())
        fixture.store._mkdir('fixture')
        candidate_ref = fixture.store._put('fixture/candidate-freshness.json',
            dict(observations=dict(captured_at=now),repository=dict(captured_at=now)))
        captured = candidates.CapturedCandidate("maint-fixture", candidate_ref, None)

        def deployment(registry, name, runner):
            d = object.__new__(Deployment)
            d.registry, d.config, d.runner = registry, config, runner
            d.state = registry.instance_path(name)
            return d

        def admit(deployment):
            events.append("admit")
            return dict(startup={config.nextcloud_jail: {}, config.onlyoffice_jail: {}}, evidence=fixture.preparation)

        def revalidate(candidate, deployment, *, source_admission):
            from installer.enrollment_start import _held
            fixture.registry._require_lock()
            _held(fixture.store, "instances/cloud/database-operation.lock")
            self.assertIs(source_admission, harness)
            admission = source_admission.admit_source(deployment)
            events.append("candidate")
            return candidates.RevalidatedCandidate(candidate.reference, admission)

        begin = native.NativeState.begin
        def observed_begin(state, *args, **kwargs):
            events.append("begin")
            return begin(state, *args, **kwargs)

        with ExitStack() as stack:
            for target, kwargs in (
                    ("installer.operations.ROOT_UID", dict(new=os.geteuid())),
                    ("installer.maintenance.entry_guard", {}),
                    ("installer.maintenance_staging.verify_stage", {}),
                    ("installer.host.verify_managed_network", {}),
                    ("installer.deploy.source_digest", dict(return_value=fixture.executor["source_sha256"] + "\n"))):
                stack.enter_context(patch(target, **kwargs))
            for owner, name, kwargs in (
                    (native, "executor_record", dict(return_value=fixture.executor)),
                    (native, "_deployment", dict(side_effect=deployment)),
                    (native.fence, "startup_inventory", dict(side_effect=lambda *a, **k: events.append("startup") or {})),
                    (native.NativeBackend, "owned_live", {}),
                    (native.NativeBackend, "source_observations", dict(side_effect=lambda: events.append("observations") or {})),
                    (native.NativeState, "begin", dict(new=observed_begin)),
                    (harness, "descriptor", dict(return_value=fixture.recipe)),
                    (harness, "admit_source", dict(side_effect=admit))):
                stack.enter_context(patch.object(owner, name, **kwargs))
            gate = stack.enter_context(patch.object(candidates, "revalidate_for_execution", side_effect=revalidate))
            yield harness, captured, gate, events

    def test_source_candidate_gate_precedes_begin_under_both_locks_and_pins_resume_reference(self):
        from installer import maintenance_candidate as candidates
        with self.candidate_gate() as (harness, captured, gate, events):
            with native.acceptance_session(self.fixture.registry, Mock(), harness=harness,
                    preparation=self.fixture.preparation, candidate=captured) as context:
                self.assertEqual(events, ["admit", "candidate", "startup", "startup", "observations", "begin"])
                harness.admit_source.assert_called_once()
                path = context.directory + "/candidate-reference.json"
                self.assertEqual(json.loads(context.store._read(path)), captured.reference)
                saved = context.store._read(path)
                operation = context.operation
            gate.reset_mock()
            gate.side_effect = AssertionError("Resume must not inspect changed target as original source")
            with patch.object(candidates, "load", return_value=captured) as load:
                with native.acceptance_session(self.fixture.registry, Mock(), harness=harness, operation=operation):
                    self.assertEqual(self.fixture.store._read(path), saved)
                load.assert_called_once()
                gate.assert_not_called()
                (self.fixture.store.root / path).unlink()
                with self.assertRaises((ValueError, OSError)):
                    with native.acceptance_session(self.fixture.registry, Mock(), harness=harness, operation=operation):
                        self.fail("Missing candidate reference must refuse")

    def test_stale_drift_and_failed_candidate_revalidation_never_begin_intent(self):
        from installer import maintenance_candidate as candidates
        with self.candidate_gate() as (harness,captured,gate,events):
            for code in ('candidate-ineligible-or-stale','candidate-inputs-changed','candidate-revalidation-failed'):
                with self.subTest(code=code):
                    events.clear()
                    gate.side_effect=candidates.CandidateError(code)
                    with self.assertRaises(candidates.CandidateError):
                        with native.acceptance_session(self.fixture.registry,Mock(),harness=harness,
                                preparation=self.fixture.preparation,candidate=captured):
                            self.fail('A refused candidate must not create a native intent')
                    self.assertNotIn('begin',events)
                    self.assertNotIn('observations',events)
                    self.assertIsNone(self.fixture.store.pending())

    def test_age_crossing_300_in_prebegin_source_observations_never_creates_intent(self):
        from installer import maintenance_candidate as candidates
        with self.candidate_gate() as (harness,captured,gate,events):
            timestamp=json.loads(self.fixture.store._bound(captured.reference))['observations']['captured_at']
            clock=[timestamp+299]
            def later():
                events.append('observations');clock[0]=timestamp+301;return {}
            with patch.object(native.time,'time',side_effect=lambda:clock[0]), \
                    patch.object(native.NativeBackend,'source_observations',side_effect=later):
                with self.assertRaises(candidates.CandidateError):
                    with native.acceptance_session(self.fixture.registry,Mock(),harness=harness,
                            preparation=self.fixture.preparation,candidate=captured):
                        self.fail('Expired candidate must not create an intent')
            self.assertNotIn('begin',events)
            self.assertIsNone(self.fixture.store.pending())

    def test_candidate_gate_rejects_supplied_dictionary_instead_of_typed_result(self):
        with self.candidate_gate() as (harness, captured, gate, events):
            gate.side_effect = None
            gate.return_value = {'reference': captured.reference, 'admission': {}}
            with self.assertRaises(ValueError):
                with native.acceptance_session(self.fixture.registry, Mock(), harness=harness,
                        preparation=self.fixture.preparation, candidate=captured):
                    self.fail('A supplied proof dictionary must never begin execution')
            self.assertNotIn('begin', events)
            self.assertIsNone(self.fixture.store.pending())

    def test_activation_interruption_retains_original_receipts_and_resumes_capture_without_services(self):
        from installer import maintenance_candidate as candidates
        fixture = self.fixture
        activate = Store.activate_intent
        saved = {}
        runner = Mock()

        def interrupt_after_activate(store, intent):
            directory = "maintenance/operations/" + intent["operation"]
            for name in ("admission.json", "source-observations.json", "candidate-reference.json"):
                saved[name] = store._read(directory + "/" + name)
            self.assertEqual(json.loads(saved["admission.json"])["evidence"], fixture.preparation)
            self.assertEqual(json.loads(saved["candidate-reference.json"]), captured.reference)
            self.assertFalse(store._present(directory + "/native-journal.json"))
            activate(store, intent)
            self.assertEqual(store.pending(), intent)
            raise RuntimeError("simulated controller interruption after activation")

        with self.candidate_gate() as (harness, captured, gate, events):
            with patch.object(Store, "activate_intent", new=interrupt_after_activate):
                with self.assertRaisesRegex(RuntimeError, "controller interruption"):
                    with native.acceptance_session(fixture.registry, runner, harness=harness,
                            preparation=fixture.preparation, candidate=captured):
                        self.fail("Controller interruption precedes context initialization/yield")
            operation = fixture.store.pending()["operation"]
            directory = "maintenance/operations/" + operation
            self.assertFalse(fixture.store._present(directory + "/native-journal.json"))
            self.assertEqual(events, ["admit", "candidate", "startup", "startup", "observations", "begin"])
            gate.reset_mock()
            gate.side_effect = AssertionError("Resume cannot revalidate changed runtime")
            with patch.object(candidates, "load", return_value=captured), \
                    patch.object(harness, "admit_source", side_effect=AssertionError("Original admission must be retained")), \
                    patch.object(native.NativeBackend, "source_observations", side_effect=AssertionError("Never rebuild observations")):
                with native.acceptance_session(fixture.registry, runner, harness=harness, operation=operation) as context:
                    value = context.journal.read()
                    self.assertEqual(value["phase"], "capture")
                    self.assertEqual(value["steps"], {})
                    self.assertEqual(value["history"], [])
                    self.assertEqual(context.admission, json.loads(saved["admission.json"]))
                    self.assertFalse(context.store._present(directory + "/closed-profile.json"))
                    for name, data in saved.items():
                        self.assertEqual(context.store._read(directory + "/" + name), data)
                    context.check()
            gate.assert_not_called()
            self.assertEqual(runner.mock_calls, [])

    def test_source_candidate_missing_wrong_or_ineligible_refuses_before_any_execution_intent(self):
        with self.candidate_gate() as (harness, captured, gate, events):
            def records():
                return {str(p): p.read_bytes() for p in self.fixture.root.rglob("*")
                        if p.is_file() and p.name != "database-operation.lock"}
            before = records()
            for candidate in (None, {}, replace(captured, operation="another"), captured):
                gate.side_effect = ValueError("candidate-ineligible")
                with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                    with native.acceptance_session(self.fixture.registry, Mock(), harness=harness,
                            preparation=self.fixture.preparation, candidate=candidate):
                        self.fail("Invalid candidate must refuse")
                self.assertNotIn("begin", events)
                self.assertEqual(before, records())
            gate.assert_called_once()

    def test_test_harness_cannot_supply_candidate(self):
        class Harness(native.AcceptanceHarness):
            def descriptor(self):
                raise AssertionError("Candidate must refuse before admission")

            def admit_source(self, deployment):
                raise AssertionError("Candidate must refuse before admission")

        with self.assertRaises(ValueError):
            with native.acceptance_session(self.fixture.registry, Mock(), harness=Harness(), candidate=object()):
                self.fail("Candidate belongs only to SourceAdmission")

    def test_acceptance_reviews_installed_code_before_executing_source_helpers(self):
        from installer.maintenance_operations import load_operation
        fixture, events = self.fixture, []
        manifest = fixture.store._generation("cloud", fixture.entries["cloud"]["generation"])
        config = Config.from_json(fixture.store._bound(manifest["config"]).decode())
        with fixture.registry.locked(recovery=True):
            _, _, staged = load_operation(fixture.registry, "maint-fixture")
            staged.initialize()
            staged.advance("staged", {"artifacts": fixture.preparation})

        class Harness(native.AcceptanceHarness):
            def descriptor(self):
                return fixture.recipe

            def admit_source(self, deployment):
                events.append("review-installed-code")
                return {"startup": {deployment.config.nextcloud_jail: {}, deployment.config.onlyoffice_jail: {}},
                        "evidence": fixture.preparation}

        def deployment(registry, name, runner):
            d = object.__new__(Deployment)
            d.registry, d.config, d.runner = registry, config, runner
            d.state = registry.instance_path(name)
            return d

        def observations(backend):
            events.append("execute-source-helpers")
            return {"source": fixture.executor["source_sha256"]}

        with patch("installer.operations.ROOT_UID", os.geteuid()), \
                patch("installer.maintenance.entry_guard"), \
                patch("installer.maintenance_staging.verify_stage"), \
                patch("installer.host.verify_managed_network"), \
                patch("installer.deploy.source_digest", return_value=fixture.executor["source_sha256"] + "\n"), \
                patch.object(native, "executor_record", return_value=fixture.executor), \
                patch.object(native, "_deployment", side_effect=deployment), \
                patch.object(native.fence, "startup_inventory", return_value={}), \
                patch.object(native.NativeBackend, "owned_live"), \
                patch.object(native.NativeBackend, "source_observations", observations):
            with native.acceptance_session(fixture.registry, Mock(), harness=Harness(), preparation=fixture.preparation) as context:
                self.assertEqual(events, ["review-installed-code", "execute-source-helpers"])
                self.assertEqual(context.journal.read()["phase"], "capture")
                context.check()
            self.assertFalse(context.active)
            with self.assertRaises(ValueError):
                context.check()

    def test_recovery_context_and_boundary_keep_pending_native_view_and_real_locks(self):
        from installer.operations import _database_guard
        fixture = self.fixture
        with fixture.registry.locked(recovery=True):
            fixture.begin()
            d = object.__new__(Deployment)
            d.registry = fixture.native.view(fixture.operation)
            d.config = d.registry.load("cloud")
            d.state, d.runner = fixture.root / "instances/cloud", Mock()
            for name in ("inputs.sha256", "inventory.json"):
                fixture.store._write("instances/cloud/" + name, b"original private input\n")
            ref = fixture.store._put("maintenance/operations/" + fixture.operation + "/admission.json", {"fixture": True})
            context = native.NativeContext(fixture.registry, fixture.native, fixture.operation, d, {})
            context.active = True
            context.record("source-observations", {"fixture": "original source observation"})
            context.record("original-services", {"pair": {d.config.nextcloud_jail: "running", d.config.onlyoffice_jail: "running"}})
            context.record("closed-profile", {"files": []})
            context.journal.advance("quiesced", {key: ref for key in journal.NATIVE_REQUIRED["quiesced"]})
            with patch("installer.operations.ROOT_UID", os.geteuid()), \
                    patch("installer.host.verify_managed_network"), \
                    patch("installer.deploy.source_digest", return_value=fixture.executor["source_sha256"] + "\n"), \
                    patch.object(native.fence, "verify_closed"):
                with self.assertRaises((ValueError, OSError)):
                    context.check()
                with _database_guard(d):
                    context.check()
                    # The observer tests the existing exclusive holder; it must
                    # not acquire a second exclusive database-operation lock.
                    with self.assertRaises(RuntimeError):
                        with _database_guard(d):
                            self.fail("nested database lock admitted")
                    recovery = context._recovery_context()
                    ack = context.acknowledge(rs.offline_acknowledgement_phrase(recovery))
                    original_shutdown = context.record("clean-shutdown-" + "0" * 32, dict(boot=BOOT1, after_start=None,
                        observation=dict(pid=123, device=4, inode=55, offset=10, end=80, segment_sha256="a" * 64)))
                    context.record("initial-closure", dict(binding=recovery.binding(), clean_database_shutdown=True,
                        profile=context.profile(), shutdown=original_shutdown, storage={},
                        original_services=context.store.reference(context.directory + "/original-services.json"), acknowledgement=ack))
                    recovery = context._recovery_context()
                    self.assertEqual({item.role for item in recovery.evidence}, rs.ROLES)
                    for missing in (None, "private-inventory.json", "tls-binding.json", "source-observations.json", "initial-closure.json",
                                    "offline-acknowledgement.json"):
                        path = context.store.root / context.directory / missing if missing else None
                        saved = path.read_bytes() if path else None
                        if path:
                            path.unlink()
                        with patch.object(context.store, "_write", side_effect=AssertionError("readonly write")), \
                                patch.object(context.store, "_put", side_effect=AssertionError("readonly put")), \
                                patch.object(context.store, "_mkdir", side_effect=AssertionError("readonly mkdir")), \
                                patch.object(context.store, "_write_once", side_effect=AssertionError("readonly retain")):
                            if path:
                                with self.assertRaises((ValueError, OSError)):
                                    context._recovery_context(readonly=True)
                                self.assertFalse(path.exists())
                            else:
                                self.assertEqual(context._recovery_context(readonly=True), recovery)
                        if path:
                            context.store._write(context.directory + "/" + missing, saved)
                    context.backend = Mock()
                    context.backend.output.return_value = BOOT1
                    context.backend.storage.return_value = {}
                    context.backend.clean_mysql_stop.return_value = {"bounded-log": "fixture"}
                    context._stop_database()
                    rebuilt = context._recovery_context(readonly=True)
                    self.assertEqual(rebuilt.evidence, recovery.evidence)
                    self.assertEqual(next(e.sha256 for e in rebuilt.evidence if e.name == "capture-clean-shutdown"),
                                     original_shutdown["sha256"])
                    # This invokes _recovery_context again from cold_boundary;
                    # load_operation must use the inert parent, not Store.graph.
                    proof = context.cold_boundary(recovery, "capture")
                    self.assertEqual(proof.phase, "quiesced")
                    self.assertFalse(proof.office_drained)
                    with patch("installer.deploy.source_digest", return_value="f" * 64 + "\n"):
                        with self.assertRaises(ValueError):
                            context.check()
                with self.assertRaises(ValueError):
                    context.check()


class OriginalRestoreTests(unittest.TestCase):
    """Actual clean capture chain and 14-member fault model; no live DB probes."""
    def setUp(self):
        fixture = ControllerTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.n, self.runner, self.ref = fixture.n, fixture.runner, fixture.ref
        self.c = fixture.c
        self.n.journal.value = journal.native_initial(self.ref, self.ref, "c" * 64)
        self.n.journal.save()
        with patch.object(self.n.backend, "clean_mysql_stop", return_value={
                "pid": 123, "device": 4, "inode": 55, "offset": 10, "end": 80, "segment_sha256": "a" * 64}):
            shutdown = self.n._stop_database()
        services = self.n.store.reference(self.n.directory + "/original-services.json")
        ack = self.n.store.reference(self.n.directory + "/offline-acknowledgement.json")
        initial = self.n.record("initial-closure", dict(binding=self.c.binding(), clean_database_shutdown=True,
            profile=self.n.profile(), shutdown=shutdown, storage=self.n.backend.storage(self.c),
            original_services=services, acknowledgement=ack))
        evidence = tuple(rs.Evidence(name, "metadata", self.n.store.root / ref["path"], ref["sha256"])
                         for name, ref in (("initial-closure", initial), ("capture-clean-shutdown", shutdown)))
        self.c = replace(self.c, evidence=self.c.evidence + evidence)
        self.n._recovery_context = lambda **kwargs: replace(self.c, original_restore=getattr(self.n, "_original_restore_consent", None))
        self.n.journal.step_start("close-writers", replay="never", precondition=services)
        self.n.journal.step_complete("close-writers", initial)
        self.n.journal.advance("quiesced", {**{key: self.ref for key in journal.NATIVE_REQUIRED["quiesced"]},
            "shutdown": shutdown, "closure": initial, "offline_acknowledgement": ack})
        self.n.capture()
        self.manifest = json.loads(self.n.store._bound(self.n.journal.read()["evidence"]["recovery_set"]))
        self.n.journal.advance("migrating", {"recipe": self.ref, "closure": initial})
        self.n.journal.step_start("migration", replay="never", precondition=self.ref)
        self.n.journal.fail("migration-failed")
        self.n.record("validation-started", {"attempt": self.ref})
        self.runner.overrides[("sysctl", "-n", "kern.boottime")] = BOOT2
        self.n.backend.d.jail_root = lambda name: Path(self.n.c.bastille_root) / "jails" / name / "root"
        self.n.backend.identity = Mock()
        for method in ("jailed", "clean_mysql_stop", "database_ready", "reclosure_runtime", "owned_live", "stop_pair"):
            setattr(self.n.backend, method, Mock(side_effect=AssertionError("Discarded application must not execute or be inspected")))

    def restore(self, assessment=None):
        if assessment is None:
            assessment = self.n.assess_original_restore()
        with patch.object(native.fence, "install_profile"):
            return self.n.restore_original("RESTORE-ORIGINAL " + self.n.operation + " DISCARD-CLOSED-CHANGES", assessment=assessment)

    def rollbacks(self):
        return [args for args in self.runner.calls if args[:2] == ("zfs", "rollback")]

    @contextmanager
    def live_discarded_pair(self, *, database_present=False, retain_alias=False):
        """Real service stop/writer waits and numeric-JID wrapper, fake host only."""
        services = ServiceRunner(self.n.store.root)
        services.root = Path(self.n.c.bastille_root) / "jails"
        services.shutdown = b""  # No positive clean-shutdown marker, even if live.
        if not database_present:
            services.process["cloudnc"] = [row for row in services.process["cloudnc"] if row[2] != "mariadbd"]
        services.process["cloudnc"].extend([(40, 1, "redis-server"), (50, 1, "cron")])
        services.process["cloudoo"] = [(60, 1, "nginx"), (70, 1, "sshd")]
        deployment = object.__new__(Deployment)
        deployment.config, deployment.runner = self.n.c, services
        self.n.backend.d = deployment
        self.runner.live = "\n".join(f"{jid} {name} {deployment.jail_root(name)} false" for name, jid in services.jids.items())
        self.runner.extra_mount = (f"\n{self.n.c.mount_root}/nc-data "
                                   f"{deployment.jail_root('cloudnc')}/var/nc-data nullfs rw 0 0")
        self.n.backend.owned_live = Mock()
        self.n.backend.closed_flags = Mock()
        self.n.backend.deny_probe = Mock()
        self.n.backend.jailed = native.NativeBackend.jailed.__get__(self.n.backend)
        self.n.backend.stop_pair = native.NativeBackend.stop_pair.__get__(self.n.backend)
        ticks = iter(range(100000))
        self.n.backend.clock, self.n.backend.sleep, self.n.backend.timeout = lambda: next(ticks), lambda _: None, 3
        effects, before_stops = [], []
        run = services.run

        def service_run(*args, **kwargs):
            if args[0] == "jexec":
                command = args[2:]
                self.assertNotIn("/usr/local/bin/mariadb", command)
                self.assertNotIn("/usr/local/bin/my_print_defaults", command)
                self.assertFalse(any(word in command for word in ("start", "onestart", "restart", "onerestart")))
                if command[0] in ("service", "kill", "/usr/local/sbin/apachectl"):
                    before_stops.append(list(self.runner.calls))
                    effects.append(args)
            return run(*args, **kwargs)

        def stop_jail(*args):
            if args[:2] == ("zfs", "rollback"):
                return self.runner.run(*args)
            self.assertEqual(args[:2], ("bastille", "stop"))
            effects.append(args)
            self.runner.calls.append(args)
            self.runner.live = "\n".join(line for line in self.runner.live.splitlines() if line.split()[1] != args[2])
            if not self.runner.live and not retain_alias:
                self.runner.extra_mount = ""

        services.run = service_run
        with patch("installer.lifecycle._require_jail"), patch.object(self.n.backend, "run", side_effect=stop_jail):
            yield services, effects, before_stops

    def close_original(self):
        return self.n.close_for_original_restore("RESTORE-ORIGINAL " + self.n.operation + " DISCARD-CLOSED-CHANGES")

    def test_live_pair_with_dead_or_unhealthy_database_closes_without_clean_proof(self):
        with self.live_discarded_pair() as (services, effects, before_stops):
            old = self.n.store._read(self.n.directory + "/current-shutdown.json")
            history = self.n.journal.read()["history"]
            self.assertFalse(self.n.assess_original_restore().eligible)
            result = self.close_original()
            self.assertTrue(result["assessment"].eligible)
            self.assertEqual(self.n.backend.pair_state(), "stopped")
            self.assertFalse(result["clean_database_shutdown"])
            self.assertFalse(result["office_drained"])
            request = json.loads(self.n.store._bound(result["request"]))
            self.assertEqual(request["manifest"], self.n.journal.read()["evidence"]["recovery_set"])
            self.assertEqual(request["capture_anchor_sha256"], self.manifest["cold_boundary"])
            self.assertFalse(request["clean_database_shutdown"])
            self.assertIsNone(getattr(self.n, "_original_restore_consent", None))
            self.assertEqual(self.n.store._read(self.n.directory + "/current-shutdown.json"), old)
            self.assertEqual(self.n.journal.read()["history"], history)
            self.assertFalse(any("mysql-server" in args for args in effects))
            for dataset in self.manifest["datasets"]:
                self.assertIn(("zfs", "get", "-Hp", "-o", "value", "guid", dataset), before_stops[0])
            for snapshot in self.manifest["snapshots"]:
                self.assertIn(("zfs", "get", "-Hp", "-o", "value", rs.TOKEN, snapshot), before_stops[0])
            self.assertEqual(self.rollbacks(), [])
            self.restore(result["assessment"])
            self.assertEqual(len(self.rollbacks()), 14)
            for method in ("clean_mysql_stop", "database_ready", "reclosure_runtime"):
                getattr(self.n.backend, method).assert_not_called()

    def test_live_database_can_stop_without_sql_or_shutdown_log_marker(self):
        with self.live_discarded_pair(database_present=True) as (services, effects, _):
            result = self.close_original()
            self.assertTrue(result["assessment"].eligible)
            self.assertIn(("jexec", "41", "service", "mysql-server", "onestop"), effects)
            self.assertFalse(result["clean_database_shutdown"])
            self.n.backend.clean_mysql_stop.assert_not_called()

    def test_original_evidence_dataset_and_snapshot_drift_refuse_before_any_stop(self):
        with self.live_discarded_pair() as (_, effects, _):
            initial = self.n.store.root / self.n.directory / "initial-closure.json"
            saved = initial.read_bytes()
            initial.write_bytes(b'{"clean_database_shutdown":true}\n')
            with self.assertRaises(ValueError):
                self.close_original()
            initial.write_bytes(saved)
            for data in (self.runner.props[self.c.resources[-1].name], self.runner.snapshots[list(self.runner.snapshots)[-1]]):
                saved = data["guid"]
                data["guid"] = "99999999"
                with self.assertRaises(ValueError):
                    self.close_original()
                data["guid"] = saved
            for marker in ("publication_may_have_begun", "recovery_publication_may_have_begun"):
                self.n.journal.value[marker] = True
                self.n.journal.save()
                with self.assertRaises(ValueError):
                    self.close_original()
                self.n.journal.value[marker] = False
            event = self.n.journal.value["history"][0]
            original_phase = event["phase"]
            event["phase"] = "recovery-validating"
            self.n.journal.save()
            with self.assertRaises(ValueError):
                self.close_original()
            event["phase"] = original_phase
            self.n.journal.save()
            with self.assertRaises(ValueError):
                self.n.close_for_original_restore("RESTORE-ORIGINAL wrong DISCARD-CLOSED-CHANGES")
            self.runner.live = self.runner.live.splitlines()[0]
            with self.assertRaises(ValueError):
                self.close_original()
            self.assertEqual(effects, [])
            self.assertEqual(list((self.n.store.root / self.n.directory).glob("restore-original-stop-*.json")), [])

    def test_poststop_alias_or_surviving_writer_never_becomes_stopped_restore_proof(self):
        with self.live_discarded_pair(retain_alias=True) as (services, effects, _):
            services.busy.add("php_fpm")
            with self.assertRaises(ValueError):
                self.close_original()
            self.assertFalse(any(args[0] == "bastille" for args in effects))
            self.assertFalse(self.n.assess_original_restore().eligible)
            services.busy.clear()
            with self.assertRaises(ValueError):
                self.close_original()
            self.assertEqual(self.n.backend.pair_state(), "stopped")
            self.assertFalse(self.n.assess_original_restore().eligible)
            self.assertEqual(self.rollbacks(), [])

    def test_cancellation_blocks_every_mutation_entry_before_effects(self):
        self.n.record("cancellation-request", {"pending": True})
        before = {str(p): p.read_bytes() for p in self.n.store.root.rglob("*") if p.is_file()}
        calls = list(self.runner.calls)
        entries = ((self.n.quiesce, ("unused",), {}), (self.n.capture, (), {}),
                   (self.n.migrate, (None,), {}), (self.n.recover, (), {}),
                   (self.n.restore_original, ("unused",), {}), (self.n.requiesce, ("unused",), {}),
                   (self.n.close_for_recovery, (), {}), (self.n.close_for_original_restore, ("unused",), {}),
                   (self.n.validate_closed, (), {"expected_version": "35.0.1.1"}))
        with patch.object(self.n, "check", side_effect=AssertionError("Guard must precede execution checks")):
            for method, args, kwargs in entries:
                with self.subTest(method=method.__name__), self.assertRaisesRegex(ValueError, "cancellation"):
                    method(*args, **kwargs)
            for method in (self.n.assess, self.n.assess_original_restore, self.n.assess_requiescence):
                self.assertFalse(method().eligible)
        self.assertEqual(calls, self.runner.calls)
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.n.store.root.rglob("*") if p.is_file()})

    def test_corrupted_discarded_database_restores_original_clean_set_without_starting(self):
        self.assertEqual(set(("initial-closure", "capture-clean-shutdown")) - self.manifest["evidence"].keys(), set())
        for name in ("initial-closure", "capture-clean-shutdown"):
            path = self.c.directory / self.manifest["evidence"][name]["path"]
            self.assertTrue(path.is_file())
        before = {str(p): p.read_bytes() for p in self.n.store.root.rglob("*") if p.is_file()}
        assessment = self.n.assess_original_restore()
        self.assertTrue(assessment.eligible)
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.n.store.root.rglob("*") if p.is_file()})
        proofs = []
        self.runner.after_rollback = lambda _: proofs.append(self.n.cold_boundary(self.n._recovery_context(readonly=True), "restore"))
        result = self.restore(assessment)
        self.assertEqual(result["state"], "datasets-restored")
        self.assertEqual(len(self.rollbacks()), 14)
        self.assertTrue(proofs and all(p.clean_database_shutdown is False and p.office_drained is False
                                      and p.restore_basis == rs.ORIGINAL_CLEAN_SET for p in proofs))
        self.assertTrue(all(p.evidence_sha256 != self.manifest["cold_boundary"] for p in proofs))
        self.assertIsNone(self.n._original_restore_consent)
        self.assertEqual(self.n.journal.read()["steps"]["migration"]["state"], "superseded")
        for method in ("jailed", "clean_mysql_stop", "database_ready", "reclosure_runtime", "owned_live", "stop_pair"):
            getattr(self.n.backend, method).assert_not_called()
        first = self.runner.calls.index(self.rollbacks()[0])
        for snapshot in self.manifest["snapshots"]:
            self.assertIn(("zfs", "get", "-Hp", "-o", "value", rs.OWNER, snapshot), self.runner.calls[:first])

    def test_sameboot_and_newboot_are_eligible_without_reinterpreting_shutdown(self):
        for boot in (BOOT1, BOOT2):
            self.runner.overrides[("sysctl", "-n", "kern.boottime")] = boot
            with self.subTest(boot=boot):
                self.assertTrue(self.n.assess_original_restore().eligible)
        self.assertFalse(self.n.assess().eligible)  # Old clean-current API remains strict.

    def test_exact_new_consent_assessment_and_original_offline_ack_required(self):
        assessment = self.n.assess_original_restore()
        with self.assertRaises(ValueError):
            self.n.restore_original("RESTORE-ORIGINAL other DISCARD-CLOSED-CHANGES", assessment=assessment)
        with self.assertRaises(ValueError):
            self.n.restore_original("RESTORE-ORIGINAL execution-test DISCARD-CLOSED-CHANGES")
        with self.assertRaises(ValueError):
            self.n.restore_original("RESTORE-ORIGINAL execution-test DISCARD-CLOSED-CHANGES", assessment={"eligible": True})
        self.n.journal.fail("interrupted")
        with self.assertRaises(ValueError):
            self.restore(assessment)
        (self.n.store.root / self.n.directory / "offline-acknowledgement.json").unlink()
        self.assertFalse(self.n.assess_original_restore().eligible)
        self.assertEqual(self.rollbacks(), [])

    def test_forged_or_missing_original_positive_proof_and_capture_anchor_refuse(self):
        paths = [self.n.store.root / self.n.directory / "initial-closure.json",
                 self.c.directory / self.manifest["evidence"]["capture-clean-shutdown"]["path"],
                 self.n.store.root / self.n.directory / ("closure-" + self.manifest["cold_boundary"] + ".json")]
        for path in paths:
            saved = path.read_bytes()
            path.write_bytes(b'{"clean_database_shutdown":true}\n')
            with self.subTest(path=path):
                self.assertFalse(self.n.assess_original_restore().eligible)
            path.write_bytes(saved)
        event = next(e for e in self.n.journal.value["history"] if e["event"] == "step-complete")
        event["step"]["observation"] = self.ref
        self.n.journal.save()
        self.assertFalse(self.n.assess_original_restore().eligible)
        self.assertEqual(self.rollbacks(), [])

    def test_publication_flags_and_last_snapshot_or_alias_block_all_effects(self):
        for marker in ("publication_may_have_begun", "recovery_publication_may_have_begun"):
            self.n.journal.value[marker] = True
            self.n.journal.save()
            calls = list(self.runner.calls)
            self.assertFalse(self.n.assess_original_restore().eligible)
            self.assertEqual(calls, self.runner.calls)
            self.n.journal.value[marker] = False
        snapshot = self.runner.snapshots[list(self.runner.snapshots)[-1]]
        original = snapshot["guid"]
        snapshot["guid"] = "999999"
        self.assertFalse(self.n.assess_original_restore().eligible)
        snapshot["guid"] = original
        self.runner.extra_mount = "\n/alias /foreign-target nullfs rw 0 0"
        self.runner.overrides[("realpath", "/alias")] = self.c.resources[-1].mountpoint
        self.assertFalse(self.n.assess_original_restore().eligible)
        self.assertEqual(self.rollbacks(), [])

    def test_interrupted_restore_retries_only_incomplete_members_and_never_starts(self):
        self.runner.rollback_fault = self.c.resources[1].name
        with self.assertRaises(rs.RecoveryError):
            self.restore()
        self.assertEqual(self.n.journal.read()["phase"], "restoring")
        self.assertIsNone(self.n._original_restore_consent)
        self.runner.rollback_fault = None
        self.runner.overrides[("sysctl", "-n", "kern.boottime")] = "{ sec = 1792200000, usec = 3 } later boot"
        self.restore()
        first = rs._snapshot(self.c, self.c.resources[0].name)
        self.assertEqual(self.rollbacks().count(("zfs", "rollback", first)), 1)
        self.assertFalse(any(args[0] in ("bastille", "jexec") for args in self.runner.calls))

    def test_failed_reclosure_is_discarded_without_restarting_database_or_losing_history(self):
        self.n.journal.advance("recovery-reclosing", {key: self.ref for key in journal.NATIVE_REQUIRED["recovery-reclosing"]})
        self.n.journal.step_start("reclose-failed", replay="never", precondition=self.ref)
        self.n.journal.fail("reconciliation-failed")
        history = self.n.journal.read()["history"]
        self.restore()
        value = self.n.journal.read()
        self.assertEqual(value["history"][:len(history)], history)
        self.assertEqual(value["steps"]["reclose-failed"]["state"], "superseded")
        self.assertEqual(len(self.rollbacks()), 14)
        self.assertIn("original_restore_consent", value["evidence"])

    def test_newer_snapshots_are_never_deleted_and_restored_canaries_never_rerolled(self):
        original = next(iter(self.runner.snapshots))
        newer = original.split("@")[0] + "@newer"
        self.runner.snapshots[newer] = {**self.runner.snapshots[original], "guid": "9000", "createtxg": "99"}
        self.assertFalse(self.n.assess_original_restore().eligible)
        self.assertEqual(self.rollbacks(), [])
        del self.runner.snapshots[newer]  # Remove only the fake model fault, not a native command.
        self.restore()
        calls = list(self.runner.calls)
        self.runner.written[self.c.resources[0].name] = "999"
        self.assertFalse(self.n.assess_original_restore().eligible)
        with self.assertRaises(ValueError):
            self.restore()
        self.assertEqual(self.runner.calls, calls)


if __name__ == "__main__":
    unittest.main()
