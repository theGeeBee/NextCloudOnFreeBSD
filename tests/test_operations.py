"""Offline maintenance/recovery tests. All process and jail administration is mocked.

Streaming tests substitute harmless Python pipe children for jexec; all files
live in private temporary directories. No installer, service, package or jail is started.
"""

import ast
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import PropertyMock, patch

from installer import operations as op
from installer.deploy import Deployment, source_digest
from installer.state import atomic_write


ROOT = Path(__file__).resolve().parents[1]
TABLES = [["oc_" + name, "BASE TABLE", "InnoDB"] for name in sorted((
    "users", "appconfig", "filecache", "migrations", "calendars", "calendarobjects", "addressbooks", "cards"))]
SQL = b"-- all users\nCREATE TABLE oc_cards (id INT);\nINSERT INTO oc_cards VALUES (42);\n"
KEY_BLOB = len(b"ssh-ed25519").to_bytes(4, "big") + b"ssh-ed25519" + (32).to_bytes(4, "big") + b"k" * 32
PUBLIC_KEY = "ssh-ed25519 " + base64.b64encode(KEY_BLOB).decode() + " local test\n"


class FakeConfig(SimpleNamespace):
    @property
    def jails(self):
        return ((self.nextcloud_jail,) if getattr(self, 'office_backend', '') == 'none'
                else (self.nextcloud_jail, self.onlyoffice_jail))

    def to_json(self):
        return json.dumps(vars(self), sort_keys=True)


class FakeDeployment:
    require_original_artifact = Deployment.require_original_artifact

    def __init__(self, directory):
        self.config = FakeConfig(instance="cloud", public_hostname="cloud.example.test",
                                      public_url="https://cloud.example.test/",
                                      nextcloud_jail="cloudnc", onlyoffice_jail="cloudoo",
                                      mount_root=str(directory / "datasets"), jail_ssh=False,
                                      ssh_username="cloudop", ssh_shell="sh", ssh_key_file="")
        self.state = directory / "state"
        self.state.mkdir(mode=0o700)
        self.registry = SimpleNamespace(evidence_path=lambda instance, filename: self.state / filename)
        atomic_write(self.state / "source.sha256", source_digest())
        self.root = directory / "jail"
        self.app_config = self.root / "usr/local/www/nextcloud/config"
        self.app_config.mkdir(parents=True)
        (self.app_config / "config.php").write_text("<?php $CONFIG=['maintenance'=>true, 'secret'=>'private-test'];\n")
        (self.app_config / "config.php").chmod(0o600)
        for name, contents in {
            "version.php": "<?php $OC_Version = array(35, 0, 1, 0);\n",
            "core/signature.json": '{"hashes": {}}\n',
            "apps/dav/appinfo/info.xml": "<info><id>dav</id><version>1.0.0</version></info>\n",
            "custom_apps/onlyoffice/appinfo/info.xml": "<info><id>onlyoffice</id><version>9.4.0</version></info>\n",
            "custom_apps/onlyoffice/appinfo/signature.json": '{"signature": "test-only-signature"}\n',
        }.items():
            path = self.app_config.parent / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents)
        self.services = {"cron": True, "apache24": True, "php_fpm": True}
        self.maintenance = False
        self.calls = []
        self.jid = 17
        self.nextcloud_version = "35.0.1.0"
        self.mariadb_version = "12.3.2-MariaDB"
        # Maintenance tests isolate orchestration from discovery/resolution.
        self.versions = {"applications": {"nextcloud": "35.0.1"},
                         "roles": {"database": "mariadb123-server"},
                         "packages": {"nextcloud": {"mariadb123-server": {"version": "12.3.2"}}}}
        self.instance_id = "ocExample123"
        self.tables = [row[:] for row in TABLES]
        self.fail_stop = None
        self.fail_start = None
        self.fail_fingerprint = False
        self.draining = False
        self.partial_database = False
        self.guard_failure = False
        self.guard_replaces_jail = False
        self.host_calls = []
        self.runner = SimpleNamespace(run=self.host_run)

    @property
    def maintenance(self):
        return "'maintenance'=>true" in (self.app_config / "config.php").read_text()

    @maintenance.setter
    def maintenance(self, enabled):
        (self.app_config / "config.php").write_text(
            "<?php $CONFIG=['maintenance'=>" + ("true" if enabled else "false") + ", 'secret'=>'private-test'];\n")

    def host_run(self, *args, **kwargs):
        self.host_calls.append((args, kwargs))
        if self.guard_replaces_jail:
            self.jid += 1
        return SimpleNamespace(returncode=int(self.guard_failure), stdout="", stderr="")

    def require_running_jail(self, name):
        if not self.jid:
            raise RuntimeError("Jail stopped")
        return self.jid

    def jail_root(self, name):
        return self.root

    def jail(self, name, *args, **kwargs):
        self.calls.append((name, args, kwargs))
        code, output = 0, ""
        if self.partial_database and "/usr/local/bin/php" in args:
            return SimpleNamespace(returncode=1, stdout="", stderr="Nextcloud database is partial")
        if args[0] == "service":
            service, action = args[1:]
            if action == "onestatus":
                code = 0 if self.services[service] else 1
            elif action == "onestop":
                if service == self.fail_stop:
                    code = 1
                else:
                    self.services[service] = False
            elif action == "onestart":
                if service == self.fail_start:
                    code = 1
                else:
                    self.services[service] = True
        elif args[0] == "pgrep":
            code = 0 if self.draining else 1
        elif "status" in args:
            output = json.dumps({"installed": True, "needsDbUpgrade": False,
                                 "maintenance": self.maintenance, "version": self.nextcloud_version})
        elif "app:list" in args:
            output = json.dumps({"enabled": {"dav": "1.0.0", "onlyoffice": "9.4.0"}, "disabled": {}})
        elif "maintenance:mode" in args:
            self.maintenance = "--on" in args
        elif "maintenance:data-fingerprint" in args and self.fail_fingerprint:
            code = 1
        elif args[0] == "redis-cli":
            output = "OK\n"
        elif args[-1] == "metadata":
            output = json.dumps({"instance_id": self.instance_id, "table_prefix": "oc_", "runtime_binding": "a" * 64})
        elif args[-1] == "create-user":
            payload = json.loads(kwargs["input"])
            output = json.dumps({"created": payload["username"], "admin": False})
        elif "SELECT VERSION()" in args:
            output = self.mariadb_version + "\n"
        elif args[0] == "/usr/local/bin/mariadb":
            output = "\n".join("\t".join(row) for row in self.tables) + "\n"
        elif args[:2] == ("id", "-u"):
            output = str(os.getuid())
        elif args[:2] == ("id", "-g"):
            output = str(os.getgid())
        elif args[-1] == "/root/cloud-installer/resources/jails/ssh.sh":
            settings = json.loads(kwargs["input"])
            output = json.dumps({key: settings[key] for key in ("username", "shell", "admin")})
        return SimpleNamespace(returncode=code, stdout=output, stderr="private diagnostic never printed")


class OperationsTests(unittest.TestCase):
    def test_user_creation_does_not_require_retained_version_lock(self):
        with patch.object(FakeDeployment, "versions", new_callable=PropertyMock, create=True) as selected:
            selected.side_effect = AssertionError("User creation must not read original version locks")
            self.assertEqual(op.create_user(self.deployment, "alice", "a-valid-password"),
                             {"created": "alice", "admin": False})
        selected.assert_not_called()

    def test_user_creation_accepts_upgraded_runtime_without_original_artifact(self):
        atomic_write(self.deployment.state / "source.sha256", "0" * 64 + "\n")
        self.deployment.nextcloud_version = "35.0.2.0"
        self.deployment.mariadb_version = "12.3.3-MariaDB"
        with patch.object(self.deployment, "require_original_artifact", side_effect=AssertionError), \
                patch.object(op, "_database_version", side_effect=AssertionError):
            self.assertEqual(op.create_user(self.deployment, "alice", "a-valid-password"),
                             {"created": "alice", "admin": False})
        self.assertFalse(any("SELECT VERSION()" in args for _, args, _ in self.deployment.calls))

    def test_user_creation_still_requires_live_ready_status_before_installing_helper(self):
        ready = {"installed": True, "maintenance": False, "needsDbUpgrade": False}
        for value in ("", [], {}, {**ready, "installed": False},
                      {**ready, "needsDbUpgrade": True}, {**ready, "needsDbUpgrade": None},
                      {**ready, "maintenance": "false"}, {**ready, "maintenance": True}):
            with self.subTest(value=value), patch.object(op, "_occ", return_value=json.dumps(value)), \
                    patch.object(op, "_install_helper") as install:
                with self.assertRaises(ValueError):
                    op.create_user(self.deployment, "alice", "a-valid-password")
                install.assert_not_called()

    def test_user_creation_does_not_inspect_the_occ_version_field(self):
        with patch.object(op, "_occ", return_value=json.dumps({
                "installed": True, "maintenance": False, "needsDbUpgrade": False})):
            self.assertEqual(op.create_user(self.deployment, "alice", "a-valid-password"),
                             {"created": "alice", "admin": False})

    def test_user_creation_rejects_unverified_or_admin_helper_result(self):
        for value in ({"created": "alice", "admin": True}, {"created": "someone-else", "admin": False}):
            with self.subTest(value=value), patch.object(op, "_helper", return_value=json.dumps(value)):
                with self.assertRaisesRegex(RuntimeError, "verified normal-user"):
                    op.create_user(self.deployment, "alice", "a-valid-password")

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="operations-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.deployment = FakeDeployment(self.directory)
        for replacement in (patch.object(op, "ROOT_UID", os.geteuid()),
                            patch.object(op, "BACKUP_ROOT", self.directory / "backups")):
            replacement.start()
            self.addCleanup(replacement.stop)
        # Avoid operational warnings obscuring test results.
        printed = patch("builtins.print")
        printed.start()
        self.addCleanup(printed.stop)

    def dump(self, deployment, path):
        self.assertTrue(deployment.maintenance)
        self.assertFalse(any(deployment.services.values()))
        with op._new_file(path) as stream:
            stream.write(gzip.compress(SQL))
        return len(SQL)

    def package(self):
        with patch.object(op, "_dump", self.dump):
            return op.backup_database(self.deployment)

    def interrupted_restore(self):
        package = self.package()
        def fail(deployment, stream, expected):
            record = op._restore_journal(deployment)
            self.assertEqual(record["state"], "pending")
            self.assertEqual(record["phase"], "importing")
            self.assertTrue((Path(record["prebackup"]) / "COMPLETE").exists())
            deployment.partial_database = True
            raise RuntimeError("simulated interrupted SQL import")
        with patch.object(op, "_dump", self.dump), patch.object(op, "_import", fail):
            with self.assertRaisesRegex(RuntimeError, "Restore is pending"):
                op.restore_database(self.deployment, package, confirmation="RESTORE cloud")
        return package, op._restore_journal(self.deployment)

    def interrupted_finalization(self):
        package = self.package()
        with patch.object(op, "_dump", self.dump), patch.object(op, "_import"), \
                patch.object(op._Paused, "resume", side_effect=SystemExit("interrupted before writer restart")):
            with self.assertRaisesRegex(RuntimeError, "Validated data will not be replayed"):
                op.restore_database(self.deployment, package, confirmation="RESTORE cloud")
        record = op._restore_journal(self.deployment)
        self.assertEqual((record["state"], record["phase"]), ("pending", "validated"))
        return package, record

    def test_pending_retry_uses_original_prebackup_without_php_or_new_backup_before_import(self):
        self.deployment.services["cron"] = False
        original = self.deployment.services.copy()
        package, record = self.interrupted_restore()
        journal = self.deployment.state / "restore.json"
        self.assertEqual(journal.stat().st_mode & 0o777, 0o600)
        self.assertEqual(record["paused"], {"maintenance": False, "services": original})
        self.assertEqual(record["source_manifest_sha256"], hashlib.sha256((package / "manifest.json").read_bytes()).hexdigest())
        self.assertNotIn("private-test", journal.read_text())
        self.assertNotIn(SQL.decode(), journal.read_text())
        # Simulate a restarted jail during an unfinished import.
        self.deployment.jid = 44
        self.deployment.services = dict.fromkeys(op.SERVICES, True)
        self.deployment.maintenance = False
        self.deployment.calls.clear()
        # Neither incomplete newer directories nor abandoned config temp files
        # can become the original pre-backup or prevent a successful replay.
        incomplete = package.parent / "999999-incomplete"
        incomplete.mkdir(mode=0o700)
        (incomplete / "database.sql.gz").write_bytes(b"partial")
        stale = self.deployment.app_config / ".cloud-restore-abandoned.tmp"
        stale.write_text("partial private config")
        imported = False
        metadata = op._metadata
        def importer(deployment, stream, expected):
            nonlocal imported
            self.assertTrue(deployment.maintenance)
            self.assertFalse(any(deployment.services.values()))
            self.assertFalse(any("/usr/local/bin/php" in args for _, args, _ in deployment.calls))
            self.assertEqual(gzip.decompress(stream.read()), SQL)
            self.assertEqual(expected, len(SQL))
            self.assertEqual(op._restore_journal(deployment), record)
            self.assertEqual({args[1] for _, args, _ in deployment.calls
                              if args[0] == "service" and args[2] == "onestop"}, set(op.SERVICES))
            deployment.partial_database = False
            imported = True
        def after_sql(deployment):
            self.assertTrue(imported, "Nextcloud metadata must not be queried before replayed SQL completes")
            return metadata(deployment)
        with patch.object(op, "_import", importer), patch.object(op, "_metadata", after_sql), \
                patch.object(op, "_snapshot") as snapshot, patch.object(op, "_dump") as dump:
            before = op.restore_database(self.deployment, package, confirmation="RESTORE cloud")
        snapshot.assert_not_called()
        dump.assert_not_called()
        self.assertEqual(before, Path(record["prebackup"]))
        self.assertEqual(self.deployment.services, original)
        self.assertFalse(self.deployment.maintenance)
        completed = op._restore_journal(self.deployment)
        self.assertEqual(completed["state"], "complete")
        self.assertEqual(completed["started"], record["started"])
        self.assertEqual(completed["paused"], record["paused"])
        self.assertFalse(stale.exists())
        self.assertTrue(incomplete.exists())
        self.assertEqual(len(list(op.BACKUP_ROOT.rglob("COMPLETE"))), 2)
        self.assertEqual(self.deployment.host_calls[-1][0], ("/usr/local/libexec/cloud-storage-guard", "cloudnc"))

    def test_retry_preserves_original_enabled_maintenance_and_mixed_stopped_services(self):
        self.deployment.maintenance = True
        self.deployment.services = {"cron": True, "apache24": False, "php_fpm": False}
        original = self.deployment.services.copy()
        package, record = self.interrupted_restore()
        self.deployment.services = dict.fromkeys(op.SERVICES, True)
        def importer(deployment, *args):
            deployment.partial_database = False
        with patch.object(op, "_import", importer):
            op.restore_database(self.deployment, package, confirmation="RESTORE cloud")
        self.assertTrue(self.deployment.maintenance)
        self.assertEqual(self.deployment.services, original)
        self.assertEqual(op._restore_journal(self.deployment)["paused"], record["paused"])

    def test_retry_requires_reconfirmation_and_repeated_failure_keeps_the_same_journal(self):
        package, record = self.interrupted_restore()
        self.deployment.calls.clear()
        with self.assertRaises(ValueError):
            op.restore_database(self.deployment, package, confirmation="RESTORE other")
        self.assertEqual(self.deployment.calls, [])
        with patch.object(op, "_import", side_effect=RuntimeError("private SQL diagnostic")), \
                patch.object(op, "_metadata") as metadata, patch.object(op, "_snapshot") as snapshot:
            with self.assertRaisesRegex(RuntimeError, "Retained pre-restore backup") as error:
                op.restore_database(self.deployment, package, confirmation="RESTORE cloud")
        self.assertNotIn("private SQL", str(error.exception))
        metadata.assert_not_called()
        snapshot.assert_not_called()
        self.assertEqual(op._restore_journal(self.deployment), record)
        self.assertTrue(self.deployment.maintenance)
        self.assertFalse(any(self.deployment.services.values()))
        self.assertFalse(any("/usr/local/bin/php" in args or "onestart" in args
                             for _, args, _ in self.deployment.calls))

    def test_retry_drain_timeout_keeps_writers_stopped_and_does_not_query_nextcloud(self):
        package, record = self.interrupted_restore()
        self.deployment.draining = True
        self.deployment.services = dict.fromkeys(op.SERVICES, True)
        self.deployment.calls.clear()
        with patch.object(op.time, "monotonic", side_effect=[0, 121, 121, 242]), \
                patch.object(op, "_metadata") as metadata, patch.object(op, "_import") as importer:
            with self.assertRaisesRegex(RuntimeError, "must remain stopped"):
                op.restore_database(self.deployment, package, confirmation="RESTORE cloud")
        metadata.assert_not_called()
        importer.assert_not_called()
        self.assertFalse(any(self.deployment.services.values()))
        self.assertEqual(op._restore_journal(self.deployment), record)
        self.assertFalse(any("/usr/local/bin/php" in args or "onestart" in args
                             for _, args, _ in self.deployment.calls))

    def test_malformed_saved_service_states_and_version_identity_do_not_enable_retry(self):
        package, record = self.interrupted_restore()
        path = self.deployment.state / "restore.json"
        for field in ("paused", "metadata", "phase", "missing-phase"):
            with self.subTest(field=field):
                changed = json.loads(json.dumps(record))
                if field == "paused":
                    changed[field]["services"]["cron"] = "true"
                elif field == "metadata":
                    changed[field]["nextcloud_version"] = "35.0.2.0"
                elif field == "phase":
                    changed[field] = "unknown"
                else:
                    del changed["phase"]  # Ambiguous legacy journals cannot authorize replay.
                op.atomic_json(path, changed)
                with patch.object(op, "_import") as importer, patch.object(op, "_metadata") as metadata:
                    with self.assertRaises(ValueError):
                        op.restore_database(self.deployment, package, confirmation="RESTORE cloud")
                importer.assert_not_called()
                metadata.assert_not_called()
                self.assertFalse(any(self.deployment.services.values()))
                op.atomic_json(path, record)

    def test_retry_rejects_code_config_database_and_guard_changes_without_import(self):
        package, record = self.interrupted_restore()
        app = self.deployment.app_config.parent
        cases = ("version.php", "core/signature.json", "apps/dav/appinfo/info.xml",
                 "custom_apps/onlyoffice/appinfo/info.xml", "custom_apps/onlyoffice/appinfo/signature.json",
                 "host-config", "database-version", "storage-guard", "jail-identity")
        for case in cases:
            with self.subTest(case=case):
                path = app / case if "/" in case or case == "version.php" else None
                old = path.read_bytes() if path else None
                if path:
                    path.write_bytes(old + b"changed version/signature marker\n")
                elif case == "host-config":
                    self.deployment.config.ssh_shell = "zsh"
                elif case == "database-version":
                    self.deployment.mariadb_version = "12.3.99-MariaDB"
                elif case == "storage-guard":
                    self.deployment.guard_failure = True
                else:
                    self.deployment.guard_replaces_jail = True
                try:
                    with patch.object(op, "_import") as importer, patch.object(op, "_metadata") as metadata, \
                            patch.object(op, "_snapshot") as snapshot, self.assertRaises((ValueError, RuntimeError)):
                        op.restore_database(self.deployment, package, confirmation="RESTORE cloud")
                    importer.assert_not_called()
                    metadata.assert_not_called()
                    snapshot.assert_not_called()
                    self.assertFalse(any(self.deployment.services.values()))
                    self.assertEqual(op._restore_journal(self.deployment), record)
                finally:
                    if path:
                        path.write_bytes(old)
                    self.deployment.config.ssh_shell = "sh"
                    self.deployment.mariadb_version = "12.3.2-MariaDB"
                    self.deployment.guard_failure = self.deployment.guard_replaces_jail = False
                    self.deployment.jid = 17

    def test_pending_restore_refuses_different_path_or_rehashed_source_and_damaged_prebackup(self):
        package, record = self.interrupted_restore()
        copied = self.directory / "copied-package"
        shutil.copytree(package, copied)
        for other in (copied, Path(record["prebackup"])):
            with self.subTest(path=other), patch.object(op, "_import") as importer:
                with self.assertRaisesRegex(ValueError, "different backup"):
                    op.restore_database(self.deployment, other, confirmation="RESTORE cloud")
                importer.assert_not_called()
        manifest = package / "manifest.json"
        original = manifest.read_bytes()
        changed = json.loads(original)
        changed["created_at"] = "different trusted package content"
        manifest.write_text(json.dumps(changed))
        (package / "COMPLETE").write_text(hashlib.sha256(manifest.read_bytes()).hexdigest() + "\n")
        with patch.object(op, "_import") as importer, self.assertRaisesRegex(ValueError, "different backup"):
            op.restore_database(self.deployment, package, confirmation="RESTORE cloud")
        importer.assert_not_called()
        manifest.write_bytes(original)
        (package / "COMPLETE").write_text(hashlib.sha256(original).hexdigest() + "\n")
        (Path(record["prebackup"]) / "COMPLETE").unlink()
        with patch.object(op, "_snapshot") as snapshot, patch.object(op, "_import") as importer:
            with self.assertRaisesRegex(ValueError, "incomplete"):
                op.restore_database(self.deployment, package, confirmation="RESTORE cloud")
        snapshot.assert_not_called()
        importer.assert_not_called()
        self.assertEqual(op._restore_journal(self.deployment), record)

    def test_pending_journal_requires_private_regular_unlinked_root_owned_state(self):
        package, _ = self.interrupted_restore()
        path = self.deployment.state / "restore.json"
        contents = path.read_bytes()
        other = self.directory / "journal-copy"
        other.write_bytes(contents)
        other.chmod(0o600)
        for kind in ("permissions", "symlink", "hardlink", "owner"):
            with self.subTest(kind=kind):
                if kind == "permissions":
                    path.chmod(0o644)
                elif kind == "symlink":
                    path.unlink()
                    path.symlink_to(other)
                elif kind == "hardlink":
                    path.unlink()
                    os.link(other, path)
                inode = path.stat().st_ino
                original_fstat = os.fstat
                def fstat(fd):
                    info = original_fstat(fd)
                    if kind == "owner" and info.st_ino == inode:
                        values = list(info)
                        values[4] = os.getuid() + 1
                        return os.stat_result(values)
                    return info
                try:
                    with patch.object(op.os, "fstat", fstat), patch.object(op, "_import") as importer:
                        with self.assertRaises((ValueError, OSError)):
                            op.restore_database(self.deployment, package, confirmation="RESTORE cloud")
                    importer.assert_not_called()
                finally:
                    path.unlink()
                    path.write_bytes(contents)
                    path.chmod(0o600)

    def test_pending_restore_blocks_backup_and_user_creation_before_jail_access(self):
        _, record = self.interrupted_restore()
        self.deployment.calls.clear()
        with self.assertRaisesRegex(RuntimeError, "restore is pending"):
            op.backup_database(self.deployment)
        with self.assertRaisesRegex(RuntimeError, "restore is pending"):
            op.create_user(self.deployment, "alice", "a-valid-password")
        self.assertEqual(self.deployment.calls, [])
        self.assertEqual(op._restore_journal(self.deployment), record)

    def test_unjournaled_partial_database_is_never_adopted(self):
        package = self.package()
        self.deployment.partial_database = True
        with patch.object(op, "_import") as importer, patch.object(op, "_snapshot") as snapshot:
            with self.assertRaises(RuntimeError):
                op.restore_database(self.deployment, package, confirmation="RESTORE cloud")
        importer.assert_not_called()
        snapshot.assert_not_called()
        self.assertFalse((self.deployment.state / "restore.json").exists())

    def test_initial_journal_write_failure_recovers_original_states_without_import(self):
        package = self.package()
        write = op.atomic_json
        def fail_after_rename(path, value):
            write(path, value)
            raise OSError("simulated journal fsync failure")
        with patch.object(op, "_dump", self.dump), patch.object(op, "atomic_json", fail_after_rename), \
                patch.object(op, "_import") as importer:
            with self.assertRaisesRegex(OSError, "fsync failure"):
                op.restore_database(self.deployment, package, confirmation="RESTORE cloud")
        importer.assert_not_called()
        self.assertFalse((self.deployment.state / "restore.json").exists())
        self.assertFalse(self.deployment.maintenance)
        self.assertTrue(all(self.deployment.services.values()))

    def test_completion_write_failure_retains_validated_phase_and_only_finalizes(self):
        write = op.atomic_json
        for renamed in (False, True):
            with self.subTest(complete_renamed_before_failure=renamed):
                package = self.package()
                def fail_complete(path, value):
                    if value["state"] == "complete":
                        self.assertTrue(all(self.deployment.services.values()))
                        self.assertFalse(self.deployment.maintenance)
                        self.assertEqual(value["phase"], "validated")
                        if renamed:
                            write(path, value)
                        raise OSError("simulated completion write failure")
                    write(path, value)
                with patch.object(op, "_dump", self.dump), patch.object(op, "_import"), \
                        patch.object(op, "atomic_json", fail_complete), self.assertRaisesRegex(RuntimeError, "pending"):
                    op.restore_database(self.deployment, package, confirmation="RESTORE cloud")
                pending = op._restore_journal(self.deployment)
                self.assertEqual((pending["state"], pending["phase"]), ("pending", "validated"))
                self.assertTrue(self.deployment.maintenance)
                self.assertFalse(any(self.deployment.services.values()))
                self.deployment.calls.clear()
                with patch.object(op, "_import") as importer, patch.object(op, "_restore_config") as config, \
                        patch.object(op, "_snapshot") as snapshot:
                    before = op.restore_database(self.deployment, package, confirmation="RESTORE cloud")
                importer.assert_not_called()
                config.assert_not_called()
                snapshot.assert_not_called()
                self.assertFalse(any("FLUSHDB" in args or "maintenance:data-fingerprint" in args
                                     for _, args, _ in self.deployment.calls))
                self.assertEqual(before, Path(pending["prebackup"]))
                self.assertTrue(all(self.deployment.services.values()))
                self.assertFalse(self.deployment.maintenance)
                completed = op._restore_journal(self.deployment)
                self.assertEqual((completed["state"], completed["phase"]), ("complete", "validated"))

    def test_controller_interruption_after_first_writer_start_preserves_new_dav_writes_on_retry(self):
        self.deployment.services["cron"] = False
        original = self.deployment.services.copy()
        package = self.package()
        dav_records = []
        current_config = self.deployment.app_config / "post-restore.config.php"
        jail = self.deployment.jail
        def importer(*args):
            dav_records[:] = ["backed-up contact"]
        def interrupt_writer(name, *args, **kwargs):
            if "--off" in args or "onestart" in args:
                record = op._restore_journal(self.deployment)
                self.assertEqual((record["state"], record["phase"]), ("pending", "validated"))
            result = jail(name, *args, **kwargs)
            if "onestart" in args:
                self.assertEqual(sum(self.deployment.services.values()), 1)
                dav_records.append("new post-restore calendar event")
                current_config.write_text("<?php $CONFIG=['post_restore_setting'=>'preserve-me'];\n")
                raise SystemExit("simulated controller interruption after the first writer started")
            return result
        with patch.object(op, "_dump", self.dump), patch.object(op, "_import", importer), \
                patch.object(self.deployment, "jail", interrupt_writer):
            with self.assertRaisesRegex(RuntimeError, "Validated data will not be replayed"):
                op.restore_database(self.deployment, package, confirmation="RESTORE cloud")
        pending = op._restore_journal(self.deployment)
        self.assertEqual(pending["phase"], "validated")
        self.assertTrue(self.deployment.maintenance)
        self.assertFalse(any(self.deployment.services.values()))
        self.assertTrue(current_config.exists(), "Failure cleanup must not restore the archived config")
        # Model changed JID/status before retry; this does not perform a reboot.
        self.deployment.jid = 44
        self.deployment.services = dict.fromkeys(op.SERVICES, True)
        self.deployment.maintenance = False
        self.deployment.calls.clear()
        metadata = op._metadata
        def current_metadata(deployment):
            self.assertFalse(any(deployment.services.values()))
            self.assertFalse(deployment.maintenance)
            self.assertEqual(dav_records, ["backed-up contact", "new post-restore calendar event"])
            return metadata(deployment)
        with patch.object(op, "_import") as imported, patch.object(op, "_restore_config") as config, \
                patch.object(op, "_snapshot") as snapshot, patch.object(op, "_metadata", current_metadata):
            before = op.restore_database(self.deployment, package, confirmation="RESTORE cloud")
        imported.assert_not_called()
        config.assert_not_called()
        snapshot.assert_not_called()
        self.assertFalse(any("FLUSHDB" in args or "maintenance:data-fingerprint" in args
                             for _, args, _ in self.deployment.calls))
        self.assertEqual(dav_records, ["backed-up contact", "new post-restore calendar event"])
        self.assertIn("preserve-me", current_config.read_text())
        self.assertEqual(self.deployment.services, original)
        self.assertFalse(self.deployment.maintenance)
        self.assertEqual(before, Path(pending["prebackup"]))
        self.assertEqual(op._restore_journal(self.deployment)["state"], "complete")

    def test_validated_checkpoint_write_failure_obeys_the_visible_phase_without_starting_writers(self):
        write = op.atomic_json
        for renamed in (False, True):
            with self.subTest(validated_renamed_before_failure=renamed):
                package = self.package()
                self.deployment.calls.clear()
                def fail_validated(path, value):
                    if value["phase"] == "validated":
                        self.assertTrue(self.deployment.maintenance)
                        self.assertFalse(any(self.deployment.services.values()))
                        if renamed:
                            write(path, value)
                        raise OSError("simulated validated checkpoint fsync failure")
                    write(path, value)
                with patch.object(op, "_dump", self.dump), patch.object(op, "_import"), \
                        patch.object(op, "_restore_config", wraps=op._restore_config) as config, \
                        patch.object(op, "atomic_json", fail_validated):
                    with self.assertRaisesRegex(RuntimeError, "Restore is pending"):
                        op.restore_database(self.deployment, package, confirmation="RESTORE cloud")
                if renamed:
                    self.assertEqual(config.call_count, 1, "Visible validated checkpoint forbids config replay even during cleanup")
                self.assertFalse(any("onestart" in args or "--off" in args for _, args, _ in self.deployment.calls))
                self.assertFalse(any(self.deployment.services.values()))
                self.assertEqual(op._restore_journal(self.deployment)["phase"], "validated" if renamed else "importing")
                self.deployment.calls.clear()
                with patch.object(op, "_import") as importer, patch.object(op, "_restore_config") as config:
                    op.restore_database(self.deployment, package, confirmation="RESTORE cloud")
                if renamed:
                    importer.assert_not_called()
                    config.assert_not_called()
                    self.assertFalse(any("FLUSHDB" in args or "maintenance:data-fingerprint" in args
                                         for _, args, _ in self.deployment.calls))
                else:
                    importer.assert_called_once()
                    config.assert_called_once()
                self.assertEqual(op._restore_journal(self.deployment)["state"], "complete")

    def test_validated_retry_requires_a_durable_checkpoint_before_resuming_writers(self):
        self.deployment.maintenance = True
        self.deployment.services = {"cron": True, "apache24": False, "php_fpm": False}
        original = self.deployment.services.copy()
        package, pending = self.interrupted_finalization()
        self.deployment.calls.clear()
        with patch.object(op, "atomic_json", side_effect=OSError("checkpoint cannot be fsynced")), \
                patch.object(op, "_import") as importer, patch.object(op, "_restore_config") as config:
            with self.assertRaisesRegex(RuntimeError, "Validated data will not be replayed"):
                op.restore_database(self.deployment, package, confirmation="RESTORE cloud")
        importer.assert_not_called()
        config.assert_not_called()
        self.assertFalse(any("onestart" in args for _, args, _ in self.deployment.calls))
        self.assertFalse(any(self.deployment.services.values()))
        self.assertEqual(op._restore_journal(self.deployment), pending)
        with patch.object(op, "_import") as importer, patch.object(op, "_restore_config") as config:
            op.restore_database(self.deployment, package, confirmation="RESTORE cloud")
        importer.assert_not_called()
        config.assert_not_called()
        self.assertTrue(self.deployment.maintenance)
        self.assertEqual(self.deployment.services, original)

    def test_validated_retry_with_unhealthy_php_or_changed_schema_stays_stopped_without_replay(self):
        package, pending = self.interrupted_finalization()
        current_config = self.deployment.app_config / "post-restore.config.php"
        current_config.write_text("<?php $CONFIG=['post_restore_setting'=>'preserve-me'];\n")
        jail = self.deployment.jail
        for failure in ("php", "schema", "runtime-identity", "php-during-resume"):
            with self.subTest(failure=failure):
                self.deployment.services = dict.fromkeys(op.SERVICES, True)
                self.deployment.maintenance = False
                self.deployment.calls.clear()
                self.deployment.partial_database = failure == "php"
                self.deployment.tables = sorted(TABLES + [["oc_unexpected", "BASE TABLE", "InnoDB"]]) if failure == "schema" else TABLES
                self.deployment.instance_id = "different-instance" if failure == "runtime-identity" else "ocExample123"
                def fail_php(name, *args, **kwargs):
                    if failure == "php-during-resume" and "--off" in args:
                        self.deployment.partial_database = True
                    return jail(name, *args, **kwargs)
                with patch.object(op, "_import") as importer, patch.object(op, "_restore_config") as config, \
                        patch.object(self.deployment, "jail", fail_php):
                    with self.assertRaisesRegex(RuntimeError, "maintenance mode could not be confirmed"):
                        op.restore_database(self.deployment, package, confirmation="RESTORE cloud")
                importer.assert_not_called()
                config.assert_not_called()
                self.assertFalse(any(self.deployment.services.values()))
                self.assertEqual(op._restore_journal(self.deployment), pending)
                self.assertIn("preserve-me", current_config.read_text())
                self.assertFalse(any("onestart" in args or "FLUSHDB" in args or "maintenance:data-fingerprint" in args
                                     for _, args, _ in self.deployment.calls))

    def test_backup_captures_all_schema_and_config_then_restores_prior_states(self):
        self.deployment.services["cron"] = False
        self.deployment.maintenance = True
        before = self.deployment.services.copy()
        package = self.package()
        self.assertTrue(self.deployment.maintenance)
        self.assertEqual(self.deployment.services, before)
        self.assertNotIn(self.deployment.state, package.parents)
        with op._read_package(package) as (manifest, config, sql, _):
            self.assertEqual(manifest["metadata"]["tables"], TABLES)
            self.assertFalse(manifest["includes_user_files"])
            self.assertIn(b"private-test", config["config.php"])
            self.assertEqual(gzip.decompress(sql.read()), SQL)
        for path in package.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(package.stat().st_mode & 0o777, 0o700)

    def test_dump_failure_never_publishes_and_restores_services_and_maintenance(self):
        def fail(deployment, path):
            with op._new_file(path) as stream:
                stream.write(b"partial")
            raise RuntimeError("dump failed")
        with patch.object(op, "_dump", fail), self.assertRaisesRegex(RuntimeError, "dump failed"):
            op.backup_database(self.deployment)
        self.assertFalse(self.deployment.maintenance)
        self.assertTrue(all(self.deployment.services.values()))
        self.assertEqual(list(op.BACKUP_ROOT.rglob("COMPLETE")), [])
        self.assertEqual(len(list(op.BACKUP_ROOT.rglob("database.sql.gz"))), 1)

    def test_service_stop_failure_recovers_exact_state(self):
        self.deployment.fail_stop = "php_fpm"
        self.deployment.services["cron"] = False
        before = self.deployment.services.copy()
        with patch.object(op, "_dump") as dump, self.assertRaises(RuntimeError):
            op.backup_database(self.deployment)
        dump.assert_not_called()
        self.assertEqual(self.deployment.services, before)
        self.assertFalse(self.deployment.maintenance)

    def test_cron_children_must_drain_before_a_dump(self):
        self.deployment.draining = True
        with patch.object(op.time, "monotonic", side_effect=[0, 121]), \
                patch.object(op, "_dump") as dump, self.assertRaisesRegex(RuntimeError, "drain"):
            op.backup_database(self.deployment)
        dump.assert_not_called()
        self.assertTrue(all(self.deployment.services.values()))

    def test_nontransactional_or_missing_groupware_schema_is_rejected(self):
        for bad_tables in (TABLES[:-1], [["oc_users", "BASE TABLE", "MyISAM"]]):
            self.deployment.tables = bad_tables
            with patch.object(op, "_dump") as dump, self.assertRaises(ValueError):
                op.backup_database(self.deployment)
            dump.assert_not_called()
            self.assertFalse(self.deployment.maintenance)

    def test_backup_guard_excludes_a_second_operation(self):
        with op._database_guard(self.deployment), self.assertRaisesRegex(RuntimeError, "already running"):
            op.backup_database(self.deployment)

    def test_backup_output_cannot_be_removed_with_instance_or_overwrite_anything(self):
        for path in (self.deployment.state / "backup", Path(self.deployment.config.mount_root) / "backup",
                     self.deployment.root / "backup", self.directory):
            with self.subTest(path=path), patch.object(op, "_dump", self.dump), self.assertRaises((ValueError, FileExistsError)):
                op.backup_database(self.deployment, path)
        self.assertFalse(self.deployment.maintenance)

    def test_symlinked_config_is_rejected_and_no_complete_marker_is_written(self):
        (self.deployment.app_config / "linked.config.php").symlink_to(self.deployment.app_config / "config.php")
        with patch.object(op, "_dump", self.dump), self.assertRaisesRegex(ValueError, "symlinks"):
            op.backup_database(self.deployment)
        self.assertEqual(list(op.BACKUP_ROOT.rglob("COMPLETE")), [])

    def test_restore_requires_exact_confirmation_before_any_commands(self):
        with self.assertRaises(ValueError):
            op.restore_database(self.deployment, "/does/not/exist", confirmation="RESTORE other")
        self.assertEqual(self.deployment.calls, [])

    def test_restore_validates_corruption_permissions_links_and_completeness_before_stop(self):
        for alteration in ("checksum", "permissions", "symlink", "hardlink", "incomplete"):
            with self.subTest(alteration=alteration):
                package = self.package()
                sql = package / "database.sql.gz"
                if alteration == "checksum":
                    sql.write_bytes(b"corrupt")
                elif alteration == "permissions":
                    sql.chmod(0o644)
                elif alteration == "symlink":
                    sql.unlink()
                    sql.symlink_to(package / "manifest.json")
                elif alteration == "hardlink":
                    os.link(sql, self.directory / "hardlink")
                else:
                    (package / "COMPLETE").unlink()
                self.deployment.calls.clear()
                with patch.object(op, "_import") as importer, self.assertRaises((ValueError, OSError)):
                    op.restore_database(self.deployment, package, confirmation="RESTORE cloud")
                importer.assert_not_called()
                self.assertEqual(self.deployment.calls, [])

    def test_wrong_instance_and_versions_fail_without_stopping_services(self):
        package = self.package()
        for attribute, changed, message in (("instance_id", "another-instance", "does not match"),
                                            ("nextcloud_version", "35.0.2.0", "locked version"),
                                            ("mariadb_version", "12.3.3-MariaDB", "retained version lock")):
            previous = getattr(self.deployment, attribute)
            setattr(self.deployment, attribute, changed)
            self.deployment.calls.clear()
            with patch.object(op, "_import") as importer, self.assertRaisesRegex(ValueError, message):
                op.restore_database(self.deployment, package, confirmation="RESTORE cloud")
            importer.assert_not_called()
            self.assertFalse(any("onestop" in args for _, args, _ in self.deployment.calls))
            setattr(self.deployment, attribute, previous)

    def test_backup_rejects_application_or_database_drift_before_stopping_writers(self):
        for attribute, version in (("nextcloud_version", "35.0.0.0"), ("nextcloud_version", "35.0.2.0"),
                                   ("mariadb_version", "12.3.1-MariaDB"), ("mariadb_version", "12.3.3-MariaDB")):
            with self.subTest(attribute=attribute, version=version):
                original = getattr(self.deployment, attribute)
                setattr(self.deployment, attribute, version)
                self.deployment.calls.clear()
                try:
                    with patch.object(op, "_dump") as dump, self.assertRaises(ValueError):
                        op.backup_database(self.deployment)
                    dump.assert_not_called()
                    self.assertFalse(any("onestop" in args or "maintenance:mode" in args or "upgrade" in args
                                         for _, args, _ in self.deployment.calls))
                    self.assertTrue(all(self.deployment.services.values()))
                finally:
                    setattr(self.deployment, attribute, original)

    def test_restore_rejects_a_changed_public_port_before_stopping_services(self):
        package = self.package()
        self.deployment.config.public_url = "https://cloud.example.test:8443/"
        self.deployment.calls.clear()
        with self.assertRaisesRegex(ValueError, "different instance"):
            op.restore_database(self.deployment, package, confirmation="RESTORE cloud")
        self.assertFalse(any("onestop" in args for _, args, _ in self.deployment.calls))

    def test_restore_retains_fresh_prebackup_and_refreshes_fingerprint(self):
        package = self.package()
        self.deployment.services["cron"] = False
        before = self.deployment.services.copy()
        observed = []
        def importer(deployment, stream, expected):
            self.assertTrue(deployment.maintenance)
            self.assertFalse(any(deployment.services.values()))
            observed.append(gzip.decompress(stream.read()))
            self.assertEqual(expected, len(SQL))
            self.assertEqual(len(list(op.BACKUP_ROOT.rglob("COMPLETE"))), 2)
        with patch.object(op, "_dump", self.dump), patch.object(op, "_import", importer), patch.object(op.os, "fchown"):
            before_path = op.restore_database(self.deployment, package, confirmation="RESTORE cloud")
        self.assertNotEqual(package, before_path)
        self.assertTrue((before_path / "COMPLETE").exists())
        self.assertEqual(op._restore_journal(self.deployment)["state"], "complete")
        self.assertEqual(observed, [SQL])
        self.assertEqual(self.deployment.services, before)
        self.assertFalse(self.deployment.maintenance)
        commands = [args for _, args, _ in self.deployment.calls]
        self.assertTrue(any("maintenance:data-fingerprint" in args for args in commands))
        self.assertTrue(any("integrity:check-core" in args for args in commands))
        self.assertFalse(any("files:scan" in args or "upgrade" in args for args in commands))

    def test_mid_import_failure_never_runs_occ_or_restarts_writers(self):
        package = self.package()
        def importer(*args):
            self.deployment.calls.clear()
            raise RuntimeError("private SQL diagnostic")
        with patch.object(op, "_dump", self.dump), patch.object(op, "_import", importer):
            with self.assertRaisesRegex(RuntimeError, "Retained pre-restore backup") as error:
                op.restore_database(self.deployment, package, confirmation="RESTORE cloud")
        self.assertNotIn("private SQL", str(error.exception))
        self.assertFalse(any("/usr/local/bin/php" in args or "onestart" in args
                             for _, args, _ in self.deployment.calls))
        self.assertTrue(self.deployment.maintenance)
        self.assertFalse(any(self.deployment.services.values()))
        self.assertEqual(len(list(op.BACKUP_ROOT.rglob("COMPLETE"))), 2)

    def test_prebackup_failure_is_nondestructive_and_resumes_application(self):
        package = self.package()
        with patch.object(op, "_dump", side_effect=RuntimeError("disk full")), patch.object(op, "_import") as importer:
            with self.assertRaisesRegex(RuntimeError, "disk full"):
                op.restore_database(self.deployment, package, confirmation="RESTORE cloud")
        importer.assert_not_called()
        self.assertFalse(self.deployment.maintenance)
        self.assertTrue(all(self.deployment.services.values()))
        self.assertFalse((self.deployment.state / "restore.json").exists())

    def test_post_import_failure_also_leaves_application_paused(self):
        package = self.package()
        self.deployment.fail_fingerprint = True
        with patch.object(op, "_dump", self.dump), patch.object(op, "_import"), patch.object(op.os, "fchown"):
            with self.assertRaisesRegex(RuntimeError, "remain stopped"):
                op.restore_database(self.deployment, package, confirmation="RESTORE cloud")
        self.assertTrue(self.deployment.maintenance)
        self.assertFalse(any(self.deployment.services.values()))

    def test_failed_writer_restart_returns_to_maintenance_with_prebackup_report(self):
        package = self.package()
        self.deployment.fail_start = "apache24"
        with patch.object(op, "_dump", self.dump), patch.object(op, "_import"), patch.object(op.os, "fchown"):
            with self.assertRaisesRegex(RuntimeError, "Retained pre-restore backup"):
                op.restore_database(self.deployment, package, confirmation="RESTORE cloud")
        self.assertTrue(self.deployment.maintenance)
        self.assertFalse(any(self.deployment.services.values()))

    def test_archive_validation_rejects_traversal_links_and_duplicate_members(self):
        for names, link in ((["../config.php"], False), (["/config.php"], False),
                            (["config.php", "config.php/child"], False),
                            (["config.php", "config.php"], False), (["config.php"], True)):
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode="w:gz") as archive:
                for name in names:
                    member = tarfile.TarInfo(name)
                    if link:
                        member.type, member.linkname = tarfile.SYMTYPE, "/etc/master.passwd"
                        archive.addfile(member)
                    else:
                        member.size = 3
                        archive.addfile(member, io.BytesIO(b"PHP"))
            with self.assertRaises(ValueError):
                op._read_config_archive(data)

    def test_streaming_checks_child_exit_jail_identity_and_whole_database_flags(self):
        original = subprocess.Popen
        commands = []
        def child(args, **kwargs):
            commands.append(args)
            return original([sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x'*1048576)"], **kwargs)
        output = self.directory / "stream.gz"
        with patch.object(op.subprocess, "Popen", child):
            self.assertEqual(op._dump(self.deployment, output), 1048576)
        self.assertEqual(len(gzip.decompress(output.read_bytes())), 1048576)
        self.assertEqual(commands[0][:4], ["/usr/sbin/jexec", "-U", "root", "17"])
        self.assertEqual(commands[0][-1], "nextcloud")
        for flag in ("--single-transaction", "--routines", "--events", "--triggers", "--hex-blob", "--default-character-set=utf8mb4"):
            self.assertIn(flag, commands[0])
        self.assertNotIn("--tables", commands[0])
        def failed_child(args, **kwargs):
            return original([sys.executable, "-c", "import sys; print('partial'); sys.exit(4)"], **kwargs)
        with patch.object(op.subprocess, "Popen", failed_child), self.assertRaisesRegex(RuntimeError, "stream failed"):
            op._dump(self.deployment, self.directory / "failed.gz")
        with patch.object(op.subprocess, "Popen", child), \
                patch.object(self.deployment, "require_running_jail", side_effect=[17, 18]), \
                self.assertRaisesRegex(RuntimeError, "changed identity"):
            op._dump(self.deployment, self.directory / "changed.gz")

    def test_stream_import_disables_logging_then_replaces_database_using_stdin(self):
        original = subprocess.Popen
        received = self.directory / "received.sql"
        commands = []
        def child(args, **kwargs):
            commands.append(args)
            code = "import sys; from pathlib import Path; Path(sys.argv[1]).write_bytes(sys.stdin.buffer.read())"
            return original([sys.executable, "-c", code, str(received)], **kwargs)
        with patch.object(op.subprocess, "Popen", child):
            op._import(self.deployment, io.BytesIO(gzip.compress(SQL)), len(SQL))
        text = received.read_bytes()
        self.assertLess(text.index(b"sql_log_bin=0"), text.index(b"DROP DATABASE"))
        self.assertLess(text.index(b"DROP DATABASE"), text.index(b"CREATE DATABASE"))
        self.assertTrue(text.endswith(SQL))
        self.assertIn("--binary-mode", commands[0])
        self.assertIn("--skip-reconnect", commands[0])
        self.assertNotIn("nextcloud", commands[0])  # A killed DROP may have left no database to select.
        self.assertIn(b"DROP DATABASE IF EXISTS `nextcloud`", text)
        self.assertNotIn("DROP DATABASE", repr(commands))

    def test_stalled_stream_is_killed_and_reaped(self):
        original = subprocess.Popen
        children = []
        def child(args, **kwargs):
            process = original([sys.executable, "-c", "import time; time.sleep(60)"], **kwargs)
            children.append(process)
            return process
        with patch.object(op.subprocess, "Popen", child), patch.object(op, "STREAM_TIMEOUT", 0.02):
            with self.assertRaisesRegex(RuntimeError, "timed out"):
                op._dump(self.deployment, self.directory / "stalled.gz")
        self.assertIsNotNone(children[0].returncode)

    def test_user_secret_is_only_stdin_and_no_admin_group_is_requested(self):
        secret = 'private password $;"\\\' <&>'
        before = {path.name: path.read_bytes() for path in self.deployment.state.iterdir()}
        result = op.create_user(self.deployment, "alice", secret, "Alice Example", "alice@example.test")
        self.assertEqual(result, {"created": "alice", "admin": False})
        sent = next(kwargs["input"] for _, args, kwargs in self.deployment.calls if args[-1] == "create-user")
        self.assertEqual(json.loads(sent)["password"], secret)
        self.assertNotIn(secret, repr([args for _, args, _ in self.deployment.calls]))
        self.assertNotIn("group", sent)
        self.assertEqual({path.name: path.read_bytes() for path in self.deployment.state.iterdir()}, before)

    def test_user_validation_precedes_jail_access(self):
        for username, password in (("--admin", "x" * 14), ("normal", "short"), ("normal", "x" * 14 + "\n")):
            with self.assertRaises(ValueError):
                op.create_user(self.deployment, username, password)
        self.assertEqual(self.deployment.calls, [])

    def test_ssh_is_opt_in_and_only_public_input_is_sent_to_both_jails(self):
        op.configure_ssh(self.deployment)
        self.assertEqual(self.deployment.calls, [])
        key = self.directory / "operator.pub"
        key.write_text(PUBLIC_KEY)
        key.chmod(0o644)
        self.deployment.config.jail_ssh = True
        self.deployment.config.ssh_key_file = str(key)
        op.configure_ssh(self.deployment)
        self.assertEqual([name for name, _, _ in self.deployment.calls], ["cloudnc", "cloudoo"])
        for _, args, kwargs in self.deployment.calls:
            self.assertEqual(args, ("/bin/sh", "/root/cloud-installer/resources/jails/ssh.sh"))
            self.assertEqual(set(json.loads(kwargs["input"])), {"username", "shell", "public_key", "admin"})
            self.assertFalse(json.loads(kwargs["input"])["admin"])
        self.deployment.config.ssh_admin = True
        op.configure_ssh(self.deployment)
        self.assertTrue(json.loads(self.deployment.calls[-1][2]["input"])["admin"])
        self.deployment.config.ssh_username = "operator"
        with self.assertRaisesRegex(ValueError, "non-system"):
            op.configure_ssh(self.deployment)

    def test_public_key_parser_refuses_options_private_keys_and_multiple_keys(self):
        for key in ("-----BEGIN OPENSSH PRIVATE KEY-----", 'command="id" ' + PUBLIC_KEY,
                    PUBLIC_KEY + PUBLIC_KEY, "ssh-ed25519 !!!", "ssh-rsa " + base64.b64encode(KEY_BLOB).decode()):
            with self.assertRaises(ValueError):
                op._public_key(key)


class WorkerTests(unittest.TestCase):
    @staticmethod
    def ssh_library():
        worker = ROOT / "resources/jails/ssh.sh"
        code = worker.read_text().split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
        namespace = {"__name__": "offline_test"}
        exec(compile(ast.parse(code), str(worker), "exec"), namespace)
        return namespace

    def test_ssh_shell_syntax_and_embedded_python(self):
        worker = ROOT / "resources/jails/ssh.sh"
        subprocess.run(["sh", "-n", str(worker)], check=True, capture_output=True)
        namespace = self.ssh_library()
        user, shell, key, admin = namespace["validate"]({
            "username": "cloudop", "shell": "zsh", "public_key": op._public_key(PUBLIC_KEY), "admin": False})
        self.assertEqual((user, shell), ("cloudop", "zsh"))
        self.assertFalse(admin)
        config = namespace["sshd_config"](user, ["Subsystem sftp /usr/libexec/sftp-server"])
        self.assertIn("AuthenticationMethods publickey\n", config)
        self.assertIn("PermitRootLogin no\n", config)
        self.assertIn("DisableForwarding yes\n", config)
        self.assertIn("Subsystem sftp /usr/libexec/sftp-server\n", config)
        self.assertIn("HIST_IGNORE_SPACE", namespace["ZSHRC"])
        self.assertIn("permit nopass cloudop as root\n", namespace["doas_policy"](user, True))
        self.assertNotIn("permit", namespace["doas_policy"](user, False))
        with self.assertRaises(ValueError):
            namespace["validate"]({"username": "operator", "shell": "sh", "public_key": key, "admin": False})
        with self.assertRaises(ValueError):
            namespace["validate"]({"username": user, "shell": shell, "public_key": key, "admin": "yes"})

    def test_doas_grant_and_revocation_are_verified_and_foreign_policy_is_refused(self):
        namespace = self.ssh_library()
        with tempfile.TemporaryDirectory(prefix="doas-policy-") as temporary:
            directory = Path(temporary)
            policy = directory / "doas.conf"
            calls = []
            granted = False
            def run(*args, **kwargs):
                calls.append(args)
                if args[0] == "mdo":
                    return SimpleNamespace(returncode=0 if granted else 1, stdout="0\n" if granted else "")
                return SimpleNamespace(returncode=0, stdout="")
            def write(fd, name, text):
                nonlocal granted
                granted = text == namespace["doas_policy"]("cloudop", True)
                policy.write_text(text)
            original_exists = Path.exists
            with patch.dict(namespace, {"STATE": directory, "DOAS": policy, "run": run,
                                        "read_root": lambda path: path.read_text(), "write_at": write,
                                        "root_directory": lambda path: None}), \
                    patch.object(Path, "exists", lambda path: path == Path("/usr/local/bin/doas") or original_exists(path)):
                namespace["configure_doas"]("cloudop", False, False)
                self.assertFalse(policy.exists())
                self.assertEqual(calls, [])
                namespace["configure_doas"]("cloudop", True, False)
                self.assertTrue(granted)
                self.assertEqual(calls[-1], ("mdo", "-u", "cloudop", "/usr/local/bin/doas", "-n", "/usr/bin/id", "-u"))
                namespace["configure_doas"]("cloudop", False, True)
                self.assertFalse(granted)
                policy.write_text("permit nopass :wheel as root\n")
                calls.clear()
                with self.assertRaisesRegex(ValueError, "unmanaged"):
                    namespace["configure_doas"]("cloudop", True, True)
                self.assertEqual(calls, [])

    @unittest.skipUnless(shutil.which("php"), "PHP CLI is needed for offline helper validation")
    def test_php_user_registration_execution_credentials_and_output(self):
        # Execute the real helper with isolated NC/Symfony doubles. Registration
        # models NC35's global-only binding; no Nextcloud installation is loaded.
        script = r'''
namespace Symfony\Component\Console\Input {
    class ArrayInput {
        public bool $interactive = true;
        public function __construct(public array $parameters) {}
        public function setInteractive(bool $value): void { $this->interactive = $value; }
    }
}
namespace Symfony\Component\Console\Output {
    interface OutputInterface { const VERBOSITY_QUIET = 16; }
    interface ConsoleOutputInterface extends OutputInterface {}
    class ConsoleOutput implements ConsoleOutputInterface {
        private object $error;
        public function __construct($verbosity = null) {
            $this->error = new class {
                public function writeln($message, $options = null): void {
                    fwrite(STDERR, $message . "\n");
                }
            };
        }
        public function setErrorOutput($output): void { $this->error = $output; }
        public function getErrorOutput(): object { return $this->error; }
        public function writeln($message, $options = null): void {
            // Explicit QUIET-level writes survive quiet verbosity in Symfony.
            $this->doWrite($message, true);
        }
        protected function doWrite(string $message, bool $newline): void {
            fwrite(STDOUT, $message . ($newline ? "\n" : ''));
        }
    }
    class NullOutput {
        public function writeln($message, $options = null): void {}
    }
}
namespace OCP {
    class Server {
        public static function get($class): object { return $GLOBALS['services'][$class]; }
    }
}
namespace OC\Console {
    class Application {
        public function loadCommands($input, $output): void {
            \recordEvent('register', $input);
            \emitPrivateOutput($output);
            if ($input->parameters !== []) {
                throw new \InvalidArgumentException('Command options cannot bind globally');
            }
            if ($GLOBALS['mode'] === 'registration-throws') {
                throw new \RuntimeException('Private registration diagnostic');
            }
        }
        public function setAutoExit($value): void {
            \recordEvent('auto-exit');
            $GLOBALS['auto_exit'] = $value;
        }
        public function run($input, $output): int {
            \recordEvent('run', $input);
            \emitPrivateOutput($output);
            // Simulate a plugin copying the in-process credential. The helper
            // must clear these copies as well as getenv on every run exit.
            $_ENV['OC_PASS'] = $_SERVER['OC_PASS'] = getenv('OC_PASS');
            $_ENV['NC_PASS'] = $_SERVER['NC_PASS'] = 'plugin-copy';
            if ($GLOBALS['mode'] === 'run-throws') {
                throw new \RuntimeException($GLOBALS['account']['password']);
            }
            return $GLOBALS['mode'] === 'nonzero' ? 1 : 0;
        }
    }
}
namespace {
    function recordEvent(string $phase, $input = null): void {
        $GLOBALS['events'][] = [
            'phase' => $phase,
            'options' => $input?->parameters,
            'interactive' => $input?->interactive,
            'password_visible' => getenv('OC_PASS') === $GLOBALS['account']['password'],
            'password_absent' => getenv('OC_PASS') === false,
            'nc_password_absent' => getenv('NC_PASS') === false,
            'copies_absent' => !isset($_ENV['OC_PASS']) && !isset($_SERVER['OC_PASS'])
                && !isset($_ENV['NC_PASS']) && !isset($_SERVER['NC_PASS']),
            'argv_private' => !in_array($GLOBALS['account']['password'], $GLOBALS['argv'], true)
                && !in_array($GLOBALS['account']['password'], $_SERVER['argv'], true),
        ];
    }
    function emitPrivateOutput($output): void {
        $output->writeln($GLOBALS['account']['password'],
            \Symfony\Component\Console\Output\OutputInterface::VERBOSITY_QUIET);
        $output->getErrorOutput()->writeln($GLOBALS['account']['password'],
            \Symfony\Component\Console\Output\OutputInterface::VERBOSITY_QUIET);
    }
    define('CLOUD_OPERATIONS_LIBRARY', true);
    require $argv[1];
    $payload = json_decode(stream_get_contents(STDIN), true, 8, JSON_THROW_ON_ERROR);
    $account = cloudOperationsUser($payload['account']);
    $mode = $payload['mode'];
    $events = [];
    $services = [
        'OCP\IConfig' => new class {
            public function getSystemValueBool($key, $default): bool { return false; }
        },
        'OC\Console\Application' => new \OC\Console\Application(),
        'OCP\IUserManager' => new class {
            public function userExists($uid): bool {
                recordEvent('exists');
                return $uid === $GLOBALS['account']['username'] && $GLOBALS['mode'] !== 'missing';
            }
        },
        'OCP\IGroupManager' => new class {
            public function isAdmin($uid): bool {
                recordEvent('admin');
                return $GLOBALS['mode'] === 'admin';
            }
        },
    ];
    recordEvent('before');
    $result = null;
    $caught = false;
    try { $result = cloudOperationsCreate($account); }
    catch (\Throwable $error) { $caught = true; }
    recordEvent('after');
    echo json_encode(['result' => $result, 'caught' => $caught, 'events' => $events,
        'auto_exit' => $auto_exit ?? null], JSON_THROW_ON_ERROR);
}
'''
        account = {"username": "alice", "password": 'private password $;"\' <&>',
                   "display_name": "Alice Example", "email": "alice@example.test"}
        worker = ROOT / "resources/jails/maintenance.php"
        environment = {key: value for key, value in os.environ.items() if key not in ("OC_PASS", "NC_PASS")}
        for mode in ("success", "run-throws", "nonzero", "missing", "admin", "registration-throws"):
            for optional in (True, False):
                with self.subTest(mode=mode, optional=optional):
                    value = dict(account, display_name=account["display_name"] if optional else "",
                                 email=account["email"] if optional else "")
                    process = subprocess.run(["php", "-r", script, str(worker)],
                                             input=json.dumps({"account": value, "mode": mode}),
                                             env=environment, text=True, capture_output=True)
                    self.assertEqual(process.returncode, 0, process.stderr)
                    self.assertEqual(process.stderr, "")
                    self.assertNotIn(account["password"], process.stdout)
                    observed = json.loads(process.stdout)  # Any raw stdout also fails.
                    self.assertEqual(observed["caught"], mode != "success")
                    self.assertEqual(observed["result"], {"created": "alice", "admin": False}
                                     if mode == "success" else None)
                    phases = ["before", "register"]
                    if mode != "registration-throws":
                        phases += ["auto-exit", "run"]
                        self.assertIs(observed["auto_exit"], False)
                        if mode in ("success", "missing", "admin"):
                            phases += ["exists"]
                        if mode in ("success", "admin"):
                            phases += ["admin"]
                    self.assertEqual([event["phase"] for event in observed["events"]], phases + ["after"])
                    expected = {"command": "user:add", "uid": "alice", "--password-from-env": True,
                                "--no-interaction": True, "--quiet": True}
                    if optional:
                        expected.update({"--display-name": value["display_name"], "--email": value["email"]})
                    for event in observed["events"]:
                        running = event["phase"] == "run"
                        self.assertEqual(event["password_visible"], running)
                        self.assertEqual(event["password_absent"], not running)
                        self.assertTrue(event["nc_password_absent"])
                        self.assertTrue(event["copies_absent"])
                        self.assertTrue(event["argv_private"])
                        if event["phase"] in ("register", "run"):
                            self.assertIs(event["interactive"], False)
                            self.assertEqual(event["options"], expected if running else [])

    @unittest.skipUnless(shutil.which("php"), "PHP CLI is needed for offline helper validation")
    def test_php_syntax_and_library_validation_keep_credentials_out_of_diagnostics(self):
        worker = ROOT / "resources/jails/maintenance.php"
        subprocess.run(["php", "-l", str(worker)], check=True, capture_output=True)
        script = ("define('CLOUD_OPERATIONS_LIBRARY', true); require $argv[1]; "
                  "$v=json_decode(stream_get_contents(STDIN), true); "
                  "try { cloudOperationsUser($v); echo 'valid'; } "
                  "catch (Throwable $e) { echo 'invalid'; exit(1); }")
        payload = {"username": "alice", "password": "private&password$123", "display_name": "Alice", "email": "a@example.test"}
        valid = subprocess.run(["php", "-r", script, str(worker)], input=json.dumps(payload),
                               text=True, capture_output=True)
        self.assertEqual(valid.returncode, 0, valid.stderr)
        payload["group"] = "admin"
        invalid = subprocess.run(["php", "-r", script, str(worker)], input=json.dumps(payload),
                                 text=True, capture_output=True)
        self.assertEqual(invalid.returncode, 1)
        self.assertNotIn(payload["password"], invalid.stdout + invalid.stderr)


if __name__ == "__main__":
    unittest.main()
