"""One-use adapter seams: synthetic archives/FS and mocked native commands only."""

import base64
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import tempfile
import traceback
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

from installer import nextcloud_update as artifacts
from installer import upgrade_nextcloud as upgrade
from installer import upgrade_native as native

DOWNLOAD = upgrade._download


def version(identity):
    public, internal = identity
    return ("<?php\n$OC_Version = [" + ",".join(internal.split(".")) + "];\n"
            "$OC_VersionString = '" + public + "';\n$OC_Channel = 'stable';\n").encode()


class UpgradeNextcloudTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="one-use-nc-")
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        self.root = self.home / "jail"
        self.root.mkdir(mode=0o700)
        (self.root / "var/db").mkdir(parents=True, mode=0o700)
        self.run = self.home / "private-run"
        self.run.mkdir(mode=0o700)
        self.uid, self.gid = os.geteuid(), os.getegid()
        # Exercise no-follow real files and modes without privileged chown.
        self.enterContext(patch.object(artifacts, "_ROOT_UID", self.uid))
        self.enterContext(patch.object(upgrade, "_ROOT_UID", self.uid))
        self.chown = self.enterContext(patch.object(upgrade.os, "fchown"))
        self.calls, self.events, self.downloads = [], [], []
        self.fail = None
        self.replace_code = True
        self.integrity = "[]"
        self.status = {"installed": True, "version": upgrade.TARGET[1], "versionstring": upgrade.TARGET[0],
                       "needsDbUpgrade": False, "maintenance": True}
        self.config = {"maintenance": True, "datadirectory": "/var/nc-data", "instanceid": "fixture123",
                       "trusted_domains": ["cloud.example.test"], "secret": "private-config-secret",
                       "onlyoffice": {"jwt_secret": "private-jwt"}}
        self.target = SimpleNamespace(nc="testnc", office="testoo", nc_root=self.root,
                                      state=self.run, config={}, registry={}, run_jail=self.run_jail,
                                      occ=self.occ, private_config=lambda: dict(self.config))
        self.source = {
            "version.php": version(upgrade.SOURCE), artifacts.PHAR: b"source-phar",
            artifacts.CERT: b"source-certificate", "occ": b"occ-source",
            "lib/core.php": b"core-source", "config/config.sample.php": b"sample-source",
            "themes/README": b"theme-readme", "themes/example/default.php": b"example-theme",
        }
        self.destination = dict(self.source, **{"version.php": version(upgrade.TARGET),
                                               artifacts.PHAR: b"target-phar", "lib/core.php": b"target-core"})
        for name, data in self.source.items():
            self.write(self.app / name, data)
        self.write(self.app / "config/config.php", b"private-config-and-jwt")
        self.write(self.app / "custom_apps/onlyoffice/custom.php", b"retained-connector")
        self.write(self.app / ".well-known/acme-challenge/token", b"retained-acme")
        self.write(self.app / "themes/custom/theme.php", b"retained-custom-theme")
        self.pgp = "[GNUPG:] VALIDSIG " + artifacts.RELEASE_KEY + " 2026-10-15 1 0 4 0 1 10 00\n"
        self.blobs = {}
        self.archives()
        self.enterContext(patch.object(upgrade, "_download", side_effect=self.download))

    @property
    def app(self):
        return self.root / upgrade.APP.lstrip("/")

    def write(self, path, data):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        path.write_bytes(data)
        path.chmod(0o600)

    def archives(self):
        source = io.BytesIO()
        with tarfile.open(fileobj=source, mode="w:bz2") as archive:
            for name, data in self.source.items():
                info = tarfile.TarInfo("nextcloud/" + name)
                info.size, info.mode = len(data), 0o755 if name == "occ" else 0o644
                archive.addfile(info, io.BytesIO(data))
        target = io.BytesIO()
        with zipfile.ZipFile(target, "w") as archive:
            for name, data in self.destination.items():
                info = zipfile.ZipInfo("nextcloud/" + name)
                info.external_attr = (stat.S_IFREG | (0o755 if name == "occ" else 0o644)) << 16
                archive.writestr(info, data)
        self.blobs.update({"nextcloud-35.0.1.tar.bz2": source.getvalue(),
                           "nextcloud-35.0.1.tar.bz2.asc": b"source-pgp",
                           "nextcloud-35.0.2.zip": target.getvalue(),
                           "nextcloud-35.0.2.zip.asc": b"target-pgp",
                           "nextcloud-35.0.2.zip.sig": base64.b64encode(b"public-openssl-signature") + b"\n",
                           "nextcloud.asc": b"public-release-key"})

    def download(self, url, directory, name, limit):
        self.downloads.append(url)
        return artifacts._create(directory, name, data=self.blobs[name], limit=limit)

    def run_jail(self, jail, *args, input=None, timeout=120, check=True):
        self.calls.append(("jail", args, input, timeout))
        self.assertEqual(jail, self.target.nc)
        self.assertEqual(check, args[0] == "/usr/bin/id")
        if args[:2] == ("/usr/bin/id", "-u"):
            return str(self.uid)
        if args[:2] == ("/usr/bin/id", "-g"):
            return str(self.gid)
        if "--verify" in args:
            return self.pgp
        if "-r" in args and self.fail == "openssl":
            raise subprocess.CalledProcessError(1, ["hidden"], stderr="private-openssl-error")
        if "--no-upgrade" in args:
            if self.fail == "updater":
                raise subprocess.CalledProcessError(1, ["hidden"], output="private-updater-secret")
            if self.replace_code:
                for name, data in self.destination.items():
                    self.write(self.app / name, data)
        return ""

    def occ(self, *args, check=True, timeout=120):
        self.calls.append(("occ", args, None, timeout))
        self.assertFalse(check)
        if args[0] == "config:system:set":
            self.config["appstoreenabled"] = args[-1] == "--value=true"
        elif args[0] == "config:system:delete":
            self.config.pop("appstoreenabled", None)
        elif args[0] == "integrity:check-core":
            return self.integrity
        elif args[0] == "upgrade" and self.fail == "migration":
            raise subprocess.CalledProcessError(1, ["hidden"], output="private-database-secret")
        elif args[0] == "status":
            return json.dumps(self.status)
        return ""

    def prepare(self):
        return upgrade.prepare(self.target, "35.0.2", self.run)

    def apply(self, prepared):
        return upgrade.apply(self.target, prepared, lambda *event: self.events.append(event))

    def test_fresh_artifacts_both_authentications_and_local_native_sequence(self):
        prepared = self.prepare()
        self.assertEqual(len(self.downloads), 6)
        self.assertFalse((self.root / artifacts.RETAINED.lstrip("/")).exists())
        self.assertEqual(prepared.summary["source"], "35.0.1")
        self.assertEqual(sum("--verify" in c[1] for c in self.calls), 2)
        self.assertTrue(any("openssl_verify" in " ".join(c[1]) for c in self.calls))
        result = self.apply(prepared)
        self.assertTrue(result["migration_verified"])
        command = next(c for c in self.calls if "--no-upgrade" in c[1])
        self.assertEqual(command[1][:3], ("/usr/bin/mdo", "-u", "www"))
        self.assertIn("--no-interaction", command[1])
        self.assertIn("--no-backup", command[1])
        self.assertNotIn("--no-verify", command[1])
        self.assertNotIn("--ignore-state", command[1])
        self.assertEqual(command[1][command[1].index("--url") + 1],
                         "file://" + prepared.stage + "/nextcloud-35.0.2.zip")
        self.assertEqual(command[3], 3600)
        phases = [e[0] for e in self.events if e[1] == "before"]
        self.assertLess(phases.index("target-code"), phases.index("target-integrity"))
        self.assertLess(phases.index("target-integrity"), phases.index("occ-upgrade"))
        self.assertLess(phases.index("occ-upgrade"), phases.index("harden-core"))
        self.assertTrue(self.config["maintenance"])
        self.assertNotIn("appstoreenabled", self.config)

    def test_original_appstore_true_and_false_are_restored_exactly(self):
        for value in (True, False):
            with self.subTest(value=value):
                # Independent invocation fixtures, never replay a prepared run.
                case = UpgradeNextcloudTests("runTest")
                case.setUp()
                try:
                    case.config["appstoreenabled"] = value
                    case.apply(case.prepare())
                    self.assertIs(case.config["appstoreenabled"], value)
                finally:
                    case.doCleanups()

    def test_native_nextcloud_0640_config_mode_is_preserved(self):
        path = self.app / "config/config.php"
        path.chmod(0o640)
        result = self.apply(self.prepare())
        self.assertTrue(result["migration_verified"])
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)

    def test_native_migration_removes_only_the_can_install_marker(self):
        self.destination["config/CAN_INSTALL"] = b""
        self.archives()
        original = self.target.occ
        def occ(*args, **kwargs):
            value = original(*args, **kwargs)
            if args[0] == "upgrade":
                (self.app / "config/CAN_INSTALL").unlink()
            return value
        self.target.occ = occ
        self.assertTrue(self.apply(self.prepare())["migration_verified"])

    def test_unremoved_can_install_marker_refuses_after_migration(self):
        self.destination["config/CAN_INSTALL"] = b""
        self.archives()
        with self.assertRaises(upgrade.UpgradeError):
            self.apply(self.prepare())
        detail = json.loads((self.run / "nextcloud-error.json").read_text())
        self.assertIn("CAN_INSTALL", detail["message"])

    def test_group_writable_config_is_refused_with_private_diagnostic(self):
        prepared = self.prepare()
        (self.app / "config/config.php").chmod(0o660)
        with self.assertRaises(upgrade.UpgradeError):
            self.apply(prepared)
        self.assertFalse(any("--no-upgrade" in c[1] for c in self.calls))
        path = self.run / "nextcloud-error.json"
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
    def test_no_source_baseline_gate_and_protected_paths_remain_untouched(self):
        self.write(self.app / "lib/core.php", b"manually-maintained-source-code")
        protected = [self.app / path for path in ("config/config.php", "custom_apps/onlyoffice/custom.php",
                     ".well-known/acme-challenge/token", "themes/custom/theme.php")]
        before = [(p.read_bytes(), p.stat().st_mode, p.stat().st_uid, p.stat().st_gid) for p in protected]
        directories = {name: (self.app / name).stat().st_mode for name in
                       ("config", "custom_apps", ".well-known")}
        original_config = dict(self.config)
        self.apply(self.prepare())
        self.assertEqual(before, [(p.read_bytes(), p.stat().st_mode, p.stat().st_uid, p.stat().st_gid)
                                  for p in protected])
        self.assertEqual(self.config, original_config)
        self.assertEqual(stat.S_IMODE((self.app / "occ").stat().st_mode), 0o750)
        self.assertEqual(stat.S_IMODE((self.app / "lib/core.php").stat().st_mode), 0o640)
        for name, mode in directories.items():
            self.assertEqual((self.app / name).stat().st_mode, mode)

    def test_live_transport_completed_process_and_wrapped_private_config(self):
        jail, occ = self.target.run_jail, self.target.occ
        self.target.run_jail = lambda *args, **kwargs: subprocess.CompletedProcess(
            [], 0, jail(*args, **kwargs), "")
        self.target.occ = lambda *args, **kwargs: subprocess.CompletedProcess(
            [], 0, occ(*args, **kwargs), "")
        self.target.private_config = lambda: {"system": dict(self.config), "apps": {}}
        self.assertTrue(self.apply(self.prepare())["migration_verified"])

    def production_failure(self, command, label, *, oversized=False):
        config = SimpleNamespace(nextcloud_jail=self.target.nc, onlyoffice_jail=self.target.office,
                                 bastille_root=str(self.home), antivirus=False)
        registry = SimpleNamespace(lifecycle_enabled=lambda: False,
                                   status=lambda instance: {"state": "ready"},
                                   load=lambda instance: config,
                                   instance_path=lambda instance: self.run)
        live = native.LiveTarget(registry, native.UpgradeRunner(), "test")
        live.nc_root = self.root
        stdout, stderr = b"private-sentinel-stdout\n", b"private-sentinel-stderr\n"
        if oversized:
            stderr += b"x" * upgrade.OUTPUT_LIMIT
        def bounded(argv, **kwargs):
            self.assertTrue(kwargs["capture_stderr"])
            args = argv[1:] if argv[0] == "/usr/bin/env" else argv
            if args[0] == "bastille":
                return artifacts.NativeResult(0, str(self.root).encode())
            if args[0] == "jls":
                return artifacts.NativeResult(0, f"17 {live.nc} {self.root}".encode())
            self.assertEqual(args[:2], ("jexec", "17"))
            args = args[2:]
            if command in args:
                return artifacts.NativeResult(9, stdout, stderr)
            if upgrade.APP + "/occ" in args:
                args = args[args.index("--no-interaction") + 1:]
                value = self.occ(*args, check=False)
            else:
                value = self.run_jail(live.nc, *args, input=kwargs["stdin"],
                                      check=args[0] == "/usr/bin/id")
            return artifacts.NativeResult(0, value.encode())
        prepared = None if command == "--import" else self.prepare()
        self.target.run_jail, self.target.occ = live.run_jail, live.occ
        with patch.object(native, "_directories"), patch.object(live, "_account"), \
                patch.object(native.bounded_process, "run", side_effect=bounded):
            # General checked transport still suppresses both private streams.
            with self.assertRaises(RuntimeError) as checked:
                live.run_jail(live.nc, command)
            self.assertNotIn("private-sentinel", "".join(traceback.format_exception(checked.exception)))
            with self.assertRaises(upgrade.UpgradeError) as caught:
                self.prepare() if prepared is None else self.apply(prepared)
        self.assertNotIn("private-sentinel", "".join(traceback.format_exception(caught.exception)))
        path = self.run / (label + ".failure.log")
        self.assertEqual(path.read_bytes(), (stdout + stderr)[:upgrade.OUTPUT_LIMIT])
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(path.stat().st_uid, self.uid)
        self.assertLessEqual(path.stat().st_size, upgrade.OUTPUT_LIMIT)
        self.assertEqual(stat.S_IMODE(self.run.stat().st_mode), 0o700)

    def test_production_updater_failure_retains_bounded_private_streams(self):
        self.production_failure("--no-upgrade", "nextcloud-updater", oversized=True)

    def test_production_migration_failure_retains_private_streams(self):
        self.production_failure("upgrade", "nextcloud-upgrade")

    def test_production_authentication_failure_retains_private_streams(self):
        self.production_failure("--import", "nextcloud-import-key")

    def test_zip_exposed_read_only_but_private_artifacts_and_logs_not_exposed(self):
        prepared = self.prepare()
        directory = self.root / prepared.stage.lstrip("/")
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        self.apply(prepared)
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o710)
        self.assertEqual(stat.S_IMODE((directory / "nextcloud-35.0.2.zip").stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE((directory / "nextcloud.asc").stat().st_mode), 0o600)
        self.assertTrue(all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in self.run.iterdir()))

    def test_unreviewed_target_and_changed_installed_updater_refuse(self):
        with self.assertRaises(upgrade.UpgradeError):
            upgrade.prepare(self.target, "36.0.0", self.run)
        self.assertFalse(self.downloads)
        self.write(self.app / artifacts.PHAR, b"untrusted-phar")
        with self.assertRaises(upgrade.UpgradeError):
            self.prepare()
        self.assertFalse(any(c[0] == "occ" for c in self.calls))

    def test_wrong_pgp_key_refuses_before_openssl_or_code_execution(self):
        self.pgp = self.pgp.replace(artifacts.RELEASE_KEY, "0" * 40)
        with self.assertRaises(upgrade.UpgradeError):
            self.prepare()
        self.assertFalse(any("-r" in c[1] or c[0] == "occ" for c in self.calls))

    def test_authenticated_but_unsafe_archive_layout_refuses(self):
        output = io.BytesIO(self.blobs["nextcloud-35.0.2.zip"])
        with zipfile.ZipFile(output, "a") as archive:
            archive.writestr("nextcloud/../outside", b"untrusted-path")
        self.blobs["nextcloud-35.0.2.zip"] = output.getvalue()
        with self.assertRaises(upgrade.UpgradeError):
            self.prepare()
        self.assertFalse(any(c[0] == "occ" for c in self.calls))

    def test_openssl_failure_refuses_and_retains_private_error(self):
        self.fail = "openssl"
        with self.assertRaises(upgrade.UpgradeError) as caught:
            self.prepare()
        self.assertNotIn("private-openssl-error", str(caught.exception))
        self.assertEqual((self.run / "nextcloud-openssl.failure.log").read_text(), "private-openssl-error")

    def test_artifact_tampering_and_cross_target_reuse_refuse(self):
        prepared = self.prepare()
        self.target.nc = "othernc"
        with self.assertRaises(upgrade.UpgradeError):
            self.apply(prepared)
        self.target.nc = "testnc"
        self.write(self.root / prepared.stage.lstrip("/") / "nextcloud-35.0.2.zip", b"tampered")
        with self.assertRaises(upgrade.UpgradeError):
            self.apply(prepared)
        self.assertFalse(any(c[0] == "occ" for c in self.calls))

    def test_symlink_core_path_is_never_followed_or_chowned(self):
        prepared = self.prepare()
        outside = self.home / "unrelated"
        self.write(outside, b"outside")
        (self.app / "lib/core.php").unlink()
        (self.app / "lib/core.php").symlink_to(outside)
        count = self.chown.call_count
        with self.assertRaises(upgrade.UpgradeError):
            self.apply(prepared)
        self.assertEqual(self.chown.call_count, count)
        self.assertEqual(outside.read_bytes(), b"outside")
        self.assertFalse(any(c[0] == "occ" for c in self.calls))

    def test_updater_zero_without_target_bytes_cannot_start_migration(self):
        self.replace_code = False
        prepared = self.prepare()
        with self.assertRaises(upgrade.UpgradeError):
            self.apply(prepared)
        self.assertFalse(any(c[0] == "occ" and c[1][0] == "upgrade" for c in self.calls))
        failure = json.loads((self.run / "nextcloud-failure.json").read_text())
        self.assertEqual(failure["phase"], "target-code")
        self.assertFalse(failure["automatic_replay"])
        self.assertTrue(self.config["maintenance"])
        self.assertEqual(stat.S_IMODE((self.app / "lib/core.php").stat().st_mode), 0o640)
        calls = len(self.calls)
        with self.assertRaises((OSError, ValueError)):
            self.apply(prepared)
        self.assertEqual(len(self.calls), calls)

    def test_integrity_error_blocks_occ_upgrade(self):
        self.integrity = '{"INVALID_HASH": {"index.php": {}}}'
        with self.assertRaises(upgrade.UpgradeError):
            self.apply(self.prepare())
        self.assertFalse(any(c[0] == "occ" and c[1][0] == "upgrade" for c in self.calls))
        self.assertNotIn("appstoreenabled", self.config)

    def test_uncertain_updater_failure_does_not_execute_mixed_core_or_replay(self):
        self.fail = "updater"
        prepared = self.prepare()
        with self.assertRaises(upgrade.UpgradeError):
            self.apply(prepared)
        failure = json.loads((self.run / "nextcloud-failure.json").read_text())
        self.assertEqual(failure["phase"], "native-updater")
        self.assertFalse(failure["appstore_restored"])
        self.assertTrue(failure["core_hardened"])
        self.assertIn("private-updater-secret", (self.run / "nextcloud-updater.failure.log").read_text())
        self.assertFalse(any(c[0] == "occ" and c[1][0] in ("upgrade", "config:system:delete")
                             for c in self.calls))
        calls = len(self.calls)
        with self.assertRaises((OSError, ValueError)):
            self.apply(prepared)
        self.assertEqual(calls, len(self.calls))

    def test_hardlinked_core_is_refused_without_changing_the_other_name(self):
        prepared = self.prepare()
        outside = self.home / "other-name"
        os.link(self.app / "lib/core.php", outside)
        before = outside.stat()
        with self.assertRaises(upgrade.UpgradeError):
            self.apply(prepared)
        self.assertEqual(outside.stat().st_mode, before.st_mode)
        self.assertFalse(any(c[0] == "occ" for c in self.calls))

    def test_migration_failure_preserves_private_output_restores_appstore_and_hardens(self):
        self.fail = "migration"
        self.config["appstoreenabled"] = True
        prepared = self.prepare()
        with self.assertRaises(upgrade.UpgradeError) as caught:
            self.apply(prepared)
        self.assertNotIn("private-database-secret", str(caught.exception))
        self.assertIn("private-database-secret", (self.run / "nextcloud-upgrade.failure.log").read_text())
        self.assertIs(self.config["appstoreenabled"], True)
        self.assertTrue(self.config["maintenance"])
        self.assertEqual(stat.S_IMODE((self.app / "lib/core.php").stat().st_mode), 0o640)
        self.assertEqual(self.events[-1][1], "failed")
        self.assertFalse((self.run / "nextcloud-result.json").exists())

    def test_migration_zero_with_pending_database_is_not_success(self):
        self.status["needsDbUpgrade"] = True
        with self.assertRaises(upgrade.UpgradeError):
            self.apply(self.prepare())
        self.assertFalse((self.run / "nextcloud-result.json").exists())

    def test_maintenance_and_updatedirectory_are_checked_before_mutation(self):
        prepared = self.prepare()
        self.config["updatedirectory"] = "/other-updater-location"
        with self.assertRaises(upgrade.UpgradeError):
            self.apply(prepared)
        self.assertFalse(any(c[0] == "occ" for c in self.calls))

    def test_download_size_bound_and_https_redirect_policy(self):
        # Real download helper is exercised through a fake response, no network.
        with patch.object(upgrade.urllib.request, "build_opener") as opener:
            response = io.BytesIO(b"oversized")
            response.status = 200
            opener.return_value.open.return_value = response
            with self.assertRaises(artifacts.UpdateError):
                DOWNLOAD("https://download.nextcloud.com/release", self.run, "oversize", 3)
            self.assertTrue((self.run / "oversize").exists())
            self.assertEqual(stat.S_IMODE((self.run / "oversize").stat().st_mode), 0o600)
        redirect = upgrade._HTTPSRedirect()
        with self.assertRaises(upgrade.UpgradeError):
            redirect.redirect_request(None, None, 302, "", {}, "http://download.nextcloud.com/release")
        with self.assertRaises(upgrade.UpgradeError):
            redirect.redirect_request(None, None, 302, "", {}, "https://untrusted.example/release")


if __name__ == "__main__":
    unittest.main()
