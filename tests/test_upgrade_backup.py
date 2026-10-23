"""Mocked FreeBSD ZFS/jls/mount/df contracts; no native execution."""

import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from installer.config import Config, datasets
from installer import upgrade_backup as backup


def configuration():
    return Config(public_hostname="cloud.example.test", admin_email="admin@example.test", external_interface="em0",
                  ingress_address="192.0.2.10", dns_server="192.0.2.53",
                  management_network="192.0.2.0/24", acme_email="admin@example.test")


class NativeFixture:
    def __init__(self, config):
        self.config, self.calls, self.filesystems, self.snapshots = config, [], {}, {}
        paths = {item.name: item.mountpoint for item in datasets(config)}
        for jail in (config.nextcloud_jail, config.onlyoffice_jail):
            for suffix in ("", "/root"):
                paths[f"{config.bastille_dataset}/jails/{jail}{suffix}"] = f"{config.bastille_root}/jails/{jail}{suffix}"
        # A real owned descendant must also be in the atomic snapshot and report.
        paths[config.dataset_root + "/nc-data/photos"] = config.mount_root + "/nc-data/photos"
        for i, (name, mount) in enumerate(paths.items(), 100):
            self.filesystems[name] = [name, "filesystem", str(i), mount, "yes", "-", config.instance, "cloud-installer"]
        self.jails, self.mount_extra, self.df_override, self.aliases = "", [], {}, {}
        self.fail_rollback = None
        self.incomplete_capture = False
        self.snapshot_error = False
        self.path_override = None

    def output(self, *argv):
        self.calls.append(argv)
        if argv[:2] == ("bastille", "config"):
            return self.path_override or f"{self.config.bastille_root}/jails/{argv[2]}/root"
        if argv[0] == "jls":
            assert argv == ("jls", "-d", "jid", "name", "path", "dying")
            return self.jails
        if argv[:2] == ("zfs", "list"):
            root = argv[-1]
            if "filesystem,volume" in argv:
                return "\n".join("\t".join(row) for name, row in self.filesystems.items()
                                 if name == root or name.startswith(root + "/"))
            assert argv[4] == "snapshot"
            return "\n".join("\t".join((name, *meta)) for name, meta in self.snapshots.items()
                             if name.split("@")[0] == root or name.startswith(root + "/"))
        if argv == ("mount", "-p"):
            return "\n".join([f"{name}\t{row[3]}\tzfs\trw,nfsv4acls\t0\t0" for name, row in self.filesystems.items()] + self.mount_extra)
        if argv[0] == "realpath":
            return self.aliases.get(argv[1], argv[1])
        if argv[0] == "stat":
            return next((row[2] for row in self.filesystems.values() if row[3] == argv[-1]), "99999")
        if argv[:2] == ("df", "-P"):
            mount = argv[-1]
            name = next(row[0] for row in self.filesystems.values() if row[3] == mount)
            return self.df_override.get(mount, f"Filesystem 512-blocks Used Available Capacity Mounted on\n{name} 104857600 1024 104856576 0% {mount}")
        raise AssertionError(argv)

    def run(self, *argv, **kwargs):
        self.calls.append(argv)
        assert kwargs == {"timeout": 120}
        if argv[:3] == ("zfs", "snapshot", "-r"):
            for root_and_suffix in argv[3:]:
                root, suffix = root_and_suffix.split("@")
                for name, row in self.filesystems.items():
                    if name == root or name.startswith(root + "/"):
                        self.snapshots[name + "@" + suffix] = [str(int(row[2]) + 1000), "45000"]
            if self.incomplete_capture:
                self.snapshots.pop(next(iter(self.snapshots)))
            if self.snapshot_error:
                raise RuntimeError("Native command failed")
        elif argv[:2] == ("zfs", "rollback"):
            assert len(argv) == 3
            if argv[2] == self.fail_rollback:
                raise RuntimeError("Native rollback failed")
        else:
            raise AssertionError(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    def mutations(self, operation):
        return [argv for argv in self.calls if argv[:2] == ("zfs", operation)]


class UpgradeSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "run"
        self.directory.mkdir(mode=0o700)  # Parent already owns the run directory.
        self.config = configuration()
        self.runner = NativeFixture(self.config)
        self.target = SimpleNamespace(config=self.config, runner=self.runner,
            nc=self.config.nextcloud_jail, office=self.config.onlyoffice_jail,
            nc_root=Path(self.config.bastille_root) / "jails" / self.config.nextcloud_jail / "root",
            office_root=Path(self.config.bastille_root) / "jails" / self.config.onlyoffice_jail / "root")
        self.patch_uid = patch.object(backup, "ROOT_UID", os.geteuid())
        self.patch_uid.start()
        self.addCleanup(self.patch_uid.stop)

    def create(self):
        return backup.create(self.target, self.directory)

    def report(self):
        return json.loads((self.directory / "report.json").read_text())

    def test_atomic_recursive_capture_includes_exact_three_roots_and_all_descendants(self):
        record = self.create()
        self.assertEqual(record["state"], "captured")
        self.assertEqual(record, self.report())
        roots = [self.config.dataset_root, self.config.bastille_dataset + "/jails/cloudnc",
                 self.config.bastille_dataset + "/jails/cloudoo"]
        self.assertEqual(record["roots"], roots)
        self.assertEqual(self.runner.mutations("snapshot"), [("zfs", "snapshot", "-r", *(r + "@" + record["suffix"] for r in roots))])
        self.assertEqual(set(record["datasets"]), set(self.runner.filesystems))
        self.assertEqual(set(record["members"]), set(self.runner.snapshots))
        self.assertEqual(len(record["members"]), 15)
        self.assertEqual(record["datasets"][self.config.dataset_root]["guid"], "100")
        self.assertTrue(all(v["createtxg"] == "45000" for v in record["members"].values()))
        self.assertEqual((self.directory / "report.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual([p.name for p in self.directory.iterdir()], ["report.json"])
        self.assertIn("operator-owned backups", record["note"])

    def test_successful_restore_is_nonrecursive_parent_before_children_and_keeps_snapshots(self):
        record = self.create()
        snapshots = copy.deepcopy(self.runner.snapshots)
        result = backup.restore(self.target, record)
        self.assertEqual(result["state"], "restored")
        self.assertEqual(result, self.report())
        ordered = sorted(record["datasets"], key=lambda name: (name.count("/"), name))
        self.assertEqual(result["rolled_back"], ordered)
        self.assertEqual(self.runner.mutations("rollback"), [("zfs", "rollback", name + "@" + record["suffix"]) for name in ordered])
        self.assertEqual(self.runner.snapshots, snapshots)
        self.assertFalse(self.runner.mutations("destroy"))
        self.assertFalse(any("start" in call or "jexec" in call for call in self.runner.calls))

    def test_running_dying_or_alias_jails_refuse_capture_before_effects(self):
        for jail, root, dying in (("cloudnc", str(self.target.nc_root), "false"),
                                  ("cloudoo", str(self.target.office_root), "true"),
                                  ("outsider", self.config.mount_root + "/nc-data", "false")):
            with self.subTest(jail=jail):
                self.runner.jails = f"7 {jail} {root} {dying}"
                with self.assertRaises(ValueError):
                    self.create()
                self.assertFalse(self.runner.mutations("snapshot"))

    def test_native_jls_header_and_changed_bastille_root_refuse(self):
        self.runner.jails = "jid name path dying"
        with self.assertRaises(ValueError):
            self.create()
        self.runner.jails = ""
        self.runner.path_override = "/unrelated/root"
        with self.assertRaises(ValueError):
            self.create()
        self.assertFalse(self.runner.mutations("snapshot"))

    def test_ownership_missing_members_and_mount_drift_refuse_capture(self):
        baseline = copy.deepcopy(self.runner.filesystems)
        for defect in ("owner", "manager", "mount", "missing", "volume", "origin", "unmounted"):
            with self.subTest(defect=defect):
                self.runner.filesystems = copy.deepcopy(baseline)
                row = self.runner.filesystems[self.config.dataset_root + "/nc-data"]
                if defect == "missing":
                    del self.runner.filesystems[row[0]]
                else:
                    index, value = {"owner": (6, "other"), "manager": (7, "other"), "mount": (3, "/unrelated"),
                                    "volume": (1, "volume"), "origin": (5, "pool/clone@old"), "unmounted": (4, "no")}[defect]
                    row[index] = value
                with self.assertRaises(ValueError):
                    self.create()
                self.assertFalse(self.runner.mutations("snapshot"))

    def test_nullfs_covering_mount_and_df_mismatch_refuse(self):
        for line in (f"{self.config.mount_root}/nc-data /unrelated nullfs rw 0 0",
                     f"devfs {self.config.mount_root}/nc-data/covered devfs rw 0 0"):
            self.runner.mount_extra = [line]
            with self.assertRaises(ValueError):
                self.create()
        self.runner.mount_extra = []
        self.runner.df_override[self.config.mount_root] = "Filesystem 512-blocks Used Available Capacity Mounted on\nother 1 1 0 100% /srv"
        with self.assertRaises(ValueError):
            self.create()
        self.assertFalse(self.runner.mutations("snapshot"))

    def test_capture_failure_retains_suffix_and_never_claims_complete(self):
        self.runner.incomplete_capture = True
        with self.assertRaisesRegex(RuntimeError, "capture failed"):
            self.create()
        self.assertEqual(self.report()["state"], "snapshot-failed")
        self.assertTrue(self.report()["suffix"].startswith("upgrade-"))
        self.assertFalse(self.runner.mutations("rollback"))
        self.assertFalse(self.runner.mutations("destroy"))

    def test_existing_report_and_symlink_destination_are_not_overwritten(self):
        path = self.directory / "report.json"
        path.write_text("keep")
        with self.assertRaises(ValueError):
            self.create()
        self.assertEqual(path.read_text(), "keep")
        path.unlink()
        link = Path(self.temp.name) / "link"
        link.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaises(ValueError):
            backup.create(self.target, link)
        self.assertFalse(self.runner.mutations("snapshot"))

    def test_all_restore_mismatches_refuse_before_first_rollback(self):
        record = self.create()
        baseline_fs, baseline_snaps = copy.deepcopy(self.runner.filesystems), copy.deepcopy(self.runner.snapshots)
        for defect in ("owner", "dataset-guid", "missing-dataset", "added-dataset", "missing-snapshot", "snapshot-guid", "newer", "transaction"):
            with self.subTest(defect=defect):
                self.runner.filesystems, self.runner.snapshots = copy.deepcopy(baseline_fs), copy.deepcopy(baseline_snaps)
                backup.atomic_json(self.directory / "report.json", record)
                dataset, snap = next(iter(baseline_fs)), next(iter(baseline_snaps))
                if defect == "owner":
                    self.runner.filesystems[dataset][6] = "other"
                elif defect == "dataset-guid":
                    self.runner.filesystems[dataset][2] = "98765"
                elif defect == "missing-dataset":
                    del self.runner.filesystems[dataset]
                elif defect == "added-dataset":
                    row = self.runner.filesystems[dataset].copy()
                    row[0], row[2], row[3] = dataset + "/new", "98765", row[3] + "/new"
                    self.runner.filesystems[row[0]] = row
                elif defect == "missing-snapshot":
                    del self.runner.snapshots[snap]
                elif defect == "snapshot-guid":
                    self.runner.snapshots[snap][0] = "98765"
                elif defect == "newer":
                    self.runner.snapshots[dataset + "@newer"] = ["98765", "45001"]
                else:
                    self.runner.snapshots[snap][1] = "45001"
                with self.assertRaisesRegex(RuntimeError, "jails remain stopped"):
                    backup.restore(self.target, record)
                self.assertFalse(self.runner.mutations("rollback"))
                self.assertEqual(self.report()["state"], "restore-failed")
                self.assertTrue(self.report()["error"])

    def test_wrong_target_or_modified_record_never_rolls_back(self):
        record = self.create()
        for field, value in (("instance", "other"), ("roots", [self.config.dataset_root]), ("suffix", "not-captured")):
            with self.subTest(field=field):
                changed = dict(record, **{field: value})
                with self.assertRaises(ValueError):
                    backup.restore(self.target, changed)
        changed = copy.deepcopy(record)
        next(iter(changed["members"].values()))["guid"] = "998877"
        with self.assertRaises(ValueError):
            backup.restore(self.target, changed)
        self.assertFalse(self.runner.mutations("rollback"))

    def test_running_jail_blocks_restore_before_storage_or_rollback(self):
        record = self.create()
        self.runner.jails = f"7 cloudnc {self.target.nc_root} false"
        with self.assertRaises(ValueError):
            backup.restore(self.target, record)
        self.assertFalse(self.runner.mutations("rollback"))

    def test_mid_restore_failure_reports_partial_progress_and_never_starts_jails(self):
        record = self.create()
        ordered = sorted(record["datasets"], key=lambda name: (name.count("/"), name))
        self.runner.fail_rollback = ordered[1] + "@" + record["suffix"]
        with self.assertRaisesRegex(RuntimeError, "may be partial"):
            backup.restore(self.target, record)
        self.assertEqual(self.report()["state"], "restore-failed")
        self.assertEqual(self.report()["rolled_back"], ordered[:1])
        self.assertEqual(self.report()["rollback_target"], self.runner.fail_rollback)
        self.assertEqual(len(self.runner.mutations("rollback")), 2)
        self.assertFalse(any("start" in call or "jexec" in call for call in self.runner.calls))


if __name__ == "__main__":
    unittest.main()
