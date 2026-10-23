"""Offline fault model only. No ZFS, pools, provisioning or native acceptance."""

import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from installer import recovery_export as export, recovery_sets as recovery
import test_recovery_sets as fixtures


class Native(fixtures.FakeNative):
    def __init__(self, context, mount):
        super().__init__(context)
        self.mutations = []
        self.props["backup/operator"] = dict(type="filesystem", origin="-", mountpoint=str(mount),
            mounted="yes", guid="900", available=str(100 * 1024 ** 3),
            **{recovery.MANAGER: "cloud-installer", export.PURPOSE: export.DESTINATION_PURPOSE})
        self.pool_guids = {context.config.pool: "700", "backup": "800"}

    def output(self, *args):
        if args in self.overrides:
            return self.overrides[args]
        if args[:2] == ("zpool", "get"):
            self.calls.append(args)
            return self.pool_guids[args[-1]]
        if args[:3] == ("zfs", "send", "-nP"):
            self.calls.append(args)
            return "full\t" + args[-1] + "\t512\nsize\t512"
        if args == ("mount", "-p"):
            rows = super().output(*args)
            return rows + "".join(f"\n{name} {p['mountpoint']} zfs rw 0 0" for name, p in self.props.items()
                                  if name.startswith("backup/") and p.get("mounted") == "yes")
        if args[:2] == ("df", "-P"):
            for name, p in self.props.items():
                if name.startswith("backup/") and p.get("mountpoint") == args[-1]:
                    return f"header\n{name} 100 1 99 1% {args[-1]}"
        if args[:2] == ("zfs", "get") and "value,source" in args:
            return self.props[args[-1]][args[-2]] + "\tlocal"
        if args[:2] == ("zfs", "list") and args[-1].startswith("backup"):
            if "snapshot" in args:
                return "\n".join(sorted(n for n in self.snapshots if n.startswith(args[-1] + "/")))
            return "\n".join(n for n in self.props if n == args[-1] or n.startswith(args[-1] + "/"))
        return super().output(*args)

    def run(self, *args):
        self.mutations.append(args)
        if args[:2] == ("zfs", "create"):
            name = args[-1]
            assert name not in self.props
            properties = {args[i + 1].split("=", 1)[0]: args[i + 1].split("=", 1)[1]
                          for i, arg in enumerate(args) if arg == "-o"}
            self.props[name] = dict(type="filesystem", origin="-", mounted="no", guid=str(901 + len(self.props)),
                                    available=str(100 * 1024 ** 3), **properties)
        elif args[:2] == ("zfs", "mount"):
            self.props[args[-1]]["mounted"] = "yes"
            Path(self.props[args[-1]]["mountpoint"]).mkdir(mode=0o700)
        else:
            # Capture must still exercise the real recovery-set validators.
            return super().run(*args)
        return SimpleNamespace(returncode=0)


class Streams:
    def __init__(self, native):
        self.native, self.sent, self.received = native, [], []
        self.interrupt = False
        self.after_send = None
        self.receive_fault = False

    def send(self, snapshot, fd, limit):
        self.sent.append(snapshot)
        data = b"PRIVATE credentials: " + snapshot.encode()
        assert len(data) < limit
        os.write(fd, data)
        if self.interrupt:
            raise KeyboardInterrupt("SECRET")
        if self.after_send:
            self.after_send(snapshot)

    def receive(self, target, fd, size, properties):
        self.received.append(target)
        data = os.read(fd, size + 1)
        assert len(data) == size
        source = data.removeprefix(b"PRIVATE credentials: ").decode()
        self.native.props[target] = dict(type="filesystem", origin="-", mounted="no", canmount="off",
            mountpoint="none", guid=str(5000 + len(self.received)), **dict(p.split("=", 1) for p in properties))
        self.native.snapshots[target + "@" + source.split("@")[1]] = dict(self.native.snapshots[source])
        if self.receive_fault:
            raise RuntimeError("SECRET")


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.RecoverySetTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.offline()
        self.c = self.fixture.c
        self.mount = self.fixture.root / "backup"
        self.mount.mkdir(mode=0o700)
        self.native = Native(self.c, self.mount)
        self.backend = recovery.NativeBackend(self.native)
        self.manifest = recovery.capture(self.c, self.backend)
        self.native.mutations.clear()
        self.fixture.phase = "recovery-ready"
        self.locks = True
        self.publication = False
        self.recovery_publication = False
        self.projections = []
        self.ctx = SimpleNamespace(backend=self.backend, check=self.check, _recovery_context=self.context)
        self.streams = Streams(self.native)
        # Root ownership is simulated only at the private-file boundary; real
        # symlink, permission, inode, digest and topology validation still runs.
        self.addCleanup(patch.stopall)
        patch.object(export, "_require_root", lambda: None).start()
        patch.object(export, "_private", self.private).start()

    def private(self, path, directory=False):
        path = recovery._path(path, directory=directory)
        self.assertEqual(path.stat().st_mode & 0o777, 0o700 if directory else 0o600)
        return path

    def check(self, *, closed=False):
        recovery._require(self.locks and closed, "locks")
        return {}, {}, dict(phase=self.fixture.phase, publication_may_have_begun=self.publication,
                            recovery_publication_may_have_begun=self.recovery_publication)

    def context(self, *, readonly=False):
        self.projections.append(readonly)
        return self.c

    def live(self):
        self.fixture.phase = "validating"
        roots = {j: f"{self.c.config.bastille_root}/jails/{j}/root"
                 for j in (self.c.config.nextcloud_jail, self.c.config.onlyoffice_jail)}
        self.native.live = "\n".join(f"{90 + i} {j} {root} false" for i, (j, root) in enumerate(roots.items()))
        self.native.extra_mount = "".join(f"\n{d.mountpoint} {roots[d.jail]}{d.target} nullfs rw 0 0"
                                         for d in recovery.datasets(self.c.config) if d.jail)
        self.native.extra_mount += "".join(f"\ndevfs {r}/dev devfs rw 0 0" for r in roots.values())

    def create(self):
        return export.export(self.ctx, "backup/operator", streams=self.streams)

    def old_bundle(self):
        suffix = f"ci-{self.c.config.instance}-previous-operation"
        name, path = "backup/operator/" + suffix, self.mount / suffix
        path.mkdir(mode=0o700)
        old = path / "private-existing.zfs"
        old.write_bytes(b"PRIVATE old bundle must remain untouched")
        old.chmod(0o600)
        self.native.props[name] = dict(type="filesystem", origin="-", mountpoint=str(path), mounted="yes", guid="899",
            **{recovery.MANAGER: "cloud-installer", recovery.OWNER: self.c.config.instance,
               recovery.TOKEN: "previous-operation"})
        return name, old

    def test_destination_parent_requires_local_manager_and_fixed_purpose(self):
        name = "backup/operator"
        for key, expected in ((recovery.MANAGER, "cloud-installer"), (export.PURPOSE, "maintenance-recovery")):
            query = ("zfs", "get", "-Hp", "-o", "value,source", key, name)
            for value in ("-\t-", "unrelated\tlocal", expected + "\tinherited from backup", expected + "\treceived"):
                self.native.overrides[query] = value
                with self.subTest(key=key, value=value), self.assertRaises(recovery.RecoveryError):
                    self.create()
                self.assertEqual(self.native.mutations, [])
                self.assertEqual(list(self.mount.iterdir()), [])
            del self.native.overrides[query]
        self.assertEqual(export.PURPOSE, "org.cloud-installer:purpose")

    def test_existing_owned_bundle_allows_distinct_operation_without_old_file_reads(self):
        name, old = self.old_bundle()
        original = old.read_bytes(), old.stat().st_mtime_ns, old.stat().st_mode
        private = export._private
        def check(path, directory=False):
            self.assertNotEqual(Path(path), old)
            return private(path, directory)
        with patch.object(export, "_private", side_effect=check):
            receipt = self.create()
            self.assertEqual(self.create(), receipt)
        self.assertNotEqual(receipt["root"], name)
        self.assertEqual((old.read_bytes(), old.stat().st_mtime_ns, old.stat().st_mode), original)
        self.assertTrue(all(a[:2] in (("zfs", "create"), ("zfs", "mount")) and a[-1] == receipt["root"]
                            for a in self.native.mutations))

    def test_parent_descendants_require_exact_bundle_markers_mounts_and_no_aliases(self):
        name, old = self.old_bundle()
        props = self.native.props[name]
        for key, value in ((recovery.MANAGER, "other"), (recovery.OWNER, "other"),
                           (recovery.TOKEN, "wrong-operation"), ("origin", "other@snap"),
                           ("mountpoint", str(old.parent) + "-wrong")):
            original = props[key]
            props[key] = value
            with self.subTest(key=key), self.assertRaises(recovery.RecoveryError):
                self.create()
            props[key] = original
            self.assertEqual(self.native.mutations, [])
        for key in (recovery.MANAGER, recovery.OWNER, recovery.TOKEN):
            query = ("zfs", "get", "-Hp", "-o", "value,source", key, name)
            self.native.overrides[query] = props[key] + "\tinherited from backup/operator"
            with self.assertRaises(recovery.RecoveryError):
                self.create()
            del self.native.overrides[query]
        for extra in (f"\n{name} /outside-alias zfs rw 0 0",
                      f"\nunrelated/fs {self.mount}/unknown zfs rw 0 0",
                      f"\n{name}/nested {old.parent}/nested zfs rw 0 0",
                      f"\n{old.parent} /outside-alias nullfs rw 0 0"):
            self.native.extra_mount = extra
            with self.subTest(extra=extra), self.assertRaises(recovery.RecoveryError):
                self.create()
            self.assertEqual(self.native.mutations, [])
        self.native.extra_mount = ""
        unknown = "backup/operator/unrelated"
        self.native.props[unknown] = self.native.props.pop(name)
        with self.assertRaises(recovery.RecoveryError):
            self.create()

    def test_operation_bundle_still_rejects_nested_mounts_and_rerun_checks_parent(self):
        receipt = self.create()
        before = list(self.native.mutations)
        path = str(Path(receipt["path"]).parent)
        self.native.extra_mount = f"\nbackup/unrelated {path}/nested zfs rw 0 0"
        with self.assertRaises(recovery.RecoveryError):
            export.verify(self.ctx, receipt)
        self.native.extra_mount = ""
        self.native.props["backup/operator"][export.PURPOSE] = "unrelated"
        with self.assertRaises(recovery.RecoveryError):
            self.create()
        self.assertEqual(self.native.mutations, before)

    def test_unmounted_descendants_are_not_hidden_by_mount_inventory(self):
        name, _ = self.old_bundle()
        self.native.props[name]["mounted"] = "no"
        with self.assertRaises(recovery.RecoveryError):
            self.create()
        self.assertEqual(self.native.mutations, [])

    def test_rerun_retains_owned_nonmounting_receive_tree(self):
        receipt = self.create()
        result = export.rehearse(self.ctx, receipt, streams=self.streams)
        before = copy.deepcopy(self.native.props)
        mutations = list(self.native.mutations)
        self.assertEqual(self.create(), receipt)
        self.assertEqual(self.native.props, before)
        self.assertEqual(self.native.mutations, mutations)
        self.native.props[result["target"]["dataset"]][recovery.TOKEN] = "unrelated"
        with self.assertRaises(recovery.RecoveryError):
            self.create()
        self.assertEqual(self.native.mutations, mutations)

    def test_all_members_private_bound_copy_and_read_only_retry(self):
        receipt = self.create()
        result = export.verify(self.ctx, receipt)
        self.assertTrue(result["evidencecopyverified"])
        self.assertFalse(result["restorestream_rehearsal"])
        self.assertFalse(result["fullapplicationrestorerehearsal"])
        self.assertEqual(result["threat_scope"], export.SCOPE)
        value = json.loads(Path(receipt["path"]).read_bytes())
        self.assertEqual(value["snapshots"], self.manifest["snapshots"])
        self.assertEqual(value["datasets"], self.manifest["datasets"])
        self.assertEqual(len(self.streams.sent), 14)
        self.assertEqual(set(self.streams.sent), set(self.manifest["snapshots"]))
        self.assertEqual(value["binding"], self.c.binding())
        self.assertEqual(value["destination"]["pool_guid"], "800")
        self.assertEqual(value["manifest"]["sha256"], hashlib.sha256((self.c.directory / "manifest.json").read_bytes()).hexdigest())
        before = list(self.native.mutations)
        self.assertEqual(self.create(), receipt)
        self.assertEqual(self.native.mutations, before)
        self.assertEqual(len(self.streams.sent), 14)
        self.assertNotIn("PRIVATE", repr(result) + repr(self.native.calls) + repr(self.native.mutations))
        self.assertFalse(any(a[:2] == ("zpool", "create") for a in self.native.mutations))

    def test_preflight_failures_leave_no_destination_writes(self):
        cases = ("same-pool", "same-guid", "alias", "cover", "dataset-guid", "snapshot-guid", "locks", "capacity", "unclean")
        for case in cases:
            with self.subTest(case=case):
                props, snapshots = copy.deepcopy(self.native.props), copy.deepcopy(self.native.snapshots)
                if case == "same-guid":
                    self.native.pool_guids["backup"] = "700"
                elif case == "alias":
                    self.native.extra_mount = f"\nbackup/operator {self.mount}-alias zfs rw 0 0"
                elif case == "cover":
                    self.native.extra_mount = f"\n/other {self.mount.parent} nullfs rw 0 0"
                elif case == "dataset-guid":
                    self.native.props[self.c.resources[-1].name]["guid"] = "99999"
                elif case == "snapshot-guid":
                    self.native.snapshots[next(iter(self.native.snapshots))]["guid"] = "99999"
                elif case == "locks":
                    self.locks = False
                elif case == "capacity":
                    self.native.props["backup/operator"]["available"] = "1"
                elif case == "unclean":
                    self.fixture.proof_changes["clean_database_shutdown"] = False
                with self.assertRaises(recovery.RecoveryError):
                    export.export(self.ctx, self.c.config.pool if case == "same-pool" else "backup/operator", streams=self.streams)
                self.assertEqual(self.native.mutations, [])
                self.assertEqual(list(self.mount.iterdir()), [])
                self.native.props, self.native.snapshots = props, snapshots
                self.native.pool_guids["backup"] = "800"
                self.native.extra_mount, self.locks = "", True
                self.fixture.proof_changes.pop("clean_database_shutdown", None)

    def test_interruption_retains_private_prefix_and_never_adopts(self):
        self.streams.interrupt = True
        with self.assertRaises(recovery.RecoveryError) as error:
            self.create()
        self.assertNotIn("SECRET", str(error.exception))
        partial = next(self.mount.glob("*/00.zfs"))
        data = partial.read_bytes()
        self.assertTrue(data)
        self.assertEqual(partial.stat().st_mode & 0o777, 0o600)
        before = list(self.native.mutations)
        self.streams.interrupt = False
        with self.assertRaises(recovery.RecoveryError):
            self.create()
        self.assertEqual(self.native.mutations, before)
        self.assertEqual(partial.read_bytes(), data)
        self.assertFalse((partial.parent / "export.json").exists())

    def test_guid_changed_during_send_keeps_staging_without_receipt(self):
        def change(snapshot):
            self.native.snapshots[snapshot]["guid"] = "99999"
        self.streams.after_send = change
        with self.assertRaises(recovery.RecoveryError):
            self.create()
        self.assertEqual(len(self.streams.sent), 1)
        self.assertFalse(list(self.mount.glob("*/export.json")))

    def test_malformed_receipt_fails_before_receive_or_mutation(self):
        receipt = self.create()
        before = list(self.native.mutations)
        for malformed in (None, {}, dict(receipt, extra=True), dict(receipt, size=True),
                          dict(receipt, path="/etc/shadow"), dict(receipt, root=self.c.config.pool),
                          dict(receipt, sha256="0" * 64)):
            with self.subTest(receipt=malformed), self.assertRaises(recovery.RecoveryError):
                export.rehearse(self.ctx, malformed, streams=self.streams)
        self.assertEqual(self.native.mutations, before)
        self.assertEqual(self.streams.received, [])

    def test_changed_files_receipt_and_topology_refuse_verified_rerun(self):
        receipt = self.create()
        root = Path(receipt["path"]).parent
        for path in (root / "00.zfs", root / "files" / self.c.evidence[0].name,
                     root / "manifest.json", root / "export.json", root / "offline-acknowledgement.json"):
            original = path.read_bytes()
            path.write_bytes(original + b"x")
            with self.subTest(path=path), self.assertRaises(recovery.RecoveryError):
                self.create()
            path.write_bytes(original)
        self.native.props[receipt["root"]]["guid"] = "99999"
        with self.assertRaises(recovery.RecoveryError):
            export.verify(self.ctx, receipt)

    def test_rehearsal_all_independent_unmounted_receives_not_application_restore(self):
        receipt = self.create()
        result = export.rehearse(self.ctx, receipt, streams=self.streams)
        self.assertTrue(result["evidencecopyverified"])
        self.assertTrue(result["restorestream_rehearsal"])
        self.assertFalse(result["fullapplicationrestorerehearsal"])
        self.assertEqual(len(result["received"]), 14)
        self.assertEqual(len({n.rsplit("/", 1)[0] for n in self.streams.received}), 1)
        for row in result["received"]:
            self.assertEqual(row["guid"], self.manifest["snapshots"][row["source"]]["guid"])
        before = list(self.native.mutations)
        with self.assertRaises(recovery.RecoveryError):
            export.rehearse(self.ctx, receipt, streams=self.streams)
        self.assertEqual(before, self.native.mutations)
        self.assertFalse(any("-F" in a or "destroy" in a or "rollback" in a for a in self.native.mutations))

    def test_partial_receive_is_retained_and_never_replayed(self):
        receipt = self.create()
        self.streams.receive_fault = True
        with self.assertRaises(recovery.RecoveryError):
            export.rehearse(self.ctx, receipt, streams=self.streams)
        self.assertEqual(len(self.streams.received), 1)
        self.assertIn(self.streams.received[0], self.native.props)
        before = list(self.native.mutations)
        with self.assertRaises(recovery.RecoveryError):
            export.rehearse(self.ctx, receipt, streams=self.streams)
        self.assertEqual(before, self.native.mutations)
        self.assertFalse((Path(receipt["path"]).parent / "rehearsal.json").exists())

    def test_stream_adapter_bounds_output_and_reaps_only_its_own_stopped_group(self):
        original = subprocess.Popen
        for code, limit in (("import os; os.write(1, b'SECRET' * 10000)", 100),
                            ("import os,signal; os.kill(os.getpid(), signal.SIGSTOP)", 100)):
            children = []
            def spawn(*args, **kwargs):
                child = original(*args, **kwargs)
                children.append(child)
                return child
            path = self.fixture.root / ("pipe-" + str(limit) + "-" + str(len(code)))
            with path.open("wb") as stream, patch.object(export.subprocess, "Popen", side_effect=spawn), \
                    patch.object(export.os, "killpg", wraps=os.killpg) as kill:
                with self.assertRaises(recovery.RecoveryError) as error:
                    export.NativeStreams(timeout=0.2)._pipe((sys.executable, "-c", code), stream.fileno(), limit, sending=True)
                self.assertNotIn("SECRET", str(error.exception))
                self.assertEqual(kill.call_args.args, (children[0].pid, signal.SIGKILL))
                self.assertIsNotNone(children[0].returncode)
            self.assertLessEqual(path.stat().st_size, limit)

    def test_receive_adapter_fixed_nonmounting_argv(self):
        adapter = export.NativeStreams()
        with patch.object(adapter, "_pipe") as pipe:
            adapter.receive("backup/bundle/rehearsal/member-00", 12, 1024, export._properties(self.c))
        argv = pipe.call_args.args[0]
        self.assertEqual(argv[:7], ("zfs", "receive", "-u", "-o", "canmount=off", "-o", "mountpoint=none"))
        self.assertEqual(argv[-1], "backup/bundle/rehearsal/member-00")
        self.assertNotIn("-F", argv)

    def test_failed_reaped_stream_process_never_signals_a_reusable_pid(self):
        with (self.fixture.root / "failed-pipe").open("wb") as stream, \
                patch.object(export.os, "killpg", wraps=os.killpg) as kill:
            with self.assertRaises(recovery.RecoveryError):
                export.NativeStreams()._pipe((sys.executable, "-c", "raise SystemExit(7)"),
                                             stream.fileno(), 1024, sending=True)
            kill.assert_not_called()

    def test_extra_export_field_rejected_even_with_pinned_new_hash(self):
        receipt = self.create()
        path = Path(receipt["path"])
        value = json.loads(path.read_bytes())
        value["unexpected"] = True
        path.write_bytes(export._encode(value))
        forged = dict(receipt, **export._file(path, recovery.MAX_FILE))
        before = list(self.native.mutations)
        with self.assertRaises(recovery.RecoveryError):
            export.rehearse(self.ctx, forged, streams=self.streams)
        self.assertEqual(self.native.mutations, before)

    def test_live_retained_verification_readonly_without_cold_proof(self):
        receipt = self.create()
        self.live()
        before = {p: (p.read_bytes(), p.stat().st_mode, p.stat().st_mtime_ns)
                  for p in self.fixture.root.rglob("*") if p.is_file()}
        mutations = list(self.native.mutations)
        self.projections.clear()
        with patch.object(recovery, "_boundary", side_effect=AssertionError("No fresh cold proof")), \
                patch.object(export, "_write", side_effect=AssertionError("No writes")), \
                patch.object(self.backend, "storage", side_effect=AssertionError("No cold storage check")):
            for phase in ("validating", "recovery-validating", "committed-closed"):
                self.fixture.phase = phase
                proof = export.verify_retained(self.ctx, receipt)
                self.assertTrue(proof["evidencecopyverified"])
                self.assertTrue(proof["physical_independence_unassessed"])
                self.assertFalse(proof["restorestream_rehearsal"])
                self.assertFalse(proof["fullapplicationrestorerehearsal"])
                self.assertEqual(proof["threat_scope"], export.SCOPE)
        self.assertTrue(self.projections and all(self.projections))
        self.assertEqual(self.native.mutations, mutations)
        self.assertEqual(before, {p: (p.read_bytes(), p.stat().st_mode, p.stat().st_mtime_ns)
                                 for p in self.fixture.root.rglob("*") if p.is_file()})
        proof["receipt"]["sha256"] = "0" * 64
        self.assertNotEqual(proof["receipt"], receipt)

    def test_live_recheck_does_not_relax_cold_export_verify_or_rehearse(self):
        receipt = self.create()
        self.live()
        before = list(self.native.mutations)
        for action in (lambda: self.create(), lambda: export.verify(self.ctx, receipt),
                       lambda: export.rehearse(self.ctx, receipt, streams=self.streams)):
            with self.assertRaises(recovery.RecoveryError):
                action()
        self.assertEqual(before, self.native.mutations)

    def test_retained_prepublication_locks_and_allowed_phase_required(self):
        receipt = self.create()
        self.live()
        before = list(self.native.mutations)
        for phase in ("quiesced", "recovery-ready", "migrating", "published", "failed"):
            self.fixture.phase = phase
            with self.subTest(phase=phase), self.assertRaises(recovery.RecoveryError):
                export.verify_retained(self.ctx, receipt)
        self.fixture.phase = "validating"
        for field, invalid in (("locks", False), ("publication", True), ("recovery_publication", True)):
            old = getattr(self, field)
            setattr(self, field, invalid)
            with self.subTest(field=field), self.assertRaises(recovery.RecoveryError):
                export.verify_retained(self.ctx, receipt)
            setattr(self, field, old)
        self.assertEqual(before, self.native.mutations)

    def test_retained_live_alias_missing_mount_jail_and_identity_changes_refused(self):
        receipt = self.create()
        self.live()
        base, jails = self.native.extra_mount, self.native.live
        r = self.c.resources[-1]
        for extra in ("", base + f"\n{r.name} /alias zfs rw 0 0",
                      base + f"\n{r.mountpoint} /alias nullfs rw 0 0",
                      base + f"\n/other {self.c.config.mount_root} nullfs rw 0 0",
                      base + f"\n/other {r.mountpoint}/var/db nullfs rw 0 0"):
            self.native.extra_mount = extra
            with self.subTest(mounts=extra), self.assertRaises(recovery.RecoveryError):
                export.verify_retained(self.ctx, receipt)
        self.native.extra_mount = base
        for live in ("", jails.replace("false", "true"), jails + f"\n500 other {r.mountpoint} false"):
            self.native.live = live
            with self.assertRaises(recovery.RecoveryError):
                export.verify_retained(self.ctx, receipt)
        self.native.live = jails
        for table, key in ((self.native.props, r.name),
                           (self.native.snapshots, next(iter(self.native.snapshots))),
                           (self.native.props, receipt["root"])):
            old = table[key]["guid"]
            table[key]["guid"] = "99999"
            with self.assertRaises(recovery.RecoveryError):
                export.verify_retained(self.ctx, receipt)
            table[key]["guid"] = old

    def test_retained_original_evidence_and_streams_cannot_be_rebound(self):
        receipt = self.create()
        self.live()
        root = Path(receipt["path"]).parent
        for path in (self.c.evidence[0].path, self.c.directory / "files" / self.c.evidence[0].name,
                     root / "files" / self.c.evidence[0].name, root / "00.zfs", root / "manifest.json"):
            data = path.read_bytes()
            path.write_bytes(data + b"changed")
            with self.subTest(path=path), self.assertRaises(recovery.RecoveryError):
                export.verify_retained(self.ctx, receipt)
            path.write_bytes(data)

    def test_retained_rehearsal_revalidates_pinned_all_received_identities(self):
        receipt = self.create()
        rehearsal = export.rehearse(self.ctx, receipt, streams=self.streams)
        self.live()
        proof = export.verify_retained(self.ctx, receipt)
        self.assertTrue(proof["restorestream_rehearsal"])
        self.assertFalse(proof["fullapplicationrestorerehearsal"])
        for table, name, key, value in ((self.native.snapshots, rehearsal["received"][-1]["target"], "guid", "99999"),
                (self.native.props, self.streams.received[-1], "guid", "99999"),
                (self.native.props, self.streams.received[-1], "canmount", "on"),
                (self.native.props, self.streams.received[-1], "mounted", "yes"),
                (self.native.props, rehearsal["target"]["dataset"], "guid", "99999")):
            old = table[name][key]
            table[name][key] = value
            with self.subTest(key=key), self.assertRaises(recovery.RecoveryError):
                export.verify_retained(self.ctx, receipt)
            table[name][key] = old
        path = Path(proof["rehearsal"]["path"])
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaises(recovery.RecoveryError):
            export.verify_retained(self.ctx, receipt)

    def test_retained_unpinned_rehearsal_is_not_adopted(self):
        receipt = self.create()
        export.rehearse(self.ctx, receipt, streams=self.streams)
        (self.c.directory / "export-rehearsal.json").unlink()
        self.live()
        with self.assertRaises(recovery.RecoveryError):
            export.verify_retained(self.ctx, receipt)

    def test_retained_phase_and_snapshot_drift_during_hashing_refused(self):
        receipt = self.create()
        self.live()
        real_file = export._file
        for drift in ("phase", "snapshot"):
            snapshot = next(iter(self.native.snapshots))
            original_guid = self.native.snapshots[snapshot]["guid"]
            def hashing(path, limit):
                result = real_file(path, limit)
                if Path(path).name == "13.zfs":
                    if drift == "phase":
                        self.fixture.phase = "migrating"
                    else:
                        self.native.snapshots[snapshot]["guid"] = "99999"
                return result
            with patch.object(export, "_file", side_effect=hashing), self.assertRaises(recovery.RecoveryError):
                export.verify_retained(self.ctx, receipt)
            self.fixture.phase = "validating"
            self.native.snapshots[snapshot]["guid"] = original_guid


if __name__ == "__main__":
    unittest.main()
