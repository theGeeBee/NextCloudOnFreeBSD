"""Cold recovery fault model. All native commands are fake; no subprocesses."""

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from installer.config import Config
from installer import recovery_sets as rs
from installer.state import atomic_json


class FakeNative:
    def __init__(self, context):
        self.c = context
        self.calls = []
        self.live = "90 othernc /srv/other/root false"
        self.extra_mount = ""
        self.extra_dataset = None
        self.overrides = {}
        self.snapshots = {}
        self.bookmarks = ""
        self.written = {r.name: "100" for r in context.resources}
        self.snapshot_fault = None
        self.rollback_fault = None
        self.after_rollback = None
        self.props = {r.name: {rs.OWNER: context.config.instance, rs.MANAGER: "cloud-installer",
                               "type": "filesystem", "origin": "-", "mountpoint": r.mountpoint, "mounted": "yes",
                              "guid": str(100 + i), "used": "1024", "available": str(100 * 1024 ** 3)}
                      for i, r in enumerate(context.resources)}
        self.props[context.config.pool] = {"available": str(100 * 1024 ** 3)}

    def output(self, *args):
        self.calls.append(args)
        if args in self.overrides:
            return self.overrides[args]
        if args[:2] == ("jls", "-d"):
            return self.live
        if args == ("mount", "-p"):
            return "\n".join(f"{r.name} {r.mountpoint} zfs rw 0 0" for r in self.c.resources) + self.extra_mount
        if args[0] == "realpath":
            return args[1]
        if args[:3] == ("stat", "-f", "%d:%i"):
            matches = [(len(r.mountpoint), index) for index, r in enumerate(self.c.resources)
                       if args[-1] == r.mountpoint or args[-1].startswith(r.mountpoint + "/")]
            return f"{1000 + max(matches)[1]}:2" if matches else "900000:2"
        if args[:2] == ("df", "-P"):
            r = next(r for r in self.c.resources if r.mountpoint == args[-1])
            return f"Filesystem 1024-blocks Used Available Capacity Mounted on\n{r.name} 100 1 99 1% {r.mountpoint}"
        if args[:2] == ("zfs", "get"):
            key, name = args[-2:]
            if key.startswith("written@"):
                return self.written[name]
            return (self.snapshots if "@" in name else self.props)[name][key]
        if args[:2] == ("zfs", "list"):
            root = args[-1]
            if "bookmark" in args:
                return self.bookmarks if self.bookmarks.startswith(root + "/") else ""
            if "snapshot" in args:
                return "\n".join(f"{name}\t{v['guid']}\t{v['createtxg']}" for name, v in self.snapshots.items()
                                 if name.split("@")[0] == root or name.startswith(root + "/"))
            names = [r.name for r in self.c.resources if r.name == root or r.name.startswith(root + "/")]
            if self.extra_dataset and self.extra_dataset.startswith(root + "/"):
                names.append(self.extra_dataset)
            return "\n".join(names)
        raise AssertionError(args)

    def run(self, *args):
        self.calls.append(args)
        if args[:2] == ("zfs", "snapshot"):
            manifest = json.loads((self.c.directory / "manifest.json").read_text())
            assert manifest["state"] == "prepared"
            assert "-r" not in args
            if self.snapshot_fault == "before":
                raise RuntimeError("SECRET diagnostic")
            for i, name in enumerate(a for a in args if "@" in a):
                self.snapshots[name] = {"guid": str(1000 + i), "createtxg": "42",
                                        rs.OWNER: self.c.config.instance, rs.MANAGER: "cloud-installer",
                                        rs.TOKEN: self.c.operation_id, "clones": "-", "userrefs": "0"}
                if self.snapshot_fault == "partial":
                    raise RuntimeError("SECRET diagnostic")
            if self.snapshot_fault == "after":
                raise RuntimeError("SECRET diagnostic")
        elif args[:2] == ("zfs", "rollback"):
            assert len(args) == 3
            name = args[-1].split("@")[0]
            journal = json.loads((self.c.directory / "restore.json").read_text())
            assert journal["members"][name] == "running"
            if self.rollback_fault == name:
                raise RuntimeError("SECRET diagnostic")
            self.written[name] = "0"
            if self.after_rollback:
                self.after_rollback(name)
        else:
            raise AssertionError(args)
        return SimpleNamespace(returncode=0)

    def mutations(self):
        return [a for a in self.calls if a[:2] in (("zfs", "snapshot"), ("zfs", "rollback"))]


class RecoverySetTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="recovery-sets-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        directory = self.root / "recovery"
        directory.mkdir(mode=0o700)
        evidence = []
        for role in sorted(rs.ROLES):
            path = self.root / (role + ".input")
            data = ("SECRET " + role).encode()
            path.write_bytes(data)
            path.chmod(0o600)
            evidence.append(rs.Evidence(role, role, path, hashlib.sha256(data).hexdigest()))
        self.events = []
        self.phase = "quiesced"
        self.proof_changes = {}
        config = Config(public_hostname="cloud.example.test", admin_email="admin@example.test",
                        acme_email="admin@example.test", external_interface="igb0", ingress_address="192.0.2.10",
                        dns_server="192.0.2.53", management_network="198.51.100.0/24").validate()
        self.c = rs.RecoveryContext(config, "op-test", *(char * 64 for char in "abcde"), directory,
                                    tuple(evidence), cold_boundary=self.boundary, checkpoint=self.checkpoint)
        self.native = FakeNative(self.c)
        self.backend = rs.NativeBackend(self.native)

    def checkpoint(self, phase, member, digest):
        self.events.append((phase, member, digest))

    def boundary(self, context, action):
        proof = rs.ColdBoundary(context.binding(), self.phase, "1" * 64,
                                ((context.config.nextcloud_jail, "running"),
                                 (context.config.onlyoffice_jail, "stopped")),
                                True, True, True, True, True, True, False, False)
        return replace(proof, **self.proof_changes)

    def capture(self):
        return rs.capture(self.c, self.backend)

    def ready(self):
        value = self.capture()
        self.phase = "recovery-required"
        return value

    def offline(self):
        self.c = replace(self.c, schema_version=2, quiescence_mode=rs.OPERATOR_OFFLINE,
                         preparation_sha256="f" * 64)
        path = self.root / "offline-acknowledgement.json"
        atomic_json(path, rs.offline_acknowledgement_record(self.c))
        ack = rs.OfflineAcknowledgement(path, hashlib.sha256(path.read_bytes()).hexdigest())
        self.c = replace(self.c, offline_acknowledgement=ack)
        self.proof_changes = {"quiescence_mode": rs.OPERATOR_OFFLINE, "office_drained": False,
                              "offline_acknowledgement_sha256": ack.sha256}
        return ack

    def offline_ready(self):
        self.offline()
        value = self.ready()
        self.proof_changes.update(capture_anchor_sha256=value["cold_boundary"], evidence_sha256="2" * 64)
        return value

    def assert_blocked(self):
        before = list(self.native.mutations())
        result = rs.assess_restore(self.c, self.backend)
        self.assertFalse(result.eligible)
        with self.assertRaises(rs.RecoveryError):
            rs.restore(self.c, self.backend)
        self.assertEqual(self.native.mutations(), before)
        return result

    def test_capture_full_atomic_tree_private_evidence_and_explicit_coverage(self):
        value = self.capture()
        self.assertEqual(len(value["datasets"]), 14)
        expected = {self.c.config.dataset_root + suffix for suffix in
                    ("", "/nc-app", "/nc-data", "/nc-database", "/nc-db-logs", "/nc-logs", "/nc-tmp",
                     "/office-runtime", "/office-data", "/office-logs")}
        expected.update(self.c.config.bastille_dataset + "/jails/" + jail + suffix
                        for jail in ("cloudnc", "cloudoo") for suffix in ("", "/root"))
        self.assertEqual(set(value["datasets"]), expected)
        for suffix in ("nc-data", "nc-db-logs", "office-runtime"):
            self.assertIn(self.c.config.dataset_root + "/" + suffix, value["datasets"])
        for jail in ("cloudnc", "cloudoo"):
            for suffix in ("", "/root"):
                self.assertIn(self.c.config.bastille_dataset + "/jails/" + jail + suffix, value["datasets"])
        commands = self.native.mutations()
        self.assertEqual(len(commands), 1)
        self.assertEqual(set(commands[0][-14:]), set(value["snapshots"]))
        self.assertFalse(any(value["coverage"].values()))
        self.assertEqual(value["state"], "complete")
        self.assertNotIn("SECRET", json.dumps(value) + repr(self.native.calls) + repr(self.events))
        for e in self.c.evidence:
            copy = self.c.directory / value["evidence"][e.name]["path"]
            self.assertEqual(copy.read_bytes(), e.path.read_bytes())
            self.assertEqual(copy.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.c.directory / "manifest.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.events[0][0], "capture-prepared")
        self.assertEqual(self.events[-1][0], "capture-complete")

    def test_no_adapter_no_native_probe_or_mutation(self):
        self.c = replace(self.c, cold_boundary=None)
        self.assertIn("adapter", self.assert_blocked().blockers[0])
        with self.assertRaises(rs.RecoveryError):
            self.capture()
        self.assertEqual(self.native.calls, [])

    def test_reclosed_phase_is_only_schema2_offline_and_never_a_capture_phase(self):
        self.offline_ready()
        self.phase = "recovery-reclosed"
        self.assertTrue(rs.assess_restore(self.c, self.backend).eligible)
        with self.assertRaises(rs.RecoveryError):
            self.capture()
        self.phase = "recovery-reclosing"
        self.assertFalse(rs.assess_restore(self.c, self.backend).eligible)
        # The schema-1 verified-drain contract does not gain this phase.
        self.c = replace(self.c, schema_version=1, quiescence_mode=rs.VERIFIED_DRAIN,
                         preparation_sha256=None, offline_acknowledgement=None)
        self.proof_changes = {"phase": "recovery-reclosed"}
        with self.assertRaisesRegex(rs.RecoveryError, "phase"):
            rs._boundary(self.c, "restore")

    def original_ready(self):
        manifest = self.offline_ready()
        def evidence(name, value):
            path = self.root / (name + ".json")
            atomic_json(path, value)
            return rs.Evidence(name, "metadata", path, hashlib.sha256(path.read_bytes()).hexdigest())
        capture = evidence("initial-closure", dict(binding=self.c.binding(), clean_database_shutdown=True))
        current = evidence("discardable-closure", dict(binding=self.c.binding(), clean_database_shutdown=False,
            office_drained=False, restore_basis=rs.ORIGINAL_CLEAN_SET))
        value = rs.original_restore_record(self.c, rs._json_hash(manifest), manifest["cold_boundary"], capture, current)
        reference = evidence("original-consent", value)
        consent = rs.OriginalRestoreConsent(reference.path, reference.sha256, rs._json_hash(manifest), manifest["cold_boundary"], capture, current)
        self.c = replace(self.c, original_restore=consent)
        self.proof_changes.update(clean_database_shutdown=False, restore_basis=rs.ORIGINAL_CLEAN_SET,
                                  capture_closure_sha256=capture.sha256, restore_consent_sha256=consent.sha256)
        return consent

    def test_original_set_restore_truthfully_allows_discardable_db_only_with_typed_consent(self):
        self.original_ready()
        proof = rs._boundary(self.c, "restore")
        self.assertFalse(proof.clean_database_shutdown)
        self.assertFalse(proof.office_drained)
        self.assertEqual(rs.restore(self.c, self.backend)["state"], "datasets-restored")
        self.assertEqual(len([args for args in self.native.calls if args[:2] == ("zfs", "rollback")]), 14)

    def test_original_consent_cannot_weaken_capture_export_or_schema_one(self):
        self.original_ready()
        self.phase = "quiesced"
        with self.assertRaises(rs.RecoveryError):
            rs._boundary(self.c, "capture")
        self.c = replace(self.c, original_restore=None)
        with self.assertRaises(rs.RecoveryError):
            rs._boundary(self.c, "capture")
        self.c = replace(self.c, schema_version=1, quiescence_mode=rs.VERIFIED_DRAIN,
                         preparation_sha256=None, offline_acknowledgement=None)
        self.phase = "restoring"
        with self.assertRaises(rs.RecoveryError):
            rs._boundary(self.c, "restore")

    def test_original_consent_missing_wrong_phrase_or_false_capture_refuses_before_rollback(self):
        consent = self.original_ready()
        for value in (None, {"enable": True}, replace(consent, sha256="f" * 64)):
            self.c = replace(self.c, original_restore=value)
            self.assert_blocked()
        self.c = replace(self.c, original_restore=consent)
        record = rs._load(consent.path)
        record["phrase"] = "RESTORE-ORIGINAL another DISCARD-CLOSED-CHANGES"
        atomic_json(consent.path, record)
        changed = replace(consent, sha256=hashlib.sha256(consent.path.read_bytes()).hexdigest())
        self.c = replace(self.c, original_restore=changed)
        self.proof_changes["restore_consent_sha256"] = changed.sha256
        self.assert_blocked()
        # A newly hashed false capture is still not affirmative clean evidence.
        atomic_json(consent.capture_closure.path, dict(binding=self.c.binding(), clean_database_shutdown=False))
        capture = replace(consent.capture_closure, sha256=hashlib.sha256(consent.capture_closure.path.read_bytes()).hexdigest())
        atomic_json(consent.path, rs.original_restore_record(self.c, consent.manifest_sha256, consent.capture_anchor_sha256,
                                                            capture, consent.current_closure))
        changed = replace(consent, capture_closure=capture, sha256=hashlib.sha256(consent.path.read_bytes()).hexdigest())
        self.c = replace(self.c, original_restore=changed)
        self.proof_changes.update(capture_closure_sha256=capture.sha256, restore_consent_sha256=changed.sha256)
        self.assert_blocked()

    def test_nullfs_canonical_source_and_same_filesystem_aliases_block_capture(self):
        point = self.c.resources[-1].mountpoint
        self.native.extra_mount = "\n/innocent /unrelated-target nullfs rw 0 0"
        self.native.overrides[("realpath", "/innocent")] = point + "/child"
        with self.assertRaises(rs.RecoveryError):
            self.capture()
        self.native.overrides.clear()
        self.native.overrides[("stat", "-f", "%d:%i", "/innocent")] = f"{1000 + len(self.c.resources) - 1}:99"
        with self.assertRaises(rs.RecoveryError):
            self.capture()
        self.assertEqual(self.native.mutations(), [])
        self.native.overrides.clear()
        self.assertEqual(self.capture()["state"], "complete")

    def test_fresh_binding_phase_and_cold_proof_required(self):
        for changes in ({"binding": {}}, {"phase": "migrating"}, {"office_drained": False},
                        {"clean_database_shutdown": False}, {"writers_frozen": False},
                        {"persistent_boot_fence": False}, {"locks_held": False},
                        {"external_dependencies_covered": False}, {"original_services": ()}):
            with self.subTest(changes=changes):
                self.proof_changes = changes
                with self.assertRaises(rs.RecoveryError):
                    self.capture()
        self.assertEqual(self.native.calls, [])

    def test_live_dying_alias_and_related_nullfs_fail(self):
        for live in ("11 cloudnc /srv/wrong false", "11 alias /srv/cloud-installer/bastille/jails/cloudnc/root true"):
            self.native.live = live
            with self.assertRaises(rs.RecoveryError):
                self.capture()
        self.native.live = ""
        for mount in (f"/elsewhere {self.c.config.mount_root} nullfs rw 0 0",
                      f"{self.c.config.mount_root}/nc-data /elsewhere nullfs rw 0 0",
                      "/elsewhere /srv/cloud-installer nullfs rw 0 0",
                      f"tmpfs {self.c.config.bastille_root}/jails/cloudnc/root/var/db tmpfs rw 0 0"):
            self.native.extra_mount = "\n" + mount
            with self.assertRaises(rs.RecoveryError):
                self.capture()
        self.assertEqual(self.native.mutations(), [])

    def test_actual_ownership_mount_guid_and_tree_checks(self):
        r = self.c.resources[-1]
        for key, value in ((rs.OWNER, "other"), (rs.MANAGER, "other"), ("mounted", "no"),
                            ("mountpoint", "/wrong"), ("guid", "0"), ("type", "volume"), ("origin", "other@base")):
            original = self.native.props[r.name][key]
            self.native.props[r.name][key] = value
            with self.subTest(key=key), self.assertRaises(rs.RecoveryError):
                self.capture()
            self.native.props[r.name][key] = original
        self.native.extra_dataset = r.name + "/unreviewed"
        with self.assertRaises(rs.RecoveryError):
            self.capture()
        self.native.extra_dataset = None
        self.native.overrides[("df", "-P", r.mountpoint)] = "header\nother 1 1 1 1% " + r.mountpoint
        with self.assertRaises(rs.RecoveryError):
            self.capture()
        self.assertEqual(self.native.mutations(), [])

    def test_capacity_uses_actual_numbers_never_quotas(self):
        self.native.props[self.c.config.pool]["available"] = "1"
        with self.assertRaisesRegex(rs.RecoveryError, "capacity"):
            self.capture()
        self.assertEqual(self.native.mutations(), [])
        self.assertFalse(any("quota" in a or "refquota" in a for a in self.native.calls))
        self.native.props[self.c.config.pool]["available"] = "10G"
        with self.assertRaises(rs.RecoveryError):
            self.capture()

    def test_capture_retry_after_atomic_command_before_checkpoint(self):
        self.native.snapshot_fault = "after"
        with self.assertRaises(rs.RecoveryError) as error:
            self.capture()
        self.assertNotIn("SECRET", str(error.exception))
        self.native.snapshot_fault = None
        value = self.capture()
        self.assertEqual(value["state"], "complete")
        self.assertEqual(len(self.native.mutations()), 1)
        self.assertEqual(self.capture(), value)

    def test_partial_or_unjournaled_snapshots_never_adopted(self):
        self.native.snapshot_fault = "partial"
        with self.assertRaises(rs.RecoveryError):
            self.capture()
        self.native.snapshot_fault = None
        with self.assertRaisesRegex(rs.RecoveryError, "Incomplete"):
            self.capture()
        self.assertEqual(len(self.native.mutations()), 1)

    def test_complete_set_without_intent_never_adopted(self):
        self.capture()
        (self.c.directory / "manifest.json").unlink()
        with self.assertRaisesRegex(rs.RecoveryError, "Unjournaled"):
            self.capture()
        self.assertEqual(len(self.native.mutations()), 1)

    def test_evidence_changed_private_errors_redacted_and_no_original_overwrite(self):
        e = next(e for e in self.c.evidence if e.role == "credentials")
        e.path.write_bytes(b"SECRET changed credential")
        with self.assertRaises(rs.RecoveryError) as error:
            self.capture()
        self.assertNotIn("SECRET", str(error.exception))
        self.assertEqual(e.path.read_bytes(), b"SECRET changed credential")
        self.assertNotEqual(json.loads((self.c.directory / "manifest.json").read_text())["state"], "complete")

    def test_private_symlinks_hardlinks_modes_and_paths_refused(self):
        e = self.c.evidence[0]
        e.path.chmod(0o644)
        with self.assertRaises(rs.RecoveryError):
            self.capture()
        e.path.chmod(0o600)
        os.link(e.path, self.root / "hardlink")
        with self.assertRaises(rs.RecoveryError):
            self.capture()
        (self.root / "hardlink").unlink()
        saved = self.root / "saved"
        e.path.rename(saved)
        e.path.symlink_to(saved)
        with self.assertRaises(rs.RecoveryError):
            self.capture()

    def test_restore_checks_entire_set_and_never_restarts_or_reconciles_metadata(self):
        value = self.ready()
        originals = {e.path: e.path.read_bytes() for e in self.c.evidence}
        self.assertTrue(rs.assess_restore(self.c, self.backend).eligible)
        result = rs.restore(self.c, self.backend)
        self.assertEqual(result["state"], "datasets-restored")
        self.assertFalse(result["recovered"])
        self.assertTrue(result["blockers"])
        rollbacks = [a for a in self.native.calls if a[:2] == ("zfs", "rollback")]
        self.assertEqual(rollbacks, [("zfs", "rollback", name) for name in value["snapshots"]])
        self.assertTrue(all(len(a) == 3 for a in rollbacks))
        self.assertFalse(any(a[0] in ("bastille", "jexec", "sh") for a in self.native.calls))
        self.assertEqual({e.path: e.path.read_bytes() for e in self.c.evidence}, originals)
        self.assertEqual(len([e for e in self.events if e[0] == "restore-running"]), 14)
        self.assertEqual(len([e for e in self.events if e[0] == "restore-complete"]), 14)
        before = len(self.native.mutations())
        rs.restore(self.c, self.backend)
        self.assertEqual(len(self.native.mutations()), before)

    def test_last_member_guid_or_owner_failure_prevents_all_rollbacks(self):
        self.ready()
        last = self.c.resources[-1]
        snapshot = rs._snapshot(self.c, last.name)
        for obj, key, wrong in ((self.native.props[last.name], "guid", "999"),
                                (self.native.snapshots[snapshot], "guid", "999"),
                                (self.native.snapshots[snapshot], rs.OWNER, "other"),
                                (self.native.snapshots[snapshot], rs.TOKEN, "other-operation"),
                                (self.native.snapshots[snapshot], "createtxg", "43")):
            previous = obj[key]
            obj[key] = wrong
            self.assert_blocked()
            obj[key] = previous

    def test_newer_snapshot_clone_hold_block_before_any_rollback(self):
        self.ready()
        last = self.c.resources[-1].name
        snapshot = self.native.snapshots[rs._snapshot(self.c, last)]
        self.native.snapshots[last + "@newer"] = {**snapshot, "guid": "9999", "createtxg": "43"}
        self.assert_blocked()
        del self.native.snapshots[last + "@newer"]
        for key, value in (("clones", "pool/clone"), ("userrefs", "1")):
            old = snapshot[key]
            snapshot[key] = value
            self.assert_blocked()
            snapshot[key] = old
        self.native.snapshots[last + "@older"] = {**snapshot, "guid": "9999", "createtxg": "41", "userrefs": "1"}
        self.assert_blocked()

    def test_partial_restore_stays_stopped_and_retries_only_unfinished_members(self):
        self.ready()
        failed = self.c.resources[3].name
        self.native.rollback_fault = failed
        with self.assertRaises(rs.RecoveryError) as error:
            rs.restore(self.c, self.backend)
        self.assertNotIn("SECRET", str(error.exception))
        record = json.loads((self.c.directory / "restore.json").read_text())
        self.assertEqual(record["members"][failed], "running")
        self.assertEqual(list(record["members"].values()).count("complete"), 3)
        self.native.rollback_fault = None
        rs.restore(self.c, self.backend)
        rollbacks = [a[-1] for a in self.native.calls if a[:2] == ("zfs", "rollback")]
        self.assertEqual(rollbacks.count(rs._snapshot(self.c, self.c.resources[0].name)), 1)
        self.assertEqual(rollbacks.count(rs._snapshot(self.c, failed)), 2)

    def test_interrupted_after_rollback_replays_only_pinned_unfinished_member(self):
        self.ready()
        def interrupt(name):
            raise RuntimeError("SECRET interrupted after rollback")
        self.native.after_rollback = interrupt
        with self.assertRaises(rs.RecoveryError):
            rs.restore(self.c, self.backend)
        self.native.after_rollback = None
        first = self.c.resources[0].name
        self.native.props[first]["guid"] = "9999"
        self.assert_blocked()
        self.native.props[first]["guid"] = "100"
        rs.restore(self.c, self.backend)
        self.assertEqual(self.native.calls.count(("zfs", "rollback", rs._snapshot(self.c, first))), 2)

    def test_complete_member_drift_is_not_silently_rolled_back_again(self):
        self.ready()
        rs.restore(self.c, self.backend)
        self.native.written[self.c.resources[-1].name] = "1"
        self.assert_blocked()

    def test_publication_flags_prevent_interrupted_replay(self):
        self.ready()
        self.native.rollback_fault = self.c.resources[1].name
        with self.assertRaises(rs.RecoveryError):
            rs.restore(self.c, self.backend)
        for key in ("publication_may_have_begun", "recovery_publication_may_have_begun"):
            self.proof_changes = {key: True}
            self.assertIn("Publication", self.assert_blocked().blockers[0])
        self.proof_changes = {}
        self.c = replace(self.c, publication_may_have_begun=True)
        before = len(self.native.calls)
        self.assert_blocked()
        self.assertEqual(len(self.native.calls), before)

    def test_fence_loss_between_members_stops_restore(self):
        self.ready()
        self.native.after_rollback = lambda name: self.proof_changes.update(writers_frozen=False)
        with self.assertRaises(rs.RecoveryError):
            rs.restore(self.c, self.backend)
        self.assertEqual(len([a for a in self.native.calls if a[:2] == ("zfs", "rollback")]), 1)

    def test_manifest_strict_schema_binding_paths_and_native_outputs(self):
        value = self.ready()
        for change in ({"schema_version": 2}, {"schema_version": True}, {"command": "zfs rollback -r"},
                       {"binding": {**value["binding"], "executor_sha256": "0" * 64}},
                       {"coverage": {"independent_copy_verified": True, "restore_rehearsal_verified": True}}):
            atomic_json(self.c.directory / "manifest.json", {**value, **change})
            self.assert_blocked()
        corrupt = json.loads(json.dumps(value))
        corrupt["evidence"][self.c.evidence[0].name]["path"] = "../../credentials"
        atomic_json(self.c.directory / "manifest.json", corrupt)
        self.assert_blocked()
        atomic_json(self.c.directory / "manifest.json", value)
        self.native.live = "SECRET malformed jls"
        self.assertNotIn("SECRET", str(self.assert_blocked()))

    def test_parent_checkpoint_failure_retains_running_member_and_redacts(self):
        self.ready()
        def checkpoint(phase, member, digest):
            if phase == "restore-complete":
                raise RuntimeError("SECRET callback")
        self.c = replace(self.c, checkpoint=checkpoint)
        with self.assertRaises(rs.RecoveryError) as error:
            rs.restore(self.c, self.backend)
        self.assertNotIn("SECRET", str(error.exception))
        self.c = replace(self.c, checkpoint=self.checkpoint)
        rs.restore(self.c, self.backend)
        first = rs._snapshot(self.c, self.c.resources[0].name)
        self.assertEqual(self.native.calls.count(("zfs", "rollback", first)), 1)

    def test_native_state_rechecked_after_durable_running_checkpoint(self):
        self.ready()
        def checkpoint(phase, member, digest):
            if phase == "restore-running":
                self.native.live = "11 cloudnc /srv/cloud-installer/bastille/jails/cloudnc/root true"
        self.c = replace(self.c, checkpoint=checkpoint)
        self.assert_blocked_after_running_checkpoint()

    def assert_blocked_after_running_checkpoint(self):
        before = self.native.mutations()
        with self.assertRaises(rs.RecoveryError):
            rs.restore(self.c, self.backend)
        self.assertEqual(self.native.mutations(), before)
        record = json.loads((self.c.directory / "restore.json").read_text())
        self.assertEqual(record["members"][self.c.resources[0].name], "running")

    def test_metadata_tamper_and_missing_snapshot_block_entire_set(self):
        self.ready()
        e = self.c.evidence[-1]
        copy = self.c.directory / "files" / e.name
        original = copy.read_bytes()
        copy.write_bytes(b"SECRET corrupt evidence")
        self.assertNotIn("SECRET", str(self.assert_blocked()))
        copy.write_bytes(original)
        del self.native.snapshots[rs._snapshot(self.c, self.c.resources[-1].name)]
        self.assert_blocked()

    def test_oversized_input_and_incomplete_roles_cannot_complete_capture(self):
        self.c = replace(self.c, evidence=self.c.evidence[:-1])
        with self.assertRaisesRegex(rs.RecoveryError, "coverage"):
            self.capture()
        self.assertEqual(self.native.calls, [])
        self.c = replace(self.c, evidence=self.native.c.evidence)
        path = self.c.evidence[0].path
        with path.open("wb") as stream:
            stream.truncate(rs.MAX_FILE + 1)
        with self.assertRaises(rs.RecoveryError):
            self.capture()
        self.assertEqual(json.loads((self.c.directory / "manifest.json").read_text())["state"], "prepared")

    def test_manifest_unknown_fields_duplicate_keys_and_plan_change(self):
        value = self.ready()
        path = self.c.directory / "manifest.json"
        text = path.read_text()
        path.write_text(text.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1'))
        self.assert_blocked()
        atomic_json(path, value)
        self.c = replace(self.c, plan_sha256="9" * 64)
        self.assert_blocked()

    def test_untyped_context_and_boundary_never_authorize_native_calls(self):
        for context in (SimpleNamespace(**vars(self.c)),
                        replace(self.c, evidence=tuple(SimpleNamespace(**vars(e)) for e in self.c.evidence)),
                        replace(self.c, checkpoint=None),
                        replace(self.c, publication_may_have_begun=0)):
            with self.subTest(context=type(context)), self.assertRaises(rs.RecoveryError):
                rs.capture(context, self.backend)
        for proof in (True, {}, SimpleNamespace(**vars(self.boundary(self.c, "capture")))):
            with self.subTest(proof=type(proof)), self.assertRaises(rs.RecoveryError):
                rs.capture(replace(self.c, cold_boundary=lambda *args: proof), self.backend)
        self.proof_changes = {"locks_held": 1}
        with self.assertRaises(rs.RecoveryError):
            self.capture()
        self.assertEqual(self.native.calls, [])

    def test_recovery_directory_cannot_be_rolled_back_with_member(self):
        for resource in self.c.resources:
            context = replace(self.c, directory=Path(resource.mountpoint) / "private-recovery")
            with self.subTest(resource=resource.name), self.assertRaisesRegex(rs.RecoveryError, "outside"):
                rs.capture(context, self.backend)
        self.assertEqual(self.native.calls, [])

    def test_adapter_and_checkpoint_recovery_errors_are_redacted(self):
        def fail(*args):
            raise rs.RecoveryError("SECRET native adapter diagnostic")
        for field in ("cold_boundary", "checkpoint"):
            context = replace(self.c, **{field: fail})
            with self.subTest(field=field), self.assertRaises(rs.RecoveryError) as error:
                rs.capture(context, self.backend)
            self.assertNotIn("SECRET", str(error.exception))
        self.assertEqual(self.native.mutations(), [])
        self.capture()
        self.phase = "recovery-required"
        context = replace(self.c, cold_boundary=fail)
        self.assertNotIn("SECRET", str(rs.assess_restore(context, self.backend)))

    def test_capture_copy_interruption_leaves_retryable_atomic_target(self):
        real_replace = os.replace
        def fail_copy(source, target):
            if Path(target).parent.name == "files":
                raise OSError("SECRET interrupted before copy publication")
            return real_replace(source, target)
        with patch.object(rs.os, "replace", side_effect=fail_copy):
            with self.assertRaises(rs.RecoveryError) as error:
                self.capture()
        self.assertNotIn("SECRET", str(error.exception))
        self.assertFalse((self.c.directory / "files" / self.c.evidence[0].name).exists())
        self.assertEqual(self.capture()["state"], "complete")
        self.assertEqual(len(self.native.mutations()), 1)

    def test_capture_copy_post_publication_interruption_preserves_valid_copy(self):
        real_replace = os.replace
        def fail_copy(source, target):
            result = real_replace(source, target)
            if Path(target).parent.name == "files":
                raise OSError("SECRET interrupted after copy publication")
            return result
        with patch.object(rs.os, "replace", side_effect=fail_copy):
            with self.assertRaises(rs.RecoveryError):
                self.capture()
        first = self.c.evidence[0]
        self.assertEqual((self.c.directory / "files" / first.name).read_bytes(), first.path.read_bytes())
        self.assertEqual(self.capture()["state"], "complete")
        self.assertEqual(len(self.native.mutations()), 1)

    def test_prepared_manifest_cannot_rebind_previously_recorded_snapshots(self):
        value = self.capture()
        value["state"] = "prepared"
        atomic_json(self.c.directory / "manifest.json", value)
        self.native.snapshots.clear()
        before = self.native.mutations()
        with self.assertRaises(rs.RecoveryError):
            self.capture()
        self.assertEqual(self.native.mutations(), before)

    def test_restore_pins_original_cold_evidence_and_service_states(self):
        self.ready()
        for changes in ({"evidence_sha256": "2" * 64},
                        {"original_services": (("cloudnc", "stopped"), ("cloudoo", "running"))}):
            self.proof_changes = changes
            with self.subTest(changes=changes):
                self.assertIn("identity", self.assert_blocked().blockers[0])

    def test_last_member_bookmark_and_clone_origin_prevent_any_rollback(self):
        self.ready()
        last = self.c.resources[-1].name
        self.native.bookmarks = last + "#newer"
        self.assertIn("Bookmark", self.assert_blocked().blockers[0])
        self.native.bookmarks = ""
        self.native.props[last]["origin"] = "pool/foreign@source"
        self.assert_blocked()

    def test_last_member_missing_duplicate_alias_or_false_covering_mount_blocks_all(self):
        self.ready()
        last = self.c.resources[-1]
        command = ("mount", "-p")
        original = self.native.output(*command)
        for inventory in ("\n".join(original.splitlines()[:-1]),
                          original + "\n" + original.splitlines()[-1],
                          original + f"\n{last.name} /alias zfs rw 0 0",
                          original.replace(last.name + " " + last.mountpoint, "pool/other " + last.mountpoint)):
            self.native.overrides[command] = inventory
            self.assert_blocked()
        del self.native.overrides[command]
        self.native.overrides[("realpath", last.mountpoint)] = "/somewhere/else"
        self.assert_blocked()

    def test_completed_member_drift_during_checkpoint_blocks_next_rollback(self):
        self.ready()
        first, second = self.c.resources[:2]
        def checkpoint(phase, member, digest):
            if phase == "restore-running" and member == second.name:
                self.native.written[first.name] = "1"
        context = replace(self.c, checkpoint=checkpoint)
        with self.assertRaisesRegex(rs.RecoveryError, "Completed restored member changed"):
            rs.restore(context, self.backend)
        self.assertEqual([a for a in self.native.mutations() if a[1] == "rollback"],
                         [("zfs", "rollback", rs._snapshot(self.c, first.name))])

    def test_publication_during_checkpoint_blocks_first_rollback(self):
        self.ready()
        for key in ("publication_may_have_begun", "recovery_publication_may_have_begun"):
            def checkpoint(phase, member, digest):
                if phase == "restore-running":
                    self.proof_changes[key] = True
            self.proof_changes = {}
            context = replace(self.c, checkpoint=checkpoint)
            with self.assertRaisesRegex(rs.RecoveryError, "Publication"):
                rs.restore(context, self.backend)
        self.assertEqual(len(self.native.mutations()), 1)

    def test_running_checkpoint_failure_precedes_mutation_and_retries_explicitly(self):
        self.ready()
        def checkpoint(phase, member, digest):
            if phase == "restore-running":
                raise rs.RecoveryError("SECRET parent checkpoint")
        with self.assertRaises(rs.RecoveryError) as error:
            rs.restore(replace(self.c, checkpoint=checkpoint), self.backend)
        self.assertNotIn("SECRET", str(error.exception))
        self.assertEqual(len(self.native.mutations()), 1)
        rs.restore(self.c, self.backend)
        self.assertEqual(len(self.native.mutations()), 15)

    def test_final_checkpoint_failure_retries_without_any_dataset_replay(self):
        self.ready()
        def checkpoint(phase, member, digest):
            if phase == "datasets-restored":
                raise RuntimeError("SECRET final checkpoint")
        with self.assertRaises(rs.RecoveryError):
            rs.restore(replace(self.c, checkpoint=checkpoint), self.backend)
        before = self.native.mutations()
        result = rs.restore(self.c, self.backend)
        self.assertFalse(result["recovered"])
        self.assertEqual(self.native.mutations(), before)

    def test_restore_journal_schema_binding_members_and_completion_are_strict(self):
        value = self.ready()
        record = rs._restore_journal(self.c, value, self.backend)
        for changes in ({"schema_version": True}, {"binding": {}}, {"manifest_sha256": "9" * 64},
                        {"members": {}}, {"state": "datasets-restored"}, {"command": "zfs destroy"},
                        {"members": {**record["members"], self.c.resources[-1].name: "recovered"}}):
            atomic_json(self.c.directory / "restore.json", {**record, **changes})
            with self.subTest(changes=changes):
                self.assert_blocked()

    def test_running_checkpoint_with_zero_written_bytes_does_not_prove_rollback(self):
        self.ready()
        first = self.c.resources[0].name
        self.native.written[first] = "0"
        def checkpoint(phase, member, digest):
            if phase == "restore-running":
                raise RuntimeError("interrupted before command")
        with self.assertRaises(rs.RecoveryError):
            rs.restore(replace(self.c, checkpoint=checkpoint), self.backend)
        self.assertEqual(len(self.native.mutations()), 1)
        rs.restore(self.c, self.backend)
        self.assertEqual(self.native.calls.count(("zfs", "rollback", rs._snapshot(self.c, first))), 1)

    def test_evidence_ancestor_symlink_and_writable_directory_are_refused(self):
        first = self.c.evidence[0]
        private = self.root / "inputs"
        private.mkdir(mode=0o700)
        path = private / "credentials"
        first.path.rename(path)
        alias = self.root / "alias"
        alias.symlink_to(private, target_is_directory=True)
        self.c = replace(self.c, evidence=(replace(first, path=alias / path.name), *self.c.evidence[1:]))
        with self.assertRaises(rs.RecoveryError):
            self.capture()
        self.c = replace(self.c, evidence=(replace(first, path=path), *self.c.evidence[1:]))
        private.chmod(0o777)
        with self.assertRaises(rs.RecoveryError):
            self.capture()
        private.chmod(0o700)
        self.assertEqual(self.capture()["state"], "complete")

    def test_ambiguous_native_success_never_completes_capture(self):
        for code in (None, False, 0.0, 1):
            with self.subTest(code=code), patch.object(self.native, "run", return_value=SimpleNamespace(returncode=code)):
                with self.assertRaises(rs.RecoveryError):
                    self.capture()
            self.assertEqual(json.loads((self.c.directory / "manifest.json").read_text())["state"], "prepared")

    def test_offline_capture_has_narrow_contract_and_all_fourteen_snapshots(self):
        ack = self.offline()
        value = self.capture()
        self.assertEqual(value["schema_version"], 2)
        self.assertEqual(value["quiescence"], {"mode": rs.OPERATOR_OFFLINE,
                         "offline_acknowledgement": {"path": str(ack.path), "sha256": ack.sha256}})
        self.assertEqual(value["coverage"], {"independent_copy_verified": False,
                         "restore_rehearsal_verified": False, "unsaved_editor_work_covered": False,
                         "machine_drain_verified": False})
        self.assertEqual(len(value["snapshots"]), 14)
        self.assertEqual(set(self.native.mutations()[0][-14:]), set(value["snapshots"]))
        self.assertEqual(self.capture(), value)
        self.assertEqual(rs.validate_manifest(self.c, value), value)
        self.assertEqual(ack.path.stat().st_mode & 0o777, 0o600)
        self.assertNotIn("SECRET", json.dumps(value) + repr(self.native.calls) + repr(self.events))

    def test_schema_one_remains_verified_drain_and_cannot_be_relabelled(self):
        value = self.ready()
        self.assertEqual(value["schema_version"], 1)
        self.assertNotIn("quiescence", value)
        self.assertTrue(rs.assess_restore(self.c, self.backend).eligible)
        self.offline()
        self.proof_changes.update(capture_anchor_sha256=value["cold_boundary"], evidence_sha256="2" * 64)
        self.assert_blocked()

    def test_offline_context_requires_typed_pinned_ack_and_explicit_version(self):
        ack = self.offline()
        for changes in ({"offline_acknowledgement": None}, {"offline_acknowledgement": True},
                        {"offline_acknowledgement": {"path": str(ack.path), "sha256": ack.sha256}},
                        {"offline_acknowledgement": replace(ack, sha256=True)},
                        {"schema_version": 1}, {"schema_version": True},
                        {"quiescence_mode": rs.VERIFIED_DRAIN}, {"preparation_sha256": None}):
            with self.subTest(changes=changes), self.assertRaises(rs.RecoveryError):
                rs.capture(replace(self.c, **changes), self.backend)
        self.assertEqual(self.native.calls, [])
        self.assertEqual(list(self.c.directory.iterdir()), [])

    def test_offline_ack_binding_exact_phrase_types_and_private_errors(self):
        ack = self.offline()
        record = rs.offline_acknowledgement_record(self.c)
        variants = [{**record, key: wrong} for key, wrong in
                    (("operation_id", "other"), ("instance", "other"),
                     ("source_sha256", "0" * 64), ("preparation_sha256", "0" * 64),
                     ("schema_version", True), ("phrase", "SECRET partial consent"),
                     ("unsaved_editor_work_covered", 0), ("machine_drain_verified", True))]
        variants.extend(({**record, "SECRET": "private value"}, True, {}))
        for value in variants:
            atomic_json(ack.path, value)
            changed = replace(ack, sha256=hashlib.sha256(ack.path.read_bytes()).hexdigest())
            with self.subTest(value=type(value)), self.assertRaises(rs.RecoveryError) as error:
                rs.capture(replace(self.c, offline_acknowledgement=changed), self.backend)
            self.assertNotIn("SECRET", str(error.exception))
        for data in (b"SECRET malformed JSON", b'{"schema_version": 1, "schema_version": 1}'):
            ack.path.write_bytes(data)
            changed = replace(ack, sha256=hashlib.sha256(data).hexdigest())
            with self.assertRaises(rs.RecoveryError) as error:
                rs.capture(replace(self.c, offline_acknowledgement=changed), self.backend)
            self.assertNotIn("SECRET", str(error.exception))
        self.assertEqual(self.native.calls, [])
        self.assertEqual(list(self.c.directory.iterdir()), [])

    def test_offline_ack_is_private_retained_outside_every_rollback_tree(self):
        ack = self.offline()
        for resource in self.c.resources:
            bad = replace(ack, path=Path(resource.mountpoint) / "ack.json")
            with self.subTest(resource=resource.name), self.assertRaisesRegex(rs.RecoveryError, "outside"):
                rs.capture(replace(self.c, offline_acknowledgement=bad), self.backend)
        ack.path.chmod(0o644)
        with self.assertRaises(rs.RecoveryError):
            self.capture()
        ack.path.chmod(0o600)
        saved = ack.path.with_suffix(".saved")
        ack.path.rename(saved)
        with self.assertRaises(rs.RecoveryError):
            self.capture()
        ack.path.symlink_to(saved)
        with self.assertRaises(rs.RecoveryError):
            self.capture()
        ack.path.unlink()
        os.link(saved, ack.path)
        with self.assertRaises(rs.RecoveryError):
            self.capture()
        self.assertEqual(self.native.calls, [])

    def test_offline_ack_change_or_reference_rebind_blocks_restore(self):
        self.offline_ready()
        ack = self.c.offline_acknowledgement
        original = ack.path.read_bytes()
        ack.path.write_bytes(b"SECRET changed acknowledgement")
        self.assertNotIn("SECRET", str(self.assert_blocked()))
        ack.path.write_bytes(original)
        other = ack.path.with_suffix(".copy")
        other.write_bytes(original)
        other.chmod(0o600)
        self.c = replace(self.c, offline_acknowledgement=replace(ack, path=other))
        self.assert_blocked()

    def test_offline_ack_is_not_clean_shutdown_or_drain_proof(self):
        self.offline()
        base = self.proof_changes.copy()
        for changes in ({"office_drained": True}, {"office_drained": 0},
                        {"quiescence_mode": rs.VERIFIED_DRAIN},
                        {"offline_acknowledgement_sha256": None},
                        {"offline_acknowledgement_sha256": "0" * 64},
                        *({key: False} for key in ("clean_database_shutdown", "writers_frozen",
                           "persistent_boot_fence", "locks_held", "external_dependencies_covered"))):
            self.proof_changes = {**base, **changes}
            with self.subTest(changes=changes), self.assertRaises(rs.RecoveryError):
                self.capture()
        self.assertEqual(self.native.calls, [])
        self.assertEqual(self.events, [])
        self.assertEqual(list(self.c.directory.iterdir()), [])

    def test_offline_clean_shutdown_rechecked_after_prepared_checkpoint(self):
        self.offline()
        def checkpoint(phase, member, digest):
            if phase == "capture-prepared":
                self.proof_changes["clean_database_shutdown"] = False
        self.c = replace(self.c, checkpoint=checkpoint)
        with self.assertRaises(rs.RecoveryError):
            self.capture()
        self.assertEqual(self.native.mutations(), [])
        self.assertFalse((self.c.directory / "files").exists())

    def test_offline_restore_separates_anchor_from_fresh_checkpoint_closure(self):
        value = self.offline_ready()
        count = 0
        def fresh(context, action):
            nonlocal count
            count += 1
            # A new parent journal closure digest on each checkpoint, with the
            # original capture anchor and historical service states unchanged.
            return replace(self.boundary(context, action),
                           evidence_sha256=hashlib.sha256(str(count).encode()).hexdigest())
        self.c = replace(self.c, cold_boundary=fresh)
        self.assertTrue(rs.assess_restore(self.c, self.backend).eligible)
        result = rs.restore(self.c, self.backend)
        self.assertEqual(result["state"], "datasets-restored")
        self.assertFalse(result["recovered"])
        self.assertGreater(count, 14)
        self.assertEqual(len(self.native.mutations()), 15)
        self.assertEqual(json.loads((self.c.directory / "manifest.json").read_text()), value)

    def test_offline_restore_rejects_missing_wrong_anchor_or_reused_capture_proof(self):
        value = self.offline_ready()
        base = self.proof_changes.copy()
        for changes in ({"capture_anchor_sha256": None}, {"capture_anchor_sha256": "3" * 64},
                        {"evidence_sha256": value["cold_boundary"]}, {"evidence_sha256": True},
                        {"original_services": (("cloudnc", "stopped"), ("cloudoo", "running"))}):
            self.proof_changes = {**base, **changes}
            with self.subTest(changes=changes):
                self.assert_blocked()

    def test_offline_capture_retry_uses_pinned_anchor_and_new_closure(self):
        self.offline()
        self.native.snapshot_fault = "after"
        with self.assertRaises(rs.RecoveryError):
            self.capture()
        self.native.snapshot_fault = None
        self.proof_changes.update(capture_anchor_sha256="1" * 64, evidence_sha256="2" * 64)
        value = self.capture()
        self.assertEqual(value["cold_boundary"], "1" * 64)
        self.assertEqual(len(self.native.mutations()), 1)
        self.proof_changes["capture_anchor_sha256"] = "3" * 64
        with self.assertRaises(rs.RecoveryError):
            self.capture()

    def test_offline_manifest_contract_cannot_claim_wider_coverage(self):
        value = self.offline_ready()
        for change in ({"schema_version": 1}, {"quiescence": {"mode": rs.VERIFIED_DRAIN}},
                       *({"coverage": {**value["coverage"], key: wrong}}
                         for key in value["coverage"] for wrong in (True, 0))):
            atomic_json(self.c.directory / "manifest.json", {**value, **change})
            with self.subTest(change=change):
                self.assert_blocked()

    def test_offline_last_snapshot_and_publication_block_all_rollbacks(self):
        self.offline_ready()
        last = self.native.snapshots[rs._snapshot(self.c, self.c.resources[-1].name)]
        original = last["guid"]
        last["guid"] = "99999"
        self.assert_blocked()
        last["guid"] = original
        for key in ("publication_may_have_begun", "recovery_publication_may_have_begun"):
            def checkpoint(phase, member, digest):
                if phase == "restore-running":
                    self.proof_changes[key] = True
            self.c = replace(self.c, checkpoint=checkpoint)
            with self.assertRaisesRegex(rs.RecoveryError, "Publication"):
                rs.restore(self.c, self.backend)
            # Even interrupted retries remain blocked by the durable parent's
            # monotonic publication marker.
            self.assert_blocked()
            del self.proof_changes[key]
        self.assertEqual(len(self.native.mutations()), 1)

    def test_offline_fresh_closure_loss_after_member_stops_restore(self):
        self.offline_ready()
        self.native.after_rollback = lambda name: self.proof_changes.update(clean_database_shutdown=False)
        with self.assertRaises(rs.RecoveryError):
            rs.restore(self.c, self.backend)
        self.assertEqual(len([a for a in self.native.mutations() if a[1] == "rollback"]), 1)


if __name__ == "__main__":
    unittest.main()
