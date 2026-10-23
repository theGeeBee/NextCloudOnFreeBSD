"""Offline generation storage, content bindings and crash/fence boundaries."""

import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from installer.config import Config
from installer.generations import Store, descriptor
from installer.state import atomic_json, atomic_write, private_directory


EXECUTOR = "e" * 64
SOURCE = "a" * 64


class GenerationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="generations-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        private_directory(self.root / "instances")
        self.store = Store(self.root)

    def instance(self, name="cloud", state="ready", source=True, plugins=False):
        path = private_directory(self.root / "instances" / name)
        config = Config(instance=name, public_hostname=name + ".example.test",
                        onlyoffice_plugins="ocr" if plugins else "")
        atomic_write(path / "config.json", config.to_json())
        atomic_json(path / "status.json", {"state": state})
        atomic_json(path / "secrets.json", {"password": "never-in-public-records"})
        if source:
            atomic_write(path / "source.sha256", SOURCE + "\n")
        # Storage fixtures, not claims of valid package locks/native evidence.
        atomic_write(path / "versions.json", '{ "fixture": "original lock" }\n')
        if source:
            atomic_write(path / "deployment.json", '{ "fixture": "original journal" }\n')
        if plugins:
            atomic_write(path / "plugins.json", '{ "fixture": "original plugin lock" }\n')
        return path

    def enroll(self, name="cloud", operation="enroll-one", generation="gen-one"):
        self.store.begin(operation, "enroll", [name], EXECUTOR)
        archive = self.store.archive_legacy(name, operation)
        evidence = {"policy.json": b'{ "fixture": "retained source policy" }\n',
                    "resources.json": b'{ "fixture": "retained identities" }\n',
                    "source/worker.sh": b"# retained fixture bytes\n"}
        reference = self.store.seal_generation(name, generation, operation,
                                               archive=archive, evidence=evidence)
        atomic_json(self.root / "instances" / name / "config.json", descriptor(name, reference))
        return {"kind": "managed", "generation": reference, "status": {"state": "ready"}}

    def publish(self, entries, operation="enroll-one", graph="graph-one"):
        self.store.commit(graph, entries, operation)
        self.store.finish(operation)

    def initialize_legacy(self, names=("cloud",)):
        self.store.begin("register-one", "register", list(names), EXECUTOR)
        entries = {name: self.store.build_entry(name) for name in names}
        self.publish(entries, "register-one")
        return entries

    def test_empty_reads_do_not_initialize_or_adopt(self):
        self.assertFalse(self.store.exists())
        self.assertIsNone(self.store.pending())
        self.assertEqual(list(self.root.iterdir()), [self.root / "instances"])
        self.instance()
        self.assertFalse(self.store.exists())
        with self.assertRaises(ValueError):
            self.store.graph()
        with self.assertRaises(ValueError):
            self.store.build_entry("cloud")
        self.assertFalse((self.root / "lifecycle").exists())
        missing = Store(self.root / "absent")
        self.assertFalse(missing.exists())
        self.assertFalse(missing.root.exists())

    def test_original_bytes_plugins_nested_evidence_and_secrets_boundary(self):
        instance = self.instance(plugins=True)
        private_directory(instance / "inventory")
        atomic_write(instance / "inventory" / "packages.txt", "original\npackage inventory\n")
        original = {str(path.relative_to(instance)): path.read_bytes()
                    for path in instance.rglob("*") if path.is_file()}
        entry = self.enroll()
        # The lookup descriptor and derived status are not effective managed inputs.
        atomic_json(instance / "config.json", descriptor("cloud", entry["generation"]))
        atomic_json(instance / "status.json", {"state": "failed"})
        self.publish({"cloud": entry})
        resolved = self.store.resolve("cloud")
        self.assertEqual(resolved["kind"], "managed")
        self.assertEqual(resolved["config_bytes"], original["config.json"])
        self.assertEqual(resolved["status"], {"state": "ready"})
        self.assertEqual(resolved["provenance"]["source_sha256"], SOURCE)
        self.assertEqual(resolved["versions_path"].read_bytes(), original["versions.json"])
        self.assertEqual(resolved["plugins_path"].read_bytes(), original["plugins.json"])
        self.assertEqual(resolved["evidence_path"], instance / "legacy/files")
        manifest = resolved["manifest"]
        self.assertIsNone(manifest["predecessor"])
        self.assertEqual(manifest["origin"], "legacy-enrollment")
        self.assertEqual(manifest["provenance"]["policy_sha256"], manifest["provenance"]["policy"]["sha256"])
        for filename, data in original.items():
            if filename == "secrets.json":
                self.assertFalse((instance / "legacy/files" / filename).exists())
                self.assertEqual(manifest["credentials"]["sha256"], hashlib.sha256(data).hexdigest())
            else:
                self.assertEqual((instance / "legacy/files" / filename).read_bytes(), data)
        for path in self.root.rglob("*"):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700 if path.is_dir() else 0o600)
            if path.is_file() and path.name != "secrets.json":
                self.assertNotIn(b"never-in-public-records", path.read_bytes())

    def test_source_bound_loader_is_explicit_and_receives_provenance(self):
        self.instance()
        entry = self.enroll()
        self.publish({"cloud": entry})
        seen = []
        def loader(data, provenance):
            seen.append((data, provenance))
            return Config(**json.loads(data))
        store = Store(self.root, config_loader=loader)
        with patch("installer.config.Config.from_json", side_effect=AssertionError("current policy consulted")):
            result = store.resolve("cloud")
        self.assertIsInstance(result["config"], Config)
        self.assertEqual(seen, [(result["config_bytes"], result["provenance"])])

    def test_mixed_graph_and_tombstone_preserve_generation(self):
        self.instance()
        self.instance("other", "configured", source=False)
        self.instance("retired", "removed")
        legacy = self.store.legacy_entry("other")
        removed = {"kind": "removed", "retained": self.store.legacy_entry("retired"),
                   "status": {"state": "removed", "data_retained": True}}
        managed = self.enroll()
        self.publish({"cloud": managed, "other": legacy, "retired": removed})
        self.assertEqual(self.store.resolve("other")["kind"], "legacy")
        self.assertIsNone(self.store.resolve("other")["provenance"]["source_sha256"])
        self.assertEqual(self.store.resolve("retired")["kind"], "removed")
        before = self.store.graph()["instances"]
        self.store.begin("remove-one", "remove", ["cloud"], EXECUTOR)
        after = copy.deepcopy(before)
        after["cloud"] = {"kind": "removed", "retained": managed,
                          "status": {"state": "removed", "data_retained": True}}
        self.publish(after, "remove-one", "graph-two")
        resolved = self.store.resolve("cloud")
        self.assertEqual(resolved["kind"], "removed")
        self.assertEqual(resolved["manifest"]["generation_id"], "gen-one")
        self.assertEqual(self.store.graph()["instances"]["other"], before["other"])

    def test_pending_blocks_reads_and_mutations_until_explicit_finalization(self):
        self.instance()
        self.initialize_legacy()
        self.store.begin("status-one", "status", ["cloud"], EXECUTOR)
        for action in (lambda: self.store.graph(), lambda: self.store.resolve("cloud"),
                       lambda: self.store.begin("other-op", "status", ["cloud"], EXECUTOR)):
            with self.assertRaises(ValueError):
                action()
        self.assertTrue(self.store.exists())
        with self.assertRaises(ValueError):
            self.store.finish("status-one")
        self.store.finish("status-one", "cancelled")
        self.assertIsNone(self.store.pending())
        self.assertTrue((self.root / "maintenance/pending.json").exists())
        self.assertTrue((self.root / "maintenance/operations/status-one/intent.json").exists())
        self.assertTrue((self.root / "maintenance/operations/status-one/terminal.json").exists())
        with self.assertRaises(ValueError):
            self.store.graph(validate_evidence=False)

    def test_explicit_fenced_legacy_refresh_and_strict_commit(self):
        path = self.instance(state="configured", source=False)
        self.initialize_legacy()
        self.store.begin("evidence-one", "evidence", ["cloud"], EXECUTOR)
        atomic_write(path / "source.sha256", SOURCE + "\n")
        atomic_json(path / "status.json", {"state": "installing"})
        entries = self.store.graph(validate_evidence=False)["instances"]
        with self.assertRaises(ValueError):
            self.store.commit("graph-two", entries, "evidence-one")
        entries["cloud"] = self.store.build_entry("cloud")
        self.publish(entries, "evidence-one", "graph-two")
        self.assertEqual(self.store.resolve("cloud")["status"]["state"], "installing")

    def test_unjournaled_legacy_drift_blocks_new_intent_without_adoption(self):
        path = self.instance()
        self.initialize_legacy()
        before = (self.root / "lifecycle/active.json").read_bytes()
        atomic_json(path / "status.json", {"state": "failed"})
        with self.assertRaises(ValueError):
            self.store.resolve("cloud")
        with self.assertRaises(ValueError):
            self.store.begin("status-one", "status", ["cloud"], EXECUTOR)
        self.assertEqual((self.root / "lifecycle/active.json").read_bytes(), before)
        self.assertIsNone(self.store.pending())

    def test_unjournaled_source_creation_is_drift_even_before_status_changes(self):
        path = self.instance(state="configured", source=False)
        self.initialize_legacy()
        atomic_write(path / "source.sha256", SOURCE + "\n")
        with self.assertRaises(ValueError):
            self.store.resolve("cloud")
        with self.assertRaises(ValueError):
            self.store.begin("evidence-one", "evidence", ["cloud"], EXECUTOR)

    def test_graph_must_cover_directories_and_preserve_unaffected_entries(self):
        self.instance()
        self.instance("other")
        entries = self.initialize_legacy(("cloud", "other"))
        self.store.begin("status-one", "status", ["cloud"], EXECUTOR)
        with self.assertRaises(ValueError):
            self.store.commit("missing-other", {"cloud": entries["cloud"]}, "status-one")
        changed = copy.deepcopy(entries)
        changed["other"] = {"kind": "removed", "retained": entries["other"], "status": {"state": "removed"}}
        with self.assertRaises(ValueError):
            self.store.commit("changed-other", changed, "status-one")
        private_directory(self.root / "instances/.pending-unpublished")
        self.publish(entries, "status-one", "graph-two")
        self.instance("unknown")
        with self.assertRaises(ValueError):
            self.store.graph()

    def test_missing_original_locks_plugins_source_or_ready_state_refused(self):
        path = self.instance(plugins=True)
        self.store.begin("enroll-one", "enroll", ["cloud"], EXECUTOR)
        for filename in ("versions.json", "plugins.json", "source.sha256", "deployment.json"):
            original = (path / filename).read_bytes()
            (path / filename).unlink()
            with self.subTest(filename=filename), self.assertRaises(ValueError):
                self.store.archive_legacy("cloud", "enroll-one")
            atomic_write(path / filename, original.decode())
        atomic_json(path / "status.json", {"state": "failed"})
        with self.assertRaises(ValueError):
            self.store.archive_legacy("cloud", "enroll-one")
        self.assertFalse((path / "legacy").exists())

    def test_missing_source_only_permitted_for_unprovisioned_or_retired_config(self):
        path = self.instance(state="configured", source=False)
        self.assertIsNone(self.store.legacy_entry("cloud")["source"])
        for state in ("ready", "failed", "installing"):
            atomic_json(path / "status.json", {"state": state})
            with self.subTest(state=state), self.assertRaises(ValueError):
                self.store.legacy_entry("cloud")

    def test_managed_corruption_never_falls_back_to_old_lookup(self):
        self.instance()
        entry = self.enroll()
        self.publish({"cloud": entry})
        resolved = self.store.resolve("cloud")
        atomic_json(resolved["versions_path"], {"fixture": "changed lock"})
        with self.assertRaises(ValueError):
            self.store.resolve("cloud")

    def test_archived_evidence_and_credential_hash_drift_are_checked(self):
        instance = self.instance()
        entry = self.enroll()
        self.publish({"cloud": entry})
        for path in (instance / "legacy/files/deployment.json", instance / "secrets.json"):
            before = path.read_bytes()
            atomic_json(path, {"changed": True})
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.store.graph()
            atomic_write(path, before.decode())
        self.store.graph()

    def test_unsafe_paths_symlinks_hardlinks_modes_owners_and_limits(self):
        path = self.instance()
        for relative in ("/etc/passwd", "../escape", "instances//cloud/config.json", "instances/./cloud/config.json"):
            with self.subTest(relative=relative), self.assertRaises(ValueError):
                self.store.reference(relative)
        target = path / "status.json"
        symlink = path / "linked.json"
        symlink.symlink_to(target)
        with self.assertRaises(ValueError):
            self.store.reference("instances/cloud/linked.json")
        symlink.unlink()
        os.link(target, symlink)
        with self.assertRaises(ValueError):
            self.store.reference("instances/cloud/status.json")
        symlink.unlink()
        target.chmod(0o640)
        with self.assertRaises(ValueError):
            self.store.reference("instances/cloud/status.json")
        target.chmod(0o600)
        with patch("installer.generations.os.geteuid", return_value=os.geteuid() + 1), self.assertRaises(ValueError):
            self.store.reference("instances/cloud/status.json")
        with patch("installer.generations.MAX_FILE_BYTES", 1), self.assertRaises(ValueError):
            self.store.reference("instances/cloud/status.json")
        alias = self.root / "alias"
        alias.symlink_to(self.root / "instances", target_is_directory=True)
        with self.assertRaises(ValueError):
            self.store.reference("alias/cloud/status.json")
        with self.assertRaises(ValueError):
            Store(alias).exists()

    def test_unknown_schemas_fields_ids_paths_and_duplicate_json_fail_closed(self):
        self.instance()
        for operation, action, names in (("../bad", "status", ["cloud"]), ("valid", "upgrade", ["cloud"]),
                                         ("valid", "status", ["Cloud"]), ("valid", "status", ["cloud", "cloud"])):
            with self.subTest(operation=operation, action=action, names=names), self.assertRaises(ValueError):
                self.store.begin(operation, action, names, EXECUTOR)
        self.initialize_legacy()
        path = self.root / "lifecycle/active.json"
        original = path.read_bytes()
        for value in ({"schema_version": True, "graph": {}}, {"schema_version": 2, "graph": {}},
                      {"schema_version": 1, "graph": {}, "unknown": True},
                      {"schema_version": 1, "graph": {"path": "instances/cloud/config.json", "sha256": "a" * 64}}):
            atomic_json(path, value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.store.graph()
        atomic_write(path, '{"schema_version":1,"schema_version":1,"graph":{}}')
        with self.assertRaises(ValueError):
            self.store.graph()
        atomic_write(path, original.decode())
        self.store.graph()

    def test_cross_instance_reference_rejected_even_when_hash_matches(self):
        self.instance()
        self.instance("other")
        self.store.begin("register-one", "register", ["cloud", "other"], EXECUTOR)
        entries = {name: self.store.build_entry(name) for name in ("cloud", "other")}
        entries["cloud"]["status"] = entries["other"]["status"]
        with self.assertRaises(ValueError):
            self.store.commit("graph-one", entries, "register-one")

    def test_generation_schema_identity_and_enrollment_only_lineage_are_strict(self):
        self.instance()
        entry = self.enroll()
        path = self.root / entry["generation"]["path"]
        original = json.loads(path.read_bytes())
        changes = ({"schema_version": True}, {"schema_version": 2}, {"secret": "must-not-be-a-field"},
                   {"entity_id": "other"}, {"predecessor": "earlier"}, {"origin": "upgrade"},
                   {"recipe": "unreviewed"}, {"generation_id": "../outside"})
        for change in changes:
            atomic_json(path, {**original, **change})
            candidate = {**entry, "generation": self.store.reference(entry["generation"]["path"])}
            atomic_json(self.root / "instances/cloud/config.json", descriptor("cloud", candidate["generation"]))
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.store.commit("graph-one", {"cloud": candidate}, "enroll-one")
        atomic_json(path, original)
        # Hash serialization changes are explicit, never guessed by resolve.
        entry["generation"] = self.store.reference(entry["generation"]["path"])
        atomic_json(self.root / "instances/cloud/config.json", descriptor("cloud", entry["generation"]))
        self.publish({"cloud": entry})

    def test_managed_status_update_preserves_manifest_and_config_bytes(self):
        self.instance()
        entry = self.enroll()
        self.publish({"cloud": entry})
        paths = (self.root / entry["generation"]["path"], self.store.resolve("cloud")["config_path"])
        before = [path.read_bytes() for path in paths]
        self.store.begin("status-one", "status", ["cloud"], EXECUTOR)
        entries = self.store.graph(validate_evidence=False)["instances"]
        entries["cloud"]["status"] = {"state": "removing", "purge_data": False}
        self.publish(entries, "status-one", "graph-two")
        self.assertEqual(self.store.resolve("cloud")["status"]["state"], "removing")
        self.assertEqual([path.read_bytes() for path in paths], before)

    def test_managed_lookup_requires_exact_descriptor_and_old_reader_refuses_it(self):
        self.instance()
        entry = self.enroll()
        self.publish({"cloud": entry})
        path = self.root / "instances/cloud/config.json"
        expected = descriptor("cloud", entry["generation"])
        with self.assertRaises(ValueError):
            Config.from_json(json.dumps(expected))
        original = json.loads((self.root / "instances/cloud/legacy/files/config.json").read_bytes())
        for value in (original, {**expected, "schema_version": True}, {**expected, "instance": "other"},
                      {**expected, "extra": "field"},
                      {**expected, "generation": {**entry["generation"], "sha256": "f" * 64}}):
            atomic_json(path, value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.store.resolve("cloud")
        atomic_json(path, expected)
        self.assertEqual(self.store.resolve("cloud")["kind"], "managed")

    def test_pinned_lookup_rejects_forged_stale_and_mid_read_changed_graphs(self):
        self.instance()
        self.instance("other")
        self.initialize_legacy(("cloud", "other"))
        graph = self.store.graph()
        with patch.object(self.store, "_entries", side_effect=AssertionError("unnecessary full scan")):
            self.assertEqual(self.store.resolve("cloud", graph=graph)["name"], "cloud")
            self.assertEqual(self.store.resolve("other", graph=graph)["name"], "other")
        forged = copy.deepcopy(graph)
        forged["instances"]["cloud"]["source"]["sha256"] = "f" * 64
        with self.assertRaises(ValueError):
            self.store.resolve("cloud", graph=forged)
        def changing_loader(data, provenance):
            self.store.begin("status-one", "status", ["cloud"], EXECUTOR)
            self.publish(graph["instances"], "status-one", "graph-two")
            return json.loads(data)
        self.store.config_loader = changing_loader
        with self.assertRaisesRegex(ValueError, "changed during lookup"):
            self.store.resolve("cloud", graph=graph)
        self.store.config_loader = None
        with self.assertRaisesRegex(ValueError, "current committed snapshot"):
            self.store.resolve("cloud", graph=graph)

    def test_archive_recovery_uses_durable_bytes_after_live_descriptor_change(self):
        instance = self.instance(plugins=True)
        originals = {path.name: path.read_bytes() for path in instance.iterdir() if path.name != "secrets.json"}
        self.store.begin("enroll-one", "enroll", ["cloud"], EXECUTOR)
        write = self.store._write
        snapshot = "maintenance/operations/enroll-one/archive-cloud/"
        def fail_archive(relative, data, **kwargs):
            if relative.startswith("instances/cloud/legacy/files/"):
                # Snapshot bytes must ALL be durable before any destination bytes.
                for filename, original in originals.items():
                    self.assertEqual((self.root / snapshot / "files" / filename).read_bytes(), original)
            if relative == "instances/cloud/legacy/files/plugins.json":
                raise OSError("injected interrupted archive")
            return write(relative, data, **kwargs)
        with patch.object(self.store, "_write", side_effect=fail_archive), self.assertRaises(OSError):
            self.store.archive_legacy("cloud", "enroll-one")
        retained = instance / "legacy/files/config.json"
        inode = retained.stat().st_ino
        atomic_json(instance / "config.json", {"record_type": "lifecycle-registration", "fixture": True})
        reference = self.store.archive_legacy("cloud", "enroll-one", recover=True)
        self.assertEqual(retained.stat().st_ino, inode)
        for filename, data in originals.items():
            self.assertEqual((instance / "legacy/files" / filename).read_bytes(), data)
        self.assertEqual(self.store.archive_legacy("cloud", "enroll-one", recover=True), reference)
        with self.assertRaises(ValueError):
            self.store.archive_legacy("cloud", "different-op", recover=True)

    def test_partial_snapshot_recovery_refuses_changed_unretained_original(self):
        instance = self.instance()
        self.store.begin("enroll-one", "enroll", ["cloud"], EXECUTOR)
        write = self.store._write
        def fail_snapshot(relative, data, **kwargs):
            if relative == "maintenance/operations/enroll-one/archive-cloud/files/source.sha256":
                raise OSError("injected interrupted snapshot")
            return write(relative, data, **kwargs)
        with patch.object(self.store, "_write", side_effect=fail_snapshot), self.assertRaises(OSError):
            self.store.archive_legacy("cloud", "enroll-one")
        self.assertFalse((instance / "legacy").exists())
        atomic_write(instance / "source.sha256", "f" * 64 + "\n")
        with self.assertRaisesRegex(ValueError, "snapshot inputs changed"):
            self.store.archive_legacy("cloud", "enroll-one", recover=True)
        self.assertFalse((instance / "legacy").exists())
        atomic_write(instance / "source.sha256", SOURCE + "\n")
        self.store.archive_legacy("cloud", "enroll-one", recover=True)

    def test_generation_recovery_requires_identical_evidence_and_preserves_files(self):
        self.instance()
        self.store.begin("enroll-one", "enroll", ["cloud"], EXECUTOR)
        archive = self.store.archive_legacy("cloud", "enroll-one")
        evidence = {"policy.json": b'{"fixture":"source"}', "resources.json": b'{"fixture":"resources"}'}
        write = self.store._write
        def fail_generation(relative, data, **kwargs):
            if relative == "instances/cloud/generations/gen-one/versions.json":
                raise OSError("injected interrupted generation")
            return write(relative, data, **kwargs)
        with patch.object(self.store, "_write", side_effect=fail_generation), self.assertRaises(OSError):
            self.store.seal_generation("cloud", "gen-one", "enroll-one", archive=archive, evidence=evidence)
        retained = self.root / "instances/cloud/generations/gen-one/config.json"
        inode = retained.stat().st_ino
        with self.assertRaises(ValueError):
            self.store.seal_generation("cloud", "gen-one", "enroll-one", archive=archive,
                                       evidence={**evidence, "resources.json": b'{"fixture":"changed"}'}, recover=True)
        self.assertFalse((retained.parent / "versions.json").exists())
        reference = self.store.seal_generation("cloud", "gen-one", "enroll-one", archive=archive,
                                               evidence=evidence, recover=True)
        self.assertEqual(retained.stat().st_ino, inode)
        self.assertEqual(self.store.seal_generation("cloud", "gen-one", "enroll-one", archive=archive,
                                                   evidence=evidence, recover=True), reference)
        atomic_json(self.root / "instances/cloud/config.json", self.store.descriptor("cloud", reference))
        self.publish({"cloud": {"kind": "managed", "generation": reference, "status": {"state": "ready"}}})

    def test_archive_recovery_validates_all_existing_bytes_before_adding_missing(self):
        instance = self.instance()
        self.store.begin("enroll-one", "enroll", ["cloud"], EXECUTOR)
        write = self.store._write
        def fail_archive(relative, data, **kwargs):
            if relative == "instances/cloud/legacy/files/versions.json":
                raise OSError("injected interrupted archive")
            return write(relative, data, **kwargs)
        with patch.object(self.store, "_write", side_effect=fail_archive), self.assertRaises(OSError):
            self.store.archive_legacy("cloud", "enroll-one")
        atomic_json(instance / "legacy/files/status.json", {"state": "failed"})
        with self.assertRaisesRegex(ValueError, "recovery file"):
            self.store.archive_legacy("cloud", "enroll-one", recover=True)
        self.assertFalse((instance / "legacy/files/versions.json").exists())

    def test_failed_replacement_keeps_prior_complete_graph_until_explicit_retry(self):
        self.instance()
        self.initialize_legacy()
        old_pointer = (self.root / "lifecycle/active.json").read_bytes()
        self.store.begin("status-one", "status", ["cloud"], EXECUTOR)
        entries = self.store.graph(validate_evidence=False)["instances"]
        replace = os.replace
        def fail_active(source, target):
            if Path(target).name == "active.json":
                raise OSError("injected replacement failure")
            return replace(source, target)
        with patch("installer.generations.os.replace", side_effect=fail_active), self.assertRaises(OSError):
            self.store.commit("graph-two", entries, "status-one")
        self.assertEqual((self.root / "lifecycle/active.json").read_bytes(), old_pointer)
        self.assertEqual(self.store.graph(validate_evidence=False)["graph_id"], "graph-one")
        self.publish(entries, "status-one", "graph-two")
        self.assertEqual(self.store.graph()["graph_id"], "graph-two")

    def test_failure_before_active_pointer_keeps_fence_and_allows_explicit_retry(self):
        self.instance()
        self.store.begin("register-one", "register", ["cloud"], EXECUTOR)
        entries = {"cloud": self.store.build_entry("cloud")}
        replace = os.replace
        def fail_active(source, target):
            if Path(target).name == "active.json":
                raise OSError("injected active publication failure")
            return replace(source, target)
        with patch("installer.generations.os.replace", side_effect=fail_active), self.assertRaises(OSError):
            self.store.commit("graph-one", entries, "register-one")
        self.assertTrue(self.store.exists())
        self.assertEqual(self.store.pending()["operation"], "register-one")
        self.assertTrue((self.root / "lifecycle/graphs/graph-one.json").exists())
        with self.assertRaises(ValueError):
            self.store.resolve("cloud")
        self.publish(entries, "register-one")
        self.assertEqual(self.store.resolve("cloud")["status"]["state"], "ready")

    def test_failed_terminal_pointer_write_never_clears_fence_implicitly(self):
        self.instance()
        self.store.begin("register-one", "register", ["cloud"], EXECUTOR)
        self.store.commit("graph-one", {"cloud": self.store.build_entry("cloud")}, "register-one")
        replace = os.replace
        def fail_pending(source, target):
            if Path(target).name == "pending.json":
                raise OSError("injected fence publication failure")
            return replace(source, target)
        with patch("installer.generations.os.replace", side_effect=fail_pending), self.assertRaises(OSError):
            self.store.finish("register-one")
        terminal = self.root / "maintenance/operations/register-one/terminal.json"
        original = terminal.read_bytes()
        self.assertEqual(self.store.pending()["operation"], "register-one")
        with self.assertRaises(ValueError):
            self.store.resolve("cloud")
        self.store.finish("register-one")
        self.assertEqual(terminal.read_bytes(), original)
        self.assertIsNone(self.store.pending())

    def test_snapshot_directory_crash_has_already_durable_plan(self):
        self.instance()
        self.store.begin("enroll-one", "enroll", ["cloud"], EXECUTOR)
        mkdir = self.store._mkdir
        failed = False
        def interrupt(relative):
            nonlocal failed
            result = mkdir(relative)
            if "/archive-cloud/files" in relative and not failed:
                failed = True
                self.assertTrue((self.root / "maintenance/operations/enroll-one/archive-cloud-plan.json").is_file())
                raise OSError("crash after snapshot directory creation")
            return result
        with patch.object(self.store, "_mkdir", side_effect=interrupt), self.assertRaises(OSError):
            self.store.archive_legacy("cloud", "enroll-one")
        archive = self.store.archive_legacy("cloud", "enroll-one", recover=True)
        self.assertTrue((self.root / archive["path"]).is_file())

    def test_retained_unpublished_instance_temporary_does_not_poison_archive(self):
        instance = self.instance()
        temporary = instance / ".pending-interrupted-atomic-write"
        atomic_write(temporary, "unpublished private bytes")
        self.store.begin("enroll-one", "enroll", ["cloud"], EXECUTOR)
        archive = self.store.archive_legacy("cloud", "enroll-one")
        record = json.loads((self.root / archive["path"]).read_text())
        self.assertNotIn(temporary.name, record["files"])
        self.assertEqual(temporary.read_text(), "unpublished private bytes")

    def test_immutable_publication_crash_never_leaves_authoritative_hardlink(self):
        self.instance()
        rename = os.rename
        target = self.root / "instances/cloud/crash-evidence"
        def interrupt(source, destination):
            rename(source, destination)
            if Path(destination) == target:
                raise OSError("crash after rename")
        with patch("installer.generations.os.rename", side_effect=interrupt), self.assertRaises(OSError):
            self.store._write("instances/cloud/crash-evidence", b"exact bytes")
        self.assertEqual(target.stat().st_nlink, 1)
        self.assertEqual(self.store._read("instances/cloud/crash-evidence"), b"exact bytes")

    def test_immutable_records_refuse_overwrite_and_fsync_precedes_publication(self):
        self.instance()
        self.store.begin("enroll-one", "enroll", ["cloud"], EXECUTOR)
        archive = self.store.archive_legacy("cloud", "enroll-one")
        with self.assertRaises(ValueError):
            self.store.archive_legacy("cloud", "enroll-one")
        events = []
        fsync, rename = os.fsync, os.rename
        def sync(fd):
            events.append("directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
            fsync(fd)
        def publish(source, target, **kwargs):
            self.assertEqual(Path(source).stat().st_mode & 0o777, 0o600)
            events.append("publish")
            rename(source, target, **kwargs)
            self.assertEqual(Path(target).stat().st_nlink, 1)
        with patch("installer.generations.os.fsync", side_effect=sync), patch("installer.generations.os.rename", side_effect=publish):
            self.store._write("instances/cloud/test-evidence", b"exact bytes")
        self.assertEqual(events, ["file", "publish", "directory"])
        with self.assertRaises(ValueError):
            self.store._write("instances/cloud/test-evidence", b"replacement")
        self.assertEqual((self.root / archive["path"]).stat().st_nlink, 1)


if __name__ == "__main__":
    unittest.main()
