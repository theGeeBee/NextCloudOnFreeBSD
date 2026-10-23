"""M3 artifact staging: local synthetic bytes only, never native execution."""

from copy import deepcopy
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from installer import maintenance_staging as staging
from installer.state import Registry
from test_state import configuration
from version_fixtures import resolved_plan


class StagingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="stage-")
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        self.source = self.home / "source"
        self.source.mkdir(mode=0o700)
        for name in ("install.sh", "installer/__init__.py", "installer/main.py", *staging._RESOURCES):
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.write_bytes(("public fixture: " + name + "\n").encode())
            path.chmod(0o600)
        self.packages = self.home / "packages"
        self.packages.mkdir(mode=0o700)
        self.plan = resolved_plan(configuration(accept_microsoft_fonts=True))
        for group in self.plan["packages"].values():
            for name, record in group.items():
                raw = ("synthetic archive " + name).encode()
                checksum = hashlib.sha256(raw).hexdigest()
                record["checksum"] = checksum
                path = self.packages / (checksum + ".pkg")
                path.write_bytes(raw)
                path.chmod(0o600)
        self.registry = Registry(self.home / "registry")
        self.registry.initialize()
        self.enterContext(patch.object(staging, "PROJECT_ROOT", self.source))
        # Production requires UID 0. Offline files use the test runner's UID;
        # owner/mode/link checks remain real and there is no public bypass.
        self.enterContext(patch.object(staging, "_ROOT_UID", os.geteuid()))
        self.specs = staging.required_artifacts(self.plan, self.source)
        _, self.source_hash, self.executor_hash = staging._source(self.source)
        self.directory = self.registry.root / "maintenance/operations/stage-test/artifacts"

    def stage(self, **kwargs):
        values = dict(registry=self.registry, versions_plan=self.plan, plan_sha256="a" * 64,
                      source_sha256=self.source_hash, executor_sha256=self.executor_hash)
        values.update(kwargs)
        with self.registry.locked():
            return staging.stage(self.registry.root, "stage-test", self.specs, self.packages,
                                 self.source, **values)

    def package(self):
        return next(item for item in self.specs if item["kind"] == "package")

    def verify(self, receipt, **kwargs):
        bindings = dict(plan_sha256="a" * 64, source_sha256=self.source_hash,
                        executor_sha256=self.executor_hash, versions_plan=self.plan)
        bindings.update(kwargs)
        return staging.verify_stage(self.registry.root, "stage-test", self.specs, receipt, **bindings)

    def test_manifest_binds_complete_deduplicated_closures_and_full_source_paths(self):
        packages = [item for item in self.specs if item["kind"] == "package"]
        merged = {name for group in self.plan["packages"].values() for name in group}
        self.assertEqual({name for item in packages for name in item["packages"]}, merged)
        self.assertEqual(len(packages), len(merged))
        self.assertEqual(sum("fixture-library" in item["packages"] for item in packages), 1)
        self.assertEqual([item["path"] for item in self.specs], sorted(item["path"] for item in self.specs))
        ref = self.stage()
        manifest_path = self.registry.root / ref["path"]
        self.assertEqual(ref["sha256"], hashlib.sha256(manifest_path.read_bytes()).hexdigest())
        manifest = json.loads(manifest_path.read_bytes())
        self.assertTrue(manifest["package_archives_complete"])
        for field in ("execution_authorized", "snapshot_recovery_includes_base_archives",
                      "full_disaster_recovery", "capacity_assured"):
            self.assertIs(manifest[field], False)
        self.assertEqual(len(manifest["artifacts"]), len(self.specs))
        intent = json.loads((self.directory / "intent.json").read_bytes())
        self.assertEqual(intent["plan_sha256"], "a" * 64)
        self.assertEqual(intent["executor_sha256"], self.executor_hash)
        for item in manifest["artifacts"]:
            path = self.directory / item["path"]
            info = path.stat()
            self.assertEqual(info.st_mode & 0o777, 0o600)
            self.assertEqual(info.st_uid, os.geteuid())
            self.assertEqual(info.st_nlink, 1)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), item["sha256"])
        for path in self.directory.rglob("*"):
            if path.is_dir():
                self.assertEqual(path.stat().st_mode & 0o777, 0o700)
        self.assertFalse((self.registry.root / "maintenance/pending.json").exists())

    def test_historical_source_digest_and_executor_are_preserved(self):
        from installer.deploy import source_digest
        with patch("installer.deploy.ROOT", self.source), patch("installer.deploy.RESOURCES", self.source / "resources"):
            self.assertEqual(source_digest(), self.source_hash + "\n")
        expected = hashlib.sha256((self.source_hash + "\n").encode() + (self.source / "install.sh").read_bytes()).hexdigest()
        self.assertEqual(self.executor_hash, expected)
        original = self.source_hash
        (self.source / "install.sh").write_bytes(b"changed shell")
        _, new_source, new_executor = staging._source(self.source)
        self.assertEqual(new_source, original)
        self.assertNotEqual(new_executor, expected)

    def test_source_only_is_explicit_and_does_not_claim_packages_complete(self):
        self.specs = staging.required_artifacts(None, self.source)
        self.assertTrue(all(item["kind"] == "source" for item in self.specs))
        self.packages = self.home / "absent"
        ref = self.stage(versions_plan=None)
        manifest = json.loads((self.registry.root / ref["path"]).read_bytes())
        self.assertFalse(manifest["package_archives_complete"])
        self.assertEqual(self.stage(versions_plan=None), ref)

    def test_assessment_report_and_opaque_manifest_checksums_are_not_locks(self):
        with self.assertRaises(ValueError):
            staging.required_artifacts({"eligible": True, "packages": {}}, self.source)
        plan = resolved_plan(configuration(accept_microsoft_fonts=True))
        with self.assertRaisesRegex(ValueError, "archive SHA256"):
            staging.required_artifacts(plan, self.source)

    def test_missing_dependency_and_conflicting_group_identity_fail(self):
        plan = deepcopy(self.plan)
        del plan["packages"]["host"]["fixture-library"]
        with self.assertRaises(ValueError):
            staging.required_artifacts(plan, self.source)
        plan = deepcopy(self.plan)
        plan["packages"]["host"]["fixture-library"]["checksum"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "Conflicting"):
            staging.required_artifacts(plan, self.source)

    def test_unheld_lock_wrong_root_source_path_and_nonroot_refused(self):
        values = dict(registry=self.registry, versions_plan=self.plan, plan_sha256="a" * 64,
                      source_sha256=self.source_hash, executor_sha256=self.executor_hash)
        with self.assertRaisesRegex(ValueError, "global"):
            staging.stage(self.registry.root, "stage-test", self.specs, self.packages, self.source, **values)
        with self.registry.locked():
            for root, source in ((self.home, self.source), (self.registry.root, self.home)):
                with self.assertRaisesRegex(ValueError, "exact registry"):
                    staging.stage(root, "stage-test", self.specs, self.packages, source, **values)
        with patch.object(staging, "_ROOT_UID", os.geteuid() + 1):
            with self.assertRaisesRegex(ValueError, "requires root"):
                self.stage()
        self.assertFalse(self.directory.exists())

    def test_identifiers_paths_and_spec_bounds(self):
        for operation in ("../escape", "a/escape", "Upper", "-a", "a" * 65, ""):
            with self.registry.locked(), self.assertRaises(ValueError):
                staging.stage(self.registry.root, operation, self.specs, self.packages, self.source,
                              registry=self.registry, versions_plan=self.plan, plan_sha256="a" * 64,
                              source_sha256=self.source_hash, executor_sha256=self.executor_hash)
        staging._id("a" * 64)
        for path in ("../escape", "/absolute", "source/../secrets.json", "source/resources/runtime.json"):
            specs = deepcopy(self.specs)
            specs[0]["path"] = path
            with self.assertRaises(ValueError):
                staging.validate_specs(specs)
        for specs in ([], self.specs[::-1], self.specs + [self.specs[-1]]):
            with self.assertRaises(ValueError):
                staging.validate_specs(specs)
        with patch.object(staging, "MAX_FILES", 1), self.assertRaises(ValueError):
            staging.validate_specs(self.specs)
        with patch.object(staging, "MAX_METADATA_BYTES", 1), self.assertRaises(ValueError):
            staging.validate_specs(self.specs)
        with patch.object(staging, "MAX_SOURCE_BYTES", 1), self.assertRaises(ValueError):
            staging.validate_specs(self.specs)

    def test_private_runtime_and_unknown_source_files_are_rejected(self):
        for name in ("installer/.env", "installer/private.log", "resources/runtime.json",
                     "resources/secrets.json", "resources/templates/onlyoffice/local.json",
                     "resources/jails/private.sh"):
            path = self.source / name
            path.write_bytes(b"must never be copied")
            try:
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, "Non-public"):
                    staging.required_artifacts(self.plan, self.source)
            finally:
                path.unlink()
        self.assertFalse(self.directory.exists())

    def test_pycache_exclusions_and_missing_public_resource(self):
        cache = self.source / "installer/__pycache__"
        cache.mkdir(mode=0o700)
        (cache / "module.pyc").write_bytes(b"bytecode")
        (self.source / "installer/stray.pyc").write_bytes(b"bytecode")
        self.assertEqual(staging.required_artifacts(self.plan, self.source), self.specs)
        (self.source / "resources/versions.json").unlink()
        with self.assertRaisesRegex(ValueError, "incomplete"):
            staging.required_artifacts(self.plan, self.source)

    def test_source_symlinks_hardlinks_and_unsafe_mode_refused(self):
        path = self.source / "installer/main.py"
        data = path.read_bytes()
        outside = self.home / "outside"
        outside.write_bytes(data)
        for kind in ("symlink", "hardlink", "mode"):
            path.unlink()
            if kind == "symlink":
                path.symlink_to(outside)
            elif kind == "hardlink":
                os.link(outside, path)
            else:
                path.write_bytes(data)
                path.chmod(0o666)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                staging.required_artifacts(self.plan, self.source)
        path.unlink()
        path.write_bytes(data)
        alias = self.home / "alias"
        alias.symlink_to(self.source, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "ancestry"):
            staging.required_artifacts(self.plan, alias)

    def test_missing_or_changed_inputs_leave_intent_and_never_fake_completion(self):
        item = self.package()
        path = self.packages / (item["sha256"] + ".pkg")
        raw = path.read_bytes()
        path.unlink()
        with self.assertRaises(FileNotFoundError):
            self.stage()
        self.assertTrue((self.directory / "intent.json").is_file())
        self.assertFalse((self.directory / "manifest.json").exists())
        path.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "exact retained hash"):
            self.stage()
        path.write_bytes(raw)
        self.stage()
        path.unlink()
        with self.assertRaises(FileNotFoundError):
            self.stage()  # Cached bytes do not conceal lost/changed inputs.

    def test_package_symlink_hardlink_and_wrong_modes_rejected(self):
        item = self.package()
        path = self.packages / (item["sha256"] + ".pkg")
        outside = self.home / "archive"
        outside.write_bytes(path.read_bytes())
        for kind in ("symlink", "hardlink", "mode"):
            path.unlink()
            if kind == "symlink":
                path.symlink_to(outside)
            elif kind == "hardlink":
                os.link(outside, path)
            else:
                path.write_bytes(outside.read_bytes())
                path.chmod(0o666)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.stage()
        self.assertFalse((self.directory / "manifest.json").exists())

    def test_identical_retry_preserves_inodes_and_refuses_changed_bindings(self):
        ref = self.stage()
        before = {path: (path.stat().st_ino, path.read_bytes()) for path in self.directory.rglob("*") if path.is_file()}
        with patch.object(staging, "_publish", side_effect=AssertionError("must not rewrite")):
            self.assertEqual(self.stage(), ref)
            for kwargs in ({"plan_sha256": "b" * 64}, {"source_sha256": "b" * 64},
                           {"executor_sha256": "b" * 64}):
                with self.assertRaises(ValueError):
                    self.stage(**kwargs)
        self.assertEqual(before, {path: (path.stat().st_ino, path.read_bytes()) for path in before})

    def test_interrupted_publication_resumes_identical_inputs(self):
        original = staging._publish
        count = 0
        def interrupt(path, writer):
            nonlocal count
            count += 1
            if count == 4:
                raise OSError("simulated interruption")
            return original(path, writer)
        with patch.object(staging, "_publish", side_effect=interrupt), self.assertRaises(OSError):
            self.stage()
        self.assertFalse((self.directory / "manifest.json").exists())
        before = {path: path.stat().st_ino for path in self.directory.rglob("*") if path.is_file()}
        self.stage()
        self.assertTrue(all(path.stat().st_ino == inode for path, inode in before.items()))

    def test_all_existing_members_validated_before_additions(self):
        self.stage()
        item = self.package()
        missing = self.directory / "source/install.sh"
        missing.unlink()
        bad = self.directory / item["path"]
        bad.write_bytes(b"tampered")
        with patch.object(staging, "_publish", side_effect=AssertionError("must not add")):
            with self.assertRaisesRegex(ValueError, "Existing staged artifact changed"):
                self.stage()
        self.assertFalse(missing.exists())

    def test_private_cache_symlink_hardlink_owner_and_modes(self):
        self.stage()
        path = self.directory / "source/install.sh"
        original = path.read_bytes()
        external = self.home / "external"
        external.write_bytes(original)
        for kind in ("symlink", "hardlink", "mode"):
            path.unlink()
            if kind == "symlink":
                path.symlink_to(external)
            elif kind == "hardlink":
                os.link(external, path)
            else:
                path.write_bytes(original)
                path.chmod(0o644)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.stage()
        info = path.lstat()
        fake = SimpleNamespace(st_mode=info.st_mode, st_nlink=1, st_uid=os.geteuid() + 1, st_size=info.st_size)
        with self.assertRaises(ValueError):
            staging._file(fake, staging.MAX_SOURCE_FILE)

    def test_cache_ancestor_symlink_or_public_directory_refused(self):
        self.stage()
        operations = self.registry.root / "maintenance/operations"
        relocated = self.home / "relocated"
        operations.rename(relocated)
        operations.symlink_to(relocated, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.stage()
        operations.unlink()
        relocated.rename(operations)
        operations.chmod(0o755)
        with self.assertRaises(ValueError):
            self.stage()

    def test_missing_intent_unexpected_files_and_changed_manifest_fail_closed(self):
        self.stage()
        unknown = self.directory / "unexpected"
        unknown.write_bytes(b"unknown")
        unknown.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "Unexpected staged"):
            self.stage()
        unknown.unlink()
        manifest = self.directory / "manifest.json"
        raw = manifest.read_bytes()
        manifest.write_bytes(b"{}")
        with self.assertRaisesRegex(ValueError, "Immutable staging inputs changed"):
            self.stage()
        manifest.write_bytes(raw)
        (self.directory / "intent.json").unlink()
        with self.assertRaisesRegex(ValueError, "intent is missing"):
            self.stage()

    def test_completed_manifest_cannot_authorize_replacing_a_missing_member(self):
        self.stage()
        (self.directory / self.package()["path"]).unlink()
        with patch.object(staging, "_publish", side_effect=AssertionError("must not replace")):
            with self.assertRaisesRegex(ValueError, "missing artifacts"):
                self.stage()

    def test_pending_temporaries_are_preserved_never_adopted(self):
        self.stage()
        temporary = self.directory / "packages/.pending-old"
        temporary.write_bytes(b"incomplete")
        temporary.chmod(0o600)
        inode = temporary.stat().st_ino
        self.stage()
        self.assertEqual(temporary.stat().st_ino, inode)
        self.assertEqual(temporary.read_bytes(), b"incomplete")

    def test_cached_source_temporaries_are_validated_retained_and_not_hashed_as_source(self):
        receipt = self.stage()
        temporaries = []
        for parent in ("source", "source/installer", "source/resources/templates/nextcloud"):
            path = self.directory / parent / ".pending-interrupted"
            path.write_bytes(b"unpublished source bytes; never adopt")
            path.chmod(0o600)
            temporaries.append((path, path.stat().st_ino, path.read_bytes()))
        self.assertEqual(self.stage(), receipt)
        self.assertTrue(self.verify(receipt)["package_archives_complete"])
        for path, inode, raw in temporaries:
            self.assertEqual((path.stat().st_ino, path.read_bytes()), (inode, raw))

    def test_cached_source_temporaries_do_not_allow_arbitrary_or_unsafe_files(self):
        receipt = self.stage()
        parent = self.directory / "source/installer"
        for name in ("private.json", ".pending-", ".pending-invalid.name"):
            path = parent / name
            path.write_bytes(b"private")
            path.chmod(0o600)
            try:
                with self.subTest(name=name), self.assertRaises(ValueError):
                    self.verify(receipt)
            finally:
                path.unlink()
        path = parent / ".pending-interrupted"
        target = self.directory / "source/install.sh"
        for kind in ("symlink", "hardlink", "public", "directory"):
            if kind == "symlink":
                path.symlink_to(target)
            elif kind == "hardlink":
                os.link(target, path)
            elif kind == "directory":
                path.mkdir(mode=0o700)
            else:
                path.write_bytes(b"unpublished")
                path.chmod(0o644)
            try:
                with self.subTest(kind=kind), self.assertRaises(ValueError):
                    self.verify(receipt)
            finally:
                path.rmdir() if kind == "directory" else path.unlink()
        # Only the cache has a separately validated temporary inventory.
        live = self.source / "installer/.pending-interrupted"
        live.write_bytes(b"must not silently exclude live source")
        live.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "Non-public source file"):
            staging.required_artifacts(self.plan, self.source)

    def test_source_aggregate_preflight_refuses_before_any_stream(self):
        total = sum(item["size"] for item in self.specs if item["kind"] == "source")
        with patch.object(staging, "MAX_SOURCE_BYTES", total - 1), \
                patch.object(staging, "_stream", side_effect=AssertionError("must size preflight first")):
            with self.assertRaisesRegex(ValueError, "payload bound"):
                staging.required_artifacts(self.plan, self.source)

    def test_source_enumeration_stops_at_count_bound_without_materializing_directory(self):
        consumed = []
        @contextmanager
        def entries(directory):
            def generate():
                for index in range(3):
                    consumed.append(index)
                    yield SimpleNamespace(path=str(self.source / "installer/main.py"))
                raise AssertionError("enumeration continued beyond file count bound")
            yield generate()
        with patch.object(staging, "MAX_FILES", 3), patch.object(staging.os, "scandir", side_effect=entries), \
                patch.object(staging, "_stream", side_effect=AssertionError("must enumerate first")):
            with self.assertRaisesRegex(ValueError, "file count bound"):
                staging.required_artifacts(None, self.source)
        self.assertEqual(consumed, [0, 1, 2])

    def test_source_growth_after_preflight_is_limited_by_remaining_aggregate_budget(self):
        total = sum(item["size"] for item in self.specs if item["kind"] == "source")
        shell = self.source / "install.sh"
        original_size = shell.stat().st_size
        original = staging._stream
        limits = []
        def grow(path, limit, **kwargs):
            if not limits:
                shell.write_bytes(shell.read_bytes() + b"grew after size preflight")
            limits.append((path, limit))
            return original(path, limit, **kwargs)
        with patch.object(staging, "MAX_SOURCE_BYTES", total), patch.object(staging, "_stream", side_effect=grow):
            with self.assertRaisesRegex(ValueError, "byte bound"):
                staging.required_artifacts(None, self.source)
        self.assertEqual(limits[-1], (shell, original_size))

    def test_copy_change_detected_and_stage_recoverable(self):
        original = staging._stream
        item = self.package()
        source = self.packages / (item["sha256"] + ".pkg")
        raw = source.read_bytes()
        def changed(path, *args, **kwargs):
            result = original(path, *args, **kwargs)
            if path == source and kwargs.get("output") is not None:
                source.write_bytes(b"changed while staging")
            return result
        with patch.object(staging, "_stream", side_effect=changed), self.assertRaises(ValueError):
            self.stage()
        self.assertTrue((self.directory / "intent.json").exists())
        self.assertFalse((self.directory / "manifest.json").exists())
        source.write_bytes(raw)
        self.stage()

    def test_streaming_byte_bounds_and_fsync_before_single_link_publication(self):
        input_path = self.home / "stream-input"
        raw = b"abc" * 1000
        input_path.write_bytes(raw)
        writes = []
        class Output(io.BytesIO):
            def write(self, chunk):
                writes.append(len(chunk))
                return super().write(chunk)
        with patch.object(staging, "CHUNK_BYTES", 17):
            self.assertEqual(staging._stream(input_path, len(raw), output=Output()),
                             (hashlib.sha256(raw).hexdigest(), len(raw)))
        self.assertLessEqual(max(writes), 17)
        with self.assertRaises(ValueError):
            staging._stream(input_path, len(raw) - 1)
        events = []
        fsync, rename = os.fsync, os.rename
        def sync(fd):
            events.append("fsync")
            return fsync(fd)
        def publish(source, destination):
            self.assertEqual(events[-1], "fsync")
            self.assertEqual(Path(source).stat().st_nlink, 1)
            self.assertFalse(Path(destination).exists())
            events.append("rename")
            return rename(source, destination)
        with patch.object(staging.os, "fsync", side_effect=sync), patch.object(staging.os, "rename", side_effect=publish):
            with patch.object(Path, "read_bytes", side_effect=AssertionError("must stream")):
                self.stage()
        self.assertIn("rename", events)
        self.assertEqual(events[-1], "fsync")

    def test_count_package_and_total_byte_bounds_fail_before_completion(self):
        with patch.object(staging, "MAX_PACKAGE_BYTES", 1), self.assertRaises(ValueError):
            self.stage()
        with patch.object(staging, "MAX_TOTAL_BYTES", 1), self.assertRaises(ValueError):
            self.stage()
        with patch.object(staging, "MAX_SOURCE_FILE", 1), self.assertRaises(ValueError):
            self.stage()
        self.assertFalse((self.directory / "manifest.json").exists())

    def test_verify_is_read_only_and_needs_no_original_package_or_source_bytes(self):
        receipt = self.stage()
        self.packages.rename(self.home / "packages-unavailable")
        self.source.rename(self.home / "source-unavailable")
        before = {path: (path.stat().st_ino, path.read_bytes())
                  for path in self.directory.rglob("*") if path.is_file()}
        with patch.object(staging, "_publish", side_effect=AssertionError("read-only")), \
                patch.object(staging.Store, "_mkdir", side_effect=AssertionError("read-only")), \
                patch.object(staging.os, "statvfs", side_effect=AssertionError("no capacity claim")):
            manifest = self.verify(receipt)
        self.assertTrue(manifest["package_archives_complete"])
        self.assertFalse(manifest["execution_authorized"])
        self.assertFalse(manifest["capacity_assured"])
        self.assertEqual(before, {path: (path.stat().st_ino, path.read_bytes()) for path in before})
        self.assertFalse(self.registry._locked)

    def test_verify_rehashes_all_artifacts_and_refuses_missing_or_unsafe_members(self):
        receipt = self.stage()
        for item in (self.package(), next(item for item in self.specs if item["kind"] == "source")):
            path = self.directory / item["path"]
            original = path.read_bytes()
            path.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "Existing staged artifact changed"):
                self.verify(receipt)
            path.unlink()
            with self.assertRaisesRegex(ValueError, "missing artifacts"):
                self.verify(receipt)
            path.write_bytes(original)
            path.chmod(0o600)
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            self.verify(receipt)
        path.chmod(0o600)
        link = self.home / "extra-link"
        os.link(path, link)
        with self.assertRaises(ValueError):
            self.verify(receipt)
        link.unlink()
        path.rename(link)
        path.symlink_to(link)
        with self.assertRaises(ValueError):
            self.verify(receipt)

    def test_verify_checks_exact_receipt_intent_manifest_fields_sizes_and_bindings(self):
        receipt = self.stage()
        for kwargs in ({"plan_sha256": "b" * 64}, {"source_sha256": "b" * 64},
                       {"executor_sha256": "b" * 64}, {"versions_plan": None}):
            with self.assertRaises(ValueError):
                self.verify(receipt, **kwargs)
        for changed in ({**receipt, "path": "../manifest.json"},
                        {**receipt, "path": receipt["path"].replace("stage-test", "stage-other")},
                        {**receipt, "sha256": "f" * 64}, {**receipt, "extra": True}):
            with self.assertRaises(ValueError):
                self.verify(changed)
        manifest_path = self.directory / "manifest.json"
        original = manifest_path.read_bytes()
        manifest = json.loads(original)
        modifications = [
            {**manifest, "unexpected": True}, {**manifest, "package_archives_complete": False},
            {**manifest, "execution_authorized": True}, {**manifest, "capacity_assured": True},
            {**manifest, "intent_sha256": "b" * 64}, {**manifest, "operation": "another"},
            {**manifest, "artifacts": manifest["artifacts"][:-1]},
        ]
        altered_sizes = deepcopy(manifest)
        altered_sizes["artifacts"][0]["size"] += 1
        modifications.append(altered_sizes)
        for changed in modifications:
            data = staging._encode(changed)
            manifest_path.write_bytes(data)
            # Updating the receipt hash cannot authorize invented manifest fields.
            with self.assertRaises(ValueError):
                self.verify({**receipt, "sha256": hashlib.sha256(data).hexdigest()})
        manifest_path.write_bytes(original)
        intent_path = self.directory / "intent.json"
        original_intent = intent_path.read_bytes()
        intent = json.loads(original_intent)
        intent["source_root"] = str(self.home / "different")
        intent_path.write_bytes(staging._encode(intent))
        with self.assertRaisesRegex(ValueError, "Immutable staging inputs changed"):
            self.verify(receipt)
        intent_path.write_bytes(original_intent)
        self.assertEqual(self.verify(receipt), manifest)

    def test_verify_source_only_coverage_and_missing_cache_does_not_create_state(self):
        receipt = {"path": "maintenance/operations/stage-test/artifacts/manifest.json", "sha256": "a" * 64}
        with self.assertRaises(FileNotFoundError):
            self.verify(receipt)
        self.assertFalse(self.directory.exists())
        self.specs = staging.required_artifacts(None, self.source)
        receipt = self.stage(versions_plan=None)
        manifest = self.verify(receipt, versions_plan=None)
        self.assertFalse(manifest["package_archives_complete"])

    def test_capacity_preflight_accounts_for_all_missing_bytes_and_metadata(self):
        missing = sum(item["size"] if item["kind"] == "source"
                      else (self.packages / (item["sha256"] + ".pkg")).stat().st_size
                      for item in self.specs)
        capacity = SimpleNamespace(f_frsize=1, f_bavail=missing + 2 * staging.MAX_METADATA_BYTES - 1)
        with patch.object(staging.os, "statvfs", return_value=capacity):
            with self.assertRaisesRegex(ValueError, "Insufficient available staging capacity"):
                self.stage()
        self.assertTrue((self.directory / "intent.json").exists())
        self.assertEqual({path.name for path in self.directory.iterdir()}, {"intent.json"})
        capacity.f_bavail += 1
        with patch.object(staging.os, "statvfs", return_value=capacity):
            receipt = self.stage()
        self.assertFalse(self.verify(receipt)["capacity_assured"])
        # A complete identical replay writes nothing and needs no fresh space.
        with patch.object(staging.os, "statvfs", side_effect=AssertionError("no copies")):
            self.assertEqual(self.stage(), receipt)

    def test_capacity_retry_counts_only_missing_copies(self):
        original = staging._publish
        count = 0
        def interrupt(path, writer):
            nonlocal count
            count += 1
            if count == 4:
                raise OSError("simulated interruption")
            return original(path, writer)
        with patch.object(staging, "_publish", side_effect=interrupt), self.assertRaises(OSError):
            self.stage()
        missing = sum(item["size"] if item["kind"] == "source"
                      else (self.packages / (item["sha256"] + ".pkg")).stat().st_size
                      for item in self.specs if not (self.directory / item["path"]).exists())
        capacity = SimpleNamespace(f_frsize=1, f_bavail=missing + 2 * staging.MAX_METADATA_BYTES)
        with patch.object(staging.os, "statvfs", return_value=capacity):
            self.stage()

    def test_retry_after_crash_before_intent_rename_retains_only_valid_temporaries(self):
        staging.Store(self.registry.root)._mkdir("maintenance/operations/stage-test/artifacts")
        temporary = self.directory / ".pending-original"
        temporary.write_bytes(b"interrupted uncommitted intent; never parse or adopt")
        temporary.chmod(0o600)
        identity = temporary.stat().st_ino, temporary.read_bytes()
        receipt = self.stage()
        self.assertEqual((temporary.stat().st_ino, temporary.read_bytes()), identity)
        self.verify(receipt)

    def test_orphan_temporaries_require_private_regular_single_link_bounded_files(self):
        staging.Store(self.registry.root)._mkdir("maintenance/operations/stage-test/artifacts")
        temporary = self.directory / ".pending-original"
        outside = self.home / "outside"
        outside.write_bytes(b"uncommitted")
        outside.chmod(0o600)
        for kind in ("symlink", "hardlink", "mode", "directory", "bounds"):
            if kind == "symlink":
                temporary.symlink_to(outside)
            elif kind == "hardlink":
                os.link(outside, temporary)
            elif kind == "directory":
                temporary.mkdir(mode=0o700)
            else:
                temporary.write_bytes(b"uncommitted")
                temporary.chmod(0o644 if kind == "mode" else 0o600)
            try:
                with self.subTest(kind=kind):
                    if kind == "bounds":
                        with patch.object(staging, "MAX_METADATA_BYTES", 1), self.assertRaises(ValueError):
                            staging._orphan_temporaries(self.directory)
                    else:
                        with self.assertRaises(ValueError):
                            self.stage()
                    self.assertFalse((self.directory / "intent.json").exists())
            finally:
                if kind == "directory":
                    temporary.rmdir()
                else:
                    temporary.unlink()


if __name__ == "__main__":
    unittest.main()
