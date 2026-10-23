"""Offline fault tests. All native commands/locks/storage observations are fake."""

from dataclasses import asdict, replace
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from installer import maintenance_update as adapter, nextcloud_update as update
from installer import maintenance_journal
from installer.generations import Store, _encode, _json
from installer.maintenance_native import NativeContext
from installer.maintenance_state import NativeView
from test_maintenance_preflight import inputs
from version_fixtures import resolved_plan


class Fixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="maintenance-update-")
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        self.root = self.home / "jail"
        self.root.mkdir(mode=0o700)
        self.enterContext(patch.object(update, "_ROOT_UID", os.geteuid()))
        self.n = object.__new__(NativeContext)
        n = self.n
        n.operation = "execution-one"
        n.directory = "maintenance/operations/" + n.operation
        self.store = n.store = Store(self.home / "state")
        n.store.root.mkdir(mode=0o700)
        n.store._mkdir(n.directory)
        n.store._put(n.directory + "/intent.json", {"operation": n.operation})
        n.journal = SimpleNamespace(path=n.directory + "/native-journal.json")
        n.store._put(n.journal.path, {"immutable-start-permission": "fixture"})
        n.native = SimpleNamespace(store=n.store)
        n.c = inputs()[0]
        n.c.instance = "test"
        n.c.php_memory_mb, n.c.php_budget_mb, n.c.host_reserved_mb = 1024, 3072, 1024
        config = n.store._put(n.directory + "/config.json", json.loads(n.c.to_json()))
        versions = resolved_plan(n.c, nextcloud="35.0.1")
        version_ref = n.store._put(n.directory + "/versions.json", versions)
        n.admission = {"evidence": n.store._put(n.directory + "/admission-evidence.json", {"review": "fixture"})}
        self.inputs = {"recipe": adapter.descriptor(), "originals": {"test": {"files": {
            "config.json": {"retained": config}, "versions.json": {"retained": version_ref}}}}}
        self.capture = {"phase": "capture", "steps": {}, "evidence": {}}
        self.journal = self.capture
        n.check = Mock(side_effect=lambda **kw: ({}, self.inputs, self.journal))
        self.jids = {"testnc": 41, "testoo": 42}
        n.d = SimpleNamespace(registry=NativeView(n.native, n.operation), versions=versions,
            require_running_jail=lambda jail: self.jids[jail], jail_root=lambda jail: self.root,
            require_original_artifact=Mock())
        n.backend = SimpleNamespace(owned_live=Mock(), closed_flags=Mock(), wait_writer_closure=Mock(),
             jailed=Mock(side_effect=lambda jail, *args: SimpleNamespace(
                 stdout=str(os.getegid() if args == ("id", "-g", "www") else os.geteuid()))),
             stop=Mock(), running=Mock(return_value=[]),
            output=Mock(side_effect=lambda *args: "4096" if args[-1] == "hw.pagesize" else "10485760"))
        self.runner = Mock(return_value=update.NativeResult(0))
        self.authority = adapter.RealAuthority(n, runner=self.runner)
        self.context = self.authority.context
        self.source_files = {"occ": b"occ", "version.php": b"source version", "lib/core.php": b"source core",
            "updater/updater.phar": b"source updater", "config/config.sample.php": b"sample"}
        self.target_files = dict(self.source_files, **{"lib/core.php": b"target core", "version.php": b"target version"})
        self.source = self.inventory(self.source_files)
        self.target = self.inventory(self.target_files)
        for name, data in self.source_files.items():
            self.write(self.context.host(update.APP + "/" + name), data)
        self.write(self.context.host(update.APP + "/config/config.php"), b"private fixture")
        self.write(self.context.host(update.APP + "/custom_apps/onlyoffice/lib.php"), b"connector bytes")
        self.bundle = update.StagedUpdate(n.operation, update.SourceReference("a" * 64, "b" * 64),
            (update.FileHash("nextcloud-35.0.2.zip", 100, "c" * 64),), self.source, self.target, "c2ln", "d" * 64)

    @staticmethod
    def inventory(files):
        return update.Inventory(tuple(update.FileHash(name, len(data), hashlib.sha256(data).hexdigest())
                                      for name, data in sorted(files.items())), ())

    def write(self, path, data):
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o600)

    def closed(self):
        ref = self.n.store._put(self.n.directory + "/manifest.json", {"capture": "fixture"})
        self.journal = {"phase": "migrating", "steps": {"reviewed-migration": {
            "state": "running", "replay": "never", "attempts": 1, "phase": "migrating", "precondition": ref}},
            "evidence": {"recovery_set": ref}}
        self.enterContext(patch.object(self.authority, "_recovery", return_value=ref))


class AuthorityTests(Fixture):
    def test_legacy_prepared_bundle_without_empty_links_remains_bound(self):
        legacy = asdict(self.bundle)
        for field in ("source_inventory", "target_inventory"):
            legacy[field].pop("links")
        self.authority.bundle = self.bundle
        self.authority.prepared = {"bundle": json.loads(_encode(legacy))}
        self.authority.artifacts(self.context, self.bundle)
        self.assertNotIn("links", self.authority.prepared["bundle"]["source_inventory"])
        self.assertEqual(self.authority.prepared["bundle"], json.loads(_encode(legacy)))

    def test_original_validates_complete_plan_with_pkgbase_keys(self):
        self.assertIn("pkgbase_keys", self.n.d.versions["target"])
        self.assertNotEqual(self.n.d.versions["target"], adapter.recipe()["target"])
        self.authority._original()

    def test_original_refuses_changed_target_and_invalid_complete_policy(self):
        original = deepcopy(self.n.d.versions)
        for field, value in (("release", "15.0-RELEASE"), ("architecture", "aarch64"),
                             ("abi", "FreeBSD:15:aarch64"), ("pkgbase_keys", ["/unreviewed/key"])):
            with self.subTest(field=field):
                changed = deepcopy(original)
                changed["target"][field] = value
                self.n.d.versions = changed
                self.inputs["originals"]["test"]["files"]["versions.json"]["retained"] = self.store._put(
                    self.n.directory + "/versions.json", changed, replace=True)
                with self.assertRaises(ValueError):
                    self.authority._original()
        changed = deepcopy(original)
        changed["policy_sha256"] = "0" * 64
        self.n.d.versions = changed
        self.inputs["originals"]["test"]["files"]["versions.json"]["retained"] = self.store._put(
            self.n.directory + "/versions.json", changed, replace=True)
        with self.assertRaises(ValueError):
            self.authority._original()

    def test_fixed_descriptor_is_not_catalog_authority(self):
        value = adapter.descriptor()
        self.assertEqual(value, adapter.recipe())
        self.assertEqual(value["source"]["internal"], "35.0.1.1")
        self.assertEqual(value["destination"]["internal"], "35.0.2.2")
        self.assertEqual(value["native_acceptance"], "not-run")
        self.assertEqual(maintenance_journal.REVIEWED_NATIVE_RECIPES, {})
        value["source"]["internal"] = "wrong"
        self.assertEqual(adapter.descriptor()["source"]["internal"], "35.0.1.1")

    def test_original_view_and_recipe_are_required(self):
        self.n.d.registry = SimpleNamespace()
        with self.assertRaises(adapter.PrerequisiteError):
            adapter.RealAuthority(self.n, runner=self.runner)
        self.n.d.registry = NativeView(self.n.native, "execution-other")
        with self.assertRaises(adapter.PrerequisiteError):
            adapter.RealAuthority(self.n, runner=self.runner)
        self.n.d.registry = NativeView(self.n.native, self.n.operation)
        self.inputs["recipe"]["destination"]["internal"] = "35.0.3.1"
        with self.assertRaises(adapter.PrerequisiteError):
            adapter.RealAuthority(self.n, runner=self.runner)

    def test_lock_failure_precedes_native_runner(self):
        self.n.check.side_effect = ValueError("lost database lock")
        with self.assertRaises(ValueError):
            self.authority.validate(self.context, update.Phase.ARTIFACTS)
        self.runner.assert_not_called()

    def test_staging_requires_original_running_pair_and_capture_phase(self):
        self.authority.validate(self.context, update.Phase.ARTIFACTS)
        self.closed()
        with self.assertRaises(adapter.PrerequisiteError):
            self.authority.validate(self.context, update.Phase.ARTIFACTS)
        self.journal = self.capture
        self.jids["testoo"] += 1
        with self.assertRaises(adapter.PrerequisiteError):
            self.authority.validate(self.context, update.Phase.ARTIFACTS)

    def test_pair_change_on_runner_failure_is_checked(self):
        def fail(*args, **kwargs):
            self.jids["testoo"] += 1
            raise RuntimeError("private command failure")
        self.runner.side_effect = fail
        with self.assertRaisesRegex(adapter.PrerequisiteError, "pair-identity-changed"):
            self.authority._run(("/usr/sbin/jexec", "41", "php"))

    def test_migration_requires_exact_phase_and_never_replay_outer_step(self):
        self.closed()
        self.authority.validate(self.context, update.Phase.CONFIG)
        self.n.check.assert_any_call(closed=True)
        for key, value in (("state", "complete"), ("attempts", 2), ("replay", "idempotent"), ("phase", "validating")):
            step = self.journal["steps"]["reviewed-migration"]
            prior = step[key]
            step[key] = value
            with self.assertRaises(adapter.PrerequisiteError):
                self.authority.validate(self.context, update.Phase.CONFIG)
            step[key] = prior
        self.journal["phase"] = "validating"
        with self.assertRaises(adapter.PrerequisiteError):
            self.authority.validate(self.context, update.Phase.CONFIG)

    def test_checkpoints_never_mutate_native_journal_and_never_replay(self):
        original = self.n.store.reference(self.n.journal.path)
        self.authority.checkpoint(self.context, "updater", "before", "a" * 64)
        with self.assertRaisesRegex(adapter.PrerequisiteError, "effect-already-attempted"):
            self.authority.checkpoint(self.context, "updater", "before", "a" * 64)
        self.authority.checkpoint(self.context, "updater", "after", "a" * 64)
        self.assertEqual(self.n.store.reference(self.n.journal.path), original)
        progress = _json(self.n.store._read(self.n.directory + "/update-progress.json"))
        self.assertEqual(progress["kind"], "nextcloud-update-progress")
        self.assertEqual(_json(self.n.store._bound(progress["effect"]))["state"], "after")
        with self.assertRaisesRegex(adapter.PrerequisiteError, "effect-already-attempted"):
            self.authority.checkpoint(self.context, "updater", "before", "a" * 64)

    def test_crash_after_before_record_does_not_make_effect_replayable(self):
        real = self.n.store._put
        def fail_progress(path, *args, **kwargs):
            if path.endswith("update-progress.json"):
                raise OSError("simulated fsync failure")
            return real(path, *args, **kwargs)
        with patch.object(self.n.store, "_put", side_effect=fail_progress):
            with self.assertRaises(OSError):
                self.authority.checkpoint(self.context, "code-writable", "before", "a" * 64)
        with self.assertRaisesRegex(adapter.PrerequisiteError, "effect-already-attempted"):
            self.authority.checkpoint(self.context, "code-writable", "before", "a" * 64)

    def test_after_requires_matching_before_binding(self):
        self.authority.checkpoint(self.context, "updater", "before", "a" * 64)
        with self.assertRaisesRegex(adapter.PrerequisiteError, "effect-binding-changed"):
            self.authority.checkpoint(self.context, "updater", "after", "b" * 64)

    def test_real_free_memory_and_zip_memory_are_required(self):
        with patch.object(adapter.os, "statvfs", return_value=SimpleNamespace(f_bavail=10000000, f_frsize=4096)):
            self.authority.capacity(100)
            with self.assertRaisesRegex(adapter.PrerequisiteError, "updater-memory-budget"):
                self.authority.capacity(1024 ** 3)
            self.n.backend.output.side_effect = lambda *args: "4096" if args[-1] == "hw.pagesize" else "1"
            with self.assertRaisesRegex(adapter.PrerequisiteError, "actual-free-memory-insufficient"):
                self.authority.capacity(100)

    def test_missing_signed_source_helper_fails_before_native_checks(self):
        def old_helper(context, *, target_zip, target_asc, target_sig, public_key):
            self.fail("unsigned-source helper must not run")
        with patch.object(update, "stage_artifacts", old_helper), patch.object(adapter, "RealAuthority") as authority:
            with self.assertRaisesRegex(adapter.PrerequisiteError, "signed-source-staging-helper-required"):
                adapter.prepare(self.n, target_zip="zip", target_asc="asc", target_sig="sig",
                                source_asc="source.asc", public_key="key", runner=self.runner)
            authority.assert_not_called()

    def test_bounded_runner_is_an_explicit_prerequisite(self):
        with self.assertRaisesRegex(adapter.PrerequisiteError, "bounded-native-runner-required"):
            adapter.RealAuthority(self.n, runner=None)

    def test_actual_packages_and_loaded_fpm_modules_are_observed(self):
        from test_maintenance_preflight import inputs
        from installer import enrollment, runtime_inventory
        _, retained, observations, _, _ = inputs()
        self.n.d.versions = retained
        self.store._mkdir("instances/test")
        self.store._put("instances/test/inventory.json", {"fixture": "retained inventory"})
        def rows(group):
            return "\n".join(" ".join(item[key] for key in ("name", "version", "origin"))
                             for item in observations["packages"][group])
        self.n.d.runner = SimpleNamespace(output=Mock(side_effect=lambda *args: rows("host")))
        self.n.d.jail = Mock(side_effect=lambda jail, *args, **kw:
            SimpleNamespace(stdout=rows("nextcloud" if jail == "testnc" else "onlyoffice")))
        status = dict(installed=True, maintenance=True, needsDbUpgrade=False, version="35.0.1.1", versionstring="35.0.1")
        apps = {"enabled": {"onlyoffice": "10.2.1"}, "disabled": {}}
        self.n.backend.occ = Mock(side_effect=lambda command, *args: json.dumps(status if command == "status" else apps))
        self.n.backend.jailed.side_effect = None
        self.n.backend.jailed.return_value = SimpleNamespace(stdout="12.3.3-MariaDB")
        with patch.object(enrollment, "_packages", return_value={"nextcloud": "a" * 64, "onlyoffice": "b" * 64}), \
                patch.object(runtime_inventory, "collect_php", return_value=observations["php"]):
            value = adapter._runtime(self.authority)
            self.assertEqual(value["php"], observations["php"])
            self.assertEqual(set(value["full_packages"]), {"host", "nextcloud", "onlyoffice"})
            observations["php"]["callback_fpm"]["loaded_modules"].remove("openssl")
            with self.assertRaises(ValueError):
                adapter._runtime(self.authority)

    def test_recovery_manifest_reference_cannot_be_substituted(self):
        self.closed()
        self.store._mkdir(self.n.directory + "/recovery")
        self.store._put(self.n.directory + "/recovery/manifest.json", {"different": "capture"})
        # Use the actual recovery validator entrypoint, before its native calls.
        with self.assertRaises(adapter.PrerequisiteError):
            adapter.RealAuthority._recovery(self.authority, self.journal)


class PermissionsTests(Fixture):
    def source_with_alias(self):
        target, alias = "dist/bundle.js.license", "dist/bundle.js.map.license"
        self.source_files[target] = b"license fixture"
        self.write(self.context.host(update.APP + "/" + target), self.source_files[target])
        self.context.host(update.APP + "/" + alias).symlink_to("bundle.js.license")
        digest = hashlib.sha256(json.dumps({alias: "bundle.js.license"}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.enterContext(patch.object(update, "SOURCE_ALIASES_SHA256", digest))
        self.source = replace(self.inventory(self.source_files), links=(update.LicenseAlias(alias, "bundle.js.license"),))
        return alias, target

    def test_source_alias_is_pinned_without_following_and_target_remains_regular(self):
        alias, target = self.source_with_alias()
        observed = adapter._code(self.context, self.source)
        self.assertEqual(observed["links"][alias]["target"], "bundle.js.license")
        self.assertIn(target, observed["files"])
        self.assertNotIn(alias, observed["files"])
        self.context.host(update.APP + "/custom_apps/onlyoffice/license.license").symlink_to("lib.php")
        with self.assertRaises((update.UpdateError, OSError)):
            adapter._custom(self.context)
        with self.assertRaises((update.UpdateError, OSError)):
            adapter._code(self.context, replace(self.source, links=()))

    def test_alias_is_never_a_permission_target_and_retargeting_is_refused(self):
        calls = self.allow_batch()
        alias, target = self.source_with_alias()
        link = self.context.host(update.APP + "/" + alias)
        before = link.lstat()
        adapter._permissions(self.authority, self.source, writable=True)
        self.assertNotIn(str(link), {name for name, _, _ in calls})
        self.assertIn(str(self.context.host(update.APP + "/" + target)), {name for name, _, _ in calls})
        self.assertEqual(update._identity(link.lstat()), update._identity(before))
        link.unlink()
        link.symlink_to("../outside.license")
        with self.assertRaisesRegex(adapter.PrerequisiteError, "source-alias-drift"):
            adapter._code(self.context, self.source)

    def test_regular_file_cannot_replace_expected_source_alias(self):
        alias, _ = self.source_with_alias()
        link = self.context.host(update.APP + "/" + alias)
        link.unlink()
        link.write_bytes(b"license fixture")
        with self.assertRaisesRegex(adapter.PrerequisiteError, "source-alias-not-link"):
            adapter._code(self.context, self.source)

    def test_alias_race_is_refused_and_target_inventory_accepts_only_regular_replacement(self):
        alias, _ = self.source_with_alias()
        link = self.context.host(update.APP + "/" + alias)
        original = os.readlink
        def raced(name, **kwargs):
            result = original(name, **kwargs)
            link.unlink()
            link.symlink_to("different.license")
            return result
        with patch.object(adapter.os, "readlink", side_effect=raced):
            with self.assertRaisesRegex(adapter.PrerequisiteError, "source-alias-drift-or-race"):
                adapter._code(self.context, self.source)
        link.unlink()
        link.write_bytes(b"license fixture")
        target = self.inventory(dict(self.source_files, **{alias: b"license fixture"}))
        observed = adapter._code(self.context, target)
        self.assertNotIn("links", observed)
        self.assertIn(alias, observed["files"])

    def test_alias_hardening_requires_exact_root_group_and_link_mode(self):
        alias, _ = self.source_with_alias()
        observed = adapter._code(self.context, self.source)
        for value in observed["files"].values():
            value.update(uid=update._ROOT_UID, gid=self.context.www_gid, mode=value["expected_mode"])
        for name in observed["directories"]:
            observed["directories"][name] = [update._ROOT_UID, self.context.www_gid, 0o750]
        observed["links"][alias].update(uid=update._ROOT_UID, gid=self.context.www_gid, mode=0o777)
        for mode in (0o700, 0o777):
            observed["links"][alias]["mode"] = mode
            adapter._hardened(self.context, observed)
        for mode in (0o600, 0o750, 0o775):
            observed["links"][alias]["mode"] = mode
            with self.assertRaisesRegex(adapter.PrerequisiteError, "source-alias-not-hardened"):
                adapter._hardened(self.context, observed)
        observed["links"][alias]["mode"] = 0o700
        observed["links"][alias]["gid"] += 1
        with self.assertRaisesRegex(adapter.PrerequisiteError, "source-alias-not-hardened"):
            adapter._hardened(self.context, observed)

    def test_generated_htaccess_keeps_full_live_hash_and_is_permission_checked(self):
        self.allow_batch()
        stock = b"Options -Indexes\n"
        content = stock + update.HTACCESS_ROOT_SUFFIX
        self.source_files[".htaccess"] = stock
        inventory = self.inventory(self.source_files)
        path = self.context.host(update.APP + "/.htaccess")
        self.write(path, content)
        observed = adapter._code(self.context, inventory)
        self.assertEqual(observed["files"][".htaccess"]["sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual(observed["files"][".htaccess"]["size"], len(content))
        adapter._permissions(self.authority, inventory, writable=True)
        self.assertEqual(path.read_bytes(), content)
        self.assertEqual(path.stat().st_mode & 0o777, 0o640)
        path.write_bytes(content + b"unknown")
        with self.assertRaisesRegex(adapter.PrerequisiteError, "code-byte-drift"):
            adapter._code(self.context, inventory)

    def allow_batch(self):
        self.enterContext(patch.object(self.authority, "validate"))
        calls = []
        def chown(fd, uid, gid):
            calls.append((os.readlink("/proc/self/fd/" + str(fd)), uid, gid))
        self.enterContext(patch.object(adapter.os, "fchown", side_effect=chown))
        return calls

    def test_only_manifest_code_paths_and_root_become_writable(self):
        calls = self.allow_batch()
        protected = adapter._custom(self.context)
        config = adapter._config_metadata(self.context)
        sample = self.context.host(update.APP + "/config/config.sample.php").stat()
        adapter._permissions(self.authority, self.source, writable=True)
        expected = {str(self.context.host(update.APP + "/" + item.path)) for item in self.source.files
                    if not adapter._protected(item.path)}
        expected |= {str(self.context.host(update.APP + ("/" + name if name else "")))
                     for name in adapter._directories(self.source) if not adapter._protected(name)}
        self.assertEqual({path for path, _, _ in calls}, expected)
        self.assertTrue(all(uid == self.context.www_uid for _, uid, _ in calls))
        self.assertEqual(adapter._custom(self.context), protected)
        self.assertEqual(adapter._config_metadata(self.context), config)
        self.assertEqual(self.context.host(update.APP + "/config/config.sample.php").stat(), sample)
        self.assertEqual(stat.S_IMODE(self.context.host(update.APP).stat().st_mode), 0o750)
        with self.assertRaisesRegex(adapter.PrerequisiteError, "effect-already-attempted"):
            adapter._permissions(self.authority, self.source, writable=True)

    def test_target_hardening_requires_target_bytes_and_keeps_custom_tree(self):
        calls = self.allow_batch()
        with self.assertRaisesRegex(adapter.PrerequisiteError, "code-byte-drift"):
            adapter._permissions(self.authority, self.target, writable=False)
        self.assertEqual(calls, [])
        for name, data in self.target_files.items():
            self.write(self.context.host(update.APP + "/" + name), data)
        protected = adapter._custom(self.context)
        adapter._permissions(self.authority, self.target, writable=False)
        self.assertEqual(adapter._custom(self.context), protected)
        self.assertTrue(all(uid == update._ROOT_UID for _, uid, _ in calls))
        self.assertEqual(stat.S_IMODE(self.context.host(update.APP + "/lib/core.php").stat().st_mode), 0o640)

    def test_permissions_derive_execute_bits_only_from_inventory(self):
        self.allow_batch()
        inventory = replace(self.source, files=tuple(replace(item, executable=item.path == "occ")
                                                    for item in self.source.files))
        # An unexpected live execute bit must not be carried into hardened code.
        self.context.host(update.APP + "/lib/core.php").chmod(0o750)
        for writable in (True, False):
            adapter._permissions(self.authority, inventory, writable=writable)
            self.assertEqual(stat.S_IMODE(self.context.host(update.APP + "/occ").stat().st_mode), 0o750)
            self.assertEqual(stat.S_IMODE(self.context.host(update.APP + "/lib/core.php").stat().st_mode), 0o640)
        adapter._hardened(self.context, adapter._code(self.context, inventory))

    def test_source_hardening_rejects_execute_bit_drift_in_either_direction(self):
        self.allow_batch()
        inventory = replace(self.source, files=tuple(replace(item, executable=item.path == "occ")
                                                    for item in self.source.files))
        adapter._permissions(self.authority, inventory, writable=False)
        adapter._hardened(self.context, adapter._code(self.context, inventory))
        for name, mode, restored in (("occ", 0o640, 0o750), ("lib/core.php", 0o750, 0o640)):
            with self.subTest(name=name):
                path = self.context.host(update.APP + "/" + name)
                path.chmod(mode)
                with self.assertRaisesRegex(adapter.PrerequisiteError, "code-not-hardened"):
                    adapter._hardened(self.context, adapter._code(self.context, inventory))
                path.chmod(restored)

    def test_interrupted_chown_stops_for_recovery(self):
        self.allow_batch()
        with patch.object(adapter.os, "fchown", side_effect=OSError("interrupted permission change")):
            with self.assertRaises(OSError):
                adapter._permissions(self.authority, self.source, writable=True)
        with self.assertRaisesRegex(adapter.PrerequisiteError, "effect-already-attempted"):
            adapter._permissions(self.authority, self.source, writable=True)
        self.assertFalse(self.n.store._present(self.n.directory + "/update-code-writable-after.json"))

    def test_hardlink_and_symlink_code_refused_before_chown(self):
        calls = self.allow_batch()
        code = self.context.host(update.APP + "/lib/core.php")
        saved = self.home / "saved"
        saved.write_bytes(self.source_files["lib/core.php"])
        saved.chmod(0o600)
        code.unlink()
        for linked in (False, True):
            if linked:
                code.symlink_to(saved)
            else:
                os.link(saved, code)
            with self.assertRaises((ValueError, OSError)):
                adapter._permissions(self.authority, self.source, writable=True)
            code.unlink()
        self.assertEqual(calls, [])

    def test_symlink_in_ancestor_and_protected_root_are_refused(self):
        path = self.context.host(update.APP + "/lib")
        path.rename(path.with_name("saved-lib"))
        path.symlink_to(path.with_name("saved-lib"), target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            adapter._code(self.context, self.source)
        path.unlink()
        path.with_name("saved-lib").rename(path)
        custom = self.context.host(update.APP + "/custom_apps")
        custom.rename(self.home / "custom")
        custom.symlink_to(self.home / "custom", target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            adapter._code(self.context, self.source)

    def test_extra_code_and_empty_directories_are_not_adopted(self):
        calls = self.allow_batch()
        extra = self.context.host(update.APP + "/extra.php")
        self.write(extra, b"unmanaged")
        with self.assertRaisesRegex(adapter.PrerequisiteError, "unexpected-or-missing-code"):
            adapter._permissions(self.authority, self.source, writable=True)
        extra.unlink()
        self.context.host(update.APP + "/extra").mkdir(mode=0o700)
        with self.assertRaisesRegex(adapter.PrerequisiteError, "unexpected-code-directory"):
            adapter._permissions(self.authority, self.source, writable=True)
        self.assertEqual(calls, [])

    def test_hash_is_rechecked_immediately_before_chown(self):
        calls = self.allow_batch()
        real = self.authority.checkpoint
        def race(context, event, state, binding):
            real(context, event, state, binding)
            if state == "before":
                self.context.host(update.APP + "/lib/core.php").write_bytes(b"tampered")
        with patch.object(self.authority, "checkpoint", side_effect=race):
            with self.assertRaisesRegex(adapter.PrerequisiteError, "code-byte-drift"):
                adapter._permissions(self.authority, self.source, writable=True)
        self.assertNotIn(str(self.context.host(update.APP + "/lib/core.php")), [path for path, _, _ in calls])

    def test_entire_custom_manifest_detects_unlisted_files_and_bytes(self):
        before = adapter._custom(self.context)
        self.write(self.context.host(update.APP + "/custom_apps/onlyoffice/nested/extra.php"), b"new")
        self.assertNotEqual(adapter._custom(self.context), before)
        self.write(self.context.host(update.APP + "/custom_apps/other/hidden.php"), b"unknown")
        with self.assertRaisesRegex(adapter.PrerequisiteError, "unreviewed-custom-app"):
            adapter._custom(self.context)


class WorkflowTests(Fixture):
    def setUp(self):
        super().setUp()
        from test_nextcloud_update import version
        self.source_files["version.php"] = version(*update.SOURCE)
        self.target_files["version.php"] = version(*update.TARGET)
        self.source = self.inventory(self.source_files)
        self.target = self.inventory(self.target_files)
        for name, data in self.source_files.items():
            self.write(self.context.host(update.APP + "/" + name), data)
        for name in adapter._directories(self.source):
            if not adapter._protected(name):
                self.context.host(update.APP + ("/" + name if name else "")).chmod(0o750)
        for item in self.source.files:
            if not adapter._protected(item.path):
                self.context.host(update.APP + "/" + item.path).chmod(0o640)
        self.n.registry = SimpleNamespace(root=self.store.root)
        self.parent = dict(operation="maint-one", plan=self.n.store._put("maintenance/plan.json", {"plan": "fixture"}))
        self.store._mkdir("maintenance/operations/maint-one")
        preparation = self.store._put("maintenance/operations/maint-one/operation.json", self.parent)
        self.inputs.update(preparation=preparation, cache_owner="maint-one")
        self.runtime = dict(packages={"nextcloud": "a" * 64, "onlyoffice": "b" * 64}, full_packages={"fixture": []},
            php={"fixture": "actual modules"}, database="12.3.3-MariaDB",
            apps={"enabled": {"onlyoffice": "10.2.1"}, "disabled": {}},
            status=dict(installed=True, maintenance=False, needsDbUpgrade=False, version="35.0.1.1", versionstring="35.0.1"))
        self.store._put(self.n.directory + "/source-observations.json", dict(packages=self.runtime["packages"],
            php=self.runtime["php"], database=self.runtime["database"], apps_sha256=adapter._hash(self.runtime["apps"])))
        self.setting = update.AppStoreSetting(False, False)
        self.updater_calls = 0
        self.runner.side_effect = self.command
        self.enterContext(patch.object(adapter.RealAuthority, "capacity"))
        self.enterContext(patch.object(adapter.RealAuthority, "_recovery", return_value={"capture": "fixture"}))
        self.enterContext(patch.object(adapter.os, "fchown"))
        self.runtime_mock = self.enterContext(patch.object(adapter, "_runtime", side_effect=self.observation))
        self.enterContext(patch.object(adapter, "_package_observations", side_effect=lambda authority:
            (self.runtime["packages"], self.runtime["full_packages"])))
        from installer import maintenance_operations, maintenance_staging
        self.enterContext(patch.object(maintenance_operations, "load_operation", return_value=(
            self.parent, {"artifacts": []}, SimpleNamespace(read=lambda: {"phase": "staged", "evidence": {"artifacts": {}}}))))
        self.enterContext(patch.object(maintenance_operations, "_artifact_bindings", return_value={}))
        self.stage_verified = self.enterContext(patch.object(maintenance_staging, "verify_stage"))
        self.staging_calls = []
        self.enterContext(patch.object(update, "stage_artifacts", self.staged_helper))
        self.target_zip = self.home / "target.zip"
        self.write(self.target_zip, b"synthetic artifact bytes")
        self.context.host(update.STAGING).parent.mkdir(parents=True, mode=0o700)
        self.fpm_running = True
        self.n.backend.running.side_effect = lambda jail, service: self.fpm_running if service == "php_fpm" else False
        self.n.backend.stop.side_effect = self.stop_service
        self.n.backend.jailed.side_effect = self.jailed_command

    def stop_service(self, jail, service):
        if service == "php_fpm":
            self.fpm_running = False

    def jailed_command(self, jail, *args):
        if args == ("service", "php_fpm", "onestart"):
            self.fpm_running = True
        return SimpleNamespace(stdout=str(os.getegid() if args == ("id", "-g", "www") else os.geteuid()))

    def closed(self):
        super().closed()
        self.fpm_running = False

    def observation(self, authority, *, target=False):
        self.assertTrue(self.fpm_running, "Runtime inventory must query actual running FPM pools")
        result = json.loads(json.dumps(self.runtime))
        result["status"]["maintenance"] = self.journal["phase"] != "capture"
        if target:
            result["status"].update(version="35.0.2.2", versionstring="35.0.2")
        return result

    def staged_helper(self, context, *, target_zip, target_asc, target_sig, source_asc, public_key):
        # Signature authentication belongs to nextcloud_update's separate tests;
        # this fixture exercises the real authority/receipt/primitive integration.
        self.staging_calls.append((context.operation, source_asc))
        context.authority.validate(context, update.Phase.ARTIFACTS)
        context.authority.checkpoint(context, "stage-artifacts", "before", "a" * 64)
        directory = context.host(context.stage)
        update._mkdir(directory)
        artifacts = (update._create(directory, "nextcloud-35.0.2.zip", source=target_zip),
                     update._create(directory, "nextcloud-35.0.2.zip.sig", data=b"c2ln"))
        receipt = update._create(directory, "receipt.json", data=b'{"fixture":"staged"}')
        bundle = update.StagedUpdate(context.operation, update.SourceReference("a" * 64, "b" * 64), artifacts,
                                    self.source, self.target, "c2ln", receipt.sha256)
        context.authority.checkpoint(context, "stage-artifacts", "after", receipt.sha256)
        return bundle

    def command(self, argv, **kwargs):
        output = b""
        if kwargs["stdin"] == update._CONFIG_PROBE:
            output = json.dumps(asdict(self.setting)).encode()
        elif "config:system:set" in argv:
            self.setting = update.AppStoreSetting(True, "--value=true" in argv)
        elif "config:system:delete" in argv:
            self.setting = update.AppStoreSetting(False, False)
        elif "--url" in argv:
            self.updater_calls += 1
            for name, data in self.target_files.items():
                self.write(self.context.host(update.APP + "/" + name), data)
        elif "integrity:check-core" in argv:
            output = b"[]"
        return update.NativeResult(0, output)

    def prepare(self):
        return adapter.prepare(self.n, target_zip=self.target_zip, target_asc=self.home / "target.asc",
            target_sig=self.home / "target.sig", source_asc=self.home / "source.asc",
            public_key=self.home / "key", runner=self.runner)

    def test_prepares_before_downtime_then_returns_bound_closed_target_result(self):
        original_journal = self.store.reference(self.n.journal.path)
        custom = adapter._custom(self.context)
        prepared = self.prepare()
        self.stage_verified.assert_called_once()
        self.assertEqual(self.updater_calls, 0)
        self.n.backend.stop.assert_not_called()
        self.assertEqual(self.staging_calls, [(self.n.operation, self.home / "source.asc")])
        self.closed()
        # The native parent stopped/restarted the pair after capture. An adapter
        # obtains fresh JIDs once, retaining the immutable operation/artifacts.
        self.jids.update(testnc=51, testoo=52)
        result = adapter.NextcloudPatch(prepared, runner=self.runner).execute(self.n)
        value = _json(self.store._bound(result))
        self.assertEqual(value["kind"], "nextcloud-patch-result")
        self.assertEqual(value["target"], ["35.0.2", "35.0.2.2"])
        self.assertTrue(value["maintenance"])
        self.assertFalse(value["publication_authorized"])
        self.assertEqual(self.setting, update.AppStoreSetting(False, False))
        self.assertEqual(adapter._custom(self.context), custom)
        self.assertEqual(self.store.reference(self.n.journal.path), original_journal)
        self.assertEqual(self.updater_calls, 1)
        self.assertFalse(self.fpm_running)
        self.assertTrue(self.store._present(self.n.directory + "/update-source-runtime-after.json"))
        self.assertTrue(all(call.args[0][:2] == ("/usr/sbin/jexec", "51") for call in self.runner.call_args_list))
        with self.assertRaisesRegex(adapter.PrerequisiteError, "effect-already-attempted"):
            adapter.NextcloudPatch(prepared, runner=self.runner).execute(self.n)
        self.assertEqual(self.updater_calls, 1)

    def test_source_baseline_accepts_authenticated_executable(self):
        self.source = replace(self.source, files=tuple(replace(item, executable=item.path == "occ")
                                                      for item in self.source.files))
        self.context.host(update.APP + "/occ").chmod(0o750)
        prepared = self.prepare()
        self.assertTrue(next(item for item in prepared.bundle.source_inventory.files if item.path == "occ").executable)

    def test_source_baseline_refuses_unsigned_execute_bit_before_recording_prepared(self):
        self.context.host(update.APP + "/occ").chmod(0o750)
        with self.assertRaisesRegex(adapter.PrerequisiteError, "code-not-hardened"):
            self.prepare()
        self.assertFalse(self.store._present(self.n.directory + "/update-prepared.json"))
        self.assertEqual(self.updater_calls, 0)

    def test_failed_updater_is_not_reinvoked_or_declared_complete(self):
        prepared = self.prepare()
        self.closed()
        real = self.command
        def fail(argv, **kwargs):
            if "--url" in argv:
                self.updater_calls += 1
                return update.NativeResult(1, b"private failure")
            return real(argv, **kwargs)
        self.runner.side_effect = fail
        with self.assertRaises(ValueError):
            adapter.NextcloudPatch(prepared, runner=self.runner).execute(self.n)
        self.assertTrue(self.store._present(self.n.directory + "/update-updater-before.json"))
        self.assertFalse(self.store._present(self.n.directory + "/update-updater-after.json"))
        self.assertFalse(self.store._present(self.n.directory + "/update-result.json"))
        with self.assertRaisesRegex(adapter.PrerequisiteError, "effect-already-attempted"):
            adapter.NextcloudPatch(prepared, runner=self.runner).execute(self.n)
        self.assertEqual(self.updater_calls, 1)

    def test_unexpected_running_fpm_refuses_before_permission_changes(self):
        prepared = self.prepare()
        self.closed()
        self.fpm_running = True
        with self.assertRaisesRegex(adapter.PrerequisiteError, "unexpected-source-fpm-writer"):
            adapter.NextcloudPatch(prepared, runner=self.runner).execute(self.n)
        self.assertEqual(self.updater_calls, 0)
        self.assertFalse(self.store._present(self.n.directory + "/update-code-writable-before.json"))

    def test_connector_drift_after_preparation_prevents_updater(self):
        prepared = self.prepare()
        self.closed()
        self.write(self.context.host(update.APP + "/custom_apps/onlyoffice/lib.php"), b"different")
        with self.assertRaises(ValueError):
            adapter.NextcloudPatch(prepared, runner=self.runner).execute(self.n)
        self.assertEqual(self.updater_calls, 0)

    def test_full_package_or_module_drift_prevents_code_permissions(self):
        prepared = self.prepare()
        self.closed()
        self.runtime["full_packages"]["unexpected"] = []
        with self.assertRaisesRegex(adapter.PrerequisiteError, "source-runtime-drift"):
            adapter.NextcloudPatch(prepared, runner=self.runner).execute(self.n)
        self.assertFalse(self.store._present(self.n.directory + "/update-code-writable-before.json"))
        self.assertEqual(self.updater_calls, 0)


if __name__ == "__main__":
    unittest.main()
