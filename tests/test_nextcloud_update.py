"""Synthetic public archives and injected runners; no native acceptance."""

from copy import deepcopy
from dataclasses import asdict, replace
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

from installer import nextcloud_update as update


def version(public, internal):
    return ("<?php\n$OC_Version = [" + ", ".join(internal.split(".")) + "];\n"
            "$OC_VersionString = '" + public + "';\n$OC_Channel = 'stable';\n").encode()


class Authority(update.Authority):
    def __init__(self):
        self.checks = []
        self.events = []
        self.source_reference = None
        self.bundle = None
        self.blocked = False

    def validate(self, context, phase):
        self.checks.append((context.jid, phase))
        if self.blocked:
            raise ValueError("closed-profile check failed")

    def source(self, context, reference):
        if reference != self.source_reference:
            raise ValueError("original authenticated install record required")

    def artifacts(self, context, bundle):
        if bundle != self.bundle:
            raise ValueError("operation receipt mismatch")

    def checkpoint(self, context, event, state, binding):
        if state == "before" and any(e == event and s == state for e, s, _ in self.events):
            raise ValueError("ambiguous/repeated effect")
        self.events.append((event, state, binding))


class NextcloudUpdateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="nc-update-")
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        self.root = self.home / "jail"
        self.root.mkdir(mode=0o700)
        self.enterContext(patch.object(update, "_ROOT_UID", os.geteuid()))
        self.authority = Authority()
        self.calls = []
        self.setting = update.AppStoreSetting(False, False)
        self.pgp = b"[GNUPG:] VALIDSIG " + update.RELEASE_KEY.encode() + b" 2026-10-15 1 0 4 0 1 10 00\n"
        self.source_pgp = self.pgp
        self.fail = None
        self.context = update.NativeContext("update-one", 42, "testnc", self.root,
                                             8080, 8080, 1024, self.authority, self.runner)
        self.files = {
            "version.php": version(*update.SOURCE),
            update.PHAR: b"authenticated source PHAR fixture",
            update.CERT: b"authenticated source public certificate fixture",
            "occ": b"public OCC fixture",
            "lib/core.php": b"source code fixture",
        }
        self.target_files = dict(self.files, **{
            "version.php": version(*update.TARGET),
            update.PHAR: b"target PHAR fixture", "lib/core.php": b"target code fixture"})
        self.make_tar()
        retained = self.context.host(update.RETAINED)
        digest = hashlib.sha256(retained.read_bytes()).hexdigest()
        proof = (digest + "\n").encode()
        self.write(self.context.host(update.SHA_PROOF), proof)
        self.authority.source_reference = update.SourceReference(digest, hashlib.sha256(proof).hexdigest())
        for name, data in self.files.items():
            self.write(self.context.host(update.APP + "/" + name), data)
        self.context.host(update.STAGING).mkdir(mode=0o700)
        self.zip = self.home / "target.zip"
        self.make_zip()
        self.asc = self.home / "target.asc"
        self.source_asc = self.home / "source.asc"
        self.sig = self.home / "target.sig"
        self.key = self.home / "release-key.asc"
        self.write(self.asc, b"PGP signature fixture")
        self.write(self.source_asc, b"source PGP signature fixture")
        self.write(self.sig, base64.b64encode(b"OpenSSL signature fixture") + b"\n")
        self.write(self.key, b"public PGP key fixture")

    def write(self, path, data):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(data)
        path.chmod(0o600)

    def make_tar(self, extra=None, modes=None, *, first=False):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:bz2", format=tarfile.USTAR_FORMAT) as archive:
            if extra and first:
                archive.addfile(extra)
            for name, data in self.files.items():
                entry = tarfile.TarInfo("nextcloud/" + name)
                entry.size, entry.mode = len(data), (modes or {}).get(name, 0o644)
                archive.addfile(entry, io.BytesIO(data))
            if extra and not first:
                archive.addfile(extra)
        self.write(self.context.host(update.RETAINED), output.getvalue())

    def license_alias(self, *, target="bundle.js.license", kind=tarfile.SYMTYPE):
        entry = tarfile.TarInfo("nextcloud/dist/bundle.js.map.license")
        entry.type, entry.linkname, entry.mode = kind, target, 0o777
        return entry

    def allow_fixture_alias(self):
        self.files["dist/bundle.js.license"] = b"public license fixture"
        aliases = {"dist/bundle.js.map.license": "bundle.js.license"}
        digest = hashlib.sha256(json.dumps(aliases, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.enterContext(patch.object(update, "SOURCE_ALIASES_SHA256", digest))

    def test_authenticated_license_alias_is_inventoried_without_dereference_in_either_order(self):
        self.allow_fixture_alias()
        for first in (True, False):
            with self.subTest(first=first):
                self.make_tar(self.license_alias(), first=first)
                inventory, _ = update._source_inventory(self.context.host(update.RETAINED))
                self.assertEqual(inventory.links, (update.LicenseAlias("dist/bundle.js.map.license", "bundle.js.license"),))
                self.assertNotIn(inventory.links[0].path, {f.path for f in inventory.files})
                self.assertEqual(update.source_aliases(inventory), {inventory.links[0].path: inventory.links[0].target})

    def test_source_alias_requires_exact_map_regular_target_and_safe_link_text(self):
        self.allow_fixture_alias()
        for target in ("../bundle.js.license", "/bundle.js.license", "missing.license", "other.js.license", "a\\b.license"):
            with self.subTest(target=target):
                self.make_tar(self.license_alias(target=target))
                with self.assertRaises(update.UpdateError):
                    update._source_inventory(self.context.host(update.RETAINED))
        self.make_tar(self.license_alias(kind=tarfile.LNKTYPE))
        with self.assertRaises(update.UpdateError):
            update._source_inventory(self.context.host(update.RETAINED))
        self.make_tar(self.license_alias(), modes={"dist/bundle.js.license": 0o755})
        with self.assertRaises(update.UpdateError):
            update._source_inventory(self.context.host(update.RETAINED))

    def test_unreviewed_alias_map_is_rejected_even_when_target_is_safe(self):
        self.files["dist/bundle.js.license"] = b"license"
        self.make_tar(self.license_alias())
        with self.assertRaises(update.UpdateError):
            update._source_inventory(self.context.host(update.RETAINED))

    def test_reviewed_two_hop_alias_is_metadata_only_and_cycles_or_deeper_chains_refuse(self):
        regular = update.FileHash("dist/final.license", 1, "a" * 64)
        for mapping, accepted in (({"dist/first.license": "second.license", "dist/second.license": "final.license"}, True),
                                  ({"dist/first.license": "second.license", "dist/second.license": "first.license"}, False),
                                  ({"dist/first.license": "second.license", "dist/second.license": "third.license",
                                    "dist/third.license": "final.license"}, False)):
            digest = hashlib.sha256(json.dumps(mapping, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            inventory = update.Inventory((regular,), (), tuple(update.LicenseAlias(k, v) for k, v in mapping.items()))
            with self.subTest(mapping=mapping), patch.object(update, "SOURCE_ALIASES_SHA256", digest):
                if accepted:
                    self.assertEqual(update.source_aliases(inventory), mapping)
                else:
                    with self.assertRaises(update.UpdateError):
                        update.source_aliases(inventory)

    def test_bounded_gnu_long_license_target_is_supported_without_general_link_extensions(self):
        name = "a" * 120 + ".license"
        self.files["dist/" + name] = b"license"
        mapping = {"dist/alias.license": name}
        digest = hashlib.sha256(json.dumps(mapping, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:bz2", format=tarfile.GNU_FORMAT) as archive:
            for path, data in self.files.items():
                member = tarfile.TarInfo("nextcloud/" + path)
                member.size, member.mode = len(data), 0o644
                archive.addfile(member, io.BytesIO(data))
            member = tarfile.TarInfo("nextcloud/dist/alias.license")
            member.type, member.linkname = tarfile.SYMTYPE, name
            archive.addfile(member)
        self.write(self.context.host(update.RETAINED), output.getvalue())
        with patch.object(update, "SOURCE_ALIASES_SHA256", digest):
            inventory, _ = update._source_inventory(self.context.host(update.RETAINED))
        self.assertEqual(inventory.links, (update.LicenseAlias("dist/alias.license", name),))

    def test_legacy_bundle_has_no_inferred_aliases_and_link_receipt_is_bound(self):
        bundle = self.stage()
        legacy = asdict(bundle)
        for field in ("source_inventory", "target_inventory"):
            legacy[field].pop("links")
        legacy = json.loads(json.dumps(legacy))
        decoded = update.decode_bundle(json.loads(json.dumps(legacy)))
        self.assertEqual(decoded.source_inventory.links, ())
        self.assertEqual(json.loads(json.dumps(update.bundle_record(decoded))), legacy)
        self.assertEqual(json.loads(json.dumps(update.inventory_record(decoded.source_inventory))), legacy["source_inventory"])
        self.assertEqual(hashlib.sha256(json.dumps(update.inventory_record(decoded.source_inventory), sort_keys=True).encode()).hexdigest(),
                         hashlib.sha256(json.dumps(legacy["source_inventory"], sort_keys=True).encode()).hexdigest())
        self.assertNotIn("source_links", update.inventory_receipt(decoded.source_inventory, decoded.target_inventory))
        self.allow_fixture_alias()
        self.make_tar(self.license_alias())
        inventory, _ = update._source_inventory(self.context.host(update.RETAINED))
        linked = replace(bundle, source_inventory=inventory)
        value = json.loads(json.dumps(asdict(linked)))
        self.assertEqual(update.decode_bundle(value), linked)
        receipt = update.inventory_receipt(inventory, bundle.target_inventory)
        self.assertEqual(receipt["source_links"], [asdict(inventory.links[0])])
        value["source_inventory"]["links"][0]["target"] = "other.license"
        with self.assertRaises(update.UpdateError):
            update.decode_bundle(value)
        value = json.loads(json.dumps(asdict(replace(linked, target_inventory=inventory))))
        with self.assertRaises(update.UpdateError):
            update.decode_bundle(value)

    def test_alias_namespace_collisions_and_nonzero_payload_are_rejected(self):
        self.allow_fixture_alias()
        self.files["dist/bundle.js.map.license"] = b"cannot also be a regular file"
        self.make_tar(self.license_alias())
        with self.assertRaises(update.UpdateError):
            update._source_inventory(self.context.host(update.RETAINED))
        extra = self.license_alias()
        extra.size = 1
        self.make_tar(extra)
        with self.assertRaises(update.UpdateError):
            update._source_inventory(self.context.host(update.RETAINED))
    def make_zip(self, extra=None, files=None, modes=None):
        with zipfile.ZipFile(self.zip, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, data in (files or self.target_files).items():
                entry = zipfile.ZipInfo("nextcloud/" + name)
                entry.create_system = 3
                entry.external_attr = (stat.S_IFREG | (modes or {}).get(name, 0o644)) << 16
                archive.writestr(entry, data)
            if extra:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    archive.writestr(*extra)
        self.zip.chmod(0o600)

    def runner(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if self.fail:
            return self.fail(argv, kwargs)
        output = b""
        if "--verify" in argv:
            output = self.source_pgp if argv[-1] == update.RETAINED else self.pgp
        elif kwargs["stdin"] == update._CONFIG_PROBE:
            output = json.dumps(self.setting.__dict__).encode()
        elif "config:system:set" in argv:
            self.setting = update.AppStoreSetting(True, "--value=true" in argv)
        elif "config:system:delete" in argv:
            self.setting = update.AppStoreSetting(False, False)
        elif "integrity:check-core" in argv:
            output = b"[]\n"
        return update.NativeResult(0, output)

    def stage(self):
        bundle = update.stage_artifacts(self.context, target_zip=self.zip, target_asc=self.asc,
                                        target_sig=self.sig, source_asc=self.source_asc, public_key=self.key)
        self.authority.bundle = bundle
        return bundle

    def config_probe_fixture(self):
        # Production validates real www ownership. Mock only that OS stat field;
        # the PHP helper/argv and output validation are exercised with the runner.
        path = self.context.host(update.APP + "/config/config.php")
        self.write(path, b"<?php /* private fixture */")
        if os.geteuid() == 0:
            os.chown(path, self.context.www_uid, self.context.www_gid)
        else:
            self.context = replace(self.context, www_uid=os.geteuid())

    def test_staging_binds_source_and_all_target_hashes_without_extracting(self):
        bundle = self.stage()
        self.assertEqual({f.path for f in bundle.target_inventory.files}, set(self.target_files))
        self.assertEqual(bundle.source, self.authority.source_reference)
        self.assertEqual(self.context.host(update.APP + "/lib/core.php").read_bytes(), self.files["lib/core.php"])
        directory = self.context.host(self.context.stage)
        for path in directory.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700 if path.is_dir() else 0o600)
        receipt = json.loads((directory / "receipt.json").read_bytes())
        self.assertEqual(receipt["source_version"], list(update.SOURCE))
        self.assertEqual(receipt["target_version"], list(update.TARGET))
        self.assertEqual(receipt["key"], update.RELEASE_KEY)
        self.assertEqual(receipt["source"], self.authority.source_reference.__dict__)
        artifacts = {record["path"]: record for record in receipt["artifacts"]}
        self.assertEqual(artifacts["nextcloud-35.0.1.tar.bz2.asc"]["sha256"],
                         hashlib.sha256(self.source_asc.read_bytes()).hexdigest())
        self.assertEqual(len(self.calls), 4)
        self.assertEqual(self.calls[1][0][-2:],
                         (self.context.stage + "/nextcloud-35.0.1.tar.bz2.asc", update.RETAINED))
        self.assertEqual(self.calls[2][0][-2:],
                         (self.context.stage + "/nextcloud-35.0.2.zip.asc",
                          self.context.stage + "/nextcloud-35.0.2.zip"))
        key_event = next(binding for event, state, binding in self.authority.events
                         if event == "import-release-key" and state == "before")
        self.assertEqual(key_event, artifacts["nextcloud.asc"]["sha256"])
        for argv, kwargs in self.calls:
            self.assertEqual(argv[:2], ("/usr/sbin/jexec", "42"))
            self.assertEqual(set(kwargs["env"]), {"PATH", "LC_ALL"})
            self.assertEqual(kwargs["stdin"], b"")
        self.assertIn("--no-options", self.calls[0][0])
        self.assertIn("openssl_verify", " ".join(self.calls[-1][0]))
        self.assertGreaterEqual(len(self.authority.checks), 8)

    def test_source_hash_alone_is_not_authentication(self):
        self.authority.source_reference = None
        with self.assertRaises(ValueError):
            self.stage()
        self.assertFalse(self.calls)
        self.assertFalse(self.context.host(self.context.stage).exists())

    def test_authenticated_archives_bind_execute_bits_in_receipt(self):
        self.make_tar(modes={"occ": 0o744, "lib/core.php": 0o641})
        digest = hashlib.sha256(self.context.host(update.RETAINED).read_bytes()).hexdigest()
        proof = (digest + "\n").encode()
        self.write(self.context.host(update.SHA_PROOF), proof)
        self.authority.source_reference = update.SourceReference(digest, hashlib.sha256(proof).hexdigest())
        self.make_zip(modes={"occ": 0o654, update.PHAR: 0o645})
        bundle = self.stage()
        self.assertEqual({f.path for f in bundle.source_inventory.files if f.executable}, {"occ", "lib/core.php"})
        self.assertEqual({f.path for f in bundle.target_inventory.files if f.executable}, {"occ", update.PHAR})
        self.assertTrue(all(f.executable is False for f in bundle.artifacts))
        receipt = json.loads(self.context.host(self.context.stage + "/receipt.json").read_bytes())
        self.assertEqual(receipt["source_files"], [asdict(f) for f in bundle.source_inventory.files])
        self.assertEqual(receipt["target_files"], [asdict(f) for f in bundle.target_inventory.files])

    def test_archive_execute_metadata_does_not_admit_special_bits(self):
        for mode in (0o4755, 0o2755, 0o1755):
            with self.subTest(mode=mode):
                self.make_tar(modes={"occ": mode})
                self.make_zip(modes={"occ": mode})
                with self.assertRaises(update.UpdateError):
                    update._source_inventory(self.context.host(update.RETAINED))
                with self.assertRaises(update.UpdateError):
                    update._zip_inventory(self.zip)

    def test_decode_bundle_exact_roundtrip_is_pure(self):
        bundle = self.stage()
        bundle = replace(bundle, source_inventory=replace(bundle.source_inventory,
            files=tuple(replace(item, executable=item.path == "occ") for item in bundle.source_inventory.files)))
        value = json.loads(json.dumps(asdict(bundle)))
        with patch.object(update, "_native") as native, patch.object(update, "_file") as read:
            decoded = update.decode_bundle(value)
            self.assertEqual(decoded, bundle)
            self.assertEqual(json.loads(json.dumps(asdict(decoded))), value)
            native.assert_not_called()
            read.assert_not_called()

    def test_decode_bundle_rejects_inexact_fields_types_paths_and_duplicates(self):
        original = json.loads(json.dumps(asdict(self.stage())))
        def bad(change):
            value = deepcopy(original)
            change(value)
            with self.assertRaises(update.UpdateError):
                update.decode_bundle(value)
        bad(lambda v: v.update(extra=True))
        bad(lambda v: v["source"].update(extra=True))
        bad(lambda v: v["source"].update(archive_sha256="g" * 64))
        bad(lambda v: v.update(operation="../other"))
        bad(lambda v: v.update(signature="YQ==\n"))
        bad(lambda v: v.update(receipt_sha256=1))
        bad(lambda v: v["source_inventory"].update(extra=True))
        bad(lambda v: v["source_inventory"]["files"][0].pop("executable"))
        for field, value in (("executable", 1), ("executable", "false"), ("size", True),
                             ("size", -1), ("size", update.MAX_FILE + 1), ("sha256", "x" * 64),
                             ("path", "../escape"), ("path", "occ/"), ("path", "config/config.php")):
            with self.subTest(field=field, value=value):
                bad(lambda v: v["source_inventory"]["files"][0].update({field: value}))
        bad(lambda v: v["source_inventory"]["files"].append(v["source_inventory"]["files"][0]))
        bad(lambda v: v["source_inventory"].update(directories=["lib", "lib"]))
        bad(lambda v: v["source_inventory"].update(directories=["lib", "LIB"]))
        bad(lambda v: v["source_inventory"].update(directories=["occ"]))
        bad(lambda v: v["source_inventory"].update(directories=["../escape"]))
        bad(lambda v: v["artifacts"][0].update(executable=True))
        bad(lambda v: v["artifacts"][0].pop("executable"))
        bad(lambda v: v["artifacts"][0].update(path="subdir/artifact"))
        bad(lambda v: v["artifacts"].append(v["artifacts"][0]))
        bad(lambda v: v["artifacts"].append(dict(v["artifacts"][0], path=v["artifacts"][0]["path"].upper())))
        bad(lambda v: v.update(artifacts=[]))
        with patch.object(update, "MAX_ENTRIES", 1), self.assertRaises(update.UpdateError):
            update.decode_bundle(original)

    def test_source_signature_is_required_before_any_effect(self):
        with self.assertRaises(TypeError):
            update.stage_artifacts(self.context, target_zip=self.zip, target_asc=self.asc,
                                   target_sig=self.sig, public_key=self.key)
        self.assertFalse(self.calls)
        self.assertFalse(self.authority.events)
        self.assertFalse(self.context.host(self.context.stage).exists())

    def test_bad_source_pgp_prevents_source_zip_and_php_inspection(self):
        self.source_pgp = b"[GNUPG:] GOODSIG unpinned-source-key name\n"
        with patch.object(update, "_source_inventory") as source, patch.object(update, "_zip_inventory") as target:
            with self.assertRaises(update.UpdateError):
                self.stage()
            source.assert_not_called()
            target.assert_not_called()
        self.assertEqual(len(self.calls), 2)
        self.assertFalse(any("/usr/local/bin/php" in argv for argv, _ in self.calls))
        directory = self.context.host(self.context.stage)
        signature = directory / "nextcloud-35.0.1.tar.bz2.asc"
        self.assertEqual(signature.read_bytes(), self.source_asc.read_bytes())
        self.assertEqual(stat.S_IMODE(signature.stat().st_mode), 0o600)
        self.assertFalse((directory / "source-core.crt").exists())
        self.assertFalse((directory / "receipt.json").exists())

    def test_source_gpg_nonzero_exit_refuses_even_with_validsig(self):
        def fail(argv, kwargs):
            return update.NativeResult(1 if argv[-1] == update.RETAINED else 0, self.source_pgp)
        self.fail = fail
        with patch.object(update, "_source_inventory") as source, patch.object(update, "_zip_inventory") as target:
            with self.assertRaises(update.UpdateError):
                self.stage()
            source.assert_not_called()
            target.assert_not_called()
        self.assertEqual(len(self.calls), 2)

    def test_source_signature_byte_bound_retains_private_partial_stage(self):
        self.write(self.source_asc, b"a" * 65537)
        with self.assertRaises(update.UpdateError):
            self.stage()
        self.assertFalse(self.calls)
        directory = self.context.host(self.context.stage)
        self.assertTrue((directory / "nextcloud-35.0.2.zip").is_file())
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        self.assertFalse((directory / "receipt.json").exists())

    def test_retained_archive_change_during_pgp_refuses_before_inventory(self):
        def fail(argv, kwargs):
            if argv[-1] == update.RETAINED:
                path = self.context.host(update.RETAINED)
                self.write(path, path.read_bytes() + b"changed")
            return update.NativeResult(0, self.source_pgp if "--verify" in argv else b"")
        self.fail = fail
        with patch.object(update, "_source_inventory") as source:
            with self.assertRaises(update.UpdateError):
                self.stage()
            source.assert_not_called()
        self.assertEqual(len(self.calls), 2)

    def test_original_proof_change_during_pgp_refuses_before_inventory(self):
        def fail(argv, kwargs):
            if argv[-1] == update.RETAINED:
                path = self.context.host(update.SHA_PROOF)
                self.write(path, path.read_bytes() + b"\n")
            return update.NativeResult(0, self.source_pgp if "--verify" in argv else b"")
        self.fail = fail
        with patch.object(update, "_source_inventory") as source:
            with self.assertRaises(update.UpdateError):
                self.stage()
            source.assert_not_called()
        self.assertEqual(len(self.calls), 2)

    def test_source_version_is_checked_only_after_pgp_and_must_be_exact(self):
        self.files["version.php"] = version("35.0.1", "35.0.1.2")
        self.make_tar()
        digest = hashlib.sha256(self.context.host(update.RETAINED).read_bytes()).hexdigest()
        proof = (digest + "\n").encode()
        self.write(self.context.host(update.SHA_PROOF), proof)
        self.authority.source_reference = update.SourceReference(digest, hashlib.sha256(proof).hexdigest())
        with patch.object(update, "_source_inventory", wraps=update._source_inventory) as source:
            with self.assertRaises(update.UpdateError):
                self.stage()
            source.assert_called_once_with(self.context.host(update.RETAINED))
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.calls[-1][0][-1], update.RETAINED)

    def test_changed_installed_phar_refuses_before_any_php(self):
        self.write(self.context.host(update.APP + "/" + update.PHAR), b"different helper")
        with self.assertRaises(update.UpdateError):
            self.stage()
        self.assertEqual(len(self.calls), 2)
        self.assertFalse(any("/usr/local/bin/php" in argv for argv, _ in self.calls))

    def test_invalid_pgp_precedes_any_zip_inspection(self):
        self.pgp = b"[GNUPG:] GOODSIG unpinned-key name\n"
        with patch.object(update, "_zip_inventory") as inspect:
            with self.assertRaises(update.UpdateError):
                self.stage()
            inspect.assert_not_called()
        self.assertEqual(len(self.calls), 3)

    def test_failed_openssl_precedes_zip_inspection(self):
        def fail(argv, kwargs):
            return update.NativeResult(1 if "-r" in argv else 0, self.pgp if "--verify" in argv else b"")
        self.fail = fail
        with patch.object(update, "_zip_inventory") as inspect:
            with self.assertRaises(update.UpdateError):
                self.stage()
            inspect.assert_not_called()

    def test_pinned_primary_subkey_validsig_and_rejection_statuses(self):
        update._pgp_valid(b"[GNUPG:] VALIDSIG " + b"A" * 40 + b" 2026-10-15 1 0 4 0 1 10 00 " + update.RELEASE_KEY.encode())
        for raw in (b"", self.pgp + b"[GNUPG:] EXPKEYSIG key\n", self.pgp.replace(update.RELEASE_KEY.encode(), b"A" * 40)):
            with self.subTest(raw=raw), self.assertRaises(update.UpdateError):
                update._pgp_valid(raw)

    def test_signature_requires_canonical_bounded_base64(self):
        self.assertEqual(update.canonical_signature(b"YQ==\n"), "YQ==")
        for raw in (b"", b"YQ==\r\n", b" YQ==", b"YR==", b"YQ==\n\n", b"!", b"a" * 2049):
            with self.subTest(raw=raw), self.assertRaises(update.UpdateError):
                update.canonical_signature(raw)

    def test_zip_rejects_paths_links_duplicates_aliases_and_version_drift(self):
        link = zipfile.ZipInfo("nextcloud/symlink")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        for extra in (("nextcloud/../escape", b"x"), ("/nextcloud/abs", b"x"),
                      ("nextcloud/lib\\escape", b"x"), ("nextcloud/lib/core.php/child", b"x"),
                      ("nextcloud/LIB/other", b"x"), ("nextcloud/version.php", b"x"), (link, b"/tmp")):
            with self.subTest(extra=extra):
                self.make_zip(extra)
                with self.assertRaises(update.UpdateError):
                    update._zip_inventory(self.zip)
        files = dict(self.target_files, **{"version.php": version("35.0.3", "35.0.3.1")})
        self.make_zip(files=files)
        with self.assertRaises(update.UpdateError):
            update._zip_inventory(self.zip)

    def test_archive_expansion_and_entry_bounds(self):
        with patch.object(update, "MAX_EXPANDED", 4), self.assertRaises(update.UpdateError):
            update._zip_inventory(self.zip)
        with patch.object(update, "MAX_ENTRIES", 2), self.assertRaises(update.UpdateError):
            update._zip_inventory(self.zip)
        with patch.object(update, "MAX_CENTRAL", 8), self.assertRaises(update.UpdateError):
            update._zip_inventory(self.zip)

    def test_tar_rejects_links_before_extracting(self):
        entry = tarfile.TarInfo("nextcloud/linked")
        entry.type, entry.linkname = tarfile.LNKTYPE, "nextcloud/occ"
        self.make_tar(entry)
        with self.assertRaises(update.UpdateError):
            update._source_inventory(self.context.host(update.RETAINED))

    def test_tar_rejects_sparse_and_pax_before_processing_extended_metadata(self):
        for kind in (tarfile.GNUTYPE_SPARSE, tarfile.XHDTYPE, tarfile.XGLTYPE):
            with self.subTest(kind=kind):
                entry = update._BoundedTarInfo("nextcloud/unexpected")
                entry.type = kind
                with self.assertRaises(update.UpdateError):
                    entry._proc_member(type("Tar", (), {})())

    def test_symlink_hardlink_and_directory_symlink_inputs_rejected(self):
        original = self.zip.with_suffix(".original")
        self.zip.rename(original)
        self.zip.symlink_to(original)
        with self.assertRaises((update.UpdateError, OSError)):
            update._digest_file(self.zip, update.MAX_ARCHIVE)
        self.zip.unlink()
        os.link(original, self.zip)
        with self.assertRaises(update.UpdateError):
            update._digest_file(self.zip, update.MAX_ARCHIVE)
        directory = self.home / "alias"
        directory.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises((update.UpdateError, OSError)):
            update._read(directory / update.RETAINED[1:], update.MAX_ARCHIVE)

    def test_stage_is_exclusive_and_retains_failed_artifacts(self):
        self.stage()
        with self.assertRaises((ValueError, OSError)):
            self.stage()
        self.assertTrue(self.context.host(self.context.stage + "/receipt.json").is_file())

    def test_post_jid_check_runs_on_runner_exception_and_hides_diagnostics(self):
        def fail(argv, kwargs):
            raise RuntimeError("secret fixture that must not escape")
        self.fail = fail
        before = len(self.authority.checks)
        with self.assertRaises(update.UpdateError) as error:
            update._native(self.context, update.Phase.ARTIFACTS, ("/usr/local/bin/gpg",))
        self.assertNotIn("secret", str(error.exception))
        self.assertEqual(len(self.authority.checks) - before, 2)

    def test_parent_authority_is_mandatory_and_cannot_return_json_true(self):
        with self.assertRaises(update.UpdateError):
            replace(self.context, authority={"closed": True})
        with patch.object(self.authority, "validate", return_value=True), self.assertRaises(update.UpdateError):
            self.stage()
        self.assertFalse(self.calls)

    def test_updater_fixed_flags_separate_migration_and_no_replay(self):
        bundle = self.stage()
        self.config_probe_fixture()
        update.suppress_appstore(self.context, self.setting)
        update.invoke_updater(self.context, bundle)
        calls = [argv for argv, _ in self.calls if update.APP + "/" + update.PHAR in argv]
        self.assertEqual(len(calls), 1)
        argv = calls[0]
        for flag in ("--no-interaction", "--no-upgrade", "--url", "--signature", "memory_limit=1024M"):
            self.assertIn(flag, argv)
        self.assertIn("/usr/bin/mdo", argv)
        self.assertIn("file://" + self.context.stage + "/nextcloud-35.0.2.zip", argv)
        for flag in ("--no-verify", "--ignore-state", "--no-backup", "upgrade"):
            self.assertNotIn(flag, argv)
        with self.assertRaises(ValueError):
            update.invoke_updater(self.context, bundle)
        self.assertEqual(len([a for a, _ in self.calls if update.APP + "/" + update.PHAR in a]), 1)
        # A successful command and no .step are deliberately not code proof.
        with self.assertRaises(update.UpdateError):
            update.verify_target_code(self.context, bundle)
        self.assertFalse(any("upgrade" in a for a, _ in self.calls))

    def test_only_exact_authenticated_prefix_and_root_htaccess_suffix_are_accepted(self):
        stock = b"Options -Indexes\n"
        item = update.FileHash(".htaccess", len(stock), hashlib.sha256(stock).hexdigest())
        for content in (stock, stock + update.HTACCESS_ROOT_SUFFIX):
            self.assertEqual(update.code_file_identity(io.BytesIO(content), item),
                             (hashlib.sha256(content).hexdigest(), len(content)))
        for content in (b"unknown prefix\n" + update.HTACCESS_ROOT_SUFFIX,
                        stock + b"#### DO NOT CHANGE ANYTHING ABOVE THIS LINE ####\n",
                        stock + update.HTACCESS_ROOT_SUFFIX + b"# unknown\n",
                        stock + update.HTACCESS_ROOT_SUFFIX.replace(b"RewriteBase /\n", b"RewriteBase /other\n"),
                        stock + update.HTACCESS_ROOT_SUFFIX * 2):
            with self.subTest(content=content), self.assertRaises(update.UpdateError):
                update.code_file_identity(io.BytesIO(content), item)
        with self.assertRaises(update.UpdateError):
            update.code_file_identity(io.BytesIO(stock + update.HTACCESS_ROOT_SUFFIX), replace(item, path="lib/code.php"))
        with self.assertRaises(update.UpdateError):
            update.code_file_identity(io.BytesIO(stock), replace(item, executable=True))

    def test_target_generated_htaccess_still_requires_native_core_integrity(self):
        stock = b"Options -Indexes\n"
        self.target_files[".htaccess"] = stock
        self.make_zip()
        bundle = self.stage()
        for name, data in self.target_files.items():
            self.write(self.context.host(update.APP + "/" + name), data)
        self.write(self.context.host(update.APP + "/.htaccess"), stock + update.HTACCESS_ROOT_SUFFIX)
        update.verify_target_code(self.context, bundle)
        self.assertTrue(any("integrity:check-core" in argv for argv, _ in self.calls))
        self.write(self.context.host(update.APP + "/.htaccess"), stock + update.HTACCESS_ROOT_SUFFIX + b"unknown")
        with self.assertRaises(update.UpdateError):
            update._target_bytes(self.context, bundle)

    def test_independent_full_target_hashes_required_before_migration(self):
        bundle = self.stage()
        self.config_probe_fixture()
        update.suppress_appstore(self.context, self.setting)
        for name, data in self.target_files.items():
            self.write(self.context.host(update.APP + "/" + name), data)
        proof = update.verify_target_code(self.context, bundle)
        self.write(self.context.host(update.APP + "/lib/core.php"), b"partial replacement")
        with self.assertRaises(update.UpdateError):
            update.migrate(self.context, bundle, proof)
        self.assertFalse(any("upgrade" in a for a, _ in self.calls))
        self.write(self.context.host(update.APP + "/lib/core.php"), self.target_files["lib/core.php"])
        update.migrate(self.context, bundle, proof)
        self.assertEqual(len([a for a, _ in self.calls if "upgrade" in a]), 1)
        self.assertEqual(self.setting, update.AppStoreSetting(True, False))

    def test_appstore_exact_presence_and_boolean_restoration(self):
        self.config_probe_fixture()
        original = update.probe_appstore(self.context)
        update.suppress_appstore(self.context, original)
        update.restore_appstore(self.context, original)
        self.assertEqual(self.setting, original)
        self.assertTrue(any("config:system:delete" in a for a, _ in self.calls))
        self.assertEqual(stat.S_IMODE(self.context.host(update.APP + "/config/config.php").stat().st_mode), 0o600)

    def test_changed_staged_zip_is_rejected_before_updater(self):
        bundle = self.stage()
        self.write(self.context.host(self.context.stage + "/nextcloud-35.0.2.zip"), b"changed")
        before = len(self.calls)
        with self.assertRaises(update.UpdateError):
            update.invoke_updater(self.context, bundle)
        self.assertEqual(len(self.calls), before)

    def test_existing_step_probe_failure_prevents_updater(self):
        bundle = self.stage()
        self.config_probe_fixture()
        self.setting = update.AppStoreSetting(True, False)
        def fail(argv, kwargs):
            if kwargs["stdin"] == update._CONFIG_PROBE:
                return update.NativeResult(0, b'{"exists":true,"value":false}')
            return update.NativeResult(1 if kwargs["stdin"] == update._UPDATER_STATE else 0)
        self.fail = fail
        with self.assertRaises(update.UpdateError):
            update.invoke_updater(self.context, bundle)
        self.assertFalse(any(update.APP + "/" + update.PHAR in argv for argv, _ in self.calls))

    def test_exposure_gives_www_read_only_zip_and_keeps_other_artifacts_private(self):
        bundle = self.stage()
        context = replace(self.context, www_gid=os.getgid())
        update.expose_target_zip(context, bundle)
        directory = context.host(context.stage)
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o710)
        self.assertEqual(stat.S_IMODE((directory / "nextcloud-35.0.2.zip").stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE((directory / "nextcloud-35.0.2.zip.sig").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((directory / "receipt.json").stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
