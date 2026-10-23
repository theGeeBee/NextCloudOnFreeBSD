"""Offline add-on tests: synthetic archives, no native operations or network."""

from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

from installer import plugins


class PluginTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.cache = self.base / "cache"
        self.root = self.base / "plugins"
        self.state = self.base / "receipts"
        self.root.mkdir(mode=0o755)
        self.root.chmod(0o755)
        self.owner = patch.object(plugins, "ROOT_UID", os.geteuid())
        self.owner.start()
        self.addCleanup(self.owner.stop)
        self.catalog = {"schema": 1, "docs_version": "9.4.0", "source_commit": "a" * 40,
                        "plugins": {}}
        self.downloads = {}
        self.trees = {}
        self.add_plugin("alpha", "zip", "1")
        self.add_plugin("zotero", "files", "2")
        self.lock = plugins.make_lock("alpha,zotero", self.catalog)

    def add_plugin(self, slug, kind, digit):
        guid = "asc.{" + digit * 8 + "-" + (digit * 4 + "-") * 3 + digit * 12 + "}"
        files = {"config.json": json.dumps({"guid": guid, "version": "1.0.0",
                 "minVersion": "7.3", "variations": [{"isSystem": False}]}).encode(),
                 "scripts/main.js": b"/* reviewed static plugin */",
                 "LICENSE": b"Synthetic fixture license"}
        record = {"name": slug.title(), "guid": guid, "version": "1.0.0", "format": kind,
                  "tree": {p: self.sha(data) for p, data in files.items()}, "artifacts": []}
        artifacts = {"plugin.zip": self.zip(files)} if kind == "zip" else files
        for path, data in artifacts.items():
            url = ("https://raw.githubusercontent.com/ONLYOFFICE/onlyoffice.github.io/"
                   + "a" * 40 + f"/sdkjs-plugins/content/{slug}/"
                   + ("deploy/plugin.plugin" if kind == "zip" else path))
            record["artifacts"].append({"path": path, "url": url, "size": len(data),
                                        "sha256": self.sha(data)})
            self.downloads[url] = data
        self.catalog["plugins"][slug] = record
        self.trees[slug] = files

    @staticmethod
    def sha(data):
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def zip(files):
        stream = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
                for path, data in files.items() if isinstance(files, dict) else files:
                    archive.writestr(path, data)
        return stream.getvalue()

    def fetch(self, url):
        return io.BytesIO(self.downloads[url])

    def prepare(self, lock=None):
        plugins.prepare(self.lock if lock is None else lock, self.cache, self.fetch)

    def install(self):
        self.prepare()
        plugins.install(self.lock, self.cache, self.root, self.state)

    def replace_archive(self, data):
        artifact = self.lock["plugins"]["alpha"]["artifacts"][0]
        artifact.update(size=len(data), sha256=self.sha(data))
        self.downloads[artifact["url"]] = data

    def snapshot(self):
        result = {}
        for path in self.base.rglob("*"):
            info = path.lstat()
            result[str(path.relative_to(self.base))] = (
                info.st_mode, info.st_mtime_ns,
                path.read_bytes() if stat.S_ISREG(info.st_mode) else None)
        return result

    def test_catalog_selection_and_immutable_lock(self):
        path = self.base / "catalog.json"
        path.write_text(json.dumps(self.catalog))
        self.assertEqual(plugins.load_catalog(path), self.catalog)
        plugins.validate_lock(self.lock, "alpha,zotero", self.catalog)
        self.assertEqual(list(plugins.make_lock("zotero,alpha", self.catalog)["plugins"]),
                         ["zotero", "alpha"])
        self.lock["plugins"]["alpha"]["name"] = "Changed"
        self.assertNotEqual(self.catalog["plugins"]["alpha"]["name"], "Changed")
        with self.assertRaises(ValueError):
            plugins.validate_lock(self.lock, "alpha,zotero", self.catalog)
        for selection in ("alpha,alpha", "alpha,", " alpha", "unknown", None):
            with self.subTest(selection=selection), self.assertRaises(ValueError):
                plugins.make_lock(selection, self.catalog)
        with self.assertRaises(ValueError):
            plugins.validate_lock(plugins.make_lock("alpha", self.catalog), "", self.catalog)

    def test_catalog_rejects_hostile_metadata(self):
        for url in ("https://evil.invalid/file", "http://raw.githubusercontent.com/file",
                    self.lock["plugins"]["alpha"]["artifacts"][0]["url"].replace("a" * 40, "main"),
                    self.lock["plugins"]["alpha"]["artifacts"][0]["url"] + "?secret=x"):
            value = deepcopy(self.catalog)
            value["plugins"]["alpha"]["artifacts"][0]["url"] = url
            with self.subTest(url=url), self.assertRaises(ValueError):
                plugins.make_lock("alpha", value)
        for path in ("../oops", "/oops", "a\\b", "a//b", "a/./b", "a:b", "a\x00b"):
            value = deepcopy(self.catalog)
            value["plugins"]["alpha"]["tree"][path] = "b" * 64
            with self.subTest(path=path), self.assertRaises(ValueError):
                plugins.make_lock("alpha", value)
        for tree in ({"Config.json": "a" * 64}, {"scripts": "a" * 64},
                     {"Scripts/other.js": "a" * 64}):
            value = deepcopy(self.catalog)
            value["plugins"]["alpha"]["tree"].update(tree)
            with self.assertRaises(ValueError):
                plugins.make_lock("alpha", value)

    def test_duplicate_json_keys_rejected(self):
        path = self.base / "catalog.json"
        path.write_text('{"schema":1,"schema":1}')
        with self.assertRaises(ValueError):
            plugins.load_catalog(path)

    def test_reviewed_catalog_schema(self):
        if not plugins.CATALOG.is_file():
            self.skipTest("Reviewed catalog is supplied by integration")
        catalog = plugins.load_catalog()
        selection = ",".join(catalog["plugins"])
        plugins.validate_lock(plugins.make_lock(selection, catalog), selection, catalog)

    def test_canonical_url_escaping_and_empty_files(self):
        record = self.catalog["plugins"]["zotero"]
        artifact = deepcopy(record["artifacts"][0])
        artifact.update(path="licenses/third@party.txt", size=0, sha256=self.sha(b""))
        prefix = artifact["url"].rsplit("/", 1)[0]
        artifact["url"] = prefix + "/licenses/third%40party.txt"
        record["artifacts"].append(artifact)
        record["tree"][artifact["path"]] = artifact["sha256"]
        lock = plugins.make_lock("zotero", self.catalog)
        self.downloads[artifact["url"]] = b""
        self.prepare(lock)
        plugins.check_cache(lock, self.cache)
        for suffix in ("%2e%2e/escape", "licenses%2fthird%40party.txt", "licenses/third%2540party.txt"):
            record["artifacts"][-1]["url"] = prefix + "/" + suffix
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                plugins.make_lock("zotero", self.catalog)

    def test_empty_selection_is_noop(self):
        lock = plugins.make_lock("", self.catalog)
        plugins.validate_lock(lock, "", self.catalog)
        before = self.snapshot()
        plugins.prepare(lock, self.cache, lambda url: self.fail("Unexpected fetch"))
        plugins.check_cache(lock, self.cache)
        plugins.install(lock, self.cache, self.base / "absent", self.state)
        plugins.verify(lock, self.base / "absent", self.state)
        self.assertEqual(before, self.snapshot())

    def test_download_only_selected_and_verified_cache_reuse(self):
        lock = plugins.make_lock("alpha", self.catalog)
        requested = []
        def fetch(url):
            requested.append(url)
            return self.fetch(url)
        plugins.prepare(lock, self.cache, fetch)
        self.assertEqual(len(requested), 1)
        self.assertFalse((self.cache / "zotero").exists())
        plugins.prepare(lock, self.cache, lambda url: self.fail("Cached file fetched"))
        plugins.check_cache(lock, self.cache)
        (self.cache / "alpha/plugin.zip").write_bytes(b"drift")
        with self.assertRaises(ValueError):
            plugins.prepare(lock, self.cache, lambda url: self.fail("Drift fetched over"))
        self.assertEqual((self.cache / "alpha/plugin.zip").read_bytes(), b"drift")

    def test_download_length_hash_redirect_and_error_are_sanitized(self):
        lock = plugins.make_lock("alpha", self.catalog)
        original = self.downloads[lock["plugins"]["alpha"]["artifacts"][0]["url"]]
        for data in (original[:-1], original + b"x", b"x" * len(original)):
            cache = self.base / ("bad-" + str(len(list(self.base.iterdir()))))
            with self.assertRaisesRegex(ValueError, "integrity or transport"):
                plugins.prepare(lock, cache, lambda url: io.BytesIO(data))
            self.assertFalse((cache / "alpha/plugin.zip").exists())
            self.assertTrue(list(cache.rglob(".cloud-partial-*")))
            for path in cache.rglob(".cloud-partial-*"):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        def bad_fetch(url):
            raise OSError("https://secret.invalid/private?token=secret")
        with self.assertRaises(ValueError) as error:
            plugins.prepare(lock, self.cache, bad_fetch)
        self.assertNotIn("secret", str(error.exception))
        response = io.BytesIO(original)
        response.geturl = lambda: "https://evil.invalid/"
        with self.assertRaises(ValueError):
            plugins.prepare(lock, self.cache, lambda url: response)
        with self.assertRaises(ValueError):
            plugins._NoRedirect().redirect_request(None, None, 302, None, None, "https://evil.invalid/")

    def test_install_verify_modes_and_unrelated_plugins(self):
        unrelated = self.root / "native-package-plugin"
        unrelated.mkdir()
        (unrelated / "keep").write_text("unmanaged")
        self.install()
        before = self.snapshot()
        plugins.verify(self.lock, self.root, self.state)
        plugins.install(self.lock, self.cache, self.root, self.state)
        self.assertEqual(before, self.snapshot())
        for slug, files in self.trees.items():
            self.assertEqual(stat.S_IMODE((self.root / slug).stat().st_mode), 0o755)
            for name, data in files.items():
                path = self.root / slug / name
                self.assertEqual(path.read_bytes(), data)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.state / "alpha.complete.json").stat().st_mode), 0o600)

    def test_missing_cache_prevents_any_live_writes(self):
        self.prepare()
        (self.cache / "zotero/LICENSE").rename(self.base / "removed")
        before = self.snapshot()
        with self.assertRaises(FileNotFoundError):
            plugins.install(self.lock, self.cache, self.root, self.state)
        self.assertEqual(before, self.snapshot())

    def test_archives_reject_hostile_paths_duplicates_and_symlinks(self):
        cases = [list(self.trees["alpha"].items()) + [(name, b"bad")]
                 for name in ("../escape", "/absolute", "a\\b", "config.json", "CONFIG.json",
                              "scripts/Main.js", "scripts", "unused/")]
        symlink = zipfile.ZipInfo("link")
        symlink.create_system = 3
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        cases.append(list(self.trees["alpha"].items()) + [(symlink, b"config.json")])
        for entries in cases:
            with self.subTest(entries=entries[-1][0]):
                data = self.zip(entries)
                self.replace_archive(data)
                # A fresh cache preserves the no-overwrite rule between cases.
                self.cache = self.base / ("cache-" + str(len(list(self.base.iterdir()))))
                self.prepare()
                before = self.snapshot()
                with self.assertRaises(ValueError):
                    plugins.install(self.lock, self.cache, self.root, self.state)
                self.assertEqual(before, self.snapshot())

    def test_wrapped_archive_root_is_normalized(self):
        data = self.zip({"alpha/" + path: data for path, data in self.trees["alpha"].items()})
        self.replace_archive(data)
        self.install()
        plugins.verify(self.lock, self.root, self.state)

    def test_archive_limits_and_reviewed_tree_drift(self):
        self.prepare()
        for name, limit in (("TREE_LIMIT", 1), ("ENTRY_LIMIT", 2), ("ARCHIVE_LIMIT", 1)):
            before = self.snapshot()
            with patch.object(plugins, name, limit), self.assertRaises(ValueError):
                plugins.install(self.lock, self.cache, self.root, self.state)
            self.assertEqual(before, self.snapshot())
        self.lock["plugins"]["alpha"]["tree"]["LICENSE"] = "0" * 64
        before = self.snapshot()
        with self.assertRaises(ValueError):
            plugins.install(self.lock, self.cache, self.root, self.state)
        self.assertEqual(before, self.snapshot())

    def test_compression_bomb_rejected_before_inflation(self):
        files = dict(self.trees["alpha"])
        files["scripts/main.js"] = b"x" * (1024 * 1024)
        self.replace_archive(self.zip(files))
        self.lock["plugins"].pop("zotero")
        self.lock["plugins"]["alpha"]["tree"]["scripts/main.js"] = self.sha(files["scripts/main.js"])
        self.prepare()
        before = self.snapshot()
        with patch.object(plugins, "TREE_LIMIT", 1024), \
                patch.object(zipfile.ZipFile, "read", side_effect=AssertionError("Archive inflated")), \
                self.assertRaisesRegex(ValueError, "archive exceeds"):
            plugins.install(self.lock, self.cache, self.root, self.state)
        self.assertEqual(before, self.snapshot())

    def test_manifest_identity_support_and_system_flags(self):
        for changes in ({"guid": "wrong"}, {"version": "2.0.0"}, {"minVersion": "9.5"},
                        {"maxVersion": "9.3"}, {"isSystemPlugin": True},
                        {"variations": [{"isSystem": True}]}, {"autoStart": True}):
            files = dict(self.trees["alpha"])
            manifest = json.loads(files["config.json"])
            manifest.update(changes)
            files["config.json"] = json.dumps(manifest).encode()
            self.lock["plugins"]["alpha"]["tree"]["config.json"] = self.sha(files["config.json"])
            self.replace_archive(self.zip(files))
            self.cache = self.base / ("cache-" + str(len(list(self.base.iterdir()))))
            self.prepare()
            before = self.snapshot()
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                plugins.install(self.lock, self.cache, self.root, self.state)
            self.assertEqual(before, self.snapshot())

    def test_foreign_directory_or_symlink_refused_before_any_install(self):
        self.prepare()
        destination = self.root / "zotero"
        destination.mkdir()
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, "unowned"):
            plugins.install(self.lock, self.cache, self.root, self.state)
        self.assertEqual(before, self.snapshot())
        destination.rename(self.base / "foreign")
        destination.symlink_to(self.base / "foreign", target_is_directory=True)
        with self.assertRaises(ValueError):
            plugins.install(self.lock, self.cache, self.root, self.state)
        self.assertFalse((self.root / "alpha").exists())

    def test_symlink_ancestors_and_unsafe_cache_modes_refused(self):
        self.prepare()
        link = self.base / "cache-link"
        link.symlink_to(self.cache, target_is_directory=True)
        with self.assertRaises(ValueError):
            plugins.check_cache(self.lock, link)
        cached = self.cache / "alpha/plugin.zip"
        cached.chmod(0o644)
        with self.assertRaises(ValueError):
            plugins.check_cache(self.lock, self.cache)
        cached.chmod(0o600)
        original = self.base / "original.zip"
        cached.rename(original)
        cached.symlink_to(original)
        with self.assertRaises((OSError, ValueError)):
            plugins.check_cache(self.lock, self.cache)

    def test_read_only_verification_failure_for_missing_drift_extra_and_mode(self):
        self.install()
        path = self.root / "alpha/LICENSE"
        for action in (lambda: path.write_bytes(b"modified"), lambda: path.chmod(0o600),
                       lambda: (self.root / "alpha/extra").write_bytes(b"extra")):
            action()
            before = self.snapshot()
            with self.assertRaises(ValueError):
                plugins.verify(self.lock, self.root, self.state)
            self.assertEqual(before, self.snapshot())
            path.write_bytes(self.trees["alpha"]["LICENSE"])
            path.chmod(0o644)
        (self.root / "alpha/extra").rename(self.base / "extra")
        path.rename(self.base / "missing-license")
        before = self.snapshot()
        with self.assertRaises(ValueError):
            plugins.verify(self.lock, self.root, self.state)
        self.assertEqual(before, self.snapshot())

    def test_interrupted_staging_and_rename_are_safely_resumable(self):
        self.prepare()
        original = plugins._publish
        interrupted = False
        def fail_once(source, destination):
            nonlocal interrupted
            if destination.name == "main.js" and not interrupted:
                interrupted = True
                raise OSError("synthetic interruption")
            original(source, destination)
        with patch.object(plugins, "_publish", side_effect=fail_once), self.assertRaises(OSError):
            plugins.install(self.lock, self.cache, self.root, self.state)
        self.assertFalse((self.root / "alpha").exists())
        self.assertTrue((self.state / "alpha.intent.json").exists())
        stage = next(self.root.glob(".cloud-alpha-*"))
        self.assertEqual(stat.S_IMODE(stage.stat().st_mode), 0o700)
        def fail_receipt(source, destination):
            if destination.name == "alpha.complete.json":
                raise OSError("synthetic receipt interruption")
            original(source, destination)
        with patch.object(plugins, "_publish", side_effect=fail_receipt), self.assertRaises(OSError):
            plugins.install(self.lock, self.cache, self.root, self.state)
        self.assertTrue((self.root / "alpha").exists())
        with self.assertRaises(ValueError):
            plugins.verify(self.lock, self.root, self.state)
        plugins.install(self.lock, self.cache, self.root, self.state)
        plugins.verify(self.lock, self.root, self.state)

    def test_partial_tree_drift_and_changed_source_refused(self):
        self.prepare()
        original = plugins._publish
        def fail_directory(source, destination):
            if destination == self.root / "alpha":
                raise OSError("interruption")
            original(source, destination)
        with patch.object(plugins, "_publish", side_effect=fail_directory), self.assertRaises(OSError):
            plugins.install(self.lock, self.cache, self.root, self.state)
        stage = next(self.root.glob(".cloud-alpha-*"))
        (stage / "LICENSE").write_bytes(b"foreign")
        before = self.snapshot()
        with self.assertRaises(ValueError):
            plugins.install(self.lock, self.cache, self.root, self.state)
        self.assertEqual(before, self.snapshot())
        self.lock["plugins"]["alpha"]["name"] = "different reviewed record"
        with self.assertRaisesRegex(ValueError, "intent mismatch"):
            plugins.install(self.lock, self.cache, self.root, self.state)

    def test_cli_failure_has_no_traceback_or_network_details(self):
        path = self.base / "lock.json"
        path.write_text(json.dumps(self.lock))
        path.chmod(0o600)
        output = io.StringIO()
        with patch.object(plugins, "load_catalog", return_value=self.catalog), \
                patch("sys.stderr", output), self.assertRaises(SystemExit) as error:
            plugins.main(["verify", "--lock", str(path), "--root", str(self.root),
                          "--state", str(self.state)])
        self.assertEqual(error.exception.code, 1)
        self.assertNotIn("Traceback", output.getvalue())
        self.assertNotIn("https://", output.getvalue())


if __name__ == "__main__":
    unittest.main()
