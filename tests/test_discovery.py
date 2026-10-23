"""Deterministic discovery tests: no repositories, packages or host mutations."""

import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import urllib.error

from installer import discovery


CHECKSUM = "2$" + "y" * 103


class DiscoveryTests(unittest.TestCase):
    def test_stable_archives_need_explicit_name_and_signature(self):
        names = ["nextcloud-35.0.2.tar.bz2", "nextcloud-35.0.2.tar.bz2.asc",
                 "nextcloud-35.0.10.tar.bz2", "nextcloud-35.0.10.tar.bz2.asc",
                 "nextcloud-36.0.0rc1.tar.bz2", "nextcloud-36.0.0rc1.tar.bz2.asc",
                 "latest-35.tar.bz2", "nextcloud-35.0.11.tar.bz2",
                 "https://foreign.test/nextcloud-36.0.0.tar.bz2"]
        self.assertEqual(discovery.nextcloud_versions("".join(f'<a href="{name}">x</a>' for name in names)),
                         ["35.0.10", "35.0.2"])

    def test_missing_or_changed_release_metadata_fails_without_guessing(self):
        for text in ("", '<a href="latest-35.tar.bz2">latest</a>', "service unavailable"):
            with self.subTest(text=text), self.assertRaises(discovery.DiscoveryError):
                discovery.nextcloud_versions(text)

    def test_office_discovery_does_not_conflate_newer_with_compatibility(self):
        records = [{"tag_name": "v10.0.0", "prerelease": False, "draft": False},
                   {"tag_name": "v9.4.0", "prerelease": False, "draft": False},
                   {"tag_name": "v11.0.0", "prerelease": True, "draft": False},
                   {"tag_name": "v10.1.0", "prerelease": False, "draft": True},
                   {"tag_name": "v12.0.0rc1", "prerelease": False, "draft": False}]
        self.assertEqual(discovery.onlyoffice_versions(json.dumps(records)), ["10.0.0", "9.4.0"])

    def test_missing_stability_flags_and_invalid_json_fail_closed(self):
        for text in ('[{"tag_name":"v9.4.0"}]', '{}', 'not-json', '[]'):
            with self.subTest(text=text), self.assertRaises(discovery.DiscoveryError):
                discovery.onlyoffice_versions(text)

    def test_signed_connector_metadata_preserves_independent_requirements(self):
        record = {"version": "10.2.1", "isNightly": False, "phpVersionSpec": ">=8.2.0 <8.6.0",
                  "platformVersionSpec": ">=33.0.0 <36.0.0", "signatureDigest": "sha512",
                  "download": "https://example.test/signed-app.tar.gz", "signature": "test-only-signature"}
        text = json.dumps([{"id": "onlyoffice", "certificate": "test-only-certificate", "releases": [record]}])
        selected = discovery.connector_releases(text)
        self.assertEqual(selected, [{**record, "certificate": "test-only-certificate"}])

    def test_absent_or_nonstable_connector_is_an_empty_candidate_list(self):
        app = {"id": "onlyoffice", "certificate": "test-only-certificate", "releases": []}
        cases = [[], [{"id": "another-app"}], [app],
                 [{**app, "releases": [{"version": "10.2.1", "isNightly": True},
                                       {"version": "10.2.2rc1", "isNightly": False}]}]]
        for apps in cases:
            with self.subTest(apps=apps):
                self.assertEqual(discovery.connector_releases(json.dumps(apps)), [])

    def test_actual_connector_id_selects_its_certificate_and_preserves_manifest_bounds(self):
        apps = []
        for app, version, php in (('onlyoffice','10.2.1','>=8.2.0 <8.6.0'),
                                  ('eurooffice','11.0.6','*'), ('richdocuments','12.0.1','>=8.3.0')):
            record = dict(version=version, isNightly=False, phpVersionSpec=php,
                          platformVersionSpec='>=35.0.0 <36.0.0', signatureDigest='sha512',
                          download='https://example.test/' + app + '.tar.gz', signature=app+'-signature')
            apps.append(dict(id=app, certificate=app+'-certificate', releases=[record]))
        for app in apps:
            with self.subTest(app=app['id']):
                selected = discovery.connector_releases(json.dumps(apps), app['id'])
                self.assertEqual(selected, [{**app['releases'][0], 'certificate': app['certificate']}])
                self.assertEqual(discovery.connector_releases(json.dumps([other for other in apps if other != app]), app['id']), [])
        self.assertEqual(discovery.connector_releases(json.dumps(apps)), discovery.connector_releases(json.dumps(apps), 'onlyoffice'))

    def test_unselected_connector_malformation_cannot_be_substituted_for_selected_app(self):
        self.assertEqual(discovery.connector_releases('[{"id":"onlyoffice"}]', 'eurooffice'), [])
        for app in ('none', 'richdocumentscode', 'richdocumentscode_arm64', 'OnlyOffice', '../eurooffice'):
            with self.subTest(app=app), self.assertRaises(discovery.DiscoveryError):
                discovery.connector_releases('not-json', app)

    def test_malformed_or_duplicate_connector_metadata_is_not_absence(self):
        app = {"id": "onlyoffice", "certificate": "test-only-certificate", "releases": []}
        cases = [None, {}, [None], [False], [[]], [app, None], [app, app],
                 [{"id": "onlyoffice", "releases": []}],
                 [{"id": "onlyoffice", "certificate": "test-only-certificate"}]]
        cases.extend([{**app, "certificate": value}] for value in (None, "", " \n", 1))
        cases.extend([{**app, "releases": value}] for value in (None, {}, "", [None], [[]]))
        cases.extend([{**app, "releases": [item]}] for item in (
            {}, {"version": "10.2.1"}, {"version": "10.2.1", "isNightly": "false"},
            {"version": None, "isNightly": False}, {"version": "", "isNightly": False},
            {"version": "10.2.1", "isNightly": False}))
        for text in ("not-json", *(json.dumps(apps) for apps in cases)):
            with self.subTest(text=text), self.assertRaises(discovery.DiscoveryError):
                discovery.connector_releases(text)

    def test_malformed_stable_connector_fields_remain_fatal(self):
        record = {"version": "10.2.1", "isNightly": False, "phpVersionSpec": ">=8.2.0 <8.6.0",
                  "platformVersionSpec": ">=33.0.0 <36.0.0", "signatureDigest": "sha512",
                  "download": "https://example.test/signed-app.tar.gz", "signature": "test-only-signature"}
        for field in ("phpVersionSpec", "platformVersionSpec", "signatureDigest", "download", "signature"):
            for value in (None, "", " \n", 1, []):
                app = {"id": "onlyoffice", "certificate": "test-only-certificate",
                       "releases": [{**record, field: value}]}
                with self.subTest(field=field, value=value), self.assertRaises(discovery.DiscoveryError):
                    discovery.connector_releases(json.dumps([app]))

    def test_catalog_versions_origins_abi_and_dependency_edges(self):
        records = (f"php85|8.5.11|lang/php85|FreeBSD:15:amd64|0|{CHECKSUM}\n"
                   f"python3|3.11_2|lang/python3|FreeBSD:15:*|1|{CHECKSUM}\n")
        deps = "python3|php85|8.5.11|lang/php85\n"
        packages = discovery.package_catalog(records, deps)
        self.assertEqual(packages["python3"]["abi"], "FreeBSD:15:*")
        self.assertEqual(packages["python3"]["dependencies"]["php85"], {"version": "8.5.11", "origin": "lang/php85"})
        self.assertEqual(packages["python3"]["checksum"], CHECKSUM)

    def test_safe_opaque_versions_include_native_usrinfo_and_dependency_edges(self):
        for version in (".10_1", "_1", "+1", "1:2_3,4"):
            records = (f"usrinfo|{version}|sysutils/usrinfo|FreeBSD:15:amd64|0|{CHECKSUM}\n"
                       f"a|1|lang/a|FreeBSD:15:amd64|1|{CHECKSUM}\n")
            deps = f"a|usrinfo|{version}|sysutils/usrinfo\n"
            with self.subTest(version=version):
                packages = discovery.package_catalog(records, deps)
                self.assertEqual(packages["usrinfo"]["version"], version)
                self.assertEqual(packages["a"]["dependencies"]["usrinfo"]["version"], version)

    def test_catalog_checksums_are_preserved_without_decoding(self):
        for checksum in (CHECKSUM, "aB" * 32, "0$" + "a" * 254):
            with self.subTest(checksum=checksum):
                packages = discovery.package_catalog(f"a|1|lang/a|FreeBSD:15:*|0|{checksum}", "")
                self.assertEqual(packages["a"]["checksum"], checksum)

    def test_unversioned_dependencies_exclude_only_unresolvable_packages(self):
        from installer.compatibility import closure
        records = "\n".join((f"safe|1|lang/safe|FreeBSD:15:*|0|{CHECKSUM}",
                             f"broken|1|lang/broken|FreeBSD:15:*|1|{CHECKSUM}",
                             f"parent|1|lang/parent|FreeBSD:15:*|1|{CHECKSUM}"))
        dependencies = "broken|restricted||lang/restricted\nparent|broken|1|lang/broken"
        packages = discovery.package_catalog(records, dependencies)
        self.assertEqual(set(packages), {"safe", "parent"})
        self.assertEqual(set(closure(packages, ["safe"])), {"safe"})
        with self.assertRaisesRegex(ValueError, "Missing/conflicting dependency"):
            closure(packages, ["parent"])
        with self.assertRaisesRegex(discovery.DiscoveryError, "Incomplete"):
            discovery.package_catalog(records.replace("lang/broken|FreeBSD:15:*|1|", "lang/broken|FreeBSD:15:*|2|"), dependencies)

    def test_unversioned_dependency_does_not_hide_unsafe_or_duplicate_edges(self):
        records = f"broken|1|lang/broken|FreeBSD:15:*|2|{CHECKSUM}"
        for dependencies in ("broken|restricted||lang/restricted\nbroken|restricted|1|lang/restricted",
                             "broken|restricted||../unsafe"):
            with self.subTest(dependencies=dependencies), self.assertRaises(discovery.DiscoveryError):
                discovery.package_catalog(records, dependencies)
        with self.assertRaisesRegex(discovery.DiscoveryError, "no fully versioned"):
            discovery.package_catalog(records.replace("|2|", "|1|"), "broken|restricted||lang/restricted")

    def test_missing_or_unsafe_catalog_checksum_fails_closed(self):
        invalid = ("", "2$", "2$ab$cd", "2$(id)", "2$ab cd", "2$ab|cd", "2$ab\ncd",
                   "2$ab\0cd", "2$" + "y" * 255, "a" * 63, "g" * 64)
        for checksum in invalid:
            with self.subTest(checksum=checksum), self.assertRaises(discovery.DiscoveryError):
                discovery.package_catalog(f"a|1|lang/a|FreeBSD:15:*|0|{checksum}", "")
        with self.assertRaisesRegex(discovery.DiscoveryError, "fields are missing"):
            discovery.package_catalog("a|1|lang/a|FreeBSD:15:*|0", "")

    def test_truncated_dependency_metadata_is_not_an_empty_graph(self):
        with self.assertRaisesRegex(discovery.DiscoveryError, "Incomplete"):
            discovery.package_catalog(f"a|1.0|lang/a|FreeBSD:15:amd64|1|{CHECKSUM}", "")

    def test_ambiguous_names_are_unavailable_not_last_wins(self):
        text = (f"openssl|3.0.22|security/openssl30|FreeBSD:15:amd64|0|{CHECKSUM}\n"
                f"openssl|3.5.9,1|security/openssl|FreeBSD:15:amd64|0|{CHECKSUM}\n"
                f"a|1|lang/a|FreeBSD:15:*|0|{CHECKSUM}")
        self.assertEqual(set(discovery.package_catalog(text, "")), {"a"})

    def test_empty_unsafe_and_incomplete_catalogs_fail(self):
        for text in ("", "a|1|lang/a", f"a|1|lang/a|foreign:ABI|0|{CHECKSUM}",
                     f"a|$(id)|lang/a|FreeBSD:15:amd64|0|{CHECKSUM}",
                     f"a|-1|lang/a|FreeBSD:15:amd64|0|{CHECKSUM}"):
            with self.subTest(text=text), self.assertRaises(discovery.DiscoveryError):
                discovery.package_catalog(text, "")

    def test_network_failure_does_not_return_fallback_versions(self):
        with patch("installer.discovery.urllib.request.build_opener") as opening:
            opening.return_value.open.side_effect = urllib.error.URLError("test failure")
            with self.assertRaisesRegex(discovery.DiscoveryError, "unavailable"):
                discovery.fetch_releases()
            self.assertEqual(opening.return_value.open.call_args.kwargs["timeout"], 30)

    def test_https_redirect_cannot_change_authority_or_downgrade_tls(self):
        handler = discovery._HTTPSOnly()
        request = SimpleNamespace(full_url=discovery.NEXTCLOUD_RELEASES)
        for url in ("http://download.nextcloud.com/server/releases/", "https://evil.test/releases/"):
            with self.subTest(url=url), self.assertRaises(discovery.DiscoveryError):
                handler.redirect_request(request, None, 302, "", {}, url)

    def test_native_metadata_uses_isolated_authenticated_database(self):
        config = SimpleNamespace(repository="latest", freebsd_release="", architecture="",
                                 nextcloud_min="", onlyoffice_min="", nextcloud_exact="", onlyoffice_exact="")
        runner = Mock()
        runner.run.return_value = SimpleNamespace(returncode=0)
        def output(*args):
            if args == ("uname", "-s"): return "FreeBSD"
            if args == ("uname", "-m"): return "amd64"
            if args == ("uname", "-U"): return "1501000"
            if args[:1] == ("freebsd-version",): return "15.1-RELEASE-p2"
            if args[-1] == "%n|%v|%o|%q|%#d|%u%d%{%|%}": return f"bastille|1.4.4|sysutils/bastille|FreeBSD:15:*|0|{CHECKSUM}"
            if args[-1] == "%n|%dn|%dv|%do": return ""
            raise AssertionError(args)
        runner.output.side_effect = output
        with tempfile.TemporaryDirectory() as directory:
            with discovery._catalog(config, runner, directory=directory) as (environment, packages, command):
                repo = next(arg.removeprefix("REPOS_DIR=") for arg in command if arg.startswith("REPOS_DIR="))
                self.assertIn('signature_type: "fingerprints"', (Path(repo) / "FreeBSD.conf").read_text())
                self.assertTrue(any(arg.startswith("PKG_DBDIR=" + directory) for arg in command))
                self.assertEqual(environment["abi"], "FreeBSD:15:amd64")
                self.assertIn("OSVERSION=1501000", command)
                self.assertFalse(any("IGNORE_OSVERSION" in arg for arg in command))
                self.assertEqual(packages["bastille"]["checksum"], CHECKSUM)
                runner.run.assert_any_call(*command, "update", "-r", "FreeBSD-ports", input="")
        self.assertTrue(all("install" not in call.args for call in runner.run.call_args_list))

    def test_native_query_failure_is_actionable(self):
        runner = Mock()
        runner.output.side_effect = lambda *args: {("uname", "-s"): "FreeBSD", ("uname", "-m"): "amd64",
                                                  ("uname", "-U"): "1501000",
                                                  ("freebsd-version", "-u"): "15.1-RELEASE",
                                                  ("freebsd-version", "-r"): "15.1-RELEASE"}[args]
        def run(*args, **kwargs):
            if args == ("/usr/sbin/pkg", "-N"):
                return SimpleNamespace(returncode=0)
            raise RuntimeError("repository offline")
        runner.run.side_effect = run
        config = SimpleNamespace(repository="latest", freebsd_release="", architecture="",
                                 nextcloud_min="", onlyoffice_min="", nextcloud_exact="", onlyoffice_exact="")
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(discovery.DiscoveryError, "Signed FreeBSD package metadata"):
                with discovery._catalog(config, runner, directory=directory):
                    self.fail("must not succeed")

    def test_missing_pkg_cannot_trigger_the_base_shims_automatic_bootstrap(self):
        runner = Mock()
        runner.output.side_effect = lambda *args: {("uname", "-s"): "FreeBSD", ("uname", "-m"): "amd64",
                                                  ("freebsd-version", "-u"): "15.1-RELEASE",
                                                  ("freebsd-version", "-r"): "15.1-RELEASE"}[args]
        runner.run.return_value = SimpleNamespace(returncode=1)
        config = SimpleNamespace(repository="latest")
        with self.assertRaisesRegex(discovery.DiscoveryError, "already bootstrapped"):
            with discovery._catalog(config, runner):
                self.fail("must not succeed")
        runner.run.assert_called_once_with("/usr/sbin/pkg", "-N", check=False)

    def test_invalid_native_osversion_refuses_before_catalog_execution(self):
        for value in ("", "1501000\nIGNORE_OSVERSION=yes", "not-a-version"):
            runner = Mock()
            runner.run.return_value = SimpleNamespace(returncode=0)
            runner.output.side_effect = lambda *args: {
                ("uname", "-s"): "FreeBSD", ("uname", "-m"): "amd64", ("uname", "-U"): value,
                ("freebsd-version", "-u"): "15.1-RELEASE", ("freebsd-version", "-r"): "15.1-RELEASE",
            }[args]
            with self.subTest(value=value), self.assertRaisesRegex(discovery.DiscoveryError, "OSVERSION is invalid"):
                with discovery._catalog(SimpleNamespace(repository="latest"), runner):
                    self.fail("must reject invalid OSVERSION")
            runner.run.assert_called_once_with("/usr/sbin/pkg", "-N", check=False)


if __name__ == "__main__":
    unittest.main()
