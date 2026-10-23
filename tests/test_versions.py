"""Offline policy/graph fixtures; no availability or native acceptance claims."""

from copy import deepcopy
import importlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from installer import compatibility, discovery, resolution, versions
from version_fixtures import historic_policy


def configuration(**changes):
    fields = dict.fromkeys(versions.FIELDS, "")
    fields.update(repository="latest", tls_mode="external", font_profile="standard",
                  jail_ssh=False, ssh_shell="sh", ssh_admin=False, accept_microsoft_fonts=True)
    fields.update(changes)
    return SimpleNamespace(**fields)


def signed_connector(**changes):
    result = {"version": "10.2.1", "phpVersionSpec": ">=8.2.0 <8.6.0",
              "platformVersionSpec": ">=33.0.0 <36.0.0", "isNightly": False,
              "signatureDigest": "sha512", "download": "https://example.org/onlyoffice-10.2.1.tar.gz",
              "signature": "fixture-signature", "certificate": "fixture-certificate"}
    result.update(changes)
    return result


def record(name, version="1.0", origin=None, abi="FreeBSD:15:amd64", dependencies=None):
    return {"name": name, "version": version, "origin": origin or "misc/" + name,
            "abi": abi, "checksum": "2$" + "y" * 103, "dependencies": dependencies or {}}


def catalog(policy=None, config=None):
    policy = versions.load_policy() if policy is None else policy
    config = configuration() if config is None else config
    packages = {}
    for names in compatibility.package_roots(config, policy).values():
        for name in names:
            if name == "security/py-certbot":
                packages["py311-certbot"] = record("py311-certbot", "5.0.0", name, "FreeBSD:15:*")
            elif "/" in name:
                package = name.split("/", 1)[1]
                packages[package] = record(package, origin=name)
            else:
                packages[name] = record(name)
    role_versions = {"manager": "1.4.4_1", "php": "8.5.11", "database": "12.3.3",
                     "database_client": "12.3.3", "web": "2.4.65", "cache": "7.4.1", "onlyoffice": "9.4.0_4"}
    for role, rule in policy["profiles"][0]["roles"].items():
        packages[rule["package"]] = record(rule["package"], role_versions[role], rule["origin"])
    packages["bastille"]["abi"] = "FreeBSD:15:*"
    packages["python3"] = record("python3", "3_3", "lang/python3", "FreeBSD:15:*")
    packages["python311"] = record("python311", "3.11.14", "lang/python311")
    packages["libxml2"] = record("libxml2", "2.14.1_1", "textproc/libxml2")
    packages["nginx"] = record("nginx", "1.28.0", "www/nginx")
    packages["py311-supervisor"] = record("py311-supervisor", "4.3.0", "sysutils/py-supervisor")
    packages["webfonts"] = record("webfonts", "0.30_15", "x11-fonts/webfonts")
    packages["libopaque"] = record("libopaque", "1.0.a20260202", "misc/libopaque")
    packages["crosextrafonts-caladea"]["version"] = "20130214_4"
    packages["liberation-fonts-ttf"]["version"] = "2.1.5,2"

    def depends(name, *names):
        packages[name]["dependencies"] = {key: {field: packages[key][field] for field in ("version", "origin")}
                                           for key in names}

    depends("python3", "python311")
    depends("php85", "libxml2")
    depends("mariadb123-server", "mariadb123-client")
    depends("onlyoffice-documentserver", "nginx", "py311-supervisor", "webfonts", "libopaque")
    depends("py311-supervisor", "python311")
    for name in list(packages):
        if name.startswith("php85-"):
            packages[name]["version"] = {"php85-pecl-APCu": "5.1.28", "php85-pecl-imagick": "3.8.1",
                                         "php85-pecl-redis": "6.3.0"}.get(name, "8.5.11")
            depends(name, "php85")
    return {"schema_version": 1, "target": versions.target(policy, "15.1-RELEASE", "amd64"),
            "repository": config.repository, "packages": packages,
            "nextcloud": ["35.0.0", "35.0.1", "35.0.2", "36.0.0", "35.0.1rc1"],
            "onlyoffice": ["9.4.0", "10.0.0"],
            "connectors": {version: [signed_connector()] for version in ("35.0.0", "35.0.1")},
            "sources": ["https://example.org/signed-catalog", "https://example.org/stable-releases"]}


def change_version(discovered, name, version):
    discovered["packages"][name]["version"] = version
    for item in discovered["packages"].values():
        if name in item["dependencies"]:
            item["dependencies"][name]["version"] = version


class VersionPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = historic_policy()

    def test_existing_font_catalog_is_not_duplicated_in_version_resource(self):
        from installer.paths import RESOURCES
        raw = json.loads((RESOURCES / "versions.json").read_text())
        self.assertEqual(raw["fonts"], {"catalog": "packages/fonts.txt"})
        lines = [line.split() for line in (RESOURCES / "packages/fonts.txt").read_text().splitlines()
                 if line.strip() and not line.lstrip().startswith("#")]
        for kind in ("required", "optional"):
            self.assertEqual(self.policy["fonts"][kind], [name for selected, name in lines if selected == kind])

    def test_extension_runtime_edge_cannot_be_omitted(self):
        metadata = catalog()
        metadata["packages"]["php85-pecl-redis"]["dependencies"] = {}
        with self.assertRaisesRegex(ValueError, "matching runtime dependency"):
            resolution.resolve(configuration(), metadata)

    def test_unreviewed_cache_major_and_mismatched_database_client_are_rejected(self):
        for name, value in (("redis", "9.0.0"), ("redis", "3.2.0"), ("mariadb123-client", "12.3.4")):
            metadata = catalog()
            change_version(metadata, name, value)
            with self.subTest(package=name, version=value), self.assertRaises(ValueError):
                resolution.resolve(configuration(), metadata)

    def test_required_cache_extension_minima_and_unreviewed_majors_are_enforced(self):
        for name, value in (("php85-pecl-APCu", "4.0.5"), ("php85-pecl-APCu", "6.0.0"),
                            ("php85-pecl-redis", "2.2.5"), ("php85-pecl-redis", "7.0.0")):
            metadata = catalog()
            change_version(metadata, name, value)
            with self.subTest(package=name, version=value), self.assertRaisesRegex(ValueError, "extension.*compatibility range"):
                resolution.resolve(configuration(), metadata)

    def test_numeric_versions_and_freebsd_ordering(self):
        self.assertEqual(versions.stable_version("35"), (35, 0, 0, 0))
        self.assertEqual(versions.stable_version("35.0.1.4"), (35, 0, 1, 4))
        self.assertGreater(versions.stable_version("35.0.10"), versions.stable_version("35.0.9"))
        self.assertGreater(versions.package_version("9.4.0_10"), versions.package_version("9.4.0_9"))
        self.assertGreater(versions.package_version("1.0,2"), versions.package_version("99.0_999,1"))
        self.assertGreater(versions.package_version("9.4.1"), versions.package_version("9.4.0_999"))
        self.assertEqual(versions.package_version("20130214_4"), (0, (20130214, 0, 0, 0), 4))
        for value in ("", "35.0.1rc1", "v35.0.1", "35.0.1-beta", "35..1", "35.01.1", "35.0.1\n", "35.0.1.1.1"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                versions.stable_version(value)
        for value in ("1.2.3_", "1.2.3,", "1.2.3_1_2", "1.2.3,1_2", "1.2.3rc1", "_2"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                versions.package_version(value)

    def test_defaults_are_lazy_and_not_shared(self):
        first = versions.defaults(self.policy)
        first["nextcloud_min"] = "1"
        self.assertEqual(versions.defaults(self.policy)["nextcloud_min"], "35.0.0")
        with patch.object(Path, "read_text", side_effect=AssertionError("import-time I/O")):
            importlib.reload(versions)
            importlib.reload(compatibility)
            importlib.reload(resolution)
        with patch.object(Path, "read_text", return_value=json.dumps(self.policy)) as read:
            self.assertEqual(versions.load_policy(), self.policy)
            read.assert_called_once()
        duplicate = '{"schema_version":1,' + json.dumps(self.policy)[1:]
        with patch.object(Path, "read_text", return_value=duplicate), self.assertRaisesRegex(ValueError, "Duplicate policy"):
            versions.load_policy()

    def test_constraints_normalize_minima_and_release_but_keep_exact_package_pins(self):
        effective = versions.constraints(configuration(nextcloud_min="35", onlyoffice_min="9.4", freebsd_release="15.1-RELEASE-p10"), self.policy)
        self.assertEqual(effective["nextcloud_min"], "35.0.0")
        self.assertEqual(effective["onlyoffice_min"], "9.4.0")
        self.assertEqual(effective["freebsd_release"], "15.1-RELEASE")
        for pin in ("9.4.0", "9.4.0_4", "9.4.0_4,2", "9.4.0,2"):
            self.assertEqual(versions.constraints(configuration(onlyoffice_exact=pin), self.policy)["onlyoffice_exact"], pin)
        for changes in ({"nextcloud_exact": "35"}, {"nextcloud_exact": "35.0.1.1"}, {"onlyoffice_exact": "9.4"},
                        {"nextcloud_exact": "34.0.1"}, {"nextcloud_min": "35.0.0.1"}, {"onlyoffice_min": None}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                versions.constraints(configuration(**changes), self.policy)

    def test_explicit_target_and_manager_boundaries(self):
        selected = versions.target(self.policy, "15.1-RELEASE-p3", "amd64")
        self.assertEqual(selected["abi"], "FreeBSD:15:amd64")
        self.assertTrue(all(value.startswith("/usr/share/keys/pkgbase-15/") for value in selected["pkgbase_keys"]))
        for release in ("15.1-STABLE", "15.1-RELEASE-p1oops", "15.2-RELEASE", "15.1"):
            with self.subTest(release=release), self.assertRaises(ValueError):
                versions.target(self.policy, release, "amd64")
        with self.assertRaisesRegex(ValueError, "reviewed targets"):
            versions.target(self.policy, "15.1-RELEASE", "aarch64")
        self.assertTrue(versions.manager_supported("1.4.4_2", self.policy))
        for version in ("1.4.5", "1.4.4rc1", "1.4.4.1", "1.5"):
            self.assertFalse(versions.manager_supported(version, self.policy))

    def test_policy_schema_and_bounded_ranges_fail_closed(self):
        mutations = [lambda p: p.update(schema_version=True), lambda p: p.update(targets=[]),
                     lambda p: p["defaults"].update(architecture="aarch64"),
                     lambda p: p["targets"][0].update(abi="FreeBSD:14:amd64"),
                     lambda p: p["targets"][0].update(pkgbase_keys=["/keys/../wrong"]),
                     lambda p: p["profiles"][0]["roles"]["php"].pop("range"),
                     lambda p: p["profiles"][0]["applications"]["nextcloud"].pop("max_exclusive"),
                     lambda p: p["profiles"][0]["php_extensions"].append("php{bad}-xml"),
                     lambda p: p["profiles"].append(deepcopy(p["profiles"][0])),
                     lambda p: p["fonts"]["optional"].append(p["fonts"]["required"][0]),
                     lambda p: p["evidence"][0].update(reviewed="2026-99-99")]
        for mutate in mutations:
            value = deepcopy(self.policy)
            mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                versions.validate_policy(value)

    def test_policy_fonts_match_reviewed_package_catalog(self):
        catalog_path = Path(__file__).resolve().parents[1] / "resources/packages/fonts.txt"
        expected = {"required": [], "optional": []}
        for line in catalog_path.read_text().splitlines():
            if line and not line.startswith("#"):
                kind, name = line.split()
                expected[kind].append(name)
        self.assertEqual(self.policy["fonts"], expected)


class ResolutionTests(unittest.TestCase):
    def setUp(self):
        self.policy = historic_policy()
        self.config = configuration()
        self.discovered = catalog(self.policy, self.config)

    def resolve(self, **kwargs):
        return resolution.resolve(self.config, self.discovered, policy=self.policy, **kwargs)

    def test_newest_reviewed_release_full_closure_no_io_or_mutations(self):
        before = deepcopy((self.config.__dict__, self.discovered, self.policy))
        with patch.object(Path, "read_text", side_effect=AssertionError("pure resolver read")), \
                patch("subprocess.run", side_effect=AssertionError("pure resolver execution")), \
                patch("socket.socket", side_effect=AssertionError("pure resolver network")):
            plan = self.resolve()
            validated = resolution.validate_plan(self.config, plan, self.policy)
        self.assertEqual(plan, validated)
        self.assertIsNot(plan, validated)
        self.assertEqual(plan["applications"], {"nextcloud": "35.0.1", "onlyoffice": "9.4.0_4", "connector": "10.2.1"})
        self.assertIn("libxml2", plan["packages"]["nextcloud"])
        self.assertIn("libopaque", plan["packages"]["onlyoffice"])
        self.assertIn("nginx", plan["packages"]["onlyoffice"])
        self.assertEqual(plan["roles"]["database"], "mariadb123-server")
        self.assertIn(resolution.NATIVE_WARNING, plan["warnings"])
        self.assertIn(resolution.SECURITY_WARNING, plan["warnings"])
        self.assertEqual(before, (self.config.__dict__, self.discovered, self.policy))
        self.assertEqual(json.loads(json.dumps(plan)), plan)

    def test_missing_connector_for_newer_platform_allows_supported_older_candidate(self):
        releases = ["35.0.1", "35.0.0"]
        responses = {
            discovery.NEXTCLOUD_RELEASES: "".join(f'<a href="nextcloud-{version}.tar.bz2{suffix}">release</a>'
                                                 for version in releases for suffix in ("", ".asc")),
            discovery.ONLYOFFICE_RELEASES: json.dumps([{"tag_name": "v9.4.0", "prerelease": False, "draft": False}]),
            discovery.CONNECTORS.format(version="35.0.1"): "[]",
            discovery.CONNECTORS.format(version="35.0.0"): json.dumps([
                {"id": "onlyoffice", "certificate": "fixture-certificate", "releases": [signed_connector()]}]),
        }
        with patch.object(discovery, "_catalog") as native:
            native.return_value.__enter__.return_value = (self.discovered["target"], self.discovered["packages"], ())
            discovered = discovery.discover(self.config, Mock(), fetch=responses.__getitem__, policy=self.policy)
        self.assertEqual(discovered["connectors"]["35.0.1"], [])
        plan = resolution.resolve(self.config, discovered, policy=self.policy)
        self.assertEqual(plan["applications"]["nextcloud"], "35.0.0")
        self.assertEqual(resolution.validate_plan(self.config, plan, self.policy), plan)
        for changes in ({"nextcloud_exact": "35.0.1"}, {"nextcloud_min": "35.0.1"}):
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, "Missing signed connector"):
                resolution.resolve(configuration(**changes), discovered, policy=self.policy)
        for failure in ("not-json", '[{"id":"onlyoffice","releases":[]}]', discovery.DiscoveryError("network unavailable")):
            def fetch(url):
                if url == discovery.CONNECTORS.format(version="35.0.1"):
                    if isinstance(failure, Exception):
                        raise failure
                    return failure
                return responses[url]
            with self.subTest(failure=failure), patch.object(discovery, "_catalog") as native:
                with self.assertRaises(discovery.DiscoveryError):
                    discovery.discover(self.config, Mock(), fetch=fetch, policy=self.policy)
                native.assert_not_called()

    def test_native_usrinfo_version_is_valid_outside_and_inside_selected_closure(self):
        self.discovered["packages"]["usrinfo"] = record("usrinfo", ".10_1", "sysutils/usrinfo")
        self.assertNotIn("usrinfo", self.resolve()["packages"]["onlyoffice"])
        self.discovered["packages"]["libopaque"]["dependencies"]["usrinfo"] = {
            "version": ".10_1", "origin": "sysutils/usrinfo"}
        plan = self.resolve()
        self.assertEqual(plan["packages"]["onlyoffice"]["usrinfo"]["version"], ".10_1")
        self.assertEqual(resolution.validate_plan(self.config, plan, self.policy), plan)

    def test_unsafe_opaque_package_and_dependency_versions_are_rejected(self):
        for version in ("-1", "$(id)", "1;id", "1|2", "1\n2", "1 2", "1\0"):
            for dependency in (False, True):
                discovered = deepcopy(self.discovered)
                item = (discovered["packages"]["onlyoffice-documentserver"]["dependencies"]["libopaque"]
                        if dependency else discovered["packages"]["libopaque"])
                item["version"] = version
                with self.subTest(version=version, dependency=dependency), self.assertRaises(ValueError):
                    resolution.resolve(self.config, discovered, policy=self.policy)

    def test_package_checksum_is_retained_byte_for_byte_in_plan(self):
        for checksum in ("2$" + "y" * 103, "aB" * 32, "0$" + "a" * 254):
            self.discovered["packages"]["libopaque"]["checksum"] = checksum
            with self.subTest(checksum=checksum):
                plan = self.resolve()
                self.assertEqual(plan["packages"]["onlyoffice"]["libopaque"]["checksum"], checksum)
                self.assertEqual(resolution.validate_plan(self.config, json.loads(json.dumps(plan)), self.policy), plan)

    def test_missing_or_invalid_package_checksum_rejects_discovery_and_retained_plan(self):
        plan = self.resolve()
        invalid = (None, 1, True, [], {}, "", "2$", "2$ab$cd", "2$(id)", "2$ab cd", "2$ab|cd",
                   "2$ab\n", "2$ab\0cd", "2$" + "y" * 255, "a" * 63, "g" * 64)
        for checksum in invalid:
            discovered, retained = deepcopy(self.discovered), deepcopy(plan)
            discovered["packages"]["bastille"]["checksum"] = checksum
            retained["packages"]["host"]["bastille"]["checksum"] = checksum
            with self.subTest(checksum=checksum):
                with self.assertRaisesRegex(ValueError, "package checksum"):
                    resolution.resolve(self.config, discovered, policy=self.policy)
                with self.assertRaisesRegex(ValueError, "package checksum"):
                    resolution.validate_plan(self.config, retained, self.policy)
        self.discovered["packages"]["bastille"].pop("checksum")
        plan["packages"]["host"]["bastille"].pop("checksum")
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.resolve()
        with self.assertRaisesRegex(ValueError, "checksum"):
            resolution.validate_plan(self.config, plan, self.policy)

    def test_shared_package_checksums_must_agree_in_retained_plan(self):
        plan = self.resolve()
        shared = set(plan["packages"]["nextcloud"]) & set(plan["packages"]["onlyoffice"])
        self.assertTrue(shared)
        plan["packages"]["onlyoffice"][sorted(shared)[0]]["checksum"] = "2$" + "b" * 103
        with self.assertRaisesRegex(ValueError, "Conflicting retained package identity"):
            resolution.validate_plan(self.config, plan, self.policy)

    def test_native_probe_rejects_same_version_rebuild_without_rewriting_lock(self):
        plan = self.resolve()
        before = deepcopy(plan)
        available = deepcopy(self.discovered["packages"])
        runner = Mock()
        def dry_run(*args, **kwargs):
            selected = [p for p in available.values() if p["name"] + "-" + p["version"] in args[7:]]
            rows = "\n".join("\t" + p["name"] + ": " + p["version"] for p in selected)
            return SimpleNamespace(stdout=f"The following {len(selected)} package(s) will be affected (of 0 checked):\n\nNew packages to be INSTALLED:\n{rows}\n\nNumber of packages to be installed: {len(selected)}\n")
        runner.run.side_effect = dry_run
        with patch.object(discovery, "_catalog") as native:
            native.return_value.__enter__.return_value = (self.discovered["target"], available, ("pkg",))
            discovery.probe_packages(self.config, plan, runner)
            self.assertEqual(runner.run.call_count, 3)
            self.assertTrue(all(call.args[:7] == ("pkg", "install", "-n", "-y", "-U", "-r", "FreeBSD-ports")
                                for call in runner.run.call_args_list))
            runner.reset_mock()
            available["bastille"]["checksum"] = "2$" + "b" * 103
            with self.assertRaisesRegex(discovery.DiscoveryError, "Locked host package bastille changed"):
                discovery.probe_packages(self.config, plan, runner)
            runner.run.assert_not_called()
        self.assertEqual(plan, before)

    def test_native_probe_rejects_successful_solver_additions_without_changing_lock(self):
        plan = self.resolve()
        before = deepcopy(plan)
        runner = Mock()
        host = plan["packages"]["host"]
        rows = "\n".join(f"\t{name}: {record['version']}" for name, record in host.items())
        count = len(host) + 1
        runner.run.return_value.stdout = f"The following {count} package(s) will be affected (of 0 checked):\nNew packages to be INSTALLED:\n{rows}\n\tunexpected-provider: 1.0\nNumber of packages to be installed: {count}\n"
        with patch.object(discovery, "_catalog") as native:
            native.return_value.__enter__.return_value = (self.discovered["target"], self.discovered["packages"], ("pkg",))
            with self.assertRaisesRegex(discovery.DiscoveryError, "differs from the immutable lock"):
                discovery.probe_packages(self.config, plan, runner)
        self.assertEqual(plan, before)

    def test_metadata_extension_allows_future_candidates_without_code_change(self):
        self.discovered["nextcloud"] = ["35.0.9", "35.0.10"]
        self.discovered["connectors"] = {version: [signed_connector()] for version in self.discovered["nextcloud"]}
        with self.assertRaisesRegex(ValueError, "reviewed compatibility"):
            self.resolve()
        self.policy["profiles"][0]["applications"]["nextcloud"]["max_exclusive"] = "35.1.0"
        self.assertEqual(self.resolve()["applications"]["nextcloud"], "35.0.10")

    def test_exact_pins_distinguish_upstream_and_entire_onlyoffice_package(self):
        self.config.nextcloud_exact = "35.0.0"
        self.config.onlyoffice_exact = "9.4.0"
        self.assertEqual(self.resolve()["applications"]["nextcloud"], "35.0.0")
        self.config.onlyoffice_exact = "9.4.0_3"
        with self.assertRaisesRegex(ValueError, "exact pin"):
            self.resolve()
        self.config.onlyoffice_exact = "9.4.0_4"
        self.assertEqual(self.resolve()["applications"]["onlyoffice"], "9.4.0_4")
        self.config.onlyoffice_exact = "9.4.0_4,0"
        with self.assertRaises(ValueError):
            self.resolve()  # Full pins preserve even explicit epoch-zero identity.

    def test_newer_native_package_does_not_imply_historical_availability(self):
        change_version(self.discovered, "onlyoffice-documentserver", "10.0.0")
        with self.assertRaisesRegex(ValueError, "No compatible obtainable"):
            self.resolve()
        self.config.onlyoffice_exact = "9.4.0"
        with self.assertRaises(ValueError):
            self.resolve()

    def test_minimum_and_missing_stable_upstream_fail_without_fallback(self):
        self.config.nextcloud_min = "35.0.2"
        with self.assertRaises(ValueError):
            self.resolve()
        self.config.nextcloud_min = ""
        self.discovered["onlyoffice"] = ["10.0.0"]
        with self.assertRaisesRegex(ValueError, "absent from stable release"):
            self.resolve()

    def test_prerelease_applications_are_never_selected(self):
        self.discovered["nextcloud"] = ["35.0.1rc1", "35.0.1-beta", "latest-35"]
        with self.assertRaisesRegex(ValueError, "No stable"):
            self.resolve()
        self.discovered["nextcloud"] = ["35.0.1"]
        change_version(self.discovered, "onlyoffice-documentserver", "9.4.0rc1_4")
        with self.assertRaisesRegex(ValueError, "stable numeric release"):
            self.resolve()

    def test_dependency_graph_missing_conflicting_origin_and_abi_fail(self):
        mutations = [lambda d: d["packages"].pop("libxml2"),
                     lambda d: d["packages"]["libxml2"].update(version="2.14.2"),
                     lambda d: d["packages"]["libxml2"].update(origin="misc/not-libxml2"),
                     lambda d: d["packages"]["libxml2"].update(abi="FreeBSD:14:*"),
                     lambda d: d["packages"]["libxml2"].update(abi="FreeBSD:15:aarch64"),
                     lambda d: d["packages"].update(libxml2=[d["packages"]["libxml2"]]),
                     lambda d: d["packages"]["php85"].update(dependencies=[])]
        for mutate in mutations:
            discovery = deepcopy(self.discovered)
            mutate(discovery)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                resolution.resolve(self.config, discovery, policy=self.policy)

    def test_essential_ranges_not_pecl_or_date_versions(self):
        self.assertEqual(self.resolve()["packages"]["nextcloud"]["php85-pecl-APCu"]["version"], "5.1.28")
        for name, version in (("php85", "8.6.0"), ("mariadb123-server", "12.4.0"), ("apache24", "2.5.0"), ("bastille", "1.4.5")):
            with self.subTest(name=name):
                discovery = deepcopy(self.discovered)
                change_version(discovery, name, version)
                with self.assertRaisesRegex(ValueError, "Incompatible"):
                    resolution.resolve(self.config, discovery, policy=self.policy)

    def test_unrelated_missing_dependency_does_not_poison_selected_closure(self):
        self.discovered["packages"]["unrelated"] = record("unrelated", dependencies={"duplicate-openssl": {"version": "3.0", "origin": "security/openssl"}})
        self.assertNotIn("unrelated", self.resolve()["packages"]["nextcloud"])

    def test_cycles_terminate_and_still_check_every_edge(self):
        packages = self.discovered["packages"]
        packages["libxml2"]["dependencies"]["php85"] = {field: packages["php85"][field] for field in ("version", "origin")}
        self.assertIn("libxml2", self.resolve()["packages"]["nextcloud"])
        packages["libxml2"]["dependencies"]["missing"] = {"version": "1", "origin": "misc/missing"}
        with self.assertRaisesRegex(ValueError, "Missing/conflicting dependency"):
            self.resolve()

    def test_required_and_optional_fonts_and_ssh_acme_roots(self):
        self.config = configuration(tls_mode="acme", font_profile="comprehensive", jail_ssh=True, ssh_shell="zsh", ssh_admin=True)
        self.discovered = catalog(self.policy, self.config)
        self.discovered["packages"]["google-fonts"] = record("google-fonts", "20260101", "x11-fonts/google-fonts")
        plan = self.resolve()
        self.assertIn("py311-certbot", plan["roots"]["nextcloud"])
        self.assertIn("google-fonts", plan["roots"]["onlyoffice"])
        self.assertIn("noto-extra", plan["fonts_unavailable"])
        self.assertNotIn("google-fonts", plan["fonts_unavailable"])
        for group in ("nextcloud", "onlyoffice"):
            self.assertTrue({"doas", "zsh"}.issubset(plan["roots"][group]))
        resolution.validate_plan(self.config, plan, self.policy)
        self.discovered["packages"].pop("dejavu")
        with self.assertRaisesRegex(ValueError, "Required package dejavu"):
            self.resolve()

    def test_ambiguous_required_origin_and_arbitrary_extra_roots_rejected(self):
        self.config.tls_mode = "acme"
        self.discovered = catalog(self.policy, self.config)
        self.discovered["packages"]["py312-certbot"] = record("py312-certbot", "5.0.0", "security/py-certbot")
        with self.assertRaisesRegex(ValueError, "origin .* ambiguous"):
            self.resolve()
        self.config.tls_mode = "external"
        self.discovered["packages"]["unexpected-service"] = record("unexpected-service")
        self.discovered["extra_roots"] = {"onlyoffice": ["unexpected-service"]}
        with self.assertRaisesRegex(ValueError, "Unapproved extra root"):
            self.resolve()

    def test_webfonts_consent(self):
        self.config.accept_microsoft_fonts = False
        with self.assertRaisesRegex(ValueError, "accept_microsoft_fonts"):
            self.resolve()

    def test_connector_proof_and_manifest_bounds_fail_closed(self):
        cases = [{"platformVersionSpec": ">=33.0.0"}, {"phpVersionSpec": ">=8.2.0 <=8.6.0"},
                 {"phpVersionSpec": ">=8.2.0 <9.0.0"}, {"platformVersionSpec": ">=36.0.0 <37.0.0"},
                 {"signature": ""}, {"certificate": ""}, {"signatureDigest": "sha256"},
                 {"download": "http://example.org/app"}, {"isNightly": True}, {"version": "10.2.2"}]
        self.discovered["nextcloud"] = ["35.0.1"]
        for changes in cases:
            self.discovered["connectors"]["35.0.1"] = [signed_connector(**changes)]
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.resolve()
        self.discovered["connectors"] = {}
        with self.assertRaisesRegex(ValueError, "Missing signed connector"):
            self.resolve()
        self.discovered["connectors"] = {"35.0.1": [signed_connector(), signed_connector()]}
        with self.assertRaisesRegex(ValueError, "No unique obtainable signed connector"):
            self.resolve()

    def test_complete_retained_plan_revalidated_without_selecting_new_versions(self):
        self.config.nextcloud_exact = "35.0.0"
        plan = self.resolve()
        self.assertEqual(resolution.validate_plan(self.config, plan, self.policy)["applications"]["nextcloud"], "35.0.0")
        changes = [lambda p: p.update(policy_sha256="0" * 64), lambda p: p.update(repository="quarterly"),
                   lambda p: p["applications"].update(nextcloud="35.0.1"),
                   lambda p: p["applications"].update(connector="10.2.2"),
                   lambda p: p["packages"]["onlyoffice"].pop("nginx"),
                   lambda p: p["packages"]["onlyoffice"].update(orphan=record("orphan")),
                   lambda p: p["roles"].update(php="php86"),
                   lambda p: p["roots"]["nextcloud"].remove("gnupg"),
                   lambda p: p["packages"]["onlyoffice"]["python3"].update(version="3_9"),
                   lambda p: p["connector"].update(phpVersionSpec=">=8.2.0 <9.0.0"),
                   lambda p: p.update(fonts_unavailable=["dejavu"])]
        for mutate in changes:
            changed = deepcopy(plan)
            mutate(changed)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                resolution.validate_plan(self.config, changed, self.policy)
        changed_policy = deepcopy(self.policy)
        changed_policy["defaults"]["nextcloud_min"] = "35.0.1"
        with self.assertRaisesRegex(ValueError, "policy changed"):
            resolution.validate_plan(self.config, plan, changed_policy)

    def test_upgrade_assessment_never_authorizes_and_catches_revision_epoch_downgrades(self):
        installed = self.resolve()
        change_version(self.discovered, "onlyoffice-documentserver", "9.4.0_5")
        candidate = self.resolve()
        before = deepcopy((installed, candidate))
        report = resolution.assess_upgrade(installed, candidate)
        self.assertEqual(report["status"], "manual-review")
        self.assertFalse(report["execution_authorized"])
        self.assertFalse(report["migration_supported"])
        self.assertTrue(report["changes"])
        self.assertEqual((installed, candidate), before)
        report = resolution.assess_upgrade(candidate, installed)
        self.assertEqual(report["status"], "blocked")
        self.assertTrue(any("Downgrade refused" in item for item in report["blockers"]))
        for old_version, new_version in (("2.14.1_10", "2.14.1_9"), ("1.0,2", "99.0_99,1")):
            change_version(self.discovered, "libxml2", old_version)
            old = self.resolve()
            change_version(self.discovered, "libxml2", new_version)
            new = self.resolve()
            self.assertEqual(resolution.assess_upgrade(old, new)["status"], "blocked")
            with self.assertRaisesRegex(ValueError, "Downgrade refused"):
                self.resolve(installed=old)

    def test_unknown_installed_identity_and_changed_opaque_versions_fail_closed(self):
        installed = self.resolve()
        with self.assertRaisesRegex(ValueError, "resolved plan"):
            resolution.assess_upgrade({"applications": installed["applications"]}, installed)
        change_version(self.discovered, "libopaque", "1.0.b20260203")
        candidate = self.resolve()
        report = resolution.assess_upgrade(installed, candidate)
        self.assertEqual(report["status"], "blocked")
        self.assertTrue(any("Cannot safely order" in item for item in report["blockers"]))

    def test_upgrade_reports_exact_checksums_and_same_version_rebuild_is_blocked(self):
        installed = self.resolve()
        self.discovered["packages"]["bastille"]["checksum"] = "2$" + "b" * 103
        candidate = self.resolve()
        report = resolution.assess_upgrade(installed, candidate)
        self.assertEqual(report["status"], "blocked")
        self.assertIn({"component": "packages.host.bastille.checksum",
                       "from": "2$" + "y" * 103, "to": "2$" + "b" * 103}, report["changes"])
        self.assertTrue(any("Same-version package checksum" in item for item in report["blockers"]))
        change_version(self.discovered, "bastille", "1.4.4_2")
        report = resolution.assess_upgrade(installed, self.resolve())
        self.assertEqual(report["status"], "manual-review")
        self.assertTrue(any(item["component"].endswith(".checksum") for item in report["changes"]))

    def test_upgrade_reports_root_changes_even_when_closure_is_identical(self):
        installed = self.resolve()
        candidate = deepcopy(installed)
        candidate["roots"]["nextcloud"].append("libxml2")
        report = resolution.assess_upgrade(installed, candidate)
        self.assertEqual(report["changes"], [{"component": "roots", "from": installed["roots"],
                                             "to": candidate["roots"]}])
        self.assertFalse(report["execution_authorized"])

    def test_all_application_downgrades_and_dependency_removals_are_blocked(self):
        installed = self.resolve()
        self.config.nextcloud_exact = "35.0.0"
        candidate = self.resolve()
        self.assertTrue(any("applications.nextcloud" in item for item in resolution.assess_upgrade(installed, candidate)["blockers"]))
        candidate = deepcopy(installed)
        candidate["applications"]["connector"] = candidate["connector"]["version"] = "10.2.0"
        self.assertTrue(any("applications.connector" in item for item in resolution.assess_upgrade(installed, candidate)["blockers"]))
        self.config.nextcloud_exact = ""
        change_version(self.discovered, "php85", "8.5.12")
        self.discovered["packages"]["php85"]["dependencies"] = {}
        candidate = self.resolve()
        self.assertTrue(any("dependency removal" in item for item in resolution.assess_upgrade(installed, candidate)["blockers"]))

    def test_malformed_discovery_is_actionable_and_never_assumed_available(self):
        for field, value in (("schema_version", True), ("connectors", []), ("packages", []),
                             ("onlyoffice", []), ("sources", []), ("fonts_unavailable", None)):
            discovery = deepcopy(self.discovered)
            discovery[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                resolution.resolve(self.config, discovery, policy=self.policy)


if __name__ == "__main__":
    unittest.main()
