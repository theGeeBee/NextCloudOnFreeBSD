"""Backend-scoped resolution fixtures; no repository or native availability claims."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from installer import compatibility, discovery, resolution, version_runtime, versions
from test_versions import catalog, change_version, configuration, record, signed_connector
from version_fixtures import historic_policy


def none_metadata(config=None, policy=None, role_versions=None):
    config = configuration(office_backend="none") if config is None else config
    policy = versions.load_policy() if policy is None else policy
    profile = versions.selected_profiles(config, policy)[0]
    packages = {}
    for names in compatibility.package_roots(config, policy).values():
        for name in names:
            package = "py311-certbot" if name == "security/py-certbot" else name.split("/")[-1]
            packages[package] = record(package, origin=name if "/" in name else None)
    selected = dict(manager="1.4.4_1", php="8.5.11", database="12.3.3",
                    database_client="12.3.3", web="2.4.65", cache="7.4.1")
    selected.update(role_versions or {})
    for role, rule in profile["roles"].items():
        packages[rule["package"]] = record(rule["package"], selected[role], rule["origin"])
    php = profile["roles"]["php"]["package"]
    packages["fixture-library"] = record("fixture-library", "1.2.3")
    packages[php]["dependencies"] = {"fixture-library": {key: packages["fixture-library"][key]
                                                         for key in ("version", "origin")}}
    for template in profile["php_extensions"]:
        name = template.replace("{suffix}", profile["php_suffix"])
        packages[name]["version"] = {"pecl-APCu": "5.1.28", "pecl-redis": "6.3.0",
                                     "pecl-imagick": "3.8.1"}.get(name.split("-", 1)[1], selected["php"])
        packages[name]["dependencies"] = {php: {key: packages[php][key] for key in ("version", "origin")}}
    return {"schema_version": 2, "office_backend": "none",
            "target": versions.target(policy, "15.1-RELEASE", "amd64"),
            "repository": config.repository, "nextcloud": ["35.0.0", "35.0.1", "35.0.2", "36.0.0"],
            "packages": packages, "sources": ["https://example.test/synthetic-catalog"]}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def native_responses(releases):
    return {
        discovery.NEXTCLOUD_RELEASES: "".join(f'<a href="nextcloud-{version}.tar.bz2{suffix}">release</a>'
                                             for version in releases for suffix in ("", ".asc")),
        discovery.ONLYOFFICE_RELEASES: json.dumps([
            {"tag_name": "v" + version, "prerelease": False, "draft": False} for version in ("9.4.0", "10.0.0")]),
        **{discovery.CONNECTORS.format(version=version): json.dumps([
            {"id": "onlyoffice", "certificate": "fixture-certificate", "releases": [signed_connector()]}])
           for version in releases},
    }


class BackendVersionTests(unittest.TestCase):
    def setUp(self):
        self.policy = versions.load_policy()
        self.config = configuration(office_backend="none", accept_microsoft_fonts=False)
        self.metadata = none_metadata(self.config, self.policy)

    def resolve(self, **kwargs):
        return resolution.resolve(self.config, self.metadata, policy=self.policy, **kwargs)

    def test_none_profile_repeats_shared_requirements_without_inheritance(self):
        native, none = self.policy["profiles"][:2]
        self.assertEqual(none["office_backend"], "none")
        for field in ("targets", "php_suffix", "php_extensions", "extension_ranges", "dependency_policy"):
            self.assertEqual(native[field], none[field])
        for role, rule in none["roles"].items():
            self.assertEqual(native["roles"][role], rule)
        for mutate in (lambda p: p.update(connector={}), lambda p: p.update(extends=native["id"]),
                       lambda p: p["applications"].update(onlyoffice={"exact": "9.4.0"}),
                       lambda p: p["roots"].update(onlyoffice=[]),
                       lambda p: p["optional_roots"]["zsh"].update(onlyoffice=["zsh"]),
                       lambda p: p["roles"]["manager"].update(groups=["onlyoffice"])):
            policy = deepcopy(self.policy)
            mutate(policy["profiles"][1])
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                versions.validate_policy(policy)

    def test_none_resolves_complete_host_and_nc_closures_without_office(self):
        before = deepcopy((self.config.__dict__, self.metadata, self.policy))
        with patch.object(Path, "read_text", side_effect=AssertionError("resolver I/O")), \
                patch("subprocess.run", side_effect=AssertionError("resolver command")):
            plan = self.resolve()
            self.assertEqual(resolution.validate_plan(self.config, plan, self.policy), plan)
        self.assertEqual(before, (self.config.__dict__, self.metadata, self.policy))
        self.assertEqual(plan["schema_version"], 2)
        self.assertEqual(plan["office_backend"], "none")
        self.assertEqual(plan["applications"], {"nextcloud": "35.0.2"})
        self.assertEqual(set(plan["constraints"]), set(versions.NC_FIELDS))
        self.assertEqual(set(plan["packages"]), {"host", "nextcloud"})
        self.assertIn("bastille", plan["packages"]["host"])
        self.assertIn("fixture-library", plan["packages"]["nextcloud"])
        for field in ("connector", "fonts_unavailable", "onlyoffice"):
            self.assertNotIn(field, plan)
            self.assertNotIn(field, plan["roles"])

    def test_none_optional_roots_only_apply_to_nextcloud(self):
        config = configuration(office_backend="none", tls_mode="acme", jail_ssh=True,
                               ssh_shell="zsh", ssh_admin=True, antivirus=True,
                               font_profile="comprehensive", accept_microsoft_fonts=False)
        roots = compatibility.package_roots(config, self.policy)
        self.assertEqual(set(roots), {"host", "nextcloud"})
        self.assertTrue({"security/py-certbot", "security/clamav", "zsh", "doas"} <= set(roots["nextcloud"]))
        self.assertFalse(set(self.policy["fonts"]["required"]) & set(roots["nextcloud"]))
        plan = resolution.resolve(config, none_metadata(config, self.policy), policy=self.policy)
        self.assertEqual(resolution.validate_plan(config, plan, self.policy), plan)

    def test_discovery_fetches_only_nc_and_keeps_selected_closure(self):
        releases = '<a href="nextcloud-35.0.1.tar.bz2">release</a><a href="nextcloud-35.0.1.tar.bz2.asc">signature</a>'
        fetch = Mock(return_value=releases)
        available = deepcopy(self.metadata["packages"])
        available["onlyoffice-documentserver"] = record("onlyoffice-documentserver")
        available["webfonts"] = record("webfonts")
        with patch.object(discovery, "_catalog") as native, \
                patch.object(discovery, "onlyoffice_versions", side_effect=AssertionError("office query")), \
                patch.object(discovery, "connector_releases", side_effect=AssertionError("connector query")):
            native.return_value.__enter__.return_value = (self.metadata["target"], available, ())
            metadata = discovery.discover(self.config, Mock(), fetch=fetch, policy=self.policy)
        fetch.assert_called_once_with(discovery.NEXTCLOUD_RELEASES)
        self.assertEqual(set(metadata), {"schema_version", "office_backend", "target", "repository", "nextcloud", "packages", "sources"})
        self.assertNotIn("onlyoffice-documentserver", metadata["packages"])
        self.assertNotIn("webfonts", metadata["packages"])
        resolution.resolve(self.config, metadata, policy=self.policy)

    def test_none_discovery_filters_future_profiles_before_catalog_access(self):
        future = deepcopy(self.policy["profiles"][1])
        future.update(id="synthetic-nc36-none")
        future["applications"]["nextcloud"] = {"exact": "36.0.0"}
        future["roots"]["nextcloud"].append("unavailable-future-package")
        self.policy["profiles"].append(future)
        for pin, advertised in (("35.0.1", ["35.0.1", "36.0.0"]), ("", ["35.0.1"])):
            config = configuration(office_backend="none", nextcloud_exact=pin)
            releases = "".join(f'<a href="nextcloud-{version}.tar.bz2{suffix}">release</a>'
                               for version in advertised for suffix in ("", ".asc"))
            events = []
            original = compatibility.profile_roots
            def roots(config, profile):
                events.append(profile["id"])
                return original(config, profile)
            with self.subTest(pin=pin), patch.object(compatibility, "profile_roots", side_effect=roots), \
                    patch.object(discovery, "_catalog") as native:
                native.return_value.__enter__.side_effect = lambda: (
                    events.append("catalog") or (self.metadata["target"], self.metadata["packages"], ()))
                metadata = discovery.discover(config, Mock(), fetch=Mock(return_value=releases), policy=self.policy)
            self.assertEqual(events, ["nc35-none-php85-mariadb123", "catalog"])
            plan = resolution.resolve(config, metadata, policy=self.policy)
            self.assertEqual(plan["applications"], {"nextcloud": "35.0.1"})

    def test_none_discovery_leaves_candidate_dependency_failures_to_resolver(self):
        future = deepcopy(self.policy["profiles"][1])
        future.update(id="synthetic-nc36-none")
        future["applications"]["nextcloud"] = {"exact": "36.0.0"}
        self.policy["profiles"].append(future)
        releases = "".join(f'<a href="nextcloud-{version}.tar.bz2{suffix}">release</a>'
                           for version in ("35.0.1", "36.0.0") for suffix in ("", ".asc"))
        for failure in ("missing-root", "missing-dependency", "ambiguous-origin"):
            available = deepcopy(self.metadata["packages"])
            future["roots"]["nextcloud"] = ["gnupg", "python3", "future-adapter"]
            if failure == "missing-dependency":
                available["future-adapter"] = record("future-adapter", dependencies={
                    "missing-library": {"version": "1.0", "origin": "devel/missing-library"}})
            elif failure == "ambiguous-origin":
                future["roots"]["nextcloud"][-1] = "devel/future-adapter"
                for name in ("future-adapter-a", "future-adapter-b"):
                    available[name] = record(name, origin="devel/future-adapter")
            with self.subTest(failure=failure), patch.object(discovery, "_catalog") as native:
                native.return_value.__enter__.return_value = (self.metadata["target"], available, ())
                metadata = discovery.discover(self.config, Mock(), fetch=Mock(return_value=releases), policy=self.policy)
                plan = resolution.resolve(self.config, metadata, policy=self.policy)
                self.assertEqual(plan["applications"], {"nextcloud": "35.0.1"})
                self.assertEqual(resolution.validate_plan(self.config, plan, self.policy), plan)
                direct = {**metadata, "packages": available}
                self.assertEqual(resolution.resolve(self.config, direct, policy=self.policy), plan)
                config = configuration(office_backend="none", nextcloud_exact="36.0.0")
                with self.assertRaisesRegex(ValueError, "No compatible obtainable"):
                    resolution.resolve(config, metadata, policy=self.policy)

    def test_none_discovery_refuses_no_applicable_profile_before_catalog(self):
        releases = '<a href="nextcloud-36.0.0.tar.bz2">release</a><a href="nextcloud-36.0.0.tar.bz2.asc">signature</a>'
        with patch.object(discovery, "_catalog") as native:
            with self.assertRaisesRegex(ValueError, "No reviewed Nextcloud package profile"):
                discovery.discover(self.config, Mock(), fetch=Mock(return_value=releases), policy=self.policy)
            native.assert_not_called()

    def test_native_discovery_defers_roots_until_candidate_profile_matches(self):
        config = configuration(nextcloud_exact="35.0.1", onlyoffice_exact="9.4.0", antivirus=True)
        available = catalog(self.policy, config)
        responses = native_responses(["35.0.1", "36.0.0"])
        for excluded_by in ("nextcloud", "onlyoffice", "target", "backend"):
            policy = deepcopy(self.policy)
            future = deepcopy(policy["profiles"][1 if excluded_by == "backend" else 0])
            future["id"] = "synthetic-future-" + excluded_by
            future["roots"]["nextcloud"].append("unavailable-future-package")
            # Old native discovery eagerly evaluated this irrelevant feature gap
            # for NC/OO-incompatible profiles before even reading availability.
            future["optional_roots"].pop("antivirus")
            if excluded_by == "nextcloud":
                future["applications"]["nextcloud"] = {"exact": "36.0.0"}
            elif excluded_by == "onlyoffice":
                future["applications"]["onlyoffice"] = {"exact": "10.0.0"}
                future["roles"]["onlyoffice"]["range"] = {"exact": "10.0.0"}
            elif excluded_by == "target":
                other = deepcopy(policy["targets"][0])
                other.update(release="14.3-RELEASE", abi="FreeBSD:14:amd64")
                policy["targets"].append(other)
                future["targets"] = ["14.3-RELEASE/amd64"]
            policy["profiles"].append(future)
            original = compatibility.profile_roots
            with self.subTest(excluded_by=excluded_by), \
                    patch.object(compatibility, "profile_roots", wraps=original) as roots, \
                    patch.object(discovery, "_catalog") as native:
                native.return_value.__enter__.return_value = (available["target"], available["packages"], ())
                metadata = discovery.discover(config, Mock(), fetch=responses.__getitem__, policy=policy)
                roots.assert_not_called()
                self.assertEqual(metadata["packages"], available["packages"])
                plan = resolution.resolve(config, metadata, policy=policy)
                self.assertEqual(plan["applications"], {"nextcloud": "35.0.1", "onlyoffice": "9.4.0_4", "connector": "10.2.1"})
                self.assertTrue(roots.called)
                self.assertTrue(all(call.args[1]["id"] == "nc35-oo94-php85-mariadb123" for call in roots.call_args_list))
                self.assertEqual(resolution.validate_plan(config, plan, policy), plan)

    def test_native_discovery_preserves_per_candidate_dependency_fallback(self):
        config = configuration(antivirus=True)
        available = catalog(self.policy, config)
        responses = native_responses(["35.0.0", "35.0.1"])
        policy = deepcopy(self.policy)
        policy["profiles"][0]["applications"]["nextcloud"] = {"exact": "35.0.0"}
        newer = deepcopy(policy["profiles"][0])
        newer["id"] = "synthetic-native-newer"
        newer["applications"]["nextcloud"] = {"exact": "35.0.1"}
        newer["roots"]["nextcloud"].append("future-adapter")
        policy["profiles"].append(newer)
        for failure in ("missing-root", "missing-dependency", "missing-feature"):
            packages = deepcopy(available["packages"])
            if failure == "missing-dependency":
                packages["future-adapter"] = record("future-adapter", dependencies={
                    "missing-library": {"version": "1.0", "origin": "devel/missing-library"}})
            elif failure == "missing-feature":
                packages["future-adapter"] = record("future-adapter")
                newer["optional_roots"].pop("antivirus")
            with self.subTest(failure=failure), patch.object(discovery, "_catalog") as native:
                native.return_value.__enter__.return_value = (available["target"], packages, ())
                metadata = discovery.discover(config, Mock(), fetch=responses.__getitem__, policy=policy)
                plan = resolution.resolve(config, metadata, policy=policy)
                self.assertEqual(plan["applications"]["nextcloud"], "35.0.0")
                self.assertNotIn("future-adapter", plan["packages"]["nextcloud"])
                self.assertEqual(resolution.validate_plan(config, plan, policy), plan)
                pinned = configuration(antivirus=True, nextcloud_exact="35.0.1")
                with self.assertRaisesRegex(ValueError, "No compatible obtainable"):
                    resolution.resolve(pinned, metadata, policy=policy)

    def test_unsupported_backends_fail_before_fetch_or_catalog_or_solver(self):
        policy = deepcopy(self.policy)
        policy['profiles'] = policy['profiles'][:2]  # No VM policy in this fixture.
        for backend in ("eurooffice", "collabora", "unreviewed"):
            config = configuration(office_backend=backend)
            with self.subTest(backend=backend), patch.object(discovery, "_catalog") as native:
                fetch, runner = Mock(), Mock()
                with self.assertRaisesRegex(ValueError, "No reviewed version policy"):
                    discovery.discover(config, runner, fetch=fetch, policy=policy)
                with self.assertRaisesRegex(ValueError, "No reviewed version policy"):
                    resolution.resolve(config, {}, policy=policy)
                with self.assertRaisesRegex(ValueError, "No reviewed version policy"):
                    compatibility.package_roots(config, policy)
                with self.assertRaisesRegex(ValueError, "No reviewed version policy" if backend == 'unreviewed' else 'backend does not match'):
                    discovery.probe_packages(config, {}, runner)
                fetch.assert_not_called()
                native.assert_not_called()
                self.assertFalse(runner.mock_calls)

    def test_vm_constraints_and_missing_policy_catalog_refusal(self):
        for backend in ("eurooffice", "collabora"):
            config = configuration(office_backend=backend, nextcloud_min="35", nextcloud_exact="35.0.1")
            effective = versions.constraints(config, self.policy)
            self.assertEqual(set(effective), set(versions.NC_FIELDS))
            self.assertEqual(effective["nextcloud_min"], "35.0.0")
            self.assertEqual(effective["nextcloud_exact"], "35.0.1")
            self.assertEqual(len(versions.selected_profiles(config, self.policy)), 1)
            policy = deepcopy(self.policy)
            policy['profiles'] = policy['profiles'][:2]
            runner = Mock()
            with self.assertRaisesRegex(ValueError, "No reviewed version policy"):
                with discovery._catalog(config, runner, policy=policy):
                    self.fail("Unreviewed backend entered catalog context")
            self.assertFalse(runner.mock_calls)

    def test_none_minimum_pin_and_missing_nc_dependency_never_fall_back(self):
        for changes in ({"nextcloud_min": "35.0.3"}, {"nextcloud_exact": "35.0.3"},
                        {"nextcloud_exact": "35.0.1rc1"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                resolution.resolve(configuration(office_backend="none", **changes), self.metadata, policy=self.policy)
        config = configuration(office_backend="none", nextcloud_exact="35.0.0")
        self.assertEqual(resolution.resolve(config, self.metadata, policy=self.policy)["applications"], {"nextcloud": "35.0.0"})
        for name in ("bastille", "php85", "fixture-library"):
            metadata = deepcopy(self.metadata)
            metadata["packages"].pop(name)
            with self.subTest(name=name), self.assertRaises(ValueError):
                resolution.resolve(self.config, metadata, policy=self.policy)

    def test_missing_backend_profile_fails_before_discovery(self):
        self.policy["profiles"] = self.policy["profiles"][:1]
        with patch.object(discovery, "_catalog") as native:
            fetch = Mock()
            with self.assertRaisesRegex(ValueError, "No reviewed compatibility profiles"):
                discovery.discover(self.config, Mock(), fetch=fetch, policy=self.policy)
            native.assert_not_called()
            fetch.assert_not_called()

    def test_none_metadata_has_strict_backend_bound_schema(self):
        for mutate in (lambda p: p.update(schema_version=1), lambda p: p.update(schema_version=True),
                       lambda p: p.pop("office_backend"), lambda p: p.update(office_backend="onlyoffice"),
                       lambda p: p.update(onlyoffice=[]), lambda p: p.update(connectors={}),
                       lambda p: p.update(fonts_unavailable=[]), lambda p: p.update(extra_roots={"onlyoffice": []})):
            metadata = deepcopy(self.metadata)
            mutate(metadata)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                resolution.resolve(self.config, metadata, policy=self.policy)
        with self.assertRaises(ValueError):
            resolution.resolve(configuration(), self.metadata, policy=self.policy)
        with self.assertRaises(ValueError):
            resolution.resolve(self.config, catalog(), policy=self.policy)

    def test_retained_none_plan_is_strict_and_bound_to_config_and_policy(self):
        plan = self.resolve()
        mutations = (lambda p: p.update(schema_version=1), lambda p: p.update(office_backend="onlyoffice"),
                     lambda p: p.update(connector={}), lambda p: p.update(fonts_unavailable=[]),
                     lambda p: p["applications"].update(onlyoffice="9.4.0"),
                     lambda p: p["constraints"].update(onlyoffice_min="9.4.0"),
                     lambda p: p["packages"].update(onlyoffice={}), lambda p: p["roots"].update(onlyoffice=[]),
                     lambda p: p["packages"]["host"].pop("bastille"),
                     lambda p: p["packages"]["nextcloud"].pop("fixture-library"),
                     lambda p: p["packages"]["nextcloud"].update(orphan=record("orphan")),
                     lambda p: p["roots"]["nextcloud"].remove("gnupg"),
                     lambda p: p["roles"].update(manager="php85"),
                     lambda p: p["packages"]["nextcloud"]["php85"]["dependencies"].clear(),
                     lambda p: p.update(policy_sha256="0" * 64), lambda p: p.update(repository="quarterly"))
        for mutate in mutations:
            retained = deepcopy(plan)
            mutate(retained)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                resolution.validate_plan(self.config, retained, self.policy)
        with self.assertRaisesRegex(ValueError, "backend changed"):
            resolution.validate_plan(configuration(), plan, self.policy)
        native = resolution.resolve(configuration(), catalog(), policy=self.policy)
        with self.assertRaisesRegex(ValueError, "backend changed"):
            resolution.validate_plan(self.config, native, self.policy)
        self.config.nextcloud_exact = "35.0.0"
        with self.assertRaisesRegex(ValueError, "constraints or target changed"):
            resolution.validate_plan(self.config, plan, self.policy)

    def test_unreviewed_nc_and_dependencies_fail_until_explicit_policy_change(self):
        self.metadata["nextcloud"] = ["36.0.0", "36.0.1", "36.0.2rc1"]
        with self.assertRaisesRegex(ValueError, "reviewed compatibility profile"):
            self.resolve()
        profile = self.policy["profiles"][1]
        profile["applications"]["nextcloud"] = {"min": "36.0.0", "max_exclusive": "36.0.2"}
        change_version(self.metadata, "php85", "8.6.1")
        with self.assertRaisesRegex(ValueError, "Incompatible php"):
            self.resolve()
        # Synthetic future requirements: names/flavors and bounds are policy data.
        profile["php_suffix"] = "86"
        profile["roles"]["php"].update(package="php86", origin="lang/php86",
                                        range={"min": "8.6.0", "max_exclusive": "8.7.0"})
        for role, suffix in (("database", "server"), ("database_client", "client")):
            name = "mariadb124-" + suffix
            profile["roles"][role].update(package=name, origin="databases/" + name,
                                         range={"min": "12.4.0", "max_exclusive": "12.5.0"})
        self.metadata = none_metadata(self.config, self.policy,
                                      dict(php="8.6.1", database="12.4.1", database_client="12.4.1"))
        self.metadata["nextcloud"] = ["36.0.0", "36.0.1", "36.0.2rc1"]
        plan = self.resolve()
        self.assertEqual(plan["applications"], {"nextcloud": "36.0.1"})
        self.assertEqual(plan["roles"]["php"], "php86")
        self.assertEqual(plan["roles"]["database"], "mariadb124-server")
        self.assertEqual(resolution.validate_plan(self.config, plan, self.policy), plan)

    def test_none_runtime_payload_has_only_common_fields_and_backend(self):
        plan = self.resolve()
        text = version_runtime.package_text(plan, "nextcloud")
        edges = version_runtime.dependency_text(plan, "nextcloud")
        runtime = version_runtime.runtime_versions(plan, text, edges)
        self.assertEqual(runtime["office_backend"], "none")
        self.assertEqual(runtime["plan_sha256"], digest(plan))
        self.assertEqual(set(runtime), {"office_backend", "nextcloud", "php", "database", "php_package",
                                        "freebsd_release", "architecture", "plan_sha256", "packages_sha256", "dependencies_sha256"})
        for changes in ({"connector": "10.2.1"}, {"onlyoffice": "9.4.0"}, {"office_backend": "onlyoffice"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                version_runtime.validate_runtime_versions({**runtime, **changes})
        with self.assertRaises(ValueError):
            version_runtime.package_text(plan, "onlyoffice")
        with self.assertRaises(ValueError):
            version_runtime.connector_text(plan)

    def test_none_solver_has_two_groups_and_rejects_backend_switch_before_probe(self):
        plan = self.resolve()
        runner = Mock()
        def dry_run(*args, **kwargs):
            selected = [p for p in self.metadata["packages"].values() if p["name"] + "-" + p["version"] in args[7:]]
            rows = "\n".join(f"\t{p['name']}: {p['version']}" for p in selected)
            return SimpleNamespace(stdout=f"The following {len(selected)} package(s) will be affected (of 0 checked):\nNew packages to be INSTALLED:\n{rows}\nNumber of packages to be installed: {len(selected)}\n")
        runner.run.side_effect = dry_run
        with patch.object(discovery, "_catalog") as native:
            native.return_value.__enter__.return_value = (self.metadata["target"], self.metadata["packages"], ("pkg",))
            discovery.probe_packages(self.config, plan, runner)
            self.assertEqual(runner.run.call_count, 2)
            native.reset_mock()
            with self.assertRaisesRegex(ValueError, "backend"):
                discovery.probe_packages(configuration(), plan, runner)
            native.assert_not_called()

    def test_assessment_refuses_backend_changes_and_none_downgrades(self):
        plan = self.resolve()
        native = resolution.resolve(configuration(), catalog(), policy=self.policy)
        for old, new in ((native, plan), (plan, native)):
            report = resolution.assess_upgrade(old, new)
            self.assertEqual(report["status"], "blocked")
            self.assertFalse(report["execution_authorized"])
            self.assertIn("backend changes", report["blockers"][0])
        with self.assertRaisesRegex(ValueError, "backend changes"):
            self.resolve(installed=native)
        self.config.nextcloud_exact = "35.0.0"
        with self.assertRaisesRegex(ValueError, "Downgrade refused"):
            self.resolve(installed=plan)
        self.config.nextcloud_exact = ""
        self.assertEqual(resolution.assess_upgrade(plan, self.resolve())["status"], "manual-review")
        change_version(self.metadata, "fixture-library", "1.2.4")
        report = resolution.assess_upgrade(plan, self.resolve())
        self.assertEqual(report["status"], "blocked")
        self.assertTrue(any("Dependency metadata changed" in blocker for blocker in report["blockers"]))

    def test_native_schema_one_plan_and_runtime_bytes_match_prechange_baseline(self):
        policy = historic_policy()
        expected_runtime = {"host": "f0df1922a97b592676d32d8c10c49e10f1bee78fa2667dba9970bf74ab1221be",
                            "nextcloud": "3005a44c277ce084ddc32151cf7220605ad9a46870654c929922097fd3a48e04",
                            "onlyoffice": "2ce1c131ad4a743fea0cb5ca9791bd5c019838af61683928ae1fa23598d8801b"}
        for config in (configuration(), configuration(office_backend=""), configuration(office_backend="onlyoffice")):
            plan = resolution.resolve(config, catalog(policy), policy=policy)
            self.assertEqual(digest(plan), "7b545eed6fd1845f7f56f3ed16f7cd4371dd06d0155c83750036c4d930de1d07")
            self.assertEqual(plan["policy_sha256"], "daa55a823bbe3f895504a8e5e6b0f274b6d02feb81d2a6835f2a8104bbc60efe")
            for group, expected in expected_runtime.items():
                runtime = version_runtime.runtime_versions(plan, version_runtime.package_text(plan, group),
                                                           version_runtime.dependency_text(plan, group))
                self.assertEqual(digest(runtime), expected)
            self.assertEqual(resolution.validate_plan(config, plan, policy), plan)
        old_policy = deepcopy(policy)
        old_policy["profiles"] = old_policy["profiles"][:1]
        old = resolution.resolve(configuration(), catalog(old_policy), policy=old_policy)
        self.assertEqual(resolution.validate_plan(configuration(), old, policy), old)


if __name__ == "__main__":
    unittest.main()
