"""Mocked native 2.8.4 contracts; these are not FreeBSD integration evidence."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest

from installer import upgrade_packages as packages
from installer.compatibility import profile_roots
from installer.versions import load_policy
from version_fixtures import discovery_metadata


REPOSITORY = '''FreeBSD-ports: {
    url             : "pkg+https://pkg.FreeBSD.org/FreeBSD:15:amd64/latest",
    enabled         : yes,
    priority        : 0,
    mirror_type     : "SRV",
    signature_type  : "FINGERPRINTS",
    fingerprints    : "/usr/share/keys/pkg"
  }
'''
# src/utils.c:display_summary_item and print_jobs_summary (tag 2.8.4).
MIXED = '''The following 5 package(s) will be affected (of 41 checked):

Installed packages to be REMOVED:
	obsolete: 1.0 (conflicts with other)

New packages to be INSTALLED:
	libnew: 2.0 [FreeBSD-ports]

Installed packages to be UPGRADED:
	php85: 8.5.11 -> 8.5.12 [FreeBSD-ports]

Installed packages to be DOWNGRADED:
	libold: 2.0 -> 1.0 [FreeBSD-ports]

Installed packages to be REINSTALLED:
	php85-curl-8.5.11 [FreeBSD-ports] (direct dependency changed: curl) (vulnerable!)

Number of packages to be removed: 1
Number of packages to be installed: 1
Number of packages to be upgraded: 1
Number of packages to be reinstalled: 1
Number of packages to be downgraded: 1

The operation will free 2 MiB.
4 MiB to be downloaded.

WARNING: 1 package(s) have known vulnerabilities
'''


def summary(rows):
    if not rows:
        return "Your packages are up to date.\n"
    groups = {}
    for action, name, old, new in rows:
        groups.setdefault(action, []).append((name, old, new))
    output = [f"The following {len(rows)} package(s) will be affected (of 42 checked):"]
    for action, values in groups.items():
        output.append(("New" if action == "installed" else "Installed") + " packages to be " + action.upper() + ":")
        for name, old, new in values:
            row = f"\t{name}-{new}" if action == "reinstalled" else f"\t{name}: " + (f"{old} -> {new}" if action in ("upgraded", "downgraded") else new or old)
            output.append(row + " [FreeBSD-ports]")
    output += [f"Number of packages to be {action}: {len(values)}" for action, values in groups.items()]
    return "\n".join(output) + "\n"


class Target:
    def __init__(self):
        self.config = SimpleNamespace(repository="latest", tls_mode="acme")
        self.nc, self.office = "cloudnc", "cloudoo"
        self.nc_root, self.office_root = Path("/jails/cloudnc/root"), Path("/jails/cloudoo/root")
        self.calls, self.rows, self.installed, self.remote = [], {}, {}, {}
        self.source = "35.0.1"
        self.repository = REPOSITORY
        self.key = 'function: "sha256"\nfingerprint: "' + packages.FINGERPRINT + '"\n'
        self.settings = dict(ABI="FreeBSD:15:amd64", PKG_DBDIR="/var/db/pkg", RUN_SCRIPTS="yes",
                             SAT_SOLVER="", CUDF_SOLVER="", PKG_ENV="", ALIAS="")
        self.fail, self.on_fetch, self.bad_verify = None, None, False
        all_packages = discovery_metadata(self.config)["packages"]
        profile = load_policy()["profiles"][0]
        for name, item in all_packages.items():
            if name.startswith("php85-") and "-pecl-" not in name:
                item["version"] = "8.5.11"
        for group, jail in (("nextcloud", self.nc), ("onlyoffice", self.office)):
            roots = profile_roots(self.config, profile)[group]
            if group == "onlyoffice":
                roots += ["nginx", "py311-supervisor"]
            pending = [next(name for name, value in all_packages.items() if value["origin"] == root) if "/" in root else root for root in roots]
            installed = {}
            while pending:
                name = pending.pop()
                if name not in installed:
                    installed[name] = deepcopy(all_packages[name])
                    pending.extend(installed[name]["dependencies"])
            self.remote[jail] = deepcopy(installed)
            self.installed[jail] = {name: {k: v for k, v in item.items() if k != "checksum"} for name, item in installed.items()}
            # Real thick-jail inventories may also contain pkgbase, left untouched.
            self.installed[jail]["FreeBSD-runtime"] = dict(name="FreeBSD-runtime", version="15.1", origin="base/FreeBSD-runtime",
                                                        abi="FreeBSD:15:amd64", dependencies={})
            self.rows[jail] = []

    def upgrade(self, jail, name, version):
        old = self.installed[jail][name]["version"]
        self.remote[jail][name]["version"] = version
        self.rows[jail].append(("upgraded", name, old, version))

    def run_jail(self, jail, *argv, input=None, timeout=120, check=True):
        self.calls.append((jail, argv, input, timeout, check))
        if self.fail and self.fail(jail, argv):
            return subprocess.CompletedProcess(argv, 1, "secret-runtime-output", "private-password")
        if argv == ("/bin/cat", "/usr/local/www/nextcloud/version.php"):
            output = "<?php\n$OC_VersionString = '" + self.source + "';\n"
        elif argv == ("/bin/sh", "-c", packages.KEYS):
            output = self.key
        elif argv == ("/bin/freebsd-version", "-u"):
            output = "15.1-RELEASE-p1\n"
        else:
            assert argv[:len(packages.PKG)] == packages.PKG, argv
            args = argv[len(packages.PKG):]
            command = args[0]
            if command == "-v":
                output = "2.8.4\n"
            elif command == "config":
                output = self.settings[args[1]] + "\n"
            elif command == "repositories":
                output = self.repository
            elif command == "update":
                output = "FreeBSD-ports repository update completed.\n"
            elif command in ("query", "rquery"):
                inventory = self.installed[jail] if command == "query" else {name: self.remote[jail][name] for name in args[5:]}
                fmt = args[2] if command == "query" else args[4]
                if "%dn" in fmt:
                    output = "\n".join("|".join((name, dep, req["version"], req["origin"])) for name, item in inventory.items() for dep, req in item["dependencies"].items())
                else:
                    output = "\n".join("|".join((name, item["version"], item["origin"], item["abi"], str(len(item["dependencies"]))))
                                       + ("|" + item["checksum"] if command == "rquery" else "") for name, item in inventory.items())
            elif command == "upgrade":
                output = summary(self.rows[jail])
                if "-F" in args:
                    if self.on_fetch:
                        self.on_fetch(self, jail)
                elif "-n" not in args:
                    assert input == "y\n" and "-y" not in args
                    if not self.bad_verify:
                        for _, name, _, _ in self.rows[jail]:
                            self.installed[jail][name] = {k: deepcopy(v) for k, v in self.remote[jail][name].items() if k != "checksum"}
                        self.rows[jail] = []
            else:
                raise AssertionError(args)
        return subprocess.CompletedProcess(argv, 0, output, "")


class ParserTests(unittest.TestCase):
    def test_all_five_native_actions_and_bounded_notes(self):
        actions, notes = packages.parse_summary(MIXED)
        self.assertEqual({a["action"] for a in actions}, {"installed", "removed", "upgraded", "downgraded", "reinstalled"})
        reinstall = next(a for a in actions if a["action"] == "reinstalled")
        self.assertEqual((reinstall["name"], reinstall["old_version"], reinstall["new_version"]), ("php85-curl", "8.5.11", "8.5.11"))
        self.assertEqual(len(notes), 3)

    def test_noop_is_explicit_not_empty(self):
        self.assertEqual(packages.parse_summary("Your packages are up to date.\n"), ([], []))
        for output in ("", "\n", "Everything is okay", "Your packages are up to date.\nsecret"):
            with self.subTest(output=output), self.assertRaises(packages.PackageUpgradeError):
                packages.parse_summary(output)

    def test_cached_archive_integrity_prefix_is_reviewed(self):
        self.assertEqual(packages.parse_summary("Checking integrity... done (0 conflicting)\n" + MIXED), packages.parse_summary(MIXED))
        with self.assertRaises(packages.PackageUpgradeError):
            packages.parse_summary("Checking integrity... done (1 conflicting)\n" + MIXED)

    def test_unknown_or_truncated_actions_never_disappear(self):
        for output in (MIXED.replace("5 package(s)", "6 package(s)"),
                       MIXED.replace("removed: 1", "removed: 2"),
                       MIXED + "New groups to be INSTALLED:\n\t@base\n",
                       MIXED.replace("[FreeBSD-ports]", "[unsigned]"),
                       MIXED.replace("UPGRADED:", "LOCKED:"),
                       MIXED + "\tunexpected: 1.0\n"):
            with self.subTest(output=output[-60:]), self.assertRaises(packages.PackageUpgradeError):
                packages.parse_summary(output)

    def test_repository_allowlist_and_no_credentials_in_errors(self):
        self.assertEqual(packages.parse_repository(REPOSITORY, "FreeBSD:15:amd64", "latest")["signature_type"], "FINGERPRINTS")
        for text in (REPOSITORY.replace("FINGERPRINTS", "NONE"),
                     REPOSITORY.replace("pkg.FreeBSD.org", "user:private-password@custom.example"),
                     REPOSITORY.replace("/usr/share/keys/pkg", "/tmp/custom"),
                     REPOSITORY.replace("/usr/share/keys/pkg", "/USR/share/keys/pkg"),
                     REPOSITORY.replace("yes,", "no,"),
                     REPOSITORY + REPOSITORY):
            with self.subTest(text=text[:60]), self.assertRaises(packages.PackageUpgradeError) as caught:
                packages.parse_repository(text, "FreeBSD:15:amd64", "latest")
            self.assertNotIn("private-password", str(caught.exception))


class PackagePlanTests(unittest.TestCase):
    def setUp(self):
        self.target = Target()

    def test_actual_db_signed_refresh_acme_and_no_host_mutations(self):
        self.target.upgrade(self.target.nc, "py311-certbot", "2.0")
        self.target.upgrade(self.target.office, "onlyoffice-documentserver", "9.4.0_5")
        approved = packages.plan(self.target)
        self.assertEqual(approved["nextcloud_path"], ["35.0.1", "35.0.2"])
        self.assertEqual(approved["status"], "changes-available")
        self.assertIn("py311-certbot", approved["jails"]["nextcloud"]["roots"])
        self.assertEqual(approved["jails"]["onlyoffice"]["actions"][0]["new"]["origin"], "www/onlyoffice-documentserver")
        self.assertEqual(json.loads(json.dumps(approved)), approved)
        self.assertEqual(sum("update" in call[1] for call in self.target.calls), 2)
        self.assertFalse(any("PKG_DBDIR=" in arg for call in self.target.calls for arg in call[1]))
        for jail, argv, _, _, _ in self.target.calls:
            self.assertIn(jail, (self.target.nc, self.target.office))
            if "upgrade" in argv:
                self.assertIn("-n", argv)
                self.assertIn("-U", argv)
                self.assertNotIn("-f", argv)

    def test_noop_is_success_with_catalog_side_effect_disclosed(self):
        approved = packages.plan(self.target)
        self.assertEqual(approved["status"], "no-compatible-package-changes")
        self.assertIn("refreshes", approved["catalog_refresh"])
        self.target.calls.clear()
        result = packages.apply(self.target, approved)
        self.assertEqual(result["status"], "no-compatible-package-changes")
        self.assertFalse(any("update" in c[1] or "-F" in c[1] for c in self.target.calls))

    def test_optional_ssh_tools_are_not_application_upgrade_roots(self):
        self.target.config.jail_ssh = True
        self.target.config.ssh_admin = True
        self.target.config.ssh_shell = "zsh"
        approved = packages.plan(self.target)
        for jail in approved["jails"].values():
            self.assertFalse({"zsh", "doas"} & set(jail["roots"]))

    def test_revalidation_rejects_exact_archive_or_installed_state_drift(self):
        self.target.upgrade(self.target.nc, "php85", "8.5.12")
        approved = packages.plan(self.target)
        self.target.remote[self.target.nc]["php85"]["checksum"] = "a" * 64
        with self.assertRaisesRegex(packages.PackageUpgradeError, "plan changed"):
            packages.revalidate(self.target, approved)
        self.target.remote[self.target.nc]["php85"]["checksum"] = approved["jails"]["nextcloud"]["actions"][0]["new"]["checksum"]
        self.target.installed[self.target.nc]["FreeBSD-runtime"]["version"] = "15.2"
        with self.assertRaisesRegex(packages.PackageUpgradeError, "plan changed"):
            packages.revalidate(self.target, approved)

    def test_fetch_revalidate_execute_order_and_single_answer(self):
        for jail, name, version in ((self.target.nc, "php85", "8.5.12"), (self.target.office, "onlyoffice-documentserver", "9.4.0_5")):
            self.target.upgrade(jail, name, version)
        approved = packages.plan(self.target)
        self.target.calls.clear()
        result = packages.apply(self.target, approved)
        self.assertEqual(result["status"], "applied")
        self.assertEqual(result["completed"], ["nextcloud", "onlyoffice"])
        jobs = [(c[0], c[1][len(packages.PKG):], c[2]) for c in self.target.calls if "upgrade" in c[1]]
        self.assertEqual([("dry" if "-n" in args else "fetch" if "-F" in args else "apply") for _, args, _ in jobs],
                         ["dry", "dry", "fetch", "fetch", "dry", "dry", "apply", "apply"])
        self.assertTrue(all("-U" in args and "-y" not in args for _, args, _ in jobs))
        self.assertFalse(any("update" in c[1] for c in self.target.calls))
        with self.assertRaises(packages.PackageUpgradeError):
            packages.revalidate(self.target, approved)

    def test_post_fetch_catalog_drift_prevents_execution(self):
        self.target.upgrade(self.target.nc, "php85", "8.5.12")
        approved = packages.plan(self.target)
        self.target.on_fetch = lambda t, j: t.remote[j]["php85"].update(checksum="b" * 64)
        self.target.calls.clear()
        result = packages.apply(self.target, approved)
        self.assertEqual((result["status"], result["phase"]), ("failed", "revalidate-after-fetch"))
        self.assertFalse(any("upgrade" in c[1] and "-F" not in c[1] and "-n" not in c[1] for c in self.target.calls))

    def test_partial_execution_failure_reports_uncertainty_without_replay_or_secrets(self):
        self.target.upgrade(self.target.nc, "php85", "8.5.12")
        self.target.upgrade(self.target.office, "onlyoffice-documentserver", "9.4.0_5")
        approved = packages.plan(self.target)
        self.target.fail = lambda jail, args: jail == self.target.office and "upgrade" in args and "-n" not in args and "-F" not in args
        result = packages.apply(self.target, approved)
        self.assertEqual(result["completed"], ["nextcloud"])
        self.assertTrue(result["installed_state_uncertain"])
        self.assertEqual(result["jail"], "onlyoffice")
        self.assertNotIn("private-password", json.dumps(result))
        self.assertNotIn("secret-runtime-output", json.dumps(result))

    def test_success_exit_with_wrong_inventory_is_failure(self):
        self.target.upgrade(self.target.nc, "php85", "8.5.12")
        approved = packages.plan(self.target)
        self.target.bad_verify = True
        result = packages.apply(self.target, approved)
        self.assertEqual(result["phase"], "verify-inventory")
        self.assertTrue(result["installed_state_uncertain"])

    def test_native_reverse_dependency_bookkeeping_keeps_exact_provider_identity(self):
        expected = deepcopy(self.target.installed[self.target.nc])
        expected["php85"]["version"] = "8.5.12"
        actual = deepcopy(expected)
        actual["php85-curl"]["dependencies"]["php85"]["version"] = "8.5.12"
        self.assertTrue(packages._verify_inventory(actual, expected))
        actual["php85-curl"]["dependencies"]["php85"]["version"] = "8.6.0"
        self.assertFalse(packages._verify_inventory(actual, expected))
        actual = deepcopy(expected)
        actual["php85"]["version"] = "8.6.0"
        self.assertFalse(packages._verify_inventory(actual, expected))

    def test_untrusted_repo_or_keys_fail_before_refresh(self):
        for field, value in (("repository", REPOSITORY.replace("FINGERPRINTS", "NONE")),
                             ("key", 'function: "sha256"\nfingerprint: "' + "0" * 64 + '"\n')):
            target = Target()
            setattr(target, field, value)
            with self.assertRaises(packages.PackageUpgradeError):
                packages.plan(target)
            self.assertFalse(any("update" in c[1] for c in target.calls))

    def test_nonstandard_pkg_configuration_is_not_silently_used(self):
        self.target.settings["PKG_DBDIR"] = "/tmp/empty-db"
        with self.assertRaisesRegex(packages.PackageUpgradeError, "PKG_DBDIR"):
            packages.plan(self.target)
        self.assertFalse(any("upgrade" in c[1] for c in self.target.calls))

    def test_removal_downgrade_and_unrelated_solver_effects_are_blocked(self):
        for action, name, old, new in (("removed", "php85", "8.5.11", None),
                                      ("downgraded", "php85", "8.5.11", "8.5.10"),
                                      ("upgraded", "FreeBSD-runtime", "15.1", "15.2")):
            target = Target()
            target.rows[target.nc] = [(action, name, old, new)]
            if new:
                target.remote[target.nc][name] = dict(target.installed[target.nc][name], version=new, checksum="a" * 64)
            with self.subTest(action=action, name=name), self.assertRaises(packages.PackageUpgradeError):
                packages.plan(target)

    def test_new_native_dependency_is_kept_with_origins_abi_and_checksum(self):
        self.target.upgrade(self.target.nc, "php85", "8.5.12")
        dependency = dict(name="new-library", version="1.0", origin="devel/new-library", abi="FreeBSD:15:amd64", checksum="c" * 64, dependencies={})
        self.target.remote[self.target.nc]["new-library"] = dependency
        self.target.remote[self.target.nc]["php85"]["dependencies"]["new-library"] = dict(version="1.0", origin="devel/new-library")
        self.target.rows[self.target.nc].append(("installed", "new-library", None, "1.0"))
        approved = packages.plan(self.target)
        action = approved["jails"]["nextcloud"]["actions"][0]
        self.assertIsNone(action["old"])
        self.assertEqual(action["new"], dependency)
        self.assertEqual(packages.apply(self.target, approved)["status"], "applied")

    def test_package_outside_owned_closure_not_authorized_by_solver(self):
        item = dict(name="unrelated", version="1.0", origin="devel/unrelated", abi="FreeBSD:15:amd64", checksum="c" * 64, dependencies={})
        self.target.remote[self.target.nc]["unrelated"] = item
        self.target.rows[self.target.nc] = [("installed", "unrelated", None, "1.0")]
        with self.assertRaisesRegex(packages.PackageUpgradeError, "outside reviewed roots"):
            packages.plan(self.target)

    def test_unsupported_php_database_office_versions_and_intermediate_nc(self):
        for jail, name, version in (("cloudnc", "php85", "8.6.0"), ("cloudnc", "php85-curl", "8.6.0"), ("cloudnc", "mariadb123-server", "12.4.0"),
                                    ("cloudoo", "onlyoffice-documentserver", "9.5.0")):
            target = Target()
            target.upgrade(jail, name, version)
            with self.subTest(name=name), self.assertRaises(packages.PackageUpgradeError):
                packages.plan(target)
        with self.assertRaises(packages.PackageUpgradeError):
            packages.plan(self.target, nextcloud_path=("35.0.99", "35.0.2"))
        self.target.source = "34.0.1"
        with self.assertRaises(packages.PackageUpgradeError):
            packages.plan(self.target)

    def test_origin_or_abi_change_is_not_a_normal_patch(self):
        for field, value in (("origin", "custom/php85"), ("abi", "FreeBSD:16:amd64")):
            target = Target()
            target.upgrade(target.nc, "php85", "8.5.12")
            target.remote[target.nc]["php85"][field] = value
            with self.subTest(field=field), self.assertRaises(packages.PackageUpgradeError):
                packages.plan(target)


if __name__ == "__main__":
    unittest.main()
