"""Offline bootstrap guards and release verification; never run provisioning."""

import hashlib
import importlib.util
import io
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRATCH = tempfile.gettempdir()


def entry_functions(script, *args, cwd=ROOT, env=None, input=None, mock_packages=False,
                     mock_flua=False, entrypoint=None, lifecycle_root=None):
    """Run only shell functions; host/package/launch operations are test doubles."""
    source = (ROOT / "install.sh").read_text()
    invocation = '\nmain "$@"\n'
    if not source.endswith(invocation):
        raise AssertionError("Expected a single explicit entrypoint invocation")
    definitions = source[:-len(invocation)]
    if lifecycle_root is not None:
        definitions = definitions.replace('/var/db/cloud-installer/lifecycle', str(lifecycle_root))
    if mock_packages:
        definitions = definitions.replace("/usr/sbin/pkg", "mock_pkg")
    if mock_flua:
        definitions = definitions.replace("/usr/libexec/flua", "mock_flua")
        # Linux has no FreeBSD base flua. Read the actual policy with the existing
        # test interpreter; the production guard's argv and failure routing run.
        script = """
mock_flua() {
    """ + shlex.quote(sys.executable) + """ -I -B -c '
import json, sys
assert len(sys.argv) == 5 and sys.argv[1] == "-"
with open(sys.argv[2]) as stream:
    policy = json.load(stream)
sys.exit(not any(t["release"] == sys.argv[3] and t["architecture"] == sys.argv[4]
                 for t in policy["targets"]))
' "$@"
}
""" + script
    return subprocess.run(
        ["sh", "-eu", "-c", definitions + "\n" + script, str(entrypoint or ROOT / "install.sh"), *args],
        cwd=cwd, text=True, capture_output=True, input=input,
        env={**os.environ, "LC_ALL": "C", **(env or {})}, timeout=10,
    )


HOST_PROBES = """
id() { printf '%s\\n' "$TEST_UID"; }
uname() {
    case "$1" in
        -s) printf '%s\\n' "$TEST_OS" ;;
        -m) printf '%s\\n' "$TEST_ARCH" ;;
        *) exit 90 ;;
    esac
}
freebsd-version() { [ "$1" = -u ] || exit 90; printf '%s\\n' "$TEST_VERSION"; }
sysctl() { [ "$*" = '-n security.jail.jailed' ] || exit 90; printf '%s\\n' "$TEST_JAILED"; }
"""


class EntrypointTests(unittest.TestCase):
    def test_recipe_routing_preserves_quoted_path_order_archive_and_cwd(self):
        with tempfile.TemporaryDirectory(prefix="recipe-shell-", dir=SCRATCH) as directory:
            path = Path(directory) / "recipe with spaces.json"
            path.write_text("{}")
            script = """
require_host() { :; }
require_python() { :; }
require_terminal() { :; }
bootstrap_python() { printf 'bootstrap yes=%s\\n' "$assume_yes"; }
confirm() { return 0; }
bootstrap_archive() { printf '%s\\n' "$TEST_PAYLOAD"; }
launch_python() { printf 'cwd=%s\\n' "$PWD"; printf '<%s>\\n' "$@"; }
main "$@"
"""
            for options in (("--config", path.name, "--yes", "--accept-licenses", "--accept-acme-terms"),
                            ("--yes", "--accept-acme-terms", "--config", path.name, "--accept-licenses"),
                            ("--config=" + path.name, "--yes", "--accept-licenses", "--accept-acme-terms")):
                for archive in ((), ("--archive", "local archive.tgz", "--sha256", "a" * 64)):
                    result = entry_functions(script, *archive, "--plain", "install", *options,
                                             cwd=directory, env={"TEST_PAYLOAD": str(ROOT)})
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("bootstrap yes=1", result.stdout)
                    self.assertIn("cwd=" + directory, result.stdout)
                    self.assertIn("<--plain>\n<install>\n" + "".join(f"<{arg}>\n" for arg in options), result.stdout)
            result = entry_functions(script, "configure", "--config", path.name, cwd=directory)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("bootstrap yes=0", result.stdout)

    def test_invalid_recipe_arguments_and_missing_files_fail_before_bootstrap(self):
        script = """
require_host() { fail 'UNSAFE-host'; }
bootstrap_python() { fail 'UNSAFE-bootstrap'; }
launch_python() { fail 'UNSAFE-launch'; }
main "$@"
"""
        with tempfile.TemporaryDirectory(prefix="recipe-errors-", dir=SCRATCH) as directory:
            path = Path(directory) / "recipe.json"
            path.write_text("{}")
            for args in (("install", "--config"), ("install", "--config", "--yes"),
                         ("install", "--yes"), ("install", "--accept-licenses"),
                         ("install", "--accept-acme-terms"), ("configure", "--yes"),
                         ("configure", "--config", str(path), "--accept-licenses"),
                         ("remove", "cloud", "--yes"), ("resume", "cloud", "--yes"),
                         ("install", "--config", str(path), "--yes", "--yes"),
                         ("install", "--config", str(path), "--accept-licenses", "--accept-licenses"),
                         ("install", "--config", str(path), "--accept-acme-terms", "--accept-acme-terms"),
                          ("install", "--config", str(path), "--config", str(path)),
                          ("install", "--config="),
                          ("install", "--config=" + str(path), "--config", str(path)),
                         ("install", "--config", str(path), "--unknown"),
                         ("install", "--config", str(path / "missing"))):
                with self.subTest(args=args):
                    result = entry_functions(script, *args)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn("UNSAFE", result.stderr)

    def test_bootstrap_yes_discloses_only_pkg_and_python_commands(self):
        result = entry_functions("""
require_terminal() { :; }
confirm() { fail 'unexpected interactive bootstrap confirmation'; }
mock_pkg() { [ "$1" = -N ] && return 1; printf 'mock-pkg %s\\n' "$*"; }
command() { return 1; }
pkg() { printf 'mock-install %s\\n' "$*"; }
require_python() { :; }
assume_yes=1
bootstrap_python
""", mock_packages=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("mock-pkg bootstrap -y -r FreeBSD-ports", result.stdout)
        self.assertIn("mock-install install -y -r FreeBSD-ports python3", result.stdout)
        self.assertIn("--yes approved", result.stderr)
        self.assertIn("Command: mock_pkg bootstrap", result.stderr)
        self.assertIn("Command: pkg install", result.stderr)

    def test_maintenance_routing_never_bootstraps_or_acquires_archive(self):
        mocks = """
require_host() { :; }
require_python() { :; }
bootstrap_python() { fail 'unexpected bootstrap'; }
bootstrap_archive() { fail 'unexpected archive'; }
launch_python() { printf 'mock-launch\\n'; }
main "$@"
"""
        for args in (("maintenance", "register", "cloud"), ("maintenance", "status"),
                     ("maintenance", "recover"),
                     ("maintenance", "plan", "--instance", "cloud", "--recovery-only", "--json"),
                     ("maintenance", "plan", "--instance", "cloud", "--target", "future", "--save"),
                      ("maintenance", "stage", "plan-one", "--artifacts", "/local archives"),
                      ("maintenance", "prepare-target", "maint-one", "--artifacts", "/local archives"),
                     ("maintenance", "continue", "maint-one", "--artifacts", "/local archives"),
                     ("maintenance", "cancel", "maint-one"),
                     ("maintenance", "status", "maint-one", "--json"),
                     ("maintenance", "recover", "maint-one", "--assess"),
                     ("maintenance", "apply", "maint-one")):
            result = entry_functions(mocks, *args)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("mock-launch", result.stdout)
        for args in (("maintenance",), ("maintenance", "unknown"),
                     ("maintenance", "register", "../bad"),
                     ("--archive", "fixture.tgz", "--sha256", "a" * 64, "maintenance", "status")):
            result = entry_functions(mocks, *args)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("mock-launch", result.stdout)

    def test_lifecycle_precheck_refuses_before_bootstrap_and_archive_writes(self):
        with tempfile.TemporaryDirectory(prefix="lifecycle-shell-", dir=SCRATCH) as directory:
            result = entry_functions("""
require_host() { :; }
require_python() { :; }
python3() { printf 'mock-lifecycle-refusal\\n' >&2; return 1; }
bootstrap_python() { printf 'UNSAFE-bootstrap\\n'; }
launch_python() { printf 'UNSAFE-launch\\n'; }
main install
""", lifecycle_root=Path(directory))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("mock-lifecycle-refusal", result.stderr)
            self.assertNotIn("UNSAFE", result.stdout)

    def test_shell_syntax(self):
        paths = [ROOT / "install.sh", *ROOT.glob("resources/jails/*.sh")]
        paths.extend(path for path in (ROOT / "resources").rglob("*")
                     if path.is_file() and path.read_bytes().startswith(b"#!/bin/sh"))
        for path in set(paths):
            with self.subTest(path=str(path.relative_to(ROOT))):
                result = subprocess.run(["sh", "-n", str(path)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_host_gate_rejects_unsupported_targets_before_bootstrap(self):
        valid = {"TEST_UID": "0", "TEST_OS": "FreeBSD", "TEST_ARCH": "amd64",
                 "TEST_VERSION": "15.1-RELEASE", "TEST_JAILED": "0"}
        for overrides, accepted in [
            ({}, True), ({"TEST_VERSION": "15.1-RELEASE-p2"}, True),
            ({"TEST_UID": "1000"}, False), ({"TEST_OS": "Linux"}, False),
            ({"TEST_ARCH": "aarch64"}, False), ({"TEST_JAILED": "1"}, False),
            ({"TEST_JAILED": ""}, False), ({"TEST_VERSION": "15.0-RELEASE"}, False),
            ({"TEST_VERSION": "15.1-STABLE"}, False),
            ({"TEST_VERSION": "15.1-RELEASE-p"}, False),
            ({"TEST_VERSION": "15.1-RELEASE-p2-invalid"}, False),
        ]:
            with self.subTest(overrides=overrides):
                result = entry_functions(HOST_PROBES + """
require_terminal() { :; }
bootstrap_python() { printf 'mock-bootstrap\\n'; }
launch_python() { printf 'mock-launch\\n'; }
main install
""", env={**valid, **overrides}, mock_flua=True)
                self.assertEqual(result.returncode == 0, accepted, result.stderr)
                self.assertEqual("mock-bootstrap" in result.stdout, accepted)
                self.assertEqual("mock-launch" in result.stdout, accepted)

    def test_standalone_unknown_policy_requires_existing_python_without_host_packages(self):
        with tempfile.TemporaryDirectory(prefix="standalone-guard-", dir=SCRATCH) as directory:
            for present in (True, False):
                result = entry_functions(HOST_PROBES + """
require_terminal() { :; }
require_python() { [ "$TEST_PYTHON" = yes ] || fail 'existing Python required'; }
bootstrap_python() { fail 'unexpected host package bootstrap before verified policy'; }
confirm() { return 0; }
bootstrap_archive() { printf '%s\n' "$TEST_PAYLOAD"; }
launch_python() { printf 'mock-launch\n'; }
main "$@"
""", "--archive", "offline-fixture.tar.gz", "--sha256", "a" * 64, "install",
                    entrypoint=Path(directory) / "install.sh", mock_flua=True,
                    env={"TEST_UID": "0", "TEST_OS": "FreeBSD", "TEST_ARCH": "amd64",
                         "TEST_VERSION": "15.1-RELEASE", "TEST_JAILED": "0", "TEST_PAYLOAD": str(ROOT),
                         "TEST_PYTHON": "yes" if present else "no"})
                with self.subTest(existing_python=present):
                    self.assertEqual(result.returncode == 0, present, result.stderr)
                    self.assertEqual("mock-launch" in result.stdout, present)
                    self.assertNotIn("unexpected host package", result.stderr)

    def test_mutating_commands_require_terminal(self):
        for args in (("install",), ("configure",), ("--configure-only",), ("resume", "cloud"),
                     ("remove", "cloud"), ("restore", "cloud", "saved"), ("add-user", "cloud")):
            with self.subTest(args=args):
                result = entry_functions("""
require_host() { :; }
require_python() { fail 'unexpected Python launch'; }
bootstrap_python() { fail 'unexpected bootstrap'; }
launch_python() { fail 'unexpected launch'; }
main "$@"
""", *args)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("interactive terminal", result.stderr)
                self.assertEqual(result.stdout, "")

    def test_plan_and_help_bypass_host_terminal_and_bootstrap(self):
        mocks = """
require_host() { fail 'unexpected host gate'; }
require_terminal() { fail 'unexpected terminal gate'; }
bootstrap_python() { fail 'unexpected bootstrap'; }
launch_python() { printf '%s\\n' "$@"; }
main "$@"
"""
        for command in ("plan", "--plan"):
            for path in ("relative config.json", "/private/saved config.json"):
                result = entry_functions(mocks, "--plain", command, path)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines(), ["--plain", command, path])
        args = ("--plain", "resolve", "configuration with spaces.json", "--metadata", "offline catalog.json",
                "--installed", "retained plan.json")
        result = entry_functions(mocks, *args)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), list(args))
        for args in (("--help",), ("install", "--help"), ("--plain", "--help"), ("upgrade", "--help")):
            result = entry_functions(mocks, *args)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Usage:", result.stdout)
            self.assertIn("--plan | --verify | --restore SNAPSHOT_REPORT", result.stdout)

    def test_inspection_and_backup_need_host_but_not_bootstrap_or_tty(self):
        for args in ((), ("--plain",), ("list",), ("status", "cloud"),
                     ("check-updates",), ("check-updates", "cloud"),
                     ("check-updates", "--all", "--refresh", "--save-report", "--json"),
                     ("--plain", "check-updates", "cloud", "--json"),
                     ("check-security",), ("check-security", "cloud"),
                     ("check-security", "--all", "--refresh", "--save-report", "--json"),
                     ("--plain", "check-security", "cloud", "--json"),
                     ("verify", "cloud"), ("--verify", "cloud"),
                     ("backup", "cloud", "--output", "archive path"), ("resolve", "config.json")):
            result = entry_functions("""
require_host() { printf 'host checked\\n'; }
require_python() { :; }
require_terminal() { fail 'unexpected terminal gate'; }
bootstrap_python() { fail 'unexpected bootstrap'; }
launch_python() { for argument in "$@"; do printf '%s\\n' "$argument"; done; }
main "$@"
""", *args)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), ["host checked", *args])

    def test_missing_python_inspection_never_prompts_or_bootstraps(self):
        for args in ((), ("--plain",), ("list",), ("status", "cloud"), ("check-updates", "--refresh"),
                     ("check-security", "--refresh")):
            with self.subTest(args=args):
                result = entry_functions("""
require_host() { :; }
command() { [ "$*" = '-v python3' ] || exit 90; return 1; }
confirm() { fail 'unexpected consent prompt'; }
require_terminal() { fail 'unexpected terminal gate'; }
bootstrap_python() { fail 'unexpected bootstrap'; }
launch_python() { fail 'unexpected launch'; }
main "$@"
""", *args)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Python 3.11+ is required", result.stderr)
                self.assertNotIn("unexpected", result.stderr)
                self.assertEqual(result.stdout, "")
                if args in ((), ("--plain",)):
                    self.assertIn("explicit install or configure", result.stderr)

    def test_inspection_host_guards_precede_python_or_package_execution(self):
        valid = {"TEST_UID": "0", "TEST_OS": "FreeBSD", "TEST_ARCH": "amd64",
                 "TEST_VERSION": "15.1-RELEASE", "TEST_JAILED": "0"}
        for args in ((), ("list",), ("status", "cloud"), ("check-updates", "--refresh"),
                     ("check-security", "--refresh")):
            for overrides in ({"TEST_UID": "1000"}, {"TEST_OS": "Linux"}, {"TEST_JAILED": "1"}):
                with self.subTest(args=args, overrides=overrides):
                    result = entry_functions(HOST_PROBES + """
require_python() { fail 'unexpected Python execution'; }
bootstrap_python() { fail 'unexpected bootstrap'; }
launch_python() { fail 'unexpected launch'; }
main "$@"
""", *args, env={**valid, **overrides}, mock_flua=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn("unexpected", result.stderr)
                    self.assertEqual(result.stdout, "")

    def test_archive_rejects_menu_and_inspection_before_acquisition(self):
        for args in ((), ("list",), ("status", "cloud"), ("check-updates",),
                     ("check-updates", "--all", "--refresh", "--save-report", "--json"),
                     ("check-security", "--all", "--refresh", "--save-report", "--json"),
                     ("maintenance", "status"), ("upgrade", "cloud", "--plan"),
                     ("upgrade", "cloud", "--restore", "/private/snapshot/report.json"),
                     ("plan", "config.json"), ("--plan", "config.json"), ("resolve", "config.json"),
                     ("resolve", "config.json", "--metadata", "catalog.json")):
            with self.subTest(args=args):
                result = entry_functions("""
require_host() { fail 'unexpected host gate'; }
require_python() { fail 'unexpected Python execution'; }
bootstrap_python() { fail 'unexpected bootstrap'; }
confirm() { fail 'unexpected consent prompt'; }
bootstrap_archive() { fail 'unexpected archive acquisition'; }
launch_python() { fail 'unexpected launch'; }
main "$@"
""", "--plain", *args, "--archive", "local release.tar.gz", "--sha256", "a" * 64)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("require an already unpacked checkout/release", result.stderr)
                self.assertNotIn("unexpected", result.stderr)
                self.assertEqual(result.stdout, "")

    def test_archive_supports_explicit_lifecycle_commands_after_guards_and_consent(self):
        with tempfile.TemporaryDirectory(prefix="standalone-commands-", dir=SCRATCH) as directory:
            for args in (("install",), ("configure",), ("--configure-only",), ("resume", "cloud"),
                         ("verify", "cloud"), ("--verify", "cloud"), ("backup", "cloud"),
                         ("backup", "cloud", "--output", "saved backup"), ("remove", "cloud"),
                         ("remove", "cloud", "--purge-data"), ("restore", "cloud", "saved backup"),
                         ("add-user", "cloud"), ("recover-install", "cloud"), ("recover-network",)):
                with self.subTest(args=args):
                    result = entry_functions("""
require_host() { host_checked=yes; }
require_terminal() { :; }
require_python() { [ "$host_checked" = yes ]; python_checked=yes; }
bootstrap_python() { fail 'unexpected package bootstrap without policy'; }
confirm() { [ "$python_checked" = yes ]; consent=yes; }
bootstrap_archive() {
    [ "$consent" = yes ] || exit 90
    printf '/mock/verified-release\\n'
}
launch_python() { printf '%s\\n' "$script_dir" "$@"; }
main "$@"
""", "--plain", *args, "--archive", "local release.tar.gz", "--sha256", "a" * 64,
                        entrypoint=Path(directory) / "install.sh")
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.splitlines(), ["/mock/verified-release", "--plain", *args])

    def test_explicit_configuration_and_resume_keep_bootstrap_routing(self):
        for args in (("install",), ("configure",), ("--configure-only",), ("resume", "cloud")):
            with self.subTest(args=args):
                result = entry_functions("""
require_host() { printf 'host checked\\n'; }
require_terminal() { printf 'terminal checked\\n'; }
bootstrap_python() { printf 'bootstrap checked\\n'; }
launch_python() { printf '%s\\n' "$@"; }
main "$@"
""", "--plain", *args)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines(),
                                 ["host checked", "terminal checked", "bootstrap checked", "--plain", *args])

    def test_check_updates_detailed_validation_is_delegated_without_bootstrap(self):
        result = entry_functions("""
require_host() { :; }
require_python() { :; }
bootstrap_python() { fail 'unexpected bootstrap'; }
launch_python() { printf '%s\\n' "$@"; }
main "$@"
""", "check-updates", "--unknown", "target with spaces")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["check-updates", "--unknown", "target with spaces"])

    def test_invalid_modes_and_archives_never_reach_host_or_bootstrap(self):
        for args in (("",), ("--plan",), ("--plan", ""), ("plan", "a.json", "--verify"),
                     ("--configure-only", "--verify"), ("verify",), ("--yes",),
                     ("resume", "--yes"), ("remove", "cloud", "--force"),
                     ("backup", "cloud", "--output"), ("restore", "cloud"),
                     ("--archive", "https://example.test/release.tar.gz"),
                     ("--sha256", "a" * 64), ("--archive", "https://example.test/a", "--sha256", "g" * 64),
                     ("--archive", "http://example.test/a", "--sha256", "a" * 64),
                     ("--archive", "ftp://example.test/a", "--sha256", "a" * 64),
                     ("--archive", "https://example.test/a", "--sha256", "a" * 64, "plan", "a.json")):
            with self.subTest(args=args):
                result = entry_functions("""
require_host() { printf 'unexpected host gate'; exit 90; }
bootstrap_python() { printf 'unexpected bootstrap'; exit 90; }
launch_python() { printf 'unexpected launch'; exit 90; }
main "$@"
""", *args)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def test_global_options_are_removed_without_losing_argument_boundaries(self):
        result = entry_functions("""
require_host() { :; }
require_terminal() { :; }
require_python() { :; }
bootstrap_python() { :; }
confirm() { return 0; }
bootstrap_archive() {
    [ "$archive_source" = 'local release.tar.gz' ] || exit 90
    printf '/mock/release\\n'
}
launch_python() { printf '%s\\n' "$script_dir" "$CLOUD_INSTALLER_PLAIN" "$@"; }
main "$@"
""", "configure", "--archive", "local release.tar.gz",
                                 "--plain", "--sha256", "a" * 64)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(),
                         ["/mock/release", "1", "--plain", "configure"])

    def test_bootstrap_confirmation_defaults_to_no(self):
        for answer, accepted in (("y\n", True), ("yes\n", True), ("\n", False),
                                 ("no\n", False), ("anything\n", False), ("", False)):
            result = entry_functions("""
require_terminal() { :; }
if confirm 'mock dependency install'; then printf accepted; else printf declined; fi
""", input=answer)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "accepted" if accepted else "declined")

    def test_bootstrap_installs_only_missing_packages_with_explicit_consent(self):
        mocks = """
require_terminal() { :; }
require_python() { :; }
mock_pkg() {
    if [ "$1" = -N ]; then [ "$TEST_PKG" = yes ]; return; fi
    printf 'base pkg %s\\n' "$*"
}
command() { [ "$*" = '-v python3' ] || exit 90; [ "$TEST_PYTHON" = yes ]; }
pkg() { printf 'pkg %s\\n' "$*"; }
bootstrap_python
"""
        for pkg, python, answers, expected in (
                ("yes", "yes", "", []),
                ("no", "yes", "y\n", ["base pkg bootstrap -y -r FreeBSD-ports"]),
                ("yes", "no", "y\n", ["pkg install -y -r FreeBSD-ports python3"]),
                ("no", "no", "y\ny\n", ["base pkg bootstrap -y -r FreeBSD-ports", "pkg install -y -r FreeBSD-ports python3"])):
            result = entry_functions(mocks, input=answers, mock_packages=True,
                                     env={"TEST_PKG": pkg, "TEST_PYTHON": python})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), expected)
        result = entry_functions(mocks, input="\n", mock_packages=True,
                                 env={"TEST_PKG": "no", "TEST_PYTHON": "no"})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_python_launch_keeps_caller_paths_and_uses_own_payload(self):
        with tempfile.TemporaryDirectory(prefix="entry-guards-", dir=SCRATCH) as directory:
            python = Path(directory, "python3")
            python.write_text("#!/bin/sh\npwd -P\nprintf '%s\\n' \"$@\" \"$PYTHONDONTWRITEBYTECODE\"\n")
            python.chmod(0o700)
            result = entry_functions('require_python() { :; }\nlaunch_python plan "saved config.json"', cwd=directory,
                                     env={"PATH": directory + os.pathsep + os.environ["PATH"]})
            self.assertEqual(result.returncode, 0, result.stderr)
            lines = result.stdout.splitlines()
            self.assertEqual(lines[0], directory)
            self.assertEqual(lines[1:4], ["-I", "-B", "-c"])
            self.assertEqual(lines[5:], [str(ROOT), "plan", "saved config.json", "1"])


def archive_module():
    source = (ROOT / "install.sh").read_text().split("<<'PY_ARCHIVE'\n", 1)[1].split("\nPY_ARCHIVE\n", 1)[0]
    module = types.ModuleType("archive_bootstrap_test")
    exec(compile(source, "install.sh:archive-verifier", "exec"), module.__dict__)
    return module


def build_module():
    spec = importlib.util.spec_from_file_location("release_builder_test", ROOT / "tools/build-release.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="archive-tests-", dir=SCRATCH)
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.destination = self.directory / "unpacked"
        self.destination.mkdir()
        self.module = archive_module()

    def make_archive(self, extra=(), *, required=True, omit=()):
        target = self.directory / "release.tar.gz"
        with tarfile.open(target, "w:gz") as archive:
            if required:
                for name in ("install.sh", "LICENSE", "pyproject.toml", "installer/__init__.py",
                             "installer/main.py", "installer/dashboard.py", "installer/updates.py",
                             "resources/jails/nextcloud.sh", "resources/versions.json"):
                    if name in omit:
                        continue
                    info = tarfile.TarInfo("cloud-installer/" + name)
                    content = b"reviewed payload\n"
                    info.size = len(content)
                    info.mode = 0o6755
                    info.uid, info.gid = 65534, 65534
                    archive.addfile(info, io.BytesIO(content))
            for info in extra:
                archive.addfile(info, io.BytesIO(b"x" * info.size) if info.isfile() else None)
        return target, hashlib.sha256(target.read_bytes()).hexdigest()

    def test_verified_release_extracts_private_files_without_archived_ownership(self):
        archive, digest = self.make_archive()
        root = self.module.verify_and_extract(archive, digest.upper(), self.destination)
        self.assertEqual(root, self.destination / "cloud-installer")
        self.assertEqual((root / "installer/main.py").read_text(), "reviewed payload\n")
        self.assertEqual((root / "install.sh").stat().st_mode & 0o7777, 0o700)
        self.assertEqual((root / "install.sh").stat().st_uid, os.geteuid())

    def test_digest_mismatch_precedes_parsing_and_extraction(self):
        archive, digest = self.make_archive()
        with patch.object(self.module.gzip, "open") as opening:
            with self.assertRaisesRegex(ValueError, "SHA256 mismatch"):
                self.module.verify_and_extract(archive, "0" * 64, self.destination)
            opening.assert_not_called()
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_unsafe_members_are_rejected_before_any_payload_extraction(self):
        bad_members = [tarfile.TarInfo(name) for name in (
            str(Path(tempfile.gettempdir()) / "escaped"), "../escaped", "cloud-installer/../escaped",
            "cloud-installer/installer/../escaped", "cloud-installer//escaped",
            "cloud-installer/./escaped", "cloud-installer/installer\\escaped",
            "cloud-installer/installer/line\nname", "cloud-installer/installer/main.py",
            "cloud-installer/.git/config", "cloud-installer/install.sh/child", "another-root/file")]
        for typecode in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE):
            member = tarfile.TarInfo("cloud-installer/installer/unsafe")
            member.type, member.linkname = typecode, "../../escaped"
            bad_members.append(member)
        for member in bad_members:
            with self.subTest(name=member.name, type=member.type):
                archive, digest = self.make_archive((member,))
                with self.assertRaises(ValueError):
                    self.module.verify_and_extract(archive, digest, self.destination)
                self.assertEqual(list(self.destination.iterdir()), [])

    def test_conflicting_file_parent_and_duplicate_directories_rejected(self):
        parent = tarfile.TarInfo("cloud-installer/installer")
        root = tarfile.TarInfo("cloud-installer/")
        root.type = tarfile.DIRTYPE
        for members in ((parent,), (root, root)):
            archive, digest = self.make_archive(members)
            with self.assertRaises(ValueError):
                self.module.verify_and_extract(archive, digest, self.destination)
            self.assertEqual(list(self.destination.iterdir()), [])

    def test_all_archive_limits_are_enforced(self):
        archive, digest = self.make_archive()
        for constant, value in (("MAX_ARCHIVE", 1), ("MAX_EXPANDED", 1024),
                                ("MAX_FILE", 1), ("MAX_ENTRIES", 2)):
            with self.subTest(limit=constant), patch.object(self.module, constant, value):
                with self.assertRaises(ValueError):
                    self.module.verify_and_extract(archive, digest, self.destination)
                self.assertEqual(list(self.destination.iterdir()), [])

    def test_missing_runtime_payload_is_rejected(self):
        archive, digest = self.make_archive(required=False)
        with self.assertRaisesRegex(ValueError, "complete"):
            self.module.verify_and_extract(archive, digest, self.destination)

    def test_verified_older_release_without_inspection_modules_is_accepted(self):
        omitted = ("installer/dashboard.py", "installer/updates.py")
        archive, digest = self.make_archive(omit=omitted)
        root = self.module.verify_and_extract(archive, digest, self.destination)
        self.assertEqual((root / "installer/main.py").read_text(), "reviewed payload\n")
        for name in omitted:
            self.assertFalse((root / name).exists())

    def test_only_https_urls_and_local_regular_files_are_accepted(self):
        self.assertTrue(self.module.validate_source("https://example.test/pinned.tar.gz"))
        self.assertFalse(self.module.validate_source("local release.tar.gz"))
        self.assertFalse(self.module.validate_source(str(self.directory / "missing-release.tar.gz")))
        for value in ("http://example.test/file", "ftp://example.test/file", "file:///etc/passwd",
                      "https://user:password@example.test/file", "https:///missing-host", "https://host/file#fragment",
                      "https://host/line\nname", "//host/file", ""):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.module.validate_source(value)
        original = self.directory / "local.tar.gz"
        original.write_bytes(b"local bytes")
        copied = self.directory / "copy.tar.gz"
        with patch.object(self.module.subprocess, "Popen") as download:
            self.module.acquire(str(original), copied)
            download.assert_not_called()
        self.assertEqual(copied.read_bytes(), b"local bytes")
        link = self.directory / "link"
        link.symlink_to(original)
        with self.assertRaises(OSError):
            self.module.acquire(str(link), self.directory / "link-copy")

    def test_invalid_digest_cannot_create_cache_or_download(self):
        with patch.object(self.module, "private_cache") as cache, patch.object(self.module, "acquire") as acquire:
            with self.assertRaises(ValueError):
                self.module.bootstrap("https://example.test/archive", "not a digest")
            cache.assert_not_called()
            acquire.assert_not_called()


class ReleaseTests(unittest.TestCase):
    def test_release_is_deterministic_allowlisted_and_verifiable(self):
        builder, verifier = build_module(), archive_module()
        with tempfile.TemporaryDirectory(prefix="release-tests-", dir=SCRATCH) as directory:
            scratch = Path(directory)
            root = scratch / "source"
            runtime = [str(path.relative_to(ROOT)) for path in (ROOT / "resources").rglob("*") if path.is_file()]
            for relative in ("install.sh", "LICENSE", "pyproject.toml", "installer/__init__.py", "installer/main.py",
                             "installer/dashboard.py", "installer/updates.py",
                             "installer/upgrade.py", "installer/upgrade_native.py", "installer/upgrade_packages.py",
                             "installer/upgrade_nextcloud.py", "installer/upgrade_backup.py",
                             "installer/security_assessment.py", "installer/security_reports.py",
                             "installer/package_security.py",
                             "installer/runtime_inventory.py",
                             "installer/maintenance_state.py", "installer/maintenance_generations.py",
                             "installer/maintenance_preflight.py", "installer/maintenance_fence.py",
                             "installer/maintenance_native.py",
                             "installer/maintenance_pkg_layout.py",
                             "installer/maintenance_inspection.py",
                             "installer/nextcloud_update.py", "installer/maintenance_update.py",
                             "installer/maintenance_admission.py", "installer/bounded_process.py",
                             "installer/recovery_export.py",
                              "installer/maintenance_candidate.py",
                              "installer/maintenance_execution.py", "installer/maintenance_publication.py",
                              "installer/maintenance_validation.py", "installer/maintenance_opening.py",
                              "installer/maintenance_cancellation.py",
                             "installer/generations.py", "installer/enrollment.py", "installer/maintenance.py",
                             "installer/enrollment_start.py",
                             "installer/maintenance_journal.py", "installer/maintenance_operations.py",
                             "installer/maintenance_staging.py", "installer/recovery_sets.py",
                             "installer/versions.py", "installer/discovery.py", "installer/compatibility.py",
                             "installer/resolution.py", "installer/version_runtime.py", "installer/plugins.py", *runtime):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("#!/bin/sh\n" if relative.endswith(".sh") else "public source\n")
            excluded = (".git/config", "state/config.json", "installer/__pycache__/main.pyc", "secrets.json",
                        "resources/jails/runtime.json", "resources/templates/nextcloud/private.key", "examples/private.json",
                        "resources/plugins/unreviewed.json", "resources/plugins/token.txt",
                         "INTERNAL_NOTES.md", "PRIVATE_REVIEW.md",
                         "docs/internal-review.md", "docs/not-reviewed.md",
                         "docs/private-implementation-plan.md")
            for relative in excluded:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("PRIVATE MUST NOT SHIP\n")
            first, second = scratch / "first.tar.gz", scratch / "second.tar.gz"
            digest = builder.build_release(root, first)
            for path in root.rglob("*"):
                os.utime(path, (1000, 1000))
            for relative in excluded:
                (root / relative).write_text("PRIVATE CONTENT CHANGED; STILL MUST NOT SHIP\n")
            self.assertEqual(digest, builder.build_release(root, second))
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with tarfile.open(first) as archive:
                names = archive.getnames()
                for relative in excluded:
                    self.assertNotIn("cloud-installer/" + relative, names)
                for relative in ("installer/dashboard.py", "installer/updates.py",
                                 "installer/security_assessment.py", "installer/security_reports.py",
                                 "installer/maintenance_journal.py", "installer/maintenance_operations.py",
                                 "installer/maintenance_staging.py", "installer/recovery_sets.py"):
                    self.assertIn("cloud-installer/" + relative, names)
                for member in archive:
                    self.assertEqual((member.uid, member.gid, member.mtime), (0, 0, 0))
                    self.assertIn(member.mode, (0o644, 0o755))
            unpacked = scratch / "unpacked"
            unpacked.mkdir()
            self.assertTrue((verifier.verify_and_extract(first, digest, unpacked) / "installer/main.py").is_file())
            with self.assertRaisesRegex(ValueError, "already exists"):
                builder.build_release(root, first)
            for relative in ("installer/dashboard.py", "installer/updates.py",
                             "installer/security_assessment.py", "installer/security_reports.py",
                             "installer/maintenance_journal.py", "installer/maintenance_operations.py",
                             "installer/maintenance_staging.py", "installer/recovery_sets.py"):
                with self.subTest(missing_module=relative):
                    path = root / relative
                    content = path.read_bytes()
                    path.unlink()
                    with self.assertRaisesRegex(ValueError, "resources are missing"):
                        builder.build_release(root, scratch / "incomplete.tar.gz")
                    self.assertFalse((scratch / "incomplete.tar.gz").exists())
                    path.write_bytes(content)

    def test_missing_required_runtime_templates_cannot_be_released(self):
        with tempfile.TemporaryDirectory(prefix="release-incomplete-", dir=SCRATCH) as directory:
            root = Path(directory)
            for relative in ("install.sh", "LICENSE", "pyproject.toml", "installer/__init__.py", "installer/main.py",
                             "resources/jails/nextcloud.sh", "resources/jails/onlyoffice.sh", "resources/jails/nextcloud-bootstrap.php"):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("public source\n")
            output = root / "incomplete.tar.gz"
            with self.assertRaisesRegex(ValueError, "resources are missing"):
                build_module().build_release(root, output)
            self.assertFalse(output.exists())

    def test_symlinked_payload_cannot_be_published(self):
        with tempfile.TemporaryDirectory(prefix="release-link-", dir=SCRATCH) as directory:
            root = Path(directory)
            (root / "LICENSE").symlink_to(ROOT / "LICENSE")
            with self.assertRaisesRegex(ValueError, "symlinks"):
                build_module().build_release(root, root / "output.tar.gz")

    def test_actual_release_contains_every_runtime_resource(self):
        selected = set(build_module().payload_files(ROOT))
        self.assertIn(ROOT / "installer/maintenance_pkg_layout.py", selected)
        resources = {path for path in (ROOT / "resources").rglob("*") if path.is_file()
                     and "__pycache__" not in path.parts}
        self.assertTrue(resources <= selected, f"Missing runtime resources: {sorted(resources - selected)}")

    def test_actual_release_offline_plan_runs_independently_of_checkout(self):
        with tempfile.TemporaryDirectory(prefix="release-plan-", dir=SCRATCH) as directory:
            scratch = Path(directory)
            archive = scratch / "release.tar.gz"
            digest = build_module().build_release(ROOT, archive)
            unpacked, caller = scratch / "unpacked", scratch / "operator"
            unpacked.mkdir()
            caller.mkdir()
            release = archive_module().verify_and_extract(archive, digest, unpacked)
            for recipe, topology in (("config.json", "ONLYOFFICE"), ("nextcloud-only.json", "No office runtime"),
                                     ("eurooffice.json", "Euro-Office"), ("collabora.json", "Collabora CODE")):
                with self.subTest(recipe=recipe):
                    (caller / "configuration.json").write_bytes((ROOT / "examples" / recipe).read_bytes())
                    before={p.relative_to(release):p.stat().st_mtime_ns for p in release.rglob('*') if p.is_file()}
                    result = subprocess.run(["sh", str(release / "install.sh"), "--plain", "plan", "configuration.json"],
                                            cwd=caller, capture_output=True, text=True, timeout=10,
                                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("Login: https://", result.stdout)
                    self.assertIn(topology,result.stdout)
                    self.assertEqual(before,{p.relative_to(release):p.stat().st_mtime_ns for p in release.rglob('*') if p.is_file()})
                    self.assertEqual({p.name for p in caller.iterdir()},{'configuration.json'})
            for payload in ('installer/office_vm.py','installer/vm_boot.py','resources/vm/bootstrap.sh'):
                self.assertTrue((release/payload).is_file())
            self.assertEqual(list(release.rglob("*.pyc")), [])


if __name__ == "__main__":
    unittest.main()
