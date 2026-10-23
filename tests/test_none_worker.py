"""Offline no-office worker contract; extracted helpers only, never provisioning."""

import copy
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest

from installer.version_runtime import validate_runtime_versions
from nextcloud_worker_fixtures import (
    FINISH, PHP, VERSIONS_SOURCE, phase, run_php, runtime,
)


@unittest.skipUnless(PHP, "PHP >= 8.1 CLI unavailable")
class NoneWorkerPHPTests(unittest.TestCase):
    def test_two_workers_allowed_only_without_office_callbacks(self):
        for backend, count, accepted in (("none", 2, True), ("none", 1, False), ("onlyoffice", 2, False)):
            c = runtime(backend=backend)
            c["php_children"] = count
            result = run_php("echo json_encode(cloudTokens($c));", {"runtime": c})
            self.assertEqual(result.returncode == 0, accepted, result.stderr)
            if accepted:
                tokens = json.loads(result.stdout)
                self.assertEqual(tokens["PHP_CHILDREN"], 2)
                self.assertNotIn("PHP_CALLBACK_CHILDREN", tokens)

    def test_common_public_shape_agrees_with_host_and_keeps_optional_apps(self):
        for mode in ("provided", "acme", "external"):
            c = runtime(mode, backend="none")
            c["nextcloud_apps"] = "bookmarks,calendar"
            self.assertEqual(validate_runtime_versions(c["versions"]), c["versions"])
            result = run_php("echo json_encode([$c,cloudApps($c['nextcloud_apps'])]);", {"runtime": c})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), [c, ["bookmarks", "calendar"]])

    def test_rejects_office_fields_unknown_secrets_and_incomplete_versions(self):
        cases = []
        for key, value in {"onlyoffice_ip": "10.77.0.6", "storage_url": "http://10.77.0.2/",
                           "office_backend": "none", "jwt_secret": "secret", "apps": {}}.items():
            cases.append(dict(runtime(backend="none"), **{key: value}))
        for key, value in {"onlyoffice": "9.4.0", "connector": "10.2.1",
                           "connector_sha256": "d" * 64, "office_backend": "collabora"}.items():
            c = runtime(backend="none")
            c["versions"][key] = value
            cases.append(c)
        for key in runtime(backend="none")["versions"]:
            c = runtime(backend="none")
            del c["versions"][key]
            cases.append(c)
        for c in cases:
            with self.subTest(runtime=c):
                result = run_php("echo 'accepted';", {"runtime": c})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertNotIn("secret", result.stderr)

    def test_no_callback_capacity_tokens_trusted_domain_or_local_server_exception(self):
        for backend in ("none", "onlyoffice"):
            c = runtime("external", port=8443, backend=backend)
            result = run_php("echo json_encode([cloudTokens($c),cloudSystemConfig($c)]);", {"runtime": c})
            self.assertEqual(result.returncode, 0, result.stderr)
            tokens, config = json.loads(result.stdout)
            self.assertEqual(tokens["PHP_CHILDREN"], 8 if backend == "none" else 6)
            for key in ("ONLYOFFICE_IP", "PHP_CALLBACK_CHILDREN"):
                self.assertEqual(key in tokens, backend == "onlyoffice")
            self.assertEqual("10.77.0.6" in tokens["HTTP_CLIENTS"], backend == "onlyoffice")
            self.assertEqual("10.77.0.2" in config["trusted_domains"], backend == "onlyoffice")
            self.assertEqual("allow_local_remote_servers" in config, backend == "onlyoffice")
            self.assertEqual(config["trusted_proxies"], c["proxy_networks"])
            self.assertEqual(config["overwrite.cli.url"], c["public_url"])
            self.assertEqual(config["redis"]["host"], "/var/run/redis/private/nextcloud.sock")

    def test_connector_entrypoints_reject_none_before_reading_record_or_booting(self):
        for expression in ("cloudConnector([], $c);", "cloudConnectorInstall($c);",
                           "cloudConnectorImport($c, []);"):
            result = run_php(expression, {"runtime": runtime(backend="none")})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Invalid public configuration", result.stderr)


@unittest.skipUnless(shutil.which("lua"), "Lua unavailable for decoded-object validation")
class NoneVersionLuaTests(unittest.TestCase):
    def test_exact_none_schema_worker_group_and_package_closure(self):
        # As in the existing worker fixture tests, substitute only libucl's
        # decoded object; run the production Lua on actual temporary lock files.
        def literal(value):
            if isinstance(value, dict):
                return "{" + ",".join("[" + literal(k) + "]=" + literal(v) for k, v in value.items()) + "}"
            if isinstance(value, list):
                return "{" + ",".join(literal(v) for v in value) + "}"
            return "nil" if value is None else json.dumps(value)

        lua = VERSIONS_SOURCE.split("<<'LUA'\n", 1)[1].split("\nLUA\n", 1)[0]
        lock = "php85|8.5.1|lang/php85|2$abc\n"
        c = runtime(backend="none")
        cases = [(c, "nextcloud", lock, "", True), (c, "onlyoffice", lock, "", False),
                 (c, "nextcloud", lock + lock, "", False),
                 (c, "nextcloud", lock, "php85|missing|1.0|devel/missing\n", False)]
        for key in c["versions"]:
            for value in (None, "$(id)", "invalid\n", 123):
                changed = copy.deepcopy(c)
                changed["versions"][key] = value
                cases.append((changed, "nextcloud", lock, "", False))
        for key in ("onlyoffice", "connector", "connector_sha256"):
            changed = copy.deepcopy(c)
            changed["versions"][key] = runtime()["versions"][key]
            cases.append((changed, "nextcloud", lock, "", False))
        for key in ("onlyoffice_ip", "storage_url"):
            cases.append((dict(c, **{key: runtime()[key]}), "nextcloud", lock, "", False))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for document, group, packages, dependencies, accepted in cases:
                (root / "lock").write_text(packages)
                (root / "edges").write_text(dependencies)
                script = "local document=" + literal(document) + "\n"
                script += 'package.preload["ucl"]=function() return {parser=function() return {parse_file=function() return true end, get_object=function() return document end} end} end\n'
                script += "arg=" + literal(["runtime.json", str(root / "lock"), str(root / "edges"), group]) + "\n"
                result = subprocess.run([shutil.which("lua"), "-"], input=script + lua, capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, accepted, result.stderr)
                if accepted:
                    self.assertTrue(result.stdout.startswith("none latest 35.0.0 8.5.1 12.3.1 "))
                else:
                    self.assertEqual(result.stdout, "")


class NoneWorkerShellTests(unittest.TestCase):
    def test_render_selects_none_vhosts_without_changing_native_or_shared_templates(self):
        for backend in ("none", "onlyoffice"):
            with self.subTest(backend=backend), tempfile.TemporaryDirectory() as tmp:
                script = "set -eu\nstage=" + shlex.quote(tmp) + "\nTEMPLATES=/fixture/templates\n"
                script += "version_office_backend=" + backend + "\n"
                script += 'json() { [ "$1" = render ]; printf "%s" "$2"; }\n'
                script += phase("render") + "\nrender https.conf\nrender external.conf\nrender challenge.conf\n"
                result = subprocess.run(["sh", "-c", script], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                for name in ("https", "external", "challenge"):
                    selected = name + ("-none" if backend == "none" and name != "challenge" else "")
                    self.assertEqual((Path(tmp) / (name + ".conf")).read_text(), "/fixture/templates/" + selected + ".conf")

    def test_finish_retains_shared_order_stdin_fences_and_failure_containment(self):
        for failed in ("", "apps", "apachectl", "cron"):
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                script = "set -eu\nSTATE=" + shlex.quote(tmp) + "\n"
                script += "PAYLOAD=$STATE\nAPP=$STATE/app\nTEMPLATES=$STATE/templates\nHELPER=$STATE/helper\n"
                script += "version_office_backend=none\nstage=\ncron_fenced=0\nantivirus_active=0\n"
                script += "FAILED=" + shlex.quote(failed) + "\n"
                script += r'''
fail() { exit 1; }
record() { printf '%s\n' "$*" >> "$STATE/calls"; }
json() { case "$1" in validate) record validate ;; apps) printf notes ;; *) exit 91 ;; esac; }
require_phase() { record "phase $1"; }
private_file() { exit 92; }
install() { exit 93; }
installed_check() { record installed; }
install_optional_apps() { record apps; [ "$FAILED" != apps ]; }
cron_check() { printf present; }
cron_closed() { record fenced; }
sysrc() { [ -z "$(cat)" ]; record "sysrc $*"; }
service() {
    [ -z "$(cat)" ]
    record "service $*"
    case "$*" in 'cron onestatus') return 1 ;; esac
}
start_service() {
    record "start $1"
    service() { [ -z "$(cat)" ]; record "service $*"; }
}
apachectl() { [ -z "$(cat)" ]; record apachectl; [ "$FAILED" != apachectl ]; }
occ() { [ -z "$(cat)" ]; [ "$*" = background:cron ]; record background; }
mdo() { [ -z "$(cat)" ]; case "$*" in *cron.php*) ;; *) exit 94 ;; esac; record cron; [ "$FAILED" != cron ]; }
crontab() { exit 95; }
find() { record permissions; }
chmod() { :; }
'''
                script += phase("cleanup") + "\ntrap cleanup EXIT\n"
                script += phase("close_cron") + "\n" + FINISH + "\nfinish\n"
                script += '[ "$(cat)" = untouched-stdin ]\n'
                result = subprocess.run(["sh", "-c", script], input="untouched-stdin", capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, not failed, result.stderr)
                calls = (root / "calls").read_text().splitlines()
                self.assertEqual((root / "nextcloud-finished").exists(), not failed)
                if failed:
                    self.assertEqual(calls[-2:], ["sysrc cron_enable=NO", "service cron onestop"])
                    self.assertNotIn("sysrc cron_enable=YES", calls)
                else:
                    ordered = ["phase published", "validate", "apps", "service php_fpm restart", "apachectl",
                               "service apache24 graceful", "background", "cron", "installed", "sysrc cron_enable=YES", "start cron"]
                    positions = [calls.index(item) for item in ordered]
                    self.assertEqual(positions, sorted(positions))

    def test_none_loader_requires_real_locks_but_no_connector_and_preserves_stdin(self):
        # The Lua schema is exercised above; stub its scalar output here to test
        # shell binding/digest enforcement with FreeBSD-format utility stand-ins.
        for drift in ("", "packages.lock", "packages.dependencies"):
            with self.subTest(drift=drift), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                c = runtime(backend="none")
                lock = "php85|8.5.1|lang/php85|2$abc\n"
                c["versions"]["packages_sha256"] = hashlib.sha256(lock.encode()).hexdigest()
                c["versions"]["dependencies_sha256"] = hashlib.sha256(b"").hexdigest()
                for name, data in {"runtime.json": json.dumps(c), "packages.lock": lock, "packages.dependencies": ""}.items():
                    (root / name).write_text(data + ("changed\n" if drift == name else ""))
                keys = ("nextcloud", "php", "database", "freebsd_release", "architecture", "php_package",
                        "plan_sha256", "packages_sha256", "dependencies_sha256", "office_backend")
                flua = root / "flua"
                flua.write_text("#!/bin/sh\nprintf '%s\\n' " + shlex.quote("none latest " + " ".join(c["versions"][k] for k in keys)) + "\n")
                flua.chmod(0o700)
                script = "set -eu\nPAYLOAD=" + shlex.quote(tmp) + "\nRUNTIME=$PAYLOAD/runtime.json\n"
                script += 'fail() { exit 1; }\nstat() { case "$2" in %u:%Lp) echo 0:600 ;; %z) wc -c < "$3" ;; *) exit 96 ;; esac; }\n'
                script += 'sha256() { sha256sum "$2" | cut -d " " -f1; }\n'
                for name in ("version_private_file", "version_load"):
                    body = re.search(r"(?ms)^" + name + r"\(\) \{\n.*?^\}", VERSIONS_SOURCE)[0]
                    script += body.replace("/usr/libexec/flua", shlex.quote(str(flua))) + "\n"
                script += 'version_load nextcloud\n[ "$version_office_backend:$version_php_package:$version_nextcloud" = none:php85:35.0.0 ]\n'
                script += '[ "${version_connector-unset}" = unset ]\n[ "$(cat)" = untouched-stdin ]\n'
                result = subprocess.run(["sh", "-c", script], input="untouched-stdin", capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, not drift, result.stderr)


if __name__ == "__main__":
    unittest.main()
