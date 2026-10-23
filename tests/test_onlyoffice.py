"""Pure native-package renderer regression tests; never start services."""

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

from installer import office_config as config
from installer import office, version_runtime
from test_versions import signed_connector


ROOT = Path(__file__).resolve().parents[1]
VERSIONS_SOURCE = (ROOT / "resources/jails/versions.sh").read_text()


def selected_plan():
    def record(name, version, origin, dependencies=None):
        return {"name": name, "version": version, "origin": origin, "abi": "FreeBSD:15:amd64",
                "dependencies": dependencies or {}, "checksum": "2$" + "a" * 103}
    library = record("libfixture", "2.0_1,2", "devel/libfixture")
    dependency = {"libfixture": {key: library[key] for key in ("version", "origin")}}
    return {
        "schema_version": 1,
        "applications": {"nextcloud": "35.0.1", "onlyoffice": "9.4.0_4,2", "connector": "10.2.1"},
        "connector": signed_connector(),
        "target": {"release": "15.1-RELEASE", "architecture": "amd64", "abi": "FreeBSD:15:amd64"},
        "roles": {"php": "php85", "database": "mariadb123-server"},
        "packages": {
            "host": {"bastille": record("bastille", "1.4.4", "sysutils/bastille")},
            "nextcloud": {"php85": record("php85", "8.5.1_2", "lang/php85", dependency),
                          "mariadb123-server": record("mariadb123-server", "12.3.1_1", "databases/mariadb123-server"),
                          "libfixture": library},
            "onlyoffice": {"onlyoffice-documentserver": record(
                "onlyoffice-documentserver", "9.4.0_4,2", "www/onlyoffice-documentserver", dependency),
                "libfixture": library},
        },
    }


def selected_versions(group="onlyoffice"):
    plan = selected_plan()
    return version_runtime.runtime_versions(plan, version_runtime.package_text(plan, group),
                                            version_runtime.dependency_text(plan, group))


def shell_function(name):
    return re.search(r"(?ms)^" + name + r"\(\) \{\n.*?^\}", VERSIONS_SOURCE)[0]


class WorkerVersionPayloadTests(unittest.TestCase):
    def test_both_jails_receive_exact_versions_and_canonical_plan_and_byte_hashes(self):
        plan = selected_plan()
        plan["evidence"] = "UTF-8 résumé"
        before = copy.deepcopy(plan)
        outputs = []
        for group in ("nextcloud", "onlyoffice"):
            text = version_runtime.package_text(plan, group)
            edges = version_runtime.dependency_text(plan, group)
            versions = version_runtime.runtime_versions(plan, text, edges)
            self.assertEqual(text.splitlines(), sorted(text.splitlines()))
            self.assertEqual(versions["packages_sha256"], hashlib.sha256(text.encode()).hexdigest())
            self.assertEqual(versions["dependencies_sha256"], hashlib.sha256(edges.encode()).hexdigest())
            self.assertEqual(versions["connector_sha256"], hashlib.sha256(version_runtime.connector_text(plan).encode()).hexdigest())
            self.assertEqual(versions["plan_sha256"], hashlib.sha256(json.dumps(
                plan, sort_keys=True, separators=(",", ":")).encode()).hexdigest())
            self.assertEqual(versions["onlyoffice"], "9.4.0")
            self.assertEqual(versions["php"], "8.5.1")
            self.assertEqual(versions["database"], "12.3.1")
            self.assertEqual(versions["connector"], "10.2.1")
            outputs.append(versions)
        self.assertEqual(set(outputs[0]), set(outputs[1]))
        for key in set(outputs[0]) - {"packages_sha256", "dependencies_sha256"}:
            self.assertEqual(outputs[0][key], outputs[1][key])
        self.assertEqual(plan, before)

    def test_versions_reject_missing_extra_nonstring_and_shell_characters(self):
        versions = selected_versions()
        self.assertEqual(version_runtime.validate_runtime_versions(versions), versions)
        self.assertIsNot(version_runtime.validate_runtime_versions(versions), versions)
        invalid = [None, [], {}, dict(versions, password="secret")]
        for key in versions:
            invalid.append({name: value for name, value in versions.items() if name != key})
            for value in [None, True, 123, [], versions[key] + "\n", "$(id)", "'quoted'", "x;id"]:
                invalid.append(dict(versions, **{key: value}))
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                version_runtime.validate_runtime_versions(value)

    def test_package_and_dependency_serialization_refuses_unsafe_or_incomplete_closures(self):
        for key, value in [("name", "different"), ("name", "--all"), ("version", "1.2;id"),
                           ("version", "1.2\nother"), ("origin", "../lang/php85"), ("origin", "lang/php85|extra")]:
            plan = selected_plan()
            plan["packages"]["nextcloud"]["php85"][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                version_runtime.package_text(plan, "nextcloud")
        for change in ("missing", "version", "origin", "injection"):
            plan = selected_plan()
            if change == "missing":
                del plan["packages"]["nextcloud"]["libfixture"]
            else:
                dependency = plan["packages"]["nextcloud"]["php85"]["dependencies"]["libfixture"]
                dependency["origin" if change == "origin" else "version"] = "other/origin" if change == "origin" else "different" if change == "version" else "1|extra"
            with self.subTest(change=change), self.assertRaises(ValueError):
                version_runtime.dependency_text(plan, "nextcloud")
        plan = selected_plan()
        text = version_runtime.package_text(plan, "nextcloud")
        for bad in ("", text.rstrip(), text + text, "\n" + text, "x" * 1048577):
            with self.assertRaises(ValueError):
                version_runtime.runtime_versions(plan, bad, "")
        self.assertEqual(version_runtime.dependency_text(plan, "host"), "")

    def test_opaque_repository_versions_and_checksum_identity_are_preserved(self):
        plan = selected_plan()
        record = plan["packages"]["host"]["bastille"]
        record["version"] = ".10_1"
        self.assertIn("|.10_1|", version_runtime.package_text(plan, "host"))
        before = version_runtime.package_text(plan, "onlyoffice")
        plan["packages"]["onlyoffice"]["onlyoffice-documentserver"]["checksum"] = "2$changed"
        after = version_runtime.package_text(plan, "onlyoffice")
        self.assertNotEqual(before, after)
        for value in ("", "2$bad|field", "2$bad\nfield", "$(id)"):
            record["checksum"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                version_runtime.package_text(plan, "host")

    def test_connector_identity_is_not_just_its_version(self):
        plan = selected_plan()
        text, edges = version_runtime.package_text(plan, "onlyoffice"), version_runtime.dependency_text(plan, "onlyoffice")
        before = version_runtime.runtime_versions(plan, text, edges)
        for field in ("signature", "certificate", "download"):
            changed = copy.deepcopy(plan)
            changed["connector"][field] += "different"
            after = version_runtime.runtime_versions(changed, text, edges)
            self.assertNotEqual(before["connector_sha256"], after["connector_sha256"])
            self.assertEqual(before["connector"], after["connector"])

    def test_office_loader_requires_public_versions_and_rejects_credentials(self):
        runtime = {"public_hostname": "cloud.example.test", "public_url": "https://cloud.example.test/",
                   "storage_url": "https://cloud.example.test/", "nextcloud_ip": "10.77.0.2",
                   "onlyoffice_ip": "10.77.0.6", "repository": "quarterly", "tls_mode": "provided",
                   "font_profile": "standard", "additional_fonts": False, "accept_microsoft_fonts": False,
                   "versions": selected_versions()}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "runtime.json"
            path.write_text(json.dumps(runtime))
            path.chmod(0o600)
            self.assertEqual(office.load_runtime(path), runtime)
            missing = dict(runtime)
            del missing["versions"]
            for bad in (missing, dict(runtime, jwt_secret="secret"),
                        dict(runtime, versions=dict(runtime["versions"], credentials="secret"))):
                path.write_text(json.dumps(bad))
                with self.assertRaises(ValueError):
                    office.load_runtime(path)

    def test_office_preserves_native_guards_and_consumes_host_font_selection(self):
        source = (ROOT / "resources/jails/onlyoffice.sh").read_text()
        self.assertLess(source.index("version_environment"), source.index('mkdir -m 700 "$STATE"'))
        self.assertLess(source.index("pkg update"), source.index("version_packages_install"))
        self.assertLess(source.index("grep -qx webfonts"), source.index("version_packages_install"))
        self.assertIn('[ "$accept_microsoft_fonts" != true ]', source)
        self.assertIn("pkg rquery -U -r FreeBSD-ports '%dn'", source)
        self.assertIn("$PAYLOAD/fonts-unavailable", source)
        self.assertIn('"${STATE}/packages.installed"', source)
        self.assertIn("version_packages_check", source)
        self.assertIn("RESTART_CONDITION=false", source)
        self.assertNotRegex(source, r"9\.4\.\*|select_package\(|required-missing|pkg install")
        for path in (ROOT / "resources/jails/onlyoffice.sh", ROOT / "resources/jails/versions.sh"):
            result = subprocess.run(["sh", "-n", str(path)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which("lua"), "Lua is unavailable for isolated base-parser logic checks")
    def test_base_lua_validates_public_scalars_and_complete_lock_rows(self):
        # Stub only libucl's decoded-object boundary. Execute the worker's actual
        # Lua validation on fixture lock files; no jail commands are invoked.
        def literal(value):
            if isinstance(value, dict):
                return "{" + ",".join("[" + literal(key) + "]=" + literal(item) for key, item in value.items()) + "}"
            if isinstance(value, list):
                return "{" + ",".join(literal(item) for item in value) + "}"
            if value is None:
                return "nil"
            return json.dumps(value)

        lua = VERSIONS_SOURCE.split("<<'LUA'\n", 1)[1].split("\nLUA\n", 1)[0]
        plan = selected_plan()
        for group in ("nextcloud", "onlyoffice"):
            lock = version_runtime.package_text(plan, group)
            edges = version_runtime.dependency_text(plan, group)
            runtime = {"repository": "quarterly", "versions": selected_versions(group)}
            cases = [(runtime, lock, edges, True), (runtime, lock + lock, edges, False),
                     (runtime, "".join(reversed(lock.splitlines(keepends=True))), edges, False),
                     (runtime, lock.rstrip(), edges, False), (runtime, lock.replace("|2.0_1,2|", "|2.0;id|"), edges, False),
                     (runtime, lock.replace("devel/libfixture", "devel/libfixture|extra"), edges, False),
                     (runtime, lock, edges + edges, False),
                     (runtime, lock, edges.replace("2.0_1,2", "2.0_2,2"), False),
                     (runtime, lock, edges.replace("|libfixture|", "|unselected|"), False)]
            for key in runtime["versions"]:
                for value in [None, 123, "$(id)", "'quoted'", runtime["versions"][key] + "\n"]:
                    cases.append((dict(runtime, versions=dict(runtime["versions"], **{key: value})), lock, edges, False))
            cases.append((dict(runtime, versions=dict(runtime["versions"], unknown="secret")), lock, edges, False))
            cases.append((dict(runtime, repository="latest;id"), lock, edges, False))
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                for document, packages, dependencies, accepted in cases:
                    (root / "packages.lock").write_text(packages)
                    (root / "packages.dependencies").write_text(dependencies)
                    script = "local document=" + literal(document) + "\n"
                    script += 'package.preload["ucl"]=function() return {parser=function() return {parse_file=function() return true end, get_object=function() return document end} end} end\n'
                    script += "arg=" + literal(["runtime.json", str(root / "packages.lock"), str(root / "packages.dependencies"), group]) + "\n"
                    result = subprocess.run([shutil.which("lua"), "-"], input=script + lua, capture_output=True, text=True)
                    self.assertEqual(result.returncode == 0, accepted, result.stderr)
                    if not accepted:
                        self.assertEqual(result.stdout, "")
        for guard in ('version_private_file "$VERSION_LOCK" 600 1048576',
                      'version_private_file "$VERSION_DEPENDENCIES" 600 1048576',
                      '"$(sha256 -q "$VERSION_LOCK")" = "$version_packages_sha256"',
                      '"$(sha256 -q "$VERSION_DEPENDENCIES")" = "$version_dependencies_sha256"'):
            self.assertIn(guard, VERSIONS_SOURCE)


class LockedPackageWorkerTests(unittest.TestCase):
    lock = "app|1.2.3_4,2|www/app|2$abc123\ndep|2.0_1|devel/dep|2$def456\n"
    edges = "app|dep|2.0_1|devel/dep\n"

    def simulate(self, *, remote=None, edges=None, installed="pkg|2.0|ports-mgmt/pkg\n", result=None, check=False):
        # Execute extracted helper functions only. Every pkg command is a shell
        # stub operating on fixtures; neither worker/entrypoint is executed.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            files = {"VERSION_LOCK": self.lock, "VERSION_DEPENDENCIES": self.edges,
                     "remote": self.lock if remote is None else remote,
                     "edges": self.edges if edges is None else edges, "inventory": installed,
                     "result": self.lock if result is None else result, "calls": ""}
            script = "set -eu\n"
            for name, value in files.items():
                (root / name).write_text(value)
                script += name + "=" + shlex.quote(str(root / name)) + "\n"
            script += r'''
fail() { printf '%s\n' "$*" >&2; exit 1; }
pkg() {
    [ -z "$(cat)" ] || fail 'pkg consumed caller stdin'
    printf '%s\n' "$*" >> "$calls"
    case "$1" in
        query)
            if [ "$2" = -a ]; then cut -d '|' -f1-3 "$inventory"
            else awk -F '|' -v name="$3" '$1 == name {print $2 "|" $3}' "$inventory"; fi ;;
        rquery)
            if [ "$5" = '%dn|%dv|%do' ]; then
                awk -F '|' -v name="$6" '$1 == name {print $2 "|" $3 "|" $4}' "$edges"
            else awk -F '|' -v name="$6" '$1 == name {print}' "$remote"; fi ;;
        install) if [ "$2" = -y ]; then cp "$result" "$inventory"; fi ;;
        *) fail 'Unexpected mock command' ;;
    esac
}
'''
            script += "\n".join(shell_function(name) for name in
                                ("version_packages_inventory", "version_packages_check", "version_packages_install"))
            script += "\n" + ("version_packages_check" if check else "version_packages_install")
            script += "\nIFS= read -r remaining\n[ \"$remaining\" = caller-input ]\n"
            completed = subprocess.run(["sh", "-c", script], input="caller-input\n", capture_output=True, text=True)
            return completed, (root / "calls").read_text().splitlines()

    def test_entire_exact_closure_is_checked_then_installed_once_without_refresh(self):
        result, calls = self.simulate()
        self.assertEqual(result.returncode, 0, result.stderr)
        installs = [call for call in calls if call.startswith("install ")]
        self.assertEqual(installs, ["install -n -y -U -r FreeBSD-ports app-1.2.3_4,2 dep-2.0_1",
                                    "install -y -U -r FreeBSD-ports app-1.2.3_4,2 dep-2.0_1"])
        self.assertLess(max(i for i, call in enumerate(calls) if call.startswith("rquery")), calls.index(installs[0]))
        self.assertGreater(max(i for i, call in enumerate(calls) if call.startswith("query")), calls.index(installs[1]))

    def test_version_origin_or_dependency_drift_stops_before_the_solver(self):
        cases = [dict(remote=self.lock.replace("1.2.3_4,2", "1.2.3_5,2")),
                 dict(remote=self.lock.replace("2$abc123", "2$changed")),
                 dict(remote=self.lock.replace("www/app", "other/app")), dict(remote=""),
                 dict(edges=""), dict(edges=self.edges.replace("2.0_1", "2.1")),
                 dict(edges=self.edges.replace("devel/dep", "other/dep")),
                 dict(edges=self.edges + "app|new|1.0|devel/new\n"), dict(edges=self.edges * 2)]
        for change in cases:
            with self.subTest(change=change):
                result, calls = self.simulate(**change)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(call.startswith("install ") for call in calls))
                self.assertRegex(result.stderr, "original|Restore")

    def test_installed_version_origin_and_extra_package_drift_never_upgrade(self):
        for inventory in (self.lock.replace("1.2.3_4,2", "1.2.3_3,2"),
                          self.lock.replace("1.2.3_4,2", "1.2.3_5,2"),
                          self.lock.replace("www/app", "other/app"),
                          self.lock + "unexpected|1.0|devel/unexpected\n"):
            with self.subTest(inventory=inventory):
                result, calls = self.simulate(installed=inventory)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(call.startswith("install ") for call in calls))
        result, calls = self.simulate(result=self.lock.replace("2.0_1", "2.0_2"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("differs from the lock", result.stderr)
        result, calls = self.simulate(installed=self.lock, check=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(all(call.startswith("query ") for call in calls))

    def test_pkgbase_inventory_is_not_an_unselected_application(self):
        base = "FreeBSD-runtime|15.1p2|base/FreeBSD-runtime\n"
        result, calls = self.simulate(installed=self.lock + base, check=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(all(call.startswith("query ") for call in calls))
        for extra in ("FreeBSD-runtime|15.1p2|devel/runtime\n", "runtime|15.1p2|base/runtime\n"):
            result, calls = self.simulate(installed=self.lock + extra)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(any(call.startswith("install ") for call in calls))

    def test_environment_matches_only_selected_stable_patch_release_and_architecture(self):
        function = shell_function("version_environment").replace("freebsd-version -u", "mock_userland")
        for kernel, userland, arch, accepted in [
            ("15.2-RELEASE", "15.2-RELEASE-p12", "amd64", True),
            ("15.2-RELEASE-p2", "15.2-RELEASE", "amd64", True),
            ("15.1-RELEASE", "15.2-RELEASE", "amd64", False),
            ("15.2-STABLE", "15.2-RELEASE", "amd64", False),
            ("15.2-RELEASE", "15.2-RELEASE-p1extra", "amd64", False),
            ("15.2-RELEASE", "15.2-RELEASE", "aarch64", False),
        ]:
            script = "set -eu\nversion_release=15.2-RELEASE\nversion_architecture=amd64\n"
            script += "fail() { exit 1; }\n"
            script += "uname() { case \"$1\" in -s) echo FreeBSD ;; -r) echo " + shlex.quote(kernel) + " ;; -m) echo " + shlex.quote(arch) + " ;; esac; }\n"
            script += "mock_userland() { echo " + shlex.quote(userland) + "; }\n"
            result = subprocess.run(["sh", "-c", script + function + "\nversion_environment"], capture_output=True, text=True)
            self.assertEqual(result.returncode == 0, accepted, result.stderr)


class ReusableOnlyofficeRendererTests(unittest.TestCase):
    def test_root_https_url_required(self):
        for url in ("https://cloud.example.test", "https://192.0.2.10:8443/"):
            self.assertEqual(config.public_base_url(url), url.rstrip("/") + "/")
        for url in ("http://cloud.example.test/", "https://user@cloud.example.test/",
                    "https://cloud.example.test/nc/", "https://cloud.example.test/?x=y",
                    "https://cloud.example.test/#fragment", "https://cloud.example.test:99999/",
                    "https://cloud.example.test/\nInjected", "https://cloud.example.test\\injected/",
                    "https://cloud.example.test/\n", " https://cloud.example.test/"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                config.public_base_url(url)

    def test_backend_port_validation(self):
        self.assertEqual(config.backend_port("8081"), 8081)
        for port in ("abc", "80", "443", "8000", "8125", "8126", "9000", "08000", "65536"):
            with self.subTest(port=port), self.assertRaises(ValueError):
                config.backend_port(port)

    def test_jwt_and_tls_preserve_package_configuration(self):
        original = {"storage": {"fs": {"secretString": "existing-cache-secret", "folderPath": "/cache"}},
                    "services": {"CoAuthoring": {"server": {"port": 8000}}}, "log": {"filePath": "/log"}}
        before = json.dumps(original, sort_keys=True)
        rendered = config.local_config(original, "test-jwt-not-a-real-secret", False)
        self.assertEqual(json.dumps(original, sort_keys=True), before)
        self.assertEqual(rendered["storage"], original["storage"])
        self.assertEqual(rendered["log"], original["log"])
        coauthoring = rendered["services"]["CoAuthoring"]
        self.assertEqual(coauthoring["server"]["port"], 8000)
        self.assertTrue(coauthoring["requestDefaults"]["rejectUnauthorized"])
        self.assertFalse(coauthoring["request-filtering-agent"]["allowPrivateIPAddress"])
        self.assertFalse(coauthoring["request-filtering-agent"]["allowMetaIPAddress"])
        self.assertEqual(coauthoring["token"]["enable"],
                         {"browser": True, "request": {"inbox": True, "outbox": True}})
        for direction in ("inbox", "outbox"):
            self.assertEqual(coauthoring["token"][direction]["header"], "AuthorizationJWT")
        for name in ("browser", "inbox", "outbox", "session"):
            self.assertEqual(coauthoring["secret"][name], {"string": "test-jwt-not-a-real-secret", "file": ""})

    def test_private_network_opt_in(self):
        rendered = config.local_config({}, "test", True)
        filters = rendered["services"]["CoAuthoring"]["request-filtering-agent"]
        self.assertTrue(filters["allowPrivateIPAddress"])
        self.assertFalse(filters["allowMetaIPAddress"])

    def test_nginx_keeps_package_includes_and_secure_link(self):
        original = """include /includes/http-common.conf;
server {
  listen 0.0.0.0:80;
  listen [::]:80 default_server;
  set $secure_link_secret existing-cache-secret;
  include /includes/ds-*.conf;
}
"""
        rendered = config.nginx_frontend(original, 8081)
        self.assertIn("listen 127.0.0.1:8081;", rendered)
        self.assertEqual(rendered.count("listen "), 1)
        self.assertIn("set $secure_link_secret existing-cache-secret;", rendered)
        self.assertIn("include /includes/http-common.conf;", rendered)
        self.assertIn("include /includes/ds-*.conf;", rendered)
        with self.assertRaises(ValueError):
            config.nginx_frontend(original.replace("0.0.0.0:80", "0.0.0.0:8080"), 8081)

    def test_backend_internal_endpoints_do_not_trust_proxy_loopback(self):
        original = """location /internal/ {
  allow 127.0.0.1;
  deny all;
  proxy_pass http://docservice;
}
location /info/ {
  allow 127.0.0.1;
  deny all;
}
"""
        rendered = config.restrict_nginx_internal(original)
        self.assertNotIn("allow 127.0.0.1;", rendered)
        self.assertEqual(rendered.count("deny all;"), 2)
        self.assertIn("proxy_pass http://docservice;", rendered)
        with self.assertRaises(ValueError):
            config.restrict_nginx_internal("location / { allow all; }")

    def test_proxy_headers_websockets_and_private_paths(self):
        template = (ROOT / "resources/templates/onlyoffice/proxy.conf").read_text()
        rendered = config.proxy_config(template, "https://cloud.example.test:8443/", 8081)
        self.assertIn('X-Forwarded-Host "cloud.example.test:8443/onlyoffice"', rendered)
        self.assertIn('X-Forwarded-Proto "https"', rendered)
        self.assertIn("upgrade=websocket", rendered)
        self.assertIn("http://127.0.0.1:8081/", rendered)
        self.assertNotIn("ONLYOFFICE_", rendered)
        pattern = re.search(r'<LocationMatch "([^"]+)">', rendered).group(1)
        for path in ("/onlyoffice/internal/cluster", "/onlyoffice/INFO/", "/onlyoffice/info",
                     "/onlyoffice/9.4.0-129/internal/test", "/onlyoffice/9.4.0.129_cache/info/",
                     "/onlyoffice/admin", "/onlyoffice/example/"):
            self.assertRegex(path, pattern)
        self.assertNotRegex("/onlyoffice/web-apps/apps/api/documents/api.js", pattern)

    def test_supervisor_socket_pid_and_ca_trust(self):
        supervisor = (ROOT / "resources/templates/onlyoffice/supervisord.conf").read_text()
        self.assertIn("chmod=0700", supervisor)
        self.assertIn("pidfile=/var/run/supervisor/supervisord.pid", supervisor)
        self.assertNotIn("inet_http_server", supervisor)
        self.assertIn("/supervisor/*.conf", supervisor)
        renderer = (ROOT / "installer/office.py").read_text()
        self.assertIn("NODE_EXTRA_CA_CERTS", renderer)
        self.assertNotIn("NODE_TLS_REJECT_UNAUTHORIZED", renderer)


if __name__ == "__main__":
    unittest.main()
