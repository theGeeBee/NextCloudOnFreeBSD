"""Offline tests for the separate ONLYOFFICE jail; no provisioning is executed."""

import configparser
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from installer import office, version_runtime
from test_versions import signed_connector


ROOT = Path(__file__).resolve().parents[1]
VERSION_SOURCE = (ROOT / "resources/jails/versions.sh").read_text()


def public_versions():
    """A resolved fixture, independent of live discovery and central policy."""
    def package(name, version, origin):
        return {"name": name, "version": version, "origin": origin,
                "abi": "FreeBSD:15:amd64", "dependencies": {}, "checksum": "2$" + "a" * 103}
    plan = {
        "schema_version": 1,
        "applications": {"nextcloud": "35.0.1", "onlyoffice": "9.4.0_4", "connector": "10.2.1"},
        "connector": signed_connector(),
        "target": {"release": "15.1-RELEASE", "architecture": "amd64", "abi": "FreeBSD:15:amd64"},
        "roles": {"php": "php85", "database": "mariadb123-server"},
        "packages": {
            "nextcloud": {"php85": package("php85", "8.5.1_2", "lang/php85"),
                          "mariadb123-server": package("mariadb123-server", "12.3.1_1", "databases/mariadb123-server")},
            "onlyoffice": {"onlyoffice-documentserver": package(
                "onlyoffice-documentserver", "9.4.0_4", "www/onlyoffice-documentserver")},
        },
    }
    return version_runtime.runtime_versions(plan, version_runtime.package_text(plan, "onlyoffice"),
                                            version_runtime.dependency_text(plan, "onlyoffice"))


def version_function(name):
    return re.search(r"(?ms)^" + re.escape(name) + r"\(\) \{\n.*?^\}", VERSION_SOURCE)[0]


PUBLIC = {
    "public_hostname": "cloud.example.test",
    "public_url": "https://cloud.example.test/",
    "storage_url": "https://cloud.example.test/",
    "nextcloud_ip": "10.77.0.2",
    "onlyoffice_ip": "10.77.0.3",
    "repository": "quarterly",
    "tls_mode": "acme",
    "font_profile": "comprehensive",
    "additional_fonts": False,
    "accept_microsoft_fonts": False,
    "versions": public_versions(),
}
CREDENTIALS = {"jwt_secret": "ab" * 32}
RUNTIME = dict(PUBLIC, **CREDENTIALS)
LOCAL = {
    "storage": {"fs": {"secretString": "generated-cache-secret", "folderPath": "/cache"}},
    "services": {"CoAuthoring": {"server": {"port": 9999, "other": "retain"},
                               "requestDefaults": {"rejectUnauthorized": False, "timeout": 1000}}},
    "unrelated": {"preserved": True},
}
FRONTEND = """include /usr/local/etc/onlyoffice/documentserver/nginx/includes/http-common.conf;
upstream retained_test_fixture { server localhost:8000; }
server {
  listen 0.0.0.0:80;
  listen [::]:80 default_server;
  set $secure_link_secret generated-cache-secret;
  include /usr/local/etc/onlyoffice/documentserver/nginx/includes/ds-*.conf;
}
"""
INTERNAL = r"""location ~* ^(/\d+\.\d+\.\d+[.-]\w+)?/(internal)(/.*)$ {
  allow 127.0.0.1;
  deny all;
  proxy_pass http://docservice/$2$3;
}
location ~* ^(/\d+\.\d+\.\d+[.-]\w+)?/(info)(/.*)$ {
  allow 127.0.0.1;
  deny all;
  proxy_pass http://docservice/$2$3;
}
"""
GROUP = "[group:ds]\nprograms=docservice,metrics\n"


def program(name):
    # Reviewed FreeBSD port files/ds-docservice.conf and ds-metrics.conf.
    directory = "DocService" if name == "docservice" else "Metrics"
    base = "/usr/local/www/onlyoffice/documentserver/server/" + directory
    command = base + "/" + name + (" ./config/config.js" if name == "metrics" else "")
    environment = "NODE_DISABLE_COLORS=1"
    if name == "docservice":
        environment = ("NODE_ENV=production-freebsd,"
                       "NODE_CONFIG_DIR=/usr/local/etc/onlyoffice/documentserver," + environment)
    return f"""[program:{name}]
command={command}
directory={base}
user=onlyoffice
environment={environment}
stdout_logfile=/var/log/onlyoffice/documentserver/{name}/out.log
stdout_logfile_backups=0
stdout_logfile_maxbytes=0
stderr_logfile=/var/log/onlyoffice/documentserver/{name}/err.log
stderr_logfile_backups=0
stderr_logfile_maxbytes=0
autostart=true
autorestart=true
"""


def render(config=None, **changes):
    arguments = {
        "config": RUNTIME if config is None else config,
        "original": LOCAL, "frontend": FRONTEND, "internal": INTERNAL,
        "programs": {name: program(name) for name in ("docservice", "metrics")},
        "group": GROUP,
    }
    arguments.update(changes)
    return office.render_files(**arguments)


class OfficeJailTests(unittest.TestCase):
    def test_import_does_not_launch_commands_or_read_runtime(self):
        fresh_spec = importlib.util.spec_from_file_location("installer.fresh_office", ROOT / "installer/office.py")
        module = importlib.util.module_from_spec(fresh_spec)
        with patch("subprocess.run", side_effect=AssertionError("unexpected command")), \
                patch("os.system", side_effect=AssertionError("unexpected command")), \
                patch.object(Path, "read_text", side_effect=AssertionError("unexpected input read")):
            fresh_spec.loader.exec_module(module)

    def test_runtime_validation_rejects_injection_and_invalid_topology(self):
        invalid = {
            "public_hostname": ["cloud.test:443", "https://cloud.test", "cloud.test/", "localhost",
                                "cloud.test\nRequire all granted", "127.0.0.1", "bad_label.test"],
            "nextcloud_ip": ["127.0.0.1", "169.254.169.254", "8.8.8.8", "::1", 123, "10.77.0.3"],
            "onlyoffice_ip": ["10.0.0.3:8081", "10.0.0.3;", "010.0.0.3", "10.77.0.2"],
            "jwt_secret": ["test-secret", "g" * 64, "ab" * 31, "ab" * 32 + "\n"],
            "repository": ["latest; id", "unknown"],
            "tls_mode": ["off", "selfsigned"],
            "public_url": ["http://cloud.example.test/", "https://other.example.test/",
                           "https://cloud.example.test/nc/", "https://cloud.example.test:0/"],
            "storage_url": ["https://other.example.test/", "http://10.77.0.2/"],
            "font_profile": ["all", False],
            "additional_fonts": [123, "relative", "/a\nfont"],
            "accept_microsoft_fonts": ["yes", 1],
        }
        for key, values in invalid.items():
            for value in values:
                with self.subTest(key=key, value=value), self.assertRaises(ValueError) as error:
                    office.validate_runtime(dict(RUNTIME, **{key: value}))
                self.assertNotIn(RUNTIME["jwt_secret"], str(error.exception))
        for invalid_object in ([], None, {}, {"jwt_secret": RUNTIME["jwt_secret"]}):
            with self.assertRaises(ValueError):
                office.validate_runtime(invalid_object)
        config = dict(RUNTIME, admin_password="unrelated-host-secret")
        self.assertEqual(office.validate_runtime(config), RUNTIME)
        self.assertIn("admin_password", config)

    def test_connector_exports_only_matching_urls_jwt_and_verification(self):
        config = dict(RUNTIME, admin_password="unrelated-host-secret", database_password="db-secret")
        exported = office.connector_settings(config)
        self.assertEqual(exported, {"apps": {"onlyoffice": {
            "DocumentServerUrl": "https://cloud.example.test/onlyoffice/",
            "DocumentServerInternalUrl": "http://10.77.0.3:8081/",
            "StorageUrl": "https://cloud.example.test/",
            "jwt_secret": RUNTIME["jwt_secret"], "jwt_header": "AuthorizationJWT",
            "verify_peer_off": "false",
        }}})
        self.assertNotIn("unrelated-host-secret", json.dumps(exported))
        self.assertNotIn("db-secret", json.dumps(exported))

    def test_public_authority_and_http_storage_are_independent(self):
        self.assertEqual(office.validate_runtime(dict(PUBLIC, font_profile="standard"))["font_profile"], "standard")
        config = dict(RUNTIME, tls_mode="external", public_url="https://cloud.example.test:8443/",
                      storage_url="http://10.77.0.2/")
        connector = office.connector_settings(config)["apps"]["onlyoffice"]
        self.assertEqual(connector["DocumentServerUrl"], "https://cloud.example.test:8443/onlyoffice/")
        self.assertEqual(connector["StorageUrl"], "http://10.77.0.2/")
        self.assertEqual(connector["verify_peer_off"], "false")
        proxy = office.apache_proxy(config)
        self.assertIn('X-Forwarded-Proto "https"', proxy)
        self.assertIn('X-Forwarded-Host "cloud.example.test:8443/onlyoffice"', proxy)
        self.assertNotIn('X-Forwarded-Host "https://', proxy)
        self.assertNotIn("http://10.77.0.2/", proxy)
        direct = dict(RUNTIME, public_url="https://cloud.example.test:8443/",
                      storage_url="https://cloud.example.test:443/")
        self.assertEqual(office.connector_settings(direct)["apps"]["onlyoffice"]["StorageUrl"],
                         "https://cloud.example.test:443/")
        for invalid in ("https://cloud.example.test/", "http://10.77.0.3/", "http://10.77.0.2/nc/"):
            with self.assertRaises(ValueError):
                office.validate_runtime(dict(config, storage_url=invalid))

    def test_credentials_are_a_bounded_jwt_only_stdin_object(self):
        self.assertEqual(office.read_credentials(io.StringIO(json.dumps(CREDENTIALS))), CREDENTIALS)
        invalid = ["", "null", "[]", "{}", '{"jwt_secret":"wrong"}',
                   json.dumps(dict(CREDENTIALS, admin_password="host-only-secret")),
                   json.dumps(CREDENTIALS) + " " * 4096,
                   '{"jwt_secret":"' + CREDENTIALS["jwt_secret"] + '","jwt_secret":"' + CREDENTIALS["jwt_secret"] + '"}']
        for value in invalid:
            with self.subTest(value=value[:20]), self.assertRaises(ValueError):
                office.read_credentials(io.StringIO(value))

    def test_jwt_tls_and_embedded_runtime_preserve_original_configuration(self):
        before = copy.deepcopy(LOCAL)
        rendered = office.local_configuration(LOCAL, RUNTIME)
        self.assertEqual(LOCAL, before)
        self.assertEqual(rendered["storage"], LOCAL["storage"])
        self.assertEqual(rendered["unrelated"], LOCAL["unrelated"])
        settings = rendered["services"]["CoAuthoring"]
        self.assertEqual(settings["server"], {"port": 8000, "other": "retain"})
        self.assertEqual(settings["requestDefaults"], {"rejectUnauthorized": True, "timeout": 1000})
        self.assertEqual(settings["request-filtering-agent"],
                         {"allowPrivateIPAddress": True, "allowMetaIPAddress": False})
        self.assertEqual(settings["token"]["enable"],
                         {"browser": True, "request": {"inbox": True, "outbox": True}})
        self.assertTrue(settings["token"]["browser"]["secretFromInbox"])
        for direction in ("inbox", "outbox"):
            self.assertEqual(settings["token"][direction]["header"], "AuthorizationJWT")
            self.assertFalse(settings["token"][direction]["inBody"])
        for name in ("browser", "inbox", "outbox", "session"):
            self.assertEqual(settings["secret"][name], {"string": RUNTIME["jwt_secret"], "file": ""})

    def test_frontend_binds_only_jail_ip_and_preserves_upstreams_and_cache_secret(self):
        files = render()
        frontend = files["ds.conf"]
        self.assertEqual(re.findall(r"\blisten\s+([^;]+);", frontend), ["10.77.0.3:8081"])
        for line in FRONTEND.splitlines():
            if "listen " not in line:
                self.assertIn(line, frontend)
        self.assertNotIn("allow 127.0.0.1;", files["ds-docservice.conf"])
        self.assertEqual(files["ds-docservice.conf"].count("deny all;"), 2)
        self.assertEqual(files["ds-docservice.conf"].count("proxy_pass http://docservice/$2$3;"), 2)
        self.assertEqual(files["healthcheck-url"], "http://10.77.0.3:8081/healthcheck\n")
        self.assertNotIn("connector.json", files)
        self.assertNotIn("vhost.conf", files)

    def test_unreviewed_package_layout_or_missing_helpers_fail_closed(self):
        invalid = [
            {"original": {}},
            {"original": {"storage": {"fs": {"secretString": "verysecretstring"}}}},
            {"frontend": FRONTEND.replace("generated-cache-secret", "different-secret")},
            {"frontend": FRONTEND.replace("0.0.0.0:80", "0.0.0.0:8080")},
            {"internal": INTERNAL.replace("allow 127.0.0.1;", "allow all;", 1)},
            {"group": GROUP.replace("metrics", "metrics,converter")},
            {"programs": {"docservice": program("docservice"),
                          "metrics": program("metrics").replace("user=onlyoffice", "user=root")}},
        ]
        for change in invalid:
            with self.subTest(change=next(iter(change))), self.assertRaises(ValueError):
                render(**change)

    def test_apache_proxy_protects_private_and_versioned_endpoints(self):
        proxy = office.apache_proxy(RUNTIME)
        self.assertEqual(proxy.count("http://10.77.0.3:8081/"), 2)
        self.assertNotIn("127.0.0.1", proxy)
        self.assertNotIn("ONLYOFFICE_", proxy)
        self.assertIn("upgrade=websocket timeout=3600", proxy)
        self.assertIn('X-Forwarded-Proto "https"', proxy)
        self.assertIn('X-Forwarded-Host "cloud.example.test/onlyoffice"', proxy)
        self.assertNotIn(RUNTIME["jwt_secret"], proxy)
        pattern = re.search(r'<LocationMatch "([^"]+)">', proxy).group(1)
        for endpoint in ("internal", "info", "admin", "example"):
            for prefix in ("", "9.4.0-129/", "9.4.0.129_cache/", "9.4.0|129/"):
                for suffix in ("", "/", "/test"):
                    self.assertRegex(f"/onlyoffice/{prefix}{endpoint}{suffix}", pattern)
        self.assertRegex("/onlyoffice/INFO", pattern)
        self.assertNotRegex("/onlyoffice/web-apps/apps/api/documents/api.js", pattern)

    def test_supervisor_programs_rotate_logs_without_altering_native_commands(self):
        files = render()
        for name in ("docservice", "metrics"):
            before = configparser.ConfigParser(interpolation=None)
            before.read_string(program(name))
            after = configparser.ConfigParser(interpolation=None)
            after.read_string(files[f"supervisor-ds-{name}.conf"])
            old, new = before[f"program:{name}"], after[f"program:{name}"]
            for key in old:
                if key.endswith("_maxbytes"):
                    self.assertEqual(new[key], "10MB")
                elif key.endswith("_backups"):
                    self.assertEqual(new[key], "5")
                else:
                    self.assertEqual(new[key], old[key])
        supervisor = configparser.ConfigParser(interpolation=None)
        supervisor.read_string(files["supervisord.conf"])
        self.assertEqual(supervisor["supervisord"]["pidfile"], "/var/run/supervisor/supervisord.pid")
        self.assertEqual(supervisor["unix_http_server"]["chmod"], "0700")
        self.assertEqual(supervisor["supervisord"]["logfile_maxbytes"], "10MB")
        self.assertNotIn("inet_http_server", supervisor)
        self.assertNotIn("environment", supervisor["supervisord"])
        self.assertIn("pid /var/run/nginx.pid;", files["nginx.conf"])
        rotation = files["nginx-newsyslog.conf"]
        self.assertIn("/var/run/nginx.pid SIGUSR1", rotation)
        self.assertNotIn("supervisord.pid", rotation)

    def test_ca_bundle_is_validated_and_only_extends_node_trust(self):
        config = dict(RUNTIME, tls_mode="provided")
        with patch.object(office.ssl, "create_default_context") as context:
            files = render(config, ca_pem="public-certificate-fixture")
        context.return_value.load_verify_locations.assert_called_once_with(cadata="public-certificate-fixture")
        self.assertIn(f'NODE_EXTRA_CA_CERTS="{office.CA_DESTINATION}"', files["supervisord.conf"])
        self.assertEqual(files["nextcloud-ca.pem"], "public-certificate-fixture")
        self.assertNotIn("NODE_TLS_REJECT_UNAUTHORIZED", files["supervisord.conf"])
        self.assertTrue(json.loads(files["local.json"])["services"]["CoAuthoring"]
                        ["requestDefaults"]["rejectUnauthorized"])
        for pem in ("invalid PEM", "-----BEGIN PRIVATE KEY-----"):
            with self.assertRaises(ValueError):
                render(config, ca_pem=pem)
        with self.assertRaises(ValueError):
            render(ca_pem="a bundle is only allowed for provided TLS")

    def fixture(self, root):
        package = root / "package"
        inputs = {
            "local.json": json.dumps(LOCAL), "nginx/ds.conf": FRONTEND,
            "nginx/ds-ssl.conf": FRONTEND,
            "nginx/includes/ds-docservice.conf": INTERNAL, "supervisor/ds.conf": GROUP,
            "supervisor/ds-docservice.conf": program("docservice"),
            "supervisor/ds-metrics.conf": program("metrics"),
        }
        for name, text in inputs.items():
            path = package / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        runtime = root / "runtime.json"
        runtime.write_text(json.dumps(PUBLIC))
        runtime.chmod(0o600)
        return SimpleNamespace(runtime=runtime, package_etc=package, staging=root / "rendered", ca_file=None)

    def test_prepare_uses_private_exclusive_staging_and_never_overwrites_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixture(Path(tmp))
            before = {path: path.read_bytes() for path in Path(tmp).rglob("*") if path.is_file()}
            old_umask = os.umask(0)
            try:
                office.prepare(args, CREDENTIALS)
            finally:
                os.umask(old_umask)
            self.assertEqual(args.staging.stat().st_mode & 0o777, 0o700)
            for path in args.staging.iterdir():
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            for path, contents in before.items():
                self.assertEqual(path.read_bytes(), contents)
            secret_file = args.staging / "local.json"
            secret_before = secret_file.read_bytes()
            with self.assertRaises(FileExistsError):
                office.prepare(args, CREDENTIALS)
            self.assertEqual(secret_file.read_bytes(), secret_before)

    def test_bad_input_does_not_create_staging(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixture(Path(tmp))
            args.runtime.chmod(0o644)
            with self.assertRaises(ValueError):
                office.prepare(args, CREDENTIALS)
            self.assertFalse(args.staging.exists())
            args.runtime.chmod(0o600)
            (args.package_etc / "nginx/ds.conf").write_text(FRONTEND.replace("generated-cache-secret", "mismatch"))
            with self.assertRaises(ValueError):
                office.prepare(args, CREDENTIALS)
            self.assertFalse(args.staging.exists())
            (args.package_etc / "nginx/ds.conf").write_text(FRONTEND)
            (args.package_etc / "supervisor/ds-converter.conf").write_text("[program:converter]\n")
            with self.assertRaises(ValueError):
                office.prepare(args, CREDENTIALS)
            self.assertFalse(args.staging.exists())

    def test_direct_cli_is_cwd_independent_and_does_not_print_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixture(Path(tmp))
            command = [sys.executable, str(ROOT / "installer/office.py"), "prepare",
                       "--runtime", str(args.runtime), "--package-etc", str(args.package_etc),
                       "--staging", str(args.staging)]
            result = subprocess.run(command, cwd=tmp, text=True, capture_output=True,
                                    input=json.dumps(CREDENTIALS), env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stderr, "")
            result = subprocess.run(command, cwd=tmp, text=True, capture_output=True,
                                    input='{"jwt_secret":"deliberate-secret-leak-probe"}',
                                    env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("deliberate-secret-leak-probe", result.stderr + result.stdout)
            self.assertNotIn("Traceback", result.stderr)
            module_command = [sys.executable, "-m", "installer.office"] + command[2:]
            module_command[-1] = str(Path(tmp) / "module-rendered")
            result = subprocess.run(module_command, cwd=ROOT, text=True, capture_output=True,
                                    input=json.dumps(CREDENTIALS), env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((Path(tmp) / "module-rendered/local.json").read_bytes(),
                             (args.staging / "local.json").read_bytes())

    def test_runtime_file_never_accepts_credentials_or_duplicate_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixture(Path(tmp))
            self.assertEqual(office.load_runtime(args.runtime), PUBLIC)
            for key in ("jwt_secret", "admin_password", "credentials", "database_password"):
                args.runtime.write_text(json.dumps(dict(PUBLIC, **{key: "host-secret"})))
                with self.subTest(key=key), self.assertRaises(ValueError):
                    office.load_runtime(args.runtime)
            args.runtime.write_text(json.dumps(PUBLIC)[:-1] + ',"repository":"latest"}')
            with self.assertRaises(ValueError):
                office.load_runtime(args.runtime)
            args.runtime.write_text(json.dumps(PUBLIC).replace('"connector": "10.2.1"',
                                                             '"connector": "10.2.1", "connector": "10.2.2"'))
            with self.assertRaises(ValueError):
                office.load_runtime(args.runtime)

    def test_both_runtime_validation_apis_require_exact_public_version_fields(self):
        versions = PUBLIC["versions"]
        self.assertEqual(versions["onlyoffice"], "9.4.0")
        self.assertEqual(versions["php"], "8.5.1")
        self.assertEqual(versions["database"], "12.3.1")
        self.assertEqual(office.validate_runtime(RUNTIME)["versions"], versions)
        invalid = [None, {}, [], dict(versions, credentials="not-public")]
        for key in versions:
            invalid.append({name: value for name, value in versions.items() if name != key})
            invalid.append(dict(versions, **{key: versions[key] + "\n"}))
            invalid.append(dict(versions, **{key: 123}))
        for key, value in (("nextcloud", "35"), ("onlyoffice", "9.4.*"), ("onlyoffice", "9.4.0_4"),
                           ("connector", "10.2"), ("php", ">=8.5.1"), ("php_package", "php85;id"),
                           ("freebsd_release", "15.1-STABLE"), ("plan_sha256", "a" * 63)):
            invalid.append(dict(versions, **{key: value}))
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixture(Path(tmp))
            self.assertEqual(office.load_runtime(args.runtime)["versions"], versions)
            for value in invalid:
                with self.subTest(versions=value):
                    with self.assertRaises(ValueError):
                        office.validate_runtime(dict(RUNTIME, versions=value))
                    args.runtime.write_text(json.dumps(dict(PUBLIC, versions=value)))
                    with self.assertRaises(ValueError):
                        office.load_runtime(args.runtime)
            missing = dict(PUBLIC)
            del missing["versions"]
            with self.assertRaises(ValueError):
                office.validate_runtime(missing)
            args.runtime.write_text(json.dumps(missing))
            with self.assertRaises(ValueError):
                office.load_runtime(args.runtime)

    def test_partial_render_is_removed_on_exception(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixture(Path(tmp))
            original = office.write_private
            calls = []

            def interrupted(path, text):
                calls.append(path.name)
                if len(calls) == 2:
                    self.assertTrue((args.staging / "local.json").exists())
                    raise OSError("simulated disk failure")
                original(path, text)

            with patch.object(office, "write_private", interrupted), self.assertRaises(OSError):
                office.prepare(args, CREDENTIALS)
            self.assertFalse(args.staging.exists())
            for path in Path(tmp).rglob("*"):
                if path.is_file():
                    self.assertNotIn(CREDENTIALS["jwt_secret"], path.read_text())

    def test_owned_partial_configuration_resumes_without_new_jwt_or_securelink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = self.fixture(root)
            args.state = root / "state"
            args.state.mkdir(mode=0o700)
            args.pristine_etc = root / "original"
            shutil.copytree(args.package_etc, args.pristine_etc)
            office.prepare(args, CREDENTIALS)
            before = {path.name: path.read_bytes() for path in args.staging.iterdir()}
            # Simulate an interruption midway through the shell's deployment.
            shutil.copyfile(args.staging / "local.json", args.package_etc / "local.json")
            shutil.copyfile(args.staging / "ds.conf", args.package_etc / "nginx/ds.conf")
            args.staging = root / "retry"
            office.prepare(args, CREDENTIALS)
            self.assertEqual(before, {path.name: path.read_bytes() for path in args.staging.iterdir()})
            self.assertTrue(office.securelink_matches(args.package_etc))
            for path in args.state.iterdir():
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertNotIn(CREDENTIALS["jwt_secret"], path.read_text())
            args.staging = root / "wrong-credential"
            with self.assertRaises(ValueError):
                office.prepare(args, {"jwt_secret": "cd" * 32})
            self.assertFalse(args.staging.exists())
            self.assertEqual(json.loads((args.pristine_etc / "local.json").read_text()), LOCAL)

    def test_deployed_configuration_verification_is_read_only_and_detects_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = self.fixture(root)
            args.state = root / "state"
            args.state.mkdir(mode=0o700)
            args.system_etc = root / "system-etc"
            office.prepare(args, CREDENTIALS)
            paths = office.deployment_paths(args.package_etc, args.system_etc)
            for name, path in paths.items():
                if (args.staging / name).exists():
                    path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(args.staging / name, path)
                    path.chmod(0o640 if name == "local.json" else 0o600)
            before = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in root.rglob("*") if path.is_file()}
            office.verify_configuration(args, RUNTIME)
            self.assertEqual(before, {path: (path.read_bytes(), path.stat().st_mtime_ns)
                                      for path in root.rglob("*") if path.is_file()})
            with self.assertRaises(ValueError):
                office.verify_configuration(args, dict(RUNTIME, jwt_secret="cd" * 32))
            paths["nginx.conf"].write_text(paths["nginx.conf"].read_text() + "# changed\n")
            with self.assertRaises(ValueError):
                office.verify_configuration(args, RUNTIME)

    def test_securelink_requires_matching_http_https_and_backend(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixture(Path(tmp))
            self.assertTrue(office.securelink_matches(args.package_etc))
            (args.package_etc / "nginx/ds-ssl.conf").write_text(FRONTEND.replace("generated-cache-secret", "different"))
            self.assertFalse(office.securelink_matches(args.package_etc))
            (args.package_etc / "local.json").write_text('{"storage":{"fs":{"secretString":"verysecretstring"}}}')
            self.assertFalse(office.securelink_matches(args.package_etc))

    def test_securelink_checks_every_native_tls_server_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixture(Path(tmp))
            tls = args.package_etc / "nginx/ds-ssl.conf"
            tls.write_text(FRONTEND * 3)
            self.assertTrue(office.securelink_matches(args.package_etc))
            for index in range(3):
                blocks = [FRONTEND] * 3
                blocks[index] = FRONTEND.replace("generated-cache-secret", "different")
                tls.write_text("\n".join(blocks))
                self.assertFalse(office.securelink_matches(args.package_etc))
            tls.write_text("# set $secure_link_secret generated-cache-secret;\n")
            self.assertFalse(office.securelink_matches(args.package_etc))

    def test_worker_orders_guards_mounts_helpers_and_both_health_checks(self):
        source = (ROOT / "resources/jails/onlyoffice.sh").read_text()
        ordered = ["uname -s", "id -u", "security.jail.jailed", "version_load onlyoffice", "version_environment",
                   "root_device=", "installed_origins=", "sockstat", "pkg bootstrap -y -r FreeBSD-ports",
                   "pkg update -r FreeBSD-ports", "pkg rquery -U -r FreeBSD-ports", "(version_packages_install)",
                   "RESTART_CONDITION=false sh -e /usr/local/bin/documentserver-update-securelink.sh",
                   "fc-cache -f", "documentserver-generate-allfonts.sh true", "RESTART_CONDITION=false sh -e /usr/local/bin/documentserver-flush-cache.sh",
                   "set -- prepare", 'python3 "$OFFICE" "$@" <&3', 'nginx -t > "${LOGS}',
                   "service supervisord start", "service nginx start", 'touch "${STATE}/complete"']
        positions = [source.index(item) for item in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertIn('. "$PAYLOAD/resources/jails/versions.sh"', source)
        self.assertIn('upstream(names["onlyoffice-documentserver"].version) == v.onlyoffice', VERSION_SOURCE)
        self.assertIn('"$version_installed" = "$version_value|$version_origin"', version_function("version_packages_check"))
        install = version_function("version_packages_install")
        exact_order = ["version_packages_inventory", "pkg rquery -U -r FreeBSD-ports '%n|%v|%o|%u%d%{%|%}'",
                       '"$version_remote" = "$version_name|$version_value|$version_origin|$version_checksum"',
                       "pkg rquery -U -r FreeBSD-ports '%dn|%dv|%do'",
                       '"$version_remote_dependencies" = "$version_expected_dependencies"',
                       '"$version_installed" = "$version_value|$version_origin"',
                       'set -- "$@" "$version_name-$version_value"',
                       "pkg install -n -y -U -r FreeBSD-ports", "pkg install -y -U -r FreeBSD-ports", "version_packages_check"]
        self.assertEqual([install.index(item) for item in exact_order], sorted(install.index(item) for item in exact_order))
        self.assertIn("freebsd-version -u", version_function("version_environment"))
        self.assertIn('"$(uname -m)" = "$version_architecture"', version_function("version_environment"))
        verify_packages = source.split("verify_packages() {", 1)[1].split("\n}", 1)[0]
        self.assertLess(verify_packages.index("version_packages_check"), verify_packages.index("pkg query"))
        self.assertIn('"${STATE}/packages.installed"', verify_packages)
        self.assertNotRegex(source, r"9\.4\.\*|select_package\(")
        self.assertIn('sysrc supervisord_enable=YES supervisord_user=root nginx_enable=YES', source)
        self.assertNotRegex(source, r"pkg upgrade|pfctl|bastille create|service (mysql|redis|rabbitmq|postgresql)")
        self.assertNotRegex(source, r"--jwt|--secret|NODE_TLS_REJECT_UNAUTHORIZED|ds:converter")
        self.assertNotIn(". /root/cloud-installer/runtime.json", source)
        self.assertIn('stat -f \'%u:%Lp\' "$RUNTIME"', source)
        self.assertIn("set +x", source)
        self.assertIn("exec 3<&0", source)
        self.assertIn("exec </dev/null", source)
        self.assertIn("for process in ds:docservice ds:metrics", source)
        self.assertIn("trap cleanup 0", source)
        self.assertIn('mktemp -d "${STATE}/render.XXXXXX"', source)
        self.assertIn('if ! python3 "$OFFICE" check-securelink', source)
        completed = source.split('if [ -f "${STATE}/complete" ]; then', 1)[1].split('\nfi', 1)[0]
        self.assertIn("verify_packages", completed)
        self.assertIn("office_verify verify <&3", completed)
        self.assertIn("healthcheck", completed)
        self.assertNotRegex(completed, r"pkg (update|install)|touch |install |start|fc-cache|mktemp")
        result = subprocess.run(["sh", "-n", str(ROOT / "resources/jails/onlyoffice.sh")], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)


class SharedVersionShellTests(unittest.TestCase):
    def test_dependency_free_package_requires_successful_empty_remote_query(self):
        # pkg src/rquery.c marks a matched package before print_query(); the
        # dependency-only format in src/query.c emits no rows for an empty list.
        # Empty output with exit 0 is valid; a failed query must still stop us.
        for dependency_status in (0, 1):
            with self.subTest(dependency_status=dependency_status), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                lock, dependencies, calls = (root / name for name in ("packages.lock", "packages.dependencies", "calls"))
                lock.write_text("onlyoffice-documentserver|9.4.0_4|www/onlyoffice-documentserver|2$abc123\n")
                dependencies.write_text("")
                calls.write_text("")
                script = "set -eu\n"
                for name, value in {"VERSION_LOCK": lock, "VERSION_DEPENDENCIES": dependencies, "calls": calls}.items():
                    script += name + "=" + shlex.quote(str(value)) + "\n"
                script += f"dependency_status={dependency_status}\n"
                script += r'''
fail() { printf '%s\n' "$*" >&2; exit 1; }
pkg() {
    [ -z "$(cat)" ] || fail 'Unexpected caller stdin'
    printf '%s\n' "$*" >> "$calls"
    case "$1" in
        query)
            if [ "$2" = -a ]; then cut -d '|' -f1-3 "$VERSION_LOCK"
            else printf '%s\n' '9.4.0_4|www/onlyoffice-documentserver'; fi ;;
        rquery)
            if [ "$5" = '%dn|%dv|%do' ]; then return "$dependency_status"
            else printf '%s\n' 'onlyoffice-documentserver|9.4.0_4|www/onlyoffice-documentserver|2$abc123'; fi ;;
        install) : ;;
        *) fail 'Unexpected mock command' ;;
    esac
}
'''
                script += "\n".join(version_function(name) for name in
                                    ("version_packages_inventory", "version_packages_check", "version_packages_install"))
                script += "\nversion_packages_install\n"
                result = subprocess.run(["sh", "-c", script], capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, dependency_status == 0, result.stderr)
                install_calls = [line for line in calls.read_text().splitlines() if line.startswith("install ")]
                self.assertEqual(install_calls, [
                    "install -n -y -U -r FreeBSD-ports onlyoffice-documentserver-9.4.0_4",
                    "install -y -U -r FreeBSD-ports onlyoffice-documentserver-9.4.0_4"] if dependency_status == 0 else [])

    def test_office_package_resume_bootstraps_only_when_native_pkg_is_absent(self):
        source = (ROOT / "resources/jails/onlyoffice.sh").read_text()
        # Run the production bootstrap/check/update block with the real dispatcher,
        # substituting both absolute executable paths. No native pkg is reachable.
        block = source[source.index("\t# Only the base stub"):source.index("\tpkg rquery -U")]
        scenarios = ("base-only", "installed", "invalid", "not-executable",
                     "dangling", "bootstrap-failed", "bootstrap-missing")
        for scenario in scenarios:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                real, base, calls = (root / name for name in ("real-pkg", "base-pkg", "calls"))
                calls.write_text("")
                native = ("#!/bin/sh\n"
                          f"printf 'native %s\\n' \"$*\" >> {shlex.quote(str(calls))}\n"
                          '[ "$1" = -C ] && [ "$2" = /dev/null ] || exit 90\n'
                          'shift 2\ncase "$*" in\n'
                          f'  -N) exit {1 if scenario == "invalid" else 0} ;;\n'
                          '  "update -r FreeBSD-ports") exit 0 ;;\n'
                          '  *) exit 91 ;;\nesac\n')
                if scenario in ("installed", "invalid", "not-executable"):
                    real.write_text(native)
                    real.chmod(0o600 if scenario == "not-executable" else 0o700)
                elif scenario == "dangling":
                    real.symlink_to(root / "missing")
                base.write_text(
                    "#!/bin/sh\n"
                    f"printf 'base %s\\n' \"$*\" >> {shlex.quote(str(calls))}\n"
                    '[ "$*" = "bootstrap -y -r FreeBSD-ports" ] || exit 92\n'
                    + ("exit 1\n" if scenario == "bootstrap-failed" else
                       "exit 0\n" if scenario == "bootstrap-missing" else
                       f"printf %s {shlex.quote(native)} > {shlex.quote(str(real))}\n"
                       f"chmod 755 {shlex.quote(str(real))}\n"))
                base.chmod(0o700)
                script = ("set -eu\n"
                          "PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin\n"
                          'fail() { printf "%s\\n" "$*" >&2; exit 1; }\n'
                          + "LOGS=" + shlex.quote(tmp) + "\n"
                          + version_function("pkg") + "\n" + block)
                script = script.replace("/usr/local/sbin/pkg", shlex.quote(str(real)))
                script = script.replace("/usr/sbin/pkg", shlex.quote(str(base)))
                result = subprocess.run(["sh", "-c", script], capture_output=True, text=True)
                success = scenario in ("base-only", "installed")
                self.assertEqual(result.returncode == 0, success, result.stderr)
                expected = []
                if scenario in ("base-only", "bootstrap-failed", "bootstrap-missing"):
                    expected.append("base bootstrap -y -r FreeBSD-ports")
                if scenario in ("base-only", "installed", "invalid"):
                    expected.append("native -C /dev/null -N")
                if success:
                    expected.append("native -C /dev/null update -r FreeBSD-ports")
                self.assertEqual(calls.read_text().splitlines(), expected)
                self.assertFalse((root / "packages.done").exists())
                if scenario == "invalid":
                    self.assertIn("not usable", result.stderr)

    def test_pkg_wrapper_clears_environment_and_only_bootstraps_through_base_shim(self):
        # Extract just the dispatcher and substitute BOTH absolute pkg paths with
        # fixture executables. No native package executable can be reached.
        for real_present in (False, True):
            with self.subTest(real_present=real_present), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                real, base = root / "real-pkg", root / "base-pkg"
                for path, kind in ((real, "real"), (base, "base")):
                    path.write_text(f"#!{sys.executable}\nimport json, os, sys\n"
                                    f"print(json.dumps({{'kind': {kind!r}, 'argv': sys.argv[1:], "
                                    "'environment': dict(os.environ), 'stdin': sys.stdin.read()}))\n")
                    path.chmod(0o700 if path == base or real_present else 0o600)
                function = version_function("pkg").replace("/usr/local/sbin/pkg", shlex.quote(str(real)))
                function = function.replace("/usr/sbin/pkg", shlex.quote(str(base)))
                script = "set -eu\nPATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin\n" + function
                arguments = ["update", "-r", "FreeBSD-ports"] if real_present else ["bootstrap", "-y", "-r", "FreeBSD-ports"]
                script += "\npkg " + shlex.join(arguments) + " < /dev/null\n"
                script += 'IFS= read -r remaining\n[ "$remaining" = phase-secret-probe ]\n'
                environment = dict(os.environ, ABI="unselected-target", PACKAGESITE="unselected-repository",
                                   PKG_DBDIR="unselected-db", IGNORE_OSVERSION="yes", SSL_NO_VERIFY_PEER="yes",
                                   CLOUD_TEST_CREDENTIAL="phase-secret-probe")
                result = subprocess.run(["sh", "-c", script], env=environment, input="phase-secret-probe\n",
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                output = json.loads(result.stdout)
                self.assertEqual(output["kind"], "real" if real_present else "base")
                self.assertEqual(output["argv"], (["-C", "/dev/null"] if real_present else []) + arguments)
                self.assertEqual(output["stdin"], "")
                self.assertEqual(output["environment"]["LC_ALL"], "C")
                # Python may itself add LC_CTYPE while coercing the C locale.
                self.assertLessEqual(set(output["environment"]), {"PATH", "LC_ALL", "LC_CTYPE"})
                self.assertNotIn("phase-secret-probe", result.stdout + result.stderr)

    def test_shell_loader_rejects_bad_file_identity_size_or_digest_before_exposing_values(self):
        # The existing Lua tests exercise decoded-object and lock validation.
        # Here only FreeBSD stat/sha256 and flua are replaced, to exercise the
        # shell's file/hash boundary using real private fixture bytes and modes.
        keys = ("nextcloud", "onlyoffice", "connector", "php", "database", "freebsd_release",
                "architecture", "php_package", "plan_sha256", "packages_sha256", "dependencies_sha256", "connector_sha256")
        scenarios = ("valid", "runtime_readonly", "runtime_mode", "runtime_symlink", "runtime_oversize",
                     "lock_owner", "lock_mode", "lock_symlink", "lock_oversize", "lock_hash",
                     "dependencies_mode", "dependencies_symlink", "dependencies_oversize", "dependencies_hash",
                     "connector_mode", "connector_symlink", "connector_oversize", "connector_hash")
        for scenario in scenarios:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                runtime, lock, dependencies, connector = (root / name for name in ("runtime.json", "packages.lock", "packages.dependencies", "connector.json"))
                runtime.write_text(json.dumps(PUBLIC))
                lock.write_text("onlyoffice-documentserver|9.4.0_4|www/onlyoffice-documentserver|2$" + "a" * 103 + "\n")
                dependencies.write_text("")
                connector.write_text(version_runtime.connector_text({"connector": signed_connector()}))
                for path in (runtime, lock, dependencies, connector):
                    path.chmod(0o600)
                if scenario == "runtime_readonly":
                    runtime.chmod(0o400)
                elif "_" in scenario:
                    name, change = scenario.split("_", 1)
                    path = {"runtime": runtime, "lock": lock, "dependencies": dependencies, "connector": connector}[name]
                    if change == "mode":
                        path.chmod(0o640)
                    elif change == "symlink":
                        target = root / "symlink-target"
                        path.rename(target)
                        path.symlink_to(target)
                    elif change == "oversize":
                        path.write_bytes(b"x" * (65537 if name in ("runtime", "connector") else 1048577))
                    elif change == "hash":
                        path.write_text(path.read_text() + "changed\n")
                probe = root / "native-probe.py"
                probe.write_text(
                    "import hashlib, pathlib, sys\n"
                    "path = pathlib.Path(sys.argv[-1])\n"
                    "if sys.argv[1] == 'stat':\n"
                    "    info = path.stat()\n"
                    f"    owner = 1 if {scenario!r} == 'lock_owner' and path.name == 'packages.lock' else 0\n"
                    "    print(f'{owner}:{info.st_mode & 0o777:o}' if sys.argv[3] == '%u:%Lp' else info.st_size)\n"
                    "elif sys.argv[1] == 'sha256':\n"
                    "    print(hashlib.sha256(path.read_bytes()).hexdigest())\n")
                flua = root / "flua-stub"
                flua.write_text(f"#!{sys.executable}\nimport json, sys\n"
                                "with open(sys.argv[2]) as stream: runtime = json.load(stream)\n"
                                f"print(' '.join([runtime['repository']] + [runtime['versions'][key] for key in {keys!r}]))\n")
                flua.chmod(0o700)
                script = "set -eu\nPAYLOAD=" + shlex.quote(str(root)) + "\nRUNTIME=" + shlex.quote(str(runtime)) + "\n"
                script += "fail() { printf '%s\\n' \"$*\" >&2; exit 1; }\n"
                for name in ("stat", "sha256"):
                    script += name + "() { " + shlex.join([sys.executable, str(probe), name]) + ' "$@"; }\n'
                script += version_function("version_private_file") + "\n"
                script += version_function("version_load").replace("/usr/libexec/flua", shlex.quote(str(flua))) + "\n"
                script += "version_load onlyoffice\n"
                script += 'printf \'%s\\n\' "$version_connector" "$version_php_package" "$version_release"\n'
                script += 'IFS= read -r remaining\n[ "$remaining" = phase-secret-probe ]\n'
                result = subprocess.run(["sh", "-c", script], input="phase-secret-probe\n", capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, scenario in ("valid", "runtime_readonly"), result.stderr)
                self.assertEqual(result.stdout, "10.2.1\nphp85\n15.1-RELEASE\n" if result.returncode == 0 else "")
                self.assertNotIn("phase-secret-probe", result.stdout + result.stderr)
                if scenario.endswith("_hash"):
                    self.assertIn("differs from the immutable runtime digest", result.stderr)


def font_bytes(signature=b"\x00\x01\x00\x00", payload=b"testfont"):
    return (signature + struct.pack(">HHHH", 1, 16, 0, 0) + b"name"
            + struct.pack(">III", 0, 28, len(payload)) + payload)


class OfficeFontsTests(unittest.TestCase):
    def fixture(self, root):
        source, state, destination = root / "source", root / "state", root / "fonts/cloud-custom"
        source.mkdir()
        state.mkdir(mode=0o700)
        destination.parent.mkdir()
        (source / "sample.ttf").write_bytes(font_bytes())
        (source / "nested").mkdir()
        (source / "nested/sample.otf").write_bytes(font_bytes(b"OTTO"))
        (source / "collection.ttc").write_bytes(b"ttcf" + struct.pack(">III", 0x10000, 1, 16) + font_bytes())
        return source, state, destination

    def test_supplied_fonts_are_private_input_regular_nonexec_sfnt_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, state, destination = self.fixture(root)
            config = dict(PUBLIC, additional_fonts=True)
            old_umask = os.umask(0o077)
            try:
                office.install_custom_fonts(config, source, state, destination)
            finally:
                os.umask(old_umask)
            for path in destination.rglob("*"):
                self.assertEqual(path.stat().st_mode & 0o777, 0o755 if path.is_dir() else 0o644)
                self.assertFalse(path.is_symlink())
            plan = json.loads((state / "custom-fonts.json").read_text())
            self.assertEqual(len(plan["files"]), 3)
            office.verify_custom_fonts(config, source, state, destination)
            for item in plan["files"]:
                self.assertEqual(item["sha256"], office.sha256_file(destination / item["path"]))
            before = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in root.rglob("*") if path.is_file()}
            office.install_custom_fonts(config, source, state, destination)
            self.assertEqual(before, {path: (path.read_bytes(), path.stat().st_mtime_ns)
                                      for path in root.rglob("*") if path.is_file()})
            (destination / "sample.ttf").chmod(0o755)
            with self.assertRaises(ValueError):
                office.verify_custom_fonts(config, source, state, destination)
            (destination / "sample.ttf").chmod(0o644)
            (destination / "nested").chmod(0o700)
            with self.assertRaises(ValueError):
                office.verify_custom_fonts(config, source, state, destination)
            (destination / "nested").chmod(0o755)
            (source / "sample.ttf").write_bytes(font_bytes(payload=b"changed"))
            with self.assertRaises(ValueError):
                office.install_custom_fonts(config, source, state, destination)

    def test_invalid_font_formats_symlinks_fifos_and_executables_fail_before_copy(self):
        cases = ["text", "wrong-extension", "truncated", "symlink", "directory-symlink", "fifo", "executable"]
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                source, state, destination = self.fixture(Path(tmp))
                bad = source / "bad.ttf"
                if case == "symlink":
                    bad.symlink_to(source / "sample.ttf")
                elif case == "directory-symlink":
                    bad.symlink_to(source / "nested", target_is_directory=True)
                elif case == "fifo":
                    os.mkfifo(bad)
                elif case == "wrong-extension":
                    (source / "bad.woff").write_bytes(font_bytes())
                elif case == "truncated":
                    bad.write_bytes(b"\x00\x01\x00\x00" + b"\x00\x01" + b"\0" * 6)
                elif case == "executable":
                    bad.write_bytes(font_bytes())
                    bad.chmod(0o755)
                else:
                    bad.write_bytes(b"#!/bin/sh\necho unsafe")
                with self.assertRaises((OSError, ValueError)):
                    office.install_custom_fonts(dict(PUBLIC, additional_fonts=True), source, state, destination)
                self.assertFalse(destination.exists())
                self.assertEqual(list(state.iterdir()), [])

    def test_unowned_font_directory_is_refused_but_owned_partial_copy_resumes(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, state, destination = self.fixture(Path(tmp))
            config = dict(PUBLIC, additional_fonts=True)
            destination.mkdir()
            with self.assertRaises(ValueError):
                office.install_custom_fonts(config, source, state, destination)
            destination.rmdir()
            original = shutil.copyfileobj
            counter = []

            def interrupted(input_stream, output, length):
                counter.append(True)
                if len(counter) == 2:
                    output.write(b"partial")
                    raise OSError("simulated interruption")
                original(input_stream, output, length)

            with patch.object(office.shutil, "copyfileobj", interrupted), self.assertRaises(OSError):
                office.install_custom_fonts(config, source, state, destination)
            self.assertEqual(len([path for path in destination.rglob("*") if path.is_file()]), 1)
            self.assertEqual(list(destination.rglob(".cloud-font-*")), [])
            office.install_custom_fonts(config, source, state, destination)
            self.assertEqual(len([path for path in destination.rglob("*") if path.is_file()]), 3)
            (destination / "foreign.ttf").write_bytes(font_bytes())
            with self.assertRaises(ValueError):
                office.install_custom_fonts(config, source, state, destination)

    def test_inventory_records_packages_fonts_and_generated_outputs_and_detects_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, state, destination = self.fixture(root)
            office.install_custom_fonts(dict(PUBLIC, additional_fonts=True), source, state, destination)
            families = ",".join(office.REQUIRED_FONT_FAMILIES)
            (state / "fontconfig.tsv").write_text(f"{destination}/sample.ttf\t{families}\tRegular\n")
            (state / "packages.installed").write_text("noto-basic|2.0_4|x11-fonts/noto-basic\n")
            (state / "fonts-unavailable").write_text("optional-unavailable-fixture\n")
            generated = (root / "AllFonts.js", root / "font_selection.bin")
            generated[0].write_text(json.dumps(office.REQUIRED_FONT_FAMILIES))
            generated[1].write_bytes(b"generated-fixture")
            inventory = office.font_inventory(PUBLIC, state, roots=(destination,), generated=generated)
            self.assertEqual(inventory["unavailable_optional"], ["optional-unavailable-fixture"])
            self.assertEqual(inventory["packages"][0]["version"], "2.0_4")
            self.assertEqual(len(inventory["fonts"]), 3)
            self.assertTrue(all(len(item["sha256"]) == 64 for item in inventory["fonts"]))
            office.remember(state / "fonts.json", inventory)
            office.verify_font_inventory(state, roots=(destination,))
            generated[0].write_text("missing required families")
            with self.assertRaises(ValueError):
                office.verify_font_inventory(state, roots=(destination,))
            with self.assertRaises(ValueError):
                office.font_inventory(PUBLIC, state, roots=(destination,), generated=generated)

    def test_font_policy_is_broad_and_microsoft_dependency_is_consent_gated(self):
        rows = [line.split() for line in (ROOT / "resources/packages/fonts.txt").read_text().splitlines()
                if line and not line.startswith("#")]
        packages = {name for kind, name in rows}
        self.assertEqual(len(rows), len(packages))
        self.assertTrue({"google-fonts", "noto-extra", "noto-jp", "noto-kr", "noto-hk", "noto-sc", "noto-tc",
                         "noto-emoji", "stixfonts", "libertinus", "Andika", "Charis"} <= packages)
        self.assertNotIn("webfonts", packages)
        self.assertTrue({"croscorefonts", "crosextrafonts-caladea", "crosextrafonts-carlito", "noto-basic"}
                        <= {name for kind, name in rows if kind == "required"})
        source = (ROOT / "resources/jails/onlyoffice.sh").read_text()
        self.assertLess(source.index("grep -qx webfonts"), source.index("version_packages_install"))
        self.assertIn('[ "$accept_microsoft_fonts" != true ]', source)
        self.assertIn("pkg rquery -U -r FreeBSD-ports '%dn'", source)
        self.assertIn('version_private_file "$PAYLOAD/fonts-unavailable" 600 1048576', source)
        self.assertIn('input=$PAYLOAD/fonts-unavailable', source)
        self.assertIn('install -S -o root -g wheel -m 600 "$input" "${STATE}/$name"', source)
        self.assertIn('"${STATE}/fonts-unavailable"', source)
        self.assertNotIn('required-missing', source)


if __name__ == "__main__":
    unittest.main()
