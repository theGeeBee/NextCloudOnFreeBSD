"""Shared offline Nextcloud worker fixtures; no collected test cases or provisioning."""

import base64
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "resources/templates/nextcloud"
WORKER_PATH = ROOT / "resources/jails/nextcloud.sh"
WORKER = WORKER_PATH.read_text()
HELPER = ROOT / "resources/jails/nextcloud-bootstrap.php"
PHP_SOURCE = HELPER.read_text()
VERSIONS_PATH = ROOT / "resources/jails/versions.sh"
VERSIONS_SOURCE = VERSIONS_PATH.read_text()
PHP = shutil.which("php")
if PHP and subprocess.run([PHP, "-r", "exit(PHP_VERSION_ID >= 80100 ? 0 : 1);"], capture_output=True).returncode:
    PHP = None


def phase(name):
    return re.search(r"(?ms)^" + name + r"\(\) \{\n.*?^\}(?=\n\n|\Z)", WORKER)[0]


PREPARE = phase("prepare")
DATABASE = phase("database")
INSTALL = phase("install_nextcloud")
PUBLISH = phase("publish")
FINISH = phase("finish")


def connector_record():
    # Shape-valid synthetic metadata, never cryptographic acceptance evidence.
    return {
        "version": "10.2.1", "phpVersionSpec": ">=8.2.0 <8.6.0",
        "platformVersionSpec": ">=33.0.0 <36.0.0", "isNightly": False,
        "signatureDigest": "sha512", "download": "https://example.test/onlyoffice-10.2.1.tar.gz",
        "signature": base64.b64encode(b"offline archive signature").decode(),
        "certificate": "-----BEGIN CERTIFICATE-----\n" + base64.b64encode(b"offline certificate").decode() + "\n-----END CERTIFICATE-----\n",
    }


def connector_record_text(record=None):
    return json.dumps(connector_record() if record is None else record, sort_keys=True, separators=(",", ":")) + "\n"


def runtime(mode="provided", port=None, backend="onlyoffice"):
    result = {
        "public_hostname": "cloud.example.com",
        "public_url": "https://cloud.example.com" + (f":{port}" if port else "") + "/",
        "storage_url": "http://10.77.0.2/" if mode == "external" else "https://cloud.example.com/",
        "nextcloud_ip": "10.77.0.2",
        "onlyoffice_ip": "10.77.0.6",
        "proxy_networks": ["192.0.2.0/24", "198.51.100.7/32"] if mode == "external" else [],
        "admin_username": "cloudadmin",
        "db_name": "nextcloud",
        "timezone": "Europe/London",
        "admin_email": "admin@example.com",
        "php_memory_mb": 512,
        "php_children": 8,
        "db_buffer_mb": 512,
        "redis_memory_mb": 128,
        "upload_max_mb": 10240,
        "tls_mode": mode,
        "acme_email": "admin@example.com" if mode == "acme" else "",
        "repository": "latest",
        "versions": {
            "nextcloud": "35.0.0", "onlyoffice": "9.4.0", "connector": "10.2.1", "php": "8.5.1", "database": "12.3.1",
            "freebsd_release": "15.1-RELEASE", "architecture": "amd64", "php_package": "php85",
            "plan_sha256": "a" * 64, "packages_sha256": "b" * 64,
            "dependencies_sha256": "c" * 64,
            "connector_sha256": hashlib.sha256(connector_record_text().encode()).hexdigest(),
        },
    }
    if backend == "none":
        del result["onlyoffice_ip"], result["storage_url"]
        for key in ("onlyoffice", "connector", "connector_sha256"):
            del result["versions"][key]
        result["versions"]["office_backend"] = "none"
    elif backend != "onlyoffice":
        raise ValueError("Unsupported worker fixture backend")
    return result


def run_php(expression, payload=None, prelude=""):
    code = (
        prelude + "namespace { define('CLOUD_NEXTCLOUD_LIBRARY', true); require " + json.dumps(str(HELPER))
        + "; $p=json_decode(stream_get_contents(STDIN), true, 32, JSON_THROW_ON_ERROR); "
        + "try { $c=cloudValidate($p['runtime']); " + expression
        + " } catch (Throwable $e) { fwrite(STDERR, cloudDiagnostic($e)); exit(1); } }"
    )
    return subprocess.run([PHP, "-d", "display_errors=0", "-d", "log_errors=0", "-r", code], input=json.dumps(payload or {"runtime": runtime()}), text=True, capture_output=True)


def run_version_lua(document, packages, dependencies, group, directory):
    """Run the real validator, replacing only unavailable FreeBSD UCL decoding."""
    def literal(value):
        if isinstance(value, dict):
            return '{' + ','.join('[' + literal(k) + ']=' + literal(v) for k, v in value.items()) + '}'
        if isinstance(value, list):
            return '{' + ','.join(literal(v) for v in value) + '}'
        return 'nil' if value is None else json.dumps(value)
    directory = Path(directory)
    (directory / 'lock').write_text(packages)
    (directory / 'edges').write_text(dependencies)
    code = 'local document=' + literal(document) + '\n'
    code += 'package.preload["ucl"]=function() return {parser=function() return {parse_file=function() return true end, get_object=function() return document end} end} end\n'
    code += 'arg=' + literal(['runtime.json',str(directory/'lock'),str(directory/'edges'),group]) + '\n'
    code += VERSIONS_SOURCE.split("<<'LUA'\n",1)[1].split('\nLUA\n',1)[0]
    return subprocess.run([shutil.which('lua'), '-'], input=code, text=True, capture_output=True)
