"""Synthetic offline catalogs; never evidence of real repository availability."""

import json
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest.mock import patch

from installer.compatibility import package_roots
from installer.resolution import resolve, validate_plan
from installer.versions import constraints, load_policy, target


def historic_policy():
    """2873217 native policy projection, with unchanged captured hash evidence.

    Disjoint profiles were excluded just as policy_hash excludes them. Keep this
    fixture independent of current range/evidence edits, not a reverse mutation
    of the live policy. Only the unchanged external font catalog is expanded.
    """
    from installer.paths import RESOURCES
    from installer.versions import validate_policy
    policy = json.loads((Path(__file__).parent / "fixtures/version-policy-2873217-native.json").read_text())
    fonts = {"required": [], "optional": []}
    for line in (RESOURCES / "packages/fonts.txt").read_text().splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            kind, name = line.split()
            fonts[kind].append(name)
    policy["fonts"] = fonts
    return validate_policy(policy)


@contextmanager
def historical_maintenance_policy():
    """Run old-artifact fixtures under their captured native policy only.

    Explicit loader sites include local imports via versions and modules which
    retain loader aliases. No source identity, admission or safety check is
    replaced. Current-policy resolver fixtures remain unchanged outside this
    context, and each load returns an independent validated policy.
    """
    with ExitStack() as stack:
        for loader in (
            "installer.versions.load_policy",
            "installer.resolution.load_policy",
            "installer.compatibility.load_policy",
            "installer.maintenance_preflight.load_policy",
            "installer.maintenance_generations.load_policy",
            "installer.maintenance_validation.load_policy",
            "version_fixtures.load_policy",
        ):
            stack.enter_context(patch(loader, side_effect=historic_policy))
        yield


def discovery_metadata(config, *, nextcloud="35.0.0"):
    """Supply every policy root and a small, exact transitive dependency graph."""
    policy = load_policy()
    effective = constraints(config, policy)
    selected_target = target(policy, effective["freebsd_release"], effective["architecture"])
    profile = policy["profiles"][0]
    packages = {}

    def package(name, version="1.0", origin=None):
        packages[name] = {"name": name, "version": version, "origin": origin or "devel/" + name,
                          "abi": selected_target["abi"], "checksum": "2$" + "y" * 103, "dependencies": {}}

    for roots in package_roots(config, policy).values():
        for root in roots:
            if "/" in root:
                package("py311-certbot" if root == "security/py-certbot" else root.split("/")[1], origin=root)
            else:
                package(root)
    for name in policy["fonts"]["optional"]:
        package(name, origin="x11-fonts/" + name)
    versions = {"manager": "1.4.4_1", "php": "8.5.11", "database": "12.3.3",
                "database_client": "12.3.3", "web": "2.4.66", "cache": "8.2.1",
                "onlyoffice": "9.4.0_4"}
    for role, rule in profile["roles"].items():
        package(rule["package"], versions[role], rule["origin"])
    for suffix, version in (("pecl-APCu", "5.1.28"), ("pecl-redis", "6.3.0"), ("pecl-imagick", "3.8.1")):
        package("php" + profile["php_suffix"] + "-" + suffix, version)
    for name, version, origin in (("fixture-library", "1.2.3", "devel/fixture-library"),
                                  ("nginx", "1.28.0_1,3", "www/nginx"),
                                  ("py311-supervisor", "4.2.5", "sysutils/py-supervisor"),
                                  ("webfonts", "0.30_14", "x11-fonts/webfonts")):
        package(name, version, origin)

    def depends(owner, *names):
        packages[owner]["dependencies"] = {
            name: {key: packages[name][key] for key in ("version", "origin")} for name in names}

    roles = {role: rule["package"] for role, rule in profile["roles"].items()}
    depends(roles["manager"], "fixture-library")
    depends(roles["php"], "fixture-library")
    depends(roles["database"], roles["database_client"])
    depends(roles["onlyoffice"], "nginx", "py311-supervisor", "webfonts")
    for extension in profile["php_extensions"]:
        depends(extension.replace("{suffix}", profile["php_suffix"]), roles["php"])
    connector = {"version": "10.2.1", "phpVersionSpec": ">=8.2.0 <8.6.0",
                 "platformVersionSpec": ">=33.0.0 <36.0.0", "isNightly": False,
                 "signatureDigest": "sha512", "download": "https://example.test/onlyoffice-10.2.1.tar.gz",
                 "signature": "synthetic-test-signature", "certificate": "synthetic-test-certificate"}
    return {"schema_version": 1, "target": selected_target, "repository": config.repository,
            "nextcloud": [nextcloud], "onlyoffice": ["9.4.0"],
            "connectors": {nextcloud: [connector]}, "packages": packages,
            "sources": ["https://example.test/offline-catalog"]}


def resolved_plan(config, *, nextcloud="35.0.0"):
    """Exercise real resolution and retained-plan validation, without discovery."""
    return validate_plan(config, resolve(config, discovery_metadata(config, nextcloud=nextcloud)))


# Captured from c905fb3:installer/config.py, before version fields were added.
# The original Config.to_json() bytes and digest are independent of current code.
LEGACY_CONFIG_JSON = '''{
  "schema_version": 2,
  "instance": "cloud",
  "pool": "zroot",
  "public_hostname": "cloud.example.test",
  "nextcloud_hostname": "",
  "onlyoffice_hostname": "",
  "admin_username": "admin",
  "admin_email": "admin@example.test",
  "timezone": "UTC",
  "repository": "latest",
  "external_interface": "igb0",
  "ingress_address": "192.0.2.10",
  "dns_address": "",
  "private_network": "10.77.0.0/29",
  "nextcloud_bridge": "bridge240",
  "onlyoffice_bridge": "bridge241",
  "dns_server": "192.0.2.53",
  "management_network": "198.51.100.0/24",
  "management_port": 22,
  "http_port": 80,
  "https_port": 443,
  "public_https_port": 443,
  "tls_mode": "acme",
  "proxy_networks": "",
  "acme_email": "admin@example.test",
  "certificate_file": "",
  "private_key_file": "",
  "ca_file": "",
  "jail_ssh": false,
  "ssh_username": "cloudop",
  "ssh_key_file": "",
  "ssh_nextcloud_port": 2201,
  "ssh_onlyoffice_port": 2202,
  "ssh_shell": "sh",
  "ssh_admin": false,
  "font_profile": "comprehensive",
  "accept_microsoft_fonts": false,
  "additional_fonts_dir": "",
  "data_quota_gib": 100,
  "database_quota_gib": 20,
  "temporary_quota_gib": 10,
  "office_quota_gib": 10,
  "logs_quota_gib": 5,
  "system_quota_gib": 32,
  "host_reserved_mb": 2048,
  "office_memory_mb": 3072,
  "php_budget_mb": 1536,
  "php_memory_mb": 512,
  "db_buffer_mb": 768,
  "redis_memory_mb": 128,
  "upload_max_mb": 1024
}
'''
LEGACY_CONFIG_SHA256 = "fcbd66c2671e1c56545559810d7c872a706ff1a4bbc94eb5b99aeb33b4621cc1"
