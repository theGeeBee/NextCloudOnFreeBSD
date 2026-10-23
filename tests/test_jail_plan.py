"""Offline tests for pure planning, policy rendering and guarded host operations."""

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from installer.config import Config, PLUGIN_CHOICES, QUOTA_FIELDS, datasets, deployment_plan, validate_plugin_selection
from installer.host import Runner, require_host, state_directory
from installer.network import pf_rules, storage_guard
from installer.versions import FIELDS, defaults


def example_config():
    return Config(public_hostname="cloud.example.test", admin_email="admin@example.test",
                  acme_email="admin@example.test", external_interface="igb0",
                  ingress_address="192.0.2.10", dns_server="192.0.2.53",
                  management_network="198.51.100.0/24")


class JailPlanTests(unittest.TestCase):
    def test_additional_apps_round_trip_union_and_legacy_digest(self):
        legacy = example_config().to_json()
        self.assertNotIn("additional_nextcloud_apps", json.loads(legacy))
        self.assertEqual(replace(example_config(), additional_nextcloud_apps="").to_json(), legacy)
        c = replace(example_config(), nextcloud_apps="calendar,notes",
                    additional_nextcloud_apps="bookmarks,mail").validate()
        self.assertEqual(c.selected_nextcloud_apps, ("bookmarks", "calendar", "mail", "notes"))
        self.assertEqual(Config.from_json(c.to_json()), c)
        self.assertIn("bookmarks, calendar, mail, notes", deployment_plan(c))
        self.assertIn("465", pf_rules([c]))
        ordinary = replace(example_config(), additional_nextcloud_apps="bookmarks").validate()
        self.assertEqual(ordinary.memory_budget_mb, example_config().memory_budget_mb)
        self.assertEqual(pf_rules([ordinary]), pf_rules([example_config()]))
        scanner = replace(example_config(), additional_nextcloud_apps="files_antivirus").validate()
        self.assertTrue(scanner.antivirus)
        self.assertGreater(scanner.memory_budget_mb, example_config().memory_budget_mb)

    def test_additional_apps_reject_unsafe_noncanonical_and_overlapping_ids(self):
        for value in (None, False, [], 1, "none", "onlyoffice", "bookmarks,onlyoffice",
                      "notes,bookmarks", "bookmarks,bookmarks", "bookmarks,", ",bookmarks",
                      "Bookmarks", "bookmarks\n", "bookmarks\x00", "bookmarks\x7f", " bookmarks",
                      "https://example.test/app", "../bookmarks", "--force", "bookmarks --force",
                      "bookmarks;id", "$(id)", "a" * 65):
            with self.subTest(value=value), self.assertRaises(ValueError):
                replace(example_config(), additional_nextcloud_apps=value).validate()
        with self.assertRaisesRegex(ValueError, "overlaps"):
            replace(example_config(), nextcloud_apps="notes", additional_nextcloud_apps="notes").validate()
        with self.assertRaises(ValueError):
            replace(example_config(), nextcloud_apps="bookmarks").validate()

    def test_example_plan_runs_through_real_entry_without_host_operations(self):
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run(["sh", str(root / "install.sh"), "--plan", str(root / "examples/config.json")],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("cloudnc", result.stdout)
        self.assertIn("cloudoo", result.stdout)
        self.assertIn("Email delivery is disabled", result.stdout)

    def test_config_round_trip_and_schema(self):
        c = example_config().validate()
        self.assertEqual(Config.from_json(c.to_json()), c)
        values = json.loads(c.to_json())
        values["admin_password"] = "must-not-be-in-config"
        with self.assertRaisesRegex(ValueError, "Unknown configuration"):
            Config.from_json(json.dumps(values))
        with self.assertRaises(ValueError):
            Config.from_json("[]")

    def test_static_version_plan_uses_policy_defaults_without_freezing_legacy_configuration(self):
        c = example_config()
        before = c.to_json()
        with patch("installer.discovery.discover") as discover, \
                patch("installer.discovery.probe_packages") as probe:
            text = deployment_plan(c)
        expected = defaults()
        self.assertIn(expected["freebsd_release"], text)
        self.assertIn(expected["architecture"], text)
        self.assertIn("Nextcloud >= " + expected["nextcloud_min"], text)
        self.assertIn("ONLYOFFICE >= " + expected["onlyoffice_min"], text)
        self.assertIn("Static plan only", text)
        self.assertEqual(c.to_json(), before)
        self.assertTrue(all(getattr(c, field) == "" for field in FIELDS))
        discover.assert_not_called()
        probe.assert_not_called()

    def test_empty_plugin_selection_preserves_legacy_schema2_bytes_and_digest(self):
        original = example_config().to_json()
        # Golden digest captured before onlyoffice_plugins was added to Config.
        self.assertEqual(hashlib.sha256(original.encode()).hexdigest(),
                         "fcbd66c2671e1c56545559810d7c872a706ff1a4bbc94eb5b99aeb33b4621cc1")
        self.assertNotIn("onlyoffice_plugins", json.loads(original))
        loaded = Config.from_json(original)
        self.assertEqual(loaded.onlyoffice_plugins, "")
        self.assertEqual(loaded.selected_onlyoffice_plugins, ())
        self.assertEqual(loaded.to_json(), original)
        self.assertTrue(loaded._legacy_target)
        explicit_empty = json.loads(original)
        explicit_empty["onlyoffice_plugins"] = ""
        self.assertEqual(Config.from_json(json.dumps(explicit_empty)).to_json(), original)

    def test_plugin_selection_is_strict_and_round_trips(self):
        all_plugins = "highlightcode,mendeley,ocr,photoeditor,speech,thesaurus,translator,wordpress,youtube,zotero"
        self.assertEqual(tuple(slug for slug, _, _ in PLUGIN_CHOICES), tuple(all_plugins.split(",")))
        for selected in ("", "ocr", "highlightcode,youtube", all_plugins):
            with self.subTest(selected=selected):
                c = replace(example_config(), onlyoffice_plugins=selected).validate()
                loaded = Config.from_json(c.to_json())
                self.assertEqual(loaded.onlyoffice_plugins, selected)
                self.assertEqual(loaded.selected_onlyoffice_plugins, tuple(selected.split(",")) if selected else ())
        for selected in (None, False, [], 1, "none", "all", "easybib", "macros", "ai", "speechrecognition",
                         "unknown", "ocr,ocr", "youtube,ocr", "ocr,", ",ocr", " ocr", "ocr, youtube", "OCR", "ocr\n"):
            with self.subTest(selected=selected):
                with self.assertRaises(ValueError):
                    validate_plugin_selection(selected)
                with self.assertRaises(ValueError):
                    replace(example_config(), onlyoffice_plugins=selected).validate()
                values = json.loads(example_config().to_json())
                values["onlyoffice_plugins"] = selected
                with self.assertRaises(ValueError):
                    Config.from_json(json.dumps(values))

    def test_plugin_plan_is_static_and_describes_requests_and_external_services(self):
        c = replace(example_config(), onlyoffice_plugins="ocr,youtube")
        before = c.to_json()
        with patch("installer.discovery.discover") as discover, patch("subprocess.run") as run:
            plan = deployment_plan(c)
        discover.assert_not_called()
        run.assert_not_called()
        self.assertEqual(c.to_json(), before)
        self.assertIn("ONLYOFFICE plugins requested for installation: ocr, youtube; no autostart", plan)
        self.assertIn("providers may receive selected content when invoked", plan)
        self.assertIn("accounts/API keys are configured separately", plan)
        self.assertIn("Installation does not establish service functionality", plan)
        self.assertIn("Macros is built-in", plan)
        self.assertIn("ONLYOFFICE plugins requested for installation: none", deployment_plan(example_config()))

    def test_explicit_minima_and_pins_round_trip_without_claiming_availability(self):
        c = replace(example_config(), freebsd_release=defaults()["freebsd_release"], architecture="amd64",
                    nextcloud_min="35", onlyoffice_min="9.4", nextcloud_exact="35.0.1",
                    onlyoffice_exact="9.4.0_4").validate()
        self.assertEqual(Config.from_json(c.to_json()), c)
        self.assertIn("Nextcloud >= 35.0.0 (exact: 35.0.1)", deployment_plan(c))
        self.assertIn("ONLYOFFICE >= 9.4.0 (exact: 9.4.0_4)", deployment_plan(c))
        for field, value in (("nextcloud_min", "35rc1"), ("onlyoffice_min", "9.4_1"),
                             ("nextcloud_exact", "35.0"), ("nextcloud_exact", "34.0.0"),
                             ("onlyoffice_exact", "9.4.0-rc1"), ("nextcloud_min", 35),
                             ("architecture", "aarch64"), ("freebsd_release", "15.0-RELEASE")):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                replace(c, **{field: value}).validate()

    def test_invalid_configuration_is_rejected(self):
        for name, value in (("instance", "../../root"), ("instance", "cloud;touch /tmp/test"),
                            ("instance", "my-cloud"), ("instance", "my_cloud"),
                            ("pool", "tank/old"), ("public_hostname", "https://cloud.example.test"),
                            ("public_hostname", "192.0.2.10"),
                            ("admin_email", "a..b@example.test"), ("admin_email", ".admin@example.test"),
                            ("admin_email", "admin@-invalid.example.test"), ("admin_email", "admin@example..test"),
                            ("admin_email", "admin@192.0.2.10"), ("redis_memory_mb", 32769),
                            ("public_hostname", "cloud.example.test\nInclude secret"),
                            ("external_interface", "igb0;false"), ("private_network", "8.8.8.0/29"),
                            ("private_network", "10.77.0.1/29"), ("private_network", "10.77.0.0/30"),
                            ("dns_server", "127.0.0.1"), ("dns_server", "10.77.0.3"),
                            ("management_port", 443), ("php_budget_mb", 512),
                            ("php_memory_mb", 128), ("system_quota_gib", 2),
                            ("tls_mode", "selfsigned"), ("tls_mode", "provided"),
                            ("nextcloud_bridge", "bridge241"), ("data_quota_gib", "100"),
                            ("data_quota_gib", True), ("repository", "arbitrary")):
            with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                replace(example_config(), **{name: value}).validate()

    def test_separate_network_stacks_and_routed_segments(self):
        c = example_config()
        self.assertEqual(c.nextcloud_ip, "10.77.0.2")
        self.assertEqual(c.onlyoffice_ip, "10.77.0.6")
        self.assertEqual(c.nextcloud_network, "10.77.0.0/30")
        self.assertEqual(c.onlyoffice_network, "10.77.0.4/30")
        self.assertNotEqual(c.nextcloud_bridge, c.onlyoffice_bridge)
        c = replace(c, instance="abcdefgh").validate()
        self.assertLessEqual(len("e0a_" + c.onlyoffice_jail), 15)
        with self.assertRaises(ValueError):
            replace(c, instance="abcdefghi").validate()

    def test_storage_properties_and_mounts(self):
        c = example_config()
        storage = datasets(c)
        self.assertEqual(sum(item.quota_gib for item in storage[1:]) + c.system_quota_gib, c.total_quota_gib)
        self.assertEqual(storage[0].quota_gib, c.total_quota_gib - c.system_quota_gib)
        self.assertEqual(c.dataset_root, "zroot/cloud-installer/instances/cloud")
        self.assertEqual(c.bastille_dataset, "zroot/cloud-installer/bastille")
        self.assertNotIn(c.bastille_dataset, {item.name for item in storage})
        for item in storage:
            self.assertTrue(item.name == c.dataset_root or item.name.startswith(c.dataset_root + "/"))
            self.assertEqual(item.properties["sync"], "standard")
            self.assertEqual(item.properties["compression"], "lz4")
            self.assertEqual(item.properties["primarycache"], "all")
        by_target = {item.target: item for item in storage if item.jail == c.nextcloud_jail}
        self.assertEqual(by_target["/var/db/mysql"].recordsize, "16K")
        self.assertEqual(by_target["/var/nc-data"].recordsize, "128K")
        self.assertFalse(by_target["/var/nc-data"].executable)
        self.assertIn("/var/log/mysql", by_target)
        self.assertIn("/var/nc-tmp", by_target)

    def test_legacy_storage_preserves_bytes_and_requires_positive_quotas(self):
        legacy = example_config().to_json()
        self.assertNotIn("storage_policy", json.loads(legacy))
        self.assertEqual(Config.from_json(legacy).to_json(), legacy)
        self.assertEqual(Config().data_quota_gib, 100)
        for quota in (1, 100, 1_000_000):
            with self.subTest(quota=quota):
                c = replace(example_config(), data_quota_gib=quota)
                self.assertEqual(Config.from_json(c.to_json()), c.validate())
        for name in ("data_quota_gib", "database_quota_gib", "temporary_quota_gib", "office_quota_gib", "logs_quota_gib"):
            for quota in (-1, True, "0", 1_000_001, 0):
                with self.subTest(name=name, quota=quota), self.assertRaises(ValueError):
                    replace(example_config(), **{name: quota}).validate()

    def test_optional_storage_has_no_parent_or_app_ceiling_with_operator_caps(self):
        for cap in (0, 200):
            c = replace(example_config(), storage_policy="optional",
                        **{name: 0 for name in QUOTA_FIELDS})
            c.data_quota_gib = cap
            before = c.to_json()
            storage = datasets(c)
            self.assertEqual(storage[0].quota_gib, 0)
            self.assertNotIn("quota", storage[0].properties)
            app = next(item for item in storage if item.name.endswith("/nc-app"))
            self.assertEqual(app.quota_gib, 0)
            data = next(item for item in storage if item.name.endswith("/nc-data"))
            self.assertEqual(data.quota_gib, cap)
            self.assertEqual(data.properties.get("quota"), "200G" if cap else None)
            self.assertTrue(all(item.quota_gib == 0 for item in storage if item != data))
            self.assertTrue(all("quota" not in item.properties for item in storage if item != data))
            self.assertTrue(all("reservation" not in item.properties and "refreservation" not in item.properties
                                for item in storage))
            plan = deployment_plan(c)
            self.assertIn("not a full growth bound", plan)
            self.assertIn("can exhaust storage", plan)
            self.assertIn("no local quota", plan)
            self.assertIn("operator caps: data 200 GiB" if cap else "no installer quotas", plan)
            self.assertNotIn("planned capacity", plan)
            self.assertNotIn("Finite service planning allowance", plan)
            self.assertEqual(c.to_json(), before)
            self.assertEqual(Config.from_json(before).to_json(), before)

    def test_optional_storage_caps_are_strict_and_do_not_impose_font_capacity_minima(self):
        c = replace(example_config(), storage_policy="optional",
                    **{name: 0 for name in QUOTA_FIELDS})
        self.assertEqual(c.validate_provisioning(), c)
        for name in QUOTA_FIELDS:
            for cap in (0, 2, 3, 1_000_000):
                with self.subTest(name=name, cap=cap):
                    # Positive tmp caps must still leave upload headroom.
                    configured = replace(c, **{name: cap}).validate_provisioning()
                    self.assertEqual(getattr(Config.from_json(configured.to_json()), name), cap)
            for cap in (-1, True, "0", None, 1_000_001):
                with self.subTest(name=name, cap=cap), self.assertRaises(ValueError):
                    replace(c, **{name: cap}).validate()
        for policy in ("all", "none", "Optional", True, None, 0):
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                replace(c, storage_policy=policy).validate()
        with self.assertRaisesRegex(ValueError, "two jails"):
            replace(c, system_quota_gib=1).validate()
        with self.assertRaisesRegex(ValueError, "at least 3 PHP workers"):
            replace(c, php_budget_mb=1024).validate_provisioning()

    def test_optional_upload_limit_keeps_range_and_positive_tmp_headroom_checks(self):
        c = replace(example_config(), storage_policy="optional",
                    **{name: 0 for name in QUOTA_FIELDS})
        self.assertEqual(replace(c, upload_max_mb=16384).validate().upload_max_mb, 16384)
        self.assertEqual(replace(c, temporary_quota_gib=1, upload_max_mb=512).validate().upload_max_mb, 512)
        for temporary, upload in ((0, 31), (0, 16385), (1, 513), (2, 1025)):
            with self.subTest(temporary=temporary, upload=upload), self.assertRaisesRegex(ValueError, "Upload chunk"):
                replace(c, temporary_quota_gib=temporary, upload_max_mb=upload).validate()

    def test_optional_service_caps_only_apply_to_the_selected_children(self):
        c = replace(example_config(), storage_policy="optional", data_quota_gib=0,
                    database_quota_gib=7, temporary_quota_gib=0, office_quota_gib=9,
                    logs_quota_gib=1, system_quota_gib=2)
        expected = {"nc-database": 7, "office-runtime": 9, "office-data": 9,
                    "nc-db-logs": 1, "nc-logs": 1, "office-logs": 1}
        for item in datasets(c):
            cap = expected.get(item.name.rsplit("/", 1)[-1], 0)
            self.assertEqual(item.quota_gib, cap)
            self.assertEqual(item.properties.get("quota"), f"{cap}G" if cap else None)
        text = deployment_plan(c)
        self.assertIn("operator caps:", text)
        self.assertIn("not a full growth bound", text)
        self.assertIn("No space reservations", text)
        self.assertIn("Pool/ancestor limits", text)

    def test_legacy_storage_loading_never_reinterprets_saved_limits(self):
        for data in (100, 75):
            c = replace(example_config(), data_quota_gib=data)
            text = c.to_json()
            before = datasets(c)
            loaded = Config.from_json(text)
            self.assertEqual(loaded.storage_policy, "")
            self.assertEqual(loaded.to_json(), text)
            self.assertEqual(datasets(loaded), before)
            self.assertEqual(before[1].quota_gib, 4)
            self.assertEqual(before[0].quota_gib, c.total_quota_gib - c.system_quota_gib)

    def test_only_explicit_optional_policy_defaults_omitted_quota_fields_to_zero(self):
        original = json.loads(example_config().to_json())
        for policy in (None, "", "optional"):
            for selected in ({}, {"data_quota_gib": 75}, {"database_quota_gib": 7, "system_quota_gib": 2}):
                if policy != "optional" and selected.get("system_quota_gib") == 2:
                    continue  # Legacy jail-root floor is deliberately unchanged.
                with self.subTest(policy=policy, selected=selected):
                    value = {key: item for key, item in original.items() if key not in QUOTA_FIELDS}
                    if policy is not None:
                        value["storage_policy"] = policy
                    value.update(selected)
                    loaded = Config.from_json(json.dumps(value))
                    for name in QUOTA_FIELDS:
                        default = 0 if policy == "optional" else getattr(Config(), name)
                        self.assertEqual(getattr(loaded, name), selected.get(name, default))
                    self.assertEqual(Config.from_json(loaded.to_json()).to_json(), loaded.to_json())

    def test_production_memory_ceiling_is_budgeted(self):
        c = example_config()
        self.assertEqual(c.php_children, 3)
        self.assertLessEqual(c.php_children * c.php_memory_mb, c.php_budget_mb)
        self.assertGreater(c.memory_budget_mb, c.php_budget_mb + c.db_buffer_mb)
        self.assertEqual(c.php_callback_children, 1)
        self.assertIn("2 web + 1 office callback", deployment_plan(c))

    def test_legacy_two_worker_state_is_readable_but_new_provisioning_refused(self):
        from installer.host import preflight
        c = replace(example_config(), php_budget_mb=1024)
        original = c.to_json()
        loaded = Config.from_json(original)
        self.assertEqual(loaded.to_json(), original)
        self.assertEqual(loaded.php_children, 2)
        self.assertTrue(datasets(loaded))  # Lifecycle ownership remains inspectable.
        runner = Mock()
        with self.assertRaisesRegex(ValueError, "at least 3 PHP workers"):
            deployment_plan(loaded)
        with self.assertRaisesRegex(ValueError, "at least 3 PHP workers"):
            preflight(loaded, {}, runner)
        self.assertEqual(runner.mock_calls, [])

    def test_pf_policy_has_only_intended_inbound_paths(self):
        text = pf_rules(example_config())
        self.assertIn("block log all", text)
        self.assertIn("nat on $ext_if", text)
        self.assertIn("port 80 -> 10.77.0.2 port 80", text)
        self.assertIn("port 443 -> 10.77.0.2 port 443", text)
        self.assertIn("from 10.77.0.2 to 10.77.0.6 port 8081", text)
        self.assertIn("from 10.77.0.6 to 10.77.0.2 port 443", text)
        self.assertIn("port 22 flags any keep state", text)
        self.assertNotRegex(text, r"(?m)^pass[^\n]*port (8000|8125|8126|3306|9000)")
        self.assertIn("received-on $ext_if", text)
        self.assertIn("set state-policy if-bound", text)
        self.assertIn("set ruleset-optimization none", text)
        self.assertIn("to ! <cloud_noninternet>", text)
        self.assertIn("169.254.0.0/16", text)
        self.assertNotIn("rdr pass", text)

    def test_managed_tables_persist_after_last_instance_removal(self):
        c = example_config()
        for configs in ([c], []):
            with self.subTest(instances=len(configs)):
                text = pf_rules(configs, host_config=c)
                self.assertRegex(text, r"(?m)^table <cloud_jails> const persist \{")
                self.assertRegex(text, r"(?m)^table <cloud_noninternet> const persist \{")
                self.assertIn("set ruleset-optimization none", text)
                self.assertIn("block log all", text)
        empty = pf_rules([], host_config=c)
        self.assertIn("table <cloud_jails> const persist {  }", empty)
        self.assertNotIn("to ! <cloud_noninternet>", empty)
        self.assertNotIn("rdr on", empty)

    def test_existing_ssh_server_first_output_is_preserved(self):
        text = pf_rules(example_config(), ("198.51.100.25", "54321", "192.0.2.10", "22"))
        self.assertIn("from 192.0.2.10 port 22 to 198.51.100.25 port 54321 flags any keep state", text)
        pickup = "pass in quick on $ext_if inet proto tcp from 198.51.100.25 port 54321 to 192.0.2.10 port 22 flags any keep state (sloppy)"
        self.assertIn(pickup, text)
        self.assertLess(text.index(pickup), text.index("from 198.51.100.0/24 to ($ext_if) port 22"))
        self.assertEqual(text.count("(sloppy)"), 2)
        for value in (("198.51.100.25", "22;bad", "192.0.2.10", "22"),
                      ("198.51.100.25", "54321", "192.0.2.10", "23"),
                      ("198.51.100.25", "0", "192.0.2.10", "22"),
                      ("203.0.113.25", "54321", "192.0.2.10", "22")):
            with self.assertRaises(ValueError):
                pf_rules(example_config(), value)

    def test_mount_guard_validates_actual_filesystem(self):
        c = example_config()
        guard = storage_guard(c, datasets(c))
        self.assertIn("zfs get -H -o value mounted", guard)
        self.assertIn('&& $3 == "zfs"', guard)
        self.assertNotIn("mkdir", guard)
        result = subprocess.run(["sh", "-n"], input=guard, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_custom_hostnames_do_not_change_resource_identities(self):
        c = replace(example_config(), nextcloud_hostname="nc.internal.example.test",
                    onlyoffice_hostname="office.internal.example.test", dns_address="203.0.113.10").validate()
        self.assertEqual((c.nextcloud_jail, c.onlyoffice_jail), ("cloudnc", "cloudoo"))
        self.assertEqual((c.nextcloud_host, c.onlyoffice_host), ("nc.internal.example.test", "office.internal.example.test"))
        self.assertIn("203.0.113.10", deployment_plan(c))
        self.assertIn("cloudnc (nc.internal.example.test)", deployment_plan(c))
        for changes in ({"onlyoffice_hostname": c.nextcloud_host}, {"onlyoffice_hostname": c.public_hostname},
                        {"nextcloud_hostname": "bad;hostname"}, {"onlyoffice_hostname": "UPPER.example.test"},
                        {"dns_address": c.nextcloud_ip}, {"dns_address": "127.0.0.1"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(c, **changes).validate()

    def test_external_tls_has_explicit_narrow_proxy_trust_and_http_callback(self):
        c = replace(example_config(), tls_mode="external", proxy_networks="192.0.2.20, 198.51.100.42/24",
                    http_port=8080, public_https_port=8443).validate()
        self.assertEqual(c.trusted_proxy_networks, ["192.0.2.20/32", "198.51.100.0/24"])
        self.assertEqual(c.public_url, "https://cloud.example.test:8443/")
        self.assertEqual(c.storage_url, "http://10.77.0.2/")
        self.assertEqual(c.callback_port, 80)
        self.assertEqual(c.ingress_ports, [8080])
        self.assertIn("proxy-managed A/AAAA; no required host-IP match", deployment_plan(c))
        self.assertNotIn("Expected DNS A address", deployment_plan(c))
        for networks in ("", "0.0.0.0/0", "192.0.2.0/23", "127.0.0.1", "224.0.0.0/24", "10.77.0.2",
                         "::1", "192.0.2.20;allow", ",".join(["192.0.2.20"] * 33)):
            with self.subTest(networks=networks), self.assertRaises(ValueError):
                replace(c, proxy_networks=networks).validate()
        with self.assertRaises(ValueError):
            replace(example_config(), proxy_networks="192.0.2.20").validate()

    def test_port_and_optional_ssh_configuration_rejects_collisions(self):
        c = replace(example_config(), tls_mode="provided", certificate_file="/test/chain.pem",
                    private_key_file="/test/key.pem", http_port=8080, https_port=8443,
                    jail_ssh=True, ssh_key_file="/test/operator.pub").validate()
        self.assertEqual(c.ingress_ports, [8080, 8443, 2201, 2202])
        for changes in ({"http_port": c.https_port}, {"https_port": c.management_port},
                        {"ssh_nextcloud_port": c.http_port}, {"ssh_onlyoffice_port": c.ssh_nextcloud_port},
                        {"ssh_nextcloud_port": c.management_port}, {"http_port": 0}, {"public_https_port": 65536},
                        {"ssh_key_file": ""}, {"ssh_key_file": "relative.pub"}, {"ssh_username": "root"},
                        {"ssh_shell": "shell;bad"}, {"jail_ssh": False, "ssh_admin": True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(c, **changes).validate()
        with self.assertRaisesRegex(ValueError, "HTTP-01"):
            replace(example_config(), http_port=8080).validate()

    def test_external_policy_limits_ingress_to_proxies_and_ssh_to_management(self):
        c = replace(example_config(), tls_mode="external", proxy_networks="192.0.2.20/32", http_port=8080,
                    jail_ssh=True, ssh_key_file="/test/operator.pub").validate()
        text = pf_rules(c)
        lines = text.splitlines()
        redirects = [line for line in lines if line.startswith("rdr ")]
        self.assertEqual(redirects, [
            "rdr on $ext_if inet proto tcp from { 192.0.2.20/32 } to 192.0.2.10 port 8080 -> 10.77.0.2 port 80",
            "rdr on $ext_if inet proto tcp from 198.51.100.0/24 to 192.0.2.10 port 2201 -> 10.77.0.2 port 22",
            "rdr on $ext_if inet proto tcp from 198.51.100.0/24 to 192.0.2.10 port 2202 -> 10.77.0.6 port 22"])
        self.assertIn("from 10.77.0.6 to 10.77.0.2 port 80 flags", text)
        self.assertNotIn("from 10.77.0.6 to 10.77.0.2 port 443", text)
        for line in lines:
            if line.startswith("pass in quick on $ext_if") and " to 10.77." in line:
                self.assertIn("from 198.51.100.0/24" if "port 22 " in line else "from { 192.0.2.20/32 }", line)
            if line.startswith("pass out quick on bridge") and "from 198.51.100.0/24" in line:
                self.assertIn("received-on $ext_if", line)
        self.assertLess(max(lines.index(line) for line in redirects), lines.index("block log all"))

    def test_multi_instance_policy_exposes_only_each_instances_own_flows(self):
        first = example_config()
        second = replace(first, instance="second", private_network="10.78.0.0/29",
                         nextcloud_bridge="bridge242", onlyoffice_bridge="bridge243", ingress_address="192.0.2.11")
        text = pf_rules([second, first])
        self.assertEqual(text, pf_rules([first, second]))
        self.assertIn("table <cloud_jails> const persist { 10.77.0.2, 10.77.0.6, 10.78.0.2, 10.78.0.6 }", text)
        for own, other in ((first, second), (second, first)):
            self.assertIn(f"from {own.nextcloud_ip} to {own.onlyoffice_ip} port 8081", text)
            for source in (own.nextcloud_ip, own.onlyoffice_ip):
                for target in (other.nextcloud_ip, other.onlyoffice_ip):
                    self.assertNotIn(f"from {source} to {target}", text)
            section = text.split(f"# Instance {own.instance}\n", 1)[1].split("# Instance ", 1)[0]
            self.assertNotIn(other.nextcloud_ip, section)
            self.assertNotIn(other.onlyoffice_ip, section)

    def test_private_source_antispoof_precedes_host_ssh_quick_pass(self):
        c = example_config()
        text = pf_rules(c)
        self.assertLess(text.index(f"block in quick on $ext_if inet from {c.private_network}"),
                        text.index(f"pass in quick on $ext_if inet proto tcp from {c.management_network}"))

    def test_removing_last_instance_preserves_management_without_app_exposure(self):
        text = pf_rules([], host_config=example_config())
        self.assertIn("port 22 flags any keep state", text)
        self.assertIn("block log all", text)
        self.assertFalse(any(line.startswith("rdr ") for line in text.splitlines()))
        self.assertNotIn("10.77.0.2", text)
        self.assertNotIn("10.77.0.6", text)
        with self.assertRaises(ValueError):
            pf_rules([])

    def test_mount_guard_executes_fail_closed_against_mocked_host_facts(self):
        c = example_config()
        storage = datasets(c)
        with tempfile.TemporaryDirectory(prefix="storage-guard-") as directory:
            root = Path(directory)
            state = root / "instances/cloud"
            active = root / "network/active"
            state.mkdir(parents=True)
            active.mkdir(parents=True)
            (state / "allow-start").write_text("allowed")
            (active / "firewall-confirmed").write_text("confirmed")
            for name in ("filter", "nat", "jails", "noninternet"):
                (active / ("pf-" + name + ".expected")).write_text("expected\n")
            targets = [(item.name, item.mountpoint) for item in storage if item.jail == c.nextcloud_jail]
            targets.append((c.bastille_dataset + "/jails/cloudnc/root", c.bastille_root + "/jails/cloudnc/root"))
            mounts = "\n".join(f"{name} {mountpoint} zfs rw 0 0" for name, mountpoint in targets)
            cases = "\n".join(f"'{name}') printf '%s\\n' '{mountpoint}' ;;" for name, mountpoint in targets)
            df_cases = "\n".join(f"'{mountpoint}') printf '%s\\n' '{name} 1 0 1 0% {mountpoint}' ;;" for name, mountpoint in targets)
            mocks = '''
pfctl() { [ "$TEST_FAULT" != policy ] || return 1; printf 'expected\\n'; }
sysctl() {
    case "$2" in
        net.inet.ip.forwarding|net.link.bridge.pfil_bridge|net.link.bridge.pfil_onlyip) printf '1\\n' ;;
        *) printf '0\\n' ;;
    esac
}
ifconfig() {
    case "$1" in bridge240) printf 'inet 10.77.0.1 netmask 0xfffffffc\\n' ;;
        bridge241) printf 'inet 10.77.0.5 netmask 0xfffffffc\\n' ;; esac
    if [ "$TEST_FAULT" = bridge ]; then printf 'member: foreign0\\n'; fi
}
zfs() {
    case "$5" in
        mounted) printf 'yes\\n' ;;
        org.cloud-installer:instance) if [ "$TEST_FAULT" = owner ]; then printf 'other\\n'; else printf 'cloud\\n'; fi ;;
        mountpoint) case "$6" in
''' + cases + '''
        *) return 99 ;; esac ;;
        *) return 98 ;;
    esac
}
realpath() { printf '%s\\n' "$1"; }
mount() { [ "$TEST_FAULT" != mount ] || return 1; printf '%s\\n' 'MOUNTS'; }
df() {
    printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n'
    if [ "$TEST_FAULT" = df ]; then printf 'foreign 1 0 1 0%% /wrong\\n'; return; fi
    case "$2" in
''' + df_cases + '''
        *) return 97 ;; esac
}
'''
            mocks = mocks.replace("MOUNTS", mounts)
            guard = storage_guard(c, storage, root)
            for command in ("pfctl", "sysctl", "ifconfig", "zfs", "mount"):
                guard = guard.replace("/sbin/" + command, command)
            for command in ("realpath", "df"):
                guard = guard.replace("/bin/" + command, command)
            for fault, jail, accepted in (("", "cloudnc", True), ("policy", "cloudnc", False),
                                         ("owner", "cloudnc", False), ("mount", "cloudnc", False),
                                         ("df", "cloudnc", False), ("bridge", "cloudnc", False),
                                         ("", "foreignnc", False)):
                with self.subTest(fault=fault, jail=jail):
                    result = subprocess.run(["sh", "-c", mocks + guard, "guard-test", jail], text=True,
                                            capture_output=True, timeout=5, env={**os.environ, "TEST_FAULT": fault})
                    self.assertEqual(result.returncode == 0, accepted, result.stderr)
            (state / "allow-start").unlink()
            result = subprocess.run(["sh", "-c", mocks + guard, "guard-test", "cloudnc"], text=True,
                                    capture_output=True, timeout=5, env={**os.environ, "TEST_FAULT": ""})
            self.assertNotEqual(result.returncode, 0)

    def test_plan_does_not_contain_secrets(self):
        text = deployment_plan(example_config())
        self.assertNotIn("password", text.lower())
        self.assertNotIn("jwt", text.lower())
        self.assertIn("IPv6", text)
        self.assertIn("PF/NAT", text)
        self.assertIn("not RCTL limits", text)

    def test_runner_does_not_use_shell_interpolation(self):
        with patch("installer.host.subprocess.run") as run:
            run.return_value.returncode = 0
            Runner().run("tool", "literal; no-shell", capture=False)
        self.assertEqual(run.call_args.args[0], ["tool", "literal; no-shell"])
        self.assertNotIn("shell", run.call_args.kwargs)
        self.assertEqual(run.call_args.kwargs["umask"], 0o022)

    def test_direct_host_gate_rejects_unreviewed_release_variants(self):
        for version in ("15.1-CURRENT", "15.1-RC1", "15.1-RELEASE-pinvalid", "15.0-RELEASE"):
            runner = Mock()
            runner.output.side_effect = ["FreeBSD", version, "amd64"]
            with self.subTest(version=version), patch("installer.host.os.geteuid", return_value=0), self.assertRaises(ValueError):
                require_host(runner)
            runner.run.assert_not_called()

    def test_direct_host_gate_checks_policy_architecture_kernel_and_jail_without_mutation(self):
        release = defaults()["freebsd_release"]
        for architecture, kernel, jailed, accepted in (
                ("amd64", release, "0", True), ("amd64", release + "-p2", "0", True),
                ("aarch64", release, "0", False), ("amd64", "15.0-RELEASE", "0", False),
                ("amd64", release, "1", False)):
            runner = Mock()
            runner.output.side_effect = ["FreeBSD", release + "-p2", architecture, kernel, jailed]
            with self.subTest(architecture=architecture, kernel=kernel, jailed=jailed), \
                    patch("installer.host.os.geteuid", return_value=0):
                if accepted:
                    require_host(runner)
                else:
                    with self.assertRaises(ValueError):
                        require_host(runner)
            runner.run.assert_not_called()

    def test_verify_cannot_create_missing_state_directory(self):
        with patch("installer.host.STATE_DIR") as state:
            state.exists.return_value = False
            state.is_symlink.return_value = False
            with self.assertRaises(ValueError):
                state_directory(create=False)
            state.mkdir.assert_not_called()


if __name__ == "__main__":
    unittest.main()
