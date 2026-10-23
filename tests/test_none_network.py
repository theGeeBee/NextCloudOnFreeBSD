"""One-jail PF/boot rendering contracts, not native PF acceptance."""

from dataclasses import replace
import json
from pathlib import Path
import subprocess
import unittest

from installer.config import Config, datasets
from installer.network import pf_rules, storage_guard


class NextcloudOnlyNetworkTests(unittest.TestCase):
    def config(self, **changes):
        root = Path(__file__).resolve().parents[1]
        config = Config.from_json((root / 'examples/nextcloud-only.json').read_text())
        return replace(config, **changes).validate()

    def test_no_office_address_bridge_callback_or_private_service_rules(self):
        config = self.config()
        rules = pf_rules(config)
        for absent in (config.onlyoffice_ip, config.onlyoffice_bridge, '8081', '8000', '8125', '8126'):
            self.assertNotIn(absent, rules)
        self.assertIn(f'table <cloud_jails> const persist {{ {config.nextcloud_ip} }}', rules)
        self.assertIn(f'block in quick on {config.nextcloud_bridge} inet from ! {config.nextcloud_ip}', rules)
        self.assertIn(f'block in quick on $ext_if inet from {config.private_network}', rules)
        self.assertIn(f'block quick on {config.nextcloud_bridge} inet6 all', rules)
        self.assertIn('set ruleset-optimization none', rules)
        self.assertIn('block log all', rules)
        self.assertIn('port { 465, 587, 993 }', rules)

    def test_external_tls_and_ssh_use_only_selected_nc_endpoint(self):
        config = self.config(tls_mode='external', proxy_networks='192.0.2.20/32', http_port=8080,
                             public_https_port=9443, jail_ssh=True, ssh_key_file='/root/admin.pub')
        rules = pf_rules(config)
        self.assertIn(f'from {{ 192.0.2.20/32 }} to {config.ingress_address} port 8080 -> {config.nextcloud_ip} port 80', rules)
        self.assertIn(f'port {config.ssh_nextcloud_port} -> {config.nextcloud_ip} port 22', rules)
        for absent in (f'port {config.ssh_onlyoffice_port}', config.onlyoffice_bridge, config.onlyoffice_ip, '9443'):
            self.assertNotIn(absent, rules)

    def test_mixed_policy_keeps_native_rules_and_does_not_join_instances(self):
        root = Path(__file__).resolve().parents[1]
        native = Config.from_json((root / 'examples/config.json').read_text())
        single = self.config(instance='solo', private_network='10.77.0.8/30', nextcloud_bridge='bridge242',
                             ingress_address='192.0.2.11', nextcloud_apps='none')
        rules = pf_rules([single, native])
        self.assertIn(f'from {native.nextcloud_ip} to {native.onlyoffice_ip} port 8081', rules)
        self.assertNotIn(single.onlyoffice_ip, rules)
        single_rules = rules.split('# Instance solo (Nextcloud only)', 1)[1]
        self.assertNotIn(native.onlyoffice_ip, single_rules)
        self.assertNotIn('8081', single_rules)
        # Removing the single-jail instance reproduces native policy exactly.
        self.assertEqual(pf_rules([native], host_config=single), pf_rules(native))

    def test_boot_guard_checks_only_real_resources_and_rejects_unknown_jails(self):
        config = self.config()
        script = storage_guard(config, datasets(config))
        self.assertIn(config.nextcloud_jail + ')', script)
        self.assertNotIn(config.onlyoffice_jail, script)
        self.assertNotIn(config.onlyoffice_bridge, script)
        self.assertNotIn('/office-', script)
        for guard in ('allow-start', 'firewall-confirmed', 'org.cloud-installer:instance',
                      'mount -p', 'df -P', 'foreign=1', '*) exit 1 ;;'):
            self.assertIn(guard, script)
        result = subprocess.run(['sh', '-n'], input=script, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
