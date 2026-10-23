"""VM PF/NC guard rendering; not live packet/boot acceptance."""
from dataclasses import replace
from pathlib import Path
import subprocess
import unittest

from installer.config import Config, datasets
from installer.network import pf_rules, storage_guard


class VmNetworkTests(unittest.TestCase):
    def config(self,backend='eurooffice',**fields):
        base=Config.from_json((Path(__file__).resolve().parents[1]/'examples'/('eurooffice.json' if backend=='eurooffice' else 'collabora.json')).read_text())
        return replace(base,**fields).validate()

    def test_private_provisioning_no_public_vm_ssh_and_only_paired_frontend_callback(self):
        for backend in ('eurooffice','collabora'):
            c=self.config(backend,jail_ssh=True,ssh_key_file='/root/operator.pub',public_https_port=9443)
            rules=pf_rules(c)
            with self.subTest(backend=backend):
                self.assertIn(f'pass out quick on {c.onlyoffice_bridge} inet proto tcp from {c.onlyoffice_gateway} to {c.onlyoffice_ip} port 22',rules)
                self.assertNotIn(f'from {c.management_network} to {c.onlyoffice_ip} port 22',rules)
                self.assertNotIn(f'port {c.ssh_onlyoffice_port} -> {c.onlyoffice_ip}',rules)
                self.assertIn(f'from {c.nextcloud_ip} to {c.onlyoffice_ip} port 8081',rules)
                self.assertIn(f'from {c.onlyoffice_ip} to {c.nextcloud_ip} port 443',rules)
                self.assertNotIn(f'from {c.onlyoffice_ip} to {c.nextcloud_ip} port 9443',rules)
                self.assertNotIn('2375',rules)
                self.assertNotIn('9980',rules)
                self.assertIn(f'block in quick on {c.onlyoffice_bridge} inet from ! {c.onlyoffice_ip}',rules)
                self.assertIn('set ruleset-optimization none',rules)

    def test_external_tls_callback80_trusted_ingress_and_no_vm_mail_egress(self):
        c=self.config('collabora',tls_mode='external',proxy_networks='192.0.2.20/32',http_port=8080)
        rules=pf_rules(c)
        self.assertIn(f'from {{ 192.0.2.20/32 }} to {c.ingress_address} port 8080 -> {c.nextcloud_ip} port 80',rules)
        self.assertIn(f'from {c.onlyoffice_ip} to {c.nextcloud_ip} port 80',rules)
        self.assertIn(f'from {c.nextcloud_ip} to ! <cloud_noninternet> port {{ 465, 587, 993 }}',rules)
        self.assertNotIn(f'from {c.onlyoffice_ip} to ! <cloud_noninternet> port {{ 465, 587, 993 }}',rules)

    def test_nc_guard_does_not_require_office_jail_but_checks_exact_vm_tap(self):
        c=self.config()
        script=storage_guard(c,datasets(c))
        self.assertIn(c.nextcloud_jail+')',script)
        self.assertNotIn(c.onlyoffice_jail+')',script)
        self.assertNotIn('e0a_'+c.onlyoffice_jail,script)
        self.assertIn('vmnet/'+c.instance+'office/0/'+c.instance+'office',script)
        self.assertIn('count > 1',script)
        self.assertIn('""|*[!0-9]*)',script)
        result=subprocess.run(['sh','-n'],input=script,text=True,capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_mixed_native_vm_none_policy_keeps_existing_native_rules(self):
        root=Path(__file__).resolve().parents[1]
        native=Config.from_json((root/'examples/config.json').read_text())
        single=replace(Config.from_json((root/'examples/nextcloud-only.json').read_text()),instance='solo',
                       private_network='10.77.0.8/30',nextcloud_bridge='bridge242',ingress_address='192.0.2.11')
        guest=self.config(instance='guest',private_network='10.77.0.16/29',nextcloud_bridge='bridge243',
                          onlyoffice_bridge='bridge244',ingress_address='192.0.2.12')
        mixed=pf_rules([native,single,guest])
        self.assertIn(f'from {native.nextcloud_ip} to {native.onlyoffice_ip} port 8081',mixed)
        self.assertIn(f'to {native.onlyoffice_ip} port {{ 8000, 8126 }}',mixed)
        self.assertNotIn(single.onlyoffice_ip,mixed)
        self.assertNotIn(f'from {guest.onlyoffice_ip} to {native.nextcloud_ip}',mixed)
        self.assertEqual(pf_rules([native]),pf_rules(native))
