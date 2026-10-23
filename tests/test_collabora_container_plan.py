"""CODE command candidate, based on observed pinned image, no Docker execution."""
from dataclasses import replace
from pathlib import Path
import unittest

from installer.config import Config
from installer.office_vm import collabora_container_arguments
from installer.resolution import resolve
from test_vm_resolution import vm_metadata


class CollaboraContainerPlanTests(unittest.TestCase):
    def config(self,**changes):
        c=Config.from_json((Path(__file__).resolve().parents[1]/'examples/collabora.json').read_text())
        return replace(c,**changes)

    def test_one_pinned_nonprivileged_container_with_readonly_proof_and_config(self):
        c=self.config();plan=resolve(c,vm_metadata(c));selected=collabora_container_arguments(c,plan)
        args=selected['args']
        self.assertEqual(args[:3],['docker','run','--detach'])
        self.assertEqual(args[-1],plan['office_runtime']['container']['reference'])
        self.assertEqual(args[args.index('--publish')+1],c.onlyoffice_ip+':8081:9980')
        self.assertEqual(args.count('--publish'),1)
        self.assertEqual(len(selected['binds']),3)
        for source,target in selected['binds'].items():
            self.assertIn('type=bind,source='+source+',target='+target+',readonly',args)
        for forbidden in ('--privileged','--cap-add','--security-opt','no-new-privileges','--user','--entrypoint','/bin/sh','JWT_SECRET','--network=host','/opt/cool/child-roots'):
            self.assertNotIn(forbidden,repr(args))
        self.assertEqual(selected['product_version'],'26.04.5.1')
        self.assertEqual(selected['discovery_path'],'/collabora/hosting/discovery')
        self.assertIn('max-size=10m',args)
        self.assertIn('max-file=3',args)

    def test_direct_callback_hostname_and_public_ca_preserve_tls_validation(self):
        c=self.config(ca_file='/root/operator-public-ca.pem')
        selected=collabora_container_arguments(c,resolve(c,vm_metadata(c)))
        self.assertIn(c.public_hostname+':'+c.nextcloud_ip,selected['args'])
        self.assertIn('/etc/coolwsd/nextcloud-ca.pem',selected['binds'].values())
        self.assertNotIn(c.ca_file,repr(selected))
        self.assertNotIn('ssl_verification=false',repr(selected))

    def test_external_callback_does_not_rewrite_browser_hostname_or_use_jwt(self):
        c=self.config(tls_mode='external',proxy_networks='192.0.2.9/32',http_port=8080)
        selected=collabora_container_arguments(c,resolve(c,vm_metadata(c)))
        self.assertNotIn('--add-host',selected['args'])
        self.assertNotIn('jwt',repr(selected).lower())

    def test_other_backend_or_mismatched_plan_cannot_choose_image(self):
        c=self.config();plan=resolve(c,vm_metadata(c))
        with self.assertRaises(ValueError):collabora_container_arguments(replace(c,office_backend='eurooffice'),plan)
        plan['office_backend']='eurooffice'
        with self.assertRaises(ValueError):collabora_container_arguments(c,plan)
