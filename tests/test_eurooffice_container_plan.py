"""Pure standalone Euro Docker command, not image/container native acceptance."""
from dataclasses import replace
from pathlib import Path
import unittest

from installer.config import Config
from installer.office_vm import eurooffice_container_arguments
from installer.resolution import resolve
from test_vm_resolution import vm_metadata


class EuroContainerPlanTests(unittest.TestCase):
    def config(self,**changes):
        root=Path(__file__).resolve().parents[1]
        return replace(Config.from_json((root/'examples/eurooffice.json').read_text()),**changes)

    def test_one_pinned_private_frontend_bounded_logs_and_only_public_environment(self):
        c=self.config()
        plan=resolve(c,vm_metadata(c))
        selected=eurooffice_container_arguments(c,plan)
        args=selected['args']
        self.assertEqual(args[:3],['docker','run','--detach'])
        self.assertEqual(args[-1],plan['office_runtime']['container']['reference'])
        self.assertIn('@sha256:',args[-1])
        self.assertEqual(args[args.index('--publish')+1],c.onlyoffice_ip+':8081:80')
        self.assertEqual(args.count('--publish'),1)
        self.assertIn('JWT_ENABLED=true',args)
        self.assertIn('JWT_HEADER=AuthorizationJWT',args)
        self.assertIn('EXAMPLE_ENABLED=false',args)
        self.assertIn('ADMINPANEL_ENABLED=false',args)
        self.assertIn('ALLOW_META_IP_ADDRESS=false',args)
        self.assertIn('USE_UNAUTHORIZED_STORAGE=false',args)
        self.assertIn('max-size=10m',args)
        self.assertIn('max-file=3',args)
        self.assertTrue(selected['jwt_file'].endswith('/data/.private/jwt_secret'))
        for forbidden in ('JWT_SECRET=','--privileged','--network=host','2375','2376',':latest','secrets.json'):
            self.assertNotIn(forbidden,repr(args))

    def test_packaged_postgres_runtime_and_queue_use_native_volume_initialization(self):
        c=self.config()
        selected=eurooffice_container_arguments(c,resolve(c,vm_metadata(c)))
        self.assertEqual(selected['volumes'],{
            c.instance+'office-database':'/var/lib/postgresql',c.instance+'office-queue':'/var/lib/rabbitmq',
            c.instance+'office-runtime':'/var/lib/euro-office',c.instance+'office-logs':'/var/log/euro-office'})
        for name,target in selected['volumes'].items():
            self.assertIn('type=volume,source='+name+',target='+target,selected['args'])
        self.assertEqual(selected['binds'],{'/var/lib/cloud-installer/office/volumes/data':'/var/www/euro-office/Data'})
        self.assertNotIn('volume-nocopy',repr(selected))
        self.assertNotIn('type=bind,source=/var/lib/postgresql',repr(selected))

    def test_direct_callback_uses_private_routing_with_hostname_verification_and_optional_ca(self):
        c=self.config(ca_file='/root/public-ca.pem',public_https_port=9443)
        args=eurooffice_container_arguments(c,resolve(c,vm_metadata(c)))['args']
        self.assertIn(c.public_hostname+':'+c.nextcloud_ip,args)
        self.assertIn('NODE_EXTRA_CA_CERTS=/etc/euro-office/nextcloud-ca.pem',args)
        self.assertIn('type=bind,source=/var/lib/cloud-installer/office/nextcloud-ca.pem,target=/etc/euro-office/nextcloud-ca.pem,readonly',args)
        self.assertNotIn(c.ca_file,args)
        self.assertNotIn('NODE_TLS_REJECT_UNAUTHORIZED=0',args)
        self.assertNotIn('JWT_SECRET',repr(args))

    def test_external_callback_never_adds_public_host_mapping_or_false_tls_exception(self):
        c=self.config(tls_mode='external',proxy_networks='192.0.2.9/32',http_port=8080)
        args=eurooffice_container_arguments(c,resolve(c,vm_metadata(c)))['args']
        self.assertNotIn('--add-host',args)
        self.assertIn('USE_UNAUTHORIZED_STORAGE=false',args)

    def test_other_backend_and_changed_entrypoint_identity_are_refused(self):
        c=self.config()
        plan=resolve(c,vm_metadata(c))
        changed=replace(c,office_backend='collabora')
        with self.assertRaises(ValueError): eurooffice_container_arguments(changed,plan)
        plan['office_runtime']['container']['entrypoint_sha256']='f'*64
        with self.assertRaises(ValueError): eurooffice_container_arguments(c,plan)
