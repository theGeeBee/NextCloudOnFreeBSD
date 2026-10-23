"""CODE install activation and read-only identity boundaries, no native operations."""
from copy import deepcopy
from pathlib import Path
import tempfile
from unittest.mock import Mock,PropertyMock,patch
import unittest

from installer.config import Config
from installer.deploy import Deployment
from installer.resolution import resolve
from installer.state import atomic_json
from test_vm_resolution import vm_metadata


class CollaboraIntegrationTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='code-integration-');self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.enterContext(patch.object(Config,'bastille_root',new_callable=PropertyMock,return_value=str(self.root/'bastille')))
        self.c=Config.from_json((Path(__file__).resolve().parents[1]/'examples/collabora.json').read_text())
        self.d=object.__new__(Deployment);self.d.config=self.c;self.d.state=self.root/'state';self.d.state.mkdir(mode=0o700)
        self.d._versions=resolve(self.c,vm_metadata(self.c))
        self.result={'product_version':'26.04.5.1','proof_sha256':'a'*64,'public_key_sha256':'b'*64,
                     'public_url':self.c.public_url+'collabora/','editing_verified':False,'discovery_actions':288}
        self.d.read_collabora_endpoints=Mock(return_value=self.result.copy())

    def test_first_install_saves_validated_public_identity_but_readonly_missing_receipt_refuses(self):
        with self.assertRaisesRegex(ValueError,'never publishes'):self.d.collabora_readiness_identity()
        self.d.read_collabora_endpoints.assert_not_called()
        value=self.d.collabora_readiness_identity(publish=True)
        self.assertTrue(value['discovery_verified']);self.assertFalse(value['editing_verified'])
        receipt=self.d.state/'collabora-readiness.json';before=receipt.stat().st_mtime_ns
        self.d.collabora_readiness_identity()
        self.assertEqual(receipt.stat().st_mtime_ns,before)
        self.d.read_collabora_endpoints.assert_called_with(expected_proof_sha256='a'*64)

    def test_changed_proof_or_public_identity_is_not_adopted(self):
        self.d.collabora_readiness_identity(publish=True)
        self.d.read_collabora_endpoints.return_value={**self.result,'public_key_sha256':'c'*64}
        with self.assertRaisesRegex(ValueError,'no rotation'):self.d.collabora_readiness_identity()

    def test_install_finish_uses_no_jwt_and_readiness_precedes_proxy_worker(self):
        events=[]
        self.d.collabora_readiness_identity=Mock(side_effect=lambda **kwargs:events.append('endpoints'))
        self.d.jail=Mock(side_effect=lambda *args,**kwargs:events.append(('worker',args,kwargs)))
        self.d.verify_connector_urls=Mock(side_effect=lambda:events.append('postconditions'))
        target=self.d.jail_root(self.c.nextcloud_jail)/'root/cloud-installer';target.mkdir(parents=True,mode=0o700)
        self.d._integrate()
        self.assertEqual(events[0],'endpoints');self.assertEqual(events[-1],'postconditions')
        worker=events[1]
        self.assertEqual(worker[1][-1],'finish')
        self.assertNotIn('jwt_secret',worker[2]['input'])
        self.assertIn('http://'+self.c.onlyoffice_ip+':8081/collabora/',worker[2]['input'])
        self.assertIn('/collabora/',(target/'apache-onlyoffice.conf').read_text())
