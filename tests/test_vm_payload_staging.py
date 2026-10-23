"""VM-profile NC staging never sends host/guest credentials into a jail."""
from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import Mock, PropertyMock, patch

from installer.config import Config
from installer.deploy import Deployment
from installer.resolution import resolve
from nextcloud_worker_fixtures import PHP, run_php
from test_vm_resolution import vm_metadata


class VmPayloadStagingTests(unittest.TestCase):
    def test_selected_nc_payload_has_real_connector_but_no_native_office_or_guest_keys(self):
        root=Path(__file__).resolve().parents[1]
        for backend in ('eurooffice','collabora'):
            with self.subTest(backend=backend),tempfile.TemporaryDirectory() as tmp, \
                    patch.object(Config,'bastille_root',new_callable=PropertyMock,return_value=str(Path(tmp)/'bastille')):
                c=Config.from_json((root/'examples'/(backend+'.json')).read_text())
                runner=Mock()
                d=Deployment(c,{},runner,registry=Mock())
                runner.assert_not_called()
                d._versions=resolve(c,vm_metadata(c))
                d.secrets={'jwt_secret':'secret-canary','admin_password':'admin-canary'}
                (d.jail_root(c.nextcloud_jail)/'root').mkdir(parents=True,mode=0o700)
                d.stage_payloads()
                target=d.jail_root(c.nextcloud_jail)/'root/cloud-installer'
                runtime=json.loads((target/'runtime.json').read_text())
                self.assertEqual(runtime['onlyoffice_ip'],c.onlyoffice_ip)
                self.assertEqual(runtime['versions']['office_backend'],backend)
                self.assertEqual(runtime['versions']['connector_app'],'eurooffice' if backend=='eurooffice' else 'richdocuments')
                self.assertNotIn('onlyoffice',runtime['versions'])
                self.assertEqual(json.loads((target/'connector.json').read_text()),d.versions['connector'])
                self.assertFalse((target/'fonts-unavailable').exists())
                self.assertFalse((target/'installer').exists())
                self.assertFalse((target/'resources/templates/onlyoffice').exists())
                self.assertFalse((target/'resources/jails/onlyoffice.sh').exists())
                self.assertFalse((target/'resources/vm').exists())
                self.assertTrue((target/'resources/templates/nextcloud/www.conf').is_file())
                self.assertFalse((target/'resources/templates/nextcloud/www-none.conf').exists())
                for file in target.rglob('*'):
                    if file.is_file():
                        self.assertNotIn('secret-canary',file.read_text())
                        self.assertNotIn('admin-canary',file.read_text())
                self.assertFalse((Path(c.bastille_root)/'jails'/c.onlyoffice_jail).exists())
                if PHP:
                    result=run_php('echo "ok";',{'runtime':runtime})
                    self.assertEqual(result.returncode,0,result.stderr)
