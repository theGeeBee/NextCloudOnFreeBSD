"""Existing verify orchestration with Euro runtime seams mocked; no native probes."""
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from installer.config import Config
from installer.deploy import Deployment
from installer.resolution import resolve
from test_vm_resolution import vm_metadata


class EuroVerifyTests(unittest.TestCase):
    def setUp(self):
        self.c=Config.from_json((Path(__file__).resolve().parents[1]/'examples/eurooffice.json').read_text())
        self.plan=resolve(self.c,vm_metadata(self.c))
        self.d=object.__new__(Deployment);self.d.config=self.c;self.d._versions=self.plan;self.d.manifest={}
        self.d.require_running_jail=Mock();self.d.wait_for_vm_office=Mock();self.d.verify_database_configuration=Mock()
        self.d.runner=Mock()
        self.d.runner.output.side_effect=lambda *args:self.plan['packages']['host'][args[-1]]['version']+'|'+self.plan['packages']['host'][args[-1]]['origin']
        self.version='9.3.5.27';self.url_changed=False
        self.d.jail=Mock(side_effect=self.jail)
        self.runtime=self.enterContext(patch('installer.office_vm.verify_eurooffice_container',return_value={
            'container':self.c.instance+'office','state':'running'}))

    def jail(self,*args,**kwargs):
        output=''
        if 'config:app:get' in args:
            expected={'DocumentServerUrl':self.c.public_url+'eurooffice/',
                'DocumentServerInternalUrl':'http://'+self.c.onlyoffice_ip+':8081/','StorageUrl':self.c.storage_url}
            output='changed' if self.url_changed else expected[args[-1]]
        elif 'eurooffice:documentserver' in args:
            output='Document server '+self.c.public_url+'eurooffice/ version '+self.version+' is successfully connected\n'
        elif args[1:]==('pkg','query','%n %v %o'):
            output='\n'.join(name+' '+record['version']+' '+record['origin'] for name,record in self.plan['packages']['nextcloud'].items())
        elif args[-2:]==('status','--output=json'):
            output=json.dumps({'installed':True,'maintenance':False,'needsDbUpgrade':False,'version':self.plan['applications']['nextcloud']})
        return SimpleNamespace(returncode=0,stdout=output)

    def test_vm_container_then_health_selected_urls_version_and_proxy_checks(self):
        self.d.verify()
        self.runtime.assert_called_once_with(self.d)
        self.d.wait_for_vm_office.assert_called_once_with()
        self.assertEqual(self.d.manifest['office_vm']['reported_version'],self.version)
        commands=[call.args for call in self.d.jail.call_args_list]
        self.assertTrue(all(args[0]==self.c.nextcloud_jail for args in commands))
        self.assertFalse(any(self.c.onlyoffice_jail in args or 'onlyoffice:documentserver' in args for args in commands))
        scripts=[args[3] for args in commands if args[1:3]==('python3','-c')]
        self.assertEqual(len(scripts),1)
        self.assertIn('eurooffice/healthcheck',scripts[0])
        self.assertNotIn("c['versions']['onlyoffice']",scripts[0])
        self.assertIn("error.code==403",scripts[0])
        self.assertNotIn('CERT_NONE',scripts[0])

    def test_wrong_runtime_version_or_url_refuses_without_repair(self):
        for version in ('9.3.6','9.3.50','9.3.5-rc1'):
            self.version=version
            with self.subTest(version=version),self.assertRaisesRegex(RuntimeError,'selected stable runtime'):self.d.verify()
        self.version='9.3.5.27';self.url_changed=True
        with self.assertRaisesRegex(RuntimeError,'never rewrites'):self.d.verify()
        self.assertFalse(any('config:app:set' in call.args for call in self.d.jail.call_args_list))
