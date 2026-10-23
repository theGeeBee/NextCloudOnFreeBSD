"""Bounded CODE endpoint contracts; synthetic public RSA data, no live editing."""
from dataclasses import replace
import base64
import hashlib
import json
import struct
import tempfile
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET
from types import SimpleNamespace
from unittest.mock import Mock,patch

from installer.config import Config
from installer.deploy import Deployment
from installer.office_vm import validate_collabora_endpoints
from installer.resolution import resolve
from installer.state import atomic_json,config_digest
from test_vm_resolution import vm_metadata


class CollaboraReadinessTests(unittest.TestCase):
    def setUp(self):
        self.c=replace(Config.from_json((Path(__file__).resolve().parents[1]/'examples/collabora.json').read_text()),public_https_port=9443)
        self.plan=resolve(self.c,vm_metadata(self.c))
        self.root=ET.Element('wopi-discovery')
        app=ET.SubElement(ET.SubElement(self.root,'net-zone',{'name':'external-https'}),'app',{'name':'writer'})
        ET.SubElement(app,'action',{'name':'edit','urlsrc':self.c.public_url+'collabora/browser/22ce52fb/cool.html?'})
        for name,path in (('editnew','browser/22ce52fb/cool.html'),('view','browser/22ce52fb/cool.html'),
                          ('view_comment','browser/22ce52fb/cool.html'),
                          ('interactivepreview','browser/22ce52fb/cool-preview.html'),
                          ('iframe','browser/22ce52fb/adminIntegratorSettings.html'),
                          ('getinfo','hosting/capabilities')):
            ET.SubElement(app,'action',{'name':name,'urlsrc':self.c.public_url+'collabora/'+path})
        self.modulus=b'\x80'+b'\x11'*255
        self.blob=struct.pack('<BBHIIII',6,2,0,0xA400,0x31415352,2048,65537)+self.modulus[::-1]
        self.value=base64.b64encode(self.blob).decode()
        ET.SubElement(self.root,'proof-key',{'value':self.value,'modulus':base64.b64encode(self.modulus).decode(),
            'exponent':base64.b64encode(b'\x01\x00\x01').decode()})
        self.caps={'productName':'Collabora Online Development Edition','productVersion':'26.04.5.1'}

    def check(self,**kwargs):
        return validate_collabora_endpoints(self.c,self.plan,ET.tostring(self.root),json.dumps(self.caps).encode(),**kwargs)

    def test_exact_product_public_authority_proof_and_no_editor_claim(self):
        result=self.check()
        self.assertEqual(result['product_version'],'26.04.5.1')
        self.assertEqual(result['public_url'],self.c.public_url+'collabora/')
        self.assertEqual(result['proof_sha256'],hashlib.sha256(self.value.encode()).hexdigest())
        self.assertEqual(result['discovery_actions'],7)
        self.assertFalse(result['editing_verified'])
        self.assertEqual(self.check(expected_proof_sha256=result['proof_sha256']),result)
        self.assertEqual(self.check(expected_public_key_sha256=result['public_key_sha256']),result)
        with self.assertRaisesRegex(ValueError,'no key rotation inferred'):self.check(expected_proof_sha256='f'*64)
        with self.assertRaisesRegex(ValueError,'provisioned public key'):self.check(expected_public_key_sha256='f'*64)

    def test_canonical_garbage_or_disagreeing_csp_material_is_not_a_public_key(self):
        proof=self.root.find('proof-key')
        for value in (b'fixture-public-CSP-blob',self.blob[:-1]+b'\x00'):
            proof.set('value',base64.b64encode(value).decode())
            with self.subTest(value=value[:10]),self.assertRaises(ValueError):self.check()

    def test_image_tag_is_not_accepted_as_capabilities_product_version(self):
        self.caps['productVersion']='26.04.5.1.1'
        with self.assertRaisesRegex(ValueError,'selected stable product'):self.check()

    def test_wrong_authority_private_http_or_proxy_prefix_cannot_pass(self):
        action=self.root.find('.//action')
        for url in ('http://'+self.c.public_hostname+':9443/collabora/browser/hash/cool.html',
                    'https://foreign.example/collabora/browser/hash/cool.html',
                    self.c.public_url+'browser/hash/cool.html',
                    self.c.public_url+'collabora/browser/../admin.html',
                    self.c.public_url+'collabora/browser/%2e%2e/admin.html'):
            action.set('urlsrc',url)
            with self.subTest(url=url),self.assertRaises(ValueError):self.check()

    def test_getinfo_only_accepts_exact_selected_https_capabilities_endpoint(self):
        action=next(a for a in self.root.findall('.//action') if a.get('name')=='getinfo')
        for url in (self.c.public_url+'hosting/capabilities',self.c.public_url+'collabora/hosting/discovery',
                    self.c.public_url+'collabora/browser/hash/cool.html',
                    self.c.public_url.replace('https:','http:')+'collabora/hosting/capabilities',
                    'https://other.example/collabora/hosting/capabilities',
                    self.c.public_url+'collabora/hosting/%63apabilities'):
            action.set('urlsrc',url)
            with self.subTest(url=url),self.assertRaises(ValueError):self.check()

    def test_editor_cannot_use_getinfo_exception_or_discovery_with_only_getinfo(self):
        app=self.root.find('.//app')
        for a in list(app):
            if a.get('name')!='getinfo':app.remove(a)
        with self.assertRaisesRegex(ValueError,'no supported editor'):self.check()
        action=ET.SubElement(app,'action',{'name':'edit','urlsrc':self.c.public_url+'collabora/hosting/capabilities'})
        with self.assertRaisesRegex(ValueError,'authority/path'):self.check()

    def test_missing_duplicate_or_invalid_proof_cannot_be_reported_ready(self):
        proof=self.root.find('proof-key')
        for key,value in (('value',''),('value','not-base64'),('modulus',base64.b64encode(b'\x01'*128).decode()),
                          ('exponent',base64.b64encode(b'\x03').decode())):
            old=proof.get(key);proof.set(key,value)
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):self.check()
            proof.set(key,old)
        self.root.remove(proof)
        with self.assertRaisesRegex(ValueError,'one native proof'):self.check()
        self.root.append(proof);ET.SubElement(self.root,'proof-key',proof.attrib)
        with self.assertRaisesRegex(ValueError,'one native proof'):self.check()

    def test_xml_entities_size_and_duplicate_json_are_refused(self):
        for discovery in (b'<!DOCTYPE x [<!ENTITY a "bad">]><wopi-discovery/>',b'x'*(1024**2+1),b'\0<xml/>'):
            with self.assertRaises(ValueError):validate_collabora_endpoints(self.c,self.plan,discovery,b'{}')
        duplicate=b'{"productVersion":"26.04.5.1","productVersion":"26.04.5.1"}'
        with self.assertRaisesRegex(ValueError,'Duplicate'):validate_collabora_endpoints(self.c,self.plan,ET.tostring(self.root),duplicate)

    def test_nc_fetch_is_readonly_owned_private_frontend_then_same_pure_contract(self):
        d=object.__new__(Deployment);d.config=self.c;d._versions=self.plan
        body=json.dumps({'discovery':base64.b64encode(ET.tostring(self.root)).decode(),
                         'capabilities':base64.b64encode(json.dumps(self.caps).encode()).decode()})
        d.jail=Mock(return_value=SimpleNamespace(stdout=body,returncode=0))
        target={'state':'Running (123)'}
        with tempfile.TemporaryDirectory() as temp,patch('installer.office_vm.native_vm_identity',return_value=target), \
                patch('installer.office_vm._vm_network_ready') as network, \
                patch('installer.office_vm.verify_collabora_container') as runtime:
            d.state=Path(temp)
            atomic_json(d.state/'collabora-proof.json',{'schema_version':2,'config_sha256':config_digest(self.c),
                        'public_sha256':'a'*64,'public_key_sha256':self.check()['public_key_sha256']})
            result=d.read_collabora_endpoints()
        network.assert_called_once_with(d,target);runtime.assert_called_once_with(d)
        self.assertEqual(result,self.check())
        args=d.jail.call_args.args
        self.assertEqual(args[:3],(self.c.nextcloud_jail,'python3','-c'))
        self.assertEqual(args[-1],self.c.onlyoffice_ip)
        self.assertIn('ProxyHandler({})',args[3])
        self.assertIn('NoRedirect()',args[3])
        self.assertIn('body=response.read(limit+1)',args[3])
        self.assertTrue(d.jail.call_args.kwargs['hide_output'])
        self.assertEqual(d.jail.call_args.kwargs['timeout'],135)

    def test_stopped_or_uncertain_runtime_prevents_endpoint_fetch(self):
        d=object.__new__(Deployment);d.config=self.c;d._versions=self.plan;d.jail=Mock()
        with patch('installer.office_vm.native_vm_identity',return_value={'state':'Stopped'}), \
                self.assertRaisesRegex(ValueError,'not running'):
            d.read_collabora_endpoints()
        d.jail.assert_not_called()
