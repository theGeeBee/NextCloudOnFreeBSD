"""Backend-specific pure settings, independent of unfinished live activation."""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import unittest

from installer.config import Config
from installer.office_vm import vm_connector_settings, vm_apache_proxy
from installer.office_vm import collabora_container_arguments
from installer.resolution import resolve
from test_vm_resolution import vm_metadata
from urllib.parse import urljoin
from nextcloud_worker_fixtures import PHP, run_php
from test_vm_worker_contract import payload


class VmConnectorSettingsTests(unittest.TestCase):
    def config(self,backend,external=False):
        root=Path(__file__).resolve().parents[1]
        c=Config.from_json((root/'examples'/(backend+'.json')).read_text())
        return replace(c,public_https_port=9443,**(dict(tls_mode='external',proxy_networks='192.0.2.9/32',http_port=8080) if external else {}))

    def test_backend_url_roles_and_authentication_are_distinct(self):
        for external in (False,True):
            euro=self.config('eurooffice',external)
            c=vm_connector_settings(euro,jwt_secret='a'*64)['apps']['eurooffice']
            self.assertEqual(c['DocumentServerUrl'],euro.public_url+'eurooffice/')
            self.assertEqual(c['DocumentServerInternalUrl'],'http://'+euro.onlyoffice_ip+':8081/')
            self.assertEqual(c['StorageUrl'],euro.storage_url)
            self.assertEqual(c['verify_peer_off'],'false')
            self.assertIn(':9443/',c['DocumentServerUrl'])
            code=self.config('collabora',external)
            c=vm_connector_settings(code)['apps']['richdocuments']
            self.assertEqual(c,{'wopi_url':'http://'+code.onlyoffice_ip+':8081/collabora/',
                'wopi_callback_url':code.storage_url,'wopi_allowlist':code.onlyoffice_ip+'/32'})
            self.assertNotIn('public_wopi_url',c)
            self.assertNotIn('jwt_secret',c)
            self.assertNotIn('disable_certificate_verification',c)

    def test_emitted_code_connector_discovery_url_equals_runtime_endpoint(self):
        c=self.config('collabora')
        settings=vm_connector_settings(c)['apps']['richdocuments']
        runtime=collabora_container_arguments(c,resolve(c,vm_metadata(c)))
        self.assertEqual(urljoin(settings['wopi_url'],'hosting/discovery'),
                         'http://'+c.onlyoffice_ip+':8081'+runtime['discovery_path'])

    def test_wrong_profile_missing_or_unexpected_credentials_are_refused_safely(self):
        for secret in (None,'short','a'*63,'secret-canary\n'):
            with self.assertRaises(ValueError) as caught:
                vm_connector_settings(self.config('eurooffice'),jwt_secret=secret)
            self.assertNotIn('secret-canary',str(caught.exception))
        with self.assertRaises(ValueError): vm_connector_settings(self.config('collabora'),jwt_secret='a'*64)
        for backend in ('onlyoffice','none'):
            c=replace(self.config('eurooffice'),office_backend=backend)
            with self.assertRaises(ValueError): vm_connector_settings(c)

    def test_euro_proxy_preserves_public_authority_scoped_path_and_internal_denial(self):
        for external in (False,True):
            c=self.config('eurooffice',external)
            text=vm_apache_proxy(c)
            self.assertIn('RedirectMatch 308 ^/eurooffice$ /eurooffice/',text)
            self.assertIn('X-Forwarded-Host "'+c.public_hostname+':9443/eurooffice"',text)
            self.assertIn('X-Forwarded-Proto "https"',text)
            self.assertIn('RequestHeader unset X-Forwarded-Prefix',text)
            self.assertIn('ProxyAddHeaders Off',text)
            self.assertIn('http://'+c.onlyoffice_ip+':8081/ upgrade=websocket',text)
            self.assertIn('(?:internal|info|admin|example)',text)
            self.assertIn('Require all denied',text)
            self.assertNotIn('/onlyoffice',text)
            self.assertNotIn('127.0.0.1',text)
            self.assertNotIn('Listen ',text)
            self.assertNotIn('SSLEngine',text)
        code=self.config('collabora')
        proxy=vm_apache_proxy(code)
        self.assertIn('AllowEncodedSlashes NoDecode',proxy)
        self.assertIn('http://'+code.onlyoffice_ip+':8081/collabora/ nocanon upgrade=websocket',proxy)
        self.assertIn('X-Forwarded-Host "'+code.public_hostname+':9443"',proxy)
        self.assertNotIn(code.public_hostname+':9443/collabora',proxy)
        self.assertIn('adminws|convert-to|insertfile|getMetrics',proxy)
        self.assertNotIn('/eurooffice',proxy)

    @unittest.skipUnless(PHP,'PHP >=8.1 unavailable')
    def test_python_php_exact_settings_agree_and_refuse_widened_trust(self):
        for backend in ('eurooffice','collabora'):
            for external in (False,True):
                c=self.config(backend,external)
                settings=vm_connector_settings(c,**({'jwt_secret':'a'*64} if backend=='eurooffice' else {}))
                runtime,_,_=payload(backend)
                runtime.update(public_url=c.public_url,storage_url=c.storage_url,tls_mode=c.tls_mode,
                               public_hostname=c.public_hostname,nextcloud_ip=c.nextcloud_ip,onlyoffice_ip=c.onlyoffice_ip,
                               proxy_networks=list(c.trusted_proxy_networks),acme_email=c.acme_email)
                result=run_php('echo json_encode(cloudVmConnector($p["settings"],$c));',{'runtime':runtime,'settings':settings})
                self.assertEqual(result.returncode,0,result.stderr)
                app=runtime['versions']['connector_app']
                self.assertEqual(json.loads(result.stdout),settings['apps'][app])
                for key,value in ((('verify_peer_off','true') if backend=='eurooffice' else ('wopi_allowlist','0.0.0.0/0')),
                                  (('StorageUrl','https://foreign.example/') if backend=='eurooffice' else ('wopi_callback_url','https://foreign.example/')),
                                  ('public_wopi_url','https://fake-discovery.example/')):
                    bad=deepcopy(settings);bad['apps'][app][key]=value
                    result=run_php('cloudVmConnector($p["settings"],$c);',{'runtime':runtime,'settings':bad})
                    self.assertNotEqual(result.returncode,0)
                    self.assertEqual(result.stdout,'')
