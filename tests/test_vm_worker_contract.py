"""Shared NC framing for the two VM connectors; integration remains gated."""
from copy import deepcopy
import json
import shutil
import tempfile
import unittest

from installer import resolution, version_runtime
from test_versions import configuration
from test_vm_resolution import vm_metadata
from nextcloud_worker_fixtures import PHP, WORKER, run_php, run_version_lua, runtime


def payload(backend):
    c = configuration(office_backend=backend)
    plan = resolution.resolve(c, vm_metadata(c))
    packages = version_runtime.package_text(plan,'nextcloud')
    edges = version_runtime.dependency_text(plan,'nextcloud')
    r = runtime('external',port=9443)
    r['versions'] = version_runtime.runtime_versions(plan,packages,edges)
    return r, packages, edges


@unittest.skipUnless(PHP,'PHP >=8.1 unavailable')
class VmPHPFrameTests(unittest.TestCase):
    def test_exact_shared_vm_frame_preserves_real_peer_callbacks_and_no_fake_oo_version(self):
        for backend in ('eurooffice','collabora'):
            r,_,_ = payload(backend)
            with self.subTest(backend=backend):
                p = run_php('echo json_encode([$c,cloudTokens($c)]);', {'runtime':r})
                self.assertEqual(p.returncode,0,p.stderr)
                accepted,tokens = json.loads(p.stdout)
                self.assertEqual(accepted,r)
                self.assertEqual(tokens['ONLYOFFICE_IP'],r['onlyoffice_ip'])
                self.assertEqual(tokens['PHP_CALLBACK_CHILDREN'],2)
                self.assertNotIn('onlyoffice',r['versions'])
                for operation in ('cloudConnector([], $c);','cloudConnectorInstall($c);','cloudConnectorImport($c, []);'):
                    blocked = run_php(operation,{'runtime':r})
                    self.assertNotEqual(blocked.returncode,0)
                    if operation == 'cloudConnectorInstall($c);':
                        self.assertIn('connector',blocked.stderr.lower())
                    else:
                        self.assertIn('Invalid public configuration',blocked.stderr)

    def test_mismatched_app_extra_native_fields_and_secrets_fail_in_both_validators(self):
        for backend in ('eurooffice','collabora'):
            r,_,_ = payload(backend)
            for key,value in (('connector_app','onlyoffice'),('onlyoffice','9.4.0'),('jwt_secret','secret-canary'),
                              ('connector_sha256','not-a-digest')):
                changed=deepcopy(r); changed['versions'][key]=value
                with self.subTest(backend=backend,key=key),self.assertRaises(ValueError):
                    version_runtime.validate_runtime_versions(changed['versions'])
                result=run_php("echo 'accepted';",{'runtime':changed})
                self.assertNotEqual(result.returncode,0)
                self.assertEqual(result.stdout,'')
                self.assertNotIn('secret-canary',result.stderr)


@unittest.skipUnless(shutil.which('lua'),'Lua unavailable')
class VmLuaFrameTests(unittest.TestCase):
    def test_real_lua_accepts_only_nc_group_and_matching_integrated_app(self):
        with tempfile.TemporaryDirectory() as directory:
            for backend in ('eurooffice','collabora'):
                r,packages,edges=payload(backend)
                for group,document,accepted in (
                        ('nextcloud',r,True), ('onlyoffice',r,False),
                        ('nextcloud',{**r,'versions':{**r['versions'],'connector_app':'onlyoffice'}},False),
                        ('nextcloud',{**r,'versions':{**r['versions'],'onlyoffice':'9.4.0'}},False)):
                    with self.subTest(backend=backend,group=group,accepted=accepted):
                        result=run_version_lua(document,packages,edges,group,directory)
                        self.assertEqual(result.returncode==0,accepted,result.stderr)
                        if accepted:
                            self.assertTrue(result.stdout.startswith(backend+' latest '))
                            self.assertIn(r['versions']['connector_app'],result.stdout)

    def test_connector_readiness_and_code_activation_precede_cron(self):
        self.assertLess(WORKER.index('occ eurooffice:documentserver --check'),WORKER.index('occ background:cron'))
        self.assertLess(WORKER.index('occ richdocuments:activate-config'),WORKER.index('occ background:cron'))
        self.assertIn('--callback-url "$code_callback"',WORKER)
        self.assertIn('public_wopi_url',WORKER)
