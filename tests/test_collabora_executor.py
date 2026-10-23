"""CODE startup/continuation model; native image proof evidence remains separate."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from installer.config import Config
from installer.office_vm import install_collabora_container,verify_collabora_container,collabora_container_arguments,_CODE_ENTRYPOINT
from installer.resolution import resolve
from installer.state import Registry,config_digest,atomic_json
from test_vm_resolution import vm_metadata


class CollaboraExecutorTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='code-executor-');self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.registry=Registry(self.root/'registry');self.registry.initialize()
        self.c=Config.from_json((Path(__file__).resolve().parents[1]/'examples/collabora.json').read_text())
        self.state=self.registry.instance_path(self.c.instance);self.state.mkdir(mode=0o700)
        self.plan=resolve(self.c,vm_metadata(self.c));self.selected=collabora_container_arguments(self.c,self.plan)
        self.d=SimpleNamespace(config=self.c,registry=self.registry,state=self.state,versions=self.plan)
        self.image={'Id':'sha256:'+'a'*64,'RepoDigests':[self.selected['args'][-1]],'Os':'linux','Architecture':'amd64',
                    'Config':{'User':'1001','Entrypoint':_CODE_ENTRYPOINT,'Env':['PATH=/usr/bin:/bin'],'Volumes':None}}
        self.container=None;self.calls=[];self.options=[];self.cached=True;self.fail_start=False;self.normalized=False
        self.remote=self.enterContext(patch('installer.office_vm.run_native_guest',side_effect=self.command))
        self.prepare=self.enterContext(patch('installer.office_vm.prepare_collabora_configuration',side_effect=self.staging_receipts))

    def staging_receipts(self,*args,**kwargs):
        atomic_json(self.state/'collabora-proof.json',{'schema_version':2,'config_sha256':config_digest(self.c),
                    'public_sha256':'b'*64,'public_key_sha256':'d'*64})
        atomic_json(self.state/'collabora-configuration.json',{'schema_version':1,'config_sha256':config_digest(self.c),
                    'source_sha256':self.selected['configuration_sha256'],'xml_sha256':'c'*64,'ca_sha256':None})

    def record(self):
        return {'Name':'/'+self.c.instance+'office','Image':self.image['Id'],
            'Config':{'Image':self.selected['args'][-1].removeprefix('docker.io/') if self.normalized else self.selected['args'][-1],'User':'1001','Entrypoint':_CODE_ENTRYPOINT,'Cmd':None,
                      'Env':self.image['Config']['Env'][:],'Labels':{'org.cloud-installer.instance':self.c.instance,
                      'org.cloud-installer.config-sha256':config_digest(self.c)}},
            'HostConfig':{'Privileged':False,'NetworkMode':'default','PortBindings':{'9980/tcp':[{'HostIp':self.c.onlyoffice_ip,'HostPort':'8081'}]},
                'RestartPolicy':{'Name':'unless-stopped'},'LogConfig':{'Type':'json-file','Config':{'max-size':'10m','max-file':'3'}},
                'ExtraHosts':[self.c.public_hostname+':'+self.c.nextcloud_ip]},
            'Mounts':[{'Type':'bind','Source':source,'Destination':target,'RW':False} for source,target in self.selected['binds'].items()],
            'State':{'Status':'created'}}

    def command(self,d,args,**kwargs):
        args=tuple(args);self.calls.append(args);self.options.append(kwargs);value=None
        if args[:3]==('docker','container','inspect'):
            if self.container is None:return SimpleNamespace(returncode=1,stdout='[]',stderr='Error: No such container: '+args[-1])
            value=self.container
        elif args[:3]==('docker','image','inspect'):
            if not self.cached:return SimpleNamespace(returncode=1,stdout='[]',stderr='Error response from daemon: No such image: '+(args[-1].removeprefix('docker.io/') if self.normalized else args[-1]))
            value=self.image
        elif args[:2]==('docker','pull'):self.cached=True
        elif args[:2]==('docker','create'):self.container=self.record()
        elif args[:2]==('docker','start'):self.container['State']['Status']='exited' if self.fail_start else 'running'
        elif args[0]=='python3':
            return SimpleNamespace(returncode=0,stdout='verified-public-config-and-native-proof-metadata\n',stderr='')
        else:raise AssertionError(args)
        return SimpleNamespace(returncode=0,stdout=json.dumps([value]) if value else '',stderr='')

    def install(self,**kwargs):
        with self.registry.locked():return install_collabora_container(self.d,**kwargs)

    def test_one_shellfree_container_has_no_privilege_or_health_claim(self):
        self.cached=False
        result=self.install()
        self.assertEqual(result['state'],'running');self.assertFalse(result['discovery_verified']);self.assertFalse(result['editing_verified'])
        self.assertEqual(sum(a[:2]==('docker','create') for a in self.calls),1)
        self.assertEqual(sum(a[:2]==('docker','pull') for a in self.calls),1)
        self.prepare.assert_called_once_with(self.d,require_existing=False)
        for forbidden in ('/bin/sh','--privileged','--cap-add','JWT_SECRET','--entrypoint','--force'):
            self.assertNotIn(forbidden,repr(self.calls))

    def test_unreserved_existing_container_is_not_adopted_or_reconfigured(self):
        self.container=self.record()
        with self.assertRaisesRegex(ValueError,'refusing adoption'):self.install()
        self.prepare.assert_not_called()
        self.assertFalse((self.state/'collabora-container.json').exists())

    def test_native_default_registry_spelling_still_requires_same_pinned_image(self):
        self.normalized=True;self.cached=False
        self.image['RepoDigests']=[self.selected['args'][-1].removeprefix('docker.io/')]
        result=self.install();self.assertEqual(result['state'],'running')
        with self.registry.locked():result=verify_collabora_container(self.d)
        self.assertTrue(result['native_files_verified'])
        self.container['Config']['Image']=self.container['Config']['Image'].replace('collabora/code','other/code')
        with self.registry.locked(),self.assertRaises(ValueError):verify_collabora_container(self.d)

    def test_completed_retry_reuses_image_and_container_but_never_reconstructs_loss(self):
        self.install();self.calls.clear();self.prepare.reset_mock()
        self.install(require_existing=True)
        self.prepare.assert_called_once_with(self.d,require_existing=True)
        self.assertFalse(any(a[:2] in (('docker','pull'),('docker','create'),('docker','start')) for a in self.calls))
        self.container=None;self.prepare.reset_mock()
        with self.assertRaises(RuntimeError):self.install(require_existing=True)
        self.prepare.assert_not_called();self.assertIsNone(self.container)

    def test_writable_proof_root_user_privilege_or_env_drift_refuses_before_prepare(self):
        self.install();original=deepcopy(self.container)
        for failure in ('mount','user','privilege','environment','paused'):
            self.container=deepcopy(original);self.prepare.reset_mock()
            if failure=='mount':self.container['Mounts'][1]['RW']=True
            elif failure=='user':self.container['Config']['User']='0'
            elif failure=='privilege':self.container['HostConfig']['CapAdd']=['SYS_ADMIN']
            elif failure=='environment':self.container['Config']['Env'].append('aliasgroup1=https://unselected.example:443')
            else:self.container['State']['Status']='paused'
            with self.subTest(failure=failure),self.assertRaises(ValueError):self.install(require_existing=True)
            self.prepare.assert_not_called()

    def test_failed_start_preserves_container_selection_and_does_not_claim_discovery(self):
        self.fail_start=True
        with self.assertRaisesRegex(RuntimeError,'remain running'):self.install()
        self.assertTrue((self.state/'collabora-container.json').is_file())
        self.assertEqual(self.container['State']['Status'],'exited')
        self.assertFalse(any(a[:3]==('docker','container','rm') for a in self.calls))

    def test_verification_uses_only_readonly_inspection_and_public_hash_expectations(self):
        self.install();self.calls.clear();self.options.clear();self.prepare.reset_mock()
        with self.registry.locked():result=verify_collabora_container(self.d)
        self.assertTrue(result['native_files_verified']);self.assertFalse(result['discovery_verified'])
        self.prepare.assert_not_called()
        self.assertTrue(all(options['read_only'] for options in self.options))
        self.assertFalse(any(a[:2] in (('docker','pull'),('docker','start'),('docker','create')) for a in self.calls))
        data=[json.loads(options['input']) for options in self.options if 'input' in options]
        self.assertEqual(set(data[0]),{'xml_sha256','ca_sha256','public_sha256'})

    def test_verification_never_starts_stopped_container_or_rebuilds_missing_file_receipts(self):
        self.install();self.container['State']['Status']='exited';self.calls.clear()
        with self.registry.locked(),self.assertRaisesRegex(ValueError,'never starts'):verify_collabora_container(self.d)
        self.assertFalse(any(a[:2]==('docker','start') for a in self.calls))
        self.container['State']['Status']='running'
        (self.state/'collabora-proof.json').rename(self.root/'retained-proof-identity')
        self.calls.clear()
        with self.registry.locked(),self.assertRaises(OSError):verify_collabora_container(self.d)
        self.assertEqual(self.calls,[])
