"""Explicit Euro Docker orchestration with guest commands mocked, no containers."""
from copy import deepcopy
from dataclasses import replace
import json
import io
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from installer.config import Config
from installer.office_vm import eurooffice_container_arguments, install_eurooffice_container, verify_eurooffice_container
from installer.resolution import resolve
from installer.state import Registry, atomic_json, config_digest
from test_vm_resolution import vm_metadata


class EuroExecutorTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='euro-executor-')
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.c=Config.from_json((Path(__file__).resolve().parents[1]/'examples/eurooffice.json').read_text())
        self.registry=Registry(self.root/'registry');self.registry.initialize()
        self.state=self.registry.instance_path(self.c.instance);self.state.mkdir(mode=0o700)
        self.plan=resolve(self.c,vm_metadata(self.c))
        self.selected=eurooffice_container_arguments(self.c,self.plan)
        self.d=SimpleNamespace(config=self.c,versions=self.plan,state=self.state,registry=self.registry,
                               secrets={'jwt_secret':'c'*64,'db_password':'secret-canary'})
        self.calls=[];self.volumes={};self.container=None;self.proof=False;self.hash=self.selected['entrypoint_sha256']
        self.image=dict(Id='sha256:'+'a'*64,RepoDigests=[self.plan['office_runtime']['container']['reference']],
                        Architecture='amd64',Os='linux',Config={'Entrypoint':['/entrypoint.sh']})
        self.fail_start=False
        self.cached=False
        self.remote=self.enterContext(patch('installer.office_vm.run_native_guest',side_effect=self.run_guest))
        self.stage=self.enterContext(patch('installer.office_vm._stage_native_guest_public'))

    def volume(self,name):
        return dict(Name=name,Driver='local',Labels={'org.cloud-installer.instance':self.c.instance,
              'org.cloud-installer.config-sha256':config_digest(self.c)},Options=None)

    def record(self):
        args=self.selected['args']
        mounts=[{'Type':'volume','Name':name,'Destination':target,'RW':True} for name,target in self.selected['volumes'].items()]
        mounts +=[{'Type':'bind','Source':name,'Destination':target,'RW':True} for name,target in self.selected['binds'].items()]
        if self.c.ca_file:
            mounts.append({'Type':'bind','Source':'/var/lib/cloud-installer/office/nextcloud-ca.pem',
                           'Destination':'/etc/euro-office/nextcloud-ca.pem','RW':False})
        return dict(Name='/'+self.c.instance+'office',Image=self.image['Id'],Config=dict(
            Image=self.plan['office_runtime']['container']['reference'],Entrypoint=['/entrypoint.sh'],
            Labels={'org.cloud-installer.instance':self.c.instance,'org.cloud-installer.config-sha256':config_digest(self.c)},
            Env=[args[i+1] for i,arg in enumerate(args) if arg=='--env']),
            HostConfig=dict(Privileged=False,NetworkMode='default',PortBindings={'80/tcp':[{'HostIp':self.c.onlyoffice_ip,'HostPort':'8081'}]},
                            RestartPolicy={'Name':'unless-stopped'},LogConfig={'Type':'json-file','Config':{'max-size':'10m','max-file':'3'}},
                            ExtraHosts=[args[i+1] for i,arg in enumerate(args) if arg=='--add-host']),
            Mounts=mounts,State={'Status':'created'})

    def run_guest(self,d,args,**kwargs):
        args=tuple(args);self.calls.append((args,kwargs));value=None
        if args[:3]==('docker','container','inspect'):
            if self.container is None:
                return SimpleNamespace(returncode=1,stdout='[]\n',stderr='Error: No such container: '+args[-1]+'\n')
            value=self.container
        elif args[:3]==('docker','volume','inspect'):
            if args[-1] not in self.volumes:
                return SimpleNamespace(returncode=1,stdout='[]\n',stderr='Error response from daemon: get '+args[-1]+': no such volume\n')
            value=self.volumes[args[-1]]
        elif args[:3]==('docker','volume','create'):self.volumes[args[-1]]=self.volume(args[-1])
        elif args[:3]==('docker','image','inspect'):
            if not self.cached:
                return SimpleNamespace(returncode=1,stdout='[]\n',stderr='Error response from daemon: No such image: '+args[-1]+'\n')
            value=self.image
        elif args[:2]==('docker','create'):self.container=self.record()
        elif args[:2]==('docker','start'):self.container['State']['Status']='exited' if self.fail_start else 'running'
        elif args[:2]==('docker','cp'):self.proof=True
        elif args[:3]==('docker','exec',self.c.instance+'office'):
            return SimpleNamespace(returncode=0,stdout=self.hash+'  /entrypoint.sh\n',stderr='')
        elif args[0]=='python3' and 'print(digest)' in args[2]:
            return SimpleNamespace(returncode=0,stdout=self.hash+'\n',stderr='')
        elif args[:2]==('docker','pull'):self.cached=True
        elif args[0] in ('chmod','python3'):pass
        else:raise AssertionError('Unexpected guest operation '+repr(args))
        return SimpleNamespace(returncode=0,stdout=json.dumps([value]) if value is not None else '',stderr='')

    def install(self,**kwargs):
        with self.registry.locked():return install_eurooffice_container(self.d,**kwargs)

    def test_one_owned_container_native_volumes_private_jwt_and_no_health_claim(self):
        result=self.install()
        self.assertEqual(result['state'],'running')
        self.assertFalse(result['health_verified'])
        self.assertFalse(result['editing_verified'])
        argv=repr([args for args,kwargs in self.calls])
        self.assertFalse(any(any(ord(c)<32 for c in arg) for args,kwargs in self.calls for arg in args))
        self.assertNotIn('c'*64,argv)
        self.assertNotIn('secret-canary',repr(self.calls))
        secret_inputs=[kwargs['input'] for args,kwargs in self.calls if 'input' in kwargs]
        self.assertEqual([json.loads(value) for value in secret_inputs],[{'jwt_secret':'c'*64}])
        self.assertEqual(len(self.volumes),4)
        self.assertEqual(sum(args[:2]==('docker','create') for args,kwargs in self.calls),1)
        self.assertFalse(any('destroy' in args or 'rm' in args for args,kwargs in self.calls))
        public=json.loads(self.stage.call_args.args[2])
        self.assertNotIn('jwt_secret',public)
        self.assertNotIn('c'*64,self.stage.call_args.args[2])
        self.assertEqual(public['jwt_file'],self.selected['jwt_file'])

    def test_existing_unowned_container_or_volume_refuses_without_publishing_intent(self):
        self.container=self.record()
        with self.assertRaisesRegex(ValueError,'refusing adoption'):self.install()
        self.assertFalse((self.state/'eurooffice-container.json').exists())
        self.container=None
        self.volumes[next(iter(self.selected['volumes']))]=self.volume(next(iter(self.selected['volumes'])))
        with self.assertRaisesRegex(ValueError,'refusing adoption'):self.install()
        self.assertFalse((self.state/'eurooffice-container.json').exists())
        self.stage.assert_not_called()

    def test_receipted_running_retry_never_replaces_container_volumes_or_source_proof(self):
        self.install();self.calls.clear()
        self.install(require_existing=True)
        for args,kwargs in self.calls:
            self.assertNotEqual(args[:2],('docker','create'))
            self.assertNotEqual(args[:2],('docker','cp'))
            self.assertNotEqual(args[:2],('docker','start'))
            self.assertNotEqual(args[:3],('docker','volume','create'))
            self.assertNotEqual(args[:2],('docker','pull'))

    def test_changed_mounts_env_or_privilege_refuses_before_credential_write(self):
        self.install()
        original=deepcopy(self.container)
        for failure in ('mount','env','privilege','command','paused'):
            self.container=deepcopy(original);self.calls.clear();self.stage.reset_mock()
            if failure=='mount':self.container['Mounts'][0]['Name']='unrelated'
            elif failure=='env':self.container['Config']['Env'].append('JWT_SECRET=unexpected')
            elif failure=='privilege':self.container['HostConfig']['Privileged']=True
            elif failure=='command':self.container['Config']['Cmd']=['unreviewed']
            else:self.container['State']['Status']='paused'
            with self.subTest(failure=failure),self.assertRaises(ValueError):self.install()
            self.stage.assert_not_called()

    def test_bad_entrypoint_or_failed_start_retains_owned_state_without_claiming_success(self):
        self.hash='f'*64
        with self.assertRaisesRegex(ValueError,'entrypoint differs'):self.install()
        self.assertEqual(self.container['State']['Status'],'created')
        self.assertTrue((self.state/'eurooffice-container.json').exists())
        self.assertFalse(any(args[:2]==('docker','start') for args,kwargs in self.calls))
        self.hash=self.selected['entrypoint_sha256'];self.fail_start=True
        with self.assertRaisesRegex(RuntimeError,'remain running'):self.install()
        self.assertEqual(len(self.volumes),4)

    def test_daemon_error_is_not_misclassified_as_absent_container(self):
        self.remote.side_effect=lambda *args,**kwargs:SimpleNamespace(returncode=1,stdout='[]\n',stderr='Cannot connect to the Docker daemon')
        with self.assertRaises(RuntimeError):self.install()
        self.assertFalse((self.state/'eurooffice-container.json').exists())
        self.stage.assert_not_called()

    def test_unselected_image_environment_override_is_refused_before_start(self):
        self.install()
        self.container['State']['Status']='exited'
        self.container['Config']['Env'].append('EO_ROOT=/unreviewed')
        self.calls.clear()
        with self.assertRaisesRegex(ValueError,'unselected image defaults'):self.install()
        self.assertFalse(any(args[:2]==('docker','start') for args,kwargs in self.calls))

    def test_ca_file_cannot_smuggle_private_key_into_guest(self):
        ca=self.root/'invalid-ca.pem';ca.write_text('-----BEGIN PRIVATE KEY-----\nprivate-canary\n')
        self.c=replace(self.c,ca_file=str(ca))
        self.plan=resolve(self.c,vm_metadata(self.c));self.selected=eurooffice_container_arguments(self.c,self.plan)
        self.d.config=self.c;self.d.versions=self.plan
        with self.assertRaisesRegex(ValueError,'private key'):self.install()
        self.assertNotIn('private-canary',repr(self.calls))
        self.assertFalse(any(args[:2]==('docker','pull') for args,kwargs in self.calls))

    def test_completed_native_ca_loss_is_not_reconstructed(self):
        ca=self.root/'public-ca.pem';ca.write_text('-----BEGIN CERTIFICATE-----\npublic-fixture\n')
        self.c=replace(self.c,ca_file=str(ca));self.plan=resolve(self.c,vm_metadata(self.c))
        self.selected=eurooffice_container_arguments(self.c,self.plan);self.d.config=self.c;self.d.versions=self.plan
        self.install(require_existing=False)
        args,kwargs=next((args,options) for args,options in self.calls if options.get('input')==ca.read_text())
        target=self.root/'guest-public-ca.pem'
        code=args[2].replace("Path('/var/lib/cloud-installer/office/nextcloud-ca.pem')",'Path('+repr(str(target))+')').replace('s.st_uid==0','s.st_uid==os.geteuid()')
        with patch('sys.stdin',io.StringIO(ca.read_text())),patch('sys.argv',['-','existing']),self.assertRaises(AssertionError):
            exec(compile(code,'completed-ca-loss','exec'),{})
        self.assertFalse(target.exists())

    def test_real_private_file_preparation_preserves_secret_and_refuses_changed_or_public_file(self):
        self.install()
        args,options=next((args,kwargs) for args,kwargs in self.calls if 'input' in kwargs)
        target=self.root/'guest-office';target.mkdir(mode=0o700)
        code=args[2].replace("Path('/var/lib/cloud-installer/office')",'Path('+repr(str(target))+')').replace('s.st_uid==0','s.st_uid==os.geteuid()')
        def prepare(value,mode='initial'):
            before=os.umask(0o077)
            try:
                with patch('sys.stdin',io.StringIO(value)),patch('sys.argv',['-',mode]):exec(compile(code,'guest-private-file-preparation','exec'),{})
            finally:os.umask(before)
        prepare(options['input'])
        secret=target/'volumes/data/.private/jwt_secret'
        self.assertEqual(secret.read_text(),'c'*64)
        self.assertEqual(secret.stat().st_mode & 0o777,0o600)
        before=secret.stat().st_mtime_ns
        prepare(options['input'])
        self.assertEqual(secret.stat().st_mtime_ns,before)
        with self.assertRaises(AssertionError):prepare(json.dumps({'jwt_secret':'d'*64}))
        self.assertEqual(secret.read_text(),'c'*64)
        secret.chmod(0o644)
        with self.assertRaises(AssertionError):prepare(options['input'])
        secret.chmod(0o600);secret.rename(self.root/'retained-native-jwt')
        with self.assertRaises(AssertionError):prepare(options['input'],'existing')
        self.assertFalse(secret.exists())

    def test_source_proof_is_recopied_and_hash_checked_without_replacing_retained_evidence(self):
        import hashlib
        self.install()
        args=next(args for args,kwargs in self.calls if args[0]=='python3' and 'print(digest)' in args[2])
        target=self.root/'source-proof';target.mkdir(mode=0o700)
        code=args[2].replace("Path('/var/lib/cloud-installer/office')",'Path('+repr(str(target))+')').replace('s.st_uid==0','s.st_uid==os.geteuid()')
        original=b'reviewed public entrypoint'
        digest=hashlib.sha256(original).hexdigest()
        def copied(command,**kwargs):
            Path(command[-1]).write_bytes(original)
            return SimpleNamespace(returncode=0)
        for iteration in range(2):
            with patch('subprocess.run',side_effect=copied) as native,patch('sys.argv',['-',self.c.instance+'office',digest]),patch('sys.stdout',io.StringIO()):
                exec(compile(code,'guest-entrypoint-proof','exec'),{})
            native.assert_called_once()
            self.assertEqual(native.call_args.kwargs['timeout'],20)
        proof=target/'eurooffice-image-entrypoint.sh'
        self.assertEqual(proof.read_bytes(),original)
        self.assertEqual(proof.stat().st_nlink,1)
        self.assertEqual(proof.stat().st_mode & 0o777,0o600)
        def changed(command,**kwargs):
            Path(command[-1]).write_bytes(b'changed running filesystem')
            return SimpleNamespace(returncode=0)
        with patch('subprocess.run',side_effect=changed),patch('sys.argv',['-',self.c.instance+'office',digest]),patch('sys.stdout',io.StringIO()) as out:
            exec(compile(code,'guest-entrypoint-proof','exec'),{})
        self.assertNotEqual(out.getvalue().strip(),digest)
        self.assertEqual(proof.read_bytes(),original)
        self.assertEqual(len(list(target.glob('entrypoint-check-*'))),1) # Mismatch retained privately.

    def test_verification_is_inspection_only_and_does_not_require_application_credentials(self):
        self.install();self.calls.clear();self.stage.reset_mock();self.d.secrets=None
        path=self.state/'eurooffice-container.json';before=path.stat().st_mtime_ns
        with self.registry.locked():result=verify_eurooffice_container(self.d)
        self.assertEqual(result['state'],'running')
        self.stage.assert_not_called()
        self.assertEqual(path.stat().st_mtime_ns,before)
        for args,kwargs in self.calls:
            self.assertTrue(kwargs['read_only'])
            self.assertTrue(args[:3] in (('docker','image','inspect'),('docker','container','inspect'),('docker','volume','inspect'))
                            or args[:2]==('docker','exec'))

    def test_verification_refuses_stopped_container_changed_volume_or_entrypoint_without_repair(self):
        self.install()
        self.container['State']['Status']='exited'
        with self.registry.locked(),self.assertRaisesRegex(ValueError,'never starts'):verify_eurooffice_container(self.d)
        self.container['State']['Status']='running'
        volume=next(iter(self.volumes));self.volumes[volume]['Labels']={}
        with self.registry.locked(),self.assertRaisesRegex(ValueError,'never adopts'):verify_eurooffice_container(self.d)
        self.volumes[volume]=self.volume(volume)
        self.hash='f'*64
        with self.registry.locked(),self.assertRaisesRegex(ValueError,'entrypoint differs'):verify_eurooffice_container(self.d)

    def test_completed_container_or_volume_deletion_refuses_reconstruction(self):
        self.install();previous=self.container;self.container=None;self.stage.reset_mock()
        with self.assertRaises(RuntimeError):self.install(require_existing=True)
        self.assertIsNone(self.container)
        self.container=previous
        lost=self.volumes.pop(next(iter(self.volumes)))
        with self.assertRaises(RuntimeError):self.install(require_existing=True)
        self.assertNotIn(lost['Name'],self.volumes)
        self.stage.assert_not_called()
