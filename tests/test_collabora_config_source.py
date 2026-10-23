"""Stopped source-object and public-cache boundaries; Docker/image bytes mocked."""
import hashlib
import json
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from installer.config import Config
from installer.office_vm import collabora_default_configuration, _CODE_ENTRYPOINT
from installer.state import Registry


class CollaboraConfigSourceTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='code-source-');self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.registry=Registry(self.root/'registry');self.registry.initialize()
        self.c=Config.from_json((Path(__file__).resolve().parents[1]/'examples/collabora.json').read_text())
        self.state=self.registry.instance_path(self.c.instance);self.state.mkdir(mode=0o700)
        self.ref='docker.io/collabora/code@sha256:'+'a'*64
        self.d=SimpleNamespace(config=self.c,state=self.state,registry=self.registry,
                               versions={'office_runtime':{'container':{'reference':self.ref}}})
        self.xml='<config><public-example /></config>\n'
        self.hash=hashlib.sha256(self.xml.encode()).hexdigest()
        # Candidate policy validation has independent tests; this fixture binds
        # synthetic XML to a real hash without mocking the checksum decision.
        self.enterContext(patch('installer.office_vm.collabora_container_arguments',return_value={'configuration_sha256':self.hash}))
        self.image=dict(Id='sha256:'+'b'*64,RepoDigests=[self.ref],Architecture='amd64',Os='linux',
                        Config={'User':'1001','Entrypoint':_CODE_ENTRYPOINT,'Volumes':None})
        self.identity='c'*64;self.source=None;self.calls=[];self.bad_hash=False;self.changed_source=False
        self.remote=self.enterContext(patch('installer.office_vm.run_native_guest',side_effect=self.run_guest))

    def run_guest(self,d,args,**kwargs):
        args=tuple(args);self.calls.append(args)
        self.assertFalse(any(any(ord(c)<32 for c in value) for value in args))
        if args[:3]==('docker','image','inspect'):
            value=[self.image]
        elif args[:2]==('docker','create'):
            name=args[args.index('--name')+1]
            self.source=dict(Id=self.identity,Name='/'+name,Image=self.image['Id'],
                             Config={'Image':self.ref,'Labels':{'org.cloud-installer.source':self.hash}},
                             HostConfig={'NetworkMode':'none','ReadonlyRootfs':True,'Privileged':False,'PortBindings':{}},
                             Mounts=[],State={'Status':'created','Running':False})
            return SimpleNamespace(returncode=0,stdout=self.identity+'\n',stderr='')
        elif args[:3]==('docker','container','inspect'):
            value=[self.source]
            if self.changed_source:value=[{**self.source,'State':{'Status':'running','Running':True}}]
        elif args[0]=='python3':
            return SimpleNamespace(returncode=0,stdout=json.dumps({'sha256':self.hash,'xml':self.xml+'changed' if self.bad_hash else self.xml}),stderr='')
        elif args[:3]==('docker','container','rm'):
            self.assertEqual(args[-1],self.identity)
            return SimpleNamespace(returncode=0,stdout=self.identity,stderr='')
        else:raise AssertionError(args)
        return SimpleNamespace(returncode=0,stdout=json.dumps(value),stderr='')

    def acquire(self,**kwargs):
        with self.registry.locked():return collabora_default_configuration(self.d,**kwargs)

    def test_source_is_never_started_and_only_verified_created_id_removed(self):
        self.assertEqual(self.acquire(),self.xml)
        creates=[a for a in self.calls if a[:2]==('docker','create')]
        self.assertEqual(len(creates),1)
        self.assertIn('--read-only',creates[0])
        self.assertEqual(creates[0][creates[0].index('--network')+1],'none')
        self.assertFalse(any(a[:2] in (('docker','start'),('docker','run')) or '--force' in a for a in self.calls))
        self.assertEqual([a for a in self.calls if a[:3]==('docker','container','rm')],[('docker','container','rm',self.identity)])
        cache=self.state/'collabora-default.xml'
        self.assertEqual(cache.stat().st_mode & 0o777,0o600)
        self.calls.clear()
        self.assertEqual(self.acquire(require_existing=True),self.xml)
        self.assertEqual(self.calls,[])

    def test_changed_or_missing_completed_cache_cannot_be_downloaded_or_repaired(self):
        with self.assertRaisesRegex(ValueError,'no source reconstruction'):self.acquire(require_existing=True)
        self.assertEqual(self.calls,[])
        self.acquire();cache=self.state/'collabora-default.xml';cache.write_text('changed')
        self.calls.clear()
        with self.assertRaisesRegex(ValueError,'never overwritten'):self.acquire()
        self.assertEqual(cache.read_text(),'changed');self.assertEqual(self.calls,[])

    def test_wrong_source_hash_retains_stopped_object_and_diagnostic_without_new_retry_object(self):
        self.bad_hash=True
        with self.assertRaisesRegex(ValueError,'extraction mismatch'):self.acquire()
        self.assertFalse(any(a[:3]==('docker','container','rm') for a in self.calls))
        failure=json.loads((self.state/'collabora-source-failure.json').read_text())
        self.assertEqual(failure['container_id'],self.identity)
        self.calls.clear()
        with self.assertRaisesRegex(ValueError,'explicit inspection'):self.acquire()
        self.assertEqual(self.calls,[])

    def test_source_object_state_change_refuses_copy_and_cleanup(self):
        self.changed_source=True
        with self.assertRaisesRegex(ValueError,'identity changed'):self.acquire()
        self.assertFalse(any(a[0]=='python3' or a[:3]==('docker','container','rm') for a in self.calls))

    def test_diagnostic_write_failure_does_not_mask_original_source_mismatch(self):
        self.bad_hash=True
        with patch('installer.state.atomic_json',side_effect=OSError('controlled disk failure')),patch('sys.stderr',io.StringIO()) as error:
            with self.assertRaisesRegex(ValueError,'extraction mismatch'):self.acquire()
        self.assertIn('Could not save CODE source diagnostics',error.getvalue())
        self.assertFalse(any(a[:3]==('docker','container','rm') for a in self.calls))
