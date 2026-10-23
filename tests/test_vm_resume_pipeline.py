"""VM phase replay wrappers and bootstrap checks; no native packages or guests."""
from pathlib import Path
import io
import hashlib
import json
import os
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, PropertyMock, patch

from installer.config import Config
from installer.deploy import Deployment
from installer.office_vm import vm_paths, verify_native_guest_bootstrap
from installer.state import atomic_json


class VmResumePipelineTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='vm-pipeline-resume-');self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.enterContext(patch.object(Config,'mount_root',new_callable=PropertyMock,return_value=str(self.root/'instance')))
        self.c=Config.from_json((Path(__file__).resolve().parents[1]/'examples/eurooffice.json').read_text())
        self.d=object.__new__(Deployment);self.d.config=self.c;self.d.state=self.root/'state';self.d.state.mkdir(mode=0o700)

    def test_sealed_creation_needs_identity_not_old_acquisition_cache(self):
        paths=vm_paths(self.c)
        atomic_json(self.d.state/(paths['name']+'.creating.json'),{'vm_config_sha256':'model-seal'})
        with patch('installer.office_vm.native_vm_identity') as identity,patch('installer.office_vm.acquire_guest_image') as fetch:
            self.d.prepare_office_vm_image()
        identity.assert_called_once_with(self.d)
        fetch.assert_not_called()
        self.assertIsNone(self.d._vm_image)

    def test_uncertain_partial_root_refuses_before_acquisition_or_mutation(self):
        paths=vm_paths(self.c);Path(paths['root']).mkdir(parents=True)
        with patch('installer.office_vm.acquire_guest_image') as fetch,self.assertRaisesRegex(ValueError,'before host mutations'):
            self.d.prepare_office_vm_image()
        fetch.assert_not_called()

    def test_completed_phase_uses_readonly_bootstrap_and_existing_container_policy(self):
        with patch('installer.office_vm.verify_native_guest_bootstrap') as verify:
            self.d.check_office_vm_bootstrap()
        verify.assert_called_once_with(self.d)
        with patch('installer.office_vm.install_eurooffice_container') as install:
            self.d.continue_vm_office()
        install.assert_called_once_with(self.d,require_existing=True)

    def test_impossible_vm_checkpoint_order_refuses_before_resource_commands(self):
        self.d.runner=Mock()
        journal=SimpleNamespace(data={'steps':{'Alpine VM boot':{'state':'complete'}}})
        with self.assertRaisesRegex(ValueError,'inconsistent'):self.d.validate_resume(journal)
        self.assertEqual(self.d.runner.mock_calls,[])

    def test_existing_bootstrap_script_only_reads_saved_config_and_queries_local_daemon(self):
        result=SimpleNamespace(returncode=0,stdout='29.8.2\n')
        with patch('installer.office_vm.run_native_guest',return_value=result) as guest:
            self.assertEqual(verify_native_guest_bootstrap(self.d),'29.8.2')
        args=guest.call_args.args[1]
        self.assertTrue(guest.call_args.kwargs['read_only'])
        self.assertFalse(any(ord(c)<32 for c in args[2]))
        office=self.root/'office';office.mkdir(mode=0o700)
        daemon=self.root/'daemon.json'
        for name,value in (('docker-version.txt','29.8.2\n'),('packages.txt','docker-29.8.2-r0\n'),('daemon.json.expected','{"hosts":["unix:///var/run/docker.sock"]}')):
            p=office/name;p.write_text(value);p.chmod(0o600)
        daemon.write_bytes((office/'daemon.json.expected').read_bytes());daemon.chmod(0o600)
        runtime=self.root/'runtime.json';runtime.write_text('{}');runtime.chmod(0o600)
        receipt=office/'bootstrap-complete.json'
        receipt.write_text(json.dumps({'schema_version':1,'runtime_sha256':hashlib.sha256(runtime.read_bytes()).hexdigest(),
            'packages_sha256':hashlib.sha256((office/'packages.txt').read_bytes()).hexdigest(),
            'daemon_sha256':hashlib.sha256(daemon.read_bytes()).hexdigest(),'docker_version':'29.8.2'}));receipt.chmod(0o600)
        code=args[2].replace("Path('/var/lib/cloud-installer/office')",'Path('+repr(str(office))+')').replace("Path('/etc/docker/daemon.json')",'Path('+repr(str(daemon))+')').replace("Path('/root/cloud-installer/runtime.json')",'Path('+repr(str(runtime))+')').replace('s.st_uid==0','s.st_uid==os.geteuid()')
        def local(command,**kwargs):
            if command==['apk','info','-v']:return SimpleNamespace(returncode=0,stdout='docker-29.8.2-r0\n')
            self.assertEqual(command[-3:],['version','--format','{{.Server.Version}}'])
            self.assertIn('--host=unix:///var/run/docker.sock',command)
            self.assertNotIn('apk',command)
            return SimpleNamespace(returncode=0,stdout='29.8.2\n')
        with patch('subprocess.run',side_effect=local),patch('sys.stdout',io.StringIO()) as out:
            exec(compile(code,'existing-docker-bootstrap','exec'),{'os':os})
        self.assertEqual(out.getvalue(),'29.8.2\n')
        daemon.write_text('{"hosts":["tcp://0.0.0.0:2375"]}')
        with patch('subprocess.run') as query,self.assertRaises(AssertionError):
            exec(compile(code,'existing-docker-bootstrap','exec'),{'os':os})
        query.assert_not_called()
