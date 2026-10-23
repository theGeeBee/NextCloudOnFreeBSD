"""Frozen public rc payload publication under mapped private test directories."""
from dataclasses import replace
import json
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, PropertyMock, patch

from installer.config import Config
from installer.deploy import ROOT, Deployment, COMPLETE_MESSAGE
from installer.maintenance_staging import _source
from installer.office_vm import publish_vm_boot_service, disable_vm_boot_service, vm_paths, _BOOT_SOURCE_CHECK
from installer.state import Registry, atomic_json, atomic_write, config_digest, private_json


class VmBootPublicationTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='vm-boot-publication-');self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.enterContext(patch.object(Config,'bastille_root',new_callable=PropertyMock,return_value=str(self.root/'shared/bastille')))
        self.c=replace(Config.from_json((ROOT/'examples/eurooffice.json').read_text()),office_vm_cpus=2,office_vm_disk_gib=16,office_memory_mb=4096)
        self.registry=Registry(self.root/'registry');self.registry.initialize()
        self.state=self.registry.instance_path(self.c.instance);self.state.mkdir(mode=0o700)
        self.paths=vm_paths(self.c);Path(self.paths['manager_root']).mkdir(parents=True,mode=0o700)
        self.rcdir=self.root/'rc.d';self.rcdir.mkdir(mode=0o700)
        self.enterContext(patch('installer.office_vm.VM_RC_DIRECTORY',self.rcdir))
        self.identity=self.enterContext(patch('installer.office_vm.native_vm_identity',return_value={'state':'Running (123)'}))
        self.network=self.enterContext(patch('installer.office_vm._vm_network_ready'))
        self.context=self.enterContext(patch('installer.office_vm._vm_rc_context',return_value=(self.rcdir,)))
        self.source_hash=_source(ROOT)[1]
        atomic_write(self.state/'source.sha256',self.source_hash+'\n')
        self.journal=dict(schema_version=self.c.schema_version,config_sha256=config_digest(self.c),steps={
            'office VM restart persistence':{'state':'complete'},'jail restart persistence':{'state':'complete'},
            'readiness checks':{'state':'complete'},'boot activation':{'state':'running'}})
        atomic_json(self.state/'deployment.json',self.journal)
        self.d=SimpleNamespace(config=self.c,state=self.state,registry=self.registry,runner=Mock(),
                               require_original_artifact=Mock(),require_running_jail=Mock())

    def publish(self):
        with self.registry.locked():return publish_vm_boot_service(self.d)

    def deployment_model(self):
        from installer.resolution import resolve
        from test_vm_resolution import vm_metadata
        d=object.__new__(Deployment);d.__dict__.update(self.d.__dict__)
        d._versions=resolve(self.c,vm_metadata(self.c));d.manifest={};d.progress=None
        for name in ('prepare_plugins','verify_source','validate_resume','prepare_office_vm_image',
                     'create_shared_storage','install_manager','create_storage','configure_network',
                     'configure_devfs','bootstrap_jails','attach_storage','create_office_vm','start_office_vm',
                     'bootstrap_office_vm','install_vm_office','stage_payloads','install_nextcloud',
                     'nextcloud_phase','integrate','restart_office_vm','restart_jails','initial_readiness',
                     'check_office_vm_bootstrap','continue_vm_office','verify'):
            setattr(d,name,Mock())
        atomic_json(self.state/'config.json',json.loads(self.c.to_json()))
        atomic_json(self.state/'deployment.json',{'schema_version':self.c.schema_version,
                    'config_sha256':config_digest(self.c),'steps':{}})
        return d

    def test_public_only_copy_bound_service_clean_environment_and_preimport_hash_check(self):
        receipt=self.publish()
        runtime=Path(receipt['runtime_root']);service=Path(receipt['service_path'])
        self.assertEqual(_source(runtime)[1],self.source_hash)
        self.assertEqual((runtime/'installer/vm_boot.py').stat().st_mode & 0o777,0o600)
        self.assertFalse((runtime/'secrets.json').exists())
        self.assertFalse((runtime/'state').exists())
        self.assertEqual(service.stat().st_mode & 0o777,0o755)
        self.assertIn('/usr/bin/env -i PATH=',service.read_text())
        self.assertNotIn('cd '+str(ROOT),service.read_text())
        self.assertEqual((self.state/'allow-vm-start').read_text(),config_digest(self.c)+'\n')
        self.d.runner.run.assert_called_once_with('sysrc','cloud_'+self.c.instance+'_office_enable=YES')
        check=subprocess.run([sys.executable,'-I','-S','-B','-c',_BOOT_SOURCE_CHECK,str(runtime),self.source_hash],capture_output=True,text=True)
        self.assertEqual(check.returncode,0,check.stderr)
        result=subprocess.run([sys.executable,'-S','-B','-c','import installer.vm_boot;print(installer.vm_boot.__file__)'],cwd=runtime,
                              env={'PATH':os.environ.get('PATH',''),'PYTHONDONTWRITEBYTECODE':'1'},capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout.strip(),str(runtime/'installer/vm_boot.py'))

    def test_missing_checks_or_changed_source_refuses_before_publication(self):
        self.journal['steps']['readiness checks']['state']='running'
        atomic_json(self.state/'deployment.json',self.journal)
        with self.assertRaisesRegex(ValueError,'completed integration'):self.publish()
        self.assertFalse((self.state/'vm-boot-service.json').exists())
        self.d.runner.run.assert_not_called()
        self.journal['steps']['readiness checks']['state']='complete'
        atomic_json(self.state/'deployment.json',self.journal)
        atomic_write(self.state/'source.sha256','f'*64+'\n')
        with self.assertRaisesRegex(ValueError,'original installer identity'):self.publish()
        self.d.runner.run.assert_not_called()

    def test_foreign_rc_file_or_payload_is_not_adopted_even_when_names_match(self):
        service=self.rcdir/('cloud_'+self.c.instance+'_office')
        service.write_text('retained administrator service\n')
        with self.assertRaisesRegex(ValueError,'refusing adoption'):self.publish()
        self.assertEqual(service.read_text(),'retained administrator service\n')
        self.assertFalse((self.state/'vm-boot-service.json').exists())

    def test_partial_public_copy_can_fill_missing_file_but_never_overwrites_changed_source(self):
        receipt=self.publish();runtime=Path(receipt['runtime_root'])
        unchanged=runtime/'installer/config.py';mtime=unchanged.stat().st_mtime_ns
        missing=runtime/'resources/vm/bootstrap.sh';missing.rename(self.root/'retained-bootstrap.sh')
        self.publish()
        self.assertEqual(unchanged.stat().st_mtime_ns,mtime)
        self.assertEqual(missing.read_bytes(),(ROOT/'resources/vm/bootstrap.sh').read_bytes())
        changed=runtime/'installer/vm_boot.py';changed.write_text('raise RuntimeError("changed source must not execute")\n')
        self.d.runner.reset_mock()
        with self.assertRaisesRegex(ValueError,'never overwritten'):self.publish()
        self.d.runner.run.assert_not_called()
        check=subprocess.run([sys.executable,'-I','-S','-B','-c',_BOOT_SOURCE_CHECK,str(runtime),self.source_hash],capture_output=True,text=True)
        self.assertNotEqual(check.returncode,0)
        self.assertNotIn('changed source must not execute',check.stderr)

    def test_unknown_private_file_refused_without_reading_or_exposing_its_contents(self):
        receipt=self.publish();runtime=Path(receipt['runtime_root'])
        unknown=runtime/'installer/.env';unknown.write_text('secret-canary')
        self.d.runner.reset_mock()
        with self.assertRaises(ValueError) as error:self.publish()
        self.assertNotIn('secret-canary',str(error.exception))
        self.assertEqual(unknown.read_text(),'secret-canary')
        self.d.runner.run.assert_not_called()

    def test_disable_withdraws_only_owned_flag_and_retains_code_data_and_service(self):
        receipt=self.publish();self.d.runner.reset_mock()
        with self.registry.locked():disable_vm_boot_service(self.d)
        self.d.runner.run.assert_called_once_with('sysrc','cloud_'+self.c.instance+'_office_enable=NO')
        self.assertTrue(Path(receipt['runtime_root']).is_dir())
        self.assertTrue(Path(receipt['service_path']).is_file())
        self.assertTrue((self.state/'vm-boot-service.json').is_file())

    def test_boot_activation_publishes_checked_vm_service_before_enabling_only_nc_jail(self):
        events=[]
        self.d.runner.run.side_effect=lambda *args,**kwargs:events.append(args)
        with self.registry.locked(),patch('installer.office_vm.publish_vm_boot_service',side_effect=lambda d:events.append(('publish-vm',))) as publish:
            Deployment.enable_boot(self.d)
        publish.assert_called_once_with(self.d)
        self.assertEqual(events,[('publish-vm',),('bastille','config',self.c.nextcloud_jail,'set','boot','on'),('sysrc','bastille_enable=YES')])

    def test_real_apply_journal_and_completion_message_are_accepted_by_boot_worker(self):
        from installer import vm_boot
        d=self.deployment_model()
        with self.registry.locked(),patch('installer.operations.configure_ssh'),patch('installer.initialization.checkpoint_initialization'):
            d.apply()
        self.assertEqual((self.state/'complete').read_text(),COMPLETE_MESSAGE)
        journal=private_json(self.state/'deployment.json')
        for name in ('Alpine VM creation','Alpine VM boot','guest Docker bootstrap','Euro-Office container',
                     'document integration','office VM restart persistence','jail restart persistence','readiness checks','boot activation'):
            self.assertEqual(journal['steps'][name]['state'],'complete')
        self.assertEqual(self.registry.status(self.c.instance)['state'],'ready')
        worker=SimpleNamespace(state=self.state,require_original_artifact=Mock(),require_running_jail=Mock())
        with patch.object(vm_boot,'require_host'),patch.object(vm_boot,'Deployment',return_value=worker),patch.object(vm_boot,'start_native_vm') as start:
            vm_boot.run('start',self.c.instance,registry=self.registry,runner=Mock())
        start.assert_called_once_with(worker)

    def test_failure_after_boot_publication_disables_only_owned_vm_and_nc_without_data_reset(self):
        d=self.deployment_model()
        d.checkpoint=Mock(side_effect=RuntimeError('private-canary'))
        atomic_json(self.state/(self.c.instance+'office.creating.json'),{'vm_config_sha256':'a'*64})
        atomic_json(self.state/(self.c.nextcloud_jail+'.creating.json'),{'model':'owned jail'})
        def command(*args,**kwargs):
            return SimpleNamespace(returncode=0,stdout=str(d.jail_root(self.c.nextcloud_jail)) if args[:2]==('bastille','config') and args[-2:]==('get','path') else '')
        self.d.runner.run.side_effect=command
        with self.registry.locked(),patch('installer.operations.configure_ssh'),patch('installer.initialization.checkpoint_initialization'), \
                patch('installer.office_vm.stop_native_vm') as stop,patch('sys.stderr',io.StringIO()) as error:
            with self.assertRaisesRegex(RuntimeError,'private-canary'):d.apply()
        stop.assert_called_once_with(d)
        commands=[call.args for call in self.d.runner.run.call_args_list]
        self.assertIn(('sysrc','cloud_'+self.c.instance+'_office_enable=NO'),commands)
        self.assertIn(('bastille','stop',self.c.nextcloud_jail),commands)
        self.assertFalse(any(self.c.onlyoffice_jail in args or 'destroy' in args or 'rollback' in args for args in commands))
        self.assertFalse((self.state/'allow-vm-start').exists())
        self.assertTrue((self.state/'allow-vm-start.disabled').exists())
        self.assertTrue((self.state/'vm-boot-service.json').is_file())
        self.assertEqual(self.registry.status(self.c.instance)['state'],'failed')
        self.assertNotIn('private-canary',error.getvalue()+json.dumps(self.registry.status(self.c.instance)))

    def test_vm_completion_marker_precedes_ready_status_so_interruption_stays_resumable(self):
        d=self.deployment_model()
        original=self.registry.set_status
        observed=[]
        def status(instance,state,**details):
            if state=='ready':
                observed.append((self.state/'complete').read_text())
                raise OSError('controlled ready-write failure')
            return original(instance,state,**details)
        with self.registry.locked(),patch.object(self.registry,'set_status',side_effect=status), \
                patch('installer.operations.configure_ssh'),patch('installer.initialization.checkpoint_initialization'):
            with self.assertRaises(OSError):d.apply()
        self.assertEqual(observed,[COMPLETE_MESSAGE])
        self.assertEqual(self.registry.status(self.c.instance)['state'],'failed')

    def test_completed_vm_steps_reconcile_without_reinstalling_guest_packages(self):
        d=self.deployment_model()
        with self.registry.locked(),patch('installer.operations.configure_ssh'),patch('installer.initialization.checkpoint_initialization'):
            d.apply()
            d.bootstrap_office_vm.reset_mock();d.install_vm_office.reset_mock();d.restart_office_vm.reset_mock()
            self.registry.set_status(self.c.instance,'failed') # Model an explicit interrupted continuation.
            d.apply()
        d.bootstrap_office_vm.assert_not_called()
        d.install_vm_office.assert_not_called()
        d.restart_office_vm.assert_not_called()
        d.check_office_vm_bootstrap.assert_called_once_with()
        d.continue_vm_office.assert_called_once_with()
        self.assertEqual(d.start_office_vm.call_count,2)

    def test_code_graph_uses_its_container_step_and_same_real_completion_boot_contract(self):
        self.c=replace(self.c,office_backend='collabora')
        self.d.config=self.c
        d=self.deployment_model()
        with self.registry.locked(),patch('installer.operations.configure_ssh'),patch('installer.initialization.checkpoint_initialization'):
            d.apply()
        journal=private_json(self.state/'deployment.json')
        self.assertEqual(journal['steps']['Collabora CODE container']['state'],'complete')
        self.assertNotIn('Euro-Office container',journal['steps'])
        self.assertEqual((self.state/'complete').read_text(),COMPLETE_MESSAGE)
        self.assertEqual(self.registry.status(self.c.instance)['state'],'ready')
