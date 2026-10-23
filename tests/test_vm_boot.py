"""Private rc boot entry gates, with all native startup/shutdown calls mocked."""
from dataclasses import replace
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from installer import vm_boot
from installer.deploy import COMPLETE_MESSAGE
from installer.config import Config
from installer.office_vm import render_vm_boot_service
from installer.state import Registry, atomic_json, atomic_write, config_digest


class VmBootTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='vm-boot-')
        self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)
        self.c=Config.from_json((Path(__file__).resolve().parents[1]/'examples/eurooffice.json').read_text())
        self.registry=Registry(self.root/'registry');self.registry.initialize()
        self.state=self.registry.instance_path(self.c.instance);self.state.mkdir(mode=0o700)
        atomic_write(self.registry.root/'operation.lock','')
        atomic_json(self.state/'config.json',json.loads(self.c.to_json()))
        self.registry.set_status(self.c.instance,'ready')
        atomic_write(self.state/'complete',COMPLETE_MESSAGE)
        atomic_write(self.state/'allow-vm-start',config_digest(self.c)+'\n')
        self.journal=dict(schema_version=self.c.schema_version,config_sha256=config_digest(self.c),
                          steps={'Alpine VM boot':{'state':'complete'},'boot activation':{'state':'complete'}})
        atomic_json(self.state/'deployment.json',self.journal)
        self.deployment=SimpleNamespace(state=self.state,require_original_artifact=Mock(),require_running_jail=Mock())
        self.factory=self.enterContext(patch('installer.vm_boot.Deployment',return_value=self.deployment))
        self.platform=self.enterContext(patch('installer.vm_boot.require_host'))
        self.start=self.enterContext(patch('installer.vm_boot.start_native_vm'))
        self.stop=self.enterContext(patch('installer.vm_boot.stop_native_vm'))
        self.runner=Mock()

    def run_boot(self,action='start'):
        return vm_boot.run(action,self.c.instance,registry=self.registry,runner=self.runner)

    def test_complete_ready_instance_requires_original_artifact_nc_and_global_lock(self):
        def start(d):
            self.assertTrue(self.registry._locked)
            self.deployment.require_original_artifact.assert_called_once_with()
            self.deployment.require_running_jail.assert_called_once_with(self.c.nextcloud_jail)
        self.start.side_effect=start
        self.run_boot()
        self.factory.assert_called_once_with(self.c,{},self.runner,registry=self.registry)
        self.assertFalse(self.registry._locked)
        self.stop.assert_not_called()

    def test_incomplete_status_running_phase_and_changed_permission_never_start(self):
        self.registry.set_status(self.c.instance,'installing')
        with self.assertRaises(ValueError): self.run_boot()
        self.registry.set_status(self.c.instance,'ready')
        self.journal['steps']['Alpine VM boot']['state']='running'
        atomic_json(self.state/'deployment.json',self.journal)
        with self.assertRaisesRegex(ValueError,'incomplete'): self.run_boot()
        self.journal['steps']['Alpine VM boot']['state']='complete'
        atomic_json(self.state/'deployment.json',self.journal)
        atomic_write(self.state/'allow-vm-start','wrong-config\n')
        with self.assertRaises(ValueError): self.run_boot()
        self.start.assert_not_called()

    def test_changed_artifact_or_stopped_nc_fails_before_vm_mutation(self):
        self.deployment.require_original_artifact.side_effect=ValueError('changed source')
        with self.assertRaises(ValueError): self.run_boot()
        self.deployment.require_original_artifact.side_effect=None
        self.deployment.require_running_jail.side_effect=ValueError('NC stopped')
        with self.assertRaises(ValueError): self.run_boot()
        self.start.assert_not_called()

    def test_stop_uses_only_owned_runtime_without_start_permission_or_any_credentials(self):
        self.registry.set_status(self.c.instance,'removing')
        (self.state/'allow-vm-start').rename(self.state/'permission-retained-disabled')
        self.run_boot('stop')
        self.stop.assert_called_once_with(self.deployment)
        self.start.assert_not_called()
        self.deployment.require_running_jail.assert_not_called()

    def test_failed_or_installing_owned_runtime_can_stop_but_cannot_auto_start(self):
        for state in ('installing','failed'):
            self.registry.set_status(self.c.instance,state)
            with self.subTest(state=state):
                self.run_boot('stop')
                with self.assertRaises(ValueError):self.run_boot('start')
        self.assertEqual(self.stop.call_count,2)
        self.start.assert_not_called()

    def test_unknown_instance_platform_failure_and_wrong_profile_cannot_initialize_or_start(self):
        with self.assertRaises(OSError):
            vm_boot.run('start','unknown',registry=self.registry,runner=self.runner)
        self.assertFalse(self.registry.instance_path('unknown').exists())
        self.platform.side_effect=ValueError('not FreeBSD root')
        with self.assertRaises(ValueError): self.run_boot()
        self.factory.assert_not_called()
        self.platform.side_effect=None
        c=replace(self.c,office_backend='none',private_network='10.77.0.0/30',
                  office_vm_cpus=0,office_vm_disk_gib=0,office_memory_mb=0)
        atomic_json(self.state/'config.json',json.loads(c.to_json()))
        self.journal['config_sha256']=config_digest(c)
        atomic_json(self.state/'deployment.json',self.journal)
        with self.assertRaisesRegex(ValueError,'no managed office VM'): self.run_boot()
        self.start.assert_not_called()

    def test_boot_lock_does_not_repair_missing_unrelated_registry_directories(self):
        removed=self.registry.root/'backups'
        removed.rename(self.root/'retained-backups')
        self.run_boot()
        self.assertFalse(removed.exists())
        self.assertFalse(self.registry._locked)
        lock=self.registry.root/'operation.lock';lock.rename(self.root/'retained-operation.lock')
        self.start.reset_mock()
        with self.assertRaises(OSError):self.run_boot()
        self.assertFalse(lock.exists())
        self.start.assert_not_called()

    def test_private_worker_diagnostics_do_not_echo_exception_payloads(self):
        with patch('installer.vm_boot.run',side_effect=ValueError('secret-canary')), \
                patch('sys.stderr') as err:
            self.assertEqual(vm_boot.main(['start','cloud']),1)
            self.assertNotIn('secret-canary',repr(err.mock_calls))

    def test_rc_render_is_disabled_by_default_and_explicitly_invokes_verified_worker(self):
        script=render_vm_boot_service(self.c,'/root/frozen-installer',source_sha256='a'*64)
        self.assertIn('# REQUIRE: bastille vm',script)
        self.assertIn('_enable:=NO',script)
        self.assertIn('cd /root/frozen-installer',script)
        self.assertIn('-B -m installer.vm_boot start '+self.c.instance,script)
        self.assertIn('-B -m installer.vm_boot stop '+self.c.instance,script)
        self.assertIn('/usr/bin/env -i PATH=',script)
        self.assertIn('-I -S -B -c',script)
        self.assertNotIn('vm start',script)
        self.assertNotIn('prestart=',script)
        result=subprocess.run(['sh','-n'],input=script,text=True,capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr)
