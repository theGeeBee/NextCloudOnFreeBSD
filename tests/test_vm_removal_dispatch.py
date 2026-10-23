"""Removal orchestration dispatch only; native VM ownership has separate models."""
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from installer.config import Config, datasets
from installer.deploy import Deployment
from installer.lifecycle import remove_instance
from installer.office_vm import vm_paths
from installer.state import Registry, atomic_json, atomic_write


class VmRemovalDispatchTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='vm-removal-')
        self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)
        self.c=Config.from_json((Path(__file__).resolve().parents[1]/'examples/eurooffice.json').read_text())
        self.registry=Registry(self.root/'registry');self.registry.initialize()
        self.state=self.registry.instance_path(self.c.instance)
        # Model only the private retained state. Public VM registration is still
        # correctly refused; do not disable that gate to exercise removal seams.
        self.state.mkdir(mode=0o700)
        self.registry.set_status(self.c.instance,'ready')
        self.paths=vm_paths(self.c)
        atomic_json(self.state/(self.paths['name']+'.creating.json'),{'test':'ownership helper mocked'})
        atomic_write(self.state/'allow-vm-start','bound permission\n')
        atomic_write(self.state/'allow-start','jail permission\n')
        (self.registry.root/'network/active').mkdir(parents=True,mode=0o700)
        self.enterContext(patch.object(self.registry,'network_configs',return_value=[]))
        self.runner=Mock()
        self.runner.run.return_value=SimpleNamespace(returncode=1,stdout='')
        self.d=object.__new__(Deployment)
        self.d.config=self.c;self.d.runner=self.runner;self.d.registry=self.registry
        self.d.state=self.state;self.d.progress=Mock();self.d.storage=datasets(self.c)
        self.d.configure_network=Mock()
        self.jails=self.enterContext(patch('installer.lifecycle._checked_jails',return_value=[]))
        self.detach=self.enterContext(patch('installer.office_vm.detach_native_vm_datastore'))

    def test_selected_runtime_detaches_before_network_withdraw_and_keeps_guest_data(self):
        def detach(d):
            self.assertFalse((self.state/'allow-vm-start').exists())
            self.runner.run.assert_not_called()
        self.detach.side_effect=detach
        with self.registry.locked(): remove_instance(self.d,confirmation='REMOVE '+self.c.instance)
        self.detach.assert_called_once_with(self.d)
        self.assertEqual(self.registry.status(self.c.instance)['state'],'removed')
        for address in (self.c.nextcloud_ip,self.c.onlyoffice_ip):
            self.assertTrue(any(call.args==('pfctl','-k',address) for call in self.runner.run.call_args_list))
        commands=[call.args for call in self.runner.run.call_args_list]
        self.assertFalse(any('bastille' in call or ('zfs' in call and 'destroy' in call) for call in commands))
        self.assertEqual(self.c.jails,(self.c.nextcloud_jail,))
        self.assertTrue((self.state/(self.paths['name']+'.creating.json')).exists())

    def test_uncertain_runtime_stop_prevents_pf_or_jail_mutation(self):
        self.detach.side_effect=ValueError('uncertain VM creation/runtime')
        with self.registry.locked(),self.assertRaisesRegex(ValueError,'uncertain VM'):
            remove_instance(self.d,confirmation='REMOVE '+self.c.instance)
        self.runner.run.assert_not_called()
        self.d.configure_network.assert_not_called()
        self.assertEqual(self.registry.status(self.c.instance)['state'],'removing')
        self.assertTrue((self.state/'allow-start').exists())

    def test_completed_removal_retry_does_not_touch_reused_network_or_runtime(self):
        with self.registry.locked(): remove_instance(self.d,confirmation='REMOVE '+self.c.instance)
        self.detach.reset_mock();self.runner.reset_mock()
        with self.registry.locked(): remove_instance(self.d,confirmation='REMOVE '+self.c.instance)
        self.detach.assert_not_called()
        self.runner.run.assert_not_called()
