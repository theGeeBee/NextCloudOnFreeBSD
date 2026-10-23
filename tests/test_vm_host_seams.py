"""Shared-host bridge/storage checks for the selected runtime role, no native ops."""
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from installer.config import Config
from installer.host import _check_bridges, _check_storage
from installer.office_vm import vm_paths
from installer.resolution import resolve
from test_vm_resolution import vm_metadata


class VmHostSeamTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='vm-host-seam-');self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.c=Config.from_json((Path(__file__).resolve().parents[1]/'examples/eurooffice.json').read_text())
        self.plan=resolve(self.c,vm_metadata(self.c))
        self.file=self.root/'versions.json';self.file.write_text(json.dumps(self.plan));self.file.chmod(0o600)
        self.registry=Mock();self.registry.evidence_path.return_value=self.file
        self.members=[];self.present=True;self.desc='vmnet/'+self.c.instance+'office/0/'+self.c.instance+'office'
        self.runner=Mock()
        def native(*args,**kwargs):
            if args==('ifconfig',self.c.nextcloud_bridge):
                text=f'{self.c.nextcloud_bridge}: flags=1008843<UP> metric 0 mtu 1500\n\tinet {self.c.nextcloud_gateway} netmask 0xfffffffc\n'
                return SimpleNamespace(returncode=0,stdout=text)
            if args==('ifconfig',self.c.onlyoffice_bridge):
                text=f'{self.c.onlyoffice_bridge}: flags=1008843<UP> metric 0 mtu 1500\n\tinet {self.c.onlyoffice_gateway} netmask 0xfffffffc\n'
                text+=''.join('\tmember: '+member+' flags=143<LEARNING>\n' for member in self.members)
                return SimpleNamespace(returncode=0 if self.present else 1,stdout=text)
            raise AssertionError(args)
        self.runner.run.side_effect=native
        self.runner.output.side_effect=lambda *args:'tap0: flags=UP\n\tdescription: '+self.desc+'\n'
        self.identity=self.enterContext(patch('installer.office_vm.native_vm_identity',return_value={'state':'Running (123)'}))

    def bridges(self,owned=None,resume=True):
        return _check_bridges(self.c,[self.c],{self.c.instance:self.root} if owned is None else owned,
                              {},resume,self.runner,registry=self.registry)

    def test_empty_owned_vm_bridge_is_reserved_before_guest_creation_without_jail_assumption(self):
        allowed=self.bridges()
        self.assertEqual(set(allowed),{self.c.nextcloud_bridge,self.c.onlyoffice_bridge})
        self.identity.assert_not_called()

    def test_existing_vm_bridge_without_owned_journal_is_not_ignored_by_one_jail_zip(self):
        with self.assertRaisesRegex(ValueError,'without resumable ownership'):self.bridges(owned={})
        self.identity.assert_not_called()

    def test_owned_tap_needs_running_sealed_vm_and_exact_description(self):
        self.members=['tap0']
        allowed=self.bridges()
        self.assertIn(self.c.onlyoffice_bridge,allowed)
        target=self.identity.call_args.args[0]
        self.assertEqual(target.config,self.c)
        self.assertEqual(target.state,self.root)
        self.assertEqual(target.versions,self.plan)
        self.identity.return_value={'state':'Stopped'}
        with self.assertRaisesRegex(ValueError,'verified running VM'):self.bridges()
        self.identity.return_value={'state':'Running (123)'}
        self.desc='vmnet/foreign/0/foreign'
        with self.assertRaisesRegex(ValueError,'tap identity'):self.bridges()

    def test_physical_uplink_or_multiple_taps_refuse_before_vm_inspection(self):
        for members in (['igb0'],['tap0','tap1']):
            self.members=members
            with self.subTest(members=members),self.assertRaisesRegex(ValueError,'foreign member'):self.bridges()
        self.identity.assert_not_called()

    def test_vm_shared_storage_collision_is_selected_only_and_not_adopted(self):
        paths=vm_paths(self.c)
        with patch('installer.host._zfs_exists',side_effect=lambda runner,name:name==paths['manager_dataset']), \
                patch('installer.host._exists',return_value=False),self.assertRaisesRegex(ValueError,'no automatic adoption'):
            _check_storage(self.c,[self.c],{},False,False,self.runner)
        for example in ('config','nextcloud-only'):
            c=Config.from_json((Path(__file__).resolve().parents[1]/'examples'/(example+'.json')).read_text())
            runner=Mock();runner.output.return_value=str(2*1024**4)
            with patch('installer.host._zfs_exists',return_value=False) as zfs,patch('installer.host._exists',return_value=False):
                _check_storage(c,[c],{},False,False,runner)
            self.assertFalse(any(call.args[-1].endswith('/vm') for call in zfs.call_args_list))
