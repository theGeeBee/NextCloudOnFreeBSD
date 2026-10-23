"""Read-only VM feasibility gates with native FreeBSD-format hardware fixtures."""
from dataclasses import replace
import hashlib
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from installer.config import Config
from installer.host import preflight_vm, check_vm_disk_capacity


class VmPreflightTests(unittest.TestCase):
    def setUp(self):
        root=Path(__file__).resolve().parents[1]
        self.c=replace(Config.from_json((root/'examples/eurooffice.json').read_text()),
                       office_vm_cpus=2,office_memory_mb=4096,office_vm_disk_gib=16)
        self.facts={'available_gib':{'zroot':73}}
        self.registry=Mock(); self.registry.host.return_value=None
        self.runner=Mock(); self.runner.output.side_effect=lambda *args: '8' if args[0]=='sysctl' else str(73*1024**3)
        self.hardware='  SVM: NP,NRIP,VClean,AFlush,NAsids=16\n'
        self.foreign=False
        def native(*args,**kwargs):
            if args[0]=='dmesg': return SimpleNamespace(returncode=0,stdout=self.hardware)
            if args==('sysrc','-n','local_startup'): return SimpleNamespace(returncode=0,stdout='/usr/local/etc/rc.d')
            if args[:2]==('sysrc','-n'): return SimpleNamespace(returncode=0 if self.foreign else 1,stdout='')
            return SimpleNamespace(returncode=0,stdout='')
        self.runner.run.side_effect=native
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.rc=Path(temporary.name)/'absent-rc'
        self.enterContext(patch('installer.office_vm.VM_RC_CONFIG',self.rc))

    def test_amd_and_intel_second_level_paging_without_loading_or_installing(self):
        for hardware in (self.hardware,'VT-x: PAT,HLT,MTF,PAUSE,EPT,UG,VPID\n'):
            self.hardware=hardware
            preflight_vm(self.c,self.facts,self.runner,registry=self.registry)
        commands=repr(self.runner.mock_calls)
        for forbidden in ('kldload','pkg','vm init','vm start','fetch'):
            self.assertNotIn(forbidden,commands)

    def test_native_none_skip_every_vm_probe(self):
        for backend in ('onlyoffice','none'):
            preflight_vm(SimpleNamespace(backend=backend),{},self.runner,registry=self.registry)
        self.assertEqual(self.runner.mock_calls,[])
        self.registry.host.assert_not_called()

    def test_pure_registry_reserves_vm_name_against_nc_jail_hostname_both_directions(self):
        from installer.host import _registry_plan
        other=replace(self.c,instance='other',office_backend='none',private_network='10.78.0.0/30',
                      nextcloud_bridge='bridge249',nextcloud_hostname=self.c.instance+'office',ingress_address='192.0.2.99',
                      office_vm_cpus=0,office_vm_disk_gib=0,office_memory_mb=Config().office_memory_mb)
        registry=Mock();registry.host.return_value=None
        registry.entries.return_value=[(other,{'state':'configured'})]
        with self.assertRaisesRegex(ValueError,'hostname conflicts'):
            _registry_plan(self.c,{'memory_mb':32768},registry,False)
        registry.entries.return_value=[(self.c,{'state':'configured'})]
        with self.assertRaisesRegex(ValueError,'hostname conflicts'):
            _registry_plan(other,{'memory_mb':32768},registry,False)
        self.assertEqual(self.runner.mock_calls,[])

    def test_minimum_cpu_disk_and_nested_hardware_refusals(self):
        for c in (replace(self.c,office_vm_cpus=0),replace(self.c,office_memory_mb=2048),
                  replace(self.c,office_vm_disk_gib=8),replace(self.c,office_vm_cpus=16)):
            with self.assertRaises(ValueError): preflight_vm(c,self.facts,self.runner,registry=self.registry)
        with self.assertRaisesRegex(ValueError,'disk capacity'):
            preflight_vm(self.c,{'available_gib':{'zroot':8}},self.runner,registry=self.registry)
        self.hardware='AMD Features2=SVM\n'
        with self.assertRaisesRegex(ValueError,'virtualization'):
            preflight_vm(self.c,self.facts,self.runner,registry=self.registry)

    def test_foreign_vm_manager_refused_not_reconfigured(self):
        self.foreign=True
        with self.assertRaisesRegex(ValueError,'foreign vm-bhyve'):
            preflight_vm(self.c,self.facts,self.runner,registry=self.registry)
        self.assertFalse(any('init' in call.args or 'install' in call.args for call in self.runner.run.call_args_list))

    def test_roomy_pool_does_not_hide_tight_effective_ancestor(self):
        self.runner.output.side_effect=lambda *args: '8' if args[0]=='sysctl' else str(2*1024**3)
        with self.assertRaisesRegex(ValueError,'Effective VM storage ancestor'):
            preflight_vm(self.c,self.facts,self.runner,registry=self.registry)
        self.assertFalse(any(call.args and call.args[0]=='dmesg' for call in self.runner.run.call_args_list))

    def test_nearest_existing_ancestor_and_dataset_cap_are_both_enforced(self):
        from installer.office_vm import vm_paths
        dataset=vm_paths(self.c)['dataset'];ancestor=dataset.rsplit('/',1)[0]
        def native(*args,**kwargs):
            self.assertEqual(args[:3],('zfs','list','-H'))
            return SimpleNamespace(returncode=0 if args[-1]==ancestor else 1,stdout=ancestor)
        self.runner.run.side_effect=native
        self.runner.output.return_value=str(16*1024**3);self.runner.output.side_effect=None
        check_vm_disk_capacity(self.c,self.runner)
        self.runner.output.assert_called_once_with('zfs','get','-Hp','-o','value','available',ancestor)
        with self.assertRaisesRegex(ValueError,'disk capacity'):
            check_vm_disk_capacity(replace(self.c,office_quota_gib=8),self.runner)
        self.runner.output.return_value=str(16*1024**3-1)
        with self.assertRaisesRegex(ValueError,'disk capacity'):check_vm_disk_capacity(self.c,self.runner)

    def test_unparseable_effective_capacity_is_not_treated_as_unlimited(self):
        self.runner.output.side_effect=None;self.runner.output.return_value='-'
        with self.assertRaises(ValueError):check_vm_disk_capacity(self.c,self.runner)

    def test_owned_marker_requires_exact_rc_guid_and_no_global_override(self):
        from installer.office_vm import vm_paths
        p=vm_paths(self.c)
        rc='vm_enable="YES"\nvm_dir="'+p['manager_root']+'"\nvm_list=""\n'
        marker=dict(dataset=p['manager_dataset'],mountpoint=p['manager_root'],guid='12345',
                    rc_file=str(self.rc),rc_sha256=hashlib.sha256(rc.encode()).hexdigest())
        self.registry.host.return_value={'vm_manager':marker}
        self.runner.output.side_effect=lambda *args: '8' if args[0]=='sysctl' else {
            'guid':'12345','mountpoint':p['manager_root'],'mounted':'yes','available':str(73*1024**3),
            'org.cloud-installer:instance':'shared'}[args[-2]]
        with self.assertRaisesRegex(ValueError,'missing'):
            preflight_vm(self.c,self.facts,self.runner,registry=self.registry)
        preflight_vm(self.c,self.facts,self.runner,registry=self.registry,resume=True)
        self.rc.write_text(rc); self.rc.chmod(0o600)
        preflight_vm(self.c,self.facts,self.runner,registry=self.registry)
        self.rc.write_text(rc+'vm_list="unrelated"\n')
        with self.assertRaisesRegex(ValueError,'settings changed'):
            preflight_vm(self.c,self.facts,self.runner,registry=self.registry)
        self.rc.write_text(rc)
        self.foreign=True
        with self.assertRaisesRegex(ValueError,'overrides'):
            preflight_vm(self.c,self.facts,self.runner,registry=self.registry)
        self.foreign=False
        marker['guid']='999'
        with self.assertRaisesRegex(ValueError,'dataset identity'):
            preflight_vm(self.c,self.facts,self.runner,registry=self.registry)
