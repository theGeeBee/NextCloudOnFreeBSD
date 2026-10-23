"""Owned VM stop/detach models; no native execution or installable VM policy."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import PropertyMock, patch

from installer import office_vm as vm
from installer.config import Config, datasets, deployment_plan
from installer.state import Registry, atomic_json, atomic_write, config_digest
from test_backend_config import selected


class Model:
    def __init__(self, config, paths):
        self.c, self.p = config, paths
        self.calls = []
        self.state = 'Stopped'
        self.after_stop = []
        self.foreign = None
        self.detached = False
        self.manager = paths['manager_root']
        self.switch_present = False

    def run(self, *args, **kwargs):
        self.calls.append(args)
        output = ''
        if args[0] == 'zfs':
            dataset, prop = args[-1], args[-2]
            manager = dataset == self.p['manager_dataset']
            values = dict(type='filesystem', mountpoint=self.p['manager_root'] if manager else self.p['mountpoint'],
                          mounted='yes', guid='123456', **{'org.cloud-installer:instance': 'shared' if manager else self.c.instance})
            output = values[prop]
            if self.foreign == 'owner' and prop == 'org.cloud-installer:instance': output = 'foreign'
        elif args[:2] == ('mount', '-p'):
            output = f"{self.p['manager_dataset']} {self.p['manager_root']} zfs rw 0 0\n{self.p['dataset']} {self.p['mountpoint']} zfs rw 0 0\n"
            if self.foreign == 'cover': output += f"foreign/dataset {self.p['disk']} nullfs rw 0 0\n"
        elif args[:2] == ('df', '-P'):
            output = f"Filesystem 1024-blocks Used Available Capacity Mounted on\n{self.p['dataset']} 1048576 1024 1047552 1% {self.p['mountpoint']}\n"
        elif args == ('sysrc','-n','local_startup'):
            output = '/usr/local/etc/rc.d'
        elif args[0] == 'sysrc' and args[-1] == 'switch_list':
            output = self.p['switch'] if self.switch_present else ''
        elif args[0] == 'sysrc' and args[-1] == 'type_'+self.p['switch']:
            output = 'manual'
        elif args[0] == 'sysrc' and args[-1] == 'bridge_'+self.p['switch']:
            output = self.c.onlyoffice_bridge
        elif args[0] == 'sysrc':
            output = '1791a15c-cbeb-11f1-b6ec-589cfc10efa3' if args[-1] == 'uuid' else self.manager
        elif args[0] == 'pkg': output = '1.7.5|sysutils/vm-bhyve'
        elif args == ('vm', 'datastore', 'list'):
            output = f"NAME TYPE PATH ZFS DATASET\ndefault directory {self.p['manager_root']} -\notheroffice directory /srv/other -\n"
            if not self.detached:
                output += f"{self.p['datastore']} directory {self.p['mountpoint']} -\n"
            if self.foreign == 'datastore': output = output.replace(self.p['mountpoint'], '/srv/foreign')
            if self.foreign == 'effective-default': output = output.replace('default directory '+self.p['manager_root'],'default directory /srv/foreign')
        elif args == ('vm', 'list'):
            if self.after_stop: self.state = self.after_stop.pop(0)
            output = 'NAME DATASTORE LOADER CPU MEMORY VNC AUTO STATE\n'
            if not self.detached:
                output += f"{self.p['name']} {self.p['datastore']} uefi {self.c.office_vm_cpus} {self.c.office_memory_mb}M - No {self.state}\n"
            output += 'otheroffice otheroffice uefi 1 1024M - No Running (77)\n'
            if self.foreign == 'duplicate':
                output += f"{self.p['name']} default uefi 2 4096M - No Stopped\n"
            if self.foreign == 'other-guest-in-datastore':
                output += f"foreignvm {self.p['datastore']} uefi 2 4096M - No Stopped\n"
        elif args[:2] == ('vm', 'stop'):
            if self.foreign != 'never-stops': self.after_stop = ['Running (91)', 'Stopped']
        elif args[:3] == ('vm', 'datastore', 'remove'):
            if args[-1] != self.p['datastore']: raise AssertionError('Unrelated datastore removal')
            self.detached = True
        elif args[:3] == ('vm','switch','destroy'):
            self.switch_present = False
        else: raise AssertionError(args)
        return SimpleNamespace(returncode=0, stdout=output + ('\n' if output and not output.endswith('\n') else ''))


class VmOwnershipTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='vm-owned-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.enterContext(patch.object(Config, 'mount_root', new_callable=PropertyMock, return_value=str(self.root / 'instance')))
        self.enterContext(patch.object(Config, 'bastille_root', new_callable=PropertyMock, return_value=str(self.root / 'shared/bastille')))
        def mapped_path(*parts):
            path = Path(*parts)
            return self.root / 'kernel-vmm' / path.name if path.is_relative_to('/dev/vmm') else path
        self.enterContext(patch('installer.office_vm.Path', side_effect=mapped_path))
        self.c = replace(selected('eurooffice'), office_vm_cpus=2, office_vm_disk_gib=1, office_memory_mb=4096)
        self.paths = vm.vm_paths(self.c)
        self.rc=self.root/'vm-rc.conf'
        atomic_write(self.rc,vm._vm_rc_text(self.paths))
        self.enterContext(patch('installer.office_vm.VM_RC_CONFIG',self.rc))
        for key in ('manager_root', 'mountpoint', 'root'):
            Path(self.paths[key]).mkdir(mode=0o700, parents=True, exist_ok=True)
        for name in ('.config','.templates','.iso','.img'):
            (Path(self.paths['manager_root'])/name).mkdir(mode=0o700)
        for name in ('null.iso','system.conf'):
            atomic_write(Path(self.paths['manager_root'])/'.config'/name,'')
        disk = Path(self.paths['disk'])
        with disk.open('wb') as stream: stream.truncate(1024**3)  # Sparse fixture, not an image or VM.
        disk.chmod(0o600)
        atomic_write(self.paths['config'], 'uuid="1791a15c-cbeb-11f1-b6ec-589cfc10efa3"\n')
        self.registry = Registry(self.root / 'registry')
        self.registry.initialize()
        self.state = self.registry.instance_path(self.c.instance)
        self.state.mkdir(mode=0o700)
        self.plan = dict(roles={'vm_manager': 'vm-bhyve'}, packages={'host': {
            'vm-bhyve': dict(name='vm-bhyve', version='1.7.5', origin='sysutils/vm-bhyve')}})
        atomic_json(self.state / 'versions.json', self.plan)
        for directory in (self.state/'vm-seed',Path(self.paths['root'])/'.cloud-init'):
            directory.mkdir(mode=0o700)
            for name in ('user-data','meta-data','network-config'):
                atomic_write(directory/name,'synthetic seed '+name+'\n')
        atomic_write(Path(self.paths['root'])/'seed.iso','synthetic NoCloud ISO\n')
        self.reservation = dict(schema_version=1, name=self.paths['name'], root=self.paths['root'],
            config_sha256=config_digest(self.c), versions_sha256=hashlib.sha256((self.state/'versions.json').read_bytes()).hexdigest(),
            uuid='1791a15c-cbeb-11f1-b6ec-589cfc10efa3', dataset_guid='123456', disk_inode=disk.stat().st_ino,
            vm_config_sha256=hashlib.sha256(Path(self.paths['config']).read_bytes()).hexdigest(),
            seed_sha256=vm._vm_seed_digest(self.state/'vm-seed'),
            seed_iso_sha256=hashlib.sha256((Path(self.paths['root'])/'seed.iso').read_bytes()).hexdigest())
        atomic_json(self.state / (self.paths['name'] + '.creating.json'), self.reservation)
        self.runner = Model(self.c, self.paths)
        self.d = SimpleNamespace(config=self.c, state=self.state, registry=self.registry, runner=self.runner, versions=self.plan)

    def test_exact_identity_readonly_and_single_disk_allocation_plan(self):
        result = vm.native_vm_identity(self.d)
        self.assertEqual(result['name'], self.paths['name'])
        self.assertEqual(result['state'], 'Stopped')
        self.assertEqual([d.name for d in datasets(self.c) if d.name.endswith('/office-vm')], [self.paths['dataset']])
        plan = deployment_plan(self.c)
        self.assertIn('1 GiB finite disk capacity', plan)
        self.assertIn('one dedicated Alpine/bhyve/Docker VM', plan)
        self.assertNotIn(('vm','stop',self.paths['name']), self.runner.calls)

    def test_native_and_none_never_acquire_vm_resources(self):
        for backend in ('none', 'onlyoffice'):
            with self.subTest(backend=backend), self.assertRaises(ValueError): vm.vm_paths(selected(backend))
        self.assertEqual(self.runner.calls, [])

    def test_wrong_storage_manager_inventory_or_duplicate_name_refuses_stop(self):
        for reason in ('owner', 'cover', 'datastore', 'duplicate', 'other-guest-in-datastore','effective-default'):
            with self.subTest(reason=reason), self.registry.locked():
                self.runner.foreign = reason
                with self.assertRaises(ValueError): vm.stop_native_vm(self.d)
        self.assertFalse(any(c[:2] == ('vm','stop') for c in self.runner.calls))
        self.runner.foreign = None
        self.runner.manager = '/srv/foreign'
        with self.registry.locked(), self.assertRaisesRegex(ValueError, 'foreign VM manager'): vm.stop_native_vm(self.d)

    def test_changed_reservation_lock_or_config_never_stops_a_matching_name(self):
        file = self.state / (self.paths['name'] + '.creating.json')
        for field, value in (('disk_inode', self.reservation['disk_inode'] + 1), ('dataset_guid', '999'),
                             ('config_sha256', 'a'*64), ('vm_config_sha256', 'b'*64)):
            atomic_json(file, {**self.reservation, field: value})
            with self.subTest(field=field), self.registry.locked(), self.assertRaises(ValueError): vm.stop_native_vm(self.d)
        atomic_json(file, self.reservation)
        atomic_write(self.state/'versions.json', '{}\n')
        with self.registry.locked(), self.assertRaises(ValueError): vm.stop_native_vm(self.d)
        self.assertFalse(any(c[:2] == ('vm','stop') for c in self.runner.calls))

    def test_stop_holds_host_lock_and_waits_for_asynchronous_manager(self):
        with self.assertRaisesRegex(ValueError, 'lock'): vm.stop_native_vm(self.d)
        self.runner.state = 'Running (91)'
        with self.registry.locked(), patch('installer.office_vm.time.sleep'):
            result = vm.stop_native_vm(self.d)
        self.assertEqual(result['state'], 'Stopped')
        self.assertEqual(self.runner.calls.count(('vm','stop',self.paths['name'])), 1)
        self.assertNotIn(('vm','stop','otheroffice'), self.runner.calls)

    def test_unknown_locked_state_and_timeout_never_force_or_destroy(self):
        self.runner.state = 'Locked (foreign-host)'
        with self.registry.locked(), self.assertRaisesRegex(ValueError, 'manual recovery'): vm.stop_native_vm(self.d)
        self.runner.state, self.runner.foreign = 'Running (91)', 'never-stops'
        clock = iter(i / 100 for i in range(10000))
        with self.registry.locked(), patch('installer.office_vm.time.monotonic', side_effect=lambda: next(clock)), \
                patch('installer.office_vm.time.sleep'), self.assertRaises(RuntimeError):
            vm.stop_native_vm(self.d, timeout=1)
        self.assertFalse(any('destroy' in c or c[0] == 'kill' for c in self.runner.calls))

    def test_normal_detach_retains_disk_and_unregisters_only_owned_datastore(self):
        self.runner.state = 'Running (91)'
        inode = Path(self.paths['disk']).stat().st_ino
        with self.registry.locked(), patch('installer.office_vm.time.sleep'):
            result = vm.detach_native_vm_datastore(self.d)
        self.assertTrue(result['stopped'])
        self.assertTrue(result['datastore_detached'])
        self.assertEqual(Path(self.paths['disk']).stat().st_ino, inode)
        self.assertTrue(Path(self.paths['config']).is_file())
        self.assertEqual(self.runner.calls.count(('vm','datastore','remove',self.paths['datastore'])), 1)
        self.assertFalse(any('destroy' in c or 'bastille' in c for c in self.runner.calls))
        self.runner.calls.clear()
        with self.registry.locked():
            repeated = vm.detach_native_vm_datastore(self.d)
        self.assertEqual(repeated,result)
        self.assertFalse(any(command[:2] == ('vm','stop') or command[:3] == ('vm','datastore','remove')
                             for command in self.runner.calls))

    def test_detach_reconciliation_refuses_foreign_remaining_vm_name(self):
        self.runner.detached=True
        original=self.runner.run
        def native(*args,**kwargs):
            result=original(*args,**kwargs)
            if args==('vm','list'):
                result.stdout+=f"{self.paths['name']} foreignstore uefi 2 4096M - No Stopped\n"
            return result
        self.runner.run=native
        with self.registry.locked(),self.assertRaisesRegex(ValueError,'conflicting manager identity'):
            vm.detach_native_vm_datastore(self.d)

    def test_owned_manual_switch_unregistered_without_destroying_bridge_or_disk(self):
        self.runner.switch_present=True
        with self.registry.locked(): vm.detach_native_vm_datastore(self.d)
        self.assertIn(('vm','switch','destroy',self.paths['switch']),self.runner.calls)
        self.assertNotIn(('vm','destroy',self.paths['name']),self.runner.calls)
        self.assertFalse(any(command[0] in ('ifconfig','zfs') and 'destroy' in command for command in self.runner.calls))
        self.assertTrue(Path(self.paths['disk']).is_file())

    def test_detach_retry_checks_manager_even_when_owned_datastore_is_absent(self):
        self.runner.detached=True
        self.runner.switch_present=True
        self.runner.manager='/srv/foreign'
        with self.registry.locked(),self.assertRaisesRegex(ValueError,'foreign VM manager'):
            vm.detach_native_vm_datastore(self.d)
        self.assertNotIn(('vm','switch','destroy',self.paths['switch']),self.runner.calls)

    def test_missing_native_manager_files_refuse_before_vm_can_recreate_them(self):
        root=Path(self.paths['manager_root'])
        for name in ('.iso','.config/null.iso','.config/system.conf'):
            with self.subTest(name=name):
                path=root/name
                retained=path.with_name(path.name+'.retained')
                path.rename(retained)
                self.runner.calls.clear()
                try:
                    with self.assertRaises(OSError):vm.native_vm_identity(self.d)
                    self.assertFalse(path.exists())
                    self.assertFalse(any(command[0]=='vm' for command in self.runner.calls))
                finally:retained.rename(path)

    def test_manager_autostart_or_other_rc_drift_refuses_before_vm_commands(self):
        self.rc.write_text(vm._vm_rc_text(self.paths).replace('vm_list=""','vm_list="'+self.paths['name']+'"'))
        self.runner.calls.clear()
        with self.assertRaisesRegex(ValueError,'startup settings changed'):vm.native_vm_identity(self.d)
        self.assertFalse(any(command[0]=='vm' for command in self.runner.calls))

    def test_stopped_listing_with_kernel_runtime_or_lock_is_not_confirmed_stopped(self):
        for kind in ('kernel', 'lock'):
            with self.subTest(kind=kind):
                target = (self.root / 'kernel-vmm' / self.paths['name']) if kind == 'kernel' else Path(self.paths['root']) / 'run.lock'
                target.parent.mkdir(exist_ok=True)
                target.touch()
                clock = iter(i/100 for i in range(10000))
                with self.registry.locked(), patch('installer.office_vm.time.monotonic', side_effect=lambda: next(clock)), \
                        patch('installer.office_vm.time.sleep'), self.assertRaises(RuntimeError):
                    vm.stop_native_vm(self.d, timeout=1)
                self.assertTrue(target.exists())
                target.rename(target.with_name(target.name + '.retained-diagnostic'))
