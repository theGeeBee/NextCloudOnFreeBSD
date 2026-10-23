"""Owned creation/reconciliation with native commands mocked; no guest boot."""
from dataclasses import replace
import hashlib
import json
import io
from pathlib import Path
import re
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import PropertyMock, patch

from installer import office_vm as vm
from installer.config import Config
from installer.state import Registry, atomic_json, atomic_write, private_json, config_digest
from test_backend_config import selected
from test_office_vm import IMAGE, PRIVATE, PUBLIC
from test_vm_ownership import Model


class CreationModel(Model):
    def __init__(self,c,p,rc):
        super().__init__(c,p)
        self.rc = rc
        self.import_options = None
        self.registered = self.created = self.global_configuration = False
        self.mac = '58:9c:fc:05:03:fc'
        self.fail_create = False
        self.switch_registered = self.bad_switch = self.bad_bridge = False
        self.ssh_result = SimpleNamespace(returncode=0,stdout='3.24.2\n',stderr='')
        self.ssh_change_vm = False
        self.last_ssh = None
        self.available_bytes = 73*1024**3

    def output(self,*args):
        result=self.run(*args)
        if result.returncode:raise RuntimeError('Mock native query failed')
        return result.stdout.strip()

    def run(self,*args,**kwargs):
        self.calls.append(args)
        output, code = '', 0
        if args[:3] == ('zfs','list','-H'):
            output=self.p['dataset']
        elif args[:2] == ('zfs','get') and args[-2]=='available':
            output=str(self.available_bytes)
        elif args[:3] == ('df','-P',self.p['manager_root']):
            output = f"Filesystem 1024-blocks Used Available Capacity Mounted on\n{self.p['manager_dataset']} 1048576 1 1048575 1% {self.p['manager_root']}\n"
        elif args == ('sysrc','-n','local_startup'):
            output = '/usr/local/etc/rc.d'
        elif args == ('sysrc','-n','vm_dir') or args == ('sysrc','-n','vm_enable'):
            output, code = (self.p['manager_root'],0) if self.global_configuration else ('',1)
        elif args == ('vm','init'):
            for name in ('.templates','.config','.img','.iso'):
                (Path(self.p['manager_root'])/name).mkdir(mode=0o700,exist_ok=True)
            for name in ('null.iso','system.conf'):
                file=Path(self.p['manager_root'])/'.config'/name
                if not file.exists(): atomic_write(file,'')
        elif args == ('vm','datastore','add',self.p['datastore'],self.p['mountpoint']): self.registered = True
        elif args == ('vm','datastore','list'):
            output = f"NAME TYPE PATH ZFS DATASET\ndefault directory {self.p['manager_root']} -\n"
            if self.registered: output += f"{self.p['datastore']} directory {self.p['mountpoint']} -\n"
        elif args == ('vm','list') and not self.created:
            output = 'NAME DATASTORE LOADER CPU MEMORY VNC AUTO STATE\n'
        elif args[:2] == ('vm','start'):
            self.state = 'Running (91)'
        elif args[:3] == ('vm','switch','create'):
            self.switch_registered = True
        elif args[0] == 'sysrc' and args[-1] == 'switch_list':
            output,code = (self.p['switch'],0) if self.switch_registered else ('',1)
        elif args[0] == 'sysrc' and args[-1] == 'type_'+self.p['switch']:
            output = 'standard' if self.bad_switch else 'manual'
        elif args[0] == 'sysrc' and args[-1] == 'bridge_'+self.p['switch']:
            output = self.c.onlyoffice_bridge
        elif args == ('ifconfig',self.c.onlyoffice_bridge):
            output = f'{self.c.onlyoffice_bridge}: flags=1008843<UP,BROADCAST,RUNNING> metric 0 mtu 1500\n\tinet {self.c.onlyoffice_gateway} netmask 0xfffffffc\n'
            if self.bad_bridge: output += '\tmember: vtnet0 flags=143<LEARNING>\n'
            elif self.state.startswith('Running ('): output += '\tmember: tap0 flags=143<LEARNING>\n'
        elif args == ('ifconfig','tap0'):
            output = f'tap0: flags=UP\n\tdescription: vmnet/{self.p["name"]}/0/{self.p["switch"]}\n'
        elif args[0] == '/usr/bin/ssh-keygen':
            key = Path(args[args.index('-f')+1])
            if '-t' in args:
                atomic_write(key,PRIVATE)
                key.with_suffix('.pub').write_text(PUBLIC+' root@native\n')
            else: output = PUBLIC+' root@native\n'
        elif args[:2] == ('qemu-img','info'):
            output = json.dumps({'format':'qcow2','virtual-size':512*1024**2,'dirty-flag':False})
        elif args[:2] == ('vm','create'):
            self.import_options = kwargs
            root=Path(self.p['root']); root.mkdir(mode=0o700)
            (root/'.cloud-init').mkdir(mode=0o755)  # Packaged manager creates this with its own umask.
            with Path(self.p['disk']).open('wb') as stream: stream.truncate(self.c.office_vm_disk_gib*1024**3)
            atomic_write(self.p['config'],f'uuid="1791a15c-cbeb-11f1-b6ec-589cfc10efa3"\nnetwork0_mac="{self.mac}"\n')
            self.created=True
            if self.fail_create: raise RuntimeError('Simulated interrupted disk import')
        elif args[:2] == ('sysrc','-f') and args[-1].startswith('network0_mac='):
            self.mac=args[-1].split('=',1)[1]
            cfg=Path(args[2]); cfg.write_text(re.sub(r'network0_mac="[^"]+"',f'network0_mac="{self.mac}"',cfg.read_text()))
        elif args[0] == 'sysrc' and args[-1] == 'network0_mac': output=self.mac
        elif args[0] == '/usr/sbin/makefs':
            Path(args[-2]).write_bytes(b'synthetic NoCloud ISO; makefs mocked')
        elif args[0] == 'ssh':
            self.last_ssh = (args,kwargs)
            if self.ssh_change_vm: self.state='Running (92)'
            return self.ssh_result
        else:
            self.calls.pop()
            return super().run(*args,**kwargs)
        return SimpleNamespace(returncode=code,stdout=output)


class VmCreationTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='vm-create-')
        self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)
        self.enterContext(patch.object(Config,'mount_root',new_callable=PropertyMock,return_value=str(self.root/'instance')))
        self.enterContext(patch.object(Config,'bastille_root',new_callable=PropertyMock,return_value=str(self.root/'shared/bastille')))
        self.c=replace(selected('eurooffice'),office_vm_cpus=2,office_vm_disk_gib=1,office_memory_mb=4096)
        self.p=vm.vm_paths(self.c)
        for key in ('manager_root','mountpoint'): Path(self.p[key]).mkdir(mode=0o700,parents=True)
        self.rc=self.root/'etc/rc.conf.d/vm'; self.rc.parent.mkdir(parents=True)
        self.enterContext(patch('installer.office_vm.VM_RC_CONFIG',self.rc))
        self.registry=Registry(self.root/'registry'); self.registry.initialize()
        self.state=self.registry.instance_path(self.c.instance); self.state.mkdir(mode=0o700)
        self.registry.set_status(self.c.instance,'installing')
        self.registry.save_host(self.c)
        self.image=self.root/'image.qcow2'; atomic_write(self.image,'synthetic QCOW bytes; parser mocked')
        image={**IMAGE,'sha512':hashlib.sha512(self.image.read_bytes()).hexdigest()}
        self.plan=dict(schema_version=3,office_backend='eurooffice',roles={'vm_manager':'vm-bhyve'},
            packages={'host':{'vm-bhyve':dict(name='vm-bhyve',version='1.7.5',origin='sysutils/vm-bhyve')}},
            office_runtime={'guest_image':image})
        atomic_json(self.state/'versions.json',self.plan)
        active=self.root/'network-confirmed'; active.mkdir(mode=0o700)
        atomic_json(active/'firewall-transition.json',{'instances':[self.c.instance]})
        self.confirmed=self.enterContext(patch('installer.host.verify_managed_network',return_value=active))
        self.model=CreationModel(self.c,self.p,self.rc)
        self.d=SimpleNamespace(config=self.c,runner=self.model,registry=self.registry,state=self.state,versions=self.plan)

    def test_foreign_configuration_refused_without_owned_marker_even_if_path_matches(self):
        self.model.global_configuration=True
        with self.registry.locked(), self.assertRaisesRegex(ValueError,'administrator-managed'):
            vm.initialize_native_vm_manager(self.d)
        self.assertNotIn('vm_manager',self.registry.host())
        self.assertFalse(self.rc.exists())
        self.assertNotIn(('vm','init'),self.model.calls)

    def test_manager_marker_rc_reconciliation_and_native_host_preservation(self):
        with self.registry.locked(): vm.initialize_native_vm_manager(self.d)
        marker=self.registry.host()['vm_manager']
        self.assertEqual(self.rc.stat().st_mode & 0o777,0o600)
        self.assertIn('vm_list=""',self.rc.read_text())
        self.registry.save_host(self.c)
        self.assertEqual(self.registry.host()['vm_manager'],marker)
        # Interrupted first RC publication: preserve old file, rebuild only the
        # missing file whose exact owned intent and native namespace still match.
        self.rc.rename(self.rc.with_name('vm.retained-before-crash'))
        with self.registry.locked(): vm.initialize_native_vm_manager(self.d)
        self.assertTrue(self.rc.is_file())

    def test_unconfirmed_network_prevents_manager_mutation(self):
        self.confirmed.side_effect=ValueError('unconfirmed network')
        with self.registry.locked(),self.assertRaisesRegex(ValueError,'unconfirmed network'):
            vm.initialize_native_vm_manager(self.d)
        self.assertEqual(self.model.calls,[])
        self.assertNotIn('vm_manager',self.registry.host())

    def test_create_pins_generated_mac_before_private_seed_and_seals_real_disk_identity(self):
        with self.registry.locked(): result=vm.create_native_vm(self.d,self.image)
        self.assertEqual(result['state'],'Stopped')
        self.assertNotEqual(self.model.mac,'58:9c:fc:05:03:fc')

        seed=json.loads((Path(self.p['root'])/'.cloud-init/network-config').read_text())
        self.assertEqual(seed['config'][0]['mac_address'],self.model.mac)
        self.assertEqual(Path(self.p['disk']).stat().st_mode & 0o777,0o600)
        record=private_json(self.state/(self.p['name']+'.creating.json'))
        self.assertEqual(record['disk_inode'],Path(self.p['disk']).stat().st_ino)
        self.assertNotIn('state',record)
        self.assertEqual((Path(self.p['root'])/'seed.iso').stat().st_mode & 0o777,0o600)
        self.assertEqual((Path(self.p['root'])/'.cloud-init').stat().st_mode & 0o777,0o700)
        self.assertFalse(any(c[:2] in (('vm','start'),('vm','destroy')) for c in self.model.calls))
        self.assertEqual(self.model.import_options,dict(hide_output=True,timeout=600,progress_label='Alpine VM disk import'))

    def test_creation_rechecks_current_headroom_before_manager_or_disk_effects(self):
        self.model.available_bytes=512*1024**2
        with self.registry.locked(),self.assertRaisesRegex(ValueError,'Effective VM storage ancestor'):
            vm.create_native_vm(self.d,self.image)
        self.assertFalse(self.model.created)
        self.assertFalse(self.model.registered)
        self.assertFalse(self.rc.exists())

    def test_sealed_creation_reconciles_without_source_reselection_or_reimport(self):
        with self.registry.locked(): vm.create_native_vm(self.d,self.image)
        creates=sum(c[:2]==('vm','create') for c in self.model.calls)
        self.image.rename(self.image.with_name('original-image-retained'))
        with self.registry.locked(): vm.create_native_vm(self.d,self.image)
        self.assertEqual(sum(c[:2]==('vm','create') for c in self.model.calls),creates)

    def test_partial_import_is_retained_and_uncertain_replay_refused_before_any_mutation(self):
        self.model.fail_create=True
        with self.registry.locked(),self.assertRaises(RuntimeError): vm.create_native_vm(self.d,self.image)
        disk=Path(self.p['disk']); inode=disk.stat().st_ino
        before=len(self.model.calls)
        with self.registry.locked(),self.assertRaisesRegex(ValueError,'uncertain creation replay'):
            vm.create_native_vm(self.d,self.image)
        self.assertEqual(len(self.model.calls),before)
        self.assertEqual(disk.stat().st_ino,inode)

    def test_wrong_image_bytes_or_missing_lock_cannot_create_manager_or_guest(self):
        self.image.write_text('changed image bytes')
        with self.registry.locked(),self.assertRaisesRegex(ValueError,'checksum'):
            vm.create_native_vm(self.d,self.image)
        self.assertEqual(self.model.calls,[])
        self.assertFalse(Path(self.p['root']).exists())

    def test_unreserved_matching_datastore_is_not_adopted(self):
        with self.registry.locked(): vm.initialize_native_vm_manager(self.d)
        self.model.registered=True
        with self.registry.locked(),self.assertRaisesRegex(ValueError,'datastore name collision'):
            vm.create_native_vm(self.d,self.image)
        self.assertFalse((self.state/(self.p['name']+'.creating.json')).exists())
        self.assertFalse(any(c[:2] == ('vm','create') for c in self.model.calls))

    def test_foreign_template_is_not_overwritten_or_adopted(self):
        with self.registry.locked(): vm.initialize_native_vm_manager(self.d)
        template=Path(self.p['manager_root'])/'.templates'/(self.p['name']+'.conf')
        atomic_write(template,'retained administrator template\n')
        with self.registry.locked(),self.assertRaisesRegex(ValueError,'Foreign VM creation template'):
            vm.create_native_vm(self.d,self.image)
        self.assertEqual(template.read_text(),'retained administrator template\n')
        self.assertFalse((self.state/(self.p['name']+'.creating.json')).exists())

    def test_image_parent_symlink_or_writable_directory_refuses_before_native_commands(self):
        linked=self.root/'linked'; linked.symlink_to(self.root,target_is_directory=True)
        with self.registry.locked(),self.assertRaises(ValueError):
            vm.create_native_vm(self.d,linked/self.image.name)
        self.assertEqual(self.model.calls,[])
        self.root.chmod(0o777)
        try:
            with self.registry.locked(),self.assertRaises(ValueError):
                vm.create_native_vm(self.d,self.image)
            self.assertEqual(self.model.calls,[])
        finally:
            self.root.chmod(0o700)

    def journal(self,state='running'):
        atomic_json(self.state/'deployment.json',dict(schema_version=2,config_sha256=config_digest(self.c),
                    steps={'Alpine VM boot':{'state':state}}))

    def test_install_start_requires_bound_phase_then_verified_private_switch_and_nic(self):
        with self.registry.locked(): vm.create_native_vm(self.d,self.image)
        with self.registry.locked(),self.assertRaisesRegex(ValueError,'journal'):
            vm.start_native_vm(self.d)
        self.journal()
        with self.registry.locked(): target=vm.start_native_vm(self.d)
        self.assertTrue(target['state'].startswith('Running ('))
        self.assertIn(('vm','switch','create','-t','manual','-b',self.c.onlyoffice_bridge,self.p['switch']),self.model.calls)
        count=self.model.calls.count(('vm','start',self.p['name']))
        with self.registry.locked(): vm.start_native_vm(self.d)
        self.assertEqual(self.model.calls.count(('vm','start',self.p['name'])),count)

    def test_explicit_install_continuation_can_start_completed_boot_step_but_failed_status_cannot(self):
        from unittest.mock import Mock
        with self.registry.locked():vm.create_native_vm(self.d,self.image)
        self.journal('complete')
        self.d.require_original_artifact=Mock()
        with self.registry.locked(),self.assertRaisesRegex(ValueError,'startup permission'):vm.start_native_vm(self.d)
        with self.registry.locked():target=vm.start_native_vm(self.d,install_continuation=True)
        self.assertTrue(target['state'].startswith('Running ('))
        self.d.require_original_artifact.assert_called_once_with()
        self.registry.set_status(self.c.instance,'failed')
        count=self.model.calls.count(('vm','start',self.p['name']))
        with self.registry.locked(),self.assertRaisesRegex(ValueError,'installing journal'):
            vm.start_native_vm(self.d,install_continuation=True)
        self.assertEqual(self.model.calls.count(('vm','start',self.p['name'])),count)

    def test_foreign_bridge_switch_or_pending_transaction_never_starts_guest(self):
        with self.registry.locked(): vm.create_native_vm(self.d,self.image)
        self.journal()
        self.model.bad_bridge=True
        with self.registry.locked(),self.assertRaisesRegex(ValueError,'foreign members'):
            vm.start_native_vm(self.d)
        self.model.bad_bridge=False
        self.model.switch_registered=self.model.bad_switch=True
        with self.registry.locked(),self.assertRaisesRegex(ValueError,'foreign or NAT'):
            vm.start_native_vm(self.d)
        with self.registry.locked(),patch('installer.firewall.pending_transactions',return_value=(self.root,)),self.assertRaises(ValueError):
            vm.start_native_vm(self.d)
        self.assertNotIn(('vm','start',self.p['name']),self.model.calls)

    def test_normal_start_needs_ready_complete_and_bound_boot_permission(self):
        with self.registry.locked(): vm.create_native_vm(self.d,self.image)
        self.journal('complete')
        with self.registry.locked(),self.assertRaisesRegex(ValueError,'startup permission'):
            vm.start_native_vm(self.d)
        atomic_write(self.state/'allow-vm-start',config_digest(self.c)+'\n')
        atomic_write(self.state/'complete','completed\n')
        self.registry.set_status(self.c.instance,'ready')
        with self.registry.locked(): target=vm.start_native_vm(self.d)
        self.assertTrue(target['state'].startswith('Running ('))

    def image_response(self,data):
        response=io.BytesIO(data)
        response.status=200
        response.headers={'Content-Length':str(len(data))}
        return response

    def test_image_acquisition_uses_exact_tls_origin_and_verified_cache_without_reselection(self):
        data=self.image.read_bytes()
        calls=[]
        def open_image(url,timeout):
            calls.append((url,timeout))
            return self.image_response(data)
        opener=SimpleNamespace(open=open_image)
        with self.registry.locked(),patch('urllib.request.build_opener',return_value=opener) as build:
            path=vm.acquire_guest_image(self.d)
        self.assertEqual(path.read_bytes(),data)
        self.assertEqual(path.stat().st_mode & 0o777,0o600)
        self.assertEqual(calls,[(self.plan['office_runtime']['guest_image']['url'],30)])
        with self.registry.locked(),patch('urllib.request.build_opener',side_effect=AssertionError('cached image network')):
            self.assertEqual(vm.acquire_guest_image(self.d),path)
        path.write_bytes(b'changed cache')
        with self.registry.locked(),self.assertRaisesRegex(ValueError,'no replacement selected'):
            vm.acquire_guest_image(self.d)

    def test_bad_download_is_private_evidence_not_a_complete_cache_or_guest(self):
        opener=SimpleNamespace(open=lambda url,timeout: self.image_response(b'wrong download'))
        with self.registry.locked(),patch('urllib.request.build_opener',return_value=opener),self.assertRaisesRegex(ValueError,'no fallback'):
            vm.acquire_guest_image(self.d)
        directory=self.state/'vm-acquisition'
        self.assertFalse((directory/'image.qcow2').exists())
        partial=list(directory.glob('*.partial'))
        self.assertEqual(len(partial),1)
        self.assertEqual(partial[0].read_bytes(),b'wrong download')
        self.assertEqual(partial[0].stat().st_mode & 0o777,0o600)
        self.assertFalse(Path(self.p['root']).exists())

    def test_sealed_seed_file_or_iso_tampering_refuses_start_before_commands(self):
        with self.registry.locked(): vm.create_native_vm(self.d,self.image)
        self.journal()
        target=Path(self.p['root'])/'.cloud-init/network-config'
        original=target.read_text()
        target.write_text('changed network seed')
        with self.registry.locked(),self.assertRaisesRegex(ValueError,'seed'):
            vm.start_native_vm(self.d)
        target.write_text(original)
        iso=Path(self.p['root'])/'seed.iso'
        iso.write_bytes(b'changed iso')
        with self.registry.locked(),self.assertRaisesRegex(ValueError,'seed ISO'):
            vm.start_native_vm(self.d)
        self.assertFalse(any(c[:2]==('vm','start') for c in self.model.calls))

    def test_guest_command_uses_original_pinned_keys_private_stdin_and_checks_runtime_after(self):
        with self.registry.locked(): vm.create_native_vm(self.d,self.image)
        self.model.state='Running (91)'
        with self.registry.locked():
            vm.run_native_guest(self.d,('/bin/cat','/etc/alpine-release'),input='secret-canary')
        args,options=self.model.last_ssh
        self.assertNotIn('secret-canary',repr(args))
        self.assertEqual(options['input'],'secret-canary')
        self.assertTrue(options['hide_output'])
        self.assertIn('StrictHostKeyChecking=yes',args)
        self.assertNotIn('accept-new',args)
        self.model.ssh_change_vm=True
        with self.registry.locked(),self.assertRaisesRegex(ValueError,'runtime changed'):
            vm.run_native_guest(self.d,('/bin/true',))

    def test_guest_missing_keys_or_changed_known_host_is_refused_not_repaired(self):
        with self.registry.locked(): vm.create_native_vm(self.d,self.image)
        self.model.state='Running (91)'
        known=self.state/'vm-keys/known_hosts'
        atomic_write(known,'foreign-key\n')
        with self.registry.locked(),self.assertRaisesRegex(ValueError,'trust changed'):
            vm.run_native_guest(self.d,('/bin/true',))
        key=self.state/'vm-keys/admin_ed25519'
        key.rename(key.with_name('admin-retained-evidence'))
        with self.registry.locked(),self.assertRaisesRegex(ValueError,'keys are missing'):
            vm.run_native_guest(self.d,('/bin/true',))
        self.assertIsNone(self.model.last_ssh)

    def test_readonly_guest_inspection_refuses_missing_trust_file_instead_of_creating_it(self):
        with self.registry.locked(): vm.create_native_vm(self.d,self.image)
        self.model.state='Running (91)'
        known=self.state/'vm-keys/known_hosts'
        with self.registry.locked(),self.assertRaisesRegex(ValueError,'original pinned trust'):
            vm.run_native_guest(self.d,('docker','version'),read_only=True)
        self.assertFalse(known.exists())
        self.assertIsNone(self.model.last_ssh)
        with self.registry.locked(): vm.run_native_guest(self.d,('/bin/true',))
        before=known.stat().st_mtime_ns
        with self.registry.locked(): vm.run_native_guest(self.d,('docker','version'),read_only=True)
        self.assertEqual(known.stat().st_mtime_ns,before)
        self.assertIn('/usr/bin/docker --host=unix:///var/run/docker.sock version',self.model.last_ssh[0][-1])
        self.assertIn('/usr/bin/env -i',self.model.last_ssh[0][-1])

    def test_static_multiline_program_is_single_scalar_through_real_guest_argument_guard(self):
        with self.assertRaisesRegex(ValueError,'argument size'):
            vm._guest_python('x'*4096)
        with self.registry.locked(): vm.create_native_vm(self.d,self.image)
        self.model.state='Running (91)'
        program="import sys\nassert sys.stdin.read() == 'private-input'\n"
        encoded=vm._guest_python(program)
        self.assertFalse(any(ord(c)<32 for c in encoded))
        with self.registry.locked():
            vm.run_native_guest(self.d,('python3','-c',encoded),input='private-input')
        args,kwargs=self.model.last_ssh
        self.assertIn('compile(',args[-1])
        self.assertEqual(kwargs['input'],'private-input')
        self.model.last_ssh=None
        with self.registry.locked(),self.assertRaises(ValueError):
            vm.run_native_guest(self.d,('python3','-c',program))
        self.assertIsNone(self.model.last_ssh)

    def test_readiness_requires_clean_nocloud_and_does_not_hide_degraded_status(self):
        good=dict(status='done',extended_status='done',datasource='nocloud',errors=[],recoverable_errors={})
        with patch('installer.office_vm.run_native_guest',return_value=SimpleNamespace(returncode=0,stdout=json.dumps(good))):
            self.assertEqual(vm.wait_native_guest(self.d),good)
        for code,text in ((2,json.dumps({**good,'extended_status':'degraded done'})),
                          (0,'not-json'),(0,json.dumps({**good,'datasource':'ec2'}))):
            with self.subTest(code=code),patch('installer.office_vm.run_native_guest',return_value=SimpleNamespace(returncode=code,stdout=text)),self.assertRaises(ValueError):
                vm.wait_native_guest(self.d)

    def test_guest_bootstrap_retains_network_allocation_and_never_sends_host_credentials(self):
        result=SimpleNamespace(returncode=0,stdout='172.31.250.0/24\n',stderr='')
        with self.registry.locked(),patch.object(self.registry,'entries',return_value=[(self.c,{'state':'installing'})]), \
                patch('installer.office_vm.wait_native_guest'),patch('installer.office_vm._stage_native_guest_public') as stage, \
                patch('installer.office_vm.run_native_guest',return_value=result) as execute:
            payload=vm.bootstrap_native_guest(self.d)
        self.assertEqual(payload['docker_network'],'172.31.250.0/24')
        self.assertEqual({call.args[1] for call in stage.call_args_list},{'runtime','bootstrap'})
        self.assertNotIn(PRIVATE,repr(stage.call_args_list))
        self.assertNotIn('jwt_secret',repr(stage.call_args_list))
        self.assertEqual(execute.call_args_list[0].args[1],('/bin/sh','/root/cloud-installer/resources/vm/bootstrap.sh','/root/cloud-installer/runtime.json'))
        saved=(self.state/'vm-runtime.json').read_bytes()
        other=replace(self.c,instance='other',private_network='172.31.250.0/29')
        with self.registry.locked(),patch.object(self.registry,'entries',return_value=[(other,{'state':'ready'})]), \
                patch('installer.office_vm.wait_native_guest'),patch('installer.office_vm._stage_native_guest_public') as stage, \
                self.assertRaisesRegex(ValueError,'no reselection'):
            vm.bootstrap_native_guest(self.d)
        self.assertEqual((self.state/'vm-runtime.json').read_bytes(),saved)
        stage.assert_not_called()

    def test_docker_pool_selection_is_private_nonoverlapping_and_bounded(self):
        self.assertEqual(vm.select_docker_network(['10.77.0.0/16']),'172.31.250.0/24')
        self.assertEqual(vm.select_docker_network(['10.0.0.0/8','172.16.0.0/12']),'192.168.250.0/24')
        with self.assertRaises(ValueError): vm.select_docker_network(['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'])
