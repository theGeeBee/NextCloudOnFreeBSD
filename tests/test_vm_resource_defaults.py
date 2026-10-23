"""Policy-derived wizard allocation, no host probes or public gate bypass."""
from copy import deepcopy
from pathlib import Path
import unittest
from unittest.mock import patch

from installer.config import Config
from installer.versions import load_policy, vm_resource_policy
from installer.wizard import vm_initial_budgets, initial_config
from test_ui import host_facts


class VmResourceDefaultsTests(unittest.TestCase):
    def config(self, backend):
        return Config.from_json((Path(__file__).resolve().parents[1]/'examples'/f'{backend}.json').read_text())

    def test_reviewed_vm_defaults_and_three_callback_capable_workers_fit_floor(self):
        for backend in ('eurooffice','collabora'):
            c=self.config(backend)
            with self.subTest(backend=backend), patch('subprocess.run') as run:
                values=vm_initial_budgets(c,6592)
                self.assertEqual((values['office_vm_cpus'],values['office_memory_mb'],values['office_vm_disk_gib']), (2,4096,16))
                self.assertEqual(values['php_budget_mb'],1536)
                for key,value in values.items():setattr(c,key,value)
                self.assertEqual(c.php_children,3)
                self.assertGreaterEqual(c.php_callback_children,1)
                with self.assertRaisesRegex(ValueError,'at least 6592 MiB'):vm_initial_budgets(c,6591)
                run.assert_not_called()

    def test_larger_budgets_do_not_oversubscribe_or_resize_guest_opportunistically(self):
        for available in (6592,7679,7680,10112,16384):
            c=self.config('collabora');values=vm_initial_budgets(c,available)
            total=sum(values[k] for k in ('office_memory_mb','db_buffer_mb','redis_memory_mb','php_budget_mb'))+640
            self.assertLessEqual(total,available)
            self.assertEqual(values['office_memory_mb'],4096)

    def test_per_request_php_limit_keeps_three_workers_not_a_fixed_pool_size(self):
        c=self.config('collabora');c.php_memory_mb=1024
        values=vm_initial_budgets(c,8128)
        self.assertEqual(values['php_budget_mb'],3072)
        with self.assertRaisesRegex(ValueError,'at least 8128 MiB'):vm_initial_budgets(c,8127)

    def test_future_reviewed_defaults_are_data_driven_and_returned_as_copies(self):
        c=self.config('collabora');policy=load_policy()
        profile=next(p for p in policy['profiles'] if p.get('office_backend')=='collabora')
        profile['office_runtime']['resources']['defaults']={'cpus':4,'memory_mb':6144,'disk_gib':24}
        values=vm_initial_budgets(c,8640,policy=policy)
        self.assertEqual((values['office_vm_cpus'],values['office_memory_mb'],values['office_vm_disk_gib']), (4,6144,24))
        selected=vm_resource_policy(c,policy);selected['defaults']['cpus']=99
        self.assertEqual(vm_resource_policy(c,policy)['defaults']['cpus'],4)

    def test_ambiguous_or_wrong_target_policy_refuses_without_guessing(self):
        c=self.config('collabora');policy=load_policy()
        duplicate=deepcopy(next(p for p in policy['profiles'] if p.get('office_backend')=='collabora'))
        duplicate['id']+='-second';policy['profiles'].append(duplicate)
        with self.assertRaisesRegex(ValueError,'one reviewed VM resource profile'):vm_resource_policy(c,policy)
        c.architecture='aarch64'
        with self.assertRaises(ValueError):vm_resource_policy(c)
        with self.assertRaises(ValueError):vm_resource_policy(Config())

    def test_initial_config_uses_reviewed_policy_and_combined_host_budget(self):
        for backend in ('eurooffice','collabora'):
            c=initial_config(host_facts(16384),office_backend=backend)
            self.assertEqual((c.office_vm_cpus,c.office_memory_mb,c.office_vm_disk_gib),(2,4096,16))
            self.assertLessEqual(c.memory_budget_mb,16384)
