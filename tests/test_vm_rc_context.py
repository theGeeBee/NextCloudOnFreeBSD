"""Native rc loader context checks without sourcing shell or invoking vm-bhyve."""
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from installer.office_vm import _vm_rc_context


class VmRcContextTests(unittest.TestCase):
    def test_later_service_override_file_or_directory_is_refused_before_vm_commands(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);directory=root/'rc.d';directory.mkdir()
            override=root/'rc.conf.d/vm';override.parent.mkdir()
            runner=Mock();runner.run.return_value=SimpleNamespace(returncode=0,stdout=str(directory))
            self.assertEqual(_vm_rc_context(runner),(directory,))
            override.write_text('vm_dir="/unrelated"\n')
            with self.assertRaisesRegex(ValueError,'Foreign service-specific'):_vm_rc_context(runner)
            override.rename(root/'retained-vm.conf');override.mkdir()
            with self.assertRaisesRegex(ValueError,'Foreign service-specific'):_vm_rc_context(runner)
            self.assertFalse(any(call.args[0]=='vm' for call in runner.run.call_args_list))

    def test_owned_location_can_be_repeated_by_loader_but_duplicate_startup_dirs_refuse(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);owned=root/'rc.conf.d/vm';owned.parent.mkdir();owned.write_text('owned')
            runner=Mock();runner.run.return_value=SimpleNamespace(returncode=0,stdout=str(root/'rc.d'))
            with patch('installer.office_vm.VM_RC_CONFIG',owned):
                self.assertEqual(_vm_rc_context(runner),(root/'rc.d',))
                runner.run.return_value.stdout=str(root/'rc.d')+' '+str(root/'rc.d')
                with self.assertRaisesRegex(ValueError,'Ambiguous'):_vm_rc_context(runner)

    def test_dynamic_or_relative_configuration_is_not_evaluated(self):
        for value in ('relative/rc.d','/tmp/$(id)/rc.d'):
            runner=Mock();runner.run.return_value=SimpleNamespace(returncode=0,stdout=value)
            with self.subTest(value=value),self.assertRaises(ValueError):_vm_rc_context(runner)
            self.assertEqual(runner.run.call_count,1)
