"""Native Docker default-registry display normalization, never tag substitution."""
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from installer.office_vm import _guest_json,_same_image_reference,_image_reference_spellings


class DockerReferenceSpellingTests(unittest.TestCase):
    reference='docker.io/collabora/code@sha256:56541aad09403975646dfb87a3716e38afecce09b5f853391eb6d937a0ccd402'

    def test_only_optional_default_registry_prefix_may_differ(self):
        short=self.reference.removeprefix('docker.io/')
        self.assertEqual(_image_reference_spellings(self.reference),(self.reference,short))
        self.assertTrue(_same_image_reference(short,self.reference))
        for actual in (short.replace('collabora','other'),short.replace('sha256:5','sha256:6'),
                       'ghcr.io/'+short,'example.org/'+short,short.replace('@sha256:',':latest@sha256:'),
                       'collabora/code:latest',None,[]):
            with self.subTest(actual=actual):self.assertFalse(_same_image_reference(actual,self.reference))
        qualified='ghcr.io/euro-office/documentserver@sha256:'+'a'*64
        self.assertEqual(_image_reference_spellings(qualified),(qualified,))
        self.assertFalse(_same_image_reference(qualified.removeprefix('ghcr.io/'),qualified))

    def test_actual_native_missing_image_error_matches_only_that_exact_digest(self):
        args=('docker','image','inspect',self.reference)
        text='Error response from daemon: No such image: '+self.reference.removeprefix('docker.io/')+'\n'
        with patch('installer.office_vm.run_native_guest',return_value=SimpleNamespace(returncode=1,stdout='[]\n',stderr=text)):
            self.assertIsNone(_guest_json(object(),args,optional=True))
            with self.assertRaises(RuntimeError):_guest_json(object(),args,read_only=True)

    def test_other_inspection_errors_do_not_become_missing_or_allow_reconstruction(self):
        args=('docker','image','inspect',self.reference)
        short=self.reference.removeprefix('docker.io/')
        for code,stdout,stderr in ((255,'[]','Error response from daemon: No such image: '+short),
            (1,'[]','Error response from daemon: No such image: '+short.replace('collabora/code','other/code')),
            (1,'[]','Cannot connect to the Docker daemon'),(1,'',''),
            (1,'[{"unexpected":true}]','Error response from daemon: No such image: '+short)):
            with self.subTest(code=code,stderr=stderr),patch('installer.office_vm.run_native_guest',
                    return_value=SimpleNamespace(returncode=code,stdout=stdout,stderr=stderr)),self.assertRaises(RuntimeError):
                _guest_json(object(),args,optional=True)
