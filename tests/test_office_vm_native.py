"""Native VM key commands mocked; never generate keys or provision a host here."""

import base64
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from installer.office_vm import native_key_pair
from test_office_vm import PRIVATE, PUBLIC


class NativeKeyPairTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='vm-key-test-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.private = self.directory / 'host_ed25519'
        self.public = self.directory / 'host_ed25519.pub'
        self.runner = Mock()
        self.runner.run.return_value = SimpleNamespace(returncode=0, stdout=PUBLIC + ' root@native-host\n')

    def existing(self):
        self.private.write_text(PRIVATE)
        self.public.write_text(PUBLIC + ' root@native-host\n')
        self.private.chmod(0o600)
        self.public.chmod(0o600)

    def test_existing_pair_is_natively_verified_and_comment_normalized_without_regeneration(self):
        self.existing()
        before = self.private.read_bytes()
        result = native_key_pair(self.runner, self.directory, 'host')
        self.assertEqual(result, dict(private_path=str(self.private), public_path=str(self.public), public_key=PUBLIC))
        self.runner.run.assert_called_once_with('/usr/bin/ssh-keygen', '-y', '-f', str(self.private),
                                               input='', hide_output=True, timeout=15)
        self.assertEqual(self.private.read_bytes(), before)
        self.assertNotIn(PRIVATE, repr(self.runner.mock_calls))

    def test_fresh_pair_generation_uses_protected_paths_and_private_output(self):
        def native(*args, **kwargs):
            self.assertEqual(kwargs, dict(input='', hide_output=True, timeout=15))
            if '-t' in args:
                self.private.write_text(PRIVATE)
                self.private.chmod(0o600)
                self.public.write_text(PUBLIC + ' comment\n')
                self.public.chmod(0o644)  # Native ssh-keygen output is tightened by the caller.
                return SimpleNamespace(returncode=0, stdout='')
            return SimpleNamespace(returncode=0, stdout=PUBLIC + ' comment\n')
        self.runner.run.side_effect = native
        native_key_pair(self.runner, self.directory, 'host')
        self.assertEqual(self.public.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.runner.run.call_args_list[0].args,
                         ('/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(self.private)))

    def test_partial_pair_is_retained_and_refused_without_execution(self):
        for target in (self.private, self.public):
            with self.subTest(target=target.name), tempfile.TemporaryDirectory() as d:
                file = Path(d) / target.name
                file.write_text('retained incomplete state')
                with self.assertRaisesRegex(ValueError, 'retain private state'):
                    native_key_pair(self.runner, d, 'host')
                self.assertEqual(file.read_text(), 'retained incomplete state')
        self.runner.run.assert_not_called()

    def test_public_mismatch_and_failure_output_are_not_exposed(self):
        self.existing()
        body = bytearray(base64.b64decode(PUBLIC.split()[1]))
        body[-1] ^= 1
        other = 'ssh-ed25519 ' + base64.b64encode(body).decode()
        self.runner.run.return_value.stdout = other
        with self.assertRaisesRegex(ValueError, 'verification failed'):
            native_key_pair(self.runner, self.directory, 'host')
        self.runner.run.side_effect = RuntimeError('secret-canary ' + PRIVATE)
        with self.assertRaises(ValueError) as caught:
            native_key_pair(self.runner, self.directory, 'host')
        self.assertIsNone(caught.exception.__cause__)
        self.assertNotIn('secret-canary', str(caught.exception))
        self.assertNotIn(PRIVATE, str(caught.exception))

    def test_file_change_during_verification_is_refused(self):
        self.existing()
        def mutate(*args, **kwargs):
            self.private.write_text(PRIVATE + '\n')
            return SimpleNamespace(returncode=0, stdout=PUBLIC)
        self.runner.run.side_effect = mutate
        with self.assertRaisesRegex(ValueError, 'verification failed'):
            native_key_pair(self.runner, self.directory, 'host')

    def test_unsafe_directory_file_links_modes_and_roles_are_refused(self):
        self.existing()
        for mode in (0o755, 0o777):
            self.directory.chmod(mode)
            with self.assertRaises(ValueError):
                native_key_pair(self.runner, self.directory, 'host')
        self.directory.chmod(0o700)
        self.public.chmod(0o644)
        with self.assertRaises(ValueError):
            native_key_pair(self.runner, self.directory, 'host')
        self.public.chmod(0o600)
        alias = self.directory / 'alias'
        alias.symlink_to(self.directory)
        with self.assertRaises(ValueError):
            native_key_pair(self.runner, alias, 'host')
        for role in ('foreign', '../host', 'host\nsecret-canary'):
            with self.assertRaises(ValueError):
                native_key_pair(self.runner, self.directory, role)
        self.runner.run.assert_not_called()
