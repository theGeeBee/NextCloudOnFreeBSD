"""Offline transport fixtures only; not native FreeBSD or provisioning evidence."""

import hashlib
import importlib.util
import os
import pty
import shlex
import subprocess
import unittest
from unittest.mock import patch

import test_release_command
from test_installer import ROOT


PIN_URL = ('https://github.com/theGeeBee/NextCloudOnFreeBSD/releases/download/'
           'v2026.10.23/NextCloudOnFreeBSD-2026.10.23.tar.gz')
PIN_DIGEST = 'b8740d8263ca26d9ed73b1b9584a4dda145422adc4b84370875d76892cbeaad2'
# The published script quotes even shell-safe pins.
PIN_LINE = "set -- '" + PIN_URL + "' '" + PIN_DIGEST + "'"
SYSTEM_PATH = 'PATH=/sbin:/bin:/usr/sbin:/usr/bin'


def launcher_module():
    spec = importlib.util.spec_from_file_location('bootstrap_command', ROOT / 'tools/bootstrap-command.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def execute_fixture(test, argv, environment, terminal):
    if not terminal:
        return subprocess.run(argv, cwd=test.root, env=environment, capture_output=True,
                              text=True, timeout=10)
    master, slave = pty.openpty()
    try:
        return subprocess.run(argv, cwd=test.root, env=environment, stdin=slave, stdout=slave,
                              stderr=subprocess.PIPE, text=True, timeout=10)
    finally:
        os.close(master)
        os.close(slave)


class StandaloneTests(test_release_command.CommandTests):
    def run_command(self, *, digest=None,
                    url='https://artifacts.example.invalid/releases/reviewed/cloud-installer.tar.gz',
                    env=None, terminal=True, args=()):
        body = (ROOT / 'bootstrap.sh').read_text()
        self.assertEqual(body.count(PIN_LINE), 1)
        body = body.replace(PIN_LINE, 'set -- ' + shlex.quote(url) + ' ' + shlex.quote(digest or self.digest))
        body = body.replace('/var', str(self.root / 'var'))
        body = body.replace(SYSTEM_PATH, 'PATH=' + shlex.quote(str(self.bin) + ':/usr/bin:/bin'))
        if env and env.get('TEST_LIMIT_FAIL'):
            body = 'ulimit() { return 1; }\n' + body
        script = self.root / 'bootstrap.sh'
        script.write_text(body)
        environment = {**os.environ, 'BASE': str(self.root), 'EVENTS': str(self.events),
                       'FIXTURE': str(self.archive), 'SSL_NO_VERIFY_PEER': '1',
                       'SSL_NO_VERIFY_HOSTNAME': '1', 'SSL_ALLOW_SSL3': '1',
                       'TAR_OPTIONS': '--checkpoint-action=exec=false',
                       'TAR_READER_OPTIONS': 'unsafe', 'TAR_WRITER_OPTIONS': 'unsafe', **(env or {})}
        return execute_fixture(self, ['/bin/sh', str(script), *args], environment, terminal)

    def test_url_metacharacters_are_literal_not_shell_code(self):
        # Controlled replacement of the known pin, not a runtime URL option.
        url = "https://example.invalid/releases/v1/quo'te;$(touch${IFS}UNEXPECTED)/cloud-installer.tar.gz"
        result = self.run_command(url=url)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'fetched-url').read_text(), url)
        self.assertFalse((self.root / 'UNEXPECTED').exists())

    def test_extra_arguments_refused_before_download(self):
        for args in (('install',), ('--url', 'https://example.invalid/payload'), ('',)):
            with self.subTest(args=args):
                result = self.run_command(args=args)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Usage:', result.stderr)
                self.assertFalse(self.events.exists())

    def test_published_pins_and_original_transport_body_are_exact(self):
        body = (ROOT / 'bootstrap.sh').read_text()
        self.assertEqual(body.count(PIN_LINE + '\n'), 1)
        # A script file has a terminating newline; the command string does not.
        original = self.builder.RELEASE_COMMAND
        self.assertEqual(body[body.index(SYSTEM_PATH):], original[original.index(SYSTEM_PATH):] + '\n')
        prefix = body[:body.index(SYSTEM_PATH)]
        self.assertIn('[ "$#" -eq 0 ]', prefix)
        self.assertLess(prefix.index('[ "$#" -eq 0 ]'), prefix.index(PIN_LINE))
        result = subprocess.run(['/bin/sh', '-n', str(ROOT / 'bootstrap.sh')],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)


class LauncherTests(unittest.TestCase):
    def setUp(self):
        test_release_command.CommandTests.setUp(self)
        self.launcher = launcher_module()
        self.commit = '0123456789abcdef' * 2 + '01234567'
        self.payload = self.root / 'mock-bootstrap.sh'
        self.payload.write_text('#!/bin/sh\nprintf "executed:%s\\n" "$#" >> "$EVENTS"\n'
                                'ulimit -f > "$BASE/launcher-file-limit"\n')
        self.payload_digest = hashlib.sha256(self.payload.read_bytes()).hexdigest()

    def run_launcher(self, *, digest=None, env=None, terminal=True):
        body = self.launcher.LAUNCHER.replace(
            SYSTEM_PATH, 'PATH=' + shlex.quote(str(self.bin) + ':/usr/bin:/bin'))
        # Keep all launcher artifacts inside the automatically cleaned sandbox.
        body = body.replace('/tmp/nextcloud-bootstrap.XXXXXXXX',
                            str(self.root / 'nextcloud-bootstrap.XXXXXXXX'))
        if env and env.get('TEST_LIMIT_FAIL'):
            body = 'ulimit() { return 1; }; ' + body
        with patch.object(self.launcher, 'LAUNCHER', body):
            command = self.launcher.install_command(self.commit, digest or self.payload_digest)
        environment = {**os.environ, 'BASE': str(self.root), 'EVENTS': str(self.events),
                       'FIXTURE': str(self.payload), 'SSL_NO_VERIFY_PEER': '1',
                       'SSL_NO_VERIFY_HOSTNAME': '1', 'SSL_ALLOW_SSL3': '1', **(env or {})}
        return execute_fixture(self, ['/bin/sh', '-c', command], environment, terminal)

    def test_hash_precedes_exact_no_argument_execution_without_inherited_limit(self):
        result = self.run_launcher()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.events.read_text().splitlines(), ['fetch', 'sha256', 'executed:0'])
        self.assertEqual((self.root / 'fetched-url').read_text(),
                         'https://raw.githubusercontent.com/theGeeBee/NextCloudOnFreeBSD/'
                         + self.commit + '/bootstrap.sh')
        inherited = subprocess.check_output(['/bin/sh', '-c', 'ulimit -f'], text=True).strip()
        self.assertEqual((self.root / 'launcher-file-limit').read_text().strip(), inherited)

    def test_bad_hash_fetch_hash_or_limit_failure_never_executes(self):
        cases = [({'digest': '0' * 64}, ['fetch', 'sha256']),
                 ({'env': {'TEST_FETCH_FAIL': '1'}}, ['fetch']),
                 ({'env': {'TEST_SHA_FAIL': '1'}}, ['fetch', 'sha256']),
                 ({'env': {'TEST_LIMIT_FAIL': '1'}}, [])]
        for kwargs, expected in cases:
            with self.subTest(kwargs=kwargs):
                if self.events.exists():
                    self.events.unlink()
                result = self.run_launcher(**kwargs)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.events.read_text().splitlines() if self.events.exists() else [], expected)
                self.assertFalse((self.root / 'launcher-file-limit').exists())

    def test_root_platform_and_terminal_guards_precede_download(self):
        for kwargs in ({'env': {'TEST_UID': '1000'}}, {'env': {'TEST_OS': 'Linux'}},
                       {'terminal': False}):
            with self.subTest(kwargs=kwargs):
                result = self.run_launcher(**kwargs)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.events.exists())

    def test_loader_validates_full_commit_and_digest(self):
        for commit in ('', 'main', 'latest', 'v2026.10.23', 'a' * 39, 'a' * 41,
                       'A' * 40, 'g' * 40, 'a' * 40 + '\n', None,
                       'https://example.invalid/bootstrap.sh', 'refs/heads/main'):
            with self.subTest(commit=commit), self.assertRaises(ValueError):
                self.launcher.install_command(commit, self.payload_digest)
        for digest in ('', 'a' * 63, 'a' * 65, 'A' * 64, 'g' * 64, None, 'a' * 64 + '\n'):
            with self.subTest(digest=digest), self.assertRaises(ValueError):
                self.launcher.install_command(self.commit, digest)

    def test_cli_prints_exact_single_physical_shell_command(self):
        result = subprocess.run(
            [os.sys.executable, str(ROOT / 'tools/bootstrap-command.py'),
             '--commit', self.commit, '--sha256', self.payload_digest],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        command = self.launcher.install_command(self.commit, self.payload_digest)
        self.assertEqual(result.stdout, command + '\n')
        self.assertEqual(len(result.stdout.splitlines()), 1)
        parts = shlex.split(command)
        self.assertEqual(parts, ['/bin/sh', '-c', self.launcher.LAUNCHER, 'bootstrap',
                                'https://raw.githubusercontent.com/theGeeBee/NextCloudOnFreeBSD/'
                                + self.commit + '/bootstrap.sh', self.payload_digest])
        syntax = subprocess.run(['/bin/sh', '-n', '-c', command], capture_output=True,
                                text=True, timeout=10)
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        invalid = subprocess.run(
            [os.sys.executable, str(ROOT / 'tools/bootstrap-command.py'),
             '--commit', 'main', '--sha256', self.payload_digest],
            capture_output=True, text=True, timeout=10)
        self.assertNotEqual(invalid.returncode, 0)
        self.assertEqual(invalid.stdout, '')


if __name__ == '__main__':
    unittest.main()
