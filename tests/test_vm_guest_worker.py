"""Guest Docker wire validation in a mapped private filesystem; no APK/Docker."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'resources/vm/bootstrap.sh').read_text()
VALIDATE = SOURCE.split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
SETTINGS = dict(schema_version=1, alpine_branch='3.24', address='10.78.0.6',
                docker_network='172.31.250.0/24',
                managed_networks=['10.77.0.0/29', '10.78.0.4/30', '192.168.122.0/24'])


class GuestDockerValidationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='guest-worker-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name in ('etc/apk', 'var/lib', 'var/run', 'root'):
            (self.root / name).mkdir(parents=True, mode=0o700, exist_ok=True)
        (self.root / 'etc/alpine-release').write_text('3.24.2\n')
        (self.root / 'etc/apk/repositories').write_text('https://dl-cdn.alpinelinux.org/alpine/v3.24/main\n')
        self.config = self.root / 'root/runtime.json'
        self.state = self.root / 'var/lib/cloud-installer/office'

    def validate(self, settings=None, text=None, address='10.78.0.6', inventory=None):
        self.config.write_text(text if text is not None else json.dumps(SETTINGS if settings is None else settings))
        self.config.chmod(0o600)
        def mapped(value):
            p = Path(value)
            return p if p.is_relative_to(self.root) else self.root / p.relative_to('/')
        # Only map paths and simulated root ownership into an unprivileged test
        # directory. Every value/branch/repository/runtime check is production code.
        code = VALIDATE.replace('from pathlib import Path\n', '').replace('info.st_uid != 0', 'info.st_uid != os.geteuid()')
        def native(args,**kwargs):
            if args==['apk','info','-v']: return SimpleNamespace(stdout=inventory or 'docker-29.8.2-r0\n',returncode=0)
            return SimpleNamespace(stdout=f'2: eth0: UP\n    inet {address}/30 scope global eth0\n',returncode=0)
        with patch.object(sys, 'argv', ['-', str(self.config), '/var/lib/cloud-installer/office']), \
                patch('subprocess.run', side_effect=native) as run:
            before_umask = os.umask(0o077)
            try:
                try:exec(compile(code, 'guest-public-validation', 'exec'), {'Path': mapped})
                except SystemExit as error:
                    if error.code!=0:raise
            finally:
                os.umask(before_umask)
        self.assertEqual(run.call_args_list[0].args,(['ip','-4','address','show'],))

    def test_valid_settings_pin_stable_signed_repositories_private_api_and_bounded_logs(self):
        self.validate()
        expected = self.state / 'daemon.json.expected'
        daemon = json.loads(expected.read_text())
        self.assertEqual(daemon, {'bip': '172.31.250.1/24', 'hosts': ['unix:///var/run/docker.sock'],
                                  'log-driver': 'json-file', 'log-opts': {'max-size': '10m', 'max-file': '3'}})
        self.assertEqual(expected.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o700)
        repos = (self.root / 'etc/apk/repositories').read_text()
        self.assertEqual(repos, 'https://dl-cdn.alpinelinux.org/alpine/v3.24/main\nhttps://dl-cdn.alpinelinux.org/alpine/v3.24/community\n')
        self.assertFalse((self.root / 'etc/docker/daemon.json').exists())
        before = expected.stat().st_mtime_ns
        with self.assertRaisesRegex(SystemExit,'uncertain'):self.validate()
        self.assertEqual(expected.stat().st_mtime_ns, before)

    def test_completed_guest_receipt_reconciles_inventory_without_apk_install_or_receipt_rewrite(self):
        self.validate()
        daemon=self.root/'etc/docker/daemon.json';daemon.parent.mkdir(mode=0o700)
        daemon.write_bytes((self.state/'daemon.json.expected').read_bytes());daemon.chmod(0o600)
        (self.state/'packages.txt').write_text('docker-29.8.2-r0\n');(self.state/'packages.txt').chmod(0o600)
        (self.state/'docker-version.txt').write_text('29.8.2\n');(self.state/'docker-version.txt').chmod(0o600)
        complete=self.state/'bootstrap-complete.json'
        complete.write_text(json.dumps({'schema_version':1,'runtime_sha256':hashlib.sha256(self.config.read_bytes()).hexdigest(),
            'packages_sha256':hashlib.sha256((self.state/'packages.txt').read_bytes()).hexdigest(),
            'daemon_sha256':hashlib.sha256(daemon.read_bytes()).hexdigest(),'docker_version':'29.8.2'}));complete.chmod(0o600)
        before=complete.stat().st_mtime_ns
        self.validate()
        self.assertEqual(complete.stat().st_mtime_ns,before)
        with self.assertRaises(SystemExit):self.validate(inventory='docker-30.0.0-r0\n')

    def test_invalid_unknown_credentials_and_duplicate_keys_fail_before_state(self):
        for settings in ({**SETTINGS, 'jwt_secret': 'secret-canary'}, {**SETTINGS, 'schema_version': True},
                         {**SETTINGS, 'address': 10}, {**SETTINGS, 'alpine_branch': 'edge'},
                         {**SETTINGS, 'docker_network': '10.78.0.0/24'},
                         {**SETTINGS, 'docker_network': '8.8.8.0/24'},
                         {**SETTINGS, 'managed_networks': [None]},
                         {**SETTINGS, 'managed_networks': []}):
            with self.subTest(settings=settings), self.assertRaises(SystemExit) as caught:
                self.validate(settings)
            self.assertNotIn('secret-canary', str(caught.exception))
            self.assertFalse(self.state.exists())
        with self.assertRaises(SystemExit):
            self.validate(text='{"schema_version":1,"schema_version":1}')

    def test_branch_mismatch_foreign_repository_and_wrong_live_address_fail(self):
        (self.root / 'etc/alpine-release').write_text('3.25.0\n')
        with self.assertRaises(SystemExit): self.validate()
        (self.root / 'etc/alpine-release').write_text('3.24.2\n')
        for repo in ('https://dl-cdn.alpinelinux.org/alpine/edge/community', 'https://foreign.test/alpine/v3.24/main'):
            (self.root / 'etc/apk/repositories').write_text(repo + '\n')
            with self.assertRaises(SystemExit): self.validate()
        (self.root / 'etc/apk/repositories').write_text('https://dl-cdn.alpinelinux.org/alpine/v3.24/main\n')
        with self.assertRaises(SystemExit): self.validate(address='10.99.0.6')
        self.assertFalse(self.state.exists())

    def test_changed_settings_or_foreign_engine_config_are_never_overwritten(self):
        self.validate()
        expected = (self.state / 'daemon.json.expected').read_bytes()
        with self.assertRaises(SystemExit): self.validate({**SETTINGS, 'docker_network': '172.31.249.0/24'})
        self.assertEqual((self.state / 'daemon.json.expected').read_bytes(), expected)
        (self.root / 'etc/docker').mkdir(mode=0o700)
        daemon = self.root / 'etc/docker/daemon.json'
        daemon.write_text('{"hosts":["tcp://0.0.0.0:2375"]}\n')
        daemon.chmod(0o600)
        with self.assertRaises(SystemExit): self.validate()
        self.assertIn('2375', daemon.read_text())

    def test_foreign_socket_without_prior_owned_intent_is_refused(self):
        (self.root / 'var/run/docker.sock').touch()
        with self.assertRaises(SystemExit): self.validate()
        self.assertFalse((self.state / 'daemon.json.expected').exists())


class GuestDockerShellContractTests(unittest.TestCase):
    def test_syntax_platform_gate_and_no_application_secret_or_host_runtime(self):
        result = subprocess.run(['sh', '-n'], input=SOURCE, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run(['sh', '-c', 'id() { printf "1000\\n"; }\n' + SOURCE], text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('requires the selected root Alpine', result.stderr)
        commands = '\n'.join(line for line in SOURCE.splitlines() if not line.lstrip().startswith('#'))
        for forbidden in ('--allow-untrusted', 'apk upgrade', 'docker run', '--privileged', '--network=host', 'compose'):
            self.assertNotIn(forbidden, commands)
        for expected in ('apk add --no-cache docker', 'dockerd --validate --config-file',
                         'rc-update add cgroups boot', 'rc-update add docker default', 'rc-service docker status',
                         'unset DOCKER_HOST DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH'):
            self.assertIn(expected, SOURCE)
