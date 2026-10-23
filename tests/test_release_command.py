"""Base-only transport orchestration in a sandbox; no network/pkg/provisioning.

FreeBSD stat-format fixtures and POSIX-sh executable doubles run on Linux. The
real extraction here is GNU tar, NOT evidence of native FreeBSD compatibility.
"""

from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import pty
import shlex
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from test_installer import ROOT, build_module


class CommandTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='release-command-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / 'var/db').mkdir(parents=True)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.events = self.root / 'events'
        self.builder = build_module()
        self.archive = self.root / 'fixture.tar.gz'
        with tarfile.open(self.archive, 'w:gz') as archive:
            files = {'install.sh': '#!/bin/sh\nprintf "dispatch:%s:%s\\n" "$#" "$1" >> "$EVENTS"\npwd -P >> "$EVENTS"\nulimit -f > "$BASE/installer-file-limit"\n',
                     'installer/main.py': '# inert fixture\n', 'resources/versions.json': '{}\n'}
            for name, text in files.items():
                member = tarfile.TarInfo('cloud-installer/' + name)
                data = text.encode()
                member.size, member.mode = len(data), 0o755 if name.endswith('.sh') else 0o644
                archive.addfile(member, io.BytesIO(data))
        self.digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        doubles = {
            'id': 'printf "%s\\n" "${TEST_UID:-0}"',
            'uname': 'printf "%s\\n" "${TEST_OS:-FreeBSD}"',
            'sysctl': 'printf "%s\\n" "${TEST_JAILED:-0}"',
            'stat': '''[ "$1" = -f ] && [ "$2" = %u:%Lp ] || exit 90
[ "${TEST_STAT_FAIL:-0}" = 0 ] || exit 94
if [ "$3" = "${TEST_UNSAFE_PATH:-}" ]; then printf '%s\\n' "$TEST_METADATA"; exit; fi
case "$3" in /|"$BASE/var"|"$BASE/var/db") printf '0:755\\n';; *) printf '0:700\\n';; esac''',
            'fetch': '''printf 'fetch\\n' >> "$EVENTS"
[ -z "${SSL_NO_VERIFY_PEER:-}${SSL_NO_VERIFY_HOSTNAME:-}${SSL_ALLOW_SSL3:-}" ] || exit 90
[ "$1" = -T ] && [ "$2" = 60 ] && [ "$3" = -o ] || exit 91
printf '%s' "$5" > "$BASE/fetched-url"
cp "$FIXTURE" "$4" || exit
if [ "${TEST_SIGNAL:-}" ]; then kill -"$TEST_SIGNAL" "$PPID"; exit 1; fi
[ "${TEST_FETCH_FAIL:-0}" = 0 ]''',
            'sha256': 'printf "sha256\\n" >> "$EVENTS"\n[ "$1" = -q ] || exit 90\n[ "${TEST_SHA_FAIL:-0}" = 0 ] || exit 93\nsha256sum "$2" | cut -d " " -f 1',
            'tar': '''printf 'tar\\n' >> "$EVENTS"
[ -z "${TAR_OPTIONS:-}${TAR_READER_OPTIONS:-}${TAR_WRITER_OPTIONS:-}" ] || exit 90
[ "${TEST_TAR_FAIL:-0}" = 0 ] || exit 92
exec /bin/tar "$@"''',
        }
        for name, body in doubles.items():
            file = self.bin / name
            file.write_text('#!/bin/sh\nset -eu\n' + body + '\n')
            file.chmod(0o700)

    def run_command(self, *, digest=None, url='https://artifacts.example.invalid/releases/reviewed/cloud-installer.tar.gz', env=None, terminal=True):
        # Change only fixed system paths/PATH to test-owned destinations/doubles.
        body = self.builder.RELEASE_COMMAND.replace('/var', str(self.root / 'var'))
        body = body.replace('PATH=/sbin:/bin:/usr/sbin:/usr/bin', 'PATH=' + shlex.quote(str(self.bin) + ':/usr/bin:/bin'))
        if env and env.get('TEST_LIMIT_FAIL'):
            body = 'ulimit() { return 1; }\n' + body
        with patch.object(self.builder, 'RELEASE_COMMAND', body):
            command = self.builder.install_command(url, digest or self.digest)
        environment = {**os.environ, 'BASE': str(self.root), 'EVENTS': str(self.events), 'FIXTURE': str(self.archive),
                       'SSL_NO_VERIFY_PEER': '1', 'SSL_NO_VERIFY_HOSTNAME': '1', 'SSL_ALLOW_SSL3': '1',
                       'TAR_OPTIONS': '--checkpoint-action=exec=false', 'TAR_READER_OPTIONS': 'unsafe',
                       'TAR_WRITER_OPTIONS': 'unsafe', **(env or {})}
        if terminal:
            master, slave = pty.openpty()
            try:
                result = subprocess.run(['/bin/sh', '-c', command], cwd=self.root, env=environment,
                                        stdin=slave, stdout=slave, stderr=subprocess.PIPE, text=True, timeout=10)
            finally:
                os.close(master)
                os.close(slave)
            return result
        return subprocess.run(['/bin/sh', '-c', command], cwd=self.root, env=environment,
                              capture_output=True, text=True, timeout=10)

    def test_success_retains_archive_payload_cwd_and_exact_install_dispatch(self):
        result = self.run_command()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.events.read_text().splitlines(), ['fetch', 'sha256', 'tar', 'dispatch:1:install', str(self.root)])
        cache = self.root / 'var/db/cloud-installer/downloads'
        stages = list(cache.iterdir())
        self.assertEqual(len(stages), 1)
        self.assertEqual((stages[0] / 'release.tar.gz').read_bytes(), self.archive.read_bytes())
        self.assertEqual(stages[0].stat().st_mode & 0o777, 0o700)
        self.assertEqual((stages[0] / 'cloud-installer/install.sh').stat().st_mode & 0o777, 0o700)
        self.assertIn(str(stages[0] / 'cloud-installer'), result.stderr)
        inherited = subprocess.check_output(['/bin/sh', '-c', 'ulimit -f'], text=True).strip()
        self.assertEqual((self.root / 'installer-file-limit').read_text().strip(), inherited)
        # A second invocation never overwrites/adopts the first payload.
        first = stages[0]
        self.assertEqual(self.run_command().returncode, 0)
        self.assertEqual(len(list(cache.iterdir())), 2)
        self.assertEqual((first / 'release.tar.gz').read_bytes(), self.archive.read_bytes())

    def test_wrong_digest_precedes_tar_and_dispatch(self):
        result = self.run_command(digest='0' * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('SHA256 mismatch', result.stderr)
        self.assertEqual(self.events.read_text().splitlines(), ['fetch', 'sha256'])

    def test_fetch_or_tar_failure_never_dispatches(self):
        for env, expected in (({'TEST_FETCH_FAIL': '1'}, ['fetch']), ({'TEST_TAR_FAIL': '1'}, ['fetch', 'sha256', 'tar'])):
            if self.events.exists():
                self.events.unlink()
            result = self.run_command(env=env)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(self.events.read_text().splitlines(), expected)

    def test_guards_refuse_before_download(self):
        for env in ({'TEST_UID': '1000'}, {'TEST_OS': 'Linux'}, {'TEST_JAILED': '1'}, {'TEST_STAT_FAIL': '1'},
                    {'TEST_UNSAFE_PATH': str(self.root / 'var/db'), 'TEST_METADATA': '0:777'},
                    {'TEST_UNSAFE_PATH': str(self.root / 'var/db'), 'TEST_METADATA': '1000:755'}):
            result = self.run_command(env=env)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(self.events.exists())
        self.assertNotEqual(self.run_command(terminal=False).returncode, 0)
        self.assertFalse(self.events.exists())

    def test_existing_unsafe_or_symlink_cache_is_not_repaired(self):
        state = self.root / 'var/db/cloud-installer'
        state.mkdir(mode=0o750)
        state.chmod(0o750)  # Fixture must not depend on another test's umask.
        result = self.run_command(env={'TEST_UNSAFE_PATH': str(state), 'TEST_METADATA': '0:750'})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(state.stat().st_mode & 0o777, 0o750)
        self.assertFalse(self.events.exists())
        (state / 'downloads').symlink_to(self.root / 'missing')
        result = self.run_command()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.events.exists())

    def test_lifecycle_dangling_fence_refuses_before_writes(self):
        state = self.root / 'var/db/cloud-installer'
        state.mkdir()
        (state / 'lifecycle').symlink_to(self.root / 'missing')
        result = self.run_command()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((state / 'downloads').exists())
        self.assertFalse(self.events.exists())
        (state / 'lifecycle').unlink()
        (state / 'maintenance').mkdir()
        (state / 'maintenance/pending.json').symlink_to(self.root / 'missing')
        self.assertNotEqual(self.run_command().returncode, 0)
        self.assertFalse((state / 'downloads').exists())
        self.assertFalse(self.events.exists())

    def test_interruption_never_extracts_or_dispatches(self):
        for name, code in (('TERM', 143), ('INT', 130), ('HUP', 129)):
            if self.events.exists():
                self.events.unlink()
            result = self.run_command(env={'TEST_SIGNAL': name})
            self.assertEqual(result.returncode, code, result.stderr)
            self.assertEqual(self.events.read_text().splitlines(), ['fetch'])

    def test_failed_file_limit_or_hash_cannot_continue(self):
        result = self.run_command(env={'TEST_LIMIT_FAIL': '1'})
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.events.exists())
        result = self.run_command(env={'TEST_SHA_FAIL': '1'})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.events.read_text().splitlines(), ['fetch', 'sha256'])

    def test_url_metacharacters_are_literal_not_shell_code(self):
        url = "https://example.invalid/releases/v1/quo'te;$(touch${IFS}UNEXPECTED)/cloud-installer.tar.gz"
        result = self.run_command(url=url)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'fetched-url').read_text(), url)
        self.assertFalse((self.root / 'UNEXPECTED').exists())


class PublisherTests(unittest.TestCase):
    def test_invalid_or_mutable_urls_and_digests_are_rejected(self):
        builder = build_module()
        for url in ('http://example.invalid/v1/file.tar.gz', 'https://user:pass@example.invalid/v1/file.tar.gz',
                    'https://example.invalid/v1/file.tar.gz?token=private', 'https://example.invalid/v1/file.tar.gz#frag',
                    'https://example.invalid/releases/latest/download/file.tar.gz', 'https://example.invalid/main/file.tar.gz',
                    'https://example.invalid/v1/cloud-installer-latest.tar.gz', 'https://example.invalid/%6catest/file.tar.gz',
                    'https://example.invalid/refs/heads/release/file.tar.gz', 'https://example.invalid/line\nfile.tar.gz',
                    'https://example.invalid/v1/file.zip', 'https://[invalid/v1/file.tar.gz'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                builder.install_command(url, 'a' * 64)
        for digest in ('', 'g' * 64, 'a' * 63, None):
            with self.assertRaises(ValueError):
                builder.install_command('https://example.invalid/v1/file.tar.gz', digest)

    def test_builder_prints_actual_digest_command_without_changing_default_output(self):
        builder = build_module()
        digest = 'a' * 64
        with patch.object(builder, 'build_release', return_value=digest), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(builder.main(['--output', 'fixture.tar.gz']), 0)
        self.assertEqual(output.getvalue(), digest + '  fixture.tar.gz\n')
        url = 'https://example.invalid/releases/v1/cloud-installer.tar.gz'
        with patch.object(builder, 'build_release', return_value=digest), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(builder.main(['--output', 'fixture.tar.gz', '--url', url]), 0)
        command = shlex.split(output.getvalue().split('\n\n')[-1])
        self.assertEqual(command[:2], ['/bin/sh', '-c'])
        self.assertEqual(command[-2:], [url, digest])
        self.assertNotIn('python3', command[2])
        self.assertNotIn('curl', command[2])
        for bad in ('https://example.invalid/latest/file.tar.gz', ''):
            with patch.object(builder, 'build_release') as build, redirect_stdout(io.StringIO()), patch('sys.stderr', new_callable=io.StringIO):
                with self.assertRaises(SystemExit):
                    builder.main(['--output', 'fixture.tar.gz', '--url', bad])
            build.assert_not_called()

    def test_public_documentation_is_positive_allowlist(self):
        builder = build_module()
        selected = {str(path.relative_to(ROOT)) for path in builder.payload_files(ROOT)}
        self.assertIn('docs/distribution.md', selected)
        self.assertIn('docs/fonts.md', selected)
        for name in ('INTERNAL_NOTES.md', 'PRIVATE_REVIEW.md',
                     'docs/internal-review.md', 'docs/private-implementation-plan.md'):
            self.assertNotIn(name, selected)

    def test_real_archive_command_uses_real_built_digest_and_required_runtime(self):
        builder = build_module()
        with tempfile.TemporaryDirectory(prefix='command-build-') as directory:
            archive = Path(directory) / 'release.tar.gz'
            digest = builder.build_release(ROOT, archive)
            command = shlex.split(builder.install_command('https://example.invalid/releases/reviewed/cloud-installer.tar.gz', digest))
            self.assertEqual(command[-1], hashlib.sha256(archive.read_bytes()).hexdigest())
            with tarfile.open(archive) as payload:
                names = set(payload.getnames())
            self.assertIn('cloud-installer/install.sh', names)
            self.assertIn('cloud-installer/resources/versions.json', names)
            self.assertIn('cloud-installer/installer/main.py', names)
            self.assertIn('cloud-installer/docs/distribution.md', names)
            self.assertNotIn('cloud-installer/docs/private-review.md', names)
            self.assertNotIn('cloud-installer/docs/internal-review.md', names)
