"""Bounded offline orchestration tests; no jail, pkg or app feature execution."""
import json
from pathlib import Path
import shlex
import socket
import subprocess
import sys
import tempfile
import unittest

from nextcloud_worker_fixtures import PHP, WORKER, FINISH, phase, runtime, run_php


@unittest.skipUnless(PHP, 'PHP >= 8.1 CLI unavailable')
class OptionalAppPHPTests(unittest.TestCase):
    php = staticmethod(run_php)

    def test_optional_selection_preserves_legacy_exact_keys_and_accepts_canonical_strings(self):
        for selection in [None, '', 'none', 'bookmarks', 'bookmarks,calendar', 'calendar', 'calendar,contacts,deck,files_antivirus,mail,notes,spreed,tasks']:
            c = runtime()
            if selection is not None:
                c['nextcloud_apps'] = selection
            result = self.php("echo json_encode(cloudApps($c['nextcloud_apps'] ?? ''));", {'runtime': c})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), [] if selection in [None, '', 'none'] else selection.split(','))
        self.assertNotIn('nextcloud_apps', runtime())

    def test_rejects_unknown_credentials_and_noncanonical_or_nonstring_apps(self):
        for selection in [None, [], {}, True, 5, 'tasks,calendar', 'calendar,calendar',
                          'calendar,', ' calendar', 'mail\n', 'none,mail', 'onlyoffice', 'mail,$(id)',
                          '--force', '../bookmarks', 'https://example.test/app', 'Bookmarks', 'a' * 65,
                          'eurooffice', 'richdocuments', 'richdocumentscode', 'richdocumentscode_arm64']:
            with self.subTest(selection=selection):
                result = self.php("echo 'accepted';", {'runtime': dict(runtime(), nextcloud_apps=selection)})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')
        for key in ['password', 'apps', 'jwt_secret', 'credentials']:
            self.assertNotEqual(self.php("echo 'accepted';", {'runtime': dict(runtime(), **{key: 'secret'})}).returncode, 0)

    def test_native_inventory_requires_matching_installed_version_not_merely_disabled_code(self):
        cases = [
            ({'enabled': {}, 'disabled': {}}, '', 'missing'),
            ({'enabled': {'notes': '1.2.3'}, 'disabled': {}}, '1.2.3\n', 'enabled'),
            ({'enabled': {}, 'disabled': {'notes': '1.2.3 (installed 1.2.3)'}}, '1.2.3\n', 'disabled'),
            ({'enabled': {}, 'disabled': {'notes': '1.2.3'}}, '', None),
            ({'enabled': {}, 'disabled': {'notes': '1.2.4 (installed 1.2.3)'}}, '1.2.3', None),
            ({'enabled': {'notes': True}, 'disabled': {}}, '', None),
            ({'enabled': {'notes': '1.2.4'}, 'disabled': {}}, '1.2.3', None),
            ({'enabled': {'notes': '1.2.3'}, 'disabled': {'notes': '1.2.3'}}, '1.2.3', None),
            ({'enabled': {}, 'disabled': {}}, '1.2.3', None),
            ({}, '', None),
        ]
        for inventory, installed, expected in cases:
            result = self.php("echo cloudOptionalAppState('notes',$p['list'],$p['installed']);",
                              {'runtime': runtime(), 'list': inventory, 'installed': installed})
            self.assertEqual(result.returncode == 0, expected is not None, result.stderr)
            self.assertEqual(result.stdout, expected or '')

    def test_additional_app_uses_existing_native_inventory_state(self):
        result = self.php("echo cloudOptionalAppState('bookmarks',$p['list'],'');",
                          {'runtime': runtime(), 'list': {'enabled': {}, 'disabled': {}}})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'missing')


class OptionalAppShellTests(unittest.TestCase):
    def test_scanner_selection_matches_an_exact_newline_separated_app_id(self):
        selection = FINISH[FINISH.index('    selected_apps=$(json apps)'):
                           FINISH.index('    # Selected connector installation starts', FINISH.index('    selected_apps=$(json apps)'))]
        self.assertNotIn('connector-install', selection)
        for apps, expected in [('files_antivirus_extra', 'no'), ('my_files_antivirus', 'no'),
                               ('bookmarks\nfiles_antivirus_extra\nnotes', 'no'),
                               ('files_antivirus', 'yes'), ('bookmarks\nfiles_antivirus\nnotes', 'yes'),
                               ('', 'no')]:
            with self.subTest(apps=apps), tempfile.TemporaryDirectory() as tmp:
                script = ('set -eu\nSTATE=' + shlex.quote(tmp) + '\nPAYLOAD=$STATE\ninvoked=no\n'
                          'json() { printf "%s\\n" "$APP_SELECTION"; }\n'
                          'mktemp() { printf unused; }\n'
                          'configure_antivirus() { invoked=yes; }\n'
                          'fail() { exit 1; }\n' + selection +
                          '\nprintf "%s" "$invoked"\n')
                result = subprocess.run(['sh', '-c', script], text=True, capture_output=True,
                                        env={'APP_SELECTION': apps, 'PATH': '/usr/bin:/bin'})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, expected)
                broken = script.replace('json() {', 'grep() { return 2; }\njson() {', 1)
                failed = subprocess.run(['sh', '-c', broken], text=True, capture_output=True,
                                        env={'APP_SELECTION': apps, 'PATH': '/usr/bin:/bin'})
                self.assertNotEqual(failed.returncode, 0)

    def test_additional_app_uses_existing_native_install_and_receipt_without_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            script = 'set -eu\nSTATE=' + shlex.quote(tmp) + '\nselected_apps=bookmarks\n'
            script += 'fail() { exit 1; }\nprivate_file() { [ -f "$1" ] && [ ! -L "$1" ]; }\n'
            script += 'optional_app_state() { if [ -f "$STATE/installed" ]; then echo enabled; else echo missing; fi; }\n'
            script += 'occ() { printf "%s\\n" "$*" > "$STATE/calls"; touch "$STATE/installed"; }\n'
            script += phase('app_progress').replace('/usr/local/bin/python3', shlex.quote(sys.executable)) + '\n'
            script += phase('install_optional_apps') + '\ninstall_optional_apps\n'
            result = subprocess.run(['sh', '-c', script], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((directory / 'calls').read_text().strip(), 'app:install bookmarks')
            self.assertEqual((directory / 'nextcloud-app-bookmarks').read_text().strip(), 'complete')
    def test_app_install_enable_skip_failures_and_uncertain_replay(self):
        for initial, failed, expected in [('missing', False, ['app:install']),
                                          ('disabled', False, ['app:enable']),
                                          ('enabled', False, []),
                                          ('missing', True, ['app:install']),
                                          ('disabled', True, ['app:enable'])]:
            with self.subTest(initial=initial, failed=failed), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                (directory / 'native').write_text(initial)
                script = 'set -eu\nSTATE=' + shlex.quote(tmp) + '\nselected_apps=notes\n'
                script += "fail() { printf '%s\\n' \"$*\" >&2; exit 1; }\n"
                script += 'private_file() { [ -f "$1" ] && [ ! -L "$1" ]; }\n'
                script += 'optional_app_state() { cat "$STATE/native"; }\n'
                script += '''occ() {
                    [ -z "$(cat)" ] || exit 99
                    printf '%s\\n' "$1" >> "$STATE/calls"
                    [ "$(cat "$STATE/nextcloud-app-notes")" = running ] || exit 98
                '''
                script += ('return 1\n' if failed else 'printf enabled > "$STATE/native"\n') + '}\n'
                script += phase('app_progress').replace('/usr/local/bin/python3', shlex.quote(sys.executable)) + '\n'
                script += phase('install_optional_apps') + '\ninstall_optional_apps\n'
                result = subprocess.run(['sh', '-c', script], input='untouched host secret', text=True, capture_output=True)
                self.assertEqual(result.returncode == 0, not failed, result.stderr)
                marker = directory / 'nextcloud-app-notes'
                self.assertEqual(marker.read_text().strip(), 'running' if failed else 'complete')
                calls = (directory / 'calls').read_text().splitlines() if (directory / 'calls').exists() else []
                self.assertEqual(calls, expected)
                # Even enabled native state cannot turn our failed migration into
                # a receipt. Conversely a complete selection skips app:install,
                # whose upstream already-installed result would be exit 1.
                (directory / 'native').write_text('enabled')
                retry = subprocess.run(['sh', '-c', script], text=True, capture_output=True)
                self.assertEqual(retry.returncode == 0, not failed)
                if failed:
                    self.assertIn('explicit recovery', retry.stderr)
                self.assertEqual((directory / 'calls').read_text().splitlines() if expected else [], expected)

    def test_status_commands_do_not_consume_host_stdin(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = 'set -eu\nstage=' + shlex.quote(tmp) + '\nSTATE=$stage\n'
            script += "fail() { exit 1; }\nocc() { [ -z \"$(cat)\" ] || exit 99; printf '{}'; }\n"
            script += "json() { [ \"$1\" = app-state ]; printf enabled; }\n"
            script += phase('optional_app_state') + '\noptional_app_state notes\n[ "$(cat)" = secret ]\n'
            result = subprocess.run(['sh', '-c', script], input='secret', text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_app_intent_is_fsynced_and_stale_temporary_intent_blocks_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            progress = Path(tmp) / 'nextcloud-app-notes'
            progress.with_suffix('.new').write_text('running\n')
            script = 'set -eu\n' + phase('app_progress').replace('/usr/local/bin/python3', shlex.quote(sys.executable))
            script += '\napp_progress ' + shlex.quote(str(progress)) + ' running\n'
            result = subprocess.run(['sh', '-c', script], text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(progress.exists())
            self.assertEqual(progress.with_suffix('.new').read_text(), 'running\n')
        intent = phase('app_progress')
        self.assertIn('os.fsync(stream.fileno())', intent)
        self.assertIn('os.fsync(directory)', intent)

    def test_scanner_signature_service_order_failure_and_private_socket_configuration(self):
        for fail_signatures in [False, True]:
            with self.subTest(fail_signatures=fail_signatures), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                sock = socket.socket(socket.AF_UNIX)
                sock.bind(str(directory / 'clamd.sock'))
                script = 'set -eu\nSTATE=' + shlex.quote(tmp) + '\nstage=$STATE\n'
                script += "fail() { exit 1; }\ninstall() { :; }\nid() { :; }\npw() { :; }\n"
                script += "sysrc() { printf '%s\\n' \"sysrc $*\" >> \"$STATE/calls\"; }\n"
                script += "stat() { printf clamav:clamav:660; }\n"
                script += '''service() {
                    printf '%s\\n' "service $*" >> "$STATE/calls"
                    case "$2" in
                        onestatus) [ -f "$STATE/$1" ] ;;
                        onestart) touch "$STATE/$1" ;;
                        onestop) exit 97 ;;
                    esac
                }
                freshclam_stub() {
                    [ -z "$(cat)" ] || exit 99
                    printf 'signatures\\n' >> "$STATE/calls"
                ''' + ('return 1\n' if fail_signatures else ':\n') + '}\n'
                configure = phase('configure_antivirus').replace('/usr/local/bin/freshclam', 'freshclam_stub')
                configure = configure.replace('/var/run/clamav/clamd.sock', tmp + '/clamd.sock')
                script += configure + '\nconfigure_antivirus\n[ "$(cat)" = host-secret ]\n'
                result = subprocess.run(['sh', '-c', script], input='host-secret', text=True, capture_output=True)
                sock.close()
                self.assertEqual(result.returncode == 0, not fail_signatures, result.stderr)
                calls = (directory / 'calls').read_text().splitlines()
                if fail_signatures:
                    self.assertFalse(any('onestart' in line for line in calls))
                else:
                    self.assertLess(calls.index('signatures'), calls.index('service clamav_clamd onestart'))
                    self.assertLess(calls.index('service clamav_clamd onestart'), calls.index('service clamav_freshclam onestart'))
                clamd = (directory / 'clamd.conf').read_text()
                self.assertIn('LocalSocketGroup clamav\nLocalSocketMode 660', clamd)
                self.assertIn('StreamMaxLength 100M', clamd)
                self.assertNotIn('TCPSocket', clamd)
                freshclam = (directory / 'freshclam.conf').read_text()
                self.assertIn('DatabaseMirror database.clamav.net', freshclam)
                self.assertIn('ScriptedUpdates yes', freshclam)

    def test_owned_finish_order_cleanup_and_log_only_policy(self):
        ordered = ['close_cron', 'json validate', 'configure_antivirus', 'connector-install',
                   'connector-import', 'install_optional_apps', 'antivirus_app_config', 'service php_fpm restart',
                   'sysrc clamav_clamd_enable=YES', 'touch "$STATE/nextcloud-finished"', 'antivirus_active=0']
        positions = [FINISH.rindex(value) if value == 'antivirus_active=0' else FINISH.index(value) for value in ordered]
        self.assertEqual(positions, sorted(positions))
        cleanup = phase('cleanup')
        self.assertIn('clamav_clamd_enable=NO clamav_freshclam_enable=NO', cleanup)
        self.assertLess(cleanup.index('service clamav_freshclam onestop'), cleanup.index('service clamav_clamd onestop'))
        settings = phase('antivirus_app_config')
        self.assertIn('av_infected_action --value=only_log', settings)
        self.assertIn('av_mode --value=socket', settings)
        self.assertIn('av_stream_max_length --value=104857600', settings)
        self.assertNotIn('delete', settings)
        self.assertNotRegex(phase('configure_antivirus'), r'(?m)^\s*pkg ')
        self.assertNotIn('--force', phase('install_optional_apps'))
        self.assertNotIn('--allow-unstable', WORKER)
