"""Legacy cosmetic contracts plus the intentional version-family wizard extension."""

from contextlib import redirect_stdout
import hashlib
import errno
import fcntl
import io
import json
import os
from pathlib import Path
import pty
import re
import select
import signal
import struct
import sys
import termios
import time
import unittest
from unittest.mock import Mock, patch

from installer.main import entrypoint, menu
from installer.config import STATE_DIR
from installer.ui import TerminalUI, _cells, _menu_view, _text_view
from installer.wizard import configure
from test_ui import ScriptedUI, host_facts


class EquivalenceTests(unittest.TestCase):
    def test_family_questions_are_explicit_and_legacy_wizard_remainder_matches_baseline(self):
        # These hashes freeze presentation-independent question/data contracts,
        # captured at aae91d8, before presentation changes. Family selection is an
        # intentional behavioral extension: assert it separately and exclude ONLY
        # its new field/questions/defaults from the unchanged legacy comparison.
        # Messages were never part of this captured dialogue hash.
        baselines = {
            'onlyoffice': ('9ef5f2e79a230b387070dcfbf467ecf0d39b24b1ad68a6198beb62f321f74bbd', '03dc99ca7f27e5e9f6bd8d30e9654eefb6ac96b68d76442feedb9d498709a431'),
            'eurooffice': ('4c52d0ef0cebf91ac9436bdfdcbdededa89e53ab469c368da218d86a5dd3d627', '931476f27d02bf9a4c313e2b60da66cb5dc1b82a444f7af96b4d8a7a5d21297e'),
            'collabora': ('316076cb1a28768ce3108b16f78e73c6ab51d4d4bfb65e6bf14fc64046466d6f', '931476f27d02bf9a4c313e2b60da66cb5dc1b82a444f7af96b4d8a7a5d21297e'),
            'none': ('cef8748d8fdc256e158a05442fd3a0e0f923bfc570ca8b9c0b0b02e2c61745a0', '890578ad657acbe969a22de0240960b46f05e5e4bc6bcf822f0accc177b53ae2'),
        }
        for backend, (config_hash, questions_hash) in baselines.items():
            with self.subTest(backend=backend):
                ui = ScriptedUI(menus={'HTTPS termination': 'external', 'Office backend (fresh installation)': backend})
                calls, original = [], ui.menu
                def recording(title, choices, default=None):
                    calls.append([title, choices, default])
                    return original(title, choices, default)
                ui.menu = recording
                with patch('sys.stdin.isatty', return_value=True), patch('sys.stdout.isatty', return_value=True):
                    config = configure(host_facts(32768), ui=ui)
                family_questions = ['Nextcloud version family', 'PHP version family', 'Database version family']
                expected_families = {'nextcloud': '35', 'php': '8.5', 'database': '12.3'}
                if backend == 'onlyoffice':
                    family_questions.append('ONLYOFFICE version family')
                    expected_families['onlyoffice'] = '9.4'
                if backend != 'none':
                    family_questions.append('Office connector version family')
                    expected_families['connector'] = {'onlyoffice': '10.2', 'eurooffice': '11.0', 'collabora': '12.0'}[backend]
                self.assertEqual([label for label in ui.questions if label.endswith(' version family')], family_questions)
                start = ui.questions.index('FreeBSD-ports branch') + 1
                self.assertEqual(ui.questions[start:start + len(family_questions)], family_questions)
                self.assertEqual([ui.defaults[label] for label in family_questions], list(expected_families.values()))
                self.assertEqual(config.version_families, expected_families)
                family_messages = [message for message in ui.messages if message.startswith('Version families select ')]
                self.assertEqual(len(family_messages), 1)
                self.assertIn('Minimums and exact pins still apply.', family_messages[0])

                serialized = json.loads(config.to_json())
                self.assertEqual(serialized.pop('version_families'), expected_families)
                legacy_config = (json.dumps(serialized, indent=2) + '\n').encode()
                legacy_questions = [label for label in ui.questions if label not in family_questions]
                legacy_defaults = {label: value for label, value in ui.defaults.items() if label not in family_questions}
                transcript = json.dumps({'menus': calls, 'questions': legacy_questions, 'defaults': legacy_defaults,
                                         'confirmations': ui.confirmations}, sort_keys=True).encode()
                self.assertEqual(hashlib.sha256(legacy_config).hexdigest(), config_hash)
                self.assertEqual(hashlib.sha256(transcript).hexdigest(), questions_hash)

    def test_exact_state_filtered_main_menu_order(self):
        registry = Mock()
        registry.lifecycle_enabled.return_value = False
        for state, expected in [(None, ['install', 'configure', 'list']),
                                ('ready', ['check-updates', 'check-security', 'install', 'configure', 'list', 'maintenance-register', 'status', 'upgrade', 'verify', 'backup', 'restore', 'add-user', 'remove']),
                                ('failed', ['check-updates', 'check-security', 'install', 'configure', 'list', 'resume', 'status', 'remove', 'recover-install'])]:
            rows = [] if state is None else [dict(instance='cloud', state=state, error=None, pending=[], public_url='https://example.test')]
            ui = Mock()
            ui.menu.return_value = 'list'
            self.assertEqual(menu(ui, registry, view=dict(instances=rows, errors=[], pending_network=[])).command, 'list')
            self.assertEqual([key for key, _ in ui.menu.call_args.args[1]], expected)


class RefinedMenuTests(unittest.TestCase):
    def test_layout_widths_ascii_frames_and_unclipped_values(self):
        label = 'Long existing explanation ' + '界e\u0301' * 60
        for columns in (50, 80, 120, 160):
            text = _menu_view('Existing title', [('one', label), ('two', 'Second')], 'one', columns, False)
            self.assertTrue(all(_cells(line) <= columns for line in text.splitlines()))
            self.assertEqual(text.count('界'), 60)
            self.assertEqual('+' in text, columns >= 60)
            self.assertIn('0. Cancel', text)
            self.assertNotIn('\x1b', text)

    def test_interactive_selection_keys_defaults_invalid_and_cancel_unchanged(self):
        for answers, expected in [(['bad', '2'], 'two'), (['one'], 'one'), ([''], 'two')]:
            with redirect_stdout(io.StringIO()) as output, patch.dict(os.environ, {'TERM': 'xterm', 'NO_COLOR': '1'}), \
                    patch('sys.stdin.isatty', return_value=True), patch('sys.stdout.isatty', return_value=True), \
                    patch('builtins.input', side_effect=answers):
                self.assertEqual(TerminalUI(plain=True).menu('Actions', [('one', 'First'), ('two', 'Second')], 'two'), expected)
                self.assertNotIn('\x1b', output.getvalue())
                self.assertIn('+', output.getvalue())
        for answer in ('0', '\x1b'):
            with patch('builtins.input', return_value=answer), redirect_stdout(io.StringIO()):
                with self.assertRaises(KeyboardInterrupt):
                    TerminalUI(plain=True).menu('Actions', [('one', 'First')])

    def test_non_tty_output_is_byte_identical(self):
        with patch('sys.stdin.isatty', return_value=False), patch('builtins.input', return_value=''), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(TerminalUI(plain=True).menu('Actions', [('one', 'First'), ('two', 'Second')], 'one'), 'one')
        self.assertEqual(output.getvalue(), '\nActions\n  1. First (default)\n  2. Second\n  0. Cancel\n')

    def test_native_dialog_uses_same_ids_order_and_derived_descriptions(self):
        ui = TerminalUI(plain=True)
        ui.dialog = '/usr/bin/bsddialog'
        with patch.object(ui, '_dialog', return_value='two') as dialog:
            self.assertEqual(ui.menu('Actions', [('one', 'First'), ('two', 'Second')], 'one'), 'two')
        args = dialog.call_args.args[1]
        self.assertEqual(args[-6:], ['one', 'First', 'First', 'two', 'Second', 'Second'])
        self.assertEqual(args[:2], ['--default-item', 'one'])

    def test_controls_are_escaped_only_in_display(self):
        text = _menu_view('Title\x1b[2J', [('one', 'Label\x1b[31m')], None, 80, False)
        self.assertNotIn('\x1b', text)
        self.assertIn('\\x1b', text)

    def test_native_no_color_and_foreground_descriptors(self):
        ui = TerminalUI(plain=True)
        ui.dialog = '/usr/bin/bsddialog'
        result = Mock(returncode=0, stderr='one\n')
        with patch.dict(os.environ, {'NO_COLOR': '1'}), patch('installer.ui.subprocess.run', return_value=result) as run:
            self.assertEqual(ui.menu('Actions', [('one', 'First')]), 'one')
        argv = run.call_args.args[0]
        self.assertIn('--ascii-lines', argv)
        self.assertEqual(argv[argv.index('--theme') + 1], 'blackwhite')
        self.assertNotIn('stdout', run.call_args.kwargs)
        self.assertNotIn('stdin', run.call_args.kwargs)


class RefinedTextTests(unittest.TestCase):
    def test_existing_plan_text_long_values_and_cell_widths(self):
        text = '\nHost: existing selected host\nVersions requested: selected policy values\nURL: https://' + 'long' * 40 + '.example.test\nPrivate state: /var/db/existing/path'
        for columns in (50, 80, 120, 160):
            rendered = _text_view(text, columns, False)
            self.assertTrue(all(_cells(line) <= columns for line in rendered.splitlines()))
            self.assertEqual(''.join(rendered.split()), ''.join(text.split()))
            self.assertNotIn('\x1b', rendered)

    def test_headless_and_dumb_messages_are_exactly_unchanged(self):
        text = '\nOriginal heading\n  Original long value ' + 'x' * 200
        for term, tty in (('xterm', False), ('dumb', True), ('', True)):
            with redirect_stdout(io.StringIO()) as output, patch.dict(os.environ, {'TERM': term}), \
                    patch('sys.stdin.isatty', return_value=tty), patch('sys.stdout.isatty', return_value=tty):
                TerminalUI.message(text)
            self.assertEqual(output.getvalue(), text + '\n')

    def test_no_color_keeps_layout_and_resize_reflows_next_message(self):
        with redirect_stdout(io.StringIO()) as output, patch.dict(os.environ, {'TERM': 'xterm', 'NO_COLOR': '1'}), \
                patch('sys.stdin.isatty', return_value=True), patch('sys.stdout.isatty', return_value=True), \
                patch('installer.ui.shutil.get_terminal_size', side_effect=[os.terminal_size((50, 18)), os.terminal_size((120, 35))]):
            TerminalUI.message('Public information ' * 10)
            split = len(output.getvalue())
            TerminalUI.message('Public information ' * 10)
            narrow, wide = output.getvalue()[:split], output.getvalue()[split:]
        self.assertNotIn('\x1b', narrow + wide)
        self.assertTrue(all(_cells(line) <= 50 for line in narrow.splitlines()))
        self.assertTrue(wide.startswith(' ' * 12))

    def test_headings_controls_and_input_prompts_remain_separate(self):
        self.assertIn('\x1b[1;36m', _text_view('\nExisting heading', 80, True))
        self.assertNotIn('\x1b[2J', _text_view('Untrusted\x1b[2J', 80, False))
        ui = TerminalUI(plain=True)
        with patch('builtins.input', return_value='APPLY') as read:
            self.assertEqual(ui.input('Type APPLY to proceed'), 'APPLY')
        read.assert_called_once_with('Type APPLY to proceed: ')


class RefinedStatusTests(unittest.TestCase):
    def test_colors_never_add_or_infer_stage_states(self):
        for text, code in (('[2/7] Existing step', '1;36'), ('Error: actual failure', '31'),
                           ('NOTICE: existing warning', '33'), ('Installer checks passed. Existing scope.', '32')):
            rendered = _text_view(text, 80, True)
            self.assertIn(f'\x1b[{code}m', rendered)
            self.assertEqual(re.sub(r'\x1b\[[0-9;]*m', '', rendered).strip(), text)
        self.assertNotIn('[OK]', _text_view('[2/7] Running existing step', 80, False))
        self.assertNotIn('%', _text_view('[2/7] Running existing step', 80, False))

    def test_headless_errors_keep_stream_bytes_root_cause_path_and_exit_code(self):
        for error, code, expected in ((RuntimeError('fixture failure; log /retained/fixture.log'), 1,
                                      'Error: fixture failure; log /retained/fixture.log\n'),
                                     (KeyboardInterrupt(), 130, '\nStopped. Saved state is retained; no datasets are deleted.\n')):
            with patch('installer.main.main', side_effect=error), patch('sys.stdin.isatty', return_value=False), \
                    patch('sys.stdout', new_callable=io.StringIO) as stdout, patch('sys.stderr', new_callable=io.StringIO) as stderr:
                with self.assertRaises(SystemExit) as stopped:
                    entrypoint()
                self.assertEqual(stopped.exception.code, code)
                self.assertEqual(stdout.getvalue(), '')
                self.assertTrue(stderr.getvalue().startswith(expected))
                if code == 130:
                    self.assertEqual(stderr.getvalue(), expected)
                else:
                    self.assertEqual(stderr.getvalue(), expected + f'State is retained under {STATE_DIR}. Correct the reported cause, then use the matching Resume/removal/restore workflow.\n')
                self.assertNotIn('\x1b', stderr.getvalue())

    def test_redirected_stdout_disables_error_decoration_even_with_stderr_tty(self):
        with patch.dict(os.environ, {'TERM': 'xterm', 'NO_COLOR': ''}), \
                patch('sys.stdin.isatty', return_value=True), patch('sys.stdout.isatty', return_value=False), \
                patch('sys.stderr', new_callable=io.StringIO) as output:
            with patch.object(output, 'isatty', return_value=True):
                TerminalUI.message('Error: fixture log /retained/fixture.log', file=output)
        self.assertEqual(output.getvalue(), 'Error: fixture log /retained/fixture.log\n')

    def test_interactive_error_sanitizes_controls_but_keeps_log_reference(self):
        with patch.dict(os.environ, {'TERM': 'xterm', 'NO_COLOR': ''}), \
                patch('sys.stdin.isatty', return_value=True), patch('sys.stdout.isatty', return_value=True), \
                patch('sys.stderr', new_callable=io.StringIO) as output:
            with patch.object(output, 'isatty', return_value=True):
                TerminalUI.message('Error: fixture\x1b[2J; log /retained/fixture.log', file=output)
        self.assertNotIn('\x1b[2J', output.getvalue())
        self.assertIn('/retained/fixture.log', output.getvalue())
        self.assertIn('\x1b[31m', output.getvalue())


class PtyTests(unittest.TestCase):
    """Actual terminal input/echo/signals; synthetic public strings, no installer."""

    def terminal(self, action, answer, *, columns=80, rows=24, term='xterm', no_color=''):
        program = r'''
import sys
sys.path.insert(0, sys.argv[1])
from installer.ui import TerminalUI
ui = TerminalUI(plain=True)
try:
    action = sys.argv[2]
    if action == 'confirm':
        value = ui.confirm('Fixture confirmation')
    elif action == 'secret':
        ui.secret('Fixture password')
        value = 'hidden-input-returned'
    elif action == 'apply':
        value = ui.input('Type APPLY to proceed')
    elif action == 'error':
        from unittest.mock import patch
        from installer.main import entrypoint
        with patch('installer.main.main', side_effect=RuntimeError('fixture failure; log /retained/fixture.log')):
            entrypoint()
    else:
        value = ui.menu('Fixture actions', [('one', 'First existing choice'), ('two', 'Second existing choice')], 'one')
        if action == 'resize':
            ui.input('Fixture pause')
            ui.message('Fixture reflow information ' * 8)
    print('RESULT:' + str(value), flush=True)
except KeyboardInterrupt:
    print('CANCELLED', flush=True)
    sys.exit(130)
'''
        root = str(Path(__file__).resolve().parents[1])
        pid, master = pty.fork()
        if pid == 0:
            env = {**os.environ, 'TERM': term, 'NO_COLOR': no_color, 'PYTHONDONTWRITEBYTECODE': '1'}
            env.pop('COLUMNS', None)
            env.pop('LINES', None)
            os.execve(sys.executable, [sys.executable, '-I', '-B', '-c', program, root, action], env)
        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack('HHHH', rows, columns, 0, 0))
        before = termios.tcgetattr(master)
        output = b''
        prompt = {'confirm': b'[y/N]: ', 'secret': b'Fixture password: ', 'apply': b'Type APPLY to proceed: ',
                  'error': None}.get(action, b'Selection: ')
        sent, resized, status = False, False, None
        deadline = time.monotonic() + 10
        try:
            while time.monotonic() < deadline:
                if not sent and prompt is not None and prompt in output:
                    os.write(master, answer)
                    sent = True
                if action == 'resize' and not resized and b'Fixture pause: ' in output:
                    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack('HHHH', 18, 50, 0, 0))
                    os.write(master, b'\n')
                    resized = True
                if select.select([master], [], [], 0.05)[0]:
                    try:
                        data = os.read(master, 65536)
                    except OSError as error:
                        if error.errno != errno.EIO:
                            raise
                        data = b''
                    output += data
                done, current = os.waitpid(pid, os.WNOHANG)
                if done:
                    status = current
                    # Drain buffered output after the child exits.
                    while select.select([master], [], [], 0)[0]:
                        try:
                            data = os.read(master, 65536)
                        except OSError as error:
                            if error.errno != errno.EIO:
                                raise
                            break
                        if not data:
                            break
                        output += data
                    break
            self.assertIsNotNone(status, 'Synthetic PTY child timed out')
            after = termios.tcgetattr(master)
            self.assertEqual(after, before, 'Terminal input/echo attributes changed')
            return os.waitstatus_to_exitcode(status), output.decode('utf-8', 'replace').replace('\r\n', '\n')
        finally:
            if status is None:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            os.close(master)

    def test_sizes_real_number_key_default_routing_and_no_color(self):
        for columns, rows in ((50, 18), (80, 24), (120, 35), (160, 45)):
            for answer, result in ((b'bad\n2\n', 'two'), (b'one\n', 'one'), (b'\n', 'one')):
                with self.subTest(size=(columns, rows), answer=answer):
                    code, text = self.terminal('menu', answer, columns=columns, rows=rows, no_color='1')
                    self.assertEqual(code, 0)
                    self.assertIn('RESULT:' + result, text)
                    self.assertNotIn('\x1b', text)
                    self.assertTrue(all(_cells(line) <= columns for line in text.split('Selection:')[0].splitlines()))

    def test_actual_cancel_escape_eof_ctrl_c_secret_and_confirm(self):
        for answer in (b'0\n', b'\x1b\n', b'\x04', b'\x03'):
            with self.subTest(answer=answer):
                code, text = self.terminal('menu', answer)
                self.assertEqual(code, 130)
                self.assertIn('CANCELLED', text)
        code, text = self.terminal('secret', b'synthetic-pty-password\n')
        self.assertEqual(code, 0)
        self.assertNotIn('synthetic-pty-password', text)
        self.assertIn('hidden-input-returned', text)
        for answer, result in ((b'possibly\nno\n', 'False'), (b'YES\n', 'True'), (b'\n', 'False')):
            code, text = self.terminal('confirm', answer)
            self.assertEqual(code, 0)
            self.assertIn('RESULT:' + result, text)

    def test_dumb_apply_failure_and_resize_keep_contracts(self):
        code, text = self.terminal('menu', b'2\n', term='dumb')
        self.assertEqual(code, 0)
        self.assertNotIn('\x1b', text)
        self.assertNotIn('+---', text)
        code, text = self.terminal('apply', b'APPLY\n')
        self.assertEqual(code, 0)
        self.assertIn('Type APPLY to proceed: ', text)
        self.assertIn('RESULT:APPLY', text)
        code, text = self.terminal('error', b'')
        self.assertEqual(code, 1)
        self.assertIn('fixture failure; log /retained/fixture.log', text)
        self.assertIn(str(STATE_DIR), text)
        code, text = self.terminal('resize', b'2\n', columns=120, rows=35, no_color='1')
        self.assertEqual(code, 0)
        self.assertIn('RESULT:two', text)
        body = text.split('Fixture pause: ', 1)[1]
        self.assertTrue(all(_cells(line) <= 50 for line in body.splitlines()))
