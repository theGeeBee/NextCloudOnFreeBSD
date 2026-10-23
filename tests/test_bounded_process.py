"""Real local child processes only, never native provisioning commands."""

import os
import subprocess
import sys
import unittest
from unittest.mock import patch

from installer import bounded_process as transport


class BoundedProcessTests(unittest.TestCase):
    def run_python(self, code, *, stdin=b"", limit=1024, timeout=5, capture_stderr=False):
        return transport.run((sys.executable, "-c", code), stdin=stdin,
                             env=dict(transport.ENV), timeout=timeout, output_limit=limit,
                             capture_stderr=capture_stderr)

    def test_bytes_stdin_stdout_and_exit_are_preserved(self):
        value = self.run_python("import sys; sys.stdout.buffer.write(sys.stdin.buffer.read()); sys.exit(3)", stdin=b"abc\0\xff")
        self.assertEqual((value.returncode, value.stdout), (3, b"abc\0\xff"))

    def test_environment_not_inherited_and_private_stderr_not_returned(self):
        with patch.dict(os.environ, {"SECRET": "must-not-inherit"}):
            value = self.run_python("import os,sys; assert 'SECRET' not in os.environ; sys.stderr.write('private'); print('public')")
        self.assertEqual(value.stdout, b"public\n")
        self.assertEqual(value.stderr, b"")

    def test_opt_in_stderr_preserves_bytes_and_nonzero_status(self):
        value = self.run_python("import os; os.write(1,b'out'); os.write(2,b'err\\xff'); exit(7)",
                                capture_stderr=True)
        self.assertEqual((value.returncode, value.stdout, value.stderr), (7, b"out", b"err\xff"))

    def test_opt_in_combined_limit_fails_without_output(self):
        with self.assertRaisesRegex(RuntimeError, "no diagnostics emitted"):
            self.run_python("import os; os.write(1,b'a'*60); os.write(2,b'b'*60)",
                            limit=100, capture_stderr=True)

    def test_limits_fail_not_truncate(self):
        for stream in ("stdout", "stderr"):
            with self.subTest(stream=stream), self.assertRaisesRegex(RuntimeError, "no diagnostics emitted") as failure:
                self.run_python(f"import sys; sys.{stream}.write('SECRET' * 10000)", limit=100)
            self.assertNotIn("SECRET", str(failure.exception))

    def test_large_duplex_transport_does_not_deadlock(self):
        data = b"a" * (512 * 1024)
        value = self.run_python("import os; os.write(1,b'b'*65536); "
                                "data=b''\nwhile True:\n chunk=os.read(0,65536)\n if not chunk: break\n data+=chunk\n"
                                "os.write(1,data)", stdin=data, limit=1024 * 1024)
        self.assertEqual(value.stdout, b"b" * 65536 + data)

    def test_timeout_kills_owned_stopped_group_and_reaps_direct_child(self):
        processes = []
        original = subprocess.Popen
        def capture(*args, **kwargs):
            process = original(*args, **kwargs)
            processes.append(process)
            return process
        with patch.object(transport.subprocess, "Popen", side_effect=capture):
            with self.assertRaises(RuntimeError):
                self.run_python("import os,signal; os.kill(os.getpid(), signal.SIGSTOP)", timeout=0.15)
        self.assertIsNotNone(processes[0].returncode)
        with self.assertRaises(ChildProcessError):
            os.waitpid(processes[0].pid, os.WNOHANG)

    def test_descendant_inheriting_pipes_does_not_extend_deadline(self):
        with self.assertRaises(RuntimeError):
            self.run_python("import os,time; pid=os.fork(); "
                            "time.sleep(30) if pid == 0 else os._exit(0)", timeout=0.15)

    def test_invalid_request_refused_before_process(self):
        with patch.object(transport.subprocess, "Popen") as spawn:
            for changes in ({"env": {"SECRET": "bad"}}, {"stdin": "text"},
                            {"output_limit": True}, {"timeout": 0}, {"argv": ["relative"]},
                            {"capture_stderr": 1}):
                request = dict(argv=[sys.executable, "-V"], env=dict(transport.ENV),
                               stdin=b"", output_limit=1024, timeout=5)
                request.update(changes)
                with self.assertRaises(ValueError):
                    transport.run(**request)
            spawn.assert_not_called()


if __name__ == "__main__":
    unittest.main()
