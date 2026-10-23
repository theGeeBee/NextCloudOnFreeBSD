"""Local process transport tests; never invoke ZFS or provision resources."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from installer import recovery_export as export


class RecoveryStreamTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="recovery-stream-")
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "stream"
        self.transport = export.NativeStreams(timeout=3)

    def test_send_stream_is_written_without_capture_or_environment_inheritance(self):
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with patch.dict(os.environ, {"SECRET": "not-inherited"}):
                self.transport._pipe((sys.executable, "-c",
                    "import os; assert 'SECRET' not in os.environ; os.write(1, b'x'*131072)"), fd, 131072, sending=True)
        finally:
            os.close(fd)
        self.assertEqual(self.path.read_bytes(), b"x" * 131072)

    def test_receive_consumes_exact_stream_size(self):
        self.path.write_bytes(b"x" * 131072)
        with self.path.open("rb") as stream:
            self.transport._pipe((sys.executable, "-c",
                "import sys; assert sys.stdin.buffer.read() == b'x'*131072"), stream.fileno(), 131072, sending=False)
        with self.path.open("rb") as stream, self.assertRaises(export.recovery.RecoveryError):
            self.transport._pipe((sys.executable, "-c", "import sys; sys.stdin.buffer.read()"),
                                 stream.fileno(), 131073, sending=False)

    def test_oversized_or_failed_send_keeps_partial_without_reporting_success(self):
        with self.path.open("wb") as stream, self.assertRaises(export.recovery.RecoveryError):
            self.transport._pipe((sys.executable, "-c", "import os; os.write(1,b'x'*8192)"),
                                 stream.fileno(), 1024, sending=True)
        self.assertTrue(self.path.exists())
        with self.path.open("wb") as stream, self.assertRaises(export.recovery.RecoveryError) as failure:
            self.transport._pipe((sys.executable, "-c", "import sys; sys.stderr.write('SECRET'); sys.exit(1)"),
                                 stream.fileno(), 1024, sending=True)
        self.assertNotIn("SECRET", str(failure.exception))

    def test_stopped_stream_child_is_killed_and_reaped(self):
        processes = []
        original = subprocess.Popen
        def capture(*args, **kwargs):
            child = original(*args, **kwargs)
            processes.append(child)
            return child
        self.transport.timeout = 0.15
        with patch.object(export.subprocess, "Popen", side_effect=capture):
            with self.path.open("wb") as stream, self.assertRaises(export.recovery.RecoveryError):
                self.transport._pipe((sys.executable, "-c",
                    "import os,signal; os.kill(os.getpid(),signal.SIGSTOP)"), stream.fileno(), 1024, sending=True)
        self.assertIsNotNone(processes[0].returncode)
        with self.assertRaises(ChildProcessError):
            os.waitpid(processes[0].pid, os.WNOHANG)


if __name__ == "__main__":
    unittest.main()
