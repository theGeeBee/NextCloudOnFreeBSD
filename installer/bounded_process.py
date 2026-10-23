"""Bounded private command transport for fixed maintenance adapters.

No shell, environment inheritance, credential logging or import-time execution.
The caller owns command authorization and verified JID checks before/after use.
This transport owns only its newly created process group, never an SSH session.
"""

import os
import selectors
import signal
import subprocess
import time


MAX_INPUT = 1024 * 1024
MAX_OUTPUT = 16 * 1024 * 1024
ENV = {"PATH": "/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin", "LC_ALL": "C"}


def run(argv, *, stdin=b"", env, timeout, output_limit, capture_stderr=False):
    """Return bounded private output; never emit diagnostics or exception details.

    stdout is bounded in memory; stderr is drained with the same byte ceiling and
    discarded by default. Opt-in capture bounds stdout and stderr together.
    A limit breach fails the command, rather than truncating output and
    potentially treating incomplete evidence as success. Timeouts/cancellation kill
    and reap the owned group, including stopped children and inherited pipes.
    """
    from .nextcloud_update import NativeResult
    if (type(argv) not in (list, tuple) or not argv or len(argv) > 256
            or any(type(arg) is not str or not arg or "\0" in arg or len(arg) > 65536 for arg in argv)
            or not argv[0].startswith("/") or env != ENV
            or type(stdin) is not bytes or len(stdin) > MAX_INPUT
            or type(capture_stderr) is not bool
            or type(timeout) not in (float, int) or not 0 < timeout <= 3600
            or type(output_limit) is not int or not 1 <= output_limit <= MAX_OUTPUT):
        raise ValueError("Invalid bounded maintenance transport request")
    process = None
    try:
        started = time.monotonic()
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=dict(ENV), close_fds=True,
                                   start_new_session=True, umask=0o077)
        output = bytearray()
        stderr = bytearray()
        diagnostics = 0
        sent = 0
        with selectors.DefaultSelector() as selector:
            for stream, event, role in ((process.stdin, selectors.EVENT_WRITE, "input"),
                                        (process.stdout, selectors.EVENT_READ, "output"),
                                        (process.stderr, selectors.EVENT_READ, "diagnostics")):
                os.set_blocking(stream.fileno(), False)
                if role == "input" and not stdin:
                    stream.close()
                else:
                    selector.register(stream, event, role)
            while selector.get_map():
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0:
                    raise TimeoutError
                for key, _ in selector.select(remaining):
                    if key.data == "input":
                        sent += os.write(key.fd, stdin[sent:sent + 65536])
                        if sent == len(stdin):
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                    else:
                        data = os.read(key.fd, 65536)
                        if not data:
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                        elif key.data == "output":
                            if len(output) + len(data) > output_limit:
                                raise ValueError
                            output.extend(data)
                        else:
                            diagnostics += len(data)
                            if diagnostics > output_limit:
                                raise ValueError
                            if capture_stderr:
                                stderr.extend(data)
                        if capture_stderr and len(output) + len(stderr) > output_limit:
                            raise ValueError
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                raise TimeoutError
            code = process.wait(timeout=remaining)
        return NativeResult(code, bytes(output), bytes(stderr))
    except BaseException as error:
        if process is not None and process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        raise RuntimeError("Bounded private maintenance command failed; no diagnostics emitted") from None
    finally:
        if process is not None:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
