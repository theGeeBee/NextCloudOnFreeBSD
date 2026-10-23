"""Real local PHP/Unix-socket protocol tests; no jail/native provisioning."""

import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from installer import runtime_inventory as runtime


PHP = shutil.which("php")
SOURCE = runtime.RESOURCES / "jails/runtime-inventory.php"


def observation(sapi="cli"):
    return dict(version="8.5.11", sapi=sapi, integer_size=8,
                loaded_modules=["core", "json", "openssl", "standard", "zend opcache"])


class RuntimeInventoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="runtime-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.helper = self.root / runtime.HELPER.removeprefix("/")
        self.helper.parent.mkdir(parents=True)
        self.helper.write_bytes(SOURCE.read_bytes())
        self.helper.chmod(0o640)
        self.enterContext(patch.object(runtime, "ROOT_UID", os.geteuid()))
        self.context = Mock()
        self.context.config.nextcloud_jail = "cloudnc"
        self.context.jail_root.return_value = self.root
        self.context.jail.side_effect = [Mock(returncode=0, stderr="", stdout=json.dumps(observation(sapi)))
                                         for sapi in ("cli", "fpm-fcgi", "fpm-fcgi")]

    def test_observes_both_actual_pools_and_cli_via_pinned_command_boundary(self):
        result = runtime.collect_php(self.context)
        self.assertEqual(set(result), {"cli", "main_fpm", "callback_fpm"})
        self.assertEqual([call.args[-1] for call in self.context.jail.call_args_list], ["cli", "main", "callback"])
        for call in self.context.jail.call_args_list:
            self.assertEqual(call.args[:4], ("cloudnc", "/usr/bin/env", "-i", "PATH=/usr/local/bin:/usr/bin:/bin"))
            self.assertTrue(call.kwargs["hide_output"])

    def test_missing_or_modified_helper_is_not_retrofitted(self):
        for content in (b"changed", b""):
            self.helper.write_bytes(content)
            with self.assertRaisesRegex(ValueError, "unavailable or unsafe"):
                runtime.collect_php(self.context)
            self.assertEqual(self.helper.read_bytes(), content)
        self.context.jail.assert_not_called()

    def test_writable_helper_and_hardlinks_are_rejected(self):
        self.helper.chmod(0o660)
        with self.assertRaises(ValueError):
            runtime.collect_php(self.context)
        self.helper.chmod(0o640)
        os.link(self.helper, self.root / "hardlink")
        with self.assertRaises(ValueError):
            runtime.collect_php(self.context)
        self.context.jail.assert_not_called()

    def test_changed_helper_during_probe_is_rejected(self):
        def change(*args, **kwargs):
            self.helper.write_bytes(b"changed")
            return Mock(returncode=0, stderr="", stdout=json.dumps(observation()))
        self.context.jail.side_effect = change
        with self.assertRaises(ValueError):
            runtime.collect_php(self.context)
        self.assertEqual(self.context.jail.call_count, 1)

    def test_failed_empty_oversized_and_private_diagnostics_are_not_inventory(self):
        for result in (Mock(returncode=1, stderr="SECRET", stdout=""),
                       Mock(returncode=0, stderr="", stdout=""),
                       Mock(returncode=0, stderr="", stdout="SECRET" * runtime.MAX_BYTES),
                       Mock(returncode=0, stderr="SECRET", stdout=json.dumps(observation()))):
            self.context.jail.side_effect = None
            self.context.jail.return_value = result
            with self.assertRaises(ValueError) as error:
                runtime.collect_php(self.context)
            self.assertNotIn("SECRET", str(error.exception))

    def test_strict_runtime_schema(self):
        for changes in ({"sapi": "cli"}, {"integer_size": True}, {"loaded_modules": []},
                        {"loaded_modules": ["json", "json"]}, {"loaded_modules": ["secret\n"]},
                        {"version": "8.6.0RC1"}, {"environment": {"password": "SECRET"}}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                runtime.validate({**observation("fpm-fcgi"), **changes}, "main_fpm")

    def test_native_cgi_module_marker_is_allowed_only_for_fpm(self):
        value = observation('fpm-fcgi')
        value['loaded_modules'] = sorted(value['loaded_modules'] + ['cgi-fcgi'])
        for kind in ('main_fpm', 'callback_fpm'):
            self.assertEqual(runtime.validate(value, kind), value)
        with self.assertRaises(ValueError):
            runtime.validate({**value, 'sapi':'cli'}, 'cli')
        with self.assertRaises(ValueError):
            runtime.validate({**value, 'loaded_modules': sorted(value['loaded_modules'] + ['unknown-module'])}, 'main_fpm')


@unittest.skipUnless(PHP, "PHP CLI unavailable; native FPM acceptance is separate")
class RuntimeHelperProtocolTests(unittest.TestCase):
    def test_real_cli_output_contains_only_runtime_metadata(self):
        result = subprocess.run([PHP, str(SOURCE), "cli"], text=True, capture_output=True, check=True)
        self.assertEqual(result.stderr, "")
        value = runtime.validate(json.loads(result.stdout), "cli")
        self.assertIn("json", value["loaded_modules"])
        for argument in ("environment", "../main", "phpinfo"):
            result = subprocess.run([PHP, str(SOURCE), argument], text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")

    def exchange(self, reply):
        with tempfile.TemporaryDirectory(prefix="fcgi-") as directory:
            root = Path(directory)
            path = root / "pool.sock"
            helper = root / "probe.php"
            helper.write_text(SOURCE.read_text().replace("/var/run/php-fpm/nextcloud.sock", str(path)))
            errors = []
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(str(path))
                server.listen(1)
                server.settimeout(5)
                def receive(connection, size):
                    data = b""
                    while len(data) < size:
                        part = connection.recv(size - len(data))
                        if not part:
                            raise ValueError("incomplete fixture request")
                        data += part
                    return data
                def worker():
                    try:
                        connection, _ = server.accept()
                        with connection:
                            connection.settimeout(5)
                            encoded = b""
                            for _ in range(8):
                                version, kind, request, size, padding, reserved = struct.unpack(">BBHHBB", receive(connection, 8))
                                body = receive(connection, size)
                                receive(connection, padding)
                                if kind == 4:
                                    encoded += body
                                if kind == 5:
                                    break
                            params = {}
                            while encoded:
                                a, b = encoded[0], encoded[1]
                                params[encoded[2:2+a].decode()] = encoded[2+a:2+a+b].decode()
                                encoded = encoded[2+a+b:]
                            connection.sendall(reply(params))
                    except Exception as error:
                        errors.append(error)
                thread = threading.Thread(target=worker)
                thread.start()
                result = subprocess.run([PHP, str(helper), "main"], capture_output=True, text=True, timeout=10)
                thread.join(6)
                self.assertFalse(thread.is_alive())
                self.assertFalse(errors, errors)
                return result

    @staticmethod
    def frame(kind, body, request=1):
        return struct.pack(">BBHHBB", 1, kind, request, len(body), 0, 0) + body

    def reply(self, params, *, nonce=None, end=b"\0" * 8, headers=b"Content-Type: application/json\r\n\r\n"):
        body = json.dumps({"nonce": params["CLOUD_INSTALLER_INVENTORY_NONCE"] if nonce is None else nonce,
                           "runtime": observation("fpm-fcgi")}).encode()
        return self.frame(6, headers + body) + self.frame(6, b"") + self.frame(3, end)

    def test_real_fastcgi_protocol_reads_bound_response(self):
        result = self.exchange(self.reply)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(runtime.validate(json.loads(result.stdout), "main_fpm"), observation("fpm-fcgi"))

    def test_reserved_end_request_bytes_are_not_application_status(self):
        result = self.exchange(lambda p: self.reply(p, end=b"\0" * 5 + b"xyz"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(runtime.validate(json.loads(result.stdout), "main_fpm"), observation("fpm-fcgi"))

    def test_wrong_nonce_error_status_and_incomplete_request_fail_closed(self):
        for reply in (lambda p: self.reply(p, nonce="0" * 32),
                      lambda p: self.reply(p, end=struct.pack(">IB3s", 1, 0, b"\0" * 3)),
                      lambda p: self.reply(p, end=struct.pack(">IB3s", 0, 1, b"\0" * 3)),
                      lambda p: self.reply(p, end=b"\0" * 7),
                      lambda p: self.reply(p, headers=b"Status: 503 Service Unavailable\r\nContent-Type: application/json\r\n\r\n"),
                      lambda p: self.frame(7, b"SECRET diagnostic"),
                      lambda p: self.frame(6, b"SECRET incomplete", request=2)):
            result = self.exchange(reply)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("SECRET", result.stdout + result.stderr)
            self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
