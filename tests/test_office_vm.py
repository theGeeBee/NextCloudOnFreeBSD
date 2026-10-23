"""Offline candidate contracts only: no image acquisition or native operations."""

import ast
import base64
import copy
import inspect
import json
import math
import struct
import unittest

from installer import office_vm as vm


IMAGE = {
    "url": "https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/cloud/alpine-3.24.2-x86_64-cloudinit-r2.qcow2",
    "sha512": "6b9928cea1c6243affb8a9b09eba6046cd090e8bdb7141fbf0c8f2649c4a99d62e12cda289da41f99de82ce2b3e3780772dd594eaee3693cb49691d81cbe5d4b",
    "architecture": "x86_64", "firmware": "limine", "bootstrap": "cloudinit", "alpine_branch": "3.24",
}
MAC = "02:00:00:00:00:06"
NETWORK = {"address": "10.77.0.6/30", "gateway": "10.77.0.5", "dns": ["9.9.9.9"], "mac": MAC}


def ssh_string(value):
    return struct.pack(">I", len(value)) + value


# Public, non-secret RFC8032 test vector in OpenSSH framing. No key generation.
PRIVATE = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gt
ZWQyNTUxOQAAACDXWpgBgrEKt9VL/tPJZAc6DuFy89qmIyWvAhpo9wdRGgAAAJAAAA
AqAAAAKgAAAAtzc2gtZWQyNTUxOQAAACDXWpgBgrEKt9VL/tPJZAc6DuFy89qmIyWv
Ahpo9wdRGgAAAECdYbGd7/1aYLqESvSS7CzEREnFaXsyaRlwO6wDHK5/YNdamAGC
sQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1EaAAAADHRlc3QgZml4dHVyZQE=
-----END OPENSSH PRIVATE KEY-----
"""
PUBLIC = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea"


def seed_args():
    return {"hostname": "cloud1office.example.test", "timezone": "Europe/Paris",
            "admin_public_key": PUBLIC + " admin-test", "host_private_key": PRIVATE,
            "host_public_key": PUBLIC + " host-test", **NETWORK}


class ImageCandidateTests(unittest.TestCase):
    def test_exact_public_identity_detached_without_approval(self):
        original = copy.deepcopy(IMAGE)
        result = vm.validate_unaccepted_image_candidate(original)
        self.assertEqual(result, IMAGE)
        result["sha512"] = "a" * 128
        self.assertEqual(original, IMAGE)
        # Syntax validation is deliberately not policy or image authentication.
        self.assertEqual(vm.validate_unaccepted_image_candidate(result), result)

    def test_only_exact_official_numeric_branch_matched_release_urls(self):
        for url in (IMAGE["url"].replace("https:", "http:"), IMAGE["url"] + "?download=1",
                    IMAGE["url"] + "#fragment", IMAGE["url"].replace("dl-cdn.", "mirror."),
                    IMAGE["url"].replace("3.24.2", "latest"), IMAGE["url"].replace("r2", "rnext"),
                    IMAGE["url"].replace("3.24.2", "3.23.2"), IMAGE["url"].replace("r2", "r02"),
                    IMAGE["url"].replace("/cloud/", "/cloud/../cloud/"),
                    IMAGE["url"].replace("https://", "https://evil@"),
                    IMAGE["url"].replace(".org/", ".org:443/")):
            with self.subTest(url=url), self.assertRaises(ValueError):
                vm.validate_unaccepted_image_candidate({**IMAGE, "url": url})

    def test_release_and_revision_are_caller_data_not_module_policy(self):
        for release in ("3.24.0", "3.24.3", "3.24.123"):
            candidate = {**IMAGE, "url": IMAGE["url"].replace("3.24.2", release).replace("r2", "r17")}
            self.assertEqual(vm.validate_unaccepted_image_candidate(candidate), candidate)
        # A synthetic future publication shape is data-only, NOT approval of its
        # existence, support, signature or runtime behavior.
        future = {**IMAGE, "alpine_branch": "3.25", "url": IMAGE["url"].replace("3.24", "3.25")}
        self.assertEqual(vm.validate_unaccepted_image_candidate(future), future)

    def test_exact_metadata_and_digest_required(self):
        for key, values in {"architecture": ["amd64", "aarch64", None], "firmware": ["uefi"],
                            "bootstrap": ["tinycloud"], "alpine_branch": ["3.23", "latest", 3.24],
                            "sha512": ["f" * 127, "f" * 129, "G" * 128, "F" * 128, "", None]}.items():
            for value in values:
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    vm.validate_unaccepted_image_candidate({**IMAGE, key: value})
        for value in (None, [], {}, {**IMAGE, "jwt": "secret-canary"}):
            with self.assertRaises(ValueError) as caught:
                vm.validate_unaccepted_image_candidate(value)
            self.assertNotIn("secret-canary", str(caught.exception))
        for key in IMAGE:
            value = dict(IMAGE)
            del value[key]
            with self.assertRaises(ValueError):
                vm.validate_unaccepted_image_candidate(value)


class VmConfigTests(unittest.TestCase):
    def test_exact_tagged_template_options_single_disk_and_nic(self):
        self.assertEqual(vm.candidate_vm_names("cloud1"), {"vm": "cloud1office", "switch": "cloud1office"})
        self.assertEqual(vm.render_unaccepted_vm_config("cloud1", cpus=2, memory_mb=3072, disk_gib=17, mac=MAC),
                         'loader="uefi"\ncpu="2"\nmemory="3072M"\ncomports="com1"\n'
                         'disk0_type="virtio-blk"\ndisk0_dev="file"\ndisk0_name="disk0.img"\n'
                         'disk0_size="17G"\nnetwork0_type="virtio-net"\n'
                         'network0_switch="cloud1office"\nnetwork0_mac="02:00:00:00:00:06"\n')

    def test_sizes_explicit_no_invented_minima(self):
        self.assertIn('memory="1M"', vm.render_unaccepted_vm_config("a", cpus=1, memory_mb=1, disk_gib=1, mac=MAC))
        for key in ("cpus", "memory_mb", "disk_gib"):
            for value in (0, -1, True, False, "2", 1.5, math.inf, math.nan, None):
                args = dict(cpus=2, memory_mb=2048, disk_gib=20, mac=MAC)
                args[key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    vm.render_unaccepted_vm_config("a", **args)

    def test_identity_and_mac_injection_refused(self):
        for instance in ("", "A", "a-b", "123", "a" * 9, "a\nloader=evil", None):
            with self.assertRaises(ValueError):
                vm.candidate_vm_names(instance)
        for mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:00:00:00:00:06",
                    "02:AA:00:00:00:06", MAC + '\n', None):
            with self.assertRaises(ValueError):
                vm.render_unaccepted_vm_config("a", cpus=1, memory_mb=1, disk_gib=1, mac=mac)


class NetworkCandidateTests(unittest.TestCase):
    def test_single_static_eni_interface_bound_to_mac(self):
        original = copy.deepcopy(NETWORK)
        output = json.loads(vm.render_unaccepted_network_config(**original))
        self.assertEqual(original, NETWORK)
        self.assertEqual(output, {"version": 1, "config": [
            {"type": "physical", "name": "eth0", "mac_address": MAC,
             "subnets": [{"type": "static", "address": NETWORK["address"], "gateway": NETWORK["gateway"]}]},
            {"type": "nameserver", "address": ["9.9.9.9"]}]})

    def test_private_subnet_hosts_only(self):
        for key, values in {"address": ["8.8.8.8/30", "127.0.0.2/30", "10.77.0.6", "10.77.0.6/31",
                                         "10.77.0.4/30", "10.77.0.7/30", "10.77.0.6/7", "fd00::6/64", None],
                            "gateway": ["10.77.0.6", "10.77.0.4", "10.77.0.7", "10.77.1.5", "8.8.8.8", None]}.items():
            for value in values:
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    vm.render_unaccepted_network_config(**{**NETWORK, key: value})

    def test_explicit_ipv4_dns_only(self):
        for dns in ([], None, "9.9.9.9", ["evil\nnameserver"], ["::1"], ["127.0.0.1"],
                    ["169.254.169.254"], ["0.0.0.0"], ["224.0.0.1"], ["255.255.255.255"], [123]):
            with self.subTest(dns=dns), self.assertRaises(ValueError):
                vm.render_unaccepted_network_config(**{**NETWORK, "dns": dns})
        self.assertIn("10.77.0.5", vm.render_unaccepted_network_config(**{**NETWORK, "dns": ["10.77.0.5"]}))


class HostTrustTests(unittest.TestCase):
    def test_supplied_openssh_envelope_and_comment_normalization(self):
        self.assertIsNone(vm.check_candidate_host_private_key_envelope(PRIVATE))
        self.assertEqual(vm.render_candidate_known_hosts("10.77.0.6", PUBLIC + " test"), "10.77.0.6 " + PUBLIC + "\n")

    def test_public_wire_encoding_not_just_text_prefix(self):
        bad_blobs = (b"garbage", ssh_string(b"ssh-rsa") + ssh_string(b"a" * 32),
                     ssh_string(b"ssh-ed25519") + ssh_string(b"a" * 31),
                     ssh_string(b"ssh-ed25519") + ssh_string(b"a" * 32) + b"extra",
                     struct.pack(">I", 10000) + b"a")
        keys = ["ssh-ed25519 " + base64.b64encode(blob).decode() for blob in bad_blobs]
        keys += ["ssh-ed25519 garbage", "ssh-rsa " + PUBLIC.split()[1], PUBLIC + "\nINJECT",
                 PUBLIC + " \tsecret-canary", 'command="evil" ' + PUBLIC, None]
        for key in keys:
            with self.subTest(key=key), self.assertRaises(ValueError) as caught:
                vm.render_candidate_known_hosts("10.77.0.6", key)
            self.assertNotIn("secret-canary", str(caught.exception))

    def test_private_envelope_bounded_secret_safe_not_pair_validation(self):
        malformed = ["-----BEGIN OPENSSH PRIVATE KEY-----\nsecret-canary\n-----END OPENSSH PRIVATE KEY-----",
                     "-----BEGIN OPENSSH PRIVATE KEY-----\n\n-----END OPENSSH PRIVATE KEY-----",
                     PRIVATE.replace("OPENSSH", "RSA"), PRIVATE[:-10], PRIVATE + "x" * 4096,
                     PRIVATE.replace("b3Bl", "!!!!"), None]
        for key in malformed:
            with self.assertRaises(ValueError) as caught:
                vm.check_candidate_host_private_key_envelope(key)
            self.assertNotIn("secret-canary", str(caught.exception))
            self.assertNotIn(base64.b64encode(b"openssh-key-v1").decode(), str(caught.exception))
            self.assertTrue(caught.exception.__suppress_context__)
        # Deliberately accepted framing with invalid internals: no hidden binary
        # parser or false pair/type/encryption verification claim.
        envelope = "-----BEGIN OPENSSH PRIVATE KEY-----\nYWJj\n-----END OPENSSH PRIVATE KEY-----\n"
        self.assertIsNone(vm.check_candidate_host_private_key_envelope(envelope))
        self.assertFalse(hasattr(vm, "validate_candidate_host_key_pair"))

    def test_ssh_argv_uses_private_pinned_trust_without_config_or_password_fallback(self):
        args = vm.candidate_ssh_arguments("10.77.0.6", known_hosts_path="/private/known_hosts", identity_path="/private/admin")
        self.assertEqual(args[:5], ["ssh", "-F", "/dev/null", "-i", "/private/admin"])
        for option in ("StrictHostKeyChecking=yes", "UpdateHostKeys=no", "HostKeyAlgorithms=ssh-ed25519",
                       "UserKnownHostsFile=/private/known_hosts", "GlobalKnownHostsFile=/dev/null",
                       "BatchMode=yes", "IdentitiesOnly=yes", "IdentityAgent=none", "PasswordAuthentication=no",
                       "KbdInteractiveAuthentication=no", "ClearAllForwardings=yes", "ForwardAgent=no"):
            self.assertIn(option, args)
        self.assertEqual(args[-1], "root@10.77.0.6")
        self.assertNotIn(PRIVATE, repr(args))
        self.assertNotIn("accept-new", repr(args))
        for address in ("8.8.8.8", "127.0.0.1", "10.77.0.6\nevil", None):
            with self.assertRaises(ValueError):
                vm.candidate_ssh_arguments(address, known_hosts_path="/private/known_hosts", identity_path="/private/admin")
        for path in ("relative", "/private/../foreign", "/secret-canary\n", "/", None):
            for field in ("known_hosts_path", "identity_path"):
                paths = {"known_hosts_path": "/private/known_hosts", "identity_path": "/private/admin", field: path}
                with self.assertRaises(ValueError) as caught:
                    vm.candidate_ssh_arguments("10.77.0.6", **paths)
                self.assertNotIn("secret-canary", str(caught.exception))


class SeedCandidateTests(unittest.TestCase):
    def test_cloud_config_is_json_yaml_subset_with_private_host_key_only(self):
        args = seed_args()
        before = copy.deepcopy(args)
        seed = vm.render_unaccepted_nocloud_seed("cloud1", **args)
        self.assertEqual(args, before)
        self.assertEqual(set(seed), {"user-data", "meta-data", "network-config"})
        self.assertTrue(seed["user-data"].startswith("#cloud-config\n"))
        config = json.loads(seed["user-data"].split("\n", 1)[1])
        self.assertEqual(config["ssh_keys"], {"ed25519_private": PRIVATE, "ed25519_public": PUBLIC})
        self.assertEqual(config["users"], [{"name": "root", "lock_passwd": False, "hashed_passwd": "*",
                                           "ssh_authorized_keys": [PUBLIC]}])
        self.assertFalse(config["disable_root"])
        self.assertFalse(config["ssh_pwauth"])
        self.assertNotIn("ssh_genkeytypes", config)
        self.assertTrue(config["ssh_deletekeys"])
        self.assertEqual(config["ssh_publish_hostkeys"], {"enabled": False})
        self.assertFalse(config["ssh"]["emit_keys_to_console"])
        self.assertTrue(config["disable_ec2_metadata"])
        self.assertEqual(config["hostname"], "cloud1office")
        self.assertEqual(config["timezone"], "Europe/Paris")
        files = {item["path"]: item for item in config["write_files"]}
        for item in files.values():
            self.assertEqual(item["owner"], "root:root")
            self.assertEqual(item["permissions"], "0644" if item['path'] == '/etc/resolv.conf' else "0600")
        self.assertEqual(files['/etc/resolv.conf']['content'], 'nameserver 9.9.9.9\n')
        self.assertEqual(json.loads(files["/etc/cloud/cloud.cfg.d/99-office-local.cfg"]["content"]),
                         {"datasource_list": ["NoCloud"]})
        sshd = files["/etc/ssh/sshd_config"]["content"]
        for line in ("PermitRootLogin prohibit-password", "PasswordAuthentication no", "KbdInteractiveAuthentication no",
                     "AllowUsers root", "AllowTcpForwarding no", "AllowAgentForwarding no"):
            self.assertIn(line + "\n", sshd)
        for forbidden in ("runcmd", "bootcmd", "packages", "chpasswd", "phone_home", "seedfrom"):
            self.assertNotIn(forbidden, config)
        self.assertEqual(json.loads(seed["meta-data"]), {
            "instance-id": "cloud1office", "local-hostname": args["hostname"], "dsmode": "local"})
        self.assertNotIn("PRIVATE KEY", seed["meta-data"] + seed["network-config"])
        self.assertEqual(seed["network-config"], vm.render_unaccepted_network_config(**NETWORK))

    def test_invalid_hostname_timezone_and_secret_safe_errors(self):
        for field, values in {"hostname": ["a\nruncmd: evil", "A.example", "-evil", "a..b", "127.0.0.1", "a" * 64, None],
                              "timezone": ["../etc/passwd", "Europe/../Paris", "UTC\nsecret-canary", "", None],
                              "host_private_key": ["secret-canary"], "admin_public_key": ["secret-canary"]}.items():
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(ValueError) as caught:
                    vm.render_unaccepted_nocloud_seed("cloud1", **{**seed_args(), field: value})
                self.assertNotIn("secret-canary", str(caught.exception))
                self.assertNotIn(PRIVATE, str(caught.exception))
        for timezone in ("UTC", "Etc/GMT+1", "America/Argentina/Buenos_Aires"):
            vm.render_unaccepted_nocloud_seed("cloud1", **{**seed_args(), "timezone": timezone})

    def test_no_overlay_or_application_secret_input(self):
        for field in ("jwt", "nextcloud_password", "user_data", "runcmd"):
            with self.assertRaises(TypeError):
                vm.render_unaccepted_nocloud_seed("cloud1", **seed_args(), **{field: "secret-canary"})

    def test_module_has_no_io_or_lifecycle_abstraction(self):
        tree = ast.parse(inspect.getsource(vm))
        self.assertFalse(any(isinstance(node, ast.ClassDef) for node in ast.walk(tree)))
        pure = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                and node.name.startswith(('render_', 'candidate_', 'validate_unaccepted_', 'check_candidate_'))]
        for node in (child for function in pure for child in ast.walk(function)):
            if isinstance(node, ast.Import):
                self.assertFalse({name.name for name in node.names} & {"subprocess", "urllib", "socket"})
            if isinstance(node, ast.Call):
                self.assertNotIn(getattr(node.func, "id", ""), ("open", "exec", "eval"))
                self.assertNotIn(getattr(node.func, "attr", ""), ("mkdir", "write_text", "write_bytes", "run", "urlopen"))


if __name__ == "__main__":
    unittest.main()
