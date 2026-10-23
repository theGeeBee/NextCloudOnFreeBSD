"""Unaccepted Alpine VM renderers and private native-key helpers.

Evidence: vm-bhyve v1.7.5 sample-templates/config.sample and cloud-init 26.1
cc_ssh, DataSourceNoCloud, and net/network_state.py. Limine describes the image,
not proven bhyve UEFI compatibility. Rendering never authenticates image bytes.
No import-time probes, image acquisition/disk creation or implicit startup occurs.
Explicit stop/datastore withdrawal requires journal-bound storage identity and the
existing global host lock; VM creation/start/deployment integration is not enabled.
Renderers remain pure. Native key generation/verification is explicit through the
existing Runner, never a private-key parser or an SSH management framework.
Seed files, ISO and cached user-data remain private secrets. No VM execution or
backend policy approval is enabled by these helpers.
"""

import base64
import binascii
import hashlib
import ipaddress
import json
import os
import re
import shlex
import stat
import time
import uuid
from pathlib import Path, PurePosixPath

from .config import PRIVATE_RANGES
from .operations import _public_key as _normalize_public_key

VM_RC_CONFIG = Path('/etc/rc.conf.d/vm')
VM_RC_DIRECTORY = Path('/usr/local/etc/rc.d')
_LOCAL_DOCKER = ('/usr/bin/env','-i','PATH=/sbin:/bin:/usr/sbin:/usr/bin','HOME=/root',
                 '/usr/bin/docker','--host=unix:///var/run/docker.sock')


def validate_unaccepted_image_candidate(image):
    """Return a detached public identity; checksum authority belongs to later policy.

    Only this firmware/bootstrap variant is understood. Branch, release/revision
    and checksum come from the caller, not module constants. Syntax is neither policy
    approval nor signature verification; no defaults are invented.
    """
    from .versions import validate_guest_image
    return validate_guest_image(image)


def candidate_vm_names(instance):
    """Dedicated office VM and manual-switch names, not resource ownership proof."""
    if not isinstance(instance, str) or not re.fullmatch(r"[a-z][a-z0-9]{0,7}", instance):
        raise ValueError("Invalid VM instance identifier")
    return {"vm": f"{instance}office", "switch": f"{instance}office"}


def _positive_integer(value):
    if type(value) is not int or value <= 0:
        raise ValueError("VM CPU, memory and disk sizes must be explicit positive integers")
    return value


def _mac(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", value):
        raise ValueError("Expected a lowercase unicast MAC address")
    if int(value[:2], 16) & 1 or value == "00:00:00:00:00:00":
        raise ValueError("Expected a nonzero unicast MAC address")
    return value


def render_unaccepted_vm_config(instance, *, cpus, memory_mb, disk_gib, mac):
    """vm-bhyve create-template text; disk0_size is a creation hint, not a resize.

    disk0_dev=file means raw disk0.img, not the acquired qcow2. The switch must
    separately be attached manually to an owned private bridge. No tested sizing
    minimum, boot success, serial output or disk growth is asserted. vm-bhyve1.7.5
    generates a MAC during create even when the template supplies one: finalize
    or inspect the owned VM configuration before binding NoCloud to its actual MAC.
    """
    names = candidate_vm_names(instance)
    values = {"loader": "uefi", "cpu": _positive_integer(cpus),
              "memory": f"{_positive_integer(memory_mb)}M", "comports": "com1",
              "disk0_type": "virtio-blk", "disk0_dev": "file", "disk0_name": "disk0.img",
              "disk0_size": f"{_positive_integer(disk_gib)}G", "network0_type": "virtio-net",
              "network0_switch": names["switch"], "network0_mac": _mac(mac)}
    return "".join(f'{key}="{value}"\n' for key, value in values.items())


def _private_ipv4(value):
    try:
        address = ipaddress.IPv4Address(value) if isinstance(value, str) else None
        if address is None or not any(address in network for network in PRIVATE_RANGES):
            raise ValueError
    except (ValueError, TypeError):
        raise ValueError("Expected an RFC1918 IPv4 address") from None
    return str(address)


def render_unaccepted_network_config(*, address, gateway, dns, mac):
    """NoCloud network-config v1 for Alpine's ENI renderer, one expected MAC."""
    try:
        interface = ipaddress.IPv4Interface(address) if isinstance(address, str) and "/" in address else None
        if interface is None or interface.network.prefixlen > 30:
            raise ValueError
        _private_ipv4(str(interface.ip))
        if not any(interface.network.subnet_of(network) for network in PRIVATE_RANGES):
            raise ValueError
        gateway_ip = ipaddress.IPv4Address(_private_ipv4(gateway))
        if (interface.ip in (interface.network.network_address, interface.network.broadcast_address)
                or gateway_ip not in interface.network or gateway_ip == interface.ip
                or gateway_ip in (interface.network.network_address, interface.network.broadcast_address)):
            raise ValueError
    except (ValueError, TypeError):
        raise ValueError("Expected distinct private guest and gateway hosts on one IPv4 subnet") from None
    if not isinstance(dns, (tuple, list)) or not dns:
        raise ValueError("Explicit IPv4 DNS resolvers are required")
    try:
        resolvers = []
        for value in dns:
            resolver = ipaddress.IPv4Address(value) if isinstance(value, str) else None
            if resolver is None or resolver.is_multicast or resolver.is_unspecified or resolver.is_loopback or resolver.is_link_local or resolver.is_reserved:
                raise ValueError
            resolvers.append(str(resolver))
    except (ValueError, TypeError):
        raise ValueError("Invalid IPv4 DNS resolver") from None
    return _json({"version": 1, "config": [
        {"type": "physical", "name": "eth0", "mac_address": _mac(mac), "subnets": [
            {"type": "static", "address": str(interface), "gateway": str(gateway_ip)}]},
        {"type": "nameserver", "address": resolvers}]})


def _json(value):
    return json.dumps(value, sort_keys=True, indent=2) + "\n"


def _public_key(value):
    """Reuse public normalization; bound the one ed25519 wire shape we render."""
    try:
        if not isinstance(value, str) or len(value) > 1024 or "\n" in value or "\r" in value:
            raise ValueError
        if any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError
        normalized = _normalize_public_key(value).rstrip("\n")
        fields = normalized.split(" ")
        blob = base64.b64decode(fields[1], validate=True)
        if (fields[0] != "ssh-ed25519" or len(blob) != 51
                or blob[:19] != b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"):
            raise ValueError
        if base64.b64encode(blob).decode("ascii") != fields[1]:
            raise ValueError
    except (ValueError, TypeError, binascii.Error):
        raise ValueError("Invalid OpenSSH ed25519 public key") from None
    return normalized


def check_candidate_host_private_key_envelope(private_key):
    """Bound a PEM envelope only; NOT a private-key or key-pair validator.

    The caller must previously generate and verify the ed25519 pair using trusted
    native OpenSSH tools. This pure renderer does not parse private key internals,
    check encryption/type, derive public keys, or execute ssh-keygen. Use the
    explicit native helper before rendering rather than relying on this envelope.
    """
    try:
        if not isinstance(private_key, str) or len(private_key) > 4096:
            raise ValueError
        lines = private_key.splitlines()
        if (len(lines) < 3 or lines[0] != "-----BEGIN OPENSSH PRIVATE KEY-----"
                or lines[-1] != "-----END OPENSSH PRIVATE KEY-----"):
            raise ValueError
        if not all(re.fullmatch(r"[A-Za-z0-9+/=]{1,128}", line) for line in lines[1:-1]):
            raise ValueError
        if not base64.b64decode("".join(lines[1:-1]), validate=True):
            raise ValueError
    except (ValueError, TypeError, binascii.Error):
        raise ValueError("Invalid OpenSSH private host key envelope") from None


def _hostname(value):
    if not isinstance(value, str) or not re.fullmatch(
            r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*", value):
        raise ValueError("Expected a lowercase DNS guest hostname")
    if re.fullmatch(r"[0-9.]+", value):
        raise ValueError("Guest hostname must not be an IP address")
    return value


def render_unaccepted_nocloud_seed(instance, *, hostname, timezone, admin_public_key,
                                   host_private_key, host_public_key, address, gateway, dns, mac):
    """Return private seed filename/text pairs; no arbitrary overlay or app secrets.

    JSON is YAML-compatible. Only the SSH host private key is secret input. No
    metadata HTTP server, remote seed URL, package install, or startup commands.
    PRECONDITION: the supplied ed25519 host pair was generated and verified using
    trusted native OpenSSH; this function checks only public shape/PEM envelope.
    The datasource restriction is persistent configuration, not proof of which
    datasource the pristine image selected before consuming this first seed.
    """
    names = candidate_vm_names(instance)
    hostname = _hostname(hostname)
    # Syntax validation only; availability in the guest's tzdata is a native check.
    if not isinstance(timezone, str) or not re.fullmatch(
            r"(?:UTC|[A-Za-z][A-Za-z0-9_+-]*(?:/[A-Za-z][A-Za-z0-9_+-]*){1,2})", timezone):
        raise ValueError("Expected a timezone identifier")
    admin = _public_key(admin_public_key)
    host = _public_key(host_public_key)
    check_candidate_host_private_key_envelope(host_private_key)
    network = render_unaccepted_network_config(address=address, gateway=gateway, dns=dns, mac=mac)
    config = {"hostname": hostname.split(".")[0], "fqdn": hostname,
              "manage_etc_hosts": True, "timezone": timezone, "disable_root": False,
              # Alpine passwd -l creates a !-locked account, which non-PAM
              # OpenSSH rejects before public-key authentication. '*' is an
              # unusable password hash without that account-lock marker.
              "ssh_pwauth": False, "users": [{"name": "root", "lock_passwd": False,
                                               "hashed_passwd": "*",
                                                "ssh_authorized_keys": [admin]}],
              # Explicit ssh_keys suppresses generation. An empty
              # ssh_genkeytypes array is rejected by cloud-init26.1's schema.
              "ssh_deletekeys": True,
              "ssh_keys": {"ed25519_private": host_private_key, "ed25519_public": host},
              "ssh_publish_hostkeys": {"enabled": False}, "ssh_quiet_keygen": True,
              "ssh": {"emit_keys_to_console": False}, "disable_ec2_metadata": True,
              "write_files": [
                  {"path": "/etc/cloud/cloud.cfg.d/99-office-local.cfg", "owner": "root:root",
                   "permissions": "0600", "content": _json({"datasource_list": ["NoCloud"]})},
                  {"path": "/etc/ssh/sshd_config", "owner": "root:root", "permissions": "0600",
                   "content": "HostKey /etc/ssh/ssh_host_ed25519_key\n"
                   "PermitRootLogin prohibit-password\nPubkeyAuthentication yes\n"
                   "PasswordAuthentication no\nKbdInteractiveAuthentication no\n"
                   "PermitEmptyPasswords no\nAllowUsers root\nAllowAgentForwarding no\n"
                    "AllowTcpForwarding no\nX11Forwarding no\n"},
                   # The reviewed Alpine image has no resolvconf executor. ENI's
                   # dns-nameservers on loopback alone leaves resolv.conf absent.
                   # Write the same validated resolver selection before APK/TLS.
                   {"path": "/etc/resolv.conf", "owner": "root:root", "permissions": "0644",
                    "content": "".join("nameserver " + str(ipaddress.IPv4Address(value)) + "\n" for value in dns)}]}
    return {"user-data": "#cloud-config\n" + _json(config),
            "meta-data": _json({"instance-id": names["vm"], "local-hostname": hostname,
                                "dsmode": "local"}), "network-config": network}


def render_candidate_known_hosts(address, host_public_key):
    """Pin the supplied host key to the private guest IP, never TOFU/keyscan."""
    address = _private_ipv4(address)
    public = _public_key(host_public_key)
    return f"{address} {public}\n"


def _absolute_path(value):
    if (not isinstance(value, str) or not value.startswith("/")
            or any(ord(c) < 32 or ord(c) == 127 for c in value)
            or ".." in PurePosixPath(value).parts or value == "/"):
        raise ValueError("SSH trust and identity files require explicit absolute paths")
    return value


def candidate_ssh_arguments(address, *, known_hosts_path, identity_path):
    """SSH argv only (no execution); paths must already have private ownership.

    Isolate user/global SSH configuration and forbid password fallback, host key
    replacement, agent forwarding and inherited forwarding. No public port map.
    """
    address = _private_ipv4(address)
    known_hosts_path = _absolute_path(known_hosts_path)
    identity_path = _absolute_path(identity_path)
    return ["ssh", "-F", "/dev/null", "-i", identity_path, "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=5", "-o", "ConnectionAttempts=1",
            "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
            "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no",
            "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", f"UserKnownHostsFile={known_hosts_path}",
            "-o", "GlobalKnownHostsFile=/dev/null", "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no", "-o", "ForwardAgent=no",
             "-o", "ClearAllForwardings=yes", f"root@{address}"]


def _key_file_identity(path, *, limit=4096):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o077 or info.st_nlink != 1 or not 0 < info.st_size <= limit):
        raise ValueError("Unsafe private VM key file")
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def native_key_pair(runner, directory, role):
    """Generate once in caller-owned private state, or verify an existing pair.

    Caller holds the existing host operation lock and binds this directory to its
    instance/install journal. Partial/changed files are retained and refused, never
    overwritten. Keys and command diagnostics never enter argv or public errors.
    FreeBSD's ssh-keygen -y includes a comment; compare canonical public fields.
    """
    if role not in ("admin", "host"):
        raise ValueError("VM key role must be admin or host")
    directory = Path(_absolute_path(str(directory)))
    try:
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or directory.resolve(strict=True) != directory):
            raise ValueError
        private, public = directory / (role + "_ed25519"), directory / (role + "_ed25519.pub")
        private_exists = private.exists() or private.is_symlink()
        public_exists = public.exists() or public.is_symlink()
        if private_exists != public_exists:
            raise ValueError
        if not private_exists:
            runner.run("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(private),
                       input="", hide_output=True, timeout=15)
            # OpenSSH writes a public-readable .pub file; the containing state
            # directory was already private. Tighten only this newly created file.
            new = public.lstat()
            if not stat.S_ISREG(new.st_mode) or new.st_uid != os.geteuid() or new.st_nlink != 1:
                raise ValueError
            public.chmod(0o600)
        before = (_key_file_identity(private), _key_file_identity(public))
        expected = _public_key(public.read_text().strip())
        check_candidate_host_private_key_envelope(private.read_text())
        result = runner.run("/usr/bin/ssh-keygen", "-y", "-f", str(private),
                            input="", hide_output=True, timeout=15)
        if result.returncode != 0 or _public_key(result.stdout.strip()) != expected:
            raise ValueError
        if before != (_key_file_identity(private), _key_file_identity(public)):
            raise ValueError
        return {"private_path": str(private), "public_path": str(public), "public_key": expected}
    except (OSError, ValueError, RuntimeError, TypeError, UnicodeError):
        raise ValueError("VM key generation/verification failed; retain private state for inspection") from None


def vm_paths(config):
    """Fixed per-instance data and shared manager namespace, never an adoption."""
    config.validate()
    if config.backend not in ("eurooffice", "collabora"):
        raise ValueError("This profile has no office VM")
    names = candidate_vm_names(config.instance)
    mount = Path(config.mount_root) / "office-vm"
    root = mount / names["vm"]
    return dict(name=names["vm"], datastore=names["vm"], switch=names["switch"],
                dataset=config.dataset_root + "/office-vm", mountpoint=str(mount),
                root=str(root), disk=str(root / "disk0.img"), config=str(root / (names["vm"] + ".conf")),
                manager_dataset=config.pool + "/cloud-installer/vm",
                manager_root=str(Path(config.bastille_root).parent / "vm"))


def _vm_output(runner, *args, deadline=None):
    timeout = 10 if deadline is None else min(10, deadline - time.monotonic())
    if timeout <= 0:
        raise RuntimeError("Owned VM operation deadline expired")
    result = runner.run(*args, hide_output=True, timeout=timeout)
    if result.returncode != 0 or not isinstance(result.stdout, str):
        raise ValueError("VM inspection command did not complete")
    return result.stdout.strip()


def _vm_rc_context(runner):
    """Refuse later service-specific overrides before invoking vm-bhyve.

    FreeBSD15.1 load_rc_config reads /etc and every local_startup rc.conf.d/vm
    location. Reading just our /etc file does not establish the effective manager.
    Do not source arbitrary shell configuration to discover it.
    """
    result=[]
    for value in _vm_output(runner,'sysrc','-n','local_startup').split():
        if re.search(r'[$`*?(){}\[\]]',value):
            raise ValueError('Dynamic/glob rc startup paths require explicit host configuration review')
        directory=Path(_absolute_path(value))
        if directory in result: raise ValueError('Ambiguous local rc startup directories')
        result.append(directory)
        base=directory.parent if directory.name=='rc.d' else directory
        override=base/'rc.conf.d/vm'
        if override!=VM_RC_CONFIG and (override.exists() or override.is_symlink()):
            raise ValueError('Foreign service-specific VM rc override exists; no automatic adoption')
    return tuple(result)


def _vm_rc_text(paths):
    return 'vm_enable="YES"\nvm_dir="'+paths['manager_root']+'"\nvm_list=""\n'


def _vm_list(text):
    lines = text.splitlines()
    if not lines or lines[0].split() != ["NAME", "DATASTORE", "LOADER", "CPU", "MEMORY", "VNC", "AUTO", "STATE"]:
        raise ValueError("Unsupported vm-bhyve list format")
    result = {}
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 8 or fields[0] in result:
            raise ValueError("Ambiguous VM manager inventory")
        index = 7
        if fields[6] == "Yes":
            if not re.fullmatch(r"\[[1-9][0-9]*\]", fields[7]):
                raise ValueError("Unsupported VM autostart inventory")
            index = 8
        elif fields[6] != "No":
            raise ValueError("Unsupported VM autostart inventory")
        state = " ".join(fields[index:])
        if not re.fullmatch(r"Stopped|Suspended|(?:Running|Bootloader) \([1-9][0-9]*\)|Locked \([^()]+\)", state):
            raise ValueError("Unsupported VM runtime state")
        result[fields[0]] = dict(datastore=fields[1], loader=fields[2], cpu=fields[3],
                                 memory=fields[4], vnc=fields[5], state=state)
    return result


def _vm_datastores(text):
    lines = text.splitlines()
    if not lines or lines[0].split() != ["NAME", "TYPE", "PATH", "ZFS", "DATASET"]:
        raise ValueError("Unsupported VM datastore inventory")
    result = {}
    for line in lines[1:]:
        fields = line.split()
        if len(fields) != 4 or fields[0] in result or not Path(fields[2]).is_absolute():
            raise ValueError("Ambiguous VM datastore inventory")
        result[fields[0]] = tuple(fields[1:])
    return result


def _vm_seed_digest(directory):
    digest = hashlib.sha256()
    for name in ('meta-data','user-data','network-config'):
        path = directory/name
        before = _key_file_identity(path,limit=65536)
        data = path.read_bytes()
        if before != _key_file_identity(path,limit=65536):
            raise ValueError('Private VM seed changed during inspection')
        digest.update(name.encode()+b'\0'+data+b'\0')
    return digest.hexdigest()


def _vm_storage(deployment, deadline=None):
    """Match an existing journal-bound creation reservation to actual storage."""
    from .state import config_digest, private_json
    d, c = deployment, deployment.config
    paths = vm_paths(c)
    if c.office_vm_cpus < 1 or c.office_vm_disk_gib < 1:
        raise ValueError("VM operations require explicit CPU and disk selection")
    reservation = d.state / (paths["name"] + ".creating.json")
    _key_file_identity(reservation, limit=65536)
    record = private_json(reservation)
    fields = {"schema_version", "name", "root", "config_sha256", "versions_sha256", "uuid",
              "dataset_guid", "disk_inode", "vm_config_sha256", "seed_sha256", "seed_iso_sha256"}
    lock = d.registry.evidence_path(c.instance, "versions.json")
    lock_before = _key_file_identity(lock, limit=16 * 1024**2)
    lock_digest = hashlib.sha256(lock.read_bytes()).hexdigest()
    if lock_before != _key_file_identity(lock, limit=16 * 1024**2):
        raise ValueError("VM version lock changed during inspection")
    if (not isinstance(record, dict) or set(record) != fields or type(record["schema_version"]) is not int
            or record["schema_version"] != 1 or record["name"] != paths["name"] or record["root"] != paths["root"]
            or record["config_sha256"] != config_digest(c)
            or record["versions_sha256"] != lock_digest
            or not isinstance(record["vm_config_sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", record["vm_config_sha256"])
            or type(record["disk_inode"]) is not int or record["disk_inode"] < 1
            or not isinstance(record["dataset_guid"], str) or not record["dataset_guid"].isdigit()
            or not 0 < len(record["dataset_guid"]) <= 20 or int(record["dataset_guid"]) < 1
            or not isinstance(record["uuid"], str) or str(uuid.UUID(record["uuid"])) != record["uuid"]
            or uuid.UUID(record["uuid"]).int == 0):
        raise ValueError("VM creation reservation/configuration binding changed")
    def out(*args): return _vm_output(d.runner, *args, deadline=deadline)
    for dataset, mount, owner in ((paths["manager_dataset"], paths["manager_root"], "shared"),
                                  (paths["dataset"], paths["mountpoint"], c.instance)):
        for prop, expected in (("type", "filesystem"), ("mountpoint", mount), ("mounted", "yes"),
                               ("org.cloud-installer:instance", owner)):
            if out("zfs", "get", "-H", "-o", "value", prop, dataset) != expected:
                raise ValueError("VM dataset ownership/mount identity changed")
    if out("zfs", "get", "-Hp", "-o", "value", "guid", paths["dataset"]) != record["dataset_guid"]:
        raise ValueError("VM dataset GUID changed")
    mounts = [row.split() for row in out("mount", "-p").splitlines()]
    for name in ("manager_root", "mountpoint", "root"):
        path = Path(paths[name])
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077
                or path.resolve(strict=True) != path):
            raise ValueError("VM paths are not private owned directories")
    for key, dataset in (("manager_root", paths["manager_dataset"]), ("mountpoint", paths["dataset"]),
                         ("root", paths["dataset"]), ("disk", paths["dataset"]), ("config", paths["dataset"])):
        covering = [row for row in mounts if len(row) == 6 and Path(paths[key]).is_relative_to(row[1])]
        if not covering or max(covering, key=lambda row: len(Path(row[1]).parts))[0] != dataset:
            raise ValueError("VM covering mount differs from its owned dataset")
    disk = Path(paths["disk"])
    info = disk.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077
            or info.st_nlink != 1 or info.st_ino != record["disk_inode"]
            or info.st_size != c.office_vm_disk_gib * 1024**3):
            raise ValueError("VM disk identity/capacity changed")
    disk_mount = out("df", "-P", paths["disk"]).splitlines()
    if (len(disk_mount) != 2 or len(disk_mount[1].split()) != 6
            or disk_mount[1].split()[0] != paths["dataset"]
            or disk_mount[1].split()[-1] != paths["mountpoint"]):
        raise ValueError("VM disk is not on its actual owned covering mount")
    cfg = Path(paths["config"])
    before = _key_file_identity(cfg)
    if hashlib.sha256(cfg.read_bytes()).hexdigest() != record["vm_config_sha256"]:
        raise ValueError("VM configuration changed after finalization")
    if out("sysrc", "-nqf", str(cfg), "uuid") != record["uuid"] or before != _key_file_identity(cfg):
        raise ValueError("VM configuration UUID/identity changed")
    if (_vm_seed_digest(Path(paths['root'])/'.cloud-init') != record['seed_sha256']
            or _vm_seed_digest(d.state/'vm-seed') != record['seed_sha256']):
        raise ValueError('Private VM seed does not match its creation reservation')
    iso = Path(paths['root'])/'seed.iso'
    before = _key_file_identity(iso,limit=16*1024**2)
    if (hashlib.sha256(iso.read_bytes()).hexdigest() != record['seed_iso_sha256']
            or before != _key_file_identity(iso,limit=16*1024**2)):
        raise ValueError('Private VM seed ISO identity changed')
    return paths, record


def _vm_manager_identity(deployment, paths, *, deadline=None):
    d = deployment
    def out(*args): return _vm_output(d.runner, *args, deadline=deadline)
    # vm-bhyve1.7.5 vm-base can mkdir/touch even for list, and its config loader
    # migrates a missing system.conf. Inspect only an already initialized manager.
    # Do not let verification/list/stop silently repair missing manager state.
    manager=Path(paths['manager_root'])
    for name in ('.config','.templates','.iso','.img'):
        path=manager/name
        info=path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode & 0o022
                or path.resolve(strict=True)!=path):
            raise ValueError('VM manager state is missing or unsafe; explicit setup/recovery required')
    for name in ('null.iso','system.conf'):
        path=manager/'.config'/name
        info=path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode & 0o022
                or info.st_nlink!=1 or info.st_size>1024**2):
            raise ValueError('VM manager native initialization files changed')
    _key_file_identity(VM_RC_CONFIG)
    if VM_RC_CONFIG.resolve(strict=True)!=VM_RC_CONFIG or VM_RC_CONFIG.read_text()!=_vm_rc_text(paths):
        raise ValueError('VM manager startup settings changed; vm_list must remain empty')
    selected = d.versions
    package = selected["packages"]["host"][selected["roles"]["vm_manager"]]
    if out("pkg", "query", "%v|%o", package["name"]) != package["version"] + "|" + package["origin"]:
        raise ValueError("VM manager differs from selected package lock")
    if out("sysrc", "-nqf", str(VM_RC_CONFIG), "vm_dir") not in (paths["manager_root"], "zfs:" + paths["manager_dataset"]):
        raise ValueError("Refusing a foreign VM manager directory")
    _vm_rc_context(d.runner)


def native_vm_identity(deployment, *, deadline=None):
    """Read-only exact datastore/config/disk identity; never prefix-match a VM."""
    paths, record = _vm_storage(deployment, deadline)
    d, c = deployment, deployment.config
    def out(*args): return _vm_output(d.runner, *args, deadline=deadline)
    _vm_manager_identity(d,paths,deadline=deadline)
    datastores = _vm_datastores(out("vm", "datastore", "list"))
    if datastores.get('default')!=('directory',paths['manager_root'],'-'):
        raise ValueError('Effective VM manager default datastore is foreign')
    if datastores.get(paths["datastore"]) != ("directory", paths["mountpoint"], "-"):
        raise ValueError("VM datastore is missing, foreign or reallocated")
    inventory = _vm_list(out("vm", "list"))
    row = inventory.get(paths["name"])
    if (row is None or row["datastore"] != paths["datastore"] or row["loader"] != "uefi"
            or row["cpu"] != str(c.office_vm_cpus) or row["memory"] != str(c.office_memory_mb) + "M"
            or row["vnc"] != "-" or any(name != paths["name"] and r["datastore"] == paths["datastore"]
                                        for name, r in inventory.items())):
        raise ValueError("Exact owned VM inventory identity changed")
    return {**paths, "state": row["state"], "uuid": record["uuid"], "datastores": datastores}


def stop_native_vm(deployment, *, timeout=60):
    """Stop only the checked owned VM; normal vm-bhyve stop is asynchronous."""
    deployment.registry._require_lock()
    if type(timeout) not in (int, float) or not 0 < timeout <= 120:
        raise ValueError("Invalid bounded VM stop timeout")
    deadline = time.monotonic() + timeout
    target = native_vm_identity(deployment, deadline=deadline)
    if target["state"] != "Stopped":
        if not target["state"].startswith(("Running (", "Bootloader (")):
            raise ValueError("VM state requires manual recovery; no stop attempted")
        _vm_output(deployment.runner, "vm", "stop", target["name"], deadline=deadline)
    while True:
        current = native_vm_identity(deployment, deadline=deadline)
        if (current["state"] == "Stopped" and not Path("/dev/vmm", target["name"]).exists()
                and not (Path(target["root"]) / "run.lock").exists()):
            return current
        if time.monotonic() >= deadline:
            raise RuntimeError("Owned VM stop could not be confirmed; retain data and inspect privately")
        time.sleep(min(.2, max(0, deadline-time.monotonic())))


def detach_native_vm_datastore(deployment):
    """Normal removal unregisters ONLY this datastore; never use vm destroy."""
    deployment.registry._require_lock()
    paths,record = _vm_storage(deployment)
    _vm_manager_identity(deployment,paths)
    def detach_switch():
        system=Path(paths['manager_root'])/'.config/system.conf'
        result=deployment.runner.run('sysrc','-nqf',str(system),'switch_list',check=False,hide_output=True,timeout=10)
        switches=result.stdout.split() if result.returncode==0 else []
        if len(switches)!=len(set(switches)):
            raise ValueError('Ambiguous VM switch inventory')
        if paths['switch'] not in switches: return
        kind=_vm_output(deployment.runner,'sysrc','-nqf',str(system),'type_'+paths['switch'])
        bridge=_vm_output(deployment.runner,'sysrc','-nqf',str(system),'bridge_'+paths['switch'])
        if kind!='manual' or bridge!=deployment.config.onlyoffice_bridge:
            raise ValueError('VM switch is not the selected owned manual bridge')
        # vm-bhyve manual switch destruction unregisters the switch; it does not
        # destroy the host bridge. Existing owner-aware network removal does that.
        _vm_output(deployment.runner,'vm','switch','destroy',paths['switch'])
    stores = _vm_datastores(_vm_output(deployment.runner,'vm','datastore','list'))
    if stores.get('default')!=('directory',paths['manager_root'],'-'):
        raise ValueError('Effective VM manager default datastore is foreign')
    if paths['datastore'] not in stores:
        # A crash may follow the successful native unregister but precede the
        # enclosing removal checkpoint. Retained, sealed storage plus no runtime
        # permits this read-only reconciliation, never guessed disk destruction.
        inventory = _vm_list(_vm_output(deployment.runner,'vm','list'))
        if (paths['name'] in inventory or Path('/dev/vmm',paths['name']).exists()
                or (Path(paths['root'])/'run.lock').exists()):
            raise ValueError('Unregistered VM still has a runtime or conflicting manager identity')
        detach_switch()
        return {'stopped':True,'datastore_detached':True,'persistent_disk_retained':paths['disk']}
    target = stop_native_vm(deployment)
    detach_switch()
    before = target["datastores"]
    _vm_output(deployment.runner, "vm", "datastore", "remove", target["datastore"])
    after = _vm_datastores(_vm_output(deployment.runner, "vm", "datastore", "list"))
    if after != {name: values for name, values in before.items() if name != target["datastore"]}:
        raise RuntimeError("VM datastore withdrawal differs from the owned selection")
    _vm_storage(deployment)  # Persistent disk/config remain, still on owned storage.
    return {"stopped": True, "datastore_detached": True, "persistent_disk_retained": target["disk"]}


def _owned_vm_dataset(runner, dataset, mountpoint, owner):
    for prop, expected in (('type','filesystem'),('mountpoint',mountpoint),('mounted','yes'),
                            ('org.cloud-installer:instance',owner)):
        if _vm_output(runner,'zfs','get','-H','-o','value',prop,dataset) != expected:
            raise ValueError('VM dataset ownership or mount properties changed')
    path = Path(mountpoint)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077
            or path.resolve(strict=True) != path):
        raise ValueError('VM dataset mount is not a private canonical directory')
    rows = _vm_output(runner,'df','-P',mountpoint).splitlines()
    if len(rows) != 2 or len(rows[1].split()) != 6 or rows[1].split()[0] != dataset or rows[1].split()[-1] != mountpoint:
        raise ValueError('VM dataset is not the actual covering filesystem')
    guid = _vm_output(runner,'zfs','get','-Hp','-o','value','guid',dataset)
    if not re.fullmatch(r'[1-9][0-9]{0,19}',guid):
        raise ValueError('VM dataset GUID is unavailable')
    return guid


def initialize_native_vm_manager(deployment):
    """Initialize only an owned shared manager, after confirmed network staging.

    This is not a package installer: all host tools were selected/solver-checked
    and installed by the existing prerequisite phase. No VM autostart is granted.
    An intent in existing host.json protects a crash before the RC file is written.
    """
    from .host import verify_managed_network, write_private
    from .state import atomic_json, private_json
    d, c = deployment, deployment.config
    d.registry._require_lock()
    from .firewall import pending_transactions
    if pending_transactions(d.registry.root):
        raise ValueError('Unresolved network transaction blocks VM manager setup')
    paths = vm_paths(c)
    if d.versions.get('schema_version') != 3 or d.versions.get('office_backend') != c.backend:
        raise ValueError('VM manager setup requires the retained backend resolution')
    active = verify_managed_network(d.registry,d.runner)
    if c.instance not in private_json(active/'firewall-transition.json')['instances']:
        raise ValueError('VM instance network has not been confirmed')
    if VM_RC_DIRECTORY not in _vm_rc_context(d.runner):
        raise ValueError('VM rc startup directory is not enabled on this host')
    guid = _owned_vm_dataset(d.runner,paths['manager_dataset'],paths['manager_root'],'shared')
    pkg = d.versions['packages']['host'][d.versions['roles']['vm_manager']]
    if _vm_output(d.runner,'pkg','query','%v|%o',pkg['name']) != pkg['version']+'|'+pkg['origin']:
        raise ValueError('VM manager package differs from immutable lock')
    rc = _vm_rc_text(paths)
    marker = dict(dataset=paths['manager_dataset'],mountpoint=paths['manager_root'],guid=guid,
                  rc_file=str(VM_RC_CONFIG),rc_sha256=hashlib.sha256(rc.encode()).hexdigest())
    host = d.registry.host()
    if not isinstance(host,dict):
        raise ValueError('Managed host record is required before VM setup')
    prior = host.get('vm_manager')
    if prior is not None and prior != marker:
        raise ValueError('Shared VM manager identity changed')
    if VM_RC_CONFIG.parent.exists() or VM_RC_CONFIG.parent.is_symlink():
        parent = VM_RC_CONFIG.parent.lstat()
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or parent.st_mode & 0o022
                or VM_RC_CONFIG.parent.resolve(strict=True) != VM_RC_CONFIG.parent):
            raise ValueError('VM RC parent directory is not an owned canonical configuration directory')
    exists = VM_RC_CONFIG.exists() or VM_RC_CONFIG.is_symlink()
    if prior is None or not exists:
        for field in ('vm_dir','vm_enable'):
            result = d.runner.run('sysrc','-n',field,check=False,hide_output=True,timeout=10)
            if result.returncode == 0:
                raise ValueError('Refusing an administrator-managed VM configuration')
        if exists:
            raise ValueError('Refusing an unowned VM RC file')
    if exists:
        _key_file_identity(VM_RC_CONFIG)
        if VM_RC_CONFIG.read_text() != rc:
            raise ValueError('Owned VM RC configuration changed')
    if prior is None:
        atomic_json(d.registry.root/'host.json',{**host,'vm_manager':marker})
    if not exists:
        VM_RC_CONFIG.parent.mkdir(exist_ok=True)
        write_private(VM_RC_CONFIG,rc)
    _vm_output(d.runner,'vm','init')
    datastores = _vm_datastores(_vm_output(d.runner,'vm','datastore','list'))
    if datastores.get('default') != ('directory',paths['manager_root'],'-'):
        raise ValueError('VM default datastore is not the owned shared manager')
    return paths


def create_native_vm(deployment, image_path):
    """Create once from locked bytes, pin NIC/seed, then seal the reservation.

    Caller journal owns sequencing. A partial guest directory without the sealed
    reservation is uncertain and refused; no disk replacement, seed replay or
    guessed completion. A sealed creation may be reconciled after a journal crash.
    """
    from .state import atomic_json, atomic_write, config_digest, private_json
    d, c = deployment, deployment.config
    d.registry._require_lock()
    paths = vm_paths(c)
    if c.office_vm_cpus < 1 or c.office_vm_disk_gib < 1:
        raise ValueError('Explicit VM CPU/disk allocation is required before creation')
    reservation = d.state/(paths['name']+'.creating.json')
    if reservation.exists() or reservation.is_symlink():
        saved = private_json(reservation)
        if isinstance(saved,dict) and 'vm_config_sha256' in saved:
            # The guest disk is live data, not the acquisition cache. Completed
            # creation reconciliation must not require a fresh source download.
            return native_vm_identity(d)
    if Path(paths['root']).exists() or Path(paths['root']).is_symlink():
        raise ValueError('Partial or foreign VM disk/config retained; uncertain creation replay requires inspection')
    runtime = d.versions['office_runtime']
    image = validate_unaccepted_image_candidate(runtime['guest_image'])
    source = Path(_absolute_path(str(image_path)))
    from .operations import _directories
    _directories(source.parent,owners={0,os.geteuid()})
    before = _key_file_identity(source,limit=2*1024**3)
    with source.open('rb') as stream:
        checksum = hashlib.file_digest(stream,'sha512').hexdigest()
    if checksum != image['sha512'] or before != _key_file_identity(source,limit=2*1024**3):
        raise ValueError('Locked guest image checksum/identity changed')
    info = json.loads(_vm_output(d.runner,'qemu-img','info','--output=json','-f','qcow2',str(source)))
    if (info.get('format') != 'qcow2' or info.get('backing-filename') or info.get('dirty-flag') is True
            or info.get('format-specific',{}).get('data',{}).get('corrupt') is True
            or info.get('format-specific',{}).get('data',{}).get('data-file')
            or type(info.get('virtual-size')) is not int or not 0 < info['virtual-size'] <= c.office_vm_disk_gib*1024**3):
        raise ValueError('Locked guest image is not a supported standalone disk')
    if before != _key_file_identity(source,limit=2*1024**3):
        raise ValueError('Locked guest image changed during disk inspection')
    lock = d.registry.evidence_path(c.instance,'versions.json')
    _key_file_identity(lock,limit=16*1024**2)
    intent = dict(schema_version=1,name=paths['name'],root=paths['root'],
                  config_sha256=config_digest(c),versions_sha256=hashlib.sha256(lock.read_bytes()).hexdigest())
    existing_intent = reservation.exists() or reservation.is_symlink()
    if existing_intent:
        saved = private_json(reservation)
        if saved != {**intent,'state':'creating','image_sha512':checksum}:
            raise ValueError('VM creation intent changed')
    from .host import check_vm_disk_capacity
    check_vm_disk_capacity(c, d.runner)
    initialize_native_vm_manager(d)
    guid = _owned_vm_dataset(d.runner,paths['dataset'],paths['mountpoint'],c.instance)
    stores = _vm_datastores(_vm_output(d.runner,'vm','datastore','list'))
    if paths['datastore'] in stores:
        if not existing_intent or stores[paths['datastore']] != ('directory',paths['mountpoint'],'-'):
            raise ValueError('Foreign VM datastore name collision')
    if paths['name'] in _vm_list(_vm_output(d.runner,'vm','list')):
        raise ValueError('VM name is already registered in another datastore')
    mac = '02:' + ':'.join(hashlib.sha256(c.instance.encode()).hexdigest()[i:i+2] for i in range(0,10,2))
    template = Path(paths['manager_root'])/'.templates'/(paths['name']+'.conf')
    template_text = render_unaccepted_vm_config(c.instance,cpus=c.office_vm_cpus,memory_mb=c.office_memory_mb,
                                               disk_gib=c.office_vm_disk_gib,mac=mac)
    if template.exists() or template.is_symlink():
        if not existing_intent:
            raise ValueError('Foreign VM creation template exists without an intent')
        _key_file_identity(template)
        if template.read_text() != template_text:
            raise ValueError('VM creation template changed')
    if not existing_intent:
        atomic_json(reservation,{**intent,'state':'creating','image_sha512':checksum})
    if paths['datastore'] not in stores:
        _vm_output(d.runner,'vm','datastore','add',paths['datastore'],paths['mountpoint'])
    keys = d.state/'vm-keys'
    from .state import private_directory
    private_directory(keys)
    host, admin = native_key_pair(d.runner,keys,'host'), native_key_pair(d.runner,keys,'admin')
    # Use a selected, stable local MAC; vm-bhyve replaces it at create, so pin and
    # read it back before producing the first seed ISO or starting the VM.
    seed = render_unaccepted_nocloud_seed(c.instance,hostname=paths['name'],timezone=c.timezone,
        admin_public_key=admin['public_key'],host_private_key=Path(host['private_path']).read_text(),
        host_public_key=host['public_key'],address=c.onlyoffice_ip+'/30',gateway=c.onlyoffice_gateway,
        dns=[c.dns_server],mac=mac)
    seed_dir = d.state/'vm-seed'
    private_directory(seed_dir)
    for name,text in seed.items():
        target = seed_dir/name
        if target.exists() and target.read_text() != text:
            raise ValueError('Retained private VM seed changed')
        atomic_write(target,text)
    atomic_write(template,template_text)
    # Disk conversion can exceed a metadata-query timeout. The existing progress
    # runner owns/reaps this command group on cancellation rather than leaving an
    # orphan qemu-img writer behind an uncertain creation intent.
    d.runner.run('vm','create','-d',paths['datastore'],'-t',paths['name'],'-s',str(c.office_vm_disk_gib)+'G',
                 '-i',str(source),'-C','-u',str(seed_dir/'user-data'),paths['name'],
                 hide_output=True,timeout=600,progress_label='Alpine VM disk import')
    root = Path(paths['root'])
    if (root/'seed.iso').exists() or (root/'seed.iso').is_symlink():
        raise ValueError('VM seed was already consumed; refusing seed replacement')
    root.chmod(0o700)
    cfg = Path(paths['config'])
    _vm_output(d.runner,'sysrc','-f',str(cfg),'network0_mac='+mac)
    if _vm_output(d.runner,'sysrc','-nqf',str(cfg),'network0_mac') != mac:
        raise ValueError('VM NIC did not retain its selected MAC')
    cfg.chmod(0o600)
    seed_root = root/'.cloud-init'
    info = seed_root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise ValueError('New VM seed directory ownership changed')
    seed_root.chmod(0o700)
    private_directory(seed_root)
    for name,text in seed.items(): atomic_write(root/'.cloud-init'/name,text)
    # Build the protected NoCloud ISO before sealing creation. vm-bhyve otherwise
    # makes it at start with its own umask. Existing ISOs are never regenerated.
    d.runner.run('/usr/sbin/makefs','-t','cd9660','-o','R,L=cidata',str(root/'seed.iso'),str(root/'.cloud-init'),
                 hide_output=True,timeout=30,progress_label='Private NoCloud seed')
    iso = root/'seed.iso'
    iso.chmod(0o600)
    disk = Path(paths['disk'])
    disk.chmod(0o600)
    vm_uuid = _vm_output(d.runner,'sysrc','-nqf',str(cfg),'uuid')
    if str(uuid.UUID(vm_uuid)) != vm_uuid:
        raise ValueError('Created VM UUID is invalid')
    atomic_json(reservation,{**intent,'uuid':vm_uuid,'dataset_guid':guid,'disk_inode':disk.stat().st_ino,
                            'vm_config_sha256':hashlib.sha256(cfg.read_bytes()).hexdigest(),
                            'seed_sha256':_vm_seed_digest(root/'.cloud-init'),
                            'seed_iso_sha256':hashlib.sha256(iso.read_bytes()).hexdigest()})
    return native_vm_identity(d)


def _vm_network_ready(deployment, target):
    """Check the committed policy and exact private bridge before guest startup."""
    from .firewall import pending_transactions
    from .host import verify_managed_network
    from .state import private_json
    d, c = deployment, deployment.config
    if pending_transactions(d.registry.root):
        raise ValueError('Unresolved network transaction blocks VM startup')
    active = verify_managed_network(d.registry,d.runner)
    if c.instance not in private_json(active/'firewall-transition.json')['instances']:
        raise ValueError('VM network is not in the confirmed instance policy')
    text = _vm_output(d.runner,'ifconfig',c.onlyoffice_bridge)
    rows = [line.split() for line in text.splitlines() if line.split()]
    if (not rows or rows[0][0] != c.onlyoffice_bridge+':'
            or [r[1] for r in rows if len(r)>1 and r[0]=='inet'] != [c.onlyoffice_gateway]):
        raise ValueError('VM private bridge address/identity changed')
    members = [r[1] for r in rows if len(r)>1 and r[0]=='member:']
    inet = [r for r in rows if r[0]=='inet']
    if len(inet)!=1 or len(inet[0])<4 or inet[0][2:4] != ['netmask','0xfffffffc']:
        raise ValueError('VM private bridge subnet differs from the selected /30')
    if target['state'] == 'Stopped' and members:
        raise ValueError('Stopped VM bridge has foreign members')
    for member in members:
        if not re.fullmatch(r'tap[0-9]+',member):
            raise ValueError('VM private bridge contains a foreign interface')
        nic = _vm_output(d.runner,'ifconfig',member)
        description = [line.strip() for line in nic.splitlines() if line.strip().startswith('description:')]
        if description != ['description: vmnet/'+target['name']+'/0/'+target['switch']]:
            raise ValueError('VM tap is not bound to the selected guest/switch')
    if len(members)>1:
        raise ValueError('Only one private VM NIC is supported')
    if target['state'].startswith('Running (') and len(members)!=1:
        raise ValueError('Running VM has no verified private NIC')


def start_native_vm(deployment, *, timeout=90, install_continuation=False):
    """Explicit install start, never permission for an incomplete guest to autostart.

    Host Journal must be executing the selected boot phase, or a completed ready
    instance must have its separate bound permission marker. No force/recreate.
    """
    from .state import private_json, config_digest
    d = deployment
    d.registry._require_lock()
    from .firewall import pending_transactions
    if pending_transactions(d.registry.root):
        raise ValueError('Unresolved network transaction blocks VM startup')
    if type(timeout) not in (int,float) or not 0 < timeout <= 180 or type(install_continuation) is not bool:
        raise ValueError('Invalid bounded VM startup timeout')
    if not (d.state/'deployment.json').is_file():
        raise ValueError('VM startup requires its bound installation journal')
    journal = private_json(d.state/'deployment.json')
    if (not isinstance(journal,dict) or type(journal.get('schema_version')) is not int
            or journal['schema_version'] != d.config.schema_version or not isinstance(journal.get('steps'),dict)):
        raise ValueError('Unsupported VM startup journal/schema')
    bound = journal.get('config_sha256') == config_digest(d.config)
    boot=journal['steps'].get('Alpine VM boot')
    boot_state=boot.get('state') if isinstance(boot,dict) else None
    install=bound and boot_state=='running' and d.registry.status(d.config.instance).get('state')=='installing'
    if install_continuation:
        if not bound or boot_state not in ('running','complete') or d.registry.status(d.config.instance).get('state')!='installing':
            raise ValueError('Explicit VM install continuation requires its bound installing journal')
        d.require_original_artifact()
        install=True
    if not install:
        marker = d.state/'allow-vm-start'
        if not marker.exists() and not marker.is_symlink():
            raise ValueError('VM has no completed-install startup permission')
        _key_file_identity(marker)
        if (not bound or not (d.state/'complete').is_file()
                or d.registry.status(d.config.instance).get('state') != 'ready'
                or marker.read_text() != config_digest(d.config)+'\n'):
            raise ValueError('VM has no completed-install startup permission')
    deadline = time.monotonic()+timeout
    target = native_vm_identity(d,deadline=deadline)
    _vm_network_ready(d,target)
    if target['state'].startswith('Running ('):
        return target
    if target['state'] != 'Stopped':
        raise ValueError('VM startup state is uncertain; explicit recovery required')
    system = Path(target['manager_root'])/'.config/system.conf'
    query = d.runner.run('sysrc','-nqf',str(system),'switch_list',check=False,hide_output=True,timeout=10)
    switches = query.stdout.split() if query.returncode == 0 else []
    if target['switch'] in switches:
        kind = _vm_output(d.runner,'sysrc','-nqf',str(system),'type_'+target['switch'])
        bridge = _vm_output(d.runner,'sysrc','-nqf',str(system),'bridge_'+target['switch'])
        if kind != 'manual' or bridge != d.config.onlyoffice_bridge:
            raise ValueError('Refusing a foreign or NAT-managed VM switch')
    else:
        _vm_output(d.runner,'vm','switch','create','-t','manual','-b',d.config.onlyoffice_bridge,target['switch'])
    d.runner.run('vm','start',target['name'],hide_output=True,timeout=20,progress_label='Alpine VM startup')
    while time.monotonic()<deadline:
        current = native_vm_identity(d,deadline=deadline)
        if current['state'].startswith('Running ('):
            _vm_network_ready(d,current)
            return current  # Boot process running, not yet SSH/cloud-init/Docker readiness.
        if current['state'].startswith(('Locked (','Suspended')):
            raise ValueError('VM startup entered an uncertain state')
        time.sleep(min(.2,max(0,deadline-time.monotonic())))
    raise RuntimeError('Owned VM did not reach running state; retain disk and inspect private logs')


def acquire_guest_image(deployment):
    """Acquire exact locked bytes before provisioning; reuse only a verified cache.

    Small per-install acquisition cache, not an image repository/lifecycle layer.
    Failed partial files are private evidence, never accepted as complete or used
    to overwrite a running guest disk. TLS, byte and elapsed bounds remain enabled.
    """
    import urllib.request
    from .discovery import _HTTPSOnly
    from .state import private_directory
    d = deployment
    d.registry._require_lock()
    if d.config.backend not in ('eurooffice','collabora'):
        raise ValueError('This profile requires no VM image acquisition')
    image = validate_unaccepted_image_candidate(d.versions['office_runtime']['guest_image'])
    directory = private_directory(d.state/'vm-acquisition')
    target = directory/'image.qcow2'
    if target.exists() or target.is_symlink():
        before = _key_file_identity(target,limit=2*1024**3)
        with target.open('rb') as stream: digest = hashlib.file_digest(stream,'sha512').hexdigest()
        if digest != image['sha512'] or before != _key_file_identity(target,limit=2*1024**3):
            raise ValueError('Retained guest image cache is changed; no replacement selected')
        return target
    pending = directory/('image-'+uuid.uuid4().hex+'.partial')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),_HTTPSOnly())
    digest, size = hashlib.sha512(), 0
    deadline = time.monotonic()+300
    try:
        with opener.open(image['url'],timeout=30) as response, pending.open('xb') as stream:
            os.fchmod(stream.fileno(),0o600)
            if response.status != 200:
                raise ValueError('Pinned guest image is unavailable')
            length = response.headers.get('Content-Length')
            if length is not None and (not length.isdigit() or not 0<int(length)<=2*1024**3):
                raise ValueError('Guest image declared size is outside the acquisition limit')
            while True:
                if time.monotonic()>deadline:
                    raise ValueError('Pinned image acquisition elapsed limit exceeded')
                chunk = response.read(1024*1024)
                if not chunk: break
                size += len(chunk)
                if size>2*1024**3:
                    raise ValueError('Pinned image exceeds acquisition limit')
                stream.write(chunk)
                digest.update(chunk)
            stream.flush()
            os.fsync(stream.fileno())
        if not size or digest.hexdigest()!=image['sha512']:
            raise ValueError('Pinned guest image SHA512 mismatch')
        os.replace(pending,target)
        descriptor = os.open(directory,os.O_RDONLY)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)
    except (OSError,ValueError):
        raise ValueError('Locked image acquisition failed; private partial evidence retained, no fallback') from None
    return target


def run_native_guest(deployment, args, *, input=None, timeout=60, check=True, read_only=False):
    """One phase command through pinned private SSH, with VM identity on both sides.

    Mirrors the existing checked-jexec boundary, not a remote agent/library.
    Arguments are public operational data only; phase secrets use private stdin.
    """
    from .host import write_private
    d = deployment
    d.registry._require_lock()
    if (not isinstance(args,(tuple,list)) or not args or any(not isinstance(arg,str)
            or len(arg)>4096 or any(ord(c)<32 or ord(c)==127 for c in arg) for arg in args)
            or type(timeout) not in (int,float) or not 0<timeout<=900 or type(read_only) is not bool):
        raise ValueError('Invalid bounded private guest command')
    target = native_vm_identity(d)
    if not target['state'].startswith('Running ('):
        raise ValueError('Selected VM is not running')
    _vm_network_ready(d,target)
    keys = d.state/'vm-keys'
    for role in ('host','admin'):
        if not (keys/(role+'_ed25519')).is_file() or not (keys/(role+'_ed25519.pub')).is_file():
            raise ValueError('Original VM provisioning keys are missing; no replacements generated')
    host = native_key_pair(d.runner,keys,'host')
    admin = native_key_pair(d.runner,keys,'admin')
    # Seed identity is sealed by native_vm_identity; never learn a new key by scan.
    seed = json.loads((d.state/'vm-seed/user-data').read_text().split('\n',1)[1])
    if _public_key(seed['ssh_keys']['ed25519_public']) != host['public_key']:
        raise ValueError('VM host key differs from its sealed provisioning seed')
    known = keys/'known_hosts'
    expected = render_candidate_known_hosts(d.config.onlyoffice_ip,host['public_key'])
    if known.exists() or known.is_symlink():
        _key_file_identity(known)
        if known.read_text()!=expected:
            raise ValueError('Pinned VM host trust changed')
    else:
        if read_only:
            raise ValueError('Read-only guest inspection requires the original pinned trust file')
        write_private(known,expected)
    ssh = candidate_ssh_arguments(d.config.onlyoffice_ip,known_hosts_path=str(known),identity_path=admin['private_path'])
    try:
        command=(*_LOCAL_DOCKER,*args[1:]) if args[0]=='docker' else args
        result = d.runner.run(*ssh,shlex.join(command),input=input,hide_output=True,check=False,
                              timeout=timeout,progress_label='Private office guest phase')
    finally:
        after = native_vm_identity(d)
        if after['uuid']!=target['uuid'] or after['state']!=target['state']:
            raise ValueError('VM identity/runtime changed during private guest execution') from None
    if result.returncode==255 and any(text in (getattr(result,'stderr','') or '') for text in ('Host key verification failed','REMOTE HOST IDENTIFICATION HAS CHANGED')):
        raise ValueError('Pinned VM host-key verification failed; do not replace trust')
    if check and result.returncode:
        raise RuntimeError('Private guest phase failed; retain protected guest diagnostics')
    return result


def wait_native_guest(deployment, *, timeout=180):
    """Require pinned SSH, cloud-init completion and non-degraded status."""
    if type(timeout) not in (int,float) or not 0<timeout<=600:
        raise ValueError('Invalid guest readiness timeout')
    deadline = time.monotonic()+timeout
    while time.monotonic()<deadline:
        try:
            result = run_native_guest(deployment,('/bin/sh','-c','test -f /var/lib/cloud/instance/boot-finished && cloud-init status --format json'),
                                      timeout=min(10,max(1,deadline-time.monotonic())),check=False)
        except RuntimeError:
            time.sleep(min(1,max(0,deadline-time.monotonic())))
            continue
        if result.returncode==0:
            try: status=json.loads(result.stdout)
            except (ValueError,TypeError):
                raise ValueError('Guest cloud-init status is not valid JSON') from None
            if (not isinstance(status,dict) or status.get('status')!='done' or status.get('extended_status')!='done'
                    or status.get('datasource')!='nocloud' or status.get('errors')!=[] or status.get('recoverable_errors')!={}):
                raise ValueError('Guest cloud-init is not cleanly complete')
            return status
        if result.returncode==2 and result.stdout.lstrip().startswith('{'):
            raise ValueError('Guest cloud-init reported degraded status; no readiness claimed')
        time.sleep(min(1,max(0,deadline-time.monotonic())))
    raise RuntimeError('Pinned guest SSH/cloud-init readiness deadline expired')


def select_docker_network(networks):
    """One deterministic private /24 disjoint from every supplied managed route."""
    if not isinstance(networks,(list,tuple)) or not networks or len(networks)>256:
        raise ValueError('Bounded managed network inventory is required')
    occupied=[ipaddress.IPv4Network(str(value),strict=True) for value in networks]
    preferred=('172.31.250.0/24','10.254.250.0/24','192.168.250.0/24')
    for text in preferred:
        candidate=ipaddress.IPv4Network(text)
        if not any(candidate.overlaps(n) for n in occupied): return str(candidate)
    for block in PRIVATE_RANGES:
        if any(block.subnet_of(n) for n in occupied): continue
        for candidate in block.subnets(new_prefix=24):
            if not any(candidate.overlaps(n) for n in occupied): return str(candidate)
    raise ValueError('No non-overlapping Docker private network is available')


def vm_connector_settings(config, *, jwt_secret=None):
    """Pure selected-connector payload, not an activation/readiness operation.

    Tagged eurooffice11.0.6 README and richdocuments12.0.1 AppConfig /
    ActivateConfig / WOPIMiddleware define these distinct namespaces and URLs.
    public_wopi_url is discovery-derived and must be checked after activation,
    never planted here as an invented working discovery result.
    """
    config.validate()
    if config.backend not in ('eurooffice','collabora'):
        raise ValueError('VM connector settings require a selected VM backend')
    internal='http://'+config.onlyoffice_ip+':8081/'
    if config.backend=='eurooffice':
        if not isinstance(jwt_secret,str) or not re.fullmatch(r'[a-fA-F0-9]{64}',jwt_secret):
            raise ValueError('Euro-Office requires the retained 64-hex per-instance JWT')
        return {'apps':{'eurooffice':{
            'DocumentServerUrl':config.public_url+'eurooffice/',
            'DocumentServerInternalUrl':internal,'StorageUrl':config.storage_url,
            'jwt_secret':jwt_secret,'jwt_header':'AuthorizationJWT','verify_peer_off':'false'}}}
    if jwt_secret is not None:
        raise ValueError('Collabora uses WOPI trust, not a Document Server JWT')
    return {'apps':{'richdocuments':{
        'wopi_url':internal+'collabora/','wopi_callback_url':config.storage_url,
        'wopi_allowlist':config.onlyoffice_ip+'/32'}}}


def vm_apache_proxy(config):
    """Distinct virtual-path adapters; rendering is not backend readiness.

    Source: Euro-Office/document-server-proxy commit
    4df50f16ac4e5053552ee749486f76ae4fe1be50/apache/proxy-to-virtual-path.conf.
    CODE's pinned configuration defines net.service_root: retain that prefix on
    the backend rather than stripping it like Euro-Office's forwarded virtual path.
    Rendering neither publishes the include nor proves the container backend.
    """
    from .paths import RESOURCES
    from .office_config import proxy_config
    config.validate()
    if config.backend=='collabora':
        from urllib.parse import urlsplit
        authority=urlsplit(config.public_url).netloc
        backend='http://'+config.onlyoffice_ip+':8081/collabora/'
        return ('# Included inside the existing NC VirtualHost; CODE service_root=/collabora.\n'
                'AllowEncodedSlashes NoDecode\n'
                'RedirectMatch 308 ^/collabora$ /collabora/\n'
                '<Location /collabora/>\n    Require all granted\n'
                '    RequestHeader set X-Forwarded-Proto "https"\n'
                f'    RequestHeader set X-Forwarded-Host "{authority}"\n'
                '    RequestHeader unset X-Forwarded-Prefix\n    ProxyAddHeaders Off\n</Location>\n'
                f'ProxyPass /collabora/ {backend} nocanon upgrade=websocket timeout=3600\n'
                f'ProxyPassReverse /collabora/ {backend}\n'
                '<LocationMatch "(?i)^/collabora/(?:browser/(?:[^/]+/)?admin(?:\\.html)?|cool/(?:adminws|convert-to|insertfile|getMetrics|extract-document-structure|transform-document-structure|render-search-result))(?:/|$)">\n'
                '    Require all denied\n</LocationMatch>\n')
    if config.backend!='eurooffice':
        raise ValueError('No reviewed VM Apache adapter for this selected backend')
    template=(RESOURCES/'templates/onlyoffice/proxy.conf').read_text()
    proxy=proxy_config(template,config.public_url,8081)
    old='http://127.0.0.1:8081/'
    if proxy.count(old)!=2 or proxy.count('/onlyoffice')!=7:
        raise ValueError('Shared document-server proxy template changed; review adapter')
    return proxy.replace(old,'http://'+config.onlyoffice_ip+':8081/').replace('/onlyoffice','/eurooffice').replace('ONLYOFFICE','Euro-Office')


def collabora_configuration(original, config, *, expected_sha256):
    """Transform only a hash-verified image XML, preserving unrelated defaults.

    Selected CODE26.04 image XML defines these paths. Pass the configuration hash
    from its immutable plan, not one learned from untrusted/mutable runtime data.
    No aliasgroup1/extra_params shell-entrypoint semantics are assumed.
    """
    import xml.etree.ElementTree as ET
    from urllib.parse import urlsplit
    config.validate()
    if (config.backend!='collabora' or not isinstance(original,str) or len(original.encode())>1024**2
            or not isinstance(expected_sha256,str) or not re.fullmatch(r'[a-f0-9]{64}',expected_sha256)
            or hashlib.sha256(original.encode()).hexdigest()!=expected_sha256):
        raise ValueError('CODE requires its selected hash-verified configuration')
    try: root=ET.fromstring(original,parser=ET.XMLParser(target=ET.TreeBuilder(insert_comments=True)))
    except ET.ParseError:
        raise ValueError('Invalid selected CODE XML') from None
    if root.tag!='config': raise ValueError('Unexpected CODE configuration root')
    def one(path):
        nodes=root.findall(path)
        if len(nodes)!=1: raise ValueError('CODE configuration layout changed')
        return nodes[0]
    for path,value in {'server_name':urlsplit(config.public_url).netloc,'net/service_root':'/collabora',
                       'net/proto':'IPv4','ssl/enable':'false','ssl/termination':'true',
                       'ssl/ssl_verification':'true','storage/ssl/as_scheme':'true','admin_console/enable':'false'}.items():
        one(path).text=value
    # The selected config documents regex matching in WOPI host parts: escape
    # dots rather than admitting hostname lookalikes or other private servers.
    callback=urlsplit(config.storage_url)
    host=callback.scheme+'://'+re.escape(callback.hostname)+':'+str(callback.port or (443 if callback.scheme=='https' else 80))
    groups=one('storage/wopi/alias_groups')
    for child in list(groups): groups.remove(child)
    groups.set('mode','groups')
    group=ET.SubElement(groups,'group')
    ET.SubElement(group,'host',{'allow':'true'}).text=host
    for path in ('net/post_allow','net/lok_allow'):
        allowed=one(path)
        for child in list(allowed): allowed.remove(child)
        if path=='net/post_allow': allowed.set('allow','true')
        ET.SubElement(allowed,'host').text=config.nextcloud_ip+'/32'
    if config.ca_file:
        one('storage/ssl/ca_file_path').text='/etc/coolwsd/nextcloud-ca.pem'
    return ET.tostring(root,encoding='unicode')+'\n'


def eurooffice_container_arguments(config, plan):
    """Pure candidate command/volume plan for the exact standalone Euro image.

    The pinned image entrypoint was hash-verified against v9.3.5. Unlike native
    ONLYOFFICE9.4, this standalone container bundles PostgreSQL/RabbitMQ/Redis.
    JWT is provisioned via its native Data/.private/jwt_secret file, never Docker
    command/env/inspect output. Bundled database/runtime paths use named volumes
    so Docker initializes their packaged contents; an empty bind over PostgreSQL
    would hide the image's built cluster. Caller must verify volume labels, every
    bind source and the pinned entrypoint before execution. No Docker call is made.
    """
    from .resolution import validate_plan
    from .state import config_digest
    if config.backend!='eurooffice':
        raise ValueError('Standalone Euro-Office command requires its selected backend')
    validate_plan(config,plan)
    identity=plan['office_runtime']['container']
    if (identity['frontend_port']!=80 or identity['guest_port']!=8081
            or not identity['reference'].startswith('ghcr.io/euro-office/documentserver@sha256:')
            or 'entrypoint_sha256' not in identity):
        raise ValueError('Euro-Office image/layout is outside the reviewed standalone adapter')
    root='/var/lib/cloud-installer/office'
    destinations={'database':'/var/lib/postgresql',
                  'queue':'/var/lib/rabbitmq','runtime':'/var/lib/euro-office','logs':'/var/log/euro-office'}
    volumes={config.instance+'office-'+name:target for name,target in destinations.items()}
    binds={root+'/volumes/data':'/var/www/euro-office/Data'}
    args=['docker','run','--detach','--name',config.instance+'office','--restart','unless-stopped',
          '--label','org.cloud-installer.instance='+config.instance,
          '--label','org.cloud-installer.config-sha256='+config_digest(config),
          '--publish',config.onlyoffice_ip+':8081:80',
          '--log-driver','json-file','--log-opt','max-size=10m','--log-opt','max-file=3']
    for source,target in volumes.items():
        args+=['--mount','type=volume,source='+source+',target='+target]
    for source,target in binds.items():
        args+=['--mount','type=bind,source='+source+',target='+target]
    for key,value in {'JWT_ENABLED':'true','JWT_HEADER':'AuthorizationJWT','JWT_IN_BODY':'false',
                      'EXAMPLE_ENABLED':'false','ADMINPANEL_ENABLED':'false','METRICS_ENABLED':'false',
                      'ALLOW_PRIVATE_IP_ADDRESS':'true','ALLOW_META_IP_ADDRESS':'false',
                      'USE_UNAUTHORIZED_STORAGE':'false'}.items():
        args+=['--env',key+'='+value]
    if config.tls_mode!='external':
        args+=['--add-host',config.public_hostname+':'+config.nextcloud_ip]
    if config.ca_file:
        args+=['--mount','type=bind,source='+root+'/nextcloud-ca.pem,target=/etc/euro-office/nextcloud-ca.pem,readonly',
               '--env','NODE_EXTRA_CA_CERTS=/etc/euro-office/nextcloud-ca.pem']
    args.append(identity['reference'])
    return {'args':args,'volumes':volumes,'binds':binds,'jwt_file':root+'/volumes/data/.private/jwt_secret',
            'entrypoint_sha256':identity['entrypoint_sha256'],'health_path':'/healthcheck'}


def collabora_container_arguments(config, plan):
    """Pure shell-free CODE candidate with private, persistent native proof files.

    Keep the image's nonroot user, seccomp and file-capability isolation defaults.
    Do not bind child-roots onto another filesystem or disable capabilities as a
    shortcut. Authoritative documents remain in NC; unsaved editor state is not a
    durable-data claim. Caller must verify config/proof bytes and owner1001 first.
    """
    from .resolution import validate_plan
    from .state import config_digest
    if config.backend!='collabora':
        raise ValueError('CODE command requires the selected Collabora backend')
    validate_plan(config,plan)
    identity=plan['office_runtime']['container']
    if (not identity['reference'].startswith('docker.io/collabora/code@sha256:')
            or identity['frontend_port']!=9980 or identity['guest_port']!=8081
            or 'configuration_sha256' not in identity or 'product_version' not in identity):
        raise ValueError('CODE image/layout is outside the reviewed shell-free adapter')
    root='/var/lib/cloud-installer/office/collabora'
    binds={root+'/coolwsd.xml':'/etc/coolwsd/coolwsd.xml',
           root+'/proof_key':'/etc/coolwsd/proof_key',root+'/proof_key.pub':'/etc/coolwsd/proof_key.pub'}
    args=['docker','run','--detach','--name',config.instance+'office','--restart','unless-stopped',
          '--label','org.cloud-installer.instance='+config.instance,
          '--label','org.cloud-installer.config-sha256='+config_digest(config),
          '--publish',config.onlyoffice_ip+':8081:9980',
          '--log-driver','json-file','--log-opt','max-size=10m','--log-opt','max-file=3']
    for source,target in binds.items():
        args+=['--mount','type=bind,source='+source+',target='+target+',readonly']
    if config.tls_mode!='external':args+=['--add-host',config.public_hostname+':'+config.nextcloud_ip]
    if config.ca_file:
        binds[root+'/nextcloud-ca.pem']='/etc/coolwsd/nextcloud-ca.pem'
        args+=['--mount','type=bind,source='+root+'/nextcloud-ca.pem,target=/etc/coolwsd/nextcloud-ca.pem,readonly']
    args.append(identity['reference'])
    return {'args':args,'binds':binds,'proof_private':root+'/proof_key','proof_public':root+'/proof_key.pub',
            'configuration_sha256':identity['configuration_sha256'],'product_version':identity['product_version'],
            'discovery_path':'/collabora/hosting/discovery','capabilities_path':'/collabora/hosting/capabilities'}


def prepare_collabora_proof(deployment, *, require_existing=False):
    """Persist one native RSA proof pair inside its owned VM; return public hash only.

    Alpine OpenSSH PEM generation/export was exercised on the exact CODE image
    component. Never read/copy the private key into host state, argv or environment.
    Partial/wrong-mode keys are retained and refused, not reset or guessed.
    """
    from .state import atomic_json,private_json,config_digest
    d,c=deployment,deployment.config
    d.registry._require_lock()
    if c.backend!='collabora' or type(require_existing) is not bool:
        raise ValueError('Native proof preparation requires the selected Collabora profile')
    receipt=d.state/'collabora-proof.json'
    exists=receipt.exists() or receipt.is_symlink()
    if require_existing and not exists:
        raise ValueError('Completed CODE proof identity is missing; no regeneration permitted')
    digest=config_digest(c)
    previous=None
    if exists:
        _key_file_identity(receipt,limit=4096)
        previous=private_json(receipt)
        if (not isinstance(previous,dict) or set(previous)!={'schema_version','config_sha256','public_sha256','public_key_sha256'}
                or type(previous['schema_version']) is not int or previous['schema_version']!=2
                or previous['config_sha256']!=digest or any(not isinstance(previous.get(key),str)
                    or not re.fullmatch(r'[a-f0-9]{64}',previous[key]) for key in ('public_sha256','public_key_sha256'))):
            raise ValueError('Retained CODE proof identity changed')
    program=r'''import base64,hashlib,json,os,stat,subprocess,sys,tempfile
from pathlib import Path
os.umask(0o077);cfg=sys.argv[1];existing=sys.argv[2]=='existing'
base=Path('/var/lib/cloud-installer/office');root=base/'collabora'
def directory(p):
 s=p.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o700 and p.resolve(strict=True)==p
directory(base)
identity={'schema_version':1,'config_sha256':cfg,'kind':'collabora-proof'}
if not root.exists() and not root.is_symlink():
 assert not existing
 root.mkdir(mode=0o700)
 with (root/'identity.json').open('x') as f:json.dump(identity,f);f.flush();os.fsync(f.fileno())
directory(root)
p=root/'identity.json';s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and 0<s.st_size<=4096
assert json.loads(p.read_text())==identity
private=root/'proof_key';public=root/'proof_key.pub'
has_private=os.path.lexists(private);has_public=os.path.lexists(public);assert has_private==has_public
new=not has_private
if new:
 assert not existing
 subprocess.run(['/usr/bin/ssh-keygen','-q','-t','rsa','-b','2048','-m','PEM','-N','','-f',str(private)],check=True,timeout=15,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
else:
 for p,mode in ((private,0o600),(public,0o644)):
  s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==1001 and s.st_gid==1001 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==mode and 0<s.st_size<16384
derived=subprocess.run(['/usr/bin/ssh-keygen','-y','-f',str(private)],check=True,capture_output=True,text=True,timeout=10,stdin=subprocess.DEVNULL).stdout
assert derived.startswith('ssh-rsa ')
fingerprint=subprocess.run(['/usr/bin/ssh-keygen','-l','-E','sha256','-f',str(private)],check=True,capture_output=True,text=True,timeout=10,stdin=subprocess.DEVNULL).stdout.split()
assert fingerprint[0]=='2048' and fingerprint[-1]=='(RSA)'
fd,temporary=tempfile.mkstemp(prefix='.public-check-',dir=root)
try:
 with os.fdopen(fd,'w') as f:f.write(derived)
 exported=subprocess.run(['/usr/bin/ssh-keygen','-e','-m','PKCS8','-f',temporary],check=True,capture_output=True,text=True,timeout=10,stdin=subprocess.DEVNULL).stdout
finally:os.unlink(temporary)
assert exported.startswith('-----BEGIN PUBLIC KEY-----') and len(exported)<4096
if new:
 public.write_text(exported);private.chmod(0o600);public.chmod(0o644)
 for p in (private,public):os.chown(p,1001,1001)
else:assert public.read_text()==exported
der=base64.b64decode(''.join(exported.splitlines()[1:-1]),validate=True)
assert der and len(der)<4096
print(json.dumps({'public_sha256':hashlib.sha256(exported.encode()).hexdigest(),'public_key_sha256':hashlib.sha256(der).hexdigest()}))
'''
    result=run_native_guest(d,('python3','-c',_guest_python(program),digest,'existing' if require_existing or exists else 'initial'),timeout=50)
    try:
        value=json.loads(result.stdout)
        if (not isinstance(value,dict) or set(value)!={'public_sha256','public_key_sha256'}
                or any(not isinstance(value[key],str) or not re.fullmatch(r'[a-f0-9]{64}',value[key]) for key in value)):
            raise ValueError
    except (ValueError,TypeError):
        raise ValueError('Native CODE proof preparation returned no valid public identity') from None
    expected={'schema_version':2,'config_sha256':digest,**value}
    if previous is not None and previous!=expected:
        raise ValueError('CODE proof public identity changed; existing files retained')
    if previous is None:atomic_json(receipt,expected)
    return expected


_CODE_ENTRYPOINT=['/usr/bin/coolwsd','--use-env-vars','--o:sys_template_path=/opt/cool/systemplate',
                 '--o:child_root_path=/opt/cool/child-roots','--o:file_server_root_path=/usr/share/coolwsd',
                 '--o:cache_files.path=/opt/cool/cache','--o:logging.color=false','--o:stop_on_config_change=true']


def _image_reference_spellings(reference):
    """Docker may omit its default registry; never remap repository or digest."""
    if (isinstance(reference,str) and re.fullmatch(
            r'docker\.io/[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)+@sha256:[a-f0-9]{64}',reference)):
        return (reference,reference.removeprefix('docker.io/'))
    return (reference,)


def _same_image_reference(actual, expected):
    return isinstance(actual,str) and actual in _image_reference_spellings(expected)


def _code_image_identity(image, reference):
    identity=image.get('Id')
    digests=image.get('RepoDigests')
    if (not isinstance(identity,str) or not re.fullmatch(r'sha256:[a-f0-9]{64}',identity)
            or not isinstance(digests,list) or any(not isinstance(value,str) for value in digests)
            or not any(_same_image_reference(value,reference) for value in digests) or image.get('Architecture')!='amd64'
            or image.get('Os')!='linux' or image.get('Config',{}).get('User')!='1001'
            or image.get('Config',{}).get('Entrypoint')!=_CODE_ENTRYPOINT
            or image.get('Config',{}).get('Volumes') not in (None,{})):
        raise ValueError('CODE image differs from reviewed shell-free identity')
    return identity


def collabora_default_configuration(deployment, *, require_existing=False):
    """Acquire only the image's hash-bound PUBLIC default XML, not image internals.

    Docker has no direct image-file copy API and this image has no shell. A unique
    stopped source container is created with no network, ports, volumes or process;
    remove only that verified never-started ID after successful extraction. Failure
    retains the source object/private diagnostics for explicit inspection.
    """
    from .state import atomic_json,atomic_write
    d,c=deployment,deployment.config
    d.registry._require_lock()
    selected=collabora_container_arguments(c,d.versions)
    expected=selected['configuration_sha256']
    path=d.state/'collabora-default.xml'
    if path.exists() or path.is_symlink():
        _key_file_identity(path,limit=1024**2)
        value=path.read_text()
        if hashlib.sha256(value.encode()).hexdigest()!=expected:
            raise ValueError('Retained CODE default XML changed; never overwritten')
        return value
    if require_existing:
        raise ValueError('Completed CODE default XML cache is missing; no source reconstruction during inspection')
    if (d.state/'collabora-source-failure.json').exists() or (d.state/'collabora-source-failure.json').is_symlink():
        raise ValueError('Retained CODE source failure requires explicit inspection before another extraction')
    reference=d.versions['office_runtime']['container']['reference']
    image=_guest_json(d,('docker','image','inspect',reference),optional=True)
    if image is None:
        run_native_guest(d,('docker','pull','--quiet',reference),timeout=900)
        image=_guest_json(d,('docker','image','inspect',reference))
    image_id=_code_image_identity(image,reference)
    name=c.instance+'-code-source-'+uuid.uuid4().hex[:16]
    label='org.cloud-installer.source='+expected
    created=run_native_guest(d,('docker','create','--name',name,'--network','none','--read-only',
                                 '--label',label,reference),timeout=30)
    identity=created.stdout.strip()
    if not re.fullmatch(r'[a-f0-9]{64}',identity):
        raise ValueError('Docker source creation returned no exact container ID')
    def check_source():
        value=_guest_json(d,('docker','container','inspect',identity))
        if (value.get('Id')!=identity or value.get('Name')!='/'+name or value.get('Image')!=image_id
                or not _same_image_reference(value.get('Config',{}).get('Image'),reference)
                or (value.get('Config',{}).get('Labels') or {}).get('org.cloud-installer.source')!=expected
                or value.get('HostConfig',{}).get('NetworkMode')!='none'
                or value.get('HostConfig',{}).get('ReadonlyRootfs') is not True
                or value.get('HostConfig',{}).get('Privileged') is not False
                or value.get('HostConfig',{}).get('PortBindings') not in (None,{})
                or value.get('Mounts') not in (None,[])
                or value.get('State',{}).get('Status')!='created' or value.get('State',{}).get('Running') is not False):
            raise ValueError('Transient CODE source object identity changed; no cleanup attempted')
    try:
        check_source()
        program=r'''import hashlib,json,os,stat,subprocess,sys,tempfile
from pathlib import Path
root=Path('/var/lib/cloud-installer/office');s=root.lstat()
assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o700 and root.resolve(strict=True)==root
fd,pending=tempfile.mkstemp(prefix='code-default-',suffix='.xml',dir=root);os.close(fd)
subprocess.run(__LOCAL_DOCKER__+['cp',sys.argv[1]+':/etc/coolwsd/coolwsd.xml',pending],check=True,timeout=20,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
p=Path(pending);s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and 0<s.st_size<=1048576
p.chmod(0o600);body=p.read_bytes();assert hashlib.sha256(body).hexdigest()==sys.argv[2]
print(json.dumps({'sha256':sys.argv[2],'xml':body.decode('utf-8')}))
os.unlink(p) # Only this newly created, verified public-source temporary.
'''.replace('__LOCAL_DOCKER__',repr(list(_LOCAL_DOCKER)))
        extracted=run_native_guest(d,('python3','-c',_guest_python(program),identity,expected),timeout=30)
        try:
            value=json.loads(extracted.stdout)
            if (not isinstance(value,dict) or set(value)!={'sha256','xml'} or value['sha256']!=expected
                    or not isinstance(value['xml'],str) or not 0<len(value['xml'].encode())<=1024**2
                    or hashlib.sha256(value['xml'].encode()).hexdigest()!=expected):raise ValueError
        except (ValueError,TypeError):
            raise ValueError('Pinned CODE public XML extraction mismatch') from None
        check_source()
        run_native_guest(d,('docker','container','rm',identity),timeout=30)
        atomic_write(path,value['xml'])
        return value['xml']
    except BaseException as error:
        try:
            atomic_json(d.state/'collabora-source-failure.json',{'schema_version':1,'container_id':identity,
                        'image':reference,'error_type':type(error).__name__,'source_object_may_be_retained':True})
        except Exception:
            import sys
            print('Could not save CODE source diagnostics; inspect the retained stopped source object.',file=sys.stderr)
        raise


def prepare_collabora_configuration(deployment, *, require_existing=False):
    """Stage only hash-bound public XML/CA next to the retained native proof pair.

    This does not create/start a container or activate a connector. An existing
    receipt makes missing native public files a refusal, not a silent repair.
    """
    from .state import atomic_json,private_json,config_digest
    d,c=deployment,deployment.config
    d.registry._require_lock()
    if type(require_existing) is not bool:
        raise ValueError('Invalid CODE configuration continuation policy')
    selected=collabora_container_arguments(c,d.versions)
    receipt=d.state/'collabora-configuration.json'
    exists=receipt.exists() or receipt.is_symlink()
    if require_existing and not exists:
        raise ValueError('Completed CODE configuration identity is missing; no reconstruction permitted')
    previous=None
    if exists:
        _key_file_identity(receipt,limit=4096)
        previous=private_json(receipt)
        if not isinstance(previous,dict) or type(previous.get('schema_version')) is not int:
            raise ValueError('Invalid retained CODE configuration identity')
    original=collabora_default_configuration(d,require_existing=require_existing or exists)
    xml=collabora_configuration(original,c,expected_sha256=selected['configuration_sha256'])
    ca=Path(c.ca_file).read_text() if c.ca_file else None
    if ca is not None and ('PRIVATE KEY' in ca or not 0<len(ca.encode())<=1024**2):
        raise ValueError('CODE trust input must be a bounded public CA, never a private key')
    expected={'schema_version':1,'config_sha256':config_digest(c),
              'source_sha256':selected['configuration_sha256'],'xml_sha256':hashlib.sha256(xml.encode()).hexdigest(),
              'ca_sha256':hashlib.sha256(ca.encode()).hexdigest() if ca is not None else None}
    if previous is not None and previous!=expected:
        raise ValueError('Retained CODE XML/CA selection changed; never overwritten')
    prepare_collabora_proof(d,require_existing=require_existing or exists)
    program=r'''import hashlib,json,os,stat,sys
from pathlib import Path
os.umask(0o077);existing=sys.argv[2]=='existing'
root=Path('/var/lib/cloud-installer/office/collabora');s=root.lstat()
assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o700 and root.resolve(strict=True)==root
p=root/'identity.json';s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and 0<s.st_size<=4096
assert json.loads(p.read_text())=={'schema_version':1,'config_sha256':sys.argv[1],'kind':'collabora-proof'}
data=json.load(sys.stdin);assert isinstance(data,dict) and set(data)=={'xml','ca'}
assert isinstance(data['xml'],str) and 0<len(data['xml'].encode())<=1048576
assert data['ca'] is None or isinstance(data['ca'],str) and 0<len(data['ca'].encode())<=1048576
for name,text in (('coolwsd.xml',data['xml']),('nextcloud-ca.pem',data['ca'])):
 if text is None:continue
 assert 'PRIVATE KEY' not in text
 p=root/name
 if p.exists() or p.is_symlink():
  s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o644 and s.st_size<=1048576
  assert p.read_text()==text
 else:
  assert not existing
  with p.open('x') as f:
   os.fchmod(f.fileno(),0o644);f.write(text);f.flush();os.fsync(f.fileno())
print(json.dumps({'xml_sha256':hashlib.sha256(data['xml'].encode()).hexdigest(),
 'ca_sha256':hashlib.sha256(data['ca'].encode()).hexdigest() if data['ca'] is not None else None}))
'''
    result=run_native_guest(d,('python3','-c',_guest_python(program),expected['config_sha256'],
                              'existing' if require_existing or exists else 'initial'),
                            input=json.dumps({'xml':xml,'ca':ca}),timeout=20)
    try:
        actual=json.loads(result.stdout)
        if actual!={key:expected[key] for key in ('xml_sha256','ca_sha256')}:raise ValueError
    except (ValueError,TypeError):
        raise ValueError('CODE native public configuration did not retain selected bytes') from None
    if not exists:atomic_json(receipt,expected)
    return expected


def _check_collabora_container(record, c, selected, image):
    """Inspect only the one nonroot, shell-free CODE runtime; no image edits."""
    from .state import config_digest
    config=record.get('Config',{});host=record.get('HostConfig',{})
    labels=config.get('Labels') or {}
    if (record.get('Name')!='/'+c.instance+'office' or record.get('Image')!=image['Id']
            or not _same_image_reference(config.get('Image'),selected['args'][-1]) or config.get('User')!='1001'
            or config.get('Entrypoint')!=_CODE_ENTRYPOINT or config.get('Cmd') not in (None,[])
            or labels.get('org.cloud-installer.instance')!=c.instance
            or labels.get('org.cloud-installer.config-sha256')!=config_digest(c)
            or host.get('Privileged') is not False or host.get('NetworkMode') not in ('default','bridge')
            or host.get('PortBindings')!={'9980/tcp':[{'HostIp':c.onlyoffice_ip,'HostPort':'8081'}]}
            or host.get('RestartPolicy',{}).get('Name')!='unless-stopped'
            or host.get('LogConfig')!={'Type':'json-file','Config':{'max-size':'10m','max-file':'3'}}
            or host.get('CapAdd') not in (None,[]) or host.get('SecurityOpt') not in (None,[])
            or host.get('PidMode','')!='' or host.get('UTSMode','')!=''
            or host.get('IpcMode','private')!='private' or host.get('Devices') not in (None,[])):
        raise ValueError('CODE container differs from selected ownership/image/isolation')
    env=config.get('Env') or [];expected_env=image.get('Config',{}).get('Env') or []
    if (not isinstance(env,list) or any(not isinstance(value,str) for value in env)
            or len({value.split('=',1)[0] for value in env})!=len(env) or sorted(env)!=sorted(expected_env)):
        raise ValueError('CODE container has unselected environment overrides')
    hosts=[selected['args'][i+1] for i,value in enumerate(selected['args']) if value=='--add-host']
    if (host.get('ExtraHosts') or [])!=hosts:
        raise ValueError('CODE callback hostname routing changed')
    expected={target:source for source,target in selected['binds'].items()};actual={}
    for mount in record.get('Mounts',[]):
        target=mount.get('Destination')
        if target in actual or mount.get('Type')!='bind' or mount.get('RW') is not False:
            raise ValueError('CODE mounts are duplicate, writable or unselected')
        actual[target]=mount.get('Source')
    if actual!=expected:
        raise ValueError('CODE native configuration/proof bindings changed')
    if record.get('State',{}).get('Status') not in ('created','exited','running'):
        raise ValueError('CODE runtime state requires explicit inspection; no forced restart')


def install_collabora_container(deployment, *, require_existing=False):
    """Explicit local CODE startup, not WOPI/connector/editor readiness.

    Only normal Docker commands over the existing verified guest boundary. No
    shell/image mutation, extra capability, source reselector or second service.
    """
    from .state import atomic_json,private_json
    d,c=deployment,deployment.config
    d.registry._require_lock()
    if type(require_existing) is not bool:raise ValueError('Invalid CODE continuation policy')
    selected=collabora_container_arguments(c,d.versions)
    intent=d.state/'collabora-container.json'
    exists=intent.exists() or intent.is_symlink()
    if require_existing and not exists:
        raise ValueError('Completed CODE container selection is missing; no reconstruction permitted')
    if exists:
        _key_file_identity(intent,limit=65536)
        if private_json(intent)!=selected:
            raise ValueError('Retained CODE container selection changed; no replacement permitted')
    name=c.instance+'office';reference=selected['args'][-1]
    previous=_guest_json(d,('docker','container','inspect',name),optional=not require_existing)
    if previous is not None and not exists:
        raise ValueError('Existing CODE container has no creation intent; refusing adoption')
    image=_guest_json(d,('docker','image','inspect',reference),optional=not require_existing)
    if image is None:
        run_native_guest(d,('docker','pull','--quiet',reference),timeout=900)
        image=_guest_json(d,('docker','image','inspect',reference))
    _code_image_identity(image,reference)
    if previous is not None:_check_collabora_container(previous,c,selected,image)
    if not exists:atomic_json(intent,selected)
    prepare_collabora_configuration(d,require_existing=require_existing)
    if previous is None:
        run_native_guest(d,('docker','create',*selected['args'][3:]),timeout=60)
    record=_guest_json(d,('docker','container','inspect',name))
    _check_collabora_container(record,c,selected,image)
    if record['State']['Status']!='running':run_native_guest(d,('docker','start',name),timeout=30)
    record=_guest_json(d,('docker','container','inspect',name))
    _check_collabora_container(record,c,selected,image)
    if record['State']['Status']!='running':raise RuntimeError('CODE container did not remain running')
    return {'container':name,'image':reference,'state':'running','discovery_verified':False,'editing_verified':False}


def verify_collabora_container(deployment):
    """Read-only local CODE identity/files, not discovery or editor acceptance."""
    from .state import private_json,config_digest
    d,c=deployment,deployment.config
    d.registry._require_lock()
    selected=collabora_container_arguments(c,d.versions)
    intent=d.state/'collabora-container.json';_key_file_identity(intent,limit=65536)
    if private_json(intent)!=selected:
        raise ValueError('CODE verification requires its original container selection')
    proof_path=d.state/'collabora-proof.json';config_path=d.state/'collabora-configuration.json'
    _key_file_identity(proof_path,limit=4096);_key_file_identity(config_path,limit=4096)
    proof=private_json(proof_path);configuration=private_json(config_path);digest=config_digest(c)
    if (not isinstance(proof,dict) or not isinstance(configuration,dict)
            or proof.get('config_sha256')!=digest or configuration.get('config_sha256')!=digest
            or type(proof.get('schema_version')) is not int or proof['schema_version']!=2
            or type(configuration.get('schema_version')) is not int or configuration['schema_version']!=1
            or configuration.get('source_sha256')!=selected['configuration_sha256']
            or not isinstance(proof.get('public_sha256'),str) or not re.fullmatch(r'[a-f0-9]{64}',proof['public_sha256'])
            or not isinstance(proof.get('public_key_sha256'),str) or not re.fullmatch(r'[a-f0-9]{64}',proof['public_key_sha256'])
            or not isinstance(configuration.get('xml_sha256'),str) or not re.fullmatch(r'[a-f0-9]{64}',configuration['xml_sha256'])
            or (bool(c.ca_file)!=(configuration.get('ca_sha256') is not None))
            or (configuration.get('ca_sha256') is not None and (not isinstance(configuration['ca_sha256'],str)
                or not re.fullmatch(r'[a-f0-9]{64}',configuration['ca_sha256'])))):
        raise ValueError('CODE native file identity is missing or changed')
    reference=selected['args'][-1]
    image=_guest_json(d,('docker','image','inspect',reference),read_only=True)
    _code_image_identity(image,reference)
    name=c.instance+'office'
    record=_guest_json(d,('docker','container','inspect',name),read_only=True)
    _check_collabora_container(record,c,selected,image)
    if record['State']['Status']!='running':raise ValueError('CODE container stopped; verify never starts it')
    program=r'''import hashlib,json,stat,sys
from pathlib import Path
expected=json.load(sys.stdin);root=Path('/var/lib/cloud-installer/office/collabora');s=root.lstat()
assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o700 and root.resolve(strict=True)==root
for name,uid,mode,checksum in (('coolwsd.xml',0,0o644,expected['xml_sha256']),
 ('proof_key',1001,0o600,None),('proof_key.pub',1001,0o644,expected['public_sha256']),
 ('nextcloud-ca.pem',0,0o644,expected['ca_sha256'])):
 if name=='nextcloud-ca.pem' and checksum is None:continue
 p=root/name;s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==uid and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==mode and 0<s.st_size<=1048576
 if checksum is not None:assert hashlib.sha256(p.read_bytes()).hexdigest()==checksum
print('verified-public-config-and-native-proof-metadata')
'''
    result=run_native_guest(d,('python3','-c',_guest_python(program)),input=json.dumps({
        'xml_sha256':configuration['xml_sha256'],'ca_sha256':configuration.get('ca_sha256'),'public_sha256':proof['public_sha256']}),
        timeout=15,read_only=True)
    if result.stdout.strip()!='verified-public-config-and-native-proof-metadata':
        raise ValueError('CODE native file verification did not establish its selected identity')
    return {'container':name,'image':reference,'state':'running','product_version':selected['product_version'],
            'native_files_verified':True,'discovery_verified':False,'editing_verified':False}


def _rsa_public_spki(modulus, exponent):
    """Encode public RSA parameters as SPKI DER, not a signature implementation."""
    def tlv(tag,value):
        size=len(value)
        length=bytes([size]) if size<128 else bytes([0x80+(size.bit_length()+7)//8])+size.to_bytes((size.bit_length()+7)//8,'big')
        return bytes([tag])+length+value
    def integer(value):
        raw=value.to_bytes((value.bit_length()+7)//8,'big')
        return tlv(2,(b'\0' if raw[0]&0x80 else b'')+raw)
    rsa=tlv(0x30,integer(modulus)+integer(exponent))
    algorithm=bytes.fromhex('300d06092a864886f70d0101010500')
    return tlv(0x30,algorithm+tlv(3,b'\0'+rsa))


def validate_collabora_endpoints(config, plan, discovery, capabilities, *, expected_proof_sha256=None, expected_public_key_sha256=None):
    """Pure bounded endpoint contract, not a WOPI signature/editor certification."""
    import xml.etree.ElementTree as ET
    from urllib.parse import urlsplit
    selected=collabora_container_arguments(config,plan)
    if expected_proof_sha256 is not None and (not isinstance(expected_proof_sha256,str)
            or not re.fullmatch(r'[a-f0-9]{64}',expected_proof_sha256)):
        raise ValueError('Invalid retained CODE discovery proof identity')
    if expected_public_key_sha256 is not None and (not isinstance(expected_public_key_sha256,str)
            or not re.fullmatch(r'[a-f0-9]{64}',expected_public_key_sha256)):
        raise ValueError('Invalid provisioned CODE public key identity')
    if (not isinstance(discovery,bytes) or not 0<len(discovery)<=1024**2
            or not isinstance(capabilities,bytes) or not 0<len(capabilities)<=65536
            or b'\0' in discovery or b'<!DOCTYPE' in discovery.upper() or b'<!ENTITY' in discovery.upper()):
        raise ValueError('CODE endpoint responses exceed bounds or contain unsupported XML declarations')
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:raise ValueError('Duplicate CODE capabilities key')
            result[key]=value
        return result
    try:
        root=ET.fromstring(discovery.decode('utf-8'))
        caps=json.loads(capabilities.decode('utf-8'),object_pairs_hook=unique)
        if (root.tag!='wopi-discovery' or not isinstance(caps,dict)
                or caps.get('productName')!='Collabora Online Development Edition'
                or caps.get('productVersion')!=selected['product_version']):
            raise ValueError('CODE capabilities do not identify the selected stable product')
        actions=root.findall('.//action')
        if not 0<len(actions)<=4096:raise ValueError('CODE discovery has no bounded editor action set')
        public=urlsplit(config.public_url)
        editors=0
        for action in actions:
            value=action.get('urlsrc')
            if not isinstance(value,str) or len(value)>4096 or re.search(r'[\s\\\x00-\x1f\x7f]',value):
                raise ValueError('CODE discovery contains an invalid editor URL')
            url=urlsplit(value)
            getinfo=action.get('name')=='getinfo'
            allowed_path=(url.path=='/collabora/hosting/capabilities' if getinfo
                          else url.path.startswith('/collabora/browser/'))
            if (url.scheme!='https' or url.netloc!=public.netloc or url.username or url.password or url.fragment
                    or not allowed_path or '%' in url.path
                    or '..' in PurePosixPath(url.path).parts):
                raise ValueError('CODE discovery editor authority/path differs from selected public URL')
            if action.get('name') in ('edit','editnew','view','view_comment'):editors+=1
        if not editors:raise ValueError('CODE discovery has no supported editor action')
        proofs=root.findall('proof-key')
        if len(proofs)!=1:raise ValueError('CODE discovery lacks one native proof key')
        proof=proofs[0]
        def decode(name,maximum):
            value=proof.get(name)
            if not isinstance(value,str) or not 0<len(value)<=maximum:raise ValueError('Missing/bounded CODE public proof field')
            raw=base64.b64decode(value,validate=True)
            if not raw or base64.b64encode(raw).decode()!=value:raise ValueError('Noncanonical CODE public proof field')
            return value,raw
        value,blob=decode('value',4096)
        _,modulus=decode('modulus',512)
        _,exponent=decode('exponent',16)
        if len(modulus)!=256 or int.from_bytes(modulus,'big').bit_length()!=2048 or int.from_bytes(exponent,'big')!=65537:
            raise ValueError('CODE discovery proof is not the selected RSA2048 public shape')
        # Microsoft PUBLICKEYBLOB: BLOBHEADER, RSA1 header and little-endian
        # modulus. Require that its public material agrees with the XML fields.
        import struct
        if len(blob)!=276:raise ValueError('Invalid CODE public CSP key encoding')
        kind,version,reserved,algorithm,magic,bits,pubexp=struct.unpack('<BBHIIII',blob[:20])
        if ((kind,version,reserved,magic,bits)!=(6,2,0,0x31415352,2048)
                or algorithm not in (0xA400,0x2400) or pubexp!=int.from_bytes(exponent,'big')
                or blob[20:]!=modulus[::-1]):
            raise ValueError('CODE public CSP key and XML parameters disagree')
        public_key_sha256=hashlib.sha256(_rsa_public_spki(int.from_bytes(modulus,'big'),pubexp)).hexdigest()
        if expected_public_key_sha256 is not None and public_key_sha256!=expected_public_key_sha256:
            raise ValueError('CODE discovery does not use the provisioned public key')
        fingerprint=hashlib.sha256(value.encode()).hexdigest()
        if expected_proof_sha256 is not None and fingerprint!=expected_proof_sha256:
            raise ValueError('CODE discovery proof identity changed; no key rotation inferred')
        return {'product_version':caps['productVersion'],'discovery_actions':len(actions),
                'proof_sha256':fingerprint,'public_key_sha256':public_key_sha256,
                'public_url':config.public_url+'collabora/','editing_verified':False}
    except (ET.ParseError,UnicodeError,binascii.Error,TypeError):
        raise ValueError('Malformed CODE discovery/capabilities response') from None


_BOOT_SOURCE_CHECK = r'''import hashlib,os,stat,sys,time
from pathlib import Path
try:
 root=Path(sys.argv[1]);assert root.is_absolute() and root.resolve(strict=True)==root
 s=root.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==os.geteuid() and stat.S_IMODE(s.st_mode)==0o700
 names=[];count=0;total=0
 for part in ('installer','resources'):
  base=root/part;s=base.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==os.geteuid() and not s.st_mode & 0o7022
  for parent,dirs,files in os.walk(base,followlinks=False):
   for name in dirs+files:
    p=Path(parent)/name;s=p.lstat();count+=1;assert count<=4096
    assert s.st_uid==os.geteuid() and not s.st_mode & 0o7022
    assert stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode)
    if stat.S_ISREG(s.st_mode) and '__pycache__' not in p.parts and p.suffix!='.pyc':
     assert s.st_nlink==1 and s.st_size<=16*1024**2
     total+=s.st_size;assert total<=128*1024**2;names.append(p)
 h=hashlib.sha256();actual_total=0;deadline=time.monotonic()+30
 for part in ('installer','resources'):
  for p in sorted(p for p in names if p.relative_to(root).parts[0]==part):
   h.update(p.relative_to(root).as_posix().encode()+b'\0')
   fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
   with os.fdopen(fd,'rb') as f:
    before=os.fstat(f.fileno());size=0
    assert stat.S_ISREG(before.st_mode) and before.st_uid==os.geteuid() and before.st_nlink==1 and not before.st_mode & 0o7022
    while True:
     chunk=f.read(65536)
     if not chunk:break
     size+=len(chunk);actual_total+=len(chunk)
     assert size<=16*1024**2 and actual_total<=128*1024**2 and time.monotonic()<deadline
     h.update(chunk)
    after=os.fstat(f.fileno());assert (before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
 assert h.hexdigest()==sys.argv[2]
except (AssertionError,OSError,ValueError):
 sys.exit('Office VM boot code identity refused; retain state and inspect with install.sh.')
'''


def render_vm_boot_service(config, artifact_root, *, source_sha256):
    """Pure, not installed: boot through the original verified installer worker.

    vm-bhyve1.7.5 ignores prestart's return status. Leave its vm_list empty and
    use an explicit rc command instead, after Bastille/network/VM initialization.
    Moving/removing/changing the artifact fails closed; boot does not reselect.
    """
    vm_paths(config)
    root=_absolute_path(str(artifact_root))
    if not isinstance(source_sha256,str) or not re.fullmatch(r'[a-f0-9]{64}',source_sha256):
        raise ValueError('VM rc worker requires its frozen public source identity')
    rcname='cloud_'+config.instance+'_office'
    clean='/usr/bin/env -i PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin '
    precheck=clean+shlex.join(['/usr/local/bin/python3','-I','-S','-B','-c',_BOOT_SOURCE_CHECK,root,source_sha256])
    command=clean+'/usr/local/bin/python3 -S -B -m installer.vm_boot'
    return (f'#!/bin/sh\n# PROVIDE: {rcname}\n# REQUIRE: bastille vm\n# KEYWORD: shutdown\n'
            '. /etc/rc.subr\n'
            f'name="{rcname}"\nrcvar="{rcname}_enable"\n'
            f'load_rc_config "$name"\n: ${{{rcname}_enable:=NO}}\n'
            f'start_cmd="{rcname}_start"\nstop_cmd="{rcname}_stop"\n'
            f'{rcname}_start() {{ ({precheck} && cd {shlex.quote(root)} && exec {command} start {config.instance}); }}\n'
            f'{rcname}_stop() {{ ({precheck} && cd {shlex.quote(root)} && exec {command} stop {config.instance}); }}\n'
            'run_rc_command "$1"\n')


def publish_vm_boot_service(deployment):
    """Publish a frozen public rc payload only after checked install/restart.

    Reuse only the bounded public-source allowlist/hash/copy primitives, not the
    maintenance package cache, generation graph, upgrade or export contracts.
    Publication still requires completed integration/restart/readiness phases;
    availability of the fresh-install adapter is not native acceptance evidence.
    """
    import tempfile
    from .deploy import ROOT
    from .host import read_private, write_private
    from .operations import _directories
    from .state import atomic_json, atomic_write, private_directory, private_json, config_digest
    from .maintenance_staging import _source, _stream
    d,c=deployment,deployment.config
    d.registry._require_lock()
    if c.backend not in ('eurooffice','collabora'):
        raise ValueError('Boot publication requires the implemented selected runtime')
    d.require_original_artifact()
    d.require_running_jail(c.nextcloud_jail)
    digest=config_digest(c)
    journal=private_json(d.state/'deployment.json')
    def phase(name):
        step=journal.get('steps',{}).get(name) if isinstance(journal,dict) and isinstance(journal.get('steps'),dict) else None
        return step.get('state') if isinstance(step,dict) else None
    if (not isinstance(journal,dict) or journal.get('config_sha256')!=digest
            or type(journal.get('schema_version')) is not int or journal['schema_version']!=c.schema_version
            or not isinstance(journal.get('steps'),dict)
            or phase('boot activation') not in ('running','complete')
            or any(phase(name)!='complete' for name in ('office VM restart persistence','jail restart persistence','readiness checks'))):
        raise ValueError('VM boot publication requires completed integration/restart checks')
    target=native_vm_identity(d)
    if not target['state'].startswith('Running ('):
        raise ValueError('VM boot publication requires the verified running VM')
    _vm_network_ready(d,target)
    paths=vm_paths(c)
    runtime=Path(paths['manager_root'])/'.boot'/c.instance
    service=VM_RC_DIRECTORY/('cloud_'+c.instance+'_office')
    _directories(VM_RC_DIRECTORY,owners={0,os.geteuid()})
    if VM_RC_DIRECTORY not in _vm_rc_context(d.runner):
        raise ValueError('The owned VM rc directory is not enabled by local_startup')
    specs,source_hash,_=_source(ROOT)
    saved=read_private(d.registry.evidence_path(c.instance,'source.sha256'))
    if saved!=source_hash+'\n':
        raise ValueError('Public boot payload differs from the original installer identity')
    script=render_vm_boot_service(c,runtime,source_sha256=source_hash)
    receipt=d.state/'vm-boot-service.json'
    expected=dict(schema_version=1,config_sha256=digest,source_sha256=source_hash,
                  runtime_root=str(runtime),service_path=str(service),service_sha256=hashlib.sha256(script.encode()).hexdigest())
    prior=receipt.exists() or receipt.is_symlink()
    if prior:
        _key_file_identity(receipt,limit=65536)
        if private_json(receipt)!=expected:
            raise ValueError('Owned VM boot publication identity changed')
    elif (runtime.exists() or runtime.is_symlink() or service.exists() or service.is_symlink()
          or (d.state/'allow-vm-start').exists() or (d.state/'allow-vm-start').is_symlink()):
        raise ValueError('Unreserved boot payload/service/permission exists; refusing adoption')
    if not prior:
        atomic_json(receipt,expected)
    private_directory(runtime.parent)
    private_directory(runtime)
    names={item['path'].removeprefix('source/'):item for item in specs}
    allowed_dirs={str(parent) for name in names for parent in Path(name).parents if str(parent)!='.'}
    # Refuse orphan temporaries/unknown files before filling missing members.
    for parent,dirs,files in os.walk(runtime,followlinks=False):
        for name in dirs:
            path=Path(parent)/name
            if path.relative_to(runtime).as_posix() not in allowed_dirs:
                raise ValueError('Unexpected directory in retained VM boot payload')
            private_directory(path)
        for name in files:
            path=Path(parent)/name
            relative=path.relative_to(runtime).as_posix()
            if relative not in names:
                raise ValueError('Unexpected/orphan file in retained VM boot payload')
            item=names[relative]
            if _stream(path,item['size'],private=True)!=(item['sha256'],item['size']):
                raise ValueError('Retained public VM boot source changed; never overwritten')
    for relative,item in sorted(names.items()):
        destination=runtime/relative
        for parent in reversed(destination.parent.relative_to(runtime).parents):
            if str(parent)!='.': private_directory(runtime/parent)
        if destination.parent!=runtime: private_directory(destination.parent)
        if destination.exists(): continue
        fd,pending=tempfile.mkstemp(prefix='.pending-boot-',dir=destination.parent)
        try:
            with os.fdopen(fd,'wb') as output:
                os.fchmod(output.fileno(),0o600)
                actual=_stream(ROOT/relative,item['size'],output=output)
                output.flush();os.fsync(output.fileno())
            if actual!=(item['sha256'],item['size']):
                raise ValueError('Installer source changed while freezing VM boot payload')
            os.link(pending,destination) # No replacement of a retained member.
        finally:
            if os.path.exists(pending):os.unlink(pending)
    _,copied_hash,_=_source(runtime)
    if copied_hash!=source_hash:
        raise ValueError('Frozen VM boot payload identity is incomplete or changed')
    if service.exists() or service.is_symlink():
        info=service.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1
                or stat.S_IMODE(info.st_mode)!=0o755 or service.read_text()!=script):
            raise ValueError('Retained VM rc service changed; never overwritten')
    else:
        write_private(service,script,mode=0o755)
    marker=d.state/'allow-vm-start'
    if marker.exists() or marker.is_symlink():
        if read_private(marker)!=digest+'\n':
            raise ValueError('Retained VM boot permission changed')
    else: atomic_write(marker,digest+'\n')
    d.runner.run('sysrc','cloud_'+c.instance+'_office_enable=YES')
    return expected


def disable_vm_boot_service(deployment):
    """Withdrawal never removes the frozen runtime, source evidence or rc file."""
    from .state import private_json, config_digest
    d,c=deployment,deployment.config
    d.registry._require_lock()
    path=d.state/'vm-boot-service.json'
    if not path.exists() and not path.is_symlink(): return
    value=private_json(path)
    service=VM_RC_DIRECTORY/('cloud_'+c.instance+'_office')
    if (not isinstance(value,dict) or value.get('config_sha256')!=config_digest(c)
            or value.get('service_path')!=str(service)):
        raise ValueError('VM boot-service removal identity changed')
    info=service.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1
            or info.st_mode & 0o022 or hashlib.sha256(service.read_bytes()).hexdigest()!=value.get('service_sha256')):
        raise ValueError('Owned VM boot service changed; removal refused')
    d.runner.run('sysrc','cloud_'+c.instance+'_office_enable=NO')


def _stage_native_guest_public(deployment, name, contents):
    """Stage only the two public common-bootstrap inputs; never a secret bundle."""
    targets={'runtime':'/root/cloud-installer/runtime.json',
             'bootstrap':'/root/cloud-installer/resources/vm/bootstrap.sh',
             'eurooffice':'/root/cloud-installer/eurooffice-container.json'}
    if name not in targets or not isinstance(contents,str) or len(contents.encode())>1024**2:
        raise ValueError('Unsupported common guest payload')
    target=targets[name]
    digest=hashlib.sha256(contents.encode()).hexdigest()
    script='set -eu; umask 077; '
    script+='for dir in /root/cloud-installer /root/cloud-installer/resources /root/cloud-installer/resources/vm; do '
    script+='[ ! -L "$dir" ]; if [ -e "$dir" ]; then [ -d "$dir" ] && [ "$(stat -c %u:%a "$dir")" = 0:700 ]; else mkdir -m 700 "$dir"; fi; done; '
    script+='temp=$(mktemp /root/cloud-installer/.public.XXXXXX); trap \'rm -f "$temp"\' EXIT; cat > "$temp"; '
    script+='[ "$(sha256sum "$temp" | cut -d " " -f 1)" = '+shlex.quote(digest)+' ]; '
    script+='target='+shlex.quote(target)+'; '
    script+='if [ -e "$target" ] || [ -L "$target" ]; then [ -f "$target" ] && [ ! -L "$target" ] && [ "$(sha256sum "$target" | cut -d " " -f 1)" = '+shlex.quote(digest)+' ]; '
    script+='else mv "$temp" "$target"; fi'
    return run_native_guest(deployment,('/bin/sh','-c',script),input=contents,timeout=30)


def bootstrap_native_guest(deployment):
    """Shared Alpine/OpenRC/Docker phase, with no connector/container secrets."""
    from .state import atomic_json, private_json
    from .paths import RESOURCES
    d,c=deployment,deployment.config
    d.registry._require_lock()
    wait_native_guest(d)
    configs=[config for config,status in d.registry.entries() if status['state'] not in ('removed','removing')]
    networks=sorted({str(config.network) for config in configs} | {str(c.network),str(ipaddress.IPv4Network(c.management_network,strict=False)),
                    str(ipaddress.IPv4Network(c.ingress_address+'/32')),str(ipaddress.IPv4Network(c.dns_server+'/32'))})
    branch=d.versions['office_runtime']['guest_image']['alpine_branch']
    path=d.state/'vm-runtime.json'
    if path.exists() or path.is_symlink():
        payload=private_json(path)
        if (not isinstance(payload,dict) or set(payload)!={'schema_version','alpine_branch','address','docker_network','managed_networks'}
                or type(payload['schema_version']) is not int or payload['schema_version']!=1
                or payload['alpine_branch']!=branch or payload['address']!=c.onlyoffice_ip):
            raise ValueError('Retained guest bootstrap identity changed')
        pool=ipaddress.IPv4Network(payload['docker_network'],strict=True)
        if pool.prefixlen!=24 or not any(pool.subnet_of(n) for n in PRIVATE_RANGES) or any(pool.overlaps(ipaddress.IPv4Network(n)) for n in networks):
            raise ValueError('Retained Docker network now overlaps host/managed resources; no reselection')
    else:
        payload=dict(schema_version=1,alpine_branch=branch,address=c.onlyoffice_ip,
                     docker_network=select_docker_network(networks),managed_networks=networks)
        atomic_json(path,payload)
    _stage_native_guest_public(d,'runtime',json.dumps(payload,sort_keys=True,indent=2)+'\n')
    _stage_native_guest_public(d,'bootstrap',(RESOURCES/'vm/bootstrap.sh').read_text())
    run_native_guest(d,('/bin/sh','/root/cloud-installer/resources/vm/bootstrap.sh','/root/cloud-installer/runtime.json'),timeout=600)
    checked=run_native_guest(d,('docker','network','inspect','bridge','--format','{{(index .IPAM.Config 0).Subnet}}'),timeout=15)
    if checked.stdout.strip()!=payload['docker_network']:
        raise ValueError('Running Docker bridge differs from the retained guest allocation')
    return payload


def verify_native_guest_bootstrap(deployment):
    """Wait for the existing local daemon, never rerun APK/bootstrap on replay."""
    program=r'''import hashlib,json,re,stat,subprocess,time
from pathlib import Path
root=Path('/var/lib/cloud-installer/office')
for p in (root/'docker-version.txt',root/'packages.txt',root/'daemon.json.expected',root/'bootstrap-complete.json',Path('/etc/docker/daemon.json'),Path('/root/cloud-installer/runtime.json')):
 s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and s.st_mode & 0o077==0 and 0<s.st_size<=1048576
assert (root/'daemon.json.expected').read_bytes()==Path('/etc/docker/daemon.json').read_bytes()
expected=(root/'docker-version.txt').read_text().strip();assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',expected)
done=json.loads((root/'bootstrap-complete.json').read_text());assert type(done['schema_version']) is int and done['schema_version']==1
assert done['runtime_sha256']==hashlib.sha256(Path('/root/cloud-installer/runtime.json').read_bytes()).hexdigest()
assert done['packages_sha256']==hashlib.sha256((root/'packages.txt').read_bytes()).hexdigest() and done['docker_version']==expected
assert done['daemon_sha256']==hashlib.sha256((root/'daemon.json.expected').read_bytes()).hexdigest()
live=subprocess.run(['apk','info','-v'],check=True,capture_output=True,text=True,timeout=10).stdout
assert sorted(live.splitlines())==sorted((root/'packages.txt').read_text().splitlines())
command=__LOCAL_DOCKER__+['version','--format','{{.Server.Version}}']
deadline=time.monotonic()+60
while time.monotonic()<deadline:
 r=subprocess.run(command,check=False,capture_output=True,text=True,timeout=5)
 if r.returncode==0:
  assert r.stdout.strip()==expected
  print(expected);break
 time.sleep(1)
else:raise SystemExit('Existing guest Docker daemon did not become ready')
'''.replace('__LOCAL_DOCKER__',repr(list(_LOCAL_DOCKER)))
    result=run_native_guest(deployment,('python3','-c',_guest_python(program)),timeout=75,read_only=True)
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',result.stdout.strip()):
        raise ValueError('Guest Docker bootstrap verification returned no stable version')
    return result.stdout.strip()


def _guest_json(deployment, args, *, optional=False, read_only=False):
    result=run_native_guest(deployment,args,timeout=30,check=False,read_only=read_only)
    if result.returncode:
        kind=args[1] if len(args)>=4 and args[0]=='docker' and args[2]=='inspect' and args[1] in ('container','volume','image') else None
        names=_image_reference_spellings(args[-1]) if kind=='image' else (args[-1],)
        name='(?:'+'|'.join(re.escape(value) for value in names)+')'
        pattern=(r'(?:(?:Error:|Error response from daemon:) No such '+kind+r': '+name+
                 (r'|Error response from daemon: get '+name+r': no such volume' if kind=='volume' else '')+r')\s*') if kind else r'(?!)'
        missing=re.fullmatch(pattern,getattr(result,'stderr',''))
        if optional and result.returncode==1 and result.stdout.strip() in ('','[]') and missing: return None
        raise RuntimeError('Guest Docker inspection failed; retain private diagnostics')
    try:
        value=json.loads(result.stdout)
        if not isinstance(value,list) or len(value)!=1 or not isinstance(value[0],dict): raise ValueError
        return value[0]
    except (ValueError,TypeError):
        raise ValueError('Guest Docker inspection is malformed or ambiguous') from None


def _guest_python(program):
    """Quote static worker source as one argv scalar; private data stays on stdin.

    Keep run_native_guest's control-character rejection rather than permitting
    arbitrary newlines in remote operational arguments.
    """
    if not isinstance(program,str) or not 0<len(program)<=65536 or '\0' in program:
        raise ValueError('Invalid static guest worker program')
    encoded='exec(compile('+repr(program)+', "<guest-phase>", "exec"))'
    if len(encoded)>4096:
        raise ValueError('Static guest worker exceeds the bounded argument size')
    return encoded


def _check_euro_container(record, c, plan, selected, image_id, *, image_environment=None):
    """Match native Docker inspect to the one immutable selected command."""
    from .state import config_digest
    labels=record.get('Config',{}).get('Labels') or {}
    host=record.get('HostConfig',{})
    identity=plan['office_runtime']['container']
    if (record.get('Name')!='/'+c.instance+'office' or record.get('Image')!=image_id
            or not isinstance(image_id,str) or not re.fullmatch(r'sha256:[a-f0-9]{64}',image_id)
            or record.get('Config',{}).get('Image')!=identity['reference']
            or labels.get('org.cloud-installer.instance')!=c.instance
            or labels.get('org.cloud-installer.config-sha256')!=config_digest(c)
            or host.get('Privileged') is not False or host.get('NetworkMode') not in ('default','bridge')
            or host.get('PortBindings')!={'80/tcp':[{'HostIp':c.onlyoffice_ip,'HostPort':'8081'}]}
            or host.get('RestartPolicy',{}).get('Name')!='unless-stopped'
            or host.get('LogConfig')!={'Type':'json-file','Config':{'max-size':'10m','max-file':'3'}}
            or record.get('Config',{}).get('Entrypoint')!=['/entrypoint.sh']
            or record.get('Config',{}).get('Cmd') not in (None,[])
            or record.get('Config',{}).get('User') not in (None,'','0','root')
            or host.get('CapAdd') not in (None,[]) or host.get('SecurityOpt') not in (None,[])
            or host.get('PidMode','')!='' or host.get('UTSMode','')!=''
            or host.get('IpcMode','private')!='private' or host.get('Devices') not in (None,[])):
        raise ValueError('Existing Euro-Office container differs from selected ownership/image/isolation')
    args=selected['args']
    expected_hosts=[args[i+1] for i,v in enumerate(args) if v=='--add-host']
    if (host.get('ExtraHosts') or [])!=expected_hosts:
        raise ValueError('Euro-Office callback hostname routing differs from selected private peer')
    required={args[i+1] for i,v in enumerate(args) if v=='--env'}
    env=record.get('Config',{}).get('Env')
    if (not isinstance(env,list) or any(not isinstance(value,str) for value in env) or not required.issubset(set(env))
            or any(value.startswith(('JWT_SECRET=','JWT_SECRET_INBOX=','JWT_SECRET_OUTBOX=')) for value in env)):
        raise ValueError('Euro-Office environment differs or exposes unexpected JWT configuration')
    if image_environment is not None:
        def environment(values):
            if not isinstance(values,list) or any(not isinstance(v,str) or '=' not in v for v in values):
                raise ValueError('Malformed image/container environment')
            pairs=[v.split('=',1) for v in values]
            if len({key for key,value in pairs})!=len(pairs):
                raise ValueError('Duplicate container environment keys')
            return dict(pairs)
        expected_env=environment(image_environment)
        expected_env.update(environment(list(required)))
        if environment(env)!=expected_env:
            raise ValueError('Euro-Office environment overrides unselected image defaults')
    expected={dest:('volume',name,True) for name,dest in selected['volumes'].items()}
    expected.update({dest:('bind',source,True) for source,dest in selected['binds'].items()})
    if c.ca_file:
        expected['/etc/euro-office/nextcloud-ca.pem']=('bind','/var/lib/cloud-installer/office/nextcloud-ca.pem',False)
    actual={}
    for mount in record.get('Mounts',[]):
        dest=mount.get('Destination')
        if dest in actual: raise ValueError('Duplicate Euro-Office container mount')
        actual[dest]=(mount.get('Type'),mount.get('Name') if mount.get('Type')=='volume' else mount.get('Source'),mount.get('RW'))
    if actual!=expected:
        raise ValueError('Euro-Office persistent mounts differ from selected owned volumes')
    if record.get('State',{}).get('Status') not in ('created','exited','running'):
        raise ValueError('Euro-Office runtime state requires explicit inspection, not forced restart')


def install_eurooffice_container(deployment, *, require_existing=False):
    """One explicit guest container, no upgrades/replacement or Docker framework.

    Existing host Journal/lock and pinned guest execution own this phase. Failed
    containers/volumes are retained. Running state is not health, connector,
    runtime-version or editor acceptance; the public VM install gate remains shut.
    """
    from .state import atomic_json, private_json, config_digest
    d,c=deployment,deployment.config
    d.registry._require_lock()
    if type(require_existing) is not bool: raise ValueError('Invalid container continuation policy')
    selected=eurooffice_container_arguments(c,d.versions)
    secret=d.secrets.get('jwt_secret')
    if not isinstance(secret,str) or not re.fullmatch(r'[a-fA-F0-9]{64}',secret):
        raise ValueError('Retained Euro-Office JWT is missing or invalid')
    intent=d.state/'eurooffice-container.json'
    existed=intent.exists() or intent.is_symlink()
    if require_existing and not existed:
        raise ValueError('Completed container phase lost its creation intent; no reconstruction permitted')
    if existed and private_json(intent)!=selected:
        raise ValueError('Retained Euro-Office container selection changed; no replacement permitted')
    name=c.instance+'office'
    previous=_guest_json(d,('docker','container','inspect',name),optional=not require_existing)
    if previous is not None and not existed:
        raise ValueError('Existing container has no installer creation intent; refusing adoption')
    if previous is not None:
        _check_euro_container(previous,c,d.versions,selected,previous.get('Image'))
    volumes={}
    labels={'org.cloud-installer.instance':c.instance,'org.cloud-installer.config-sha256':config_digest(c)}
    for volume in selected['volumes']:
        value=_guest_json(d,('docker','volume','inspect',volume),optional=not require_existing)
        if value is not None and (not existed or value.get('Name')!=volume or value.get('Driver')!='local'
                                  or value.get('Labels')!=labels or value.get('Options') not in (None,{})):
            raise ValueError('Foreign or changed Euro-Office volume; refusing adoption')
        volumes[volume]=value
    if not existed: atomic_json(intent,selected)
    _stage_native_guest_public(d,'eurooffice',json.dumps(selected,sort_keys=True,indent=2)+'\n')
    # No JWT in argv, inherited command environments or Docker inspect. The image
    # reads this root-only native file under the retained Data volume on startup.
    prepare=r'''import json,os,re,stat,sys
from pathlib import Path
os.umask(0o077)
existing=len(sys.argv)>1 and sys.argv[1]=='existing'
v=json.load(sys.stdin)
assert isinstance(v,dict) and set(v)=={'jwt_secret'} and isinstance(v['jwt_secret'],str) and re.fullmatch(r'[a-fA-F0-9]{64}',v['jwt_secret'])
base=Path('/var/lib/cloud-installer/office')
for p in (base,base/'volumes',base/'volumes/data',base/'volumes/data/.private'):
 if p.exists() or p.is_symlink():
  s=p.lstat();assert stat.S_ISDIR(s.st_mode) and p.resolve(strict=True)==p
  if p!=base/'volumes/data': assert s.st_uid==0 and s.st_mode & 0o077==0
 else:
  assert not existing
  p.mkdir(mode=0o700)
p=base/'volumes/data/.private/jwt_secret'
if p.exists() or p.is_symlink():
 s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and s.st_mode & 0o077==0
 assert p.read_text()==v['jwt_secret']
else:
 assert not existing
 with p.open('x') as f:
  f.write(v['jwt_secret']);f.flush();os.fsync(f.fileno())
'''
    run_native_guest(d,('python3','-c',_guest_python(prepare),'existing' if require_existing else 'initial'),input=json.dumps({'jwt_secret':secret}),timeout=15)
    if c.ca_file:
        ca=Path(c.ca_file).read_text()
        if 'PRIVATE KEY' in ca:
            raise ValueError('Guest CA trust input must not contain a private key')
        stage_ca=r'''import os,stat,sys
from pathlib import Path
os.umask(0o077);existing=sys.argv[1]=='existing';data=sys.stdin.read(1048577);assert 0<len(data)<=1048576
p=Path('/var/lib/cloud-installer/office/nextcloud-ca.pem')
if p.exists() or p.is_symlink():
 s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o644 and p.read_text()==data
else:
 assert not existing
 with p.open('x') as f:
  os.fchmod(f.fileno(),0o644);f.write(data);f.flush();os.fsync(f.fileno())
'''
        run_native_guest(d,('python3','-c',_guest_python(stage_ca),'existing' if require_existing else 'initial'),input=ca,timeout=15)
    reference=d.versions['office_runtime']['container']['reference']
    image=_guest_json(d,('docker','image','inspect',reference),optional=not require_existing)
    if image is None:
        run_native_guest(d,('docker','pull','--quiet',reference),timeout=900)
        image=_guest_json(d,('docker','image','inspect',reference))
    image_id=image.get('Id')
    if (not isinstance(image_id,str) or not re.fullmatch(r'sha256:[a-f0-9]{64}',image_id)
            or reference not in image.get('RepoDigests',[]) or image.get('Architecture')!='amd64'
            or image.get('Os')!='linux' or image.get('Config',{}).get('Entrypoint')!=['/entrypoint.sh']):
        raise ValueError('Pulled Euro-Office image does not match the locked standalone image')
    for volume,value in volumes.items():
        if value is None:
            run_native_guest(d,('docker','volume','create','--label','org.cloud-installer.instance='+c.instance,
                               '--label','org.cloud-installer.config-sha256='+config_digest(c),volume),timeout=30)
            created=_guest_json(d,('docker','volume','inspect',volume))
            if (created.get('Name')!=volume or created.get('Driver')!='local'
                    or created.get('Labels')!=labels or created.get('Options') not in (None,{})):
                raise ValueError('Docker volume creation did not preserve selected ownership')
    if previous is None:
        run_native_guest(d,('docker','create',*selected['args'][3:]),timeout=60)
    # Verify the image's actual script before allowing its first start. Retain the
    # copied public script privately as source evidence, not an executed worker.
    hash_script=r'''import hashlib,os,stat,subprocess,sys,tempfile
from pathlib import Path
root=Path('/var/lib/cloud-installer/office')
fd,pending=tempfile.mkstemp(prefix='entrypoint-check-',dir=root);os.close(fd)
subprocess.run(__LOCAL_DOCKER__+['cp',sys.argv[1]+':/entrypoint.sh',pending],check=True,timeout=20,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
p=Path(pending);s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and 0<s.st_size<=65536
p.chmod(0o600);digest=hashlib.sha256(p.read_bytes()).hexdigest()
if digest==sys.argv[2]:
 proof=root/'eurooffice-image-entrypoint.sh'
 if not os.path.lexists(proof):os.link(p,proof)
 else:
  s=proof.lstat();assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and s.st_mode & 0o077==0 and hashlib.sha256(proof.read_bytes()).hexdigest()==digest
 os.unlink(p) # Only the new verified temporary copy, never retained data/evidence.
print(digest)
'''.replace('__LOCAL_DOCKER__',repr(list(_LOCAL_DOCKER)))
    checked=run_native_guest(d,('python3','-c',_guest_python(hash_script),name,selected['entrypoint_sha256']),timeout=30)
    if checked.stdout.strip()!=selected['entrypoint_sha256']:
        raise ValueError('Euro-Office entrypoint differs from reviewed source; no start or replacement attempted')
    record=_guest_json(d,('docker','container','inspect',name))
    _check_euro_container(record,c,d.versions,selected,image_id,image_environment=image.get('Config',{}).get('Env',[]))
    if record['State']['Status']!='running':
        run_native_guest(d,('docker','start',name),timeout=30)
    record=_guest_json(d,('docker','container','inspect',name))
    _check_euro_container(record,c,d.versions,selected,image_id,image_environment=image.get('Config',{}).get('Env',[]))
    if record['State']['Status']!='running': raise RuntimeError('Euro-Office container did not remain running')
    return {'container':name,'image':reference,'state':'running','health_verified':False,'editing_verified':False}


def verify_eurooffice_container(deployment):
    """Read-only selected runtime checks: no pull/create/start/config/trust repair."""
    from .state import private_json, config_digest
    d,c=deployment,deployment.config
    d.registry._require_lock()
    selected=eurooffice_container_arguments(c,d.versions)
    intent=d.state/'eurooffice-container.json'
    _key_file_identity(intent,limit=65536)
    if private_json(intent)!=selected:
        raise ValueError('Euro-Office verification requires the original container selection')
    reference=d.versions['office_runtime']['container']['reference']
    image=_guest_json(d,('docker','image','inspect',reference),read_only=True)
    image_id=image.get('Id')
    if (reference not in image.get('RepoDigests',[]) or image.get('Architecture')!='amd64'
            or image.get('Os')!='linux' or image.get('Config',{}).get('Entrypoint')!=['/entrypoint.sh']):
        raise ValueError('Retained Euro-Office image identity differs; verify never pulls/replaces it')
    name=c.instance+'office'
    record=_guest_json(d,('docker','container','inspect',name),read_only=True)
    _check_euro_container(record,c,d.versions,selected,image_id,image_environment=image.get('Config',{}).get('Env',[]))
    if record['State']['Status']!='running':
        raise ValueError('Euro-Office container is not running; verify never starts it')
    for volume in selected['volumes']:
        value=_guest_json(d,('docker','volume','inspect',volume),read_only=True)
        labels={'org.cloud-installer.instance':c.instance,'org.cloud-installer.config-sha256':config_digest(c)}
        if (value.get('Name')!=volume or value.get('Driver')!='local' or value.get('Labels')!=labels
                or value.get('Options') not in (None,{})):
            raise ValueError('Euro-Office volume ownership changed; verification never adopts it')
    result=run_native_guest(d,('docker','exec',name,'sha256sum','/entrypoint.sh'),timeout=15,read_only=True)
    fields=result.stdout.split()
    if fields!=[selected['entrypoint_sha256'],'/entrypoint.sh']:
        raise ValueError('Running Euro-Office entrypoint differs from its selected source')
    return {'container':name,'image':reference,'state':'running','entrypoint_sha256':selected['entrypoint_sha256']}
