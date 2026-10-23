"""PF transition supervisor and isolated network worker, including repeat changes.

Only the worker holds mutation/commit locks. The detached supervisor owns that
child and its separate process group, kills/reaps it before rollback, and never
depends on the interactive installer releasing a lock. No application data is
rolled back or deleted. This module is copied into the private transaction state
so recovery does not depend on the checkout remaining accessible.
"""

import fcntl
import ipaddress
from contextlib import contextmanager
import json
import math
import os
from pathlib import Path
import select
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid


SYSCTL_FILE = Path("/etc/sysctl.conf")
BRIDGE_SYSCTLS = frozenset(("net.link.bridge.pfil_member", "net.link.bridge.pfil_bridge",
                           "net.link.bridge.pfil_local_phys", "net.link.bridge.pfil_onlyip"))
SYSCTL_BEGIN = "# Nextcloud installer: filter routed VNET jail segments on their private bridges."
SYSCTL_END = "# End cloud-installer bridge sysctls."
PF_SNAPSHOTS = (("filter", ("-sr",)), ("nat", ("-sn",)),
                ("jails", ("-t", "cloud_jails", "-T", "show")),
                ("noninternet", ("-t", "cloud_noninternet", "-T", "show")))


def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def exclusive_file(path, contents):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "w") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        fsync_directory(Path(path).parent)
    except BaseException:
        # A failed write/fsync must not leave a success marker for the supervisor.
        Path(path).unlink()
        fsync_directory(Path(path).parent)
        raise


def replace_file(path, contents, *, validate=None, mode=0o600):
    """Validate a private same-filesystem candidate before an atomic replacement."""
    path = Path(path)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    candidate = Path(name)
    try:
        with os.fdopen(descriptor, "w") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        if validate is not None:
            validate(candidate)
        os.replace(candidate, path)
        fsync_directory(path.parent)
    finally:
        candidate.unlink(missing_ok=True)


def replace_link(path, destination):
    path = Path(path)
    candidate = path.with_name(f".{path.name}.{uuid.uuid4().hex}")
    os.symlink(str(destination), candidate)
    try:
        os.replace(candidate, path)
        fsync_directory(path.parent)
    finally:
        candidate.unlink(missing_ok=True)


def active_pointer(state, settings, *, restore=False):
    """Change only the expected shared pointer; never unlink a foreign target."""
    if "active_link" not in settings:
        return  # Fresh-host transactions written by the original installer.
    path = Path(settings["active_link"])
    previous = settings.get("previous_active")
    own = str(Path(state).absolute())
    if not path.is_absolute() or (previous is not None and
            (not Path(previous).is_absolute() or previous == own
             or not (Path(previous) / "firewall-confirmed").is_file())):
        raise RuntimeError("Invalid active network pointer or previous committed transaction")
    try:
        current = os.readlink(path)
    except FileNotFoundError:
        current = None
    except OSError as error:
        raise RuntimeError("The active network pointer is not a symbolic link") from error
    if current is not None and not Path(current).is_absolute():
        raise RuntimeError("The active network pointer must have an absolute destination")
    if restore:
        if current == previous:
            fsync_directory(path.parent)
            return
        if current != own:
            raise RuntimeError("The active network pointer changed outside this transaction")
        if previous is None:
            path.unlink()
            fsync_directory(path.parent)
        else:
            replace_link(path, previous)
    else:
        if current != previous:
            raise RuntimeError("The active network pointer changed outside this transaction")
        replace_link(path, own)


def bridge_sysctl_config(contents, values, previous):
    """Replace only our validated bridge entries, retaining unrelated settings.

    The original installer used the same beginning comment without an end
    marker; its consecutive bridge assignments are also recognized. A foreign
    assignment of the same key is refused, even if its value happens to match.
    """
    if any(name not in BRIDGE_SYSCTLS or str(value) not in ("0", "1")
           for name, value in values.items()):
        raise RuntimeError("Invalid managed bridge sysctl setting")
    lines = []
    managed = False
    for line in contents.splitlines(keepends=True):
        if line.strip() == SYSCTL_BEGIN:
            managed = True
            continue
        if line.strip() == SYSCTL_END:
            managed = False
            continue
        name, separator, value = line.split("#", 1)[0].strip().partition("=")
        name, value = name.strip(), value.strip()
        if separator and name in values:
            if not managed or value != str(previous.get(name, values[name])):
                raise RuntimeError(f"Refusing foreign or changed persistent bridge sysctl: {name}")
            continue
        if line.strip():
            managed = False
        lines.append(line)
    body = "".join(lines).rstrip("\n")
    block = "\n".join(f"{name}={value}" for name, value in values.items())
    return (body + "\n\n" if body else "") + f"{SYSCTL_BEGIN}\n{block}\n{SYSCTL_END}\n"


def require_pending(state):
    settings = json.loads((state / "firewall-transition.json").read_text())
    if ((state / "firewall-rolled-back").exists() or (state / "firewall-confirmed").exists()
            or time.monotonic() >= settings["deadline"]):
        raise RuntimeError("The firewall transition is no longer pending; no further network mutations are allowed")


def _private_info(path, info, *, directory=False):
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (not expected_type(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o077 or (not directory and info.st_nlink != 1)):
        raise ValueError(f"Unsafe private network state: {path}")


def _private_path(path, *, directory=False, optional=False):
    try:
        info = path.lstat()
    except FileNotFoundError:
        if optional:
            return False
        raise
    _private_info(path, info, directory=directory)
    return True


def _transaction_files(state):
    _private_path(state, directory=True)
    names = set()
    for path in state.iterdir():
        _private_path(path)
        names.add(path.name)
    return names


def _private_text(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, encoding="utf-8", newline="") as stream:
        _private_info(path, os.fstat(stream.fileno()))
        return stream.read()


def _previous_policy(state, settings):
    """Bind recovery input and expected live policy to the previous commit."""
    previous = settings.get("previous_active")
    state = Path(state).absolute()
    if not isinstance(previous, str) or not Path(previous).is_absolute():
        raise ValueError("Previous managed PF requires its committed transaction; manual recovery is required")
    previous = Path(previous)
    if state.parent.name != "transactions" or previous.parent != state.parent or previous == state:
        raise ValueError("Previous PF transaction is outside this registry")
    for directory in (state.parent.parent, state.parent, state, previous):
        _private_path(directory, directory=True)
    _private_path(previous / "firewall-confirmed")
    if _private_path(previous / "firewall-rolled-back", optional=True):
        raise ValueError("Previous PF transaction was rolled back")
    committed = json.loads(_private_text(previous / "firewall-transition.json"))
    network = committed.get("network") if isinstance(committed, dict) else None
    rules = network.get("pf_rules") if isinstance(network, dict) else None
    if not isinstance(rules, str) or not rules.strip():
        raise ValueError("Previous committed PF policy is missing or empty")
    source = settings.get("previous_pf_file")
    if not isinstance(source, str) or not Path(source).is_absolute():
        raise ValueError("Missing private copy of the previous PF policy")
    if _private_text(Path(source)) != rules:
        raise ValueError("Previous PF copy differs from the committed policy; manual recovery is required")
    expected = {name: _private_text(previous / f"pf-{name}.expected") for name, _ in PF_SNAPSHOTS}
    return rules, expected


def pending_transactions(root):
    """Return name-sorted unresolved transaction Paths without creating state.

    All existing registry/transaction directories and their direct files must
    be private and owned by the caller (root on the host). Pre-arm diagnostic
    directories without a transition JSON are retained but do not block work.
    Call while holding the host operation lock before allowing a new operation.
    """
    root = Path(root).absolute()
    if not _private_path(root, directory=True, optional=True):
        return ()
    directory = root / "transactions"
    if not _private_path(directory, directory=True, optional=True):
        return ()
    pending = []
    for state in sorted(directory.iterdir()):
        files = _transaction_files(state)
        if ("firewall-transition.json" in files
                and not files.intersection(("firewall-confirmed", "firewall-rolled-back"))):
            pending.append(state)
    return tuple(pending)


def _recovery_settings(state):
    path = state / "firewall-transition.json"
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor) as stream:
        _private_info(path, os.fstat(stream.fileno()))
        settings = json.load(stream)
    required = {"deadline", "boot_identity", "forwarding", "bridge_sysctls", "bridges", "backups",
                "previous_pf_enabled", "previous_pf_file", "active_link", "previous_active", "network"}
    if not isinstance(settings, dict) or not required.issubset(settings):
        raise ValueError("Incomplete or legacy network transaction; manual recovery is required")
    deadline = settings["deadline"]
    if (type(deadline) not in (int, float) or deadline < 0
            or (type(deadline) is float and not math.isfinite(deadline))):
        raise ValueError("Invalid network recovery deadline; manual recovery is required")
    network = settings["network"]
    if (not isinstance(network, dict)
            or not {"bridge_addresses", "bridge_sysctls", "pf_file", "pf_rules"}.issubset(network)):
        raise ValueError("Incomplete network recovery policy; manual recovery is required")
    def absolute(value):
        return isinstance(value, str) and Path(value).is_absolute()
    if (type(settings["previous_pf_enabled"]) is not bool
            or not absolute(network["pf_file"]) or not absolute(settings["active_link"])
            or (settings["previous_active"] is not None and not absolute(settings["previous_active"]))
            or not isinstance(network["pf_rules"], str)):
        raise ValueError("Invalid previous network policy or active pointer; manual recovery is required")
    if str(settings["forwarding"]) not in ("0", "1"):
        raise ValueError("Invalid saved forwarding setting")
    for values in (settings["bridge_sysctls"], network["bridge_sysctls"]):
        if (not isinstance(values, dict) or any(name not in BRIDGE_SYSCTLS or str(value) not in ("0", "1")
                                               for name, value in values.items())):
            raise ValueError("Invalid saved bridge sysctls")
    bridges = settings["bridges"]
    if (not isinstance(bridges, list)
            or any(not isinstance(name, str) or not name.startswith("bridge") or not name[6:].isdigit() for name in bridges)
            or not isinstance(network["bridge_addresses"], dict)
            or len(bridges) != len(set(bridges))
            or set(bridges) != set(network["bridge_addresses"])):
        raise ValueError("Invalid owned bridge recovery list")
    try:
        if any(not isinstance(value, str) or str(ipaddress.IPv4Address(value)) != value
               for value in network["bridge_addresses"].values()):
            raise ValueError
    except ValueError:
        raise ValueError("Invalid owned bridge IPv4 recovery addresses") from None
    backups = settings["backups"]
    if not isinstance(backups, dict) or network["pf_file"] not in backups:
        raise ValueError("Missing managed PF file backup entry")
    for target, backup in backups.items():
        if not absolute(target) or (backup is not None and
                (not isinstance(backup, str) or not backup or Path(backup).name != backup or backup in (".", ".."))):
            raise ValueError("Invalid network recovery backup path")
        if backup is not None:
            _private_path(state / backup)
    previous_pf = settings["previous_pf_file"]
    if settings["previous_pf_enabled"]:
        backup = backups[network["pf_file"]]
        if not backup or not absolute(previous_pf) or Path(previous_pf) != state / backup:
            raise ValueError("Missing private copy of the previous PF policy; manual recovery is required")
        _previous_policy(state, settings)
    elif previous_pf is not None:
        raise ValueError("Unexpected previous PF policy for a fresh-host transaction")
    active = Path(settings["active_link"])
    _private_path(active.parent, directory=True)
    previous_active = settings["previous_active"]
    if previous_active is not None:
        _private_path(Path(previous_active), directory=True)
        _private_path(Path(previous_active) / "firewall-confirmed")
    try:
        current = os.readlink(active)
    except FileNotFoundError:
        current = None
    if current not in (previous_active, str(state)):
        # Refuse stale/out-of-order recovery before changing live PF, not only
        # when trying to restore the shared readiness pointer afterwards.
        raise ValueError("Active network pointer changed outside this transaction; manual recovery is required")
    return settings


def _require_recoverable(settings, current_boot):
    saved_boot = settings["boot_identity"]
    if (not isinstance(saved_boot, str) or not saved_boot.strip()
            or not isinstance(current_boot, str) or not current_boot.strip()):
        raise ValueError("Saved and current boot identities are required; manual recovery is required")
    if saved_boot.strip() == current_boot.strip() and time.monotonic() < settings["deadline"]:
        raise RuntimeError("Network transaction is still pending on this boot; recovery requires its deadline to expire")


def _load_recovery_modules():
    for module in ("pf", "if_bridge"):
        try:
            present = subprocess.run(["/sbin/kldstat", "-q", "-m", module], check=False,
                                     text=True, capture_output=True, timeout=30)
            if present.returncode:
                subprocess.run(["/sbin/kldload", module], check=True,
                               text=True, capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError) as error:
            raise RuntimeError(f"Network recovery could not prepare module {module}; no policy rollback was attempted: {error}") from None


def recover_pending(state, current_boot):
    """Explicit RECOVER-only rollback; the caller must hold the host operation lock.

    A different boot permits immediate recovery. On the same boot the saved
    monotonic deadline must have expired. Never wait for a lock, poll liveness,
    or signal a process: a surviving supervisor alone owns its worker group.
    Return None on recovery or an already-resolved transaction; errors leave
    pending state blocking subsequent operations.
    """
    state = Path(state).absolute()
    if state.parent.name != "transactions":
        raise ValueError("Expected a private registry transactions/<id> directory")
    _private_path(state.parent.parent, directory=True)
    _private_path(state.parent, directory=True)
    files = _transaction_files(state)
    if files.intersection(("firewall-confirmed", "firewall-rolled-back")):
        return
    _require_recoverable(_recovery_settings(state), current_boot)
    path = state / "firewall.lock"
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(descriptor, "r+") as lock:
        _private_info(path, os.fstat(lock.fileno()))
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Network transaction is still active or recovering; recovery lock is busy") from None
        # Recheck after obtaining the lock: the detached supervisor may have
        # completed between discovery and our nonblocking acquisition.
        files = _transaction_files(state)
        if files.intersection(("firewall-confirmed", "firewall-rolled-back")):
            return
        settings = _recovery_settings(state)
        _require_recoverable(settings, current_boot)
        _load_recovery_modules()
        _rollback_locked(state, settings)


@contextmanager
def mutation(state):
    """Serialize *all* applying mutations with rollback, not merely commit.

    Only the supervised worker may hold this lock in production. It releases the
    lock before waiting for confirmation. Its supervisor can kill even a stopped
    worker and its command descendants before acquiring this lock for rollback.
    """
    state = Path(state)
    with (state / "firewall.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        require_pending(state)
        yield lambda: require_pending(state)


def rollback(state):
    state = Path(state)
    with (state / "firewall.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        _rollback_locked(state)


def _withdraw_new_bridge_addresses(settings):
    """Restore PF's host-address context without destroying an unverified bridge.

    FreeBSD expands ``self`` when loading PF. A new bridge's address would change
    the previous policy's snapshots even with identical policy bytes. Inspect ALL
    newly-created bridges first, then withdraw only their exact recorded IPv4
    addresses. Foreign addresses/members refuse recovery; existing bridges never
    occur in this transaction-owned list. Empty/absent bridges permit retry.
    """
    bridges = settings["bridges"]
    if not bridges:
        return
    addresses = settings["network"]["bridge_addresses"]
    if set(bridges) != set(addresses):
        raise RuntimeError("New bridge address inventory changed")
    for bridge in bridges:
        address = addresses[bridge]
        if (not isinstance(bridge, str) or not bridge.startswith("bridge") or not bridge[6:].isdigit()
                or not isinstance(address, str) or str(ipaddress.IPv4Address(address)) != address):
            raise RuntimeError("Invalid new bridge address identity")
    interfaces = subprocess.run(("/sbin/ifconfig", "-l"), check=True, timeout=30,
                               text=True, capture_output=True).stdout.split()
    if not interfaces or len(interfaces) != len(set(interfaces)):
        raise RuntimeError("Cannot establish host interface inventory for network recovery")
    withdraw = []
    for bridge in bridges:
        if bridge not in interfaces:
            continue
        result = subprocess.run(("/sbin/ifconfig", bridge), check=True, timeout=30,
                                text=True, capture_output=True)
        rows = [line.split() for line in result.stdout.splitlines()]
        if not rows or not rows[0] or rows[0][0] != bridge + ":":
            raise RuntimeError("Cannot establish new bridge identity")
        actual = [row[1] for row in rows if len(row) > 1 and row[0] == "inet"]
        if (any(row[0] == "member:" for row in rows if row)
                or actual not in ([], [addresses[bridge]])):
            raise RuntimeError("New bridge has foreign members or IPv4 addresses; recovery refused")
        if actual:
            withdraw.append((bridge, actual[0]))
    for bridge, address in withdraw:
        subprocess.run(("/sbin/ifconfig", bridge, "inet", address, "-alias"), check=True,
                       timeout=30, stdout=sys.stderr)


def _rollback_locked(state, settings=None):
    """Caller owns firewall.lock, including throughout the final durable marker."""
    if (state / "firewall-confirmed").exists() or (state / "firewall-rolled-back").exists():
        return
    if settings is None:
        settings = json.loads((state / "firewall-transition.json").read_text())
    errors = []
    def run(*args):
        try:
            # Supervisor stdout is the caller's IPC pipe, which can be closed
            # during rollback. Send command output to its private diagnostic
            # stream, not a disconnected terminal/control channel (SIGPIPE).
            subprocess.run(args, check=True, timeout=30, stdout=sys.stderr)
            return True
        except (OSError, subprocess.SubprocessError) as error:
            errors.append(str(error))
            return False
    def exists(*args):
        try:
            return subprocess.run(list(args), stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, timeout=30, check=False).returncode == 0
        except (OSError, subprocess.SubprocessError) as error:
            errors.append(str(error))
            return False
    previous_enabled = settings.get("previous_pf_enabled", False)
    pf_file = settings.get("network", {}).get("pf_file")
    if previous_enabled:
        previous_pf = settings.get("previous_pf_file")
        try:
            if not previous_pf or not Path(previous_pf).is_absolute() or not pf_file:
                raise RuntimeError("Missing private copy of the previous PF policy")
            rules, expected = _previous_policy(state, settings)
            if not run("/sbin/pfctl", "-nf", previous_pf):
                raise RuntimeError("Previous PF policy validation failed")
            _withdraw_new_bridge_addresses(settings)
            replace_file(pf_file, rules)
            if not run("/sbin/pfctl", "-f", previous_pf):
                raise RuntimeError("Previous PF policy reload failed")
            if not run("/sbin/pfctl", "-s", "Running"):
                raise RuntimeError("Previously enabled PF is no longer running")
            for name, args in PF_SNAPSHOTS:
                actual = subprocess.run(("/sbin/pfctl", *args), check=True, timeout=30,
                                        text=True, capture_output=True).stdout
                if actual.rstrip("\n") != expected[name].rstrip("\n"):
                    raise RuntimeError(f"Restored PF {name} snapshot differs from the previous committed policy")
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            errors.append(f"{error}; existing PF was NOT disabled or flushed")
            # Do not destroy bridges or publish previous readiness unless the
            # reloaded live policy has actually matched the committed snapshots.
            raise RuntimeError("Network rollback needs manual attention: " + "; ".join(errors)) from None
        run("/sbin/sysctl", f"net.inet.ip.forwarding={settings['forwarding']}")
    else:
        run("/sbin/sysctl", f"net.inet.ip.forwarding={settings['forwarding']}")
        if exists("/sbin/pfctl", "-s", "Running"):
            run("/sbin/pfctl", "-d")
        # Fresh-host preflight proved that rules, anchors and states were empty.
        # Disabling PF alone leaves our unconfirmed rules/states behind and would
        # make a safe Resume look like adoption of a foreign disabled policy.
        run("/sbin/pfctl", "-f", "/dev/null")
        run("/sbin/pfctl", "-F", "states")
    for name, value in settings["bridge_sysctls"].items():
        run("/sbin/sysctl", f"{name}={value}")
    for target, backup in settings["backups"].items():
        if previous_enabled and target == pf_file:
            continue  # Restored only after validating the private PF copy.
        # All paths are fixed by the parent, not supplied by a jail. An
        # originally absent file is left empty rather than deleted.
        try:
            path = Path(target)
            mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
            replace_file(path, (state / backup).read_text() if backup else "", mode=mode)
        except OSError as error:
            errors.append(str(error))
    for bridge in settings["bridges"]:
        if exists("/sbin/ifconfig", bridge):
            run("/sbin/ifconfig", bridge, "destroy")
    try:
        active_pointer(state, settings, restore=True)
    except (OSError, RuntimeError) as error:
        errors.append(str(error))
    if errors:
        raise RuntimeError("Network rollback needs manual attention: " + "; ".join(errors))
    exclusive_file(state / "firewall-rolled-back", "Unconfirmed PF/network configuration rolled back.\n")


def arm(state):
    state = Path(state)
    exclusive_file(state / "firewall.lock", "")
    script = state / "firewall-watchdog.py"
    exclusive_file(script, Path(__file__).read_text())
    descriptor = os.open(state / "firewall-rollback.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as log:
        process = subprocess.Popen([sys.executable, str(script), "supervise", str(state)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=log, text=True, start_new_session=True)
    return Controller(state, process)


def read_message(stream, deadline, *, abort=None):
    """Read a tiny private IPC line without an unbounded readline on partial input."""
    message = bytearray()
    while len(message) < 64:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Firewall transition confirmation deadline expired")
        descriptors = [stream] if abort is None else [stream, abort]
        ready, _, _ = select.select(descriptors, [], [], remaining)
        if not ready:
            raise TimeoutError("Firewall transition confirmation deadline expired")
        if abort is not None and abort in ready:
            raise RuntimeError("The installer disconnected or cancelled during network mutation")
        char = os.read(stream.fileno(), 1)
        if not char:
            raise RuntimeError("Firewall transaction channel closed before completion")
        if char == b"\n":
            return message.decode("ascii")
        message.extend(char)
    raise RuntimeError("Invalid firewall transaction message")


def send_message(stream, message):
    stream.write(message + "\n")
    stream.flush()


def close_pipe(stream):
    # Buffered stdin may still contain KEEP after a failed flush. Closing it
    # can raise EPIPE again; a cleanup error must never bypass network rollback.
    try:
        stream.close()
    except OSError:
        pass


def notify_final(stream, message):
    """Best-effort notification only after a durable commit/rollback marker.

    Losing the caller must not turn a completed recovery into a noisy secondary
    failure; close the buffered pipe too so interpreter shutdown cannot reflush.
    Application/confirmation messages still use strict send_message semantics.
    """
    try:
        send_message(stream, message)
    except (BrokenPipeError, ConnectionResetError):
        close_pipe(stream)


class Controller:
    """Interactive caller handle. It never mutates PF or acquires its lock."""

    def __init__(self, state, process):
        self.state = Path(state)
        self.process = process
        self.deadline = json.loads((self.state / "firewall-transition.json").read_text())["deadline"]

    def wait_applied(self):
        if read_message(self.process.stdout, self.deadline) != "APPLIED":
            raise RuntimeError("Network application failed; inspect the private firewall-rollback.log")

    def confirm(self):
        send_message(self.process.stdin, "KEEP")
        if read_message(self.process.stdout, self.deadline) != "COMMITTED":
            raise RuntimeError("Network confirmation failed; inspect the private firewall-rollback.log")
        if self.process.wait(timeout=15) != 0:
            raise RuntimeError("The network supervisor did not exit successfully")
        close_pipe(self.process.stdin)
        close_pipe(self.process.stdout)

    def cancel(self):
        # EOF also works if the interactive caller dies without calling cancel.
        # Never kill the supervisor: it must remain able to restore networking.
        if not self.process.stdin.closed:
            close_pipe(self.process.stdin)
        try:
            self.process.wait(timeout=120)
        except subprocess.TimeoutExpired:
            raise RuntimeError("Network recovery is still running; inspect the private firewall-rollback.log and use the console if needed") from None
        finally:
            close_pipe(self.process.stdout)


class NativeRunner:
    """Bounded network-only commands in the private helper, with no shell eval."""

    def __init__(self, deadline):
        self.deadline = deadline

    def run(self, *args, check=True, timeout=15):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Firewall mutation deadline expired")
        result = subprocess.run([str(arg) for arg in args], text=True, capture_output=True,
                                check=False, timeout=min(timeout, remaining), umask=0o022)
        if check and result.returncode:
            raise RuntimeError(f"Network command failed: {' '.join(map(str, args))}\n{result.stderr.strip()}")
        return result


def apply_network(state, runner):
    state = Path(state)
    transaction = json.loads((state / "firewall-transition.json").read_text())
    settings = transaction["network"]
    require_pending(state)
    original_sysctls = SYSCTL_FILE.read_text() if SYSCTL_FILE.exists() else ""
    persistent_sysctls = bridge_sysctl_config(original_sysctls, settings["bridge_sysctls"],
                                            transaction["bridge_sysctls"])
    bridges = settings["bridge_addresses"]
    if bridges:
        for module in ("if_bridge", "bridgestp", "if_epair"):
            runner.run("sysrc", "-f", "/boot/loader.conf", f"{module}_load=YES")
        cloned = runner.run("sysrc", "-n", "cloned_interfaces", check=False).stdout.strip().split()
        combined = list(dict.fromkeys(cloned + list(bridges)))
        if combined != cloned:
            runner.run("sysrc", "cloned_interfaces=" + " ".join(combined))
    # Only add private bridges; the physical uplink is NEVER a bridge member.
    for bridge, gateway in bridges.items():
        runner.run("ifconfig", bridge, "create")
        runner.run("ifconfig", bridge, "inet", gateway + "/30", "up")
        runner.run("sysrc", f"ifconfig_{bridge}=inet {gateway}/30 up")
    for name, value in settings["bridge_sysctls"].items():
        runner.run("sysctl", f"{name}={value}")
    require_pending(state)
    if persistent_sysctls != original_sysctls:
        mode = SYSCTL_FILE.stat().st_mode & 0o777 if SYSCTL_FILE.exists() else 0o644
        replace_file(SYSCTL_FILE, persistent_sysctls, mode=mode)
    def validate(candidate):
        runner.run("pfctl", "-nf", str(candidate))
        require_pending(state)
    replace_file(settings["pf_file"], settings["pf_rules"], validate=validate)
    runner.run("pfctl", "-f", settings["pf_file"])
    if not transaction.get("previous_pf_enabled", False):
        runner.run("pfctl", "-e")


def worker(state):
    transaction = json.loads((Path(state) / "firewall-transition.json").read_text())
    runner = NativeRunner(transaction["deadline"])
    try:
        with mutation(state):
            apply_network(state, runner)
        send_message(sys.stdout, "APPLIED")
        if read_message(sys.stdin, transaction["deadline"]) != "KEEP":
            raise RuntimeError("Network confirmation was not received")
        commit(state, runner, transaction["network"]["pf_file"])
        send_message(sys.stdout, "COMMITTED")
    except BaseException as error:
        print(f"Network worker failed: {error}", file=sys.stderr, flush=True)
        send_message(sys.stdout, "FAILED")
    finally:
        # Stay the process-group leader until the supervisor terminates/reaps us.
        # This prevents PID reuse while it terminates command descendants too.
        sys.stdin.read()


def terminate_worker(process):
    """Only use with our unreaped direct child, created with start_new_session."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass  # The direct child can already be an unreaped zombie, never a reused PID.
    process.wait(timeout=15)
    close_pipe(process.stdin)
    close_pipe(process.stdout)


def supervise(state, request, response, *, worker_command=None):
    """Own the mutator lifecycle; tests may inject a harmless Python child."""
    state = Path(state)
    transaction = json.loads((state / "firewall-transition.json").read_text())
    command = worker_command or [sys.executable, str(Path(__file__).resolve()), "mutate", str(state)]
    process = None
    try:
        require_pending(state)
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=sys.stderr, text=True, start_new_session=True)
        if read_message(process.stdout, transaction["deadline"], abort=request) != "APPLIED":
            raise RuntimeError("Network worker did not apply the reviewed policy")
        send_message(response, "APPLIED")
        if read_message(request, transaction["deadline"]) != "KEEP":
            raise RuntimeError("Network confirmation declined")
        send_message(process.stdin, "KEEP")
        if read_message(process.stdout, transaction["deadline"], abort=request) != "COMMITTED":
            raise RuntimeError("Network worker did not commit the confirmed policy")
    except BaseException as error:
        print(f"Network supervisor: {error}", file=sys.stderr, flush=True)
    finally:
        # Critically, kill/reap BEFORE trying the rollback lock. SIGKILL releases
        # it even if the worker was suspended with SIGSTOP while holding flock.
        if process is not None:
            terminate_worker(process)
    # A worker paused just after its final durable commit marker is still a
    # committed transaction. Never undo an explicitly confirmed policy then.
    if (state / "firewall-confirmed").exists():
        notify_final(response, "COMMITTED")
        return 0
    rollback(state)
    notify_final(response, "ROLLED_BACK")
    return 1


def commit(state, runner, pf_file):
    state = Path(state)
    with (state / "firewall.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        settings = json.loads((state / "firewall-transition.json").read_text())
        require_pending(state)
        runner.run("pfctl", "-s", "Running", timeout=15)
        for name, args in PF_SNAPSHOTS:
            # Preserve leading table indentation: shell command substitution in
            # the startup guard strips trailing newlines, not leading spaces.
            exclusive_file(state / f"pf-{name}.expected", runner.run("pfctl", *args, timeout=15).stdout)
        require_pending(state)
        runner.run("sysrc", "gateway_enable=YES", "pf_enable=YES", f"pf_rules={pf_file}", timeout=15)
        runner.run("sysctl", "net.inet.ip.forwarding=1", timeout=15)
        require_pending(state)
        # Publish the pending transaction first. Startup guards fail closed until
        # its final marker exists, and rollback can restore the previous pointer
        # if the worker is stopped/killed between these two durable operations.
        active_pointer(state, settings)
        require_pending(state)
        # Last operation: the watchdog cannot race with this write under flock.
        exclusive_file(state / "firewall-confirmed", "Administrator confirmed management connectivity.\n")


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("supervise", "mutate"):
        raise SystemExit("Internal helper: expected supervise|mutate and the private state directory")
    if os.geteuid() != 0 or not sys.platform.startswith("freebsd"):
        raise SystemExit("This internal network helper requires the target FreeBSD root context")
    os.environ["PATH"] = "/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin"
    directory = Path(sys.argv[2])
    if sys.argv[1] == "supervise":
        raise SystemExit(supervise(directory, sys.stdin, sys.stdout))
    worker(directory)
