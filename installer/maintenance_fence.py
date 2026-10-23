"""Persistent, original-root maintenance closure and live-lock boot permission.

The admitted native caller supplies reviewed startup hashes and confirms editors
are saved, closed and visible in Nextcloud. This is not an ONLYOFFICE drain or
unsaved-work guarantee. No commands, PF changes, service starts or commits occur
here (publication permission additionally reads kern.boottime). Storage/mount/PF
guards and pinned-JID service execution remain mandatory.
"""

from contextlib import contextmanager
import fcntl
import ipaddress
import os
from pathlib import Path
import re
import stat
import tempfile

from .enrollment_start import _held, _lock_file
from .generations import Store, MAX_FILE_BYTES, _encode, _fields, _hash, _id, _json, _schema


DENIED = "Maintenance closed-profile permission refused"
PHASES = frozenset(("quiesced", "recovery-ready", "migrating", "validating", "restored-closed", "recovery-validating",
                    "recovery-reclosing"))
VHOST = "usr/local/etc/apache24/cloud-vhost.conf"
SERVICES = {"nextcloud": ("cron", "sshd", "apache24", "php_fpm", "mysql", "redis"),
            "onlyoffice": ("cron", "sshd", "nginx", "supervisord")}
STARTUP_FILES = ("etc/rc.conf", "etc/defaults/rc.conf", "etc/rc", "etc/rc.subr")
STARTUP_TREES = ("etc/rc.d", "usr/local/etc/rc.d")
OVERRIDES = ("etc/rc.conf.local", "usr/local/etc/rc.conf.local", "etc/rc.local", "usr/local/etc/rc.local")


def _root_required():
    if os.geteuid() != 0:
        raise ValueError(DENIED)


def _file(root, relative):
    """Host-side read, never following a jail-controlled symlink or hardlink."""
    root = Path(root)
    if not root.is_absolute() or str(root) != os.path.normpath(root):
        raise ValueError(DENIED)
    parts = Path(relative).parts
    if not parts or Path(relative).is_absolute() or any(p in (".", "..") for p in parts):
        raise ValueError(DENIED)
    path = root / relative
    for parent in reversed(path.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError(DENIED)
        # Host ancestors may be shared (e.g. /tmp in offline tests); the actual
        # jail tree must be root-owned and not group/world writable.
        if (parent == root or root in parent.parents) and (info.st_uid != os.geteuid() or info.st_mode & 0o022):
            raise ValueError(DENIED)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or before.st_nlink != 1 or before.st_mode & 0o022 or before.st_size > MAX_FILE_BYTES):
            raise ValueError(DENIED)
        data = stream.read(MAX_FILE_BYTES + 1)
        after = os.fstat(stream.fileno())
        identity = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                                 info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if identity(before) != identity(after) or len(data) != before.st_size or identity(path.lstat()) != identity(after):
            raise ValueError(DENIED)
    return data, stat.S_IMODE(before.st_mode), before.st_gid


def startup_inventory(root, *, nextcloud=False):
    """Inventory for comparison with caller-reviewed baseline; not admission."""
    root = Path(root)
    for relative in OVERRIDES:
        if os.path.lexists(root / relative):
            raise ValueError(DENIED)
    for relative in ("etc/rc.conf.d", "usr/local/etc/rc.conf.d"):
        path = root / relative
        if os.path.lexists(path):
            info = path.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_mode & 0o022 or any(path.iterdir())):
                raise ValueError(DENIED)
    names = list(STARTUP_FILES)
    trees = STARTUP_TREES + (("usr/local/etc/apache24",) if nextcloud else ())
    for relative in trees:
        pending = [root / relative]
        while pending:
            directory = pending.pop()
            info = directory.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022):
                raise ValueError(DENIED)
            for path in sorted(directory.iterdir()):
                if stat.S_ISDIR(path.lstat().st_mode):
                    pending.append(path)
                else:
                    names.append(str(path.relative_to(root)))
                if len(names) + len(pending) > 4096:
                    raise ValueError(DENIED)
    return {name: _hash(_file(root, name)[0]) for name in sorted(names)}


def _closed_rc(data, services):
    # rc.conf is shell input at boot, but we never evaluate it. Only literal
    # assignments/comments are supported; source, expansions and control flow
    # require separate review instead of pretending a last sysrc flag suffices.
    text = data.decode("utf-8")
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r"\s*([A-Za-z_][A-Za-z0-9_]*)=(?:\"([A-Za-z0-9_ ./,:@%+*=!~\-]*)\"|'([A-Za-z0-9_ ./,:@%+*=!~\-]*)'|([A-Za-z0-9_./,:@%+*=!~\-]*))\s*(?:#.*)?", line)
        if match is None or match[1] in ("rc_conf_files", "local_startup", "rc_conf_dirs"):
            raise ValueError(DENIED)
    return data + ("\n# Installer maintenance CLOSED; explicit publication required.\n" +
                   "".join(f'{service}_enable="NO"\n' for service in services)).encode()


def _closed_vhost(data, config):
    peer = str(ipaddress.IPv4Address(config.onlyoffice_ip))
    fence = ("    # Installer maintenance CLOSED: actual connection peer only.\n"
             "    RewriteEngine On\n"
             "    RewriteCond %{CONN_REMOTE_ADDR} !^127\\.0\\.0\\.1$\n"
             "    RewriteCond %{CONN_REMOTE_ADDR} !^::1$\n"
             f"    RewriteCond %{{CONN_REMOTE_ADDR}} !^{re.escape(peer)}$\n"
             "    RewriteRule ^ - [R=503,END]\n")
    ports, inside, result = [], False, []
    for line in data.decode("utf-8").splitlines(keepends=True):
        if "virtualhost" in line.lower() and not line.lstrip().startswith("#"):
            opening = re.fullmatch(r"<VirtualHost \*:(80|443)>\n", line)
            if opening and not inside:
                inside = True
                ports.append(int(opening[1]))
                result.extend((line, fence))
                continue
            if line.strip() != "</VirtualHost>" or not inside:
                raise ValueError(DENIED)
            inside = False
        result.append(line)
    if inside or ports != ([80] if config.tls_mode == "external" else [80, 443]):
        raise ValueError(DENIED)
    return "".join(result).encode()


def _binding(store, intent=None):
    from .config import Config
    from .maintenance import executor_record
    from .maintenance_state import NativeState, validate_intent
    from .state import Registry

    _root_required()
    intent = store.pending() if intent is None else intent
    validate_intent(intent)
    if store.pending() != intent:
        raise ValueError(DENIED)
    executor = executor_record()
    if _json(store._read("lifecycle/executor.json")) != executor:
        raise ValueError(DENIED)
    # These strict validators read immutable inputs without acquiring the parent
    # Registry lock. NativeState.read/view are intentionally NOT used by boot.
    state = NativeState(Registry(store.root), executor)
    inputs = state._inputs(intent)
    state._chain(intent, inputs)
    name = inputs["instance"]
    config_ref = inputs["originals"][name]["files"]["config.json"]["retained"]
    config = Config.from_json(store._bound(config_ref).decode())
    roots = {jail: str(Path(config.bastille_root, "jails", jail, "root"))
             for jail in (config.nextcloud_jail, config.onlyoffice_jail)}
    if any(store.root == Path(root) or Path(root) in store.root.parents for root in roots.values()):
        raise ValueError(DENIED)
    directory = "maintenance/operations/" + intent["operation"]
    record = dict(schema_version=1, operation=intent["operation"], instance=name,
                  executor=executor, intent=store.reference(directory + "/intent.json"),
                  config=config_ref, roots=roots, network=inputs["network"])
    return directory, record, config


def _native_journal(store, directory, binding, reference=None):
    """NativeJournal's strict read binding, without taking the parent's lock."""
    from .maintenance_journal import native_validate

    path = directory + "/native-journal.json"
    reference = store.reference(path) if reference is None else reference
    value = native_validate(_json(store._bound(reference, path)))
    intent = _json(store._bound(binding["intent"]))
    inputs = _json(store._bound(intent["inputs"]))
    if (value["operation"] != binding["intent"] or value["inputs"] != intent["inputs"]
            or value["recipe_sha256"] != inputs["recipe_sha256"]
            or store._present(directory + "/native-terminal.json")):
        raise ValueError(DENIED)
    for evidence in [value["evidence"], *(event["evidence"] for event in value["history"])]:
        for ref in evidence.values():
            store._bound(ref)
    for step in [*value["steps"].values(), *(event["step"] for event in value["history"] if event["step"] is not None)]:
        for key in ("precondition", "observation", "recovery"):
            if step[key] is not None:
                store._bound(step[key])
    return reference, value


@contextmanager
def _exclusive(store, directory):
    _root_required()
    _held(store, "operation.lock")
    # Mutating a profile must never revive an old native-start.json merely by
    # taking the boot-permission lock. Serialize profiles separately; only the
    # validation context below ever holds native-start.lock.
    fd = _lock_file(store, directory + "/native-profile.lock", create=True)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def capture_profile(context, store, operation):
    """Seal immutable copies outside the rollback set under both real locks.

    context is serializable: {config: Config JSON object, roots: {jail: path},
    baseline: {jail: startup_inventory(...)}, operator_saved_closed: True}.
    The baseline must come from the parent's admitted original-file assessment.
    """
    directory, binding, config = _binding(store)
    _fields(context, "config roots baseline operator_saved_closed")
    if (operation != binding["operation"] or context["config"] != _json(config.to_json().encode())
            or context["roots"] != binding["roots"] or context["operator_saved_closed"] is not True
            or set(context["baseline"]) != set(binding["roots"])):
        raise ValueError(DENIED)
    with _exclusive(store, directory):
        profile_path = directory + "/closed-profile.json"
        if store._present(profile_path):
            reference = store.reference(profile_path)
            profile, _ = _profile(store, reference)
            if profile["baseline"] != context["baseline"]:
                raise ValueError(DENIED)
            _check_files(store, profile, "either")
            return reference
        files = []
        for role, jail in (("nextcloud", config.nextcloud_jail), ("onlyoffice", config.onlyoffice_jail)):
            root = binding["roots"][jail]
            if startup_inventory(root, nextcloud=role == "nextcloud") != context["baseline"][jail]:
                raise ValueError(DENIED)
            for path in (("etc/rc.conf", VHOST) if role == "nextcloud" else ("etc/rc.conf",)):
                data, mode, gid = _file(root, path)
                if mode not in (0o600, 0o640, 0o644, 0o400, 0o440, 0o444):
                    raise ValueError(DENIED)
                closed = _closed_vhost(data, config) if path == VHOST else _closed_rc(data, SERVICES[role])
                files.append((jail, path, data, closed, mode, gid))
        store._mkdir(directory + "/profile")
        entries = []
        for index, (jail, path, data, closed, mode, gid) in enumerate(files):
            prefix = directory + f"/profile/{index}"
            entries.append(dict(jail=jail, path=path, mode=mode, gid=gid,
                original=store._write_once(prefix + "-original", data, recover=True),
                closed=store._write_once(prefix + "-closed", closed, recover=True)))
        return store._put(profile_path, dict(**binding, kind="native-closed-profile",
            baseline=context["baseline"], operator_saved_closed=True, files=entries))


def _profile(store, receipt):
    directory, binding, config = _binding(store)
    value = _json(store._bound(receipt, directory + "/closed-profile.json"))
    _fields(value, "schema_version operation instance executor intent config roots network kind baseline operator_saved_closed files")
    _schema(value)
    if (any(value[key] != item for key, item in binding.items())
            or value["kind"] != "native-closed-profile" or value["operator_saved_closed"] is not True
            or type(value["baseline"]) is not dict or set(value["baseline"]) != set(binding["roots"])
            or type(value["files"]) is not list or len(value["files"]) != 3):
        raise ValueError(DENIED)
    expected = [(config.nextcloud_jail, "etc/rc.conf"), (config.nextcloud_jail, VHOST),
                (config.onlyoffice_jail, "etc/rc.conf")]
    for index, (item, pair) in enumerate(zip(value["files"], expected)):
        _fields(item, "jail path mode gid original closed")
        if ((item["jail"], item["path"]) != pair or type(item["mode"]) is not int
                or item["mode"] not in (0o600, 0o640, 0o644, 0o400, 0o440, 0o444)
                or type(item["gid"]) is not int or item["gid"] < 0):
            raise ValueError(DENIED)
        prefix = directory + f"/profile/{index}"
        original = store._bound(item["original"], prefix + "-original")
        closed = store._bound(item["closed"], prefix + "-closed")
        role = "nextcloud" if pair[0] == config.nextcloud_jail else "onlyoffice"
        derived = _closed_vhost(original, config) if pair[1] == VHOST else _closed_rc(original, SERVICES[role])
        if closed != derived or value["baseline"][pair[0]].get(pair[1]) != _hash(original):
            raise ValueError(DENIED)
    return value, config


def publication_bytes(store, item):
    """Exact original application startup, with scheduled/SSH writers fenced."""
    original = store._bound(item["original"])
    return _closed_rc(original, ("cron", "sshd")) if item["path"] == "etc/rc.conf" else original


def _check_files(store, profile, state):
    expected = {jail: dict(files) for jail, files in profile["baseline"].items()}
    for item in profile["files"]:
        data, mode, gid = _file(profile["roots"][item["jail"]], item["path"])
        allowed = (("original", "closed", "publication") if state == "publication-either" else
                   ("original", "closed") if state == "either" else (state,))
        if (mode != item["mode"] or gid != item["gid"]
                or data not in [publication_bytes(store, item) if key == "publication" else
                                store._bound(item[key]) for key in allowed]):
            raise ValueError(DENIED)
        expected[item["jail"]][item["path"]] = _hash(data)
    for jail, root in profile["roots"].items():
        if startup_inventory(root, nextcloud=jail.endswith("nc")) != expected[jail]:
            raise ValueError(DENIED)


def verify_closed(store, receipt):
    """Read actual original roots, without jexec; pending boot guard still applies."""
    profile, config = _profile(store, receipt)
    _check_files(store, profile, "closed")
    return config


def _replace(root, item, data):
    path = Path(root) / item["path"]
    fd, temporary = tempfile.mkstemp(prefix=".maintenance-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchown(stream.fileno(), os.geteuid(), item["gid"])
            os.fchmod(stream.fileno(), item["mode"])
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        Store._sync(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _apply(registry, receipt):
    registry._require_lock(recovery=True)
    store = Store(registry.root)
    profile, _ = _profile(store, receipt)
    directory = "maintenance/operations/" + profile["operation"]
    with _exclusive(store, directory):
        journal = directory + "/profile-apply.json"
        previous = None
        if store._present(journal):
            previous = _json(store._read(journal))
            _fields(previous, "schema_version profile target publication index state")
            _schema(previous)
            if (previous["profile"] != receipt or previous["target"] not in ("closed", "original")
                    or previous["state"] not in ("applying", "complete")
                    or type(previous["index"]) is not int or not 0 <= previous["index"] <= 3
                    or (previous["state"] == "complete") != (previous["index"] == 3)
                    or (previous["target"] == "closed" and previous["publication"] is not None)):
                raise ValueError(DENIED)
            if previous["publication"] is not None:
                store._bound(previous["publication"], directory + "/native-publication.json")
        target = "closed"
        # Validate the entire pair before the first write. Only these exact two
        # byte states are recoverable after interruption or ZFS restoration.
        _check_files(store, profile, "either")
        for index, item in enumerate(profile["files"]):
            store._put(journal, dict(schema_version=1, profile=receipt, target=target,
                       publication=None, index=index, state="applying"), replace=store._present(journal))
            root = profile["roots"][item["jail"]]
            data, _, _ = _file(root, item["path"])
            wanted = store._bound(item[target])
            if data != wanted:
                if data not in (store._bound(item["original"]), store._bound(item["closed"])):
                    raise ValueError(DENIED)
                _replace(root, item, wanted)
        _check_files(store, profile, target)
        store._put(journal, dict(schema_version=1, profile=receipt, target=target,
                   publication=None, index=3, state="complete"), replace=True)
    return receipt


def install_profile(registry, receipt):
    """Idempotent closure, including exact original bytes restored by ZFS."""
    return _apply(registry, receipt)


def restore_profile(registry, receipt, *, publication, progress=None):
    """Original flags require the dedicated scheduled-services checkpoint.

    Old terminal records remain readable, but an opening marker alone no longer
    authorizes releasing scheduled writers through this compatibility entry.
    """
    if publication is None or progress is None:
        raise ValueError(DENIED)
    return publication_profile(registry, receipt, publication=publication, progress=progress)


def publication_profile(registry, receipt, *, publication, progress=None):
    """Forward-only profile transition; release writers only at their checkpoint.

    Separate progress preserves historical terminal profile-apply references. The
    derived bytes never replace the immutable original/closed source snapshots.
    """
    from .maintenance_opening import bound, chain
    from .maintenance_publication import STEPS
    registry._require_lock(recovery=True)
    store = Store(registry.root)
    data = bound(store, terminal=True)
    directory, binding = data[:2]
    _held(store, f"instances/{data[2].instance}/database-operation.lock")
    if publication != data[6] or receipt != store.reference(directory + "/closed-profile.json"):
        raise ValueError(DENIED)
    release = progress is not None
    if release:
        newest, identity = chain(store, data)
        progress_path = (directory + "/publication-progress-" + newest[0]["sha256"] + ".json"
                         if newest else directory + "/publication-progress.json")
        value = _json(store._bound(progress))
        _fields(value, "schema_version publication completed running evidence")
        _schema(value)
        if (not store._present(progress_path) or progress != store.reference(progress_path)
                or newest is not None and identity is None
                or value.get("publication") != publication
                or value.get("completed") != list(STEPS[:4]) or value.get("running") != "scheduled-services"
                or type(value["evidence"]) is not dict or set(value["evidence"]) != set(STEPS[:4])):
            raise ValueError(DENIED)
        for reference in value["evidence"].values():
            if not reference["path"].startswith(directory + "/"):
                raise ValueError(DENIED)
            store._bound(reference)
    profile, _ = _profile(store, receipt)
    plan = dict(schema_version=1, intent=binding["intent"], publication=publication, profile=receipt,
                files=[dict(jail=item["jail"], path=item["path"], sha256=_hash(publication_bytes(store, item)))
                       for item in profile["files"]])
    store._write_once(directory + "/publication-start-profile.json", _encode(plan), recover=True)
    with _exclusive(store, directory):
        _check_files(store, profile, "publication-either")
        path = directory + "/publication-profile-progress.json"
        for index, item in enumerate(profile["files"]):
            store._put(path, dict(plan=store.reference(directory + "/publication-start-profile.json"),
                journal=store.reference(directory + "/native-journal.json"), progress=progress,
                target="original" if release else "publication", index=index), replace=store._present(path))
            wanted = store._bound(item["original"]) if release else publication_bytes(store, item)
            if _file(profile["roots"][item["jail"]], item["path"])[0] != wanted:
                _replace(profile["roots"][item["jail"]], item, wanted)
        _check_files(store, profile, "original" if release else "publication")
        if release:
            # Same exact historical format: terminal finalization remains readable.
            store._put(directory + "/profile-apply.json", dict(schema_version=1, profile=receipt,
                target="original", publication=publication, index=3, state="complete"), replace=True)
    return receipt


@contextmanager
def validation_starts(registry, intent, receipt, *, phase):
    """Grant temporary boot permission ONLY; caller admits recipe/starts services.

    Re-enter after journal updates. native-start.json hashes native-phase.json,
    which in turn hashes the exact native journal. Neither mutable pointer alone
    nor a caller-supplied phase string grants permission.
    """
    registry._require_lock(recovery=True)
    store = Store(registry.root)
    directory, binding, config = _binding(store, intent)
    if phase not in PHASES:
        raise ValueError(DENIED)
    with _exclusive(store, directory):
        verify_closed(store, receipt)
        journal_ref, journal = _native_journal(store, directory, binding)
        if (journal["phase"] != phase or journal["publication_may_have_begun"]
                or journal["recovery_publication_may_have_begun"]):
            raise ValueError(DENIED)
        phase_path = directory + "/native-phase.json"
        phase_ref = store._put(phase_path, dict(schema_version=1, kind="native-closed-phase",
            intent=binding["intent"], profile=receipt, phase=phase, journal=journal_ref), replace=store._present(phase_path))
        path = directory + "/native-start.json"
        store._put(path, dict(**binding, kind="native-maintenance-start", profile=receipt,
            phase=phase_ref), replace=store._present(path))
        fd = _lock_file(store, directory + "/native-start.lock", create=True)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            boot_permission(registry, intent, config.instance, config.nextcloud_jail, intent["executor_sha256"])
            yield config
        finally:
            os.close(fd)


def _publication_boot():
    from .host import Runner
    from .maintenance_native import _boot
    return _boot(Runner().output("sysctl", "-n", "kern.boottime"))


def _publication_permission(store, intent, instance, jail, executor, *, attempt=True):
    from .maintenance_opening import bound, chain, payload
    data = bound(store, intent, terminal=True)
    directory, binding, config, inputs, journal, proof, publication, graph, generation = data
    permission = _json(store._read(directory + "/publication-start.json"))
    _fields(permission, "schema_version kind intent profile request publication journal graph boot roots executor")
    _schema(permission)
    current, _ = chain(store, data)
    if current is None:
        raise ValueError(DENIED)
    reference, request = current
    if _json(store._read(directory + "/native-journal.json"))["phase"] in ("complete", "recovered"):
        from .maintenance_opening import terminal_binding
        if request["terminal"] != terminal_binding(store, directory)[0]:
            raise ValueError(DENIED)
    elif request["terminal"] is not None:
        raise ValueError(DENIED)
    expected = dict(schema_version=1, kind="native-publication-start", intent=binding["intent"],
                    profile=store.reference(directory + "/closed-profile.json"), request=reference,
                    publication=publication, journal=store.reference(directory + "/native-journal.json"),
                    graph=graph, boot=request["boot"], roots=binding["roots"], executor=binding["executor"])
    if (_encode(permission) != _encode(expected) or instance != config.instance or jail not in binding["roots"]
            or executor != binding["executor"]["executor_sha256"] or _publication_boot() != request["boot"]):
        raise ValueError(DENIED)
    _held(store, "operation.lock")
    _held(store, f"instances/{instance}/database-operation.lock")
    _held(store, directory + "/publication-start.lock")
    if attempt:
        progress = _json(store._read(directory + "/opening-progress-" + reference["sha256"] + ".json"))
        _fields(progress, "schema_version request states")
        _schema(progress)
        if (progress["request"] != reference or set(progress["states"]) != set(binding["roots"])
                or progress["states"][jail] != dict(state="starting", jid=None, observation=None)):
            raise ValueError(DENIED)
    profile, _ = _profile(store, permission["profile"])
    _check_files(store, profile, "publication")
    applied = _json(store._read(directory + "/publication-start-profile.json"))
    if applied != dict(schema_version=1, intent=binding["intent"], publication=publication,
                       profile=permission["profile"], files=[dict(jail=item["jail"], path=item["path"],
                       sha256=_hash(publication_bytes(store, item))) for item in profile["files"]]):
        raise ValueError(DENIED)
    if payload(store, config, inputs, journal, proof) != _json(store._bound(request["inspection"])):
        raise ValueError(DENIED)
    store._bound(permission["journal"], directory + "/native-journal.json")
    if store.pending() != intent or store._active() != graph or _publication_boot() != request["boot"]:
        raise ValueError(DENIED)
    _held(store, "operation.lock")
    _held(store, f"instances/{instance}/database-operation.lock")
    _held(store, directory + "/publication-start.lock")
    return config


@contextmanager
def publication_starts(registry, intent, receipt, request):
    """One exact opening request, scheduled-writer fence, distinct live lock.

    No validation/enrollment lock or persistent JSON alone grants this permission.
    The caller already recorded CONTINUE-PUBLICATION and checked live topology;
    normal exec.prepare storage/PF guards run after this exception too.
    """
    from .maintenance_opening import bound, chain
    registry._require_lock(recovery=True)
    store = Store(registry.root)
    data = bound(store, intent, terminal=True)
    directory, binding, config, inputs, journal, proof, publication, graph, generation = data
    current, _ = chain(store, data)
    if current is None or current[0] != request or receipt != store.reference(directory + "/closed-profile.json"):
        raise ValueError(DENIED)
    _held(store, f"instances/{config.instance}/database-operation.lock")
    with _exclusive(store, directory):
        fd = _lock_file(store, directory + "/publication-start.lock", create=True)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            value = dict(schema_version=1, kind="native-publication-start", intent=binding["intent"], profile=receipt,
                request=request, publication=publication, journal=store.reference(directory + "/native-journal.json"),
                graph=graph, boot=current[1]["boot"], roots=binding["roots"], executor=binding["executor"])
            path = directory + "/publication-start.json"
            store._put(path, value, replace=store._present(path))
            _publication_permission(store, intent, config.instance, config.nextcloud_jail,
                                    intent["executor_sha256"], attempt=False)
            yield config
        finally:
            os.close(fd)


def _unaffected_boot(store, intent, binding, instance, jail, executor):
    """Original ready neighbors may reboot; the affected pair never uses this."""
    from .config import Config
    from .maintenance_state import _graph

    # _binding has already applied NativeState._inputs and _chain to this exact
    # pending intent. Recheck actual unaffected registration/files, not just the
    # retained snapshots, and never follow an arbitrary successor graph.
    inputs = _json(store._bound(intent["inputs"]))
    if instance == inputs["instance"] or instance not in inputs["entries"]:
        raise ValueError(DENIED)
    active_ref = store._active()
    active = _graph(store, active_ref)
    selected = None
    for name, entry in inputs["entries"].items():
        if name == inputs["instance"]:
            continue
        if _encode(active["instances"].get(name)) != _encode(entry):
            raise ValueError(DENIED)
        resolved = store._resolve_entry(name, entry)
        for pair in inputs["originals"][name]["files"].values():
            if pair is not None:
                store._bound(pair["original"])
        if name == instance:
            selected = resolved
    directory = store._path("instances")
    store._check(directory.lstat(), directory=True)
    names = set()
    for path in directory.iterdir():
        if not path.name.startswith(".pending-"):
            _id(path.name, True)
            store._check(path.lstat(), directory=True)
            names.add(path.name)
    if names != set(inputs["entries"]):
        raise ValueError(DENIED)
    original = inputs["originals"][instance]
    config_bytes = store._bound(original["files"]["config.json"]["retained"])
    config = Config.from_json(config_bytes.decode())
    source = original["files"]["source.sha256"]
    if (selected is None or selected.kind not in ("managed", "legacy")
            or original["status"]["state"] != "ready" or selected.status != original["status"]
            or selected.config_bytes != config_bytes or config.instance != instance
            or jail not in (config.nextcloud_jail, config.onlyoffice_jail)
            or source is None or Store._source(store._bound(source["retained"])) != binding["executor"]["source_sha256"]
            or selected.provenance["source_sha256"] != binding["executor"]["source_sha256"]
            or executor != binding["executor"]["executor_sha256"]
            or store.pending() != intent or store._active() != active_ref):
        raise ValueError(DENIED)
    return config


def boot_permission(registry, intent, instance, jail, executor):
    """Read-only maintenance exception; ordinary storage/PF guard MUST follow."""
    try:
        store = Store(registry.root)
        directory, binding, config = _binding(store, intent)
        if instance != config.instance:
            return _unaffected_boot(store, intent, binding, instance, jail, executor)
        if store._present(directory + "/cancellation-request.json"):
            from .maintenance_cancellation import boot_permission as cancellation_permission
            return cancellation_permission(registry, intent, instance, jail, executor)
        from .maintenance_journal import native_validate
        current = native_validate(_json(store._read(directory + "/native-journal.json")))
        if current["phase"] in ("opening", "recovery-opening", "complete", "recovered"):
            return _publication_permission(store, intent, instance, jail, executor)
        permission = _json(store._read(directory + "/native-start.json"))
        _fields(permission, "schema_version operation instance executor intent config roots network kind profile phase")
        _schema(permission)
        if (instance != config.instance or jail not in binding["roots"]
                or executor != binding["executor"]["executor_sha256"]
                or permission["kind"] != "native-maintenance-start"
                or any(permission[key] != value for key, value in binding.items())):
            raise ValueError(DENIED)
        phase = _json(store._bound(permission["phase"], directory + "/native-phase.json"))
        _fields(phase, "schema_version kind intent profile phase journal")
        _schema(phase)
        if (phase["kind"] != "native-closed-phase" or phase["intent"] != binding["intent"]
                or phase["profile"] != permission["profile"] or phase["phase"] not in PHASES):
            raise ValueError(DENIED)
        _, journal = _native_journal(store, directory, binding, phase["journal"])
        if (journal["phase"] != phase["phase"] or journal["publication_may_have_begun"]
                or journal["recovery_publication_may_have_begun"]):
            raise ValueError(DENIED)
        if journal["phase"] == "recovery-reclosing":
            request = _json(store._bound(journal["evidence"]["reclosure_request"]))
            _fields(request, "schema_version kind operation confirmation prior_phase prior_last_safe_phase prior_journal boot old_shutdown capture_anchor_sha256 manifest runtime assessment_sha256 profile")
            _schema(request)
            prior = _json(store._bound(request["prior_journal"]))
            from .maintenance_journal import native_validate
            native_validate(prior)
            boot = (re.fullmatch(r"\{\s*sec = ([1-9][0-9]*),\s*usec = ([0-9]+)\s*\}[^\r\n]*", request["boot"])
                    if type(request["boot"]) is str else None)
            if (request["kind"] != "native-reclosure-request" or request["operation"] != intent["operation"]
                    or request["confirmation"] != "REQUIESCE-MAINTENANCE " + intent["operation"]
                    or request["manifest"] != journal["evidence"]["recovery_set"]
                    or request["profile"] != permission["profile"] or prior["operation"] != journal["operation"]
                    or prior["publication_may_have_begun"] or prior["recovery_publication_may_have_begun"]
                    or request["prior_phase"] != prior["phase"] or request["prior_last_safe_phase"] != prior["last_safe_phase"]
                    or prior["last_safe_phase"] not in ("recovery-ready", "migrating", "awaiting-reboot", "validating",
                                                       "committed-closed", "recovery-reclosing", "recovery-reclosed")
                    or boot is None or int(boot[2]) >= 1000000
                    or type(request["assessment_sha256"]) is not str
                    or re.fullmatch(r"[a-f0-9]{64}", request["assessment_sha256"]) is None
                    or request["capture_anchor_sha256"] != _json(store._bound(request["manifest"]))["cold_boundary"]):
                raise ValueError(DENIED)
            store._bound(request["old_shutdown"])
            store._bound(request["runtime"])
            _held(store, f"instances/{instance}/database-operation.lock")
        _held(store, "operation.lock")
        _held(store, directory + "/native-start.lock")
        verify_closed(store, permission["profile"])
        store._bound(phase["journal"], directory + "/native-journal.json")
        store._bound(permission["phase"], directory + "/native-phase.json")
        if _json(store._read(directory + "/native-start.json")) != permission:
            raise ValueError(DENIED)
        _held(store, "operation.lock")
        _held(store, directory + "/native-start.lock")
        if store.pending() != intent:
            raise ValueError(DENIED)
        if journal["phase"] == "recovery-reclosing":
            _held(store, f"instances/{instance}/database-operation.lock")
        return config
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        raise ValueError(DENIED) from None
