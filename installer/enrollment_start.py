"""Live, same-intent permission to start the original enrollment pair.

The host operation lock is acquired by the caller. The permission file is only
an immutable binding: BOTH exclusive locks must still be held to authorize a
boot. No PID, timestamp, stale file, or previous successful check grants access.
This is not application writer fencing or permission to execute old artifacts.
"""

from contextlib import contextmanager
import fcntl
import os
import stat


DENIED = "Enrollment validation start permission refused"


def _lock_file(store, relative, *, create=False):
    path = store._path(relative)
    flags = os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    if create:
        try:
            fd = os.open(path, flags | os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            fd = os.open(path, flags | os.O_RDWR)
    else:
        fd = os.open(path, flags | os.O_RDONLY)
    try:
        info = os.fstat(fd)
        current = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid != os.geteuid() or info.st_nlink != 1
                or info.st_size != 0
                or (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino)):
            raise ValueError(DENIED)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _held(store, relative):
    """Read-only probe: only an existing EXCLUSIVE holder counts as authority."""
    fd = _lock_file(store, relative)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        fcntl.flock(fd, fcntl.LOCK_UN)
        raise ValueError(DENIED)
    finally:
        os.close(fd)


def _binding(registry, intent, *, supplied_plan=None):
    from .config import Config
    from .enrollment import ADAPTER
    from .generations import Store, _fields, _json, _schema
    from .maintenance import executor_identity, executor_record
    from .state import config_digest

    store = Store(registry.root)
    store._intent(intent)
    if (store.pending() != intent or intent["action"] != "enroll"
            or intent["executor_sha256"] != executor_identity()):
        raise ValueError(DENIED)
    directory = "maintenance/operations/" + intent["operation"]
    anchor = _json(store._read(directory + "/enrollment-inputs.json"))
    _fields(anchor, "schema_version plan")
    _schema(anchor)
    plan = _json(store._bound(anchor["plan"], directory + "/enrollment.json"))
    _fields(plan, "schema_version instance operation executor generation graph originals entries assessment evidence")
    _schema(plan)
    executor = executor_record()
    name = plan["instance"]
    if (plan["operation"] != intent["operation"] or intent["instances"] != [name]
            or plan["executor"] != executor
            or (supplied_plan is not None and supplied_plan != plan)):
        raise ValueError(DENIED)
    original = plan["originals"][name]
    _fields(original, "config status")
    config = Config.from_json(store._bound(original["config"], directory + "/" + name + "-config.json").decode())
    status = _json(store._bound(original["status"], directory + "/" + name + "-status.json"))
    assessment = plan["assessment"]
    if (config.instance != name or config.schema_version != 2 or status.get("state") != "ready"
            or assessment.get("schema") != 1 or assessment.get("adapter") != ADAPTER
            or assessment.get("eligible") is not True or assessment.get("instance") != name
            or assessment.get("source_sha256") != executor["source_sha256"]
            or assessment.get("config_sha256") != config_digest(config)
            or assessment["artifacts"]["config.json"] != original["config"]["sha256"]):
        raise ValueError(DENIED)
    record = {"schema_version": 1, "operation": intent["operation"], "executor": executor,
              "instance": name, "jails": [config.nextcloud_jail, config.onlyoffice_jail],
              "plan": anchor["plan"], "config": original["config"],
              "intent": store.reference(directory + "/intent.json")}
    return store, directory, record, config


def _permission_matches(store, path, record):
    from .generations import _encode, _json
    # Canonical encoding also distinguishes JSON booleans from integer schema
    # values; Python dictionary equality alone does not.
    return _encode(_json(store._read(path))) == _encode(record)


@contextmanager
def start_permission(registry, intent, plan):
    """Hold temporary boot authority under the caller's real Registry lock.

    Pass the actual Registry, not the deployment's read-only enrollment view.
    Retained permission records are reused only for the identical sealed plan.
    """
    fd = None
    try:
        if getattr(registry, "_locked", False) is not True:
            raise ValueError(DENIED)
        store, directory, record, config = _binding(registry, intent, supplied_plan=plan)
        _held(store, "operation.lock")
        fd = _lock_file(store, directory + "/start-permission.lock", create=True)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        path = directory + "/start-permission.json"
        if store._present(path):
            if not _permission_matches(store, path, record):
                raise ValueError(DENIED)
        else:
            store._put(path, record)
        # Check the publication and lock paths exactly as a separate boot reader.
        boot_permission(registry, intent, config.instance, config.nextcloud_jail, intent["executor_sha256"])
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        if fd is not None:
            os.close(fd)
        raise ValueError(DENIED) from None
    try:
        yield config
    finally:
        os.close(fd)


def boot_permission(registry, intent, instance, jail, executor):
    """Return the source-bound Config, or refuse with a fixed diagnostic.

    Called BEFORE the ordinary pending-intent entry guard. The caller must still
    execute the unchanged storage/PF guard after this narrowly scoped exception.
    This reader never creates a file, changes a record, or retains a lock.
    """
    try:
        store, directory, record, config = _binding(registry, intent)
        if (instance != config.instance or jail not in record["jails"]
                or executor != record["executor"]["executor_sha256"]
                or not _permission_matches(store, directory + "/start-permission.json", record)):
            raise ValueError(DENIED)
        _held(store, "operation.lock")
        _held(store, directory + "/start-permission.lock")
        if store.pending() != intent:
            raise ValueError(DENIED)
        return config
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        raise ValueError(DENIED) from None


def _live_pair(deployment):
    """Include dying jails; a failed/ambiguous inventory is never 'stopped'."""
    result = deployment.runner.run("jls", "-d", "jid", "name", "path", "dying", "host.hostname",
                                   hide_output=True)
    if result.returncode or not isinstance(result.stdout, str):
        raise ValueError(DENIED)
    c = deployment.config
    expected = {c.nextcloud_jail: c.nextcloud_host, c.onlyoffice_jail: c.onlyoffice_host}
    roots = {str(deployment.jail_root(name)) for name in expected}
    live, names, jids = {}, set(), set()
    for line in result.stdout.splitlines():
        row = line.split()
        if (len(row) != 5 or not row[0].isdigit() or int(row[0]) < 1
                or row[3] not in ("false", "true", "0", "1") or row[1] in names or int(row[0]) in jids):
            raise ValueError(DENIED)
        jid, name, root, dying, hostname = row
        names.add(name)
        jids.add(int(jid))
        if name in expected:
            if (root != str(deployment.jail_root(name)) or hostname != expected[name]
                    or dying not in ("false", "0")):
                raise ValueError(DENIED)
            if deployment.require_running_jail(name) != int(jid):
                raise ValueError(DENIED)
            live[name] = int(jid)
        elif root in roots:
            raise ValueError(DENIED)
    return live


def _preflight(deployment, registry, intent, plan):
    from . import enrollment
    from .generations import Store, _hash
    from .lifecycle import _checked_jails
    from .network import storage_guard
    from .state import Journal

    c = deployment.config
    bound = boot_permission(registry, intent, c.instance, c.nextcloud_jail, intent["executor_sha256"])
    if (c != bound or deployment.registry.root != registry.root
            or deployment.state != registry.instance_path(c.instance)):
        raise ValueError(DENIED)
    enrollment._source(deployment)  # Includes the unmodified original-artifact gate.
    enrollment._inputs(deployment)
    store = Store(registry.root)
    for filename, digest in plan["assessment"]["artifacts"].items():
        path = (plan["originals"][c.instance]["config"]["path"] if filename == "config.json"
                else "instances/" + c.instance + "/" + filename)
        if _hash(store._read(path)) != digest:
            raise ValueError(DENIED)
    journal = Journal(deployment.state / "deployment.json", c)
    steps = journal.data["steps"]
    required = {"instance ZFS storage", "private networking and PF", "FreeBSD jail roots",
                "persistent mounts", "Nextcloud publication", "readiness checks", "boot activation"}
    if not required.issubset(steps) or any(item.get("state") != "complete" for item in steps.values()):
        raise ValueError(DENIED)
    deployment.validate_resume(journal)
    pair = {c.nextcloud_jail, c.onlyoffice_jail}
    if {name for name, _ in _checked_jails(deployment)} != pair:
        raise ValueError(DENIED)
    # This source-rendered probe has no lifecycle recursion and performs no writes.
    # The actual exec.prepare still runs its ordinary storage/PF checks on start.
    for name in sorted(pair):
        deployment.runner.run("/bin/sh", "-s", "--", name,
                              input=storage_guard(c, deployment.storage, registry.root, lifecycle=False),
                              hide_output=True)
    return _live_pair(deployment)


@contextmanager
def validation_starts(registry, deployment, intent, plan):
    """Start only missing exact targets; yield for recheck; clean up on failure.

    Existing live jails are never stopped. A newly started jail is stopped only
    while its original numeric JID, root, hostname and owned inventory still match.
    Successful validation leaves the pair running for enrollment completion.
    """
    from .lifecycle import _checked_jails

    with start_permission(registry, intent, plan):
        before = _preflight(deployment, registry, intent, plan)
        started = {}
        pair = (deployment.config.nextcloud_jail, deployment.config.onlyoffice_jail)
        try:
            for name in pair:
                current = _live_pair(deployment)
                if any(current.get(jail) != jid for jail, jid in {**before, **started}.items()):
                    raise ValueError(DENIED)
                if name in before:
                    continue
                if name in current:
                    raise ValueError(DENIED)
                if {jail for jail, _ in _checked_jails(deployment, (name,), stopped=True)} != {name}:
                    raise ValueError(DENIED)
                try:
                    deployment.runner.run("bastille", "start", name, hide_output=True)
                finally:
                    # Bastille can report failure after creating the jail. Record
                    # only an exact live identity; never guess a JID for cleanup.
                    live = _live_pair(deployment)
                    if name in live:
                        started[name] = live[name]
                if name not in started:
                    raise ValueError(DENIED)
            yield
        except BaseException:
            for name, jid in reversed(tuple(started.items())):
                try:
                    if (_live_pair(deployment).get(name) == jid
                            and {jail for jail, _ in _checked_jails(deployment, (name,))} == {name}
                            and deployment.require_running_jail(name) == jid):
                        deployment.runner.run("bastille", "stop", name, hide_output=True)
                except (OSError, RuntimeError, ValueError):
                    # Identity uncertainty must not stop a replacement/unrelated
                    # jail. Keep the durable pending fence and propagate failure.
                    continue
            raise
