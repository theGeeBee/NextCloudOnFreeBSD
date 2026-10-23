"""Fail-closed, source-bound legacy enrollment evidence and boot fencing.

This module never adopts observed state as intended state during enrollment.
Only a first-install baseline can supply the static identities absent from the
schema-2 inventory. ``check``'s ``eligible`` flag MUST gate enrollment.
The caller holds the host operation lock for checking and all guard operations.
No helper stops a jail, rewrites a staged worker, or relaxes Deployment's source
gate.  Historical artifacts have no reviewed adapter here.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat

from . import firewall
from .deploy import source_digest
from .network import storage_guard
from .paths import PROJECT_ROOT
from .state import Journal, atomic_json, atomic_write, config_digest


LIBEXEC = Path("/usr/local/libexec")
ADAPTER = "current-schema2-ready-v1"
BASELINE = "enrollment-baseline.json"
STATIC_ROOTS = ("etc", "usr/local/etc", "root/cloud-installer", "bin", "sbin", "lib", "libexec",
                "usr/bin", "usr/sbin", "usr/lib", "usr/libexec", "usr/include", "usr/share",
                "usr/local/bin", "usr/local/sbin", "usr/local/lib", "usr/local/libexec",
                "usr/local/llvm19", "usr/local/share")


def _exists(path):
    return path.exists() or path.is_symlink()


def _directory(path, *, private=False):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("Enrollment paths must be absolute and traversal-free")
    for item in (*reversed(path.parents), path):
        info = item.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022
                and not (info.st_mode & stat.S_ISVTX)):
            raise ValueError("Unsafe enrollment directory")
    info = path.lstat()
    if info.st_uid != os.geteuid() or (private and info.st_mode & 0o077):
        raise ValueError("Unsafe enrollment directory ownership or mode")
    return path


def _bytes(path, *, private=True):
    path = Path(path)
    _directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_mode & (0o077 if private else 0o022)
                or info.st_size > 16 * 1024 * 1024):
            raise ValueError("Unsafe enrollment evidence file")
        data = stream.read(16 * 1024 * 1024 + 1)
        after = os.fstat(stream.fileno())
        if (len(data) != info.st_size or len(data) > 16 * 1024 * 1024
                or (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError("Enrollment evidence changed during read")
        return data


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def _json(path):
    try:
        from .generations import _json as strict_json
        value = strict_json(_bytes(path))
    except (UnicodeError, ValueError):
        raise ValueError("Invalid enrollment evidence JSON") from None
    if not isinstance(value, dict):
        raise ValueError("Enrollment evidence must be an object")
    return value


def _source(deployment):
    # This is deliberately the unmodified, read-only Deployment gate.
    deployment.require_original_artifact()
    root = _directory(PROJECT_ROOT)
    for name in ("installer", "resources"):
        _directory(root / name)
        for path in (root / name).rglob("*"):
            if "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            if path.is_symlink():
                raise ValueError("Source-bound adapter refuses linked payloads")
            if path.is_dir():
                _directory(path)
            else:
                _bytes(path, private=False)
    return source_digest().strip()


def _inputs(deployment):
    """Compare the exact verify_source input recipe, without its atomic writes."""
    from .host import read_private
    c = deployment.config
    if _json(deployment.state / "secrets.json") != deployment.secrets:
        raise ValueError("Enrollment credential input binding changed")
    digest = hashlib.sha256(json.dumps(deployment.secrets, sort_keys=True).encode())
    for field in ("certificate_file", "private_key_file", "ca_file", "ssh_key_file"):
        filename = getattr(c, field)
        if filename:
            path = Path(filename)
            _directory(path.parent)
            if path.is_symlink() or not path.is_file():
                raise ValueError("Enrollment input is not an original regular file")
            digest.update(field.encode() + b"\0" + path.read_bytes())
    if c.additional_fonts_dir:
        directory = _directory(c.additional_fonts_dir)
        for path in sorted(directory.rglob("*")):
            if path.is_symlink():
                raise ValueError("Enrollment font input is linked")
            if path.is_file():
                digest.update(str(path.relative_to(directory)).encode() + b"\0")
                with path.open("rb") as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(block)
    if read_private(deployment.state / "inputs.sha256") != digest.hexdigest() + "\n":
        raise ValueError("Enrollment original inputs changed")


def _idle(deployment):
    root, state = deployment.registry.root, deployment.state
    if firewall.pending_transactions(root):
        raise ValueError("Enrollment refused: unresolved network transaction")
    from .generations import Store
    if Store(root).pending() is not None:
        raise ValueError("Enrollment refused: pending maintenance or recovery")
    for path in (state / "allow-start.initialization-recovery",):
        if _exists(path):
            raise ValueError("Enrollment refused: pending maintenance or recovery")
    if any(state.glob("allow-start.enrollment-*")):
        raise ValueError("Enrollment refused: retained enrollment boot fence")
    for name in ("restore.json", "removal.json", "purge.json"):
        path = state / name
        if _exists(path):
            # Even completed restore/removal needs a separate reviewed adapter.
            raise ValueError("Enrollment of restored/removed state has no reviewed adapter")
    path = state / "initialization.json"
    if _exists(path):
        record = _json(path)
        recoveries = record.get("recoveries", [])
        if (record.get("state") != "complete" or not isinstance(recoveries, list)
                or any(not isinstance(item, dict) or item.get("state") != "complete" for item in recoveries)):
            raise ValueError("Enrollment refused: unresolved initialization recovery")


def _packages(deployment, retained):
    """Read packages through the existing checked numeric-JID execution path."""
    c = deployment.config
    expected = retained.get("package_versions")
    if not isinstance(expected, dict) or set(expected) != {c.nextcloud_jail, c.onlyoffice_jail}:
        raise ValueError("Enrollment needs original jail package inventories")
    result = {}
    for jail, group in ((c.nextcloud_jail, "nextcloud"), (c.onlyoffice_jail, "onlyoffice")):
        output = deployment.jail(jail, "pkg", "query", "%n %v %o", hide_output=True).stdout
        rows = [line.split() for line in output.splitlines() if line.strip()]
        if not rows or any(len(row) != 3 for row in rows) or len({row[0] for row in rows}) != len(rows):
            raise ValueError("Enrollment package inventory is empty or ambiguous")
        lines = sorted(" ".join(row) for row in rows)
        if not isinstance(expected[jail], list) or lines != sorted(expected[jail]):
            raise ValueError("Enrollment package inventory drift")
        inventory = {name: (version, origin) for name, version, origin in rows}
        locked = deployment.versions["packages"][group]
        if any(inventory.get(name) != (item["version"], item["origin"]) for name, item in locked.items()):
            raise ValueError("Enrollment package lock drift")
        extras = set(inventory) - set(locked) - {"pkg"}
        if any(not re.fullmatch(r"FreeBSD-[A-Za-z0-9_+.-]+", name)
               or inventory[name][1] != "base/" + name for name in extras):
            raise ValueError("Enrollment has unlocked jail packages")
        result[group] = _hash(json.dumps(lines).encode())
    for name, record in deployment.versions["packages"]["host"].items():
        if deployment.runner.output("pkg", "query", "%v|%o", name) != record["version"] + "|" + record["origin"]:
            raise ValueError("Enrollment host package lock drift")
    return result


def _plugins(deployment):
    """Reject unowned plugin files even when no optional plugins were selected.

    Packaged plugin paths come from pkg's retained file inventory. Selected trees
    are verified by the existing read-only plugin verifier. This is only plugin
    evidence, not a substitute for an exhaustive application/config baseline.
    """
    from .plugins import verify
    c = deployment.config
    jail = c.onlyoffice_jail
    prefix = "/usr/local/www/onlyoffice/documentserver/sdkjs-plugins"
    packaged = deployment.jail(jail, "pkg", "query", "%Fp", "onlyoffice-documentserver",
                               hide_output=True).stdout.splitlines()
    allowed = {line[len(prefix) + 1:] for line in packaged if line.startswith(prefix + "/")}
    if not allowed or any(".." in Path(name).parts for name in allowed):
        raise ValueError("Enrollment cannot establish packaged plugin paths")
    root = deployment.jail_root(jail) / prefix.lstrip("/")
    _directory(root)
    if c.onlyoffice_plugins:
        lock = deployment.plugin_lock
        verify(lock, root, deployment.jail_root(jail) / "var/db/cloud-installer-onlyoffice/plugins")
        for slug, record in lock["plugins"].items():
            allowed.update(slug + "/" + name for name in record["tree"])
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink() or (not path.is_dir() and not path.is_file()):
            raise ValueError("Enrollment cannot authenticate linked/special plugin paths")
        if path.is_file() and relative not in allowed:
            raise ValueError("Enrollment refused: unselected or unowned ONLYOFFICE plugin drift")
        if path.is_dir() and not any(name.startswith(relative + "/") for name in allowed):
            raise ValueError("Enrollment refused: unselected ONLYOFFICE plugin directory")


def check(deployment):
    """Return secret-free retained evidence; never authorize incomplete proof.

    Native commands here are read-only. Do NOT substitute Deployment.verify(),
    validate_resume actions, or verify_source(): some verification/provisioning
    paths can write reports, source bindings or service state. Exceptions contain
    fixed diagnostics, never native output or decoded credential/config values.
    """
    state = _directory(deployment.state, private=True)
    if _exists(state / "enrollment-unavailable.json"):
        raise ValueError("First-readiness enrollment evidence was unavailable; no retrospective enrollment is supported")
    source = _source(deployment)
    _idle(deployment)
    if deployment.config.schema_version != 2 or _json(state / "status.json").get("state") != "ready":
        raise ValueError("Enrollment requires a ready schema-2 legacy instance")
    if _json(state / "config.json") != json.loads(deployment.config.to_json()):
        raise ValueError("Enrollment original configuration changed")
    journal = Journal(state / "deployment.json", deployment.config)
    required = {"instance ZFS storage", "private networking and PF", "FreeBSD jail roots",
                "persistent mounts", "Nextcloud publication", "readiness checks", "boot activation"}
    steps = journal.data["steps"]
    if not required.issubset(steps) or any(record.get("state") != "complete" for record in steps.values()):
        raise ValueError("Enrollment needs a complete original deployment journal")
    names = ["config.json", "status.json", "deployment.json", "versions.json", "inventory.json",
             "source.sha256", "inputs.sha256", "complete", "allow-start"]
    artifacts = {name: _hash(_bytes(state / name)) for name in names}
    # Reload the retained lock, rather than trust a caller's cached plan.
    from .resolution import validate_plan
    plan = validate_plan(deployment.config, _json(state / "versions.json"))
    if deployment.versions != plan:
        raise ValueError("Enrollment cached version lock differs from original evidence")
    if deployment.config.onlyoffice_plugins:
        deployment.plugin_lock
        artifacts["plugins.json"] = _hash(_bytes(state / "plugins.json"))
    elif _exists(state / "plugins.json"):
        raise ValueError("Enrollment has an unselected plugin lock")
    _inputs(deployment)
    # validate_resume only probes ownership, PF and jail identity; it does not
    # replay Journal.run's provisioning checks.
    deployment.validate_resume(journal)
    for jail in (deployment.config.nextcloud_jail, deployment.config.onlyoffice_jail):
        deployment.require_running_jail(jail)
    packages = _packages(deployment, _json(state / "inventory.json"))
    _plugins(deployment)
    baseline = _json(state / BASELINE) if _exists(state / BASELINE) else None
    if baseline is not None:
        expected = _baseline_bindings(deployment)
        if (set(baseline) != {*expected, "observation"}
                or any(baseline.get(key) != value for key, value in expected.items())
                or not isinstance(baseline.get("observation"), dict)):
            raise ValueError("Enrollment baseline provenance changed")
        if baseline["observation"] != _observe(deployment):
            raise ValueError("Enrollment resource/package/application/configuration drift")
        artifacts[BASELINE] = _hash(_bytes(state / BASELINE))
    for name, digest in artifacts.items():
        if _hash(_bytes(state / name)) != digest:
            raise ValueError("Enrollment evidence changed during assessment")
    if _source(deployment) != source:
        raise ValueError("Enrollment executor changed during assessment")
    return {"schema": 1, "adapter": ADAPTER, "instance": deployment.config.instance,
            "source_sha256": source, "config_sha256": config_digest(deployment.config),
            "artifacts": artifacts, "package_inventory_sha256": packages,
            "eligible": baseline is not None,
            "blockers": [] if baseline is not None else ["missing-original-first-readiness-baseline"],
            "coverage": "first-readiness-static-identity-comparison" if baseline is not None
                        else "retained-provenance-and-partial-read-only-drift-checks"}


def _baseline_bindings(deployment):
    from .maintenance import executor_identity
    return {"schema": 1, "adapter": ADAPTER, "origin": "first-install-readiness",
            "instance": deployment.config.instance, "source_sha256": _source(deployment),
            "executor_sha256": executor_identity(), "config_sha256": config_digest(deployment.config),
            "versions_sha256": _hash(_bytes(deployment.state / "versions.json")),
            "inputs_sha256": _hash(_bytes(deployment.state / "inputs.sha256")),
            "plugins_sha256": _hash(_bytes(deployment.state / "plugins.json"))
            if deployment.config.onlyoffice_plugins else None}


def _jail_link(path, jail_root):
    """Resolve link identity using jail-absolute, never host-absolute, semantics."""
    pending = list(path.relative_to(jail_root).parts)
    resolved, links = [], 0
    while pending:
        part = pending.pop(0)
        if part in ("", "."):
            continue
        if part == "..":
            if not resolved:
                raise ValueError("Static identity link escapes jail root")
            resolved.pop()
            continue
        candidate = jail_root.joinpath(*resolved, part)
        info = candidate.lstat()
        if stat.S_ISLNK(info.st_mode):
            links += 1
            if links > 40:
                raise ValueError("Static identity link cycle")
            target = Path(os.readlink(candidate))
            if target.is_absolute():
                resolved = []
                pending = list(target.parts[1:]) + pending
            else:
                pending = list(target.parts) + pending
        else:
            if pending and not stat.S_ISDIR(info.st_mode):
                raise ValueError("Invalid static identity link path")
            resolved.append(part)
    return jail_root.joinpath(*resolved)


def _tree_identity(root, *, jail_root=None, observed_roots=()):
    """Hash bounded static trees, including names, modes, uid/gid and link text.

    No timestamps or mutable data roots are read. Symlinks must resolve within
    the same static tree or another explicitly observed jail tree; unknown
    layouts fail closed. File contents never leave the
    hash accumulator, including app credentials and TLS keys.
    """
    root = Path(root)
    if (not root.is_absolute() or ".." in root.parts or root.is_symlink() or not root.is_dir()
            or any(parent.is_symlink() for parent in root.parents)):
        raise ValueError("Missing or linked static identity root")
    digest, total, count, records = hashlib.sha256(), 0, 0, []
    import itertools
    for path in itertools.chain((root,), root.rglob("*")):
        count += 1
        if count > 250000:
            raise ValueError("Enrollment static identity exceeds its entry bound")
        before = path.lstat()
        identity = [str(path.relative_to(root)), stat.S_IMODE(before.st_mode), before.st_uid, before.st_gid]
        if stat.S_ISLNK(before.st_mode):
            target = os.readlink(path)
            try:
                if jail_root is None:
                    if Path(target).is_absolute():
                        raise ValueError("Unreviewed absolute symlink in static identity")
                    path.resolve(strict=True).relative_to(root)
                else:
                    jail_root = Path(jail_root)
                    broken_font = _reviewed_broken_font_link(path, jail_root, target)
                    runtime_motd = path == jail_root / "etc/motd" and target == "/var/run/motd"
                    if broken_font or runtime_motd:
                        # Ghostscript installs compatibility links for optional
                        # CJK font packages. Their exact absent targets are inert;
                        # an installed target would instead need static coverage.
                        pass
                    else:
                        destination = _jail_link(path, jail_root)
                    if broken_font:
                        pass
                    elif runtime_motd:
                        # FreeBSD rc.d/motd maintains this runtime presentation
                        # file. Bind the reviewed link itself, not mutable /var.
                        pass
                    elif (path == jail_root / "etc/os-release" and target == "../var/run/os-release"
                            and destination == Path(jail_root) / "var/run/os-release"):
                        # FreeBSD releng/15.1 etc/Makefile and rc.d/os-release:
                        # this one generated identity file is derived from -u.
                        # Bind its bytes without scanning arbitrary /var/run.
                        release = _bytes(destination, private=False)
                        if len(release) > 16384:
                            raise ValueError("Oversized FreeBSD release identity")
                        identity.extend(["freebsd-os-release", _hash(release)])
                    elif not any(destination == tree or tree in destination.parents for tree in observed_roots):
                        raise ValueError("Link target is not covered by static observation")
            except (ValueError, OSError, RuntimeError):
                raise ValueError("Unreviewed escaping or broken static identity symlink") from None
            identity.extend(["link", target])
        elif stat.S_ISDIR(before.st_mode):
            identity.append("directory")
        elif stat.S_ISREG(before.st_mode):
            total += before.st_size
            if before.st_size > 512 * 1024 * 1024 or total > 8 * 1024**3:
                raise ValueError("Enrollment static identity exceeds its file bound")
            content = hashlib.sha256()
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as stream:
                opened = os.fstat(stream.fileno())
                if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                    raise ValueError("Static identity changed while opening")
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    content.update(block)
            # Native pkgbase includes hardlinked tools. Bind their count and
            # bytes; private host registry records still forbid hardlinks.
            identity.extend(["file", before.st_nlink, content.hexdigest()])
        else:
            raise ValueError("Unreviewed special file in static identity")
        after = path.lstat()
        if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("Static identity changed during observation")
        # Accumulate bounded records, then sort below: filesystem traversal
        # order is not an identity and must not cause false drift.
        records.append(json.dumps(identity, separators=(",", ":")))
    for record in sorted(records):
        digest.update(record.encode() + b"\0")
    return digest.hexdigest()


_GHOSTSCRIPT_LINKS = {
    "GothicBBB-Medium": "/usr/local/share/fonts/std.ja_JP/GothicBBB-Medium",
    "GothicBBB-Medium.gs7": "/usr/local/share/fonts/std.ja_JP/GothicBBB-Medium.gs7",
    "MSung-Light": "/usr/local/share/fonts/std.zh_CN/MSung-Light",
    "Ryumin-Light": "/usr/local/share/fonts/std.ja_JP/Ryumin-Light",
    "Ryumin-Light.gs7": "/usr/local/share/fonts/std.ja_JP/Ryumin-Light.gs7",
    "STHeiti-Regular": "/usr/local/share/fonts/std.zh_CN/STHeiti-Regular",
    "STSong-Light": "/usr/local/share/fonts/std.zh_CN/STSong-Light",
}


def _reviewed_broken_font_link(path, jail_root, target):
    parent = jail_root / "usr/local/share/ghostscript/fonts"
    expected = _GHOSTSCRIPT_LINKS.get(path.name)
    if path.parent != parent or target != expected:
        return False
    destination = jail_root / target.lstrip("/")
    if destination.exists() or destination.is_symlink():
        raise ValueError("Optional Ghostscript compatibility target must be statically observed when installed")
    return True


def _query_identity(result):
    value = result.stdout
    if result.returncode or not isinstance(value, str) or not value.strip() or len(value) > 16 * 1024 * 1024:
        raise ValueError("Enrollment identity query failed or returned empty/unbounded output")
    return value


def _observe(deployment, *, intent=None):
    """Read only static code/configuration identities and native inventory.

    Application data, DB contents, logs, runtime caches and timestamps are not
    baselines. All installed NC apps (enabled AND disabled) are included. The
    full app configuration is hashed conservatively: even an unexplained change
    to a background-job setting blocks enrollment rather than being adopted.
    """
    return _observe_inventory(deployment, intent=intent, include_trees=True)


def _observe_non_tree(deployment):
    """Private inventory component, NOT authenticated admission evidence.

    SourceAdmission brackets this with its own full tree checks in one locked
    call. No caller-supplied tree inventory or reusable verification token is
    accepted. Ordinary enrollment always uses _observe and scans its trees.
    """
    return _observe_inventory(deployment, intent=None, include_trees=False)


def _observe_inventory(deployment, *, intent, include_trees):
    c = deployment.config
    observation = {"packages": {}, "base": {}, "resources": {}}
    if include_trees:
        observation["trees"] = {}
    original, _ = _guard_paths(deployment)
    if _bytes(original, private=False) != storage_guard(c, deployment.storage, deployment.registry.root).encode():
        raise ValueError("Unreviewed storage guard during baseline observation")
    for jail, application in ((c.nextcloud_jail, "nextcloud"), (c.onlyoffice_jail, "onlyoffice/documentserver")):
        jid = deployment.require_running_jail(jail)
        # Existing guard proves actual dataset/mount ownership, active PF,
        # bridge membership and filtering before reading application trees.
        if intent is None:
            deployment.runner.run(str(original), jail, hide_output=True)
        else:
            from .generations import Store
            from .maintenance import executor_identity
            if (Store(deployment.registry.root).pending() != intent
                    or intent.get("action") != "enroll" or c.instance not in intent["instances"]
                    or intent["executor_sha256"] != executor_identity()):
                raise ValueError("Read-only enrollment probe requires its exact pending intent")
            # Validate storage/PF under the still-closed boot fence. This script
            # contains probes only: it cannot grant exec.prepare/start permission
            # or invoke a worker. The unchanged on-disk guard still denies boot.
            deployment.runner.run("/bin/sh", "-s", "--", jail,
                                  input=storage_guard(c, deployment.storage, deployment.registry.root,
                                                      lifecycle=False), hide_output=True)
        root = deployment.jail_root(jail)
        if include_trees:
            roots = (*STATIC_ROOTS, "usr/local/www/" + application)
            if (root / "etc/unbound").is_symlink() and os.readlink(root / "etc/unbound") == "../var/unbound":
                # The same reviewed FreeBSD Makefile installs this config-directory
                # link. Include that exact target, not all mutable /var state.
                roots += ("var/unbound",)
            observed_roots = tuple(root / name for name in roots)
            observation["trees"][jail] = {name: _tree_identity(root / name, jail_root=root,
                                                              observed_roots=observed_roots) for name in roots}
        observation["packages"][jail] = _hash(_query_identity(deployment.jail(
            jail, "pkg", "query", "%n|%v|%o|%q", hide_output=True)).encode())
        observation["base"][jail] = _query_identity(deployment.jail(
            jail, "freebsd-version", "-u", hide_output=True)).strip()
        for key, args in (("configured_hostname", ("jls", "-j", jail, "host.hostname")),):
            observation["resources"][jail + ":" + key] = _query_identity(deployment.runner.run(*args, hide_output=True)).strip()
        observation["resources"][jail + ":hostname"] = _query_identity(deployment.jail(jail, "hostname", hide_output=True)).strip()
        jaildir = root.parent
        # boot is deliberately enabled after readiness, and exec.prepare changes
        # during enrollment. Those fields have explicit guard/identity checks;
        # hashing the whole jail.conf would classify our own transition as drift.
        for name in ("fstab",):
            observation["resources"][jail + ":" + name] = _hash(_bytes(jaildir / name, private=False))
        if deployment.require_running_jail(jail) != jid:
            raise ValueError("Jail restarted during enrollment observation")
    for args in (("freebsd-version", "-kru"), ("uname", "-m", "-p"), ("uname", "-K", "-U")):
        observation["base"]["host:" + " ".join(args)] = _query_identity(deployment.runner.run(*args, hide_output=True)).strip()
    observation["packages"]["host"] = _hash(_query_identity(deployment.runner.run(
        "pkg", "query", "%n|%v|%o|%q", hide_output=True)).encode())
    # Host OS/package identities are recorded above. This is not a whole-host
    # filesystem integrity monitor: unrelated host files and later instances'
    # shared PF/rc settings must not become this instance's immutable config.
    resources = [item.name for item in deployment.storage]
    resources.extend(f"{c.bastille_dataset}/jails/{jail}/root" for jail in (c.nextcloud_jail, c.onlyoffice_jail))
    for name in resources:
        observation["resources"][name] = _query_identity(deployment.runner.run(
            "zfs", "get", "-Hp", "-o", "property,value", "guid,mountpoint,mounted,org.cloud-installer:instance",
            name, hide_output=True)).strip()
    mounts = _query_identity(deployment.runner.run("mount", "-p", hide_output=True))
    roots = [str(deployment.jail_root(jail)) for jail in (c.nextcloud_jail, c.onlyoffice_jail)]
    roots.extend(item.mountpoint for item in deployment.storage)
    rows = [line.split() for line in mounts.splitlines() if line.strip()]
    if any(len(row) != 6 for row in rows):
        raise ValueError("Ambiguous enrollment mount topology")
    relevant = sorted(" ".join(row) for row in rows
                      if any(row[1] == root or row[1].startswith(root + "/") for root in roots))
    if not relevant:
        raise ValueError("Missing enrollment mount topology")
    observation["resources"]["mounts"] = _hash(json.dumps(relevant).encode())
    for command in (("app:list", "--output=json"), ("config:list", "--private", "--output=json")):
        raw = _query_identity(deployment.jail(c.nextcloud_jail, "mdo", "-u", "www", "php",
                              "/usr/local/www/nextcloud/occ", *command, hide_output=True, timeout=60))
        try:
            value = json.loads(raw)
        except ValueError:
            raise ValueError("Invalid Nextcloud identity JSON") from None
        if not isinstance(value, dict) or not value:
            raise ValueError("Empty Nextcloud identity JSON")
        if command[0] == "app:list" and (set(value) != {"enabled", "disabled"}
                or not isinstance(value["enabled"], dict) or not value["enabled"]
                or not isinstance(value["disabled"], (dict, list))):
            raise ValueError("Invalid complete Nextcloud app inventory")
        if command[0] == "config:list":
            # App configuration also contains normal last-run/update timestamps.
            # Bind system config plus this installer's connector settings, not
            # volatile background-job state. Unknown app *code* is still covered
            # by the full app list/tree comparison.
            apps = value.get("apps")
            if not isinstance(value.get("system"), dict) or not isinstance(apps, dict):
                raise ValueError("Invalid Nextcloud configuration identity")
            connector = apps.get("onlyoffice")
            if not isinstance(connector, dict):
                raise ValueError("Missing Nextcloud connector configuration")
            value = {"system": value["system"], "onlyoffice": connector}
        observation[command[0]] = _hash(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())
    return observation


def capture_baseline(deployment):
    """Seal once during first installation readiness, never retrofit on Resume.

    Parent calls AFTER successful Deployment.verify(), inside the original first
    readiness Journal step, before boot activation. A resumed/published instance
    without this record remains ineligible. The baseline is private metadata,
    not a data snapshot or a claim of native acceptance.
    """
    state = _directory(deployment.state, private=True)
    if _exists(state / BASELINE):
        raise ValueError("Enrollment baseline is immutable; never recapture it")
    _source(deployment)
    _idle(deployment)
    _inputs(deployment)
    journal = Journal(state / "deployment.json", deployment.config)
    step = journal.data["steps"].get("readiness checks", {})
    if (_json(state / "status.json").get("state") != "installing"
            or _exists(state / "complete") or "boot activation" in journal.data["steps"]
            or step.get("state") != "running" or step.get("attempt") != 1):
        raise ValueError("Baseline capture requires the first installation readiness attempt")
    _packages(deployment, deployment.manifest)
    _plugins(deployment)
    bindings = _baseline_bindings(deployment)
    observation = _observe(deployment)
    # A moving configuration is not a coherent initial intended identity.
    if observation != _observe(deployment) or bindings != _baseline_bindings(deployment):
        raise ValueError("Initial enrollment identity is not stable")
    atomic_json(state / BASELINE, {**bindings, "observation": observation})
    return {"baseline_sha256": _hash(_bytes(state / BASELINE))}


def recheck(deployment, *, intent):
    """Revalidate live identity before completing a recorded enrollment.

    The orchestrator supplies a read-only view of hash-bound pre-intent config;
    mutable evidence and the live environment must still agree with the original
    baseline. This never rebuilds evidence or enables a jail.
    """
    _source(deployment)
    _inputs(deployment)
    journal = Journal(deployment.state / "deployment.json", deployment.config)
    deployment.validate_resume(journal)
    _packages(deployment, _json(deployment.state / "inventory.json"))
    _plugins(deployment)
    baseline = _json(deployment.state / BASELINE)
    expected = _baseline_bindings(deployment)
    if (set(baseline) != {*expected, "observation"}
            or any(baseline.get(key) != value for key, value in expected.items())
            or baseline["observation"] != _observe(deployment, intent=intent)):
        raise ValueError("Enrollment recovery cannot establish original live identity")


def _marker(deployment, operation):
    if not isinstance(operation, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", operation):
        raise ValueError("Invalid enrollment operation identifier")
    _directory(deployment.state, private=True)
    return deployment.state / ("allow-start.enrollment-" + operation)


def _sync(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def fence_start(deployment, *, operation):
    """Close the old shell guard before intent/lookup changes; retry is safe.

    Caller fences EVERY instantiated legacy pair before first host enrollment.
    A missing original and retained marker is ambiguous and refused. No marker
    is synthesized, deleted or overwritten, and running jails are untouched.
    """
    retained = _marker(deployment, operation)
    original = deployment.state / "allow-start"
    others = set(deployment.state.glob("allow-start.enrollment-*")) - {retained}
    if others:
        raise ValueError("Another enrollment owns the boot fence")
    if _exists(retained):
        data = _bytes(retained)
        if _exists(original):
            raise ValueError("Ambiguous enrollment boot permission")
    else:
        data = _bytes(original)
        os.rename(original, retained)
    _sync(deployment.state)
    return {"marker": retained.name, "sha256": _hash(data)}


def restore_start(deployment, *, operation):
    """Restore permission ONLY after caller proves graph commit and both guards.

    The durable operation must record this step. Missing retained markers are
    not silently accepted as a completed restore; recovery inspects its journal.
    """
    retained = _marker(deployment, operation)
    original = deployment.state / "allow-start"
    _bytes(retained)
    if _exists(original):
        raise ValueError("Refusing to overwrite boot permission")
    os.rename(retained, original)
    _sync(deployment.state)


def _guard_paths(deployment):
    instance = deployment.config.validate().instance
    return LIBEXEC / (instance + "-storage-guard"), LIBEXEC / (instance + "-lifecycle-guard")


def guard_text(deployment, *, dispatcher):
    """Render a separate source-pinned wrapper; dispatcher is a trusted script.

    Calls maintenance.boot_check(root, instance, jail, executor). It must resolve
    the committed graph and refuse pending/invalid state. It runs with this
    source root on sys.path, isolated Python, and bytecode disabled.
    The shell then execs the unchanged, hash-pinned original storage guard.
    """
    source = _source(deployment)
    dispatcher = Path(dispatcher)
    if dispatcher != PROJECT_ROOT / "installer/maintenance.py":
        raise ValueError("Enrollment dispatcher must belong to the bound artifact")
    _bytes(dispatcher, private=False)
    from .maintenance import executor_identity
    executor = executor_identity()
    original, _ = _guard_paths(deployment)
    old = _bytes(original, private=False)
    if old != storage_guard(deployment.config, deployment.storage, deployment.registry.root).encode():
        raise ValueError("Original storage guard differs from its source-bound rendering")
    # Validate source bytes BEFORE executing imports from that source. Reusing
    # deploy.source_digest alone here would first execute possibly changed code.
    program = "\n".join([
        "import hashlib, importlib.machinery, os, pathlib, stat, sys",
        f"root = pathlib.Path({str(PROJECT_ROOT)!r})",
        "digest = hashlib.sha256()",
        "for directory in (root / 'installer', root / 'resources'):",
        "    for parent in (*reversed(directory.parents), directory):",
        "        info = parent.lstat()",
        "        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022: raise SystemExit(1)",
        "    for path in sorted(directory.rglob('*')):",
        "        if '__pycache__' in path.parts or path.suffix == '.pyc': continue",
        "        info = path.lstat()",
        "        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022: raise SystemExit(1)",
        "        if stat.S_ISDIR(info.st_mode): continue",
        "        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1: raise SystemExit(1)",
        "        digest.update(str(path.relative_to(root)).encode() + b'\\0' + path.read_bytes())",
        f"if digest.hexdigest() != {source!r}: raise SystemExit(1)",
        "entry = root / 'install.sh'",
        "info = entry.lstat()",
        "if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1: raise SystemExit(1)",
        f"if hashlib.sha256((digest.hexdigest() + '\\n').encode() + entry.read_bytes()).hexdigest() != {executor!r}: raise SystemExit(1)",
        f"guard = pathlib.Path({str(original)!r})",
        "for parent in reversed(guard.parents):",
        "    info = parent.lstat()",
        "    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022: raise SystemExit(1)",
        "info = guard.lstat()",
        "if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1: raise SystemExit(1)",
        f"if hashlib.sha256(guard.read_bytes()).hexdigest() != {_hash(old)!r}: raise SystemExit(1)",
        f"if sys.argv[1:] not in ([{deployment.config.nextcloud_jail!r}], [{deployment.config.onlyoffice_jail!r}]): raise SystemExit(1)",
        # -B prevents writes, not reads of unchecked .pyc files. Compile source
        # directly so the verified source bytes are the executed module bytes.
        "importlib.machinery.SourceFileLoader.get_code = lambda loader, fullname: compile(loader.get_data(loader.path), loader.path, 'exec', dont_inherit=True)",
        "sys.path.insert(0, str(root))",
        "from installer.maintenance import boot_check",
        f"boot_check({str(deployment.registry.root)!r}, {deployment.config.instance!r}, sys.argv[1], {executor!r})",
    ])
    return ("#!/bin/sh\nset -eu\n[ \"$#\" = 1 ] || exit 1\n"
            + "/usr/local/bin/python3 -I -B -c " + shlex.quote(program) + ' "$1"\n'
            + "exec " + shlex.quote(str(original)) + ' "$1"\n')


def validate_guard(deployment, *, dispatcher):
    original, wrapper = _guard_paths(deployment)
    expected = guard_text(deployment, dispatcher=dispatcher)
    if _bytes(wrapper, private=False) != expected.encode() or not wrapper.stat().st_mode & stat.S_IXUSR:
        raise ValueError("Enrollment lifecycle guard differs from its bound artifact")
    for jail in (deployment.config.nextcloud_jail, deployment.config.onlyoffice_jail):
        if deployment.runner.output("bastille", "config", jail, "get", "exec.prepare") != f"{wrapper} {jail}":
            raise ValueError("Enrollment lifecycle prepare hook is not installed")
    return {"guard_sha256": _hash(expected.encode()), "storage_guard_sha256": _hash(_bytes(original, private=False))}


def validate_original_guard(deployment):
    """Pre-intent proof for EVERY existing resource jail on the managed host.

    The exact current renderer includes the pending-intent boot gate. Therefore
    Store.begin fences all checked old hooks before replacing either hook. A
    historical shell lacking that gate is not accepted by this adapter.
    """
    source = _source(deployment)
    original, _ = _guard_paths(deployment)
    data = _bytes(original, private=False)
    if (data != storage_guard(deployment.config, deployment.storage, deployment.registry.root).encode()
            or not original.stat().st_mode & stat.S_IXUSR):
        raise ValueError("Original storage guard lacks the exact current source-bound fence")
    for jail in (deployment.config.nextcloud_jail, deployment.config.onlyoffice_jail):
        if deployment.runner.output("bastille", "config", jail, "get", "path") != str(deployment.jail_root(jail)):
            raise ValueError("Enrollment jail root identity changed")
        if deployment.runner.output("bastille", "config", jail, "get", "exec.prepare") != f"{original} {jail}":
            raise ValueError("Enrollment original prepare hook differs")
    return {"source_sha256": source, "storage_guard_sha256": _hash(data)}


def install_guard(deployment, *, dispatcher, intent, operation=None):
    """Install after durable intent, with permission fenced; partial retry safe.

    ``intent`` must equal Store.pending() and bind the current executor identity.
    No failure path restores boot permission. The caller retains the pending
    operation until all host hooks, archival, graph publication and verification
    are complete. Existing staged code and the original shell remain untouched.
    """
    from .generations import Store
    from .maintenance import executor_identity
    if operation is not None:
        retained = _marker(deployment, operation)
        _bytes(retained)
        if _exists(deployment.state / "allow-start"):
            raise ValueError("Close the enrollment boot fence before installing hooks")
    _source(deployment)
    if (Store(deployment.registry.root).pending() != intent or not isinstance(intent, dict)
            or intent.get("executor_sha256") != executor_identity()
            or deployment.config.instance not in intent.get("instances", [])
            or intent.get("action") != "enroll"):
        raise ValueError("Enrollment guard needs its exact durable source-bound intent")
    original, wrapper = _guard_paths(deployment)
    text = guard_text(deployment, dispatcher=dispatcher)
    # Validate both identities and all old hooks before changing either hook.
    for jail in (deployment.config.nextcloud_jail, deployment.config.onlyoffice_jail):
        if deployment.runner.output("bastille", "config", jail, "get", "path") != str(deployment.jail_root(jail)):
            raise ValueError("Enrollment jail root identity changed")
        hook = deployment.runner.output("bastille", "config", jail, "get", "exec.prepare")
        if hook not in (f"{original} {jail}", f"{wrapper} {jail}"):
            raise ValueError("Enrollment refuses an unknown jail prepare hook")
    _directory(wrapper.parent)
    if _exists(wrapper):
        if _bytes(wrapper, private=False) != text.encode():
            raise ValueError("Enrollment refuses to overwrite another lifecycle guard")
    else:
        atomic_write(wrapper, text, mode=0o700)
    for jail in (deployment.config.nextcloud_jail, deployment.config.onlyoffice_jail):
        deployment.install_prepare_guard(jail, wrapper)
        if deployment.runner.output("bastille", "config", jail, "get", "exec.prepare") != f"{wrapper} {jail}":
            raise ValueError("Enrollment prepare hook read-back failed; boot fence remains closed")
    return validate_guard(deployment, dispatcher=dispatcher)
