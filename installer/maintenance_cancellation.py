"""Original-generation cancellation before capture, for the trusted harness only.

No snapshot is restored, removed, or represented as a complete recovery set. The
existing cancelled journal transition is used only after live original readiness.
The caller obtains actual operator input; this module never supplies consent.

Integration seams (owned by the native/fence coordinators): route an affected
pending intent with cancellation-request.json to boot_permission below, and refuse
quiesce/capture/migrate/recover once that request exists. No catalog is registered.
Continuation is same-boot only; a reboot during cancellation requires manual
assessment. A complete capture belongs to the separate recovery path, even when
migration has not started.
"""

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import itertools
import json
import os
from pathlib import Path
import re
import stat
from types import SimpleNamespace

from . import enrollment, maintenance_fence as fence, recovery_sets as recovery
from .generations import Store, _encode, _fields, _hash, _json
from .maintenance_native import SERVICES, _boot


DENIED = "Pre-capture cancellation refused; retain the pending fence and private evidence"
STEPS = ("close-original-writers", "original-runtime", "maintenance-off",
         "original-profile", "application-services", "original-readiness", "scheduled-services")
PREPARATION_EVENTS = ("staging-parent", "stage-artifacts", "import-release-key")
PREPARATION_FILES = {"update-prepared.json", "update-progress.json"} | {
    f"update-{event}-{state}.json" for event in PREPARATION_EVENTS for state in ("before", "after")}


def _require(value):
    if not value:
        raise ValueError(DENIED)


@dataclass(frozen=True)
class CancellationAssessment:
    eligible: bool
    blockers: tuple[str, ...]
    binding_sha256: str | None = None


def require_no_cancellation(n):
    """Native mutation entry guard; call before phase changes or capture effects."""
    _require(not n.store._present(n.directory + "/cancellation-request.json"))


def _history(journal):
    """Absence of a success marker is insufficient: reject every later attempt."""
    _require(journal["last_safe_phase"] in ("capture", "quiesced")
             and journal["phase"] in ("capture", "quiesced", "recovery-required")
             and not journal["publication_may_have_begun"]
             and not journal["recovery_publication_may_have_begun"]
             and not {"recovery_set", "restored_set", "graph", "readiness"}.intersection(journal["evidence"]))
    for event in journal["history"]:
        _require(event["phase"] in ("capture", "quiesced", "recovery-required")
                 and not {"recovery_set", "restored_set", "graph", "readiness"}.intersection(event["evidence"]))
        if event["step"] is not None:
            _require(event["name"] == "close-writers" and event["step"]["phase"] == "capture")
    _require(set(journal["steps"]) <= {"close-writers"})
    for step in journal["steps"].values():
        _require(step["phase"] == "capture" and step["replay"] == "never" and step["attempts"] == 1)


def _no_later_effects(store, directory):
    for path in store._path(directory).iterdir():
        name = path.name
        _require(not (name.startswith("update-") and name not in PREPARATION_FILES)
                 and not name.startswith(("publication-", "native-publication", "opening-", "descriptor-",
                                          "target-runtime-", "execution-successor", "execution-generation",
                                          "restored-", "validated-closed", "validation-started", "restore-original-",
                                          "reclose-", "reclosed-")))
        if name.startswith("checkpoint-") and name.endswith(".json"):
            _require(_json(store._read(directory + "/" + name))["phase"] == "capture-prepared")
    _require(not store._present(directory + "/recovery/restore.json"))
    path = directory + "/recovery/manifest.json"
    if store._present(path):
        value = _json(store._read(path))
        # A prepared manifest can exist before the atomic snapshot command. It
        # stays private audit evidence, never cancellation rollback authority.
        _require(value.get("state") == "prepared")
    _preparation_effects(store, directory)


def _preparation_effects(store, directory):
    """Validate the real checkpoint writer's records, including interrupted ones."""
    intent = None
    effects = {}
    for event in PREPARATION_EVENTS:
        before = None
        for state in ("before", "after"):
            path = f"{directory}/update-{event}-{state}.json"
            if not store._present(path):
                continue
            if intent is None:
                intent = store.reference(directory + "/intent.json")
            reference = store.reference(path)
            value = _json(store._bound(reference))
            _fields(value, "schema_version kind operation intent journal event state binding before")
            from .generations import _reference
            _reference(value["journal"], directory + "/native-journal.json")
            _require(type(value["schema_version"]) is int and value["schema_version"] == 1
                     and value["kind"] == "nextcloud-update-effect" and value["operation"] == directory.split("/")[-1]
                     and value["intent"] == intent and value["event"] == event and value["state"] == state
                     and type(value["binding"]) is str and len(value["binding"]) <= 4096)
            if event == "staging-parent":
                _require(Path(value["binding"]).is_absolute() and ".." not in Path(value["binding"]).parts)
            else:
                _require(re.fullmatch(r"[0-9a-f]{64}", value["binding"]) is not None)
            if state == "before":
                _require(value["before"] is None)
                before = (reference, value)
            else:
                _require(before is not None and value["before"] == before[0]
                         and value["journal"] == before[1]["journal"]
                         and (event == "stage-artifacts" or value["binding"] == before[1]["binding"]))
            effects[path] = reference
    ordered = (("staging-parent", "before"), ("staging-parent", "after"), ("stage-artifacts", "before"),
               ("import-release-key", "before"), ("import-release-key", "after"), ("stage-artifacts", "after"))
    present = [f"{directory}/update-{event}-{state}.json" in effects for event, state in ordered]
    _require(present == [True] * sum(present) + [False] * (len(present) - sum(present)))
    _require(len({_json(store._bound(ref))["journal"]["sha256"] for ref in effects.values()}) <= 1)
    path = directory + "/update-progress.json"
    if store._present(path):
        value = _json(store._read(path))
        _fields(value, "schema_version kind operation intent effect")
        _require(type(value["schema_version"]) is int and value["schema_version"] == 1
                 and value["kind"] == "nextcloud-update-progress" and value["operation"] == directory.split("/")[-1]
                 and intent is not None and value["intent"] == intent
                 and type(value["effect"]) is dict and value["effect"] == effects.get(value["effect"].get("path")))
        store._bound(value["effect"])
    # Missing/stale progress is possible after a checkpoint fsync failure. It
    # never hides forbidden effects: the complete directory was checked above.


def _mode(store, directory, journal):
    if store._present(directory + "/closed-profile.json"):
        return "partial-quiesce"
    _require(journal["phase"] == "capture" and not journal["steps"] and not journal["history"])
    for name in ("offline-acknowledgement.json", "original-services.json", "profile", "profile-apply.json",
                 "ingress-denied.json", "initial-closure.json", "current-shutdown.json", "recovery/manifest.json"):
        _require(not store._present(directory + "/" + name))
    _require(not any(p.name.startswith(("clean-shutdown-", "closure-", "checkpoint-"))
                     for p in store._path(directory).iterdir()))
    return "pre-quiesce"


def _maintenance_bytes(data):
    """Only Nextcloud's canonical top-level boolean may differ from readiness.

    Hash comparison to the authenticated first baseline still covers ALL bytes,
    including any other PHP code. Never execute a changed config to inspect it.
    Noncanonical/absent/duplicate maintenance settings fail conservatively.
    """
    pattern = rb"(?m)^  'maintenance' => (?:true|false),$"
    _require(len(data) <= 1024 * 1024 and len(re.findall(pattern, data)) == 1)
    return re.sub(pattern, b"  'maintenance' => false,", data)


def _tree_identity(root, *, jail_root, observed_roots, replacements=None, maintenance=False):
    """Enrollment's exact digest format, with checked maintenance-only projection.

    The digest MUST match the pre-intent first-readiness digest; this is never a
    new baseline. Replacements are exact persisted original/closed profile bytes.
    """
    root = Path(root)
    _require(root.is_absolute() and ".." not in root.parts and root.is_dir()
             and not root.is_symlink() and not any(p.is_symlink() for p in root.parents))
    replacements, records, total = replacements or {}, [], 0
    for count, path in enumerate(itertools.chain((root,), root.rglob("*")), 1):
        _require(count <= 250000)
        before = path.lstat()
        relative = str(path.relative_to(root))
        identity = [relative, stat.S_IMODE(before.st_mode), before.st_uid, before.st_gid]
        if stat.S_ISLNK(before.st_mode):
            target = os.readlink(path)
            try:
                destination = enrollment._jail_link(path, Path(jail_root))
            except (ValueError, OSError, RuntimeError):
                raise ValueError(DENIED) from None
            if (path == Path(jail_root) / "etc/os-release" and target == "../var/run/os-release"
                    and destination == Path(jail_root) / "var/run/os-release"):
                data = enrollment._bytes(destination, private=False)
                _require(len(data) <= 16384)
                identity.extend(["freebsd-os-release", _hash(data)])
            else:
                _require(any(destination == tree or tree in destination.parents for tree in observed_roots))
            identity.extend(["link", target])
        elif stat.S_ISDIR(before.st_mode):
            identity.append("directory")
        else:
            _require(stat.S_ISREG(before.st_mode))
            total += before.st_size
            _require(before.st_size <= 512 * 1024 * 1024 and total <= 8 * 1024**3)
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as stream:
                _require(enrollment_identity(os.fstat(stream.fileno())) == enrollment_identity(before))
                if relative in replacements or maintenance and relative == "config/config.php":
                    _require(before.st_size <= 1024 * 1024)
                    data = stream.read(1024 * 1024 + 1)
                    if relative in replacements:
                        original, closed = replacements[relative]
                        _require(data in (original, closed))
                        data = original
                    else:
                        data = _maintenance_bytes(data)
                    content = _hash(data)
                else:
                    digest = hashlib.sha256()
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(block)
                    content = digest.hexdigest()
                _require(enrollment_identity(os.fstat(stream.fileno())) == enrollment_identity(before))
            identity.extend(["file", before.st_nlink, content])
        _require(enrollment_identity(path.lstat()) == enrollment_identity(before))
        records.append(json.dumps(identity, separators=(",", ":")))
    return _hash(b"".join(record.encode() + b"\0" for record in sorted(records)))


def enrollment_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _bound(store, intent=None):
    directory, binding, config = fence._binding(store, intent)
    from .maintenance_journal import native_validate, native_transition
    current = native_validate(_json(store._read(directory + "/native-journal.json")))
    if current["phase"] == "cancelled":
        # Resume only the final fence removal after an interrupted terminal
        # write. Never make a terminal journal mutable or manufacture a phase.
        journal_ref = store.reference(directory + "/cancellation-journal.json")
        journal = native_validate(_json(store._bound(journal_ref)))
        evidence = {key: current["evidence"][key] for key in ("original_services", "consistency", "closure_removed")}
        expected = native_transition(journal, "cancelled", evidence)
        expected["updated"] = current["updated"]
        _require(_encode(expected) == _encode(current) and current["operation"] == binding["intent"])
        for ref in evidence.values():
            store._bound(ref)
    else:
        journal_ref, journal = fence._native_journal(store, directory, binding)
    _history(journal)
    _no_later_effects(store, directory)
    intent = _json(store._bound(binding["intent"]))
    inputs = _json(store._bound(intent["inputs"]))
    _require(store._active() == intent["base_graph"])
    graph = _json(store._bound(intent["base_graph"]))
    _require(graph["instances"] == inputs["entries"])
    for name, entry in inputs["entries"].items():
        store._resolve_entry(name, entry)
        for pair in inputs["originals"][name]["files"].values():
            if pair is not None:
                store._bound(pair["original"])
    admission = _json(store._read(directory + "/admission.json"))
    admitted = _json(store._bound(admission["evidence"]))
    _require(admitted["kind"] == "original-generation-admission" and admitted["graph"] == intent["base_graph"]
             and admitted["generation"] == inputs["entries"][config.instance]["generation"]
             and admitted["executor"] == inputs["executor"] and admitted["recipe"] == inputs["recipe"]
             and admitted["startup"] == admission["startup"] and admitted["instance"] == config.instance)
    baseline = _json(store._bound(admitted["first_readiness"]))["observation"]
    observations = _json(store._read(directory + "/source-observations.json"))
    _require(observations["status"]["maintenance"] is False and observations["status"]["installed"] is True
             and observations["status"]["needsDbUpgrade"] is False and observations["reclosure_runtime"])
    if _mode(store, directory, journal) == "partial-quiesce":
        ack = recovery.offline_acknowledgement_record(SimpleNamespace(operation_id=inputs["operation"], config=config,
            source_sha256=inputs["executor"]["source_sha256"], preparation_sha256=inputs["preparation"]["sha256"]))
        _require(_encode(_json(store._read(directory + "/offline-acknowledgement.json"))) == _encode(ack))
    return directory, binding, config, inputs, journal_ref, baseline, observations


def _prepared(store, data):
    """Reauthenticate public staging without running its installed helper code."""
    from . import nextcloud_update as update
    from .maintenance_validation import _effect
    directory, binding, config, inputs, _, _, _ = data
    path = directory + "/update-prepared.json"
    if not store._present(path):
        return
    prepared = _json(store._read(path))
    _fields(prepared, "schema_version kind operation intent preparation plan admission recipe memory_mib bundle observations custom config_metadata")
    _require(type(prepared["schema_version"]) is int and prepared["schema_version"] == 1
             and prepared["kind"] == "prepared-nextcloud-patch" and prepared["operation"] == binding["operation"]
             and prepared["intent"] == binding["intent"] and prepared["recipe"] == inputs["recipe"]
             and prepared["admission"] == _json(store._read(directory + "/admission.json"))["evidence"]
             and prepared["preparation"] == inputs["preparation"])
    _require(prepared["plan"] == _json(store._bound(inputs["preparation"]))["plan"])
    store._bound(prepared["plan"])
    from dataclasses import asdict
    bundle = update.decode_bundle(prepared["bundle"])
    _require(bundle.operation == binding["operation"])
    root = Path(binding["roots"][config.nextcloud_jail])
    stage = root / update.STAGING.lstrip("/") / binding["operation"]
    raw = update._read(stage / "receipt.json", update.MAX_CENTRAL)
    _require(_hash(raw) == bundle.receipt_sha256)
    expected = dict(source=asdict(bundle.source), source_version=list(update.SOURCE), target_version=list(update.TARGET),
        operation=binding["operation"], key=update.RELEASE_KEY, artifacts=[asdict(item) for item in bundle.artifacts],
        **update.inventory_receipt(bundle.source_inventory, bundle.target_inventory))
    _require(_encode(_json(raw)) == _encode(expected))
    for item in bundle.artifacts:
        _require(update._digest_file(stage / item.path, update.MAX_ARCHIVE) == (item.sha256, item.size))
    _require(update.canonical_signature(update._read(stage / "nextcloud-35.0.2.zip.sig", 2048)) == bundle.signature)
    _require(update._digest_file(root / update.RETAINED.lstrip("/"), update.MAX_ARCHIVE)[0]
             == bundle.source.archive_sha256)
    proof = update._read(root / update.SHA_PROOF.lstrip("/"), 128)
    _require(_hash(proof) == bundle.source.proof_sha256 and proof in (
        bundle.source.archive_sha256.encode(), (bundle.source.archive_sha256 + "\n").encode()))
    context = SimpleNamespace(store=store, directory=directory, operation=binding["operation"],
                              journal=SimpleNamespace(reference=binding["intent"], path=directory + "/native-journal.json"))
    artifacts = {item.path: item for item in bundle.artifacts}
    _require(set(artifacts) == {"nextcloud-35.0.2.zip", "nextcloud-35.0.2.zip.asc", "nextcloud-35.0.2.zip.sig",
                               "nextcloud-35.0.1.tar.bz2.asc", "nextcloud.asc", "source-core.crt"})
    _effect(context, "staging-parent", str(root / update.STAGING.lstrip("/")))
    _effect(context, "import-release-key", artifacts["nextcloud.asc"].sha256)
    _effect(context, "stage-artifacts", bundle.receipt_sha256)
    _require(_json(store._read(directory + "/update-stage-artifacts-before.json"))["binding"] == bundle.source.archive_sha256)


def payload(store, data):
    """Positive host-only proof before any installed PHP or daemon can execute."""
    from .maintenance_admission import STATIC_ROOTS
    from .maintenance_generations import public_runtime_files
    directory, binding, config, inputs, _, baseline, _ = data
    mode = _mode(store, directory, _json(store._bound(data[4])))
    profile = None
    if mode == "partial-quiesce":
        profile, _ = fence._profile(store, store.reference(directory + "/closed-profile.json"))
        _require(profile["baseline"] == _json(store._read(directory + "/admission.json"))["startup"])
        fence._check_files(store, profile, "either")
    for group, jail in (("nextcloud", config.nextcloud_jail), ("onlyoffice", config.onlyoffice_jail)):
        root = Path(binding["roots"][jail])
        appname = "usr/local/www/" + ("nextcloud" if group == "nextcloud" else "onlyoffice/documentserver")
        names = (*STATIC_ROOTS, appname)
        if (root / "etc/unbound").is_symlink():
            names += ("var/unbound",)
        _require(set(baseline["trees"][jail]) == set(names))
        roots = tuple(root / name for name in names)
        for name in names:
            changes = {item["path"][len(name) + 1:]: (store._bound(item["original"]), store._bound(item["closed"]))
                       for item in (profile["files"] if profile else ())
                       if item["jail"] == jail and item["path"].startswith(name + "/")}
            # Always inspect the authoritative nc-app ZFS source, including when
            # a stopped jail has no nullfs mount at its normal application path.
            actual = Path(config.mount_root) / "nc-app" if group == "nextcloud" and name == appname else root / name
            digest = _tree_identity(actual, jail_root=root, observed_roots=roots, replacements=changes,
                                    maintenance=mode == "partial-quiesce" and group == "nextcloud" and name == appname)
            _require(digest == baseline["trees"][jail][name])
        files = inputs["originals"][config.instance]["files"]
        plan = _json(store._bound(files["versions.json"]["retained"]))
        for name, content in public_runtime_files(config, plan, group).items():
            _require(fence._file(root, "root/cloud-installer/" + name) == (content, 0o600, 0))
    _prepared(store, data)
    return dict(admission=store.reference(directory + "/admission.json"),
                source=store.reference(directory + "/source-observations.json"), graph=store._active(),
                profile=store.reference(directory + "/closed-profile.json") if profile else None)


def _original_services(n):
    prior = _json(n.store._read(n.directory + "/original-services.json"))
    _fields(prior, "pair services")
    _require(prior["pair"] == {n.c.nextcloud_jail: "running", n.c.onlyoffice_jail: "running"}
             and set(prior["services"]) == set(prior["pair"]))
    for group, jail in (("nextcloud", n.c.nextcloud_jail), ("onlyoffice", n.c.onlyoffice_jail)):
        values = prior["services"][jail]
        _require(set(values) == set(SERVICES[group]) and all(type(v) is bool for v in values.values())
                 and all(values[s] for s in SERVICES[group] if s not in ("cron", "sshd")))
    return prior["services"]


def _runtime(n, data):
    """Read-only identity, mounts, packages and known process ownership, any half-pair."""
    from .maintenance_opening import _pair
    from .lifecycle import _checked_jails
    from .network import storage_guard
    live = _pair(n)
    roots = data[1]["roots"]
    resources = recovery.expected_resources(n.c)
    expected = {(r.name, r.mountpoint, "zfs") for r in resources}
    expected.update((d.mountpoint, roots[d.jail] + d.target, "nullfs")
                    for d in recovery.datasets(n.c) if d.jail in live)
    devices = {("devfs", roots[jail] + "/dev", "devfs") for jail in live}
    seen = set()
    identities = None
    for line in n.backend.output("mount", "-p").splitlines():
        row = line.split()
        _require(len(row) == 6 and "\\" not in row[0] + row[1])
        if any(recovery._related(row[1], r.mountpoint) or row[2] == "nullfs" and
               recovery._related(row[0], r.mountpoint) for r in resources):
            # Ancestor ZFS mounts are normal, but cannot cover an expected member.
            if any(row[1] == r.mountpoint or row[1].startswith(r.mountpoint + "/") for r in resources) or row[2] == "nullfs":
                triple = tuple(row[:3])
                _require(triple in expected | devices and triple not in seen)
                seen.add(triple)
        if row[2] == "nullfs" and tuple(row[:3]) not in expected:
            if identities is None:
                identities = [n.backend.mounted_identity(r.mountpoint) for r in resources]
                _require([point for point, _ in identities] == [r.mountpoint for r in resources])
            for point in row[:2]:
                canonical, identity = n.backend.mounted_identity(point)
                _require(not any(recovery._related(canonical, original) or identity[0] == observed[0]
                                 for original, observed in identities))
    _require(expected <= seen)
    for root in (n.c.dataset_root, *(n.c.bastille_dataset + "/jails/" + jail for jail in roots)):
        names = n.backend.output("zfs", "list", "-H", "-o", "name", "-t", "filesystem,volume", "-r", root).splitlines()
        _require(len(names) == len(set(names)) and set(names) ==
                 {r.name for r in resources if r.name == root or r.name.startswith(root + "/")})
    for r in resources:
        for key, value in (("type", "filesystem"), ("origin", "-"), ("mounted", "yes"),
                           ("mountpoint", r.mountpoint), (recovery.OWNER, n.c.instance),
                           (recovery.MANAGER, "cloud-installer")):
            _require(n.backend.get(r.name, key) == value)
        df = n.backend.output("df", "-P", r.mountpoint).splitlines()
        _require(n.backend.output("realpath", r.mountpoint) == r.mountpoint and len(df) == 2
                 and len(df[-1].split()) == 6 and df[-1].split()[0] == r.name
                 and df[-1].split()[-1] == r.mountpoint)
        if r.name in data[5]["resources"]:
            observed = n.backend.output("zfs", "get", "-Hp", "-o", "property,value",
                "guid,mountpoint,mounted,org.cloud-installer:instance", r.name)
            _require(observed == data[5]["resources"][r.name])
        else:
            _require(r.name in {n.c.bastille_dataset + "/jails/" + jail for jail in roots})
    closure = n.directory + "/initial-closure.json"
    if n.store._present(closure):
        stored = _json(n.store._read(closure))["storage"]
        _require(set(stored) == {r.name for r in resources})
        for r in resources:
            _require(n.backend.get(r.name, "guid") == stored[r.name]["guid"]
                     and r.mountpoint == stored[r.name]["mountpoint"])
    original = data[6]["reclosure_runtime"]
    _require(n.backend.reclosure_runtime(original) == original)
    for jail in roots:
        _require({name for name, _ in _checked_jails(n.d, [jail], stopped=jail not in live)} == {jail})
        _require(n.backend.output("bastille", "config", jail, "get", "path") == roots[jail])
        hostname = n.c.nextcloud_host if jail == n.c.nextcloud_jail else n.c.onlyoffice_host
        _require(n.backend.output("bastille", "config", jail, "get", "host.hostname") == hostname)
        script = storage_guard(n.c, n.d.storage, n.d.registry.root, lifecycle=False)
        result = n.backend.runner.run("/bin/sh", "-s", "--", jail, input=script, hide_output=True, timeout=60)
        _require(result.returncode == 0)
        if jail in live:
            _require(n.d.require_running_jail(jail) == live[jail])
            _require(n.backend.output("jls", "-j", jail, "host.hostname") == hostname
                     and n.backend.jailed(jail, "hostname").stdout.strip() == hostname)
            rows = n.backend.processes(jail)
            known = {row[0] for service in SERVICES["nextcloud" if jail == n.c.nextcloud_jail else "onlyoffice"]
                     for row in n.backend._service_rows(jail, service, rows)}
            _require(all(row[0] in known or row[2] in ("init", "syslogd", "ps") for row in rows))
    _require(_pair(n) == live)
    return live


def _preflight(n):
    n.check()
    data = _bound(n.store)
    proof = payload(n.store, data)
    if proof["profile"] is not None:
        _original_services(n)
    live = _runtime(n, data)
    if proof["profile"] is None:
        proof["readiness"] = _prequiesce_ready(n, data, live)
    return data, dict(**proof, journal=data[4], live=live,
                      boot=_boot(n.backend.output("sysctl", "-n", "kern.boottime")))


def _prequiesce_ready(n, data, live):
    """Observe ready originals only after exact, unprojected static code proof."""
    from .maintenance_publication import Publication
    _require(set(live) == set(data[1]["roots"]))
    n.backend.owned_live()
    states = n.backend.service_states()
    _require(set(states) == set(live))
    for group, jail in (("nextcloud", n.c.nextcloud_jail), ("onlyoffice", n.c.onlyoffice_jail)):
        _require(set(states[jail]) == set(SERVICES[group]) and all(type(v) is bool for v in states[jail].values()))
        for service, running in states[jail].items():
            flag = "mysql" if service == "mysql-server" else service
            enabled = n.backend.jailed(jail, "sysrc", "-n", flag + "_enable").stdout.strip()
            _require(enabled in ("YES", "NO") and running is (enabled == "YES")
                     and (service in ("cron", "sshd") or running))
    observed = n.backend.source_observations()
    _require(observed == data[6])
    status = Publication(n)._public_status(data[6]["status"]["version"])
    # Detect moving source/identity while querying it. No newly observed baseline
    # and no reenrollment/admit_source call under a pending maintenance intent.
    payload(n.store, data)
    n.backend.owned_live()
    _require(_runtime(n, data) == live and n.backend.service_states() == states)
    return dict(kind="original-ready-without-quiescence", source_sha256=_hash(_encode(observed)),
                services=states, jids=live, status=status)


def assess(n):
    """Read-only; installed readiness probes follow affirmative host code checks."""
    try:
        _, value = _preflight(n)
        return CancellationAssessment(True, (), _hash(_encode(value)))
    except Exception:
        return CancellationAssessment(False, (DENIED,))


def _request(store, data):
    directory, binding, _, _, journal, _, _ = data
    ref = store.reference(directory + "/cancellation-request.json")
    value = _json(store._bound(ref))
    _fields(value, "schema_version kind intent journal graph profile boot confirmation inspection")
    mode = _mode(store, directory, _json(store._bound(journal)))
    profile = store.reference(directory + "/closed-profile.json") if mode == "partial-quiesce" else None
    kind = "native-original-cancellation" if profile is not None else "native-pre-quiesce-cancellation"
    _require(type(value["schema_version"]) is int and value["schema_version"] == 1
             and value["kind"] == kind and value["intent"] == binding["intent"]
             and value["journal"] == store.reference(directory + "/cancellation-journal.json")
             and value["journal"]["sha256"] == journal["sha256"] and value["graph"] == store._active()
             and value["profile"] == profile
             and value["confirmation"] == "CANCEL-MAINTENANCE " + binding["operation"])
    _boot(value["boot"])
    store._bound(value["inspection"])
    return ref, value


def boot_permission(registry, intent, instance, jail, executor):
    """A separate actively held permission; never a generic pending-fence bypass."""
    from .enrollment_start import _held
    store = Store(registry.root)
    data = _bound(store, intent)
    directory, binding, config, _, _, _, _ = data
    reference, request = _request(store, data)
    _require(request["kind"] == "native-original-cancellation" and request["profile"] is not None)
    _require(_json(store._read(directory + "/native-journal.json"))["phase"] != "cancelled")
    _require(instance == config.instance and jail in binding["roots"]
             and executor == binding["executor"]["executor_sha256"]
             and fence._publication_boot() == request["boot"])
    for path in ("operation.lock", f"instances/{instance}/database-operation.lock", directory + "/cancellation-start.lock"):
        _held(store, path)
    _require(_json(store._read(directory + "/cancellation-start.json")) == dict(request=reference, journal=data[4]))
    progress = _json(store._read(directory + "/cancellation-progress.json"))
    _require(progress["request"] == reference and progress["completed"] == [STEPS[0]]
             and progress["running"] == "original-runtime")
    fence.verify_closed(store, request["profile"])
    payload(store, data)
    _require(store.pending() == intent and store._active() == request["graph"])
    return config


@contextmanager
def cancellation_starts(n):
    from .enrollment_start import _lock_file
    n.registry._require_lock(recovery=True)
    data = _bound(n.store)
    reference, request = _request(n.store, data)
    fence.verify_closed(n.store, request["profile"])
    with fence._exclusive(n.store, n.directory):
        fd = _lock_file(n.store, n.directory + "/cancellation-start.lock", create=True)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            path = n.directory + "/cancellation-start.json"
            n.store._put(path, dict(request=reference, journal=data[4]), replace=n.store._present(path))
            intent = _json(n.store._bound(data[1]["intent"]))
            boot_permission(n.registry, intent, n.c.instance, n.c.nextcloud_jail,
                            data[1]["executor"]["executor_sha256"])
            yield
        finally:
            os.close(fd)


def _restore_profile(n):
    """Exact original selection with cancellation proof, never publication forgery."""
    data = _bound(n.store)
    _request(n.store, data)
    payload(n.store, data)
    profile, _ = fence._profile(n.store, n.profile())
    with fence._exclusive(n.store, n.directory):
        fence._check_files(n.store, profile, "either")
        for item in profile["files"]:
            fence._check_files(n.store, profile, "either")
            fence._replace(profile["roots"][item["jail"]], item, n.store._bound(item["original"]))
        fence._check_files(n.store, profile, "original")


def _close(n, data):
    live = _runtime(n, data)
    fence.install_profile(n.registry, n.profile())
    if n.c.nextcloud_jail in live and n.backend.running(n.c.nextcloud_jail, "apache24"):
        n.backend.jailed(n.c.nextcloud_jail, "/usr/local/sbin/apachectl", "configtest")
        n.backend.jailed(n.c.nextcloud_jail, "/usr/local/sbin/apachectl", "-k", "graceful")
        n.backend.deny_probe()
    for jail in live:
        services = ("apache24", "cron", "sshd", "php_fpm") if jail == n.c.nextcloud_jail else ("nginx", "cron", "sshd", "supervisord")
        for service in services:
            n.backend.stop(jail, service)
    # Unknown processes were rejected before effects. Recheck after graceful
    # waits: never kill an orphan writer to manufacture closure.
    _runtime(n, data)


def _start_runtime(n, data):
    from .maintenance_opening import _pair
    with cancellation_starts(n):
        for jail in (n.c.nextcloud_jail, n.c.onlyoffice_jail):
            live = _runtime(n, data)
            if jail not in live:
                # The actual exec.prepare dispatcher must know this narrowly
                # scoped permission. Refuse BEFORE start on an older dispatcher.
                fence.boot_permission(n.registry, _json(n.store._bound(data[1]["intent"])),
                                      n.c.instance, jail, data[1]["executor"]["executor_sha256"])
                n.record("cancellation-start-" + jail, dict(jail=jail, root=data[1]["roots"][jail]))
                n.backend.run("bastille", "start", jail)
                _require(jail in _pair(n) and all(_pair(n).get(name) == jid for name, jid in live.items()))
        n.backend.owned_live()
        # A previous attempt may have reached the final private FPM start below.
        # Before opening, graceful reclosure of that known original worker is
        # safe; unknown workers still fail the independent inventory check.
        n.backend.stop(n.c.nextcloud_jail, "php_fpm")
        n.backend.wait_writer_closure(database_running=True)
        for service in ("mysql-server", "redis"):
            if not n.backend.running(n.c.nextcloud_jail, service):
                n.backend.jailed(n.c.nextcloud_jail, "service", service, "onestart")
            _require(n.backend.running(n.c.nextcloud_jail, service))
        # Original DB crash recovery is allowed, initialization/repair/reset is
        # not. reclosure_runtime checked the existing mysql system tables first.
        n.backend.database_ready()
        status = _json(n.backend.occ("status", "--output=json"))
        _require(status.get("installed") is True and status.get("needsDbUpgrade") is False
                 and type(status.get("maintenance")) is bool
                 and status.get("version") == data[6]["status"]["version"])
        apps = _json(n.backend.occ("app:list", "--output=json"))
        config = _json(n.backend.occ("config:list", "--private", "--output=json"))
        _require(type(config.get("system")) is dict and type(config["system"].get("maintenance")) is bool)
        config["system"]["maintenance"] = False
        _require(_hash(_encode(apps)) == data[6]["apps_sha256"]
                 and _hash(_encode(config)) == data[6]["config_sha256"])
        n.backend.jailed(n.c.nextcloud_jail, "service", "php_fpm", "onestart")
        _require(n.backend.running(n.c.nextcloud_jail, "php_fpm"))


def _services(n, original, *, scheduled):
    order = ((n.c.nextcloud_jail, ("mysql-server", "redis", "php_fpm")),
             (n.c.onlyoffice_jail, ("supervisord", "nginx")), (n.c.nextcloud_jail, ("apache24",)))
    if scheduled:
        order = tuple((jail, ("cron", "sshd")) for jail in original)
    for jail, services in order:
        for service in services:
            n.backend.owned_live()
            running = bool(n.backend.running(jail, service))
            if original[jail][service] and not running:
                n.backend.jailed(jail, "service", service, "onestart")
            elif not original[jail][service]:
                _require(not running)
            _require(bool(n.backend.running(jail, service)) == original[jail][service])


def _ready(n, data):
    from .maintenance_publication import Publication
    from .maintenance_validation import _integration
    payload(n.store, data)
    n.backend.owned_live()
    actual = n.backend.source_observations()
    _require(actual == data[6])
    public = Publication(n)._public_status(data[6]["status"]["version"])
    cache, connector = _integration(n, n.d.versions)
    return dict(source_sha256=_hash(_encode(actual)), status=public, cache=cache, connector=connector)


def _cancel_prequiesce(n, request, value):
    """Metadata-only finalization: closure was never installed, not restored."""
    data, current = _preflight(n)
    _require(current["profile"] is None and current["boot"] == value["boot"]
             and current["live"] == _json(n.store._bound(value["inspection"]))["live"])
    _require(_request(n.store, data)[0] == request)
    services = n.record("cancellation-live-services", dict(kind="observed-original-ready-services",
        request=request, services=current["readiness"]["services"], jids=current["live"], boot=current["boot"]))
    consistency = n.record("cancellation-consistency", current["readiness"])
    closure = n.record("cancellation-no-closure", dict(kind="closure-never-installed", request=request,
        graph=n.store._active(), source=current["source"], admission=current["admission"], profile=None))
    if n.journal.read()["phase"] != "cancelled":
        n.journal.advance("cancelled", dict(original_services=services, consistency=consistency, closure_removed=closure))
    n.journal.terminal()
    n.native.finish(n.operation, "cancelled")
    return dict(state="cancelled", ready=True, original_generation=True, downtime_entered=False,
                snapshots_retained=True, machine_drain_verified=False, unsaved_editor_work_covered=False)


def cancel(n, confirmation):
    """Actual original runtime return, under the caller's host/database locks.

    Forward-only after maintenance-off. Re-entry needs fresh explicit consent;
    completed actions are not replayed. Failed checks retain the ordinary fence.
    Entered downtime requires original editor save/close acknowledgment. The
    strictly untouched pre-quiesce path neither needs nor fabricates that consent.
    """
    _require(type(confirmation) is str and confirmation == "CANCEL-MAINTENANCE " + n.operation)
    try:
        data, inspection = _preflight(n)
        path = n.directory + "/cancellation-request.json"
        if not n.store._present(path):
            observed = n.record("cancellation-inspection", inspection)
            saved_journal = n.record("cancellation-journal", n.journal.read())
            prequiesce = _mode(n.store, n.directory, _json(n.store._bound(data[4]))) == "pre-quiesce"
            n.record("cancellation-request", dict(schema_version=1,
                kind="native-pre-quiesce-cancellation" if prequiesce else "native-original-cancellation",
                intent=data[1]["intent"], journal=saved_journal, graph=n.store._active(), profile=None if prequiesce else n.profile(),
                boot=inspection["boot"], confirmation=confirmation, inspection=observed))
        request, value = _request(n.store, data)
        _require(inspection["boot"] == value["boot"])
        if value["kind"] == "native-pre-quiesce-cancellation":
            return _cancel_prequiesce(n, request, value)
        progress_path = n.directory + "/cancellation-progress.json"
        progress = dict(request=request, completed=[], running=None, evidence={})
        if n.store._present(progress_path):
            progress = _json(n.store._read(progress_path))
            _fields(progress, "request completed running evidence")
            count = len(progress["completed"])
            _require(progress["request"] == request and progress["completed"] == list(STEPS[:count])
                     and count <= len(STEPS) and set(progress["evidence"]) == set(progress["completed"])
                     and progress["running"] in (None, STEPS[count] if count < len(STEPS) else None))
            for ref in progress["evidence"].values():
                n.store._bound(ref)
        original = _original_services(n)
        for step in STEPS[len(progress["completed"]):]:
            data, current = _preflight(n)
            _require(current["boot"] == value["boot"])
            progress["running"] = step
            n.store._put(progress_path, progress, replace=n.store._present(progress_path))
            observation = dict(step=step, request=request)
            if step == "close-original-writers":
                _close(n, data)
            elif step == "original-runtime":
                _start_runtime(n, data)
            elif step == "maintenance-off":
                n.backend.occ("maintenance:mode", "--off")
                # Full original package/PHP/app/config/status checks precede
                # restoring public ingress. The profile remains closed here.
                _require(n.backend.source_observations() == data[6])
            elif step == "original-profile":
                _restore_profile(n)
            elif step in ("application-services", "scheduled-services"):
                _services(n, original, scheduled=step == "scheduled-services")
            else:
                observation = _ready(n, data)
            reference = n.record("cancelled-" + step, observation)
            progress["completed"].append(step)
            progress["evidence"][step] = reference
            progress["running"] = None
            n.store._put(progress_path, progress, replace=True)
        data, _ = _preflight(n)
        profile, _ = fence._profile(n.store, n.profile())
        fence._check_files(n.store, profile, "original")
        _require(n.backend.service_states() == original)
        consistency = n.record("cancellation-consistency", _ready(n, data))
        if n.journal.read()["phase"] != "cancelled":
            n.journal.advance("cancelled", dict(original_services=n.store.reference(n.directory + "/original-services.json"),
                consistency=consistency, closure_removed=progress["evidence"]["original-profile"]))
        n.journal.terminal()
        n.native.finish(n.operation, "cancelled")
        return dict(state="cancelled", ready=True, original_generation=True, snapshots_retained=True,
                    machine_drain_verified=False, unsaved_editor_work_covered=False)
    except Exception:
        raise ValueError(DENIED) from None
