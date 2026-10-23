"""Explicit forward-only publication boot continuation. No rollback authority.

The original readiness boot/JIDs are never edited. Each operator-confirmed new
boot appends an immutable request and observed identity. Start attempts are durable
before Bastille; an interrupted live start is observed, never stopped/repeated.
Only publication_starts' separate live lock permits the affected pair to boot.
"""

from contextlib import contextmanager
from dataclasses import asdict
import hashlib
import itertools
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace

from . import maintenance_fence as fence, recovery_sets as recovery
from .generations import _encode, _fields, _hash, _json, _schema
from .maintenance_journal import native_validate
from .maintenance_publication import Publication, PublicationBlocked


ROOT_GID = 0


def _require(value, code="publication-continuation-binding-drift"):
    if not value:
        raise PublicationBlocked(code)


def terminal_binding(store, directory, *, prepared=False):
    """Exact presealed transition and cleanup evidence, never a journal rewrite."""
    from .maintenance_journal import native_transition
    from .maintenance_publication import STEPS, OPEN_CHECKS
    reference = store.reference(directory + "/publication-finalization.json")
    value = _json(store._bound(reference))
    _fields(value, "schema_version kind intent publication opening journal terminal outcome graph progress profile_apply evidence")
    _schema(value)
    opening = native_validate(_json(store._bound(value["opening"], directory + "/opening-journal.json")))
    outcome = "recovered" if opening["phase"] == "recovery-opening" else "complete"
    _fields(value["evidence"], "post_open consistency")
    _require(value["kind"] == "native-publication-finalization" and value["outcome"] == outcome
             and opening["phase"] in ("opening", "recovery-opening")
             and value["intent"] == opening["operation"] == store.reference(directory + "/intent.json")
             and store.pending() == _json(store._bound(value["intent"]))
             and value["publication"] == store.reference(directory + "/native-publication.json")
             and value["graph"] == opening["evidence"]["graph"] == store._active())
    expected = native_transition(opening, outcome, value["evidence"])
    saved = native_validate(value["terminal"])
    # Transition timestamps are chosen once, before the durable write. Only that
    # presealed timestamp is used on retry; all other fields must derive exactly.
    expected["updated"] = saved["updated"]
    _require(expected == saved)
    _require(value["journal"] == dict(path=directory + "/native-journal.json", sha256=_hash(_encode(expected))))
    current = store._read(directory + "/native-journal.json")
    _require(current == _encode(expected) or prepared and current == _encode(opening), "terminal-journal-binding-drift")
    for key in ("progress", "profile_apply"):
        _require(value[key]["path"].startswith(directory + "/"))
    progress = _json(store._bound(value["progress"]))
    _fields(progress, "schema_version publication completed running evidence")
    _schema(progress)
    _require(progress["publication"] == value["publication"] and progress["completed"] == list(STEPS)
             and progress["running"] is None and set(progress["evidence"]) == set(STEPS)
             and progress["evidence"]["post-open"] == value["evidence"]["post_open"])
    for ref in (*progress["evidence"].values(), *value["evidence"].values()):
        _require(ref["path"].startswith(directory + "/"))
        store._bound(ref)
    applied = _json(store._bound(value["profile_apply"], directory + "/profile-apply.json"))
    _require(applied == dict(schema_version=1, profile=store.reference(directory + "/closed-profile.json"),
        target="original", publication=value["publication"], index=3, state="complete"))
    consistency = _json(store._bound(value["evidence"]["consistency"]))
    _fields(consistency, "checks status frontend_probe external_ingress_verified graph original_services")
    _require(consistency["graph"] == value["graph"] and consistency["original_services"] == store.reference(directory + "/original-services.json"))
    _require(consistency["frontend_probe"] == "host-direct-frontend" and consistency["external_ingress_verified"] is False)
    status = consistency["status"]
    _require(type(status) is dict and status.get("installed") is True and status.get("maintenance") is False
             and status.get("needsDbUpgrade") is False
             and status.get("version") == ("35.0.1.1" if outcome == "recovered" else "35.0.2.2"))
    for checks in (consistency["checks"], _json(store._bound(value["evidence"]["post_open"]))):
        _require(type(checks) is dict and set(checks) == OPEN_CHECKS)
        for ref in checks.values():
            _require(ref["path"].startswith(directory + "/"))
            store._bound(ref)
    if outcome == "complete":
        _require(not store._present(directory + "/restored-closed.json"))
    for path, expected_record in (
        ("native-terminal.json", dict(schema_version=1, kind="native-maintenance-terminal", operation=value["intent"],
                                     phase=outcome, journal=value["journal"])),
        ("terminal.json", dict(schema_version=1, operation=opening["operation"]["path"].split("/")[-2],
                               outcome=outcome, intent=value["intent"], graph=value["graph"]))):
        if store._present(directory + "/" + path):
            _require(current == _encode(expected) and _json(store._read(directory + "/" + path)) == expected_record)
    return reference, value


def bound(store, intent=None, *, terminal=False):
    """Boot-reader binding, without acquiring the interactive parent's lock."""
    directory, binding, config = fence._binding(store, intent)
    current = native_validate(_json(store._read(directory + "/native-journal.json")))
    journal = current
    if current["phase"] in ("complete", "recovered") and terminal:
        terminal_binding(store, directory)
        raw = store._read(directory + "/opening-journal.json")
        journal = native_validate(_json(raw))
        _require(current["history"][:len(journal["history"])] == journal["history"])
        journal_ref = dict(path=directory + "/native-journal.json", sha256=_hash(raw))
    else:
        journal_ref, journal = fence._native_journal(store, directory, binding)
    _require(journal["phase"] in ("opening", "recovery-opening"))
    marker = "publication_may_have_begun" if journal["phase"] == "opening" else "recovery_publication_may_have_begun"
    _require(journal[marker] is True and current[marker] is True and journal["operation"] == binding["intent"])
    inputs = _json(store._bound(_json(store._bound(binding["intent"]))["inputs"]))
    _require(journal["inputs"] == current["inputs"] == store.reference(directory + "/native-inputs.json")
             and journal["recipe_sha256"] == current["recipe_sha256"] == inputs["recipe_sha256"])
    publication = store.reference(directory + "/native-publication.json")
    suffix = "original" if journal["phase"] == "recovery-opening" else "target"
    pub = _json(store._bound(publication))
    expected = dict(schema_version=1, kind="native-publication-proof", intent=binding["intent"],
        profile=store.reference(directory + "/closed-profile.json"), phase=journal["phase"], journal=journal_ref,
        markers=dict(closed_validation=journal["evidence"]["readiness"],
            writers_stopped=store.reference(directory + "/publication-writers-stopped-" + suffix + ".json"),
            publication_authorized=store.reference(directory + "/publication-authorized-" + suffix + ".json")))
    _require(_encode(pub) == _encode(expected))
    proof = _json(store._bound(journal["evidence"]["readiness"]))
    _require(proof["intent"] == binding["intent"] and proof["recovering"] is (journal["phase"] == "recovery-opening")
             and set(proof["jids"]) == set(binding["roots"])
             and all(type(jid) is int and jid > 0 for jid in proof["jids"].values()))
    graph = store._active()
    stage = "restored-closed" if proof["recovering"] else "validated-closed"
    _require(graph == journal["evidence"]["graph"] == current["evidence"]["graph"]
             == _json(store._read(directory + "/" + stage + ".json"))["graph"])
    active = _json(store._bound(graph))
    _require(active["instances"][config.instance]["generation"] == proof["generation"])
    from .maintenance_state import NativeState
    NativeState._entries(inputs, active["instances"], restored=proof["recovering"])
    for name, entry in active["instances"].items():
        store._resolve_entry(name, entry)
    from .maintenance_operations import _network_binding
    _require(_network_binding(store) == inputs["network"]
             == _json(store._bound(journal["evidence"]["network"])))
    generation = store._generation(config.instance, proof["generation"])
    return directory, binding, config, inputs, journal, proof, publication, graph, generation


def _profile_tree(root, *, jail_root, observed_roots, replacements):
    """Enrollment digest with only exact retained original/closed bytes projected.

    No live file is rewritten for inspection. Metadata, every other byte, links
    and directory entries remain covered by the original enrollment identity.
    """
    from . import enrollment
    _require(root.is_absolute() and ".." not in root.parts and root.is_dir() and not root.is_symlink()
             and not any(parent.is_symlink() for parent in root.parents))
    records, total = [], 0
    for count, path in enumerate(itertools.chain((root,), root.rglob("*")), 1):
        _require(count <= 250000)
        before = path.lstat()
        identity = [str(path.relative_to(root)), stat.S_IMODE(before.st_mode), before.st_uid, before.st_gid]
        if stat.S_ISLNK(before.st_mode):
            target = os.readlink(path)
            destination = enrollment._jail_link(path, jail_root)
            if (path == jail_root / "etc/os-release" and target == "../var/run/os-release"
                    and destination == jail_root / "var/run/os-release"):
                release = enrollment._bytes(destination, private=False)
                _require(len(release) <= 16384)
                identity.extend(["freebsd-os-release", _hash(release)])
            else:
                _require(any(destination == tree or tree in destination.parents for tree in observed_roots))
            identity.extend(["link", target])
        elif stat.S_ISDIR(before.st_mode):
            identity.append("directory")
        elif stat.S_ISREG(before.st_mode):
            total += before.st_size
            _require(before.st_size <= 512 * 1024**2 and total <= 8 * 1024**3)
            digest = hashlib.sha256()
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as stream:
                opened = os.fstat(stream.fileno())
                _require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino))
                if path in replacements:
                    original, *alternatives = replacements[path]
                    actual = stream.read(max(map(len, (original, *alternatives))) + 1)
                    _require(actual in (original, *alternatives) and before.st_nlink == 1)
                    digest.update(original)
                else:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(block)
            identity.extend(["file", before.st_nlink, digest.hexdigest()])
        else:
            _require(False)
        after = path.lstat()
        _require((before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                 (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns))
        records.append(json.dumps(identity, separators=(",", ":")))
    return _hash(b"".join(record.encode() + b"\0" for record in sorted(records)))


def payload(store, config, inputs, journal, proof):
    """Host-only code/static-runtime checks, including the stopped NC nullfs source.

    User data and config.php content are deliberately not compared to pre-open
    contents. Code/custom apps, configuration ownership/modes, startup files and
    executable/helper trees must still match their authenticated identities.
    """
    from . import maintenance_update as patch
    from . import maintenance_generations as generations, nextcloud_update as update, enrollment
    from .maintenance_admission import STATIC_ROOTS
    from .maintenance_preflight import recipe
    _require(inputs["recipe"] == recipe(), "fixed-publication-recipe-required")
    directory = "maintenance/operations/" + inputs["operation"]
    roots = {jail: Path(config.bastille_root) / "jails" / jail / "root"
             for jail in (config.nextcloud_jail, config.onlyoffice_jail)}
    code = _json(store._bound(proof["checks"]["code"]))
    _fields(code, "prepared authenticated target inventory_sha256")
    prepared = _json(store._bound(code["prepared"], directory + "/update-prepared.json"))
    _require(prepared["intent"] == journal["operation"] and prepared["operation"] == inputs["operation"]
             and prepared["recipe"] == recipe() and code["target"] is not proof["recovering"])
    bundle = prepared["bundle"]
    decoded = update.decode_bundle(bundle)
    receipt = update._read(roots[config.nextcloud_jail] / update.STAGING.lstrip("/") / inputs["operation"] / "receipt.json",
                           update.MAX_CENTRAL)
    _require(_hash(receipt) == bundle["receipt_sha256"])
    authenticated = _json(store._bound(code["authenticated"], directory + "/update-stage-artifacts-after.json"))
    _require(authenticated["intent"] == journal["operation"] and authenticated["state"] == "after"
             and authenticated["binding"] == bundle["receipt_sha256"])
    signed = _json(receipt)
    kind = "source" if proof["recovering"] else "target"
    inventory = decoded.source_inventory if proof["recovering"] else decoded.target_inventory
    _require(_encode(signed[kind + "_files"]) == _encode(bundle[kind + "_inventory"]["files"])
              and signed[kind + "_directories"] == bundle[kind + "_inventory"]["directories"])
    _require(signed.get("source_links", []) == [asdict(link) for link in decoded.source_inventory.links])
    rows = [line.split(":") for line in fence._file(roots[config.nextcloud_jail], "etc/passwd")[0].decode().splitlines()]
    www = [row for row in rows if row[0] == "www"]
    _require(len(www) == 1 and len(www[0]) == 7 and all(value.isdigit() and int(value) > 0 for value in www[0][2:4]))
    app = Path(config.mount_root) / "nc-app"
    def host(path):
        _require(path == update.APP or path.startswith(update.APP + "/"))
        return app / path.removeprefix(update.APP).lstrip("/")
    context = SimpleNamespace(host=host, www_uid=int(www[0][2]), www_gid=int(www[0][3]))
    observed = patch._code(context, inventory)
    patch._hardened(context, observed)
    _require(patch._hash(observed) == code["inventory_sha256"]
             and patch._custom(context) == prepared["custom"]
             and patch._config_metadata(context) == prepared["config_metadata"])
    admission = _json(store._read(directory + "/admission.json"))
    admitted = _json(store._bound(admission["evidence"]))
    _require(admitted["generation"] == inputs["entries"][config.instance]["generation"]
             and admitted["executor"] == inputs["executor"])
    baseline = _json(store._bound(admitted["first_readiness"]))["observation"]["trees"]
    files = inputs["originals"][config.instance]["files"]
    raw = store._bound(files["config.json"]["retained"])
    source_plan = _json(store._bound(files["versions.json"]["retained"]))
    plan = source_plan if proof["recovering"] else generations.target_plan(raw, source_plan)
    effective_config = config if proof["recovering"] else generations.target_configuration(raw)
    helpers = generations.source_hashes(inputs["executor"])
    profile, _ = fence._profile(store, store.reference(directory + "/closed-profile.json"))
    fence._check_files(store, profile, "publication-either")
    replacements = {Path(profile["roots"][item["jail"]]) / item["path"]:
                    (store._bound(item["original"]), store._bound(item["closed"]),
                     fence.publication_bytes(store, item)) for item in profile["files"]}
    for group, jail in (("nextcloud", config.nextcloud_jail), ("onlyoffice", config.onlyoffice_jail)):
        root = roots[jail]
        names = (*STATIC_ROOTS, "usr/local/www/" + ("nextcloud" if group == "nextcloud" else "onlyoffice/documentserver"))
        if (root / "etc/unbound").is_symlink():
            names += ("var/unbound",)
        for name in names:
            if name == "root/cloud-installer" or name == "usr/local/www/nextcloud":
                continue
            tree = root / name
            options = dict(jail_root=root, observed_roots=tuple(root / p for p in names))
            observed = (_profile_tree(tree, replacements=replacements, **options)
                        if any(tree in path.parents for path in replacements) else enrollment._tree_identity(tree, **options))
            _require(observed == baseline[jail][name], "publication-static-runtime-drift")
        for name, digest in helpers.items():
            _require(_hash(fence._file(root, "root/cloud-installer/" + name)[0]) == digest)
        for name, data in generations.public_runtime_files(effective_config, plan, group).items():
            _require(fence._file(root, "root/cloud-installer/" + name) == (data, 0o600, ROOT_GID))
        if group == "nextcloud":
            _require(_hash(fence._file(root, "usr/local/libexec/cloud-runtime-inventory.php")[0])
                     == helpers["resources/jails/runtime-inventory.php"])
    return dict(code=proof["checks"]["code"], generation=proof["generation"], baseline=admitted["first_readiness"])


def _pair(n):
    resources = recovery.expected_resources(n.c)
    roots = {jail: str(n.d.jail_root(jail)) for jail in (n.c.nextcloud_jail, n.c.onlyoffice_jail)}
    found, ids = {}, set()
    for line in n.backend.output("jls", "-d", "jid", "name", "path", "dying").splitlines():
        row = line.split()
        _require(len(row) == 4 and row[0].isdigit() and int(row[0]) > 0 and row[0] not in ids and row[3] in ("true", "false"))
        ids.add(row[0])
        if row[1] in roots or any(recovery._related(row[2], r.mountpoint) for r in resources):
            _require(row[1] in roots and row[2] == roots[row[1]] and row[3] == "false" and row[1] not in found)
            found[row[1]] = int(row[0])
    return found


def storage(n, inputs, journal, live):
    """Exact original snapshot/member ownership; allow only this partial live pair.

    No clean-shutdown, written-byte or rollback eligibility assertion is made.
    Ordinary exec.prepare storage/PF checks still run after the boot permission.
    """
    from .maintenance_operations import load_operation
    from .enrollment import validate_guard
    from .paths import PROJECT_ROOT
    validate_guard(n.d, dispatcher=PROJECT_ROOT / "installer/maintenance.py")
    original_runtime = _json(n.store._read(n.directory + "/source-observations.json"))["reclosure_runtime"]
    _require(n.backend.reclosure_runtime(original_runtime) == original_runtime,
             "publication-package-or-database-layout-drift")
    parent, _, _ = load_operation(n.registry, inputs["cache_owner"])
    evidence = tuple(recovery.Evidence(name, role, n.store.root / ref["path"], ref["sha256"])
                     for name, role, ref in n._evidence(inputs, parent, readonly=True))
    ack = n.store.reference(n.directory + "/offline-acknowledgement.json")
    intent = _json(n.store._bound(journal["operation"]))
    context = recovery.RecoveryContext(n.c, n.operation, inputs["executor"]["source_sha256"],
        inputs["executor"]["executor_sha256"], parent["plan"]["sha256"], intent["base_graph"]["sha256"],
        _hash(_encode(inputs["network"])), n.store.root / n.directory / "recovery", evidence,
        publication_may_have_begun=True, recovery_publication_may_have_begun=journal["recovery_publication_may_have_begun"],
        schema_version=2, quiescence_mode=recovery.OPERATOR_OFFLINE, preparation_sha256=inputs["preparation"]["sha256"],
        offline_acknowledgement=recovery.OfflineAcknowledgement(n.store.root / ack["path"], ack["sha256"]))
    manifest = recovery.validate_manifest(context, _json(n.store._bound(journal["evidence"]["recovery_set"])))
    roots = {jail: str(n.d.jail_root(jail)) for jail in (n.c.nextcloud_jail, n.c.onlyoffice_jail)}
    expected = {(r.name, r.mountpoint, "zfs") for r in context.resources}
    expected.update((d.mountpoint, roots[d.jail] + d.target, "nullfs") for d in recovery.datasets(n.c) if d.jail in live)
    devices = {("devfs", roots[jail] + "/dev", "devfs") for jail in live}
    seen = set()
    for line in n.backend.output("mount", "-p").splitlines():
        row = line.split()
        _require(len(row) == 6 and "\\" not in row[0] + row[1] and row[1].startswith("/"))
        if row[0] in manifest["datasets"] or any(row[1] == r.mountpoint or row[1].startswith(r.mountpoint + "/")
                or row[2] == "nullfs" and (recovery._related(row[0], r.mountpoint) or recovery._related(row[1], r.mountpoint))
                for r in context.resources):
            triple = tuple(row[:3])
            _require(triple in expected | devices and triple not in seen)
            seen.add(triple)
    _require(expected <= seen)
    for root in recovery._roots(context):
        names = n.backend.output("zfs", "list", "-H", "-o", "name", "-t", "filesystem,volume", "-r", root).splitlines()
        _require(len(names) == len(set(names)) and set(names) == {r.name for r in context.resources if r.name == root or r.name.startswith(root + "/")})
    for r in context.resources:
        for key, value in (("guid", manifest["datasets"][r.name]["guid"]), ("type", "filesystem"), ("origin", "-"),
                ("mounted", "yes"), ("mountpoint", r.mountpoint), (recovery.OWNER, n.c.instance), (recovery.MANAGER, "cloud-installer")):
            _require(n.backend.get(r.name, key) == value)
        df = n.backend.output("df", "-P", r.mountpoint).splitlines()
        _require(n.backend.output("realpath", r.mountpoint) == r.mountpoint and len(df) == 2
                 and len(df[-1].split()) == 6 and df[-1].split()[0] == r.name and df[-1].split()[-1] == r.mountpoint)
    _require(n.backend.snapshots(context, manifest["datasets"]) == manifest["snapshots"])
    from .lifecycle import _checked_jails
    for jail in roots:
        _require({name for name, _ in _checked_jails(n.d, [jail], stopped=jail not in live)} == {jail})
        _require(n.backend.output("bastille", "config", jail, "get", "path") == roots[jail])
        hostname = n.c.nextcloud_host if jail == n.c.nextcloud_jail else n.c.onlyoffice_host
        _require(n.backend.output("bastille", "config", jail, "get", "host.hostname") == hostname)
    return journal["evidence"]["recovery_set"]


def chain(store, data):
    directory, binding, config, inputs, journal, proof, publication, graph, generation = data
    path = directory + "/opening-active.json"
    if not store._present(path):
        return None, None
    active = _json(store._read(path))
    _fields(active, "schema_version request")
    _schema(active)
    ref, seen, newest, identity, boots = active["request"], set(), None, None, set()
    while ref is not None:
        _require(ref["path"].startswith(directory + "/opening-request-") and ref["path"] not in seen and len(seen) < 128)
        seen.add(ref["path"])
        request = _json(store._bound(ref))
        _fields(request, "schema_version kind intent publication readiness journal terminal graph generation profile roots previous boot confirmation checkpoint inspection")
        _schema(request)
        _require(request["kind"] == "native-publication-continuation" and request["intent"] == binding["intent"]
                 and request["publication"] == publication and request["readiness"] == journal["evidence"]["readiness"]
                 and request["journal"] == _json(store._bound(publication))["journal"] and request["graph"] == graph
                 and request["generation"] == proof["generation"] and request["profile"] == store.reference(directory + "/closed-profile.json")
                 and request["roots"] == binding["roots"] and request["confirmation"] == "CONTINUE-PUBLICATION " + inputs["operation"])
        from .maintenance_native import _boot
        _boot(request["boot"])
        _require(request["boot"] not in boots and request["boot"] != proof["boot"])
        boots.add(request["boot"])
        if request["terminal"] is not None:
            _require(request["terminal"] == terminal_binding(store, directory)[0])
        _require(_json(store._bound(request["checkpoint"])) == dict(intent=binding["intent"],
            publication=publication, readiness=request["readiness"], graph=graph,
            boot=request["boot"], confirmation=request["confirmation"], terminal=request["terminal"]))
        store._bound(request["inspection"])
        if newest is None:
            newest = (ref, request)
            identity_path = directory + "/opening-identity-" + ref["sha256"] + ".json"
            if store._present(identity_path):
                identity = _json(store._read(identity_path))
                _fields(identity, "schema_version kind request readiness journal terminal graph boot jids")
                _schema(identity)
                _require(identity["kind"] == "native-publication-identity" and identity["request"] == ref
                         and identity["readiness"] == request["readiness"] and identity["journal"] == request["journal"]
                         and identity["terminal"] == request["terminal"]
                         and identity["graph"] == graph and identity["boot"] == request["boot"]
                         and set(identity["jids"]) == set(binding["roots"])
                         and all(type(jid) is int and jid > 0 for jid in identity["jids"].values())
                         and len(set(identity["jids"].values())) == len(identity["jids"]))
                progress = _json(store._read(directory + "/opening-progress-" + ref["sha256"] + ".json"))
                _fields(progress, "schema_version request states")
                _schema(progress)
                _require(progress["request"] == ref and set(progress["states"]) == set(identity["jids"]))
                for jail, jid in identity["jids"].items():
                    state = progress["states"][jail]
                    _fields(state, "state jid observation")
                    _require(state["state"] == "observed" and state["jid"] == jid)
                    observed = _json(store._bound(state["observation"]))
                    _fields(observed, "request boot jail root jid classification")
                    _require(observed == dict(request=ref, boot=request["boot"], jail=jail, root=binding["roots"][jail],
                        jid=jid, classification=observed["classification"])
                        and observed["classification"] in ("observed-after-start", "observed-after-interruption"))
        ref = request["previous"]
    return newest, identity


def current_identity(n, proof):
    if not n.store._present(n.directory + "/opening-active.json"):
        return dict(boot=proof["boot"], jids=proof["jids"])
    data = bound(n.store, terminal=True)
    _require(data[5] == proof)
    _, identity = chain(n.store, data)
    _require(identity is not None, "publication-start-reconciliation-required")
    return dict(boot=identity["boot"], jids=identity["jids"])


def progress_path(n):
    """New boot gets its own forward replay; old uncertain/completed steps remain."""
    if not n.store._present(n.directory + "/opening-active.json"):
        return n.directory + "/publication-progress.json"
    newest, identity = chain(n.store, bound(n.store, terminal=True))
    _require(identity is not None, "publication-start-reconciliation-required")
    return n.directory + "/publication-progress-" + newest[0]["sha256"] + ".json"


def continue_publication(publication, confirmation):
    n = publication.context
    _require(confirmation == "CONTINUE-PUBLICATION " + n.operation, "exact-publication-confirmation-required")
    journal, proof = publication._publication_context()
    terminal = journal["phase"] in ("complete", "recovered")
    terminal_ref = terminal_binding(n.store, n.directory)[0] if terminal else None
    pubref = (n.store.reference(n.directory + "/native-publication.json") if terminal else
              publication._publication_record(journal))
    data = bound(n.store, terminal=True)
    previous, identity = chain(n.store, data)
    from .maintenance_native import _boot
    boot = _boot(n.backend.output("sysctl", "-n", "kern.boottime"))
    live = _pair(n)
    checkpoint = dict(intent=n.journal.reference, publication=pubref, readiness=journal["evidence"]["readiness"],
                      graph=n.store._active(), boot=boot, confirmation=confirmation, terminal=terminal_ref)
    checkpoint_ref = n.record("opening-confirmation-" + _hash(_encode(checkpoint)), checkpoint)
    # Every explicit resume validates actual executable/static bytes before any
    # old-JID shortcut or command inside either jail. Known profile states are
    # compared read-only; mutable config.php contents are not an old-data gate.
    profile, _ = fence._profile(n.store, n.profile())
    fence._check_files(n.store, profile, "publication-either")
    inspection = payload(n.store, n.c, data[3], data[4], proof)
    storage(n, data[3], data[4], live)
    inspected = n.record("opening-inspection-" + _hash(_encode(inspection)), inspection)
    if previous is None and boot == proof["boot"]:
        publication.check_publication()
        return dict(boot=proof["boot"], jids=proof["jids"])
    if identity is not None and identity["boot"] == boot:
        publication.check_publication()
        return identity
    if previous is None or previous[1]["boot"] != boot:
        _require(not live, "new-publication-boot-requires-stopped-pair")
    for jail in live:
        _require(not n.backend.running(jail, "cron") and not n.backend.running(jail, "sshd"),
                 "publication-start-scheduled-writer-running")
    fence.publication_profile(n.registry, n.profile(), publication=pubref)
    if previous is None or previous[1]["boot"] != boot:
        _require(boot != proof["boot"] or previous is not None, "publication-pair-loss-needs-separate-assessment")
        request = dict(schema_version=1, kind="native-publication-continuation", intent=n.journal.reference,
            publication=pubref, readiness=journal["evidence"]["readiness"], journal=_json(n.store._bound(pubref))["journal"],
            terminal=terminal_ref,
            graph=n.store._active(), generation=proof["generation"], profile=n.profile(), roots=data[1]["roots"],
            previous=previous[0] if previous else None, boot=boot, confirmation=confirmation,
            checkpoint=checkpoint_ref, inspection=inspected)
        ref = n.record("opening-request-" + _hash(_encode(request)), request)
        n.store._put(n.directory + "/opening-active.json", dict(schema_version=1, request=ref),
                     replace=n.store._present(n.directory + "/opening-active.json"))
    else:
        ref, request = previous
        _require(request["inspection"] == inspected)
    path = n.directory + "/opening-progress-" + ref["sha256"] + ".json"
    states = {jail: dict(state="waiting", jid=None, observation=None) for jail in data[1]["roots"]}
    if n.store._present(path):
        progress = _json(n.store._read(path))
        _fields(progress, "schema_version request states")
        _schema(progress)
        _require(progress["request"] == ref and set(progress["states"]) == set(states))
        states = progress["states"]
    for jail, item in states.items():
        _fields(item, "state jid observation")
        _require(item["state"] in ("waiting", "starting", "observed"))
        if item["state"] == "observed":
            _require(type(item["jid"]) is int and item["jid"] > 0 and live.get(jail) == item["jid"])
            n.store._bound(item["observation"])
        else:
            _require(item["jid"] is None and item["observation"] is None
                     and (jail not in live or item["state"] == "starting"))
    with fence.publication_starts(n.registry, _json(n.store._bound(data[1]["intent"])), n.profile(), ref):
        for jail, item in states.items():
            publication._publication_context()
            _require(_boot(n.backend.output("sysctl", "-n", "kern.boottime")) == boot)
            live = _pair(n)
            storage(n, data[3], data[4], live)
            if item["state"] == "observed":
                _require(live.get(jail) == item["jid"])
                continue
            interrupted = jail in live
            if interrupted:
                _require(item["state"] == "starting")
            else:
                item["state"] = "starting"
                n.store._put(path, dict(schema_version=1, request=ref, states=states), replace=n.store._present(path))
                n.backend.run("bastille", "start", jail)
            observed = _pair(n)
            _require(jail in observed and all(observed.get(name) == jid for name, jid in live.items()))
            storage(n, data[3], data[4], observed)
            jid = n.d.require_running_jail(jail)
            _require(observed[jail] == jid)
            observation = n.record("opening-start-observed-" + _hash(_encode([ref, jail, jid])), dict(
                request=ref, boot=boot, jail=jail, root=data[1]["roots"][jail], jid=jid,
                classification="observed-after-interruption" if interrupted else "observed-after-start"))
            item.update(state="observed", jid=jid, observation=observation)
            n.store._put(path, dict(schema_version=1, request=ref, states=states), replace=True)
    n.backend.owned_live()
    live = _pair(n)
    _require(live == {jail: item["jid"] for jail, item in states.items()}
             and _boot(n.backend.output("sysctl", "-n", "kern.boottime")) == boot)
    result = dict(schema_version=1, kind="native-publication-identity", request=ref, readiness=request["readiness"],
                  journal=request["journal"], terminal=request["terminal"], graph=request["graph"], boot=boot, jids=live)
    n.record("opening-identity-" + ref["sha256"], result)
    publication.check_publication()
    return result


@contextmanager
def publication_session(registry, runner, operation):
    """Existing publication only; the general NativeContext.check stays closed."""
    from .maintenance import executor_record, _deployment
    from .maintenance_state import NativeState
    from .maintenance_native import NativeContext
    from .operations import _database_guard
    with registry.locked(recovery=True):
        native = NativeState(registry, executor_record())
        _, inputs = native.read(operation)
        directory = "maintenance/operations/" + operation
        journal = native_validate(_json(native.store._read(directory + "/native-journal.json")))
        _require(journal["phase"] in ("opening", "recovery-opening", "complete", "recovered"))
        deployment = _deployment(native.view(operation), inputs["instance"], runner)
        with _database_guard(deployment):
            admission = _json(native.store._read(directory + "/admission.json"))
            native.store._bound(admission["evidence"])
            n = NativeContext(registry, native, operation, deployment, admission)
            n.active = True
            try:
                p = Publication(n)
                p._publication_context()
                yield p
            finally:
                n.active = False
