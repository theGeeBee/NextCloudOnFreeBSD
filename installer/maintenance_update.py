"""Internal fixed NC patch adapter, exclusively for a trusted native harness.

No catalog registration or CLI authority. Native acceptance has NOT RUN. Prepare
local artifacts while the original pair is running, after NativeState.begin;
then pass NextcloudPatch(prepared) to NativeContext.migrate after offline capture.
Missing signed-source staging support is a blocker, never inferred provenance.
Updater effects have their own immutable records: writing NativeJournal inside
validation_starts would invalidate its exact-hash start permission.
"""

from dataclasses import asdict, dataclass
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import stat
import xml.etree.ElementTree as ET

from . import nextcloud_update as update, recovery_sets as recovery
from .generations import _encode, _json, _fields, _reference
from .maintenance_native import MigrationAdapter, NativeContext
from .maintenance_preflight import recipe, _actual_packages, _php
from .maintenance_state import NativeView
from .resolution import validate_plan


DENIED = "Nextcloud patch prerequisites failed; retain private evidence for recovery"
PROTECTED = frozenset(("config", "custom_apps", "data", "tls"))


class PrerequisiteError(ValueError):
    """Public, fixed blocker identifiers only; never include command diagnostics."""

    def __init__(self, *blockers):
        self.blockers = tuple(blockers)
        super().__init__(DENIED + ": " + ", ".join(blockers))


def _require(value, code="source-or-phase-binding"):
    if not value:
        raise PrerequisiteError(code)


def descriptor():
    # One exact descriptor binds admission, preflight and successor sealing.
    # Implementation bytes are independently bound by the retained executor;
    # this inspection descriptor never grants native execution authority.
    return recipe()


def _hash(value):
    return hashlib.sha256(_encode(value)).hexdigest()


def _relative(name):
    _require(type(name) is str and name and len(name) <= 1024
             and not name.startswith("/") and "\\" not in name
             and all(part not in ("", ".", "..") for part in name.split("/")))
    return name


def _directories(inventory):
    result = {""}
    for name in (*inventory.directories, *(item.path for item in inventory.files), *(item.path for item in inventory.links)):
        if not name:
            continue
        _relative(name)
        result.update(str(p) for p in Path(name).parents if str(p) != ".")
    result.update(inventory.directories)
    return result


def _protected(name):
    return name.split("/", 1)[0] in PROTECTED


def _tree(root, *, owners, omit=(), aliases=None):
    """Full no-follow manifest, with only explicitly authenticated source aliases.

    This is inspection, never a permission target generator. Mutation targets
    below come exclusively from authenticated archive inventories.
    """
    files, directories, links, total = {}, {}, {}, 0
    aliases = {} if aliases is None else aliases

    def visit(path, relative):
        nonlocal total
        with update._directory(path, owners) as directory:
            info = os.fstat(directory)
            directories[relative] = [info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)]
            for name in sorted(os.listdir(directory)):
                _relative(name)
                child = relative + "/" + name if relative else name
                total += 1
                _require(total <= update.MAX_ENTRIES, "oversized-live-tree")
                before = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if not relative and name in omit:
                    _require(stat.S_ISDIR(before.st_mode), "unsafe-protected-path")
                    # Pin even the protected directory; no symlink ancestry.
                    with update._directory(path / name, owners):
                        pass
                    continue
                if child in aliases:
                    _require(stat.S_ISLNK(before.st_mode), "source-alias-not-link")
                    target = os.readlink(name, dir_fd=directory)
                    after = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    _require(target == aliases[child] and update._identity(before) == update._identity(after),
                             "source-alias-drift-or-race")
                    links[child] = dict(target=target, uid=after.st_uid, gid=after.st_gid,
                                        mode=stat.S_IMODE(after.st_mode))
                elif stat.S_ISDIR(before.st_mode):
                    visit(path / name, child)
                else:
                    digest, size = update._digest_file(path / name, update.MAX_FILE, owners)
                    after = os.stat(name, dir_fd=directory, follow_symlinks=False)
                    _require(update._identity(before) == update._identity(after), "live-file-raced")
                    files[child] = dict(sha256=digest, size=size, uid=after.st_uid,
                                       gid=after.st_gid, mode=stat.S_IMODE(after.st_mode))
    visit(Path(root), "")
    _require(set(links) == set(aliases), "source-alias-missing")
    result = dict(files=files, directories=directories)
    if aliases:
        result["links"] = links
    return result


def _code(context, inventory):
    aliases = update.source_aliases(inventory)
    observed = _tree(context.host(update.APP), owners=(context.www_uid,), omit=PROTECTED, aliases=aliases)
    expected = {item.path: item for item in inventory.files if not _protected(item.path)}
    _require(set(observed["files"]) == set(expected), "unexpected-or-missing-code")
    _require(set(observed["directories"]) == {name for name in _directories(inventory)
                                            if not _protected(name)}, "unexpected-code-directory")
    for name, item in expected.items():
        actual = observed["files"][name]
        identity = (actual["sha256"], actual["size"])
        if identity != (item.sha256, item.size):
            _require(name == ".htaccess", "code-byte-drift")
            with update._file(context.host(update.APP + "/" + name), update.MAX_FILE, (context.www_uid,)) as stream:
                _require(_archive_file(stream, item) == identity, "code-byte-drift")
        actual["expected_mode"] = 0o750 if item.executable else 0o640
    return observed


def _archive_file(stream, item):
    try:
        return update.code_file_identity(stream, item)
    except update.UpdateError:
        raise PrerequisiteError("code-byte-drift") from None


def _hardened(context, observed):
    _require(all(value["uid"] == update._ROOT_UID and value["gid"] == context.www_gid
                 and value["mode"] == value["expected_mode"]
                 for value in observed["files"].values()) and all(value == [update._ROOT_UID, context.www_gid, 0o750]
                  for value in observed["directories"].values()), "code-not-hardened")
    # FreeBSD symlinks retain creation umask (0700); Linux reports fixed 0777.
    # The original static baseline separately binds the actual mode/link text.
    _require(all(value["uid"] == update._ROOT_UID and value["gid"] == context.www_gid and value["mode"] in (0o700, 0o777)
                 for value in observed.get("links", {}).values()), "source-alias-not-hardened")


def _config_metadata(context):
    path = context.host(update.APP + "/config/config.php")
    with update._file(path, 1024 * 1024, (context.www_uid,)) as stream:
        info = os.fstat(stream.fileno())
        _require(info.st_uid == context.www_uid and stat.S_IMODE(info.st_mode) == 0o600,
                 "config-owner-or-mode")
        result = [info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)]
    with update._directory(path.parent, (context.www_uid,)) as directory:
        info = os.fstat(directory)
        result.extend((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)))
    return result


def _custom(context):
    # Every connector byte and every empty/non-shipped directory is bound. No
    # symlinks, hardlinks or special files are admitted, including nested paths.
    result = _tree(context.host(update.APP + "/custom_apps"), owners=(context.www_uid,))
    _require({name.split("/", 1)[0] for name in result["files"]} == {"onlyoffice"},
             "unreviewed-custom-app")
    _require(all(not name or name == "onlyoffice" or name.startswith("onlyoffice/")
                 for name in result["directories"]), "unreviewed-custom-directory")
    return result


def _permissions(authority, inventory, *, writable):
    """Hash each exact file through its pinned fd immediately before fchown.

    Partial batches are NEVER replayed. Config/custom_apps/data/TLS are excluded
    even if present in the distribution. Directory ownership, including the app
    root, temporarily becomes www: no group-write or arbitrary recursive chown.
    """
    context = authority.context
    authority.validate(context, update.Phase.CONFIG if writable else update.Phase.MIGRATION)
    _code(context, inventory)
    event = "code-writable" if writable else "code-hardened"
    binding = _hash(update.inventory_record(inventory))
    authority.checkpoint(context, event, "before", binding)
    uid = context.www_uid if writable else update._ROOT_UID
    for item in inventory.files:
        if _protected(item.path):
            continue
        path = context.host(update.APP + "/" + _relative(item.path))
        with update._directory(path.parent, (context.www_uid,)) as directory:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            with os.fdopen(fd, "rb") as stream:
                before = os.fstat(stream.fileno())
                _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                         and before.st_uid in (update._ROOT_UID, context.www_uid)
                         and not before.st_mode & 0o7022, "unsafe-code-permissions")
                _archive_file(stream, item)
                _require(update._identity(before) == update._identity(os.fstat(stream.fileno()))
                         == update._identity(os.stat(path.name, dir_fd=directory, follow_symlinks=False)),
                         "code-file-raced")
                os.fchown(stream.fileno(), uid, context.www_gid)
                os.fchmod(stream.fileno(), 0o750 if item.executable else 0o640)
                os.fsync(stream.fileno())
    for name in sorted(_directories(inventory), key=lambda n: (-n.count("/"), n), reverse=False):
        if not _protected(name):
            with update._directory(context.host(update.APP + ("/" + name if name else "")),
                                   (context.www_uid,)) as directory:
                os.fchown(directory, uid, context.www_gid)
                os.fchmod(directory, 0o750)
                os.fsync(directory)
    authority.validate(context, update.Phase.CONFIG if writable else update.Phase.MIGRATION)
    authority.checkpoint(context, event, "after", binding)


@dataclass(frozen=True)
class PreparedUpdate:
    operation: str
    reference: dict
    bundle: update.StagedUpdate


class RealAuthority(update.Authority):
    """Only a live NativeContext with its exact original NativeView is admitted."""

    def __init__(self, native, *, runner, memory_mib=None):
        _require(isinstance(native, NativeContext), "native-context-required")
        _require(callable(runner), "bounded-native-runner-required")
        self.native, self.bundle, self.prepared = native, None, None
        self.pair = None
        self.context = None
        self.runner = runner
        self.memory_mib = native.c.php_memory_mb if memory_mib is None else memory_mib
        self._original()
        self.pair = self._pair()
        backend = native.backend
        uid = backend.jailed(native.c.nextcloud_jail, "id", "-u", "www").stdout.strip()
        gid = backend.jailed(native.c.nextcloud_jail, "id", "-g", "www").stdout.strip()
        _require(uid.isdigit() and gid.isdigit(), "www-identity-unavailable")
        self.context = update.NativeContext(native.operation, self.pair[native.c.nextcloud_jail],
            native.c.nextcloud_jail, native.d.jail_root(native.c.nextcloud_jail), int(uid), int(gid),
            self.memory_mib, self, self._run)
        _require(self._pair() == self.pair, "pair-identity-changed")

    def _original(self):
        n = self.native
        intent, inputs, journal = n.check()
        view = n.d.registry
        _require(isinstance(view, NativeView) and view._state is n.native
                 and view._operation == n.operation and inputs["recipe"] == descriptor())
        files = inputs["originals"][n.c.instance]["files"]
        _require(json.loads(n.c.to_json()) == _json(n.store._bound(files["config.json"]["retained"])))
        _require(n.d.versions == _json(n.store._bound(files["versions.json"]["retained"])))
        validate_plan(n.c, n.d.versions)
        reviewed = recipe()
        _require(n.d.versions["applications"]["nextcloud"] == update.SOURCE[0]
                 and n.d.versions["applications"]["onlyoffice"] == reviewed["onlyoffice"]
                 and n.d.versions["connector"]["version"] == reviewed["connector"]
                 and {key: n.d.versions["target"][key] for key in reviewed["target"]} == reviewed["target"])
        n.store._bound(n.admission["evidence"])
        return intent, inputs, journal

    def _pair(self):
        n = self.native
        n.backend.owned_live()
        result = {jail: n.d.require_running_jail(jail) for jail in (n.c.nextcloud_jail, n.c.onlyoffice_jail)}
        _require(all(type(jid) is int and jid > 0 for jid in result.values()), "numeric-pair-jid-required")
        return result

    def _run(self, argv, **kwargs):
        _require(tuple(argv[:2]) == ("/usr/sbin/jexec", str(self.context.jid)))
        _require(self._pair() == self.pair, "pair-identity-changed")
        try:
            return self.runner(argv, **kwargs)
        finally:
            _require(self._pair() == self.pair, "pair-identity-changed")

    def _recovery(self, journal):
        n = self.native
        reference = journal["evidence"]["recovery_set"]
        _require(reference == n.store.reference(n.directory + "/recovery/manifest.json"))
        context = n._recovery_context()
        manifest = recovery.validate_manifest(context, _json(n.store._bound(reference)))
        recovery._acknowledgement(context)
        _require(recovery._copies(context) == manifest["evidence"], "recovery-copy-drift")
        for dataset, meta in manifest["datasets"].items():
            _require(n.backend.get(dataset, "guid") == meta["guid"]
                     and n.backend.get(dataset, "mountpoint") == meta["mountpoint"], "recovery-dataset-drift")
        _require(n.backend.snapshots(context, manifest["datasets"]) == manifest["snapshots"],
                 "recovery-snapshot-drift")
        return reference

    def validate(self, context, phase):
        _require(context is self.context and isinstance(phase, update.Phase))
        _, _, journal = self._original()
        _require(self._pair() == self.pair, "pair-identity-changed")
        if phase == update.Phase.ARTIFACTS:
            _require(journal["phase"] == "capture" and not journal["steps"], "stage-before-downtime-required")
        else:
            _require(journal["phase"] == "migrating", "exact-migration-phase-required")
            step = journal["steps"].get("reviewed-migration", {})
            _require(step.get("state") == "running" and step.get("replay") == "never"
                     and step.get("attempts") == 1 and step.get("phase") == "migrating"
                     and step.get("precondition") == journal["evidence"]["recovery_set"],
                     "outer-never-replay-step-required")
            self.native.check(closed=True)
            self.native.backend.closed_flags()
            self._recovery(journal)
            if phase in (update.Phase.UPDATER, update.Phase.TARGET, update.Phase.MIGRATION,
                         update.Phase.RESTORE_CONFIG):
                self.done("writers-stopped")
                self.native.backend.wait_writer_closure(database_running=True)
                _require(self.bundle is not None and self.prepared is not None)
                _require(_custom(context) == self.prepared["custom"], "custom-app-byte-drift")
                _require(_config_metadata(context) == self.prepared["config_metadata"], "config-metadata-drift")
                packages, full = _package_observations(self)
                _require(packages == self.prepared["observations"]["packages"]
                         and full == self.prepared["observations"]["full_packages"], "live-package-closure-drift")
            if phase == update.Phase.UPDATER:
                self.done("code-writable")
                self.done("suppress-appstore")
            if phase == update.Phase.MIGRATION:
                self.done("target-code-verified")

    def source(self, context, reference):
        self.validate(context, update.Phase.ARTIFACTS)
        # This only binds retained bytes to the original instance. Authenticity
        # additionally MUST come from stage_artifacts' source detached signature.
        _require(reference == update.SourceReference(
            update._digest_file(context.host(update.RETAINED), update.MAX_ARCHIVE)[0],
            update._hash(update._read(context.host(update.SHA_PROOF), 128))))
        self.native.d.require_original_artifact()

    def artifacts(self, context, bundle):
        _require(context is self.context and bundle == self.bundle and self.prepared is not None)
        _require(self.prepared["bundle"] == json.loads(_encode(update.bundle_record(bundle))))

    def _event_path(self, event, state):
        _require(re.fullmatch(r"[a-z0-9-]{1,80}", event) and state in ("before", "after"))
        return self.native.directory + "/update-" + event + "-" + state + ".json"

    def done(self, event):
        n = self.native
        value = _json(n.store._read(self._event_path(event, "after")))
        _fields(value, "schema_version kind operation intent journal event state binding before")
        _require(type(value["schema_version"]) is int and value["schema_version"] == 1
                 and value["kind"] == "nextcloud-update-effect" and value["operation"] == n.operation
                 and value["event"] == event and value["state"] == "after"
                 and value["intent"] == n.store.reference(n.directory + "/intent.json")
                 and type(value["binding"]) is str and len(value["binding"]) <= 4096)
        _reference(value["journal"], n.journal.path)
        if event != "target-code-verified":
            _require(value["before"] == n.store.reference(self._event_path(event, "before")))
            before = _json(n.store._bound(value["before"]))
            _fields(before, "schema_version kind operation intent journal event state binding before")
            _require(before["state"] == "before" and before["before"] is None
                     and before["intent"] == value["intent"] and before["operation"] == n.operation
                     and before["event"] == event and before["journal"] == value["journal"]
                     and (event == "stage-artifacts" or before["binding"] == value["binding"]))
        else:
            _require(value["before"] is None and self.done("target-integrity")["binding"] == value["binding"])
        return value

    def checkpoint(self, context, event, state, binding):
        _require(context is self.context and type(binding) is str and len(binding) <= 4096)
        n = self.native
        self._original()
        path = self._event_path(event, state)
        # Even a fully written prior 'before' is an attempt, not permission to
        # retry. record(recover=True) alone would incorrectly admit identical bytes.
        _require(not n.store._present(path), "effect-already-attempted")
        previous = None
        if state == "after" and event != "target-code-verified":
            previous = n.store.reference(self._event_path(event, "before"))
            old = _json(n.store._bound(previous))
            _require(old["operation"] == n.operation and old["event"] == event and old["state"] == "before")
            _require(event == "stage-artifacts" or old["binding"] == binding, "effect-binding-changed")
        if event == "target-code-verified":
            _require(self.done("target-integrity")["binding"] == binding)
        if event in ("suppress-appstore", "restore-appstore"):
            original = _json(n.store._read(n.directory + "/update-original-appstore.json"))
            _require(json.loads(binding) == original, "original-appstore-binding")
        value = dict(schema_version=1, kind="nextcloud-update-effect", operation=n.operation,
                     intent=n.store.reference(n.directory + "/intent.json"),
                     journal=n.store.reference(n.journal.path), event=event, state=state,
                     binding=binding, before=previous)
        reference = n.record("update-" + event + "-" + state, value)
        progress = n.directory + "/update-progress.json"
        n.store._put(progress, dict(schema_version=1, kind="nextcloud-update-progress",
            operation=n.operation, intent=value["intent"], effect=reference), replace=n.store._present(progress))

    def capacity(self, zip_size):
        n = self.native
        memory = self.memory_mib * 1024 * 1024
        _require(memory >= 3 * zip_size + 256 * 1024 * 1024
                 and self.memory_mib <= n.c.php_budget_mb, "updater-memory-budget")
        page_size = int(n.backend.output("sysctl", "-n", "hw.pagesize"))
        free_pages = int(n.backend.output("sysctl", "-n", "vm.stats.vm.v_free_count"))
        _require(page_size >= 4096 and free_pages >= 0 and free_pages * page_size >=
                 memory + n.c.host_reserved_mb * 1024 * 1024, "actual-free-memory-insufficient")
        for path in (update.APP, "/var/nc-data", "/var/db"):
            available = os.statvfs(self.context.host(path))
            _require(available.f_bavail * available.f_frsize >= 2 * update.MAX_EXPANDED + zip_size,
                     "actual-update-space-insufficient")


def _package_observations(authority):
    _require(authority._pair() == authority.pair, "pair-identity-changed")
    try:
        return _read_packages(authority)
    finally:
        _require(authority._pair() == authority.pair, "pair-identity-changed")


def _read_packages(authority):
    from .enrollment import _packages
    n = authority.native
    packages = _packages(n.d, _json(n.store._read(f"instances/{n.c.instance}/inventory.json")))
    full_packages = {}
    _require(authority._pair() == authority.pair, "pair-identity-changed")
    for group, jail in (("host", None), ("nextcloud", n.c.nextcloud_jail), ("onlyoffice", n.c.onlyoffice_jail)):
        output = (n.d.runner.output("pkg", "query", "%n %v %o") if jail is None else
                  n.d.jail(jail, "pkg", "query", "%n %v %o", hide_output=True).stdout)
        rows = [line.split() for line in output.splitlines() if line.strip()]
        _require(rows and all(len(row) == 3 for row in rows), "complete-package-inventory-required")
        full_packages[group] = [dict(zip(("name", "version", "origin"), row)) for row in sorted(rows)]
    _actual_packages(full_packages, n.d.versions)
    return packages, full_packages


def _runtime(authority, *, target=False):
    _require(authority._pair() == authority.pair, "pair-identity-changed")
    try:
        return _read_runtime(authority, target=target)
    finally:
        _require(authority._pair() == authority.pair, "pair-identity-changed")


def _read_runtime(authority, *, target=False):
    from .runtime_inventory import collect_php
    from .versions import load_policy, package_upstream
    n = authority.native
    packages, full_packages = _package_observations(authority)
    php = collect_php(n.d)
    _php(php, n.d.versions, load_policy())
    database = n.backend.jailed(n.c.nextcloud_jail, "/usr/local/bin/mariadb", "--no-defaults",
        "--protocol=socket", "--socket=/var/run/mysql/mysql.sock", "--user=root", "--batch",
        "--skip-column-names", "--execute", "SELECT VERSION()").stdout.strip()
    expected_db = package_upstream(n.d.versions["packages"]["nextcloud"][n.d.versions["roles"]["database"]]["version"])
    _require(expected_db.startswith("12.3.") and database.startswith(expected_db + "-MariaDB"),
             "database-runtime-drift")
    status = json.loads(n.backend.occ("status", "--output=json"))
    expected = update.TARGET if target else update.SOURCE
    _require(status.get("installed") is True and status.get("needsDbUpgrade") is False
             and status.get("version") == expected[1] and status.get("versionstring") == expected[0],
             "unexpected-nextcloud-status")
    apps = json.loads(n.backend.occ("app:list", "--output=json"))
    _require(set(apps) == {"enabled", "disabled"} and all(type(v) is dict for v in apps.values())
             and apps["enabled"].get("onlyoffice") == "10.2.1"
             and not set(apps["enabled"]) & set(apps["disabled"]), "application-inventory-unavailable")
    _require(authority._pair() == authority.pair, "pair-identity-changed")
    return dict(packages=packages, full_packages=full_packages, php=php, database=database, status=status, apps=apps)


def _apps(context, inventory, observed):
    expected = {"onlyoffice": "10.2.1"}
    for item in inventory.files:
        if re.fullmatch(r"apps/[a-z][a-z0-9_]{0,63}/appinfo/info.xml", item.path):
            data = update._read(context.host(update.APP + "/" + item.path), update.MAX_FILE, (context.www_uid,))
            _require(update._hash(data) == item.sha256, "app-manifest-byte-drift")
            root = ET.fromstring(data)
            name = item.path.split("/")[1]
            _require(root.findtext("id") == name and len(root.findall("version")) == 1, "app-manifest-identity")
            expected[name] = root.findtext("version")
    actual = {**observed["enabled"], **observed["disabled"]}
    _require(actual == expected, "full-app-inventory-drift")


def prepare(native, *, target_zip, target_asc, target_sig, source_asc, public_key,
            runner=None, memory_mib=None):
    """Local staging only; runner is a trusted bounded NativeResult runner.

    host.Runner buffers unbounded output and does not replace the environment;
    it is deliberately not silently adapted to this stronger interface. The
    disposable acceptance harness must supply the reviewed bounded runner.
    """
    _require("source_asc" in inspect.signature(update.stage_artifacts).parameters,
             "signed-source-staging-helper-required")
    authority = RealAuthority(native, runner=runner, memory_mib=memory_mib)
    context = authority.context
    authority.validate(context, update.Phase.ARTIFACTS)
    n = native
    _, inputs, _ = authority._original()
    from .maintenance_operations import load_operation, _artifact_bindings
    from .maintenance_staging import verify_stage
    parent, plan, staged = load_operation(n.registry, inputs["cache_owner"])
    record = staged.read()
    _require(record["phase"] == "staged" and inputs["preparation"] ==
             n.store.reference(f"maintenance/operations/{parent['operation']}/operation.json"))
    verify_stage(n.registry.root, parent["operation"], plan["artifacts"], record["evidence"]["artifacts"],
                 **_artifact_bindings(n.registry, parent, plan))
    observations = _runtime(authority)
    _require(observations["status"]["maintenance"] is False)
    original = _json(n.store._read(n.directory + "/source-observations.json"))
    _require(observations["packages"] == original["packages"] and observations["php"] == original["php"]
             and observations["database"] == original["database"]
             and _hash(observations["apps"]) == original["apps_sha256"], "original-observation-drift")
    size = update._digest_file(Path(target_zip), update.MAX_ARCHIVE)[1]
    authority.capacity(size)
    parent_path = context.host(update.STAGING)
    authority.checkpoint(context, "staging-parent", "before", str(parent_path))
    if not parent_path.exists():
        update._mkdir(parent_path)
    with update._directory(parent_path) as directory:
        info = os.fstat(directory)
        _require(info.st_uid == update._ROOT_UID and stat.S_IMODE(info.st_mode) in (0o700, 0o710))
    authority.checkpoint(context, "staging-parent", "after", str(parent_path))
    bundle = update.stage_artifacts(context, target_zip=target_zip, target_asc=target_asc,
        target_sig=target_sig, source_asc=source_asc, public_key=public_key)
    _hardened(context, _code(context, bundle.source_inventory))
    _apps(context, bundle.source_inventory, observations["apps"])
    value = dict(schema_version=1, kind="prepared-nextcloud-patch", operation=n.operation,
        intent=n.store.reference(n.directory + "/intent.json"), preparation=inputs["preparation"],
        plan=parent["plan"], admission=n.admission["evidence"], recipe=descriptor(), memory_mib=context.memory_mib,
        bundle=update.bundle_record(bundle), observations=observations, custom=_custom(context),
        config_metadata=_config_metadata(context))
    authority.validate(context, update.Phase.ARTIFACTS)
    reference = n.record("update-prepared", value)
    return PreparedUpdate(n.operation, reference, bundle)


class NextcloudPatch(MigrationAdapter):
    """Fixed, unregistered adapter. The outer controller owns recovery on error."""

    def __init__(self, prepared, *, runner=None):
        _require(isinstance(prepared, PreparedUpdate), "prepared-artifacts-required")
        self.prepared, self.runner = prepared, runner

    def descriptor(self):
        return descriptor()

    def execute(self, native):
        _require(native.operation == self.prepared.operation)
        record = _json(native.store._bound(self.prepared.reference))
        _require(self.prepared.reference == native.store.reference(native.directory + "/update-prepared.json")
                 and record["kind"] == "prepared-nextcloud-patch" and record["operation"] == native.operation
                 and record["intent"] == native.store.reference(native.directory + "/intent.json")
                 and record["recipe"] == descriptor())
        authority = RealAuthority(native, runner=self.runner, memory_mib=record["memory_mib"])
        authority.prepared, authority.bundle = record, self.prepared.bundle
        context, bundle = authority.context, authority.bundle
        _, inputs, _ = authority._original()
        _require(record["preparation"] == inputs["preparation"] and record["admission"] == native.admission["evidence"])
        authority.artifacts(context, bundle)
        authority.validate(context, update.Phase.CONFIG)
        authority.done("stage-artifacts")
        authority.checkpoint(context, "adapter", "before", self.prepared.reference["sha256"])
        # The cold controller starts only database/cache services. Briefly start
        # the still-hardened source FPM pools for actual runtime observation;
        # Apache/office/cron/SSH remain stopped and FPM is stopped before any
        # permission or code change. Do not mistake cached pre-downtime modules
        # for a live pool observation.
        _require(not native.backend.running(native.c.nextcloud_jail, "php_fpm"),
                 "unexpected-source-fpm-writer")
        authority.checkpoint(context, "source-runtime", "before", bundle.receipt_sha256)
        native.backend.jailed(native.c.nextcloud_jail, "service", "php_fpm", "onestart")
        try:
            before = _runtime(authority)
        finally:
            native.backend.stop(native.c.nextcloud_jail, "php_fpm")
        authority.checkpoint(context, "source-runtime", "after", bundle.receipt_sha256)
        _require(before["status"]["maintenance"] is True and before["packages"] == record["observations"]["packages"]
                 and before["full_packages"] == record["observations"]["full_packages"]
                 and before["php"] == record["observations"]["php"]
                 and before["database"] == record["observations"]["database"]
                 and before["apps"] == record["observations"]["apps"], "source-runtime-drift")
        _require(_custom(context) == record["custom"] and _config_metadata(context) == record["config_metadata"])
        _hardened(context, _code(context, bundle.source_inventory))
        authority.capacity(next(item.size for item in bundle.artifacts if item.path == "nextcloud-35.0.2.zip"))
        authority.checkpoint(context, "writers-stopped", "before", bundle.receipt_sha256)
        for jail, services in ((native.c.nextcloud_jail, ("apache24", "php_fpm", "cron", "sshd")),
                               (native.c.onlyoffice_jail, ("nginx", "supervisord", "cron", "sshd"))):
            for service in services:
                native.backend.stop(jail, service)
        native.backend.wait_writer_closure(database_running=True)
        authority.checkpoint(context, "writers-stopped", "after", bundle.receipt_sha256)
        original = update.probe_appstore(context)
        native.record("update-original-appstore", asdict(original))
        update.suppress_appstore(context, original)
        authority.checkpoint(context, "staging-traversal", "before", bundle.receipt_sha256)
        with update._directory(context.host(update.STAGING)) as directory:
            os.fchown(directory, update._ROOT_UID, context.www_gid)
            os.fchmod(directory, 0o710)
            os.fsync(directory)
        authority.checkpoint(context, "staging-traversal", "after", bundle.receipt_sha256)
        update.expose_target_zip(context, bundle)
        authority.capacity(next(item.size for item in bundle.artifacts if item.path == "nextcloud-35.0.2.zip"))
        _permissions(authority, bundle.source_inventory, writable=True)
        update.invoke_updater(context, bundle)
        _code(context, bundle.target_inventory)
        proof = update.verify_target_code(context, bundle)
        update.migrate(context, bundle, proof)
        _permissions(authority, bundle.target_inventory, writable=False)
        update.restore_appstore(context, original)
        _require(update.probe_appstore(context, phase=update.Phase.RESTORE_CONFIG) == original)
        # Observe actual final FPM modules under the parent's exact-hash start
        # permission, with ingress/cron/SSH/office still closed. Stop it again.
        authority.checkpoint(context, "final-runtime", "before", bundle.receipt_sha256)
        native.backend.jailed(native.c.nextcloud_jail, "service", "php_fpm", "onestart")
        try:
            after = _runtime(authority, target=True)
        finally:
            native.backend.stop(native.c.nextcloud_jail, "php_fpm")
        _require(after["status"]["maintenance"] is True and after["packages"] == before["packages"]
                 and after["full_packages"] == before["full_packages"]
                 and after["database"] == before["database"]
                 and after["php"] == before["php"], "target-runtime-drift")
        _apps(context, bundle.target_inventory, after["apps"])
        _require(all(set(after["apps"][kind]) == set(before["apps"][kind]) for kind in ("enabled", "disabled")),
                 "application-enabled-state-drift")
        hardened = _code(context, bundle.target_inventory)
        _hardened(context, hardened)
        authority.validate(context, update.Phase.RESTORE_CONFIG)
        authority.checkpoint(context, "final-runtime", "after", bundle.receipt_sha256)
        authority.checkpoint(context, "adapter", "after", self.prepared.reference["sha256"])
        return native.record("update-result", dict(schema_version=1, kind="nextcloud-patch-result",
            operation=native.operation, prepared=self.prepared.reference, receipt_sha256=bundle.receipt_sha256,
            target=list(update.TARGET), runtime=after, hardened_sha256=_hash(hardened),
            custom_sha256=_hash(record["custom"]), appstore=asdict(original), maintenance=True,
            native_acceptance="not-run", publication_authorized=False))
