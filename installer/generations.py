"""Private, local-only lifecycle storage (schema 1); no enrollment orchestration.

Writers MUST hold Registry.locked(). This module does not establish eligibility,
inspect resources, authorize enrollment, install guards, or validate locks against
the current checkout. A source-bound adapter must do those things explicitly.

Storage workflow: begin -> archive_legacy -> seal_generation -> write descriptor
and verify external guards -> commit (the COMPLETE instance map) -> finish. Interrupted
writes leave the pending fence and immutable evidence in place. No recovery is
inferred and no published file is deleted. finish is an explicit assertion by the
caller that graph/PF consistency and external fence cleanup were verified.

resolve returns a dictionary: exact config bytes/document, status, provenance,
instance/evidence/effective-file paths, and optional manifest. It does not call
Config.from_json: that method applies today's policy to historical inputs. The
caller must use its reviewed source-bound adapter before executing anything.
Store(root, config_loader=...) optionally calls loader(config_bytes, provenance)
and includes its result as "config"; otherwise "config" is the raw document.
Ordinary graph/resolve reads refuse pending mutations. graph(validate_evidence=
False) is ONLY available while fenced: it validates the committed graph's own
hash/schema and reference shapes, not mutable legacy files or directory coverage.

References are root-relative {path, sha256} objects. IDs are lowercase ASCII
letters/digits/hyphens (1..64, starting with a letter); instances retain the
existing 1..8 letter/digit format. Archives copy all regular instance files except
secrets.json and reserved legacy/generations directories. Credentials are hashed
in place, never copied or returned. Evidence bytes are supplied explicitly, not
fabricated; policy.json and resources.json are required. Their domain semantics,
including inventory completeness, belong to the enrollment adapter.

archive_legacy/seal_generation recover=True is explicit same-intent replay. An
immutable operation-local hash plan and private byte snapshots precede destination
writes. Missing snapshot members require exact original/supplied bytes; existing
members are never replaced. Missing plans, unexpected files, symlinks, hardlinks
and changed content require separate recovery rather than automatic cleanup.
"""

from dataclasses import dataclass, fields
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile

from .config import Config, SCHEMA_VERSION as CONFIG_SCHEMA, STATE_DIR


SCHEMA_VERSION = 1
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_FILES = 1024
MAX_DEPTH = 16
STATES = {"configured", "installing", "failed", "ready", "removing", "removed"}


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def _fields(value, names):
    if type(value) is not dict or set(value) != set(names.split()):
        raise ValueError("Unexpected lifecycle record fields")


def _schema(value):
    if type(value.get("schema_version")) is not int or value["schema_version"] != SCHEMA_VERSION:
        raise ValueError("Unsupported lifecycle schema")


def _id(value, instance=False):
    pattern = r"[a-z][a-z0-9]{0,7}" if instance else r"[a-z][a-z0-9-]{0,63}"
    if type(value) is not str or not re.fullmatch(pattern, value):
        raise ValueError("Invalid lifecycle identifier")
    return value


def _digest(value):
    if type(value) is not str or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("Invalid lifecycle content hash")
    return value


def _relative(value):
    if (type(value) is not str or len(value) > 1024 or not value
            or len(value.split("/")) > MAX_DEPTH
            or any(not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", part)
                   for part in value.split("/"))):
        raise ValueError("Unsafe lifecycle relative path")
    return value


def _reference(value, expected=None):
    _fields(value, "path sha256")
    _relative(value["path"])
    _digest(value["sha256"])
    if expected is not None and value["path"] != expected:
        raise ValueError("Lifecycle reference has the wrong owner/path")
    return value


def _json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate lifecycle JSON field")
            result[key] = value
        return result
    def invalid_constant(value):
        raise ValueError("Non-finite lifecycle JSON number")
    try:
        value = json.loads(data, object_pairs_hook=unique, parse_constant=invalid_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError("Invalid lifecycle JSON") from None
    if type(value) is not dict:
        raise ValueError("Expected lifecycle JSON object")
    return value


def _encode(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()


def _config(data, name):
    value = _json(data)
    known = {field.name: field.type for field in fields(Config)}
    if (set(value) - set(known) or value.get("instance") != name
            or type(value.get("schema_version")) is not int
            or value["schema_version"] != CONFIG_SCHEMA
            or any(type(item) is not known[key] for key, item in value.items())):
        raise ValueError("Invalid source configuration structure/identity")
    return value


def _status(value):
    if type(value) is not dict or type(value.get("state")) is not str or value["state"] not in STATES:
        raise ValueError("Invalid lifecycle instance status")
    types = dict(state=str, updated=str, error_type=str, next_action=str,
                 initialization_recovered=bool, purge_data=bool, data_retained=bool)
    if set(value) - types.keys() or any(type(item) is not types[key] for key, item in value.items()):
        raise ValueError("Unknown/invalid lifecycle status fields")
    if any(isinstance(item, str) and (len(item) > 256 or any(ord(char) < 32 for char in item))
           for item in value.values()):
        raise ValueError("Invalid lifecycle status text")
    return value


def descriptor(name, generation_ref):
    """Pure legacy-reader refusal descriptor for one sealed generation reference."""
    _id(name, True)
    _reference(generation_ref)
    if not re.fullmatch(re.escape(f"instances/{name}/") + r"generations/[a-z][a-z0-9-]{0,63}/manifest\.json",
                        generation_ref["path"]):
        raise ValueError("Invalid registration generation path")
    return dict(schema_version=1, record_type="lifecycle-registration", instance=name,
                generation=dict(generation_ref))


@dataclass(frozen=True)
class Resolved:
    name: str
    kind: str
    config_bytes: bytes
    config_document: dict
    status: dict
    provenance: dict
    instance_path: Path
    config_path: Path
    versions_path: Path | None
    plugins_path: Path | None
    manifest: dict | None


class Store:
    descriptor = staticmethod(descriptor)

    def __init__(self, root=STATE_DIR, *, config_loader=None):
        # Do not resolve(): that would hide symlink ancestors.
        self.root = Path(os.path.abspath(root))
        self.config_loader = config_loader

    def _parents(self):
        for path in reversed((self.root, *self.root.parents)):
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError("Symlink/non-directory lifecycle ancestor")
        self._check(self.root.lstat(), directory=True)

    @staticmethod
    def _check(info, *, directory=False):
        mode = stat.S_IMODE(info.st_mode)
        if (info.st_uid != os.geteuid()
                or mode not in ((0o700,) if directory else (0o600, 0o400))
                or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
                or (not directory and (info.st_nlink != 1 or info.st_size > MAX_FILE_BYTES))):
            raise ValueError("Unsafe private lifecycle file/directory")

    def _path(self, relative):
        _relative(relative)
        self._parents()
        path = self.root
        parts = PurePosixPath(relative).parts
        for part in parts[:-1]:
            path = path / part
            self._check(path.lstat(), directory=True)
        return path / parts[-1]

    def _present(self, relative):
        try:
            self._path(relative).lstat()
            return True
        except FileNotFoundError:
            return False

    def _mkdir(self, relative):
        _relative(relative)
        self._parents()
        path = self.root
        for part in PurePosixPath(relative).parts:
            child = path / part
            try:
                child.mkdir(mode=0o700)
            except FileExistsError:
                pass
            else:
                self._sync(path)
            self._check(child.lstat(), directory=True)
            path = child
        return path

    @staticmethod
    def _sync(path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _read(self, relative):
        path = self._path(relative)
        self._check(path.lstat())
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            self._check(before)
            data = stream.read(MAX_FILE_BYTES + 1)
            after = os.fstat(stream.fileno())
            self._check(after)
            if (len(data) > MAX_FILE_BYTES or len(data) != before.st_size
                    or (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    != (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                raise ValueError("Lifecycle file changed during read")
        return data

    def reference(self, relative):
        """Hash an existing private file; does not adopt or copy it."""
        return {"path": relative, "sha256": _hash(self._read(relative))}

    def _bound(self, reference, expected=None):
        _reference(reference, expected)
        data = self._read(reference["path"])
        if _hash(data) != reference["sha256"]:
            raise ValueError("Lifecycle referenced content changed")
        return data

    def _write(self, relative, data, *, replace=False):
        if type(data) is not bytes or len(data) > MAX_FILE_BYTES:
            raise ValueError("Lifecycle file exceeds byte/type limit")
        path = self._path(relative)
        if self._present(relative):
            self._check(path.lstat())
            if not replace:
                raise ValueError("Immutable lifecycle record already exists")
        fd, temporary = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            # All supported writers hold the global operation lock. Rename is
            # a single-link atomic publication: link+unlink has an unrecoverable
            # two-link window on power loss. Refuse an existing immutable target
            # again immediately before publication; unrelated root writers that
            # disregard the lock are outside the supported execution contract.
            if replace:
                os.replace(temporary, path)
            else:
                if path.exists() or path.is_symlink():
                    raise ValueError("Immutable lifecycle record already exists")
                os.rename(temporary, path)
            self._sync(path.parent)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)  # Only this call's unpublished temporary.
        return {"path": relative, "sha256": _hash(data)}

    def _put(self, relative, value, *, replace=False):
        return self._write(relative, _encode(value), replace=replace)

    def _write_once(self, relative, data, *, recover):
        if recover and self._present(relative):
            if self._read(relative) != data:
                raise ValueError("Recovery would change immutable bytes")
            return self.reference(relative)
        return self._write(relative, data)

    def _partial_tree(self, prefix, expected):
        """Validate ALL existing members before adding any missing immutable file."""
        if not self._present(prefix):
            return
        directories = {""}
        for filename in expected:
            _relative(filename)
            directories.update(str(parent) for parent in PurePosixPath(filename).parents if str(parent) != ".")
        def visit(relative):
            path = self._path(prefix + ("/" + relative if relative else ""))
            self._check(path.lstat(), directory=True)
            for child in path.iterdir():
                if child.name.startswith(".pending-"):
                    self._check(child.lstat())
                    continue  # Retain, never adopt, interrupted atomic-write temporaries.
                filename = (relative + "/" if relative else "") + child.name
                if stat.S_ISDIR(child.lstat().st_mode):
                    if filename not in directories:
                        raise ValueError("Unexpected recovery directory")
                    visit(filename)
                elif filename not in expected or self._read(prefix + "/" + filename) != expected[filename]:
                    raise ValueError("Unexpected/changed recovery file")
        visit("")

    def _snapshot(self, prefix, context, files, *, recover, source_prefix=None):
        """Retain a hash plan then exact bytes before touching an archive/generation.

        A partial snapshot can only be completed from bytes matching its already
        durable plan. Completed snapshots are the source after descriptor changes.
        """
        if files is not None:
            if type(files) is not dict or not 1 <= len(files) <= MAX_FILES:
                raise ValueError("Invalid recovery snapshot inputs")
            total = 0
            for filename, data in files.items():
                _relative(filename)
                if type(data) is not bytes or len(data) > MAX_FILE_BYTES:
                    raise ValueError("Invalid recovery snapshot bytes")
                total += len(data)
            if total > MAX_ARCHIVE_BYTES:
                raise ValueError("Recovery snapshot exceeds limits")
        # Publish the plan in the already-existing operation directory BEFORE
        # creating the snapshot directory; even a mkdir crash is then replayable.
        plan_path = prefix + "-plan.json"
        if self._present(plan_path):
            if not recover:
                raise ValueError("Snapshot already exists; explicit recovery required")
            plan_bytes = self._read(plan_path)
            plan = _json(plan_bytes)
            _fields(plan, "schema_version kind context files")
            _schema(plan)
            if plan["kind"] != "enrollment-byte-snapshot" or plan["context"] != context:
                raise ValueError("Recovery snapshot context differs")
            references = plan["files"]
            if type(references) is not dict or not 1 <= len(references) <= MAX_FILES:
                raise ValueError("Invalid recovery snapshot file set")
            if files is not None and set(files) != set(references):
                raise ValueError("Recovery snapshot inputs differ")
            retained = {}
            total = 0
            for filename, reference in references.items():
                _relative(filename)
                _reference(reference, prefix + "/files/" + filename)
                if self._present(reference["path"]):
                    data = self._bound(reference)
                elif files is not None:
                    data = files[filename]
                elif source_prefix is not None:
                    data = self._read(source_prefix + filename)
                else:
                    raise ValueError("Recovery snapshot bytes unavailable")
                if (type(data) is not bytes or _hash(data) != reference["sha256"]
                        or (files is not None and data != files[filename])):
                    raise ValueError("Recovery snapshot inputs changed")
                total += len(data)
                if total > MAX_ARCHIVE_BYTES:
                    raise ValueError("Recovery snapshot exceeds limits")
                retained[filename] = data
            files = retained
        else:
            if files is None or self._present(prefix):
                raise ValueError("Recovery snapshot plan is missing")
            references = {filename: dict(path=prefix + "/files/" + filename, sha256=_hash(data))
                          for filename, data in files.items()}
            plan = dict(schema_version=1, kind="enrollment-byte-snapshot", context=context, files=references)
            plan_bytes = _encode(plan)
            self._write(plan_path, plan_bytes)
        expected = {"files/" + key: data for key, data in files.items()}
        self._partial_tree(prefix, expected)
        for filename, data in files.items():
            path = prefix + "/files/" + filename
            self._mkdir(str(PurePosixPath(path).parent))
            self._write_once(path, data, recover=True)
        return files

    def exists(self):
        """True even for interrupted lifecycle publication; never legacy fallback."""
        return self._present("lifecycle") or self.pending() is not None

    def _active(self, *, allow_unpublished=False):
        if not self._present("lifecycle/active.json"):
            if self._present("lifecycle") and not allow_unpublished:
                raise ValueError("Lifecycle graph publication is incomplete")
            return None
        value = _json(self._read("lifecycle/active.json"))
        _fields(value, "schema_version graph")
        _schema(value)
        _reference(value["graph"])
        if not re.fullmatch(r"lifecycle/graphs/[a-z][a-z0-9-]{0,63}\.json", value["graph"]["path"]):
            raise ValueError("Invalid active graph path")
        return value["graph"]

    def pending(self):
        """Return the immutable pending intent, or None for a validated idle fence."""
        if not self._present("maintenance/pending.json"):
            return None
        value = _json(self._read("maintenance/pending.json"))
        _fields(value, "schema_version state record")
        _schema(value)
        record = _json(self._bound(value["record"]))
        if value["state"] == "pending":
            self._intent(record)
            _reference(value["record"], f"maintenance/operations/{record['operation']}/intent.json")
            return record
        if value["state"] != "idle":
            raise ValueError("Unknown mutation fence state")
        self._terminal(record)
        _reference(value["record"], f"maintenance/operations/{record['operation']}/terminal.json")
        intent = _json(self._bound(record["intent"]))
        self._intent(intent)
        if intent["operation"] != record["operation"]:
            raise ValueError("Terminal intent identity differs")
        if record["graph"] is not None:
            self._bound(record["graph"])
        return None

    @staticmethod
    def _intent(value):
        if type(value) is dict and value.get("action") == "maintenance":
            from .maintenance_state import validate_intent
            validate_intent(value)
            return
        _fields(value, "schema_version operation action instances executor_sha256 base_graph")
        _schema(value)
        _id(value["operation"])
        if value["action"] not in ("enroll", "register", "status", "evidence", "remove", "purge"):
            raise ValueError("Unsupported lifecycle intent")
        names = value["instances"]
        if type(names) is not list or not names or len(names) > MAX_FILES:
            raise ValueError("Invalid intent instance set")
        for name in names:
            _id(name, True)
        if sorted(set(names)) != names:
            raise ValueError("Intent instances must be unique and sorted")
        _digest(value["executor_sha256"])
        if value["base_graph"] is not None:
            Store._graph_reference(value["base_graph"])

    @staticmethod
    def _terminal(value):
        _fields(value, "schema_version operation outcome intent graph")
        _schema(value)
        _id(value["operation"])
        if value["outcome"] not in ("complete", "cancelled", "recovered"):
            raise ValueError("Invalid terminal outcome")
        _reference(value["intent"], f"maintenance/operations/{value['operation']}/intent.json")
        if value["graph"] is not None:
            Store._graph_reference(value["graph"])

    def begin(self, operation, action, instances, executor_sha256):
        """Persist the mutation fence before the caller changes any instance files."""
        value = self.prepare_intent(operation, action, instances, executor_sha256)
        self.activate_intent(value)
        return value

    def prepare_intent(self, operation, action, instances, executor_sha256):
        """Seal unpublished intent so exact recovery inputs can precede fencing."""
        if self.pending() is not None:
            raise ValueError("A lifecycle mutation is pending")
        base = self._active()
        if base is not None:
            self.graph()
        value = dict(schema_version=1, operation=operation, action=action,
                     instances=sorted(instances), executor_sha256=executor_sha256, base_graph=base)
        self._intent(value)
        directory = f"maintenance/operations/{operation}"
        self._mkdir(directory)
        reference = self._put(directory + "/intent.json", value)
        return value

    def activate_intent(self, value):
        """Publish only a prepared intent whose original graph is still active."""
        self._intent(value)
        if self.pending() is not None or self._active() != value["base_graph"]:
            raise ValueError("Prepared lifecycle intent is stale or another mutation is pending")
        relative = f"maintenance/operations/{value['operation']}/intent.json"
        if self._read(relative) != _encode(value):
            raise ValueError("Prepared lifecycle intent changed")
        self._put("maintenance/pending.json", dict(schema_version=1, state="pending", record=self.reference(relative)), replace=True)

    def _require_intent(self, operation, name=None):
        value = self.pending()
        if value is None or value["operation"] != operation or (name is not None and name not in value["instances"]):
            raise ValueError("Mutation does not own the pending intent")
        return value

    def finish(self, operation, outcome="complete"):
        """Retain terminal evidence, then atomically replace the fence with idle.

        This explicit API is also usable after a terminal-write crash, after the
        caller rechecks external consistency. It never infers success from a PID.
        """
        self._require_intent(operation)
        active = self._active()
        if active is not None:
            graph = self._graph(validate_evidence=True)
            if outcome == "complete" and graph["operation"] != operation:
                raise ValueError("Operation has not committed its graph")
        elif outcome == "complete":
            raise ValueError("Cannot complete without a graph")
        value = dict(schema_version=1, operation=operation, outcome=outcome,
                     intent=self.reference(f"maintenance/operations/{operation}/intent.json"), graph=active)
        self._terminal(value)
        path = f"maintenance/operations/{operation}/terminal.json"
        if self._present(path):
            if self._read(path) != _encode(value):
                raise ValueError("Terminal record differs from requested finalization")
            reference = self.reference(path)
        else:
            reference = self._put(path, value)
        self._put("maintenance/pending.json", dict(schema_version=1, state="idle", record=reference), replace=True)
        return value

    def legacy_entry(self, name):
        """Explicitly bind current legacy bytes; caller must first validate ownership."""
        _id(name, True)
        prefix = f"instances/{name}/"
        entry = dict(kind="legacy", config=self.reference(prefix + "config.json"),
                     status=self.reference(prefix + "status.json"),
                     source=self.reference(prefix + "source.sha256") if self._present(prefix + "source.sha256") else None)
        self._resolve_entry(name, entry)
        return entry

    def build_entry(self, name):
        """Bind legacy bytes explicitly, under this instance's pending intent.

        Configured instances alone may lack source.sha256. This does not convert
        a managed descriptor into legacy config or refresh a managed generation.
        """
        _id(name, True)
        intent = self.pending()
        if intent is None or name not in intent["instances"]:
            raise ValueError("Building an entry requires its pending intent")
        return self.legacy_entry(name)

    def archive_legacy(self, name, operation, *, recover=False):
        """Seal original bytes BEFORE replacing config.json with a descriptor.

        Missing locks are refused, not reconstructed. recover=True replays only
        this pending operation's durable byte snapshot, without replacing files.
        """
        _id(name, True)
        intent = self._require_intent(operation, name)
        if intent["action"] != "enroll":
            raise ValueError("Archiving requires enrollment intent")
        prefix = f"instances/{name}/"
        if self._present(prefix + "legacy") and not recover:
            raise ValueError("Legacy archive already exists; explicit recovery required")
        snapshot = f"maintenance/operations/{operation}/archive-{name}"
        credential = self.reference(prefix + "secrets.json")
        context = dict(instance=name, operation=operation, kind="legacy-archive", credentials=credential)
        originals = {}
        total = 0
        def visit(relative):
            nonlocal total
            path = self._path(prefix + relative) if relative else self._path(f"instances/{name}")
            self._check(path.lstat(), directory=True)
            for child in sorted(path.iterdir()):
                if child.name.startswith(".pending-"):
                    self._check(child.lstat())
                    continue  # Retain unpublished atomic temporaries, never adopt them.
                if not relative and child.name in ("secrets.json", "legacy", "generations"):
                    continue
                filename = (relative + "/" if relative else "") + child.name
                _relative(filename)
                if stat.S_ISDIR(child.lstat().st_mode):
                    visit(filename)
                else:
                    data = self._read(prefix + filename)
                    total += len(data)
                    if total > MAX_ARCHIVE_BYTES or len(originals) >= MAX_FILES:
                        raise ValueError("Legacy archive exceeds limits")
                    originals[filename] = data
        if recover and self._present(snapshot + "-plan.json"):
            originals = self._snapshot(snapshot, context, None, recover=True, source_prefix=prefix)
        else:
            if self._present(prefix + "legacy"):
                raise ValueError("Partial archive has no retained snapshot plan")
            visit("")
        required = {"config.json", "versions.json", "source.sha256", "status.json", "deployment.json"}
        if not required <= originals.keys():
            raise ValueError("Missing original enrollment locks/evidence")
        config = _config(originals["config.json"], name)
        if config.get("onlyoffice_plugins") and "plugins.json" not in originals:
            raise ValueError("Missing original plugin lock")
        if _status(_json(originals["status.json"]))["state"] != "ready":
            raise ValueError("Only ready legacy instances can be archived")
        self._source(originals["source.sha256"])
        for filename in ("versions.json", "deployment.json", "plugins.json"):
            if filename in originals:
                _json(originals[filename])
        # All original bytes are durable before the first archive destination write.
        originals = self._snapshot(snapshot, context, originals, recover=recover, source_prefix=prefix)
        destination = prefix + "legacy"
        references = {filename: dict(path=destination + "/files/" + filename, sha256=_hash(data))
                      for filename, data in originals.items()}
        value = dict(schema_version=1, kind="legacy-archive", instance=name,
                      operation=operation, files=references, credentials=credential)
        expected = {"manifest.json": _encode(value), **{"files/" + key: data for key, data in originals.items()}}
        self._partial_tree(destination, expected)
        for filename, data in originals.items():
            relative = references[filename]["path"]
            self._mkdir(str(PurePosixPath(relative).parent))
            self._write_once(relative, data, recover=recover)
        return self._write_once(destination + "/manifest.json", _encode(value), recover=recover)

    @staticmethod
    def _source(data):
        try:
            value = data.decode("ascii")
        except UnicodeError:
            raise ValueError("Invalid source artifact identity") from None
        return _digest(value[:-1] if value.endswith("\n") else value)

    def _archive(self, name, reference):
        prefix = f"instances/{name}/legacy/"
        value = _json(self._bound(reference, prefix + "manifest.json"))
        _fields(value, "schema_version kind instance operation files credentials")
        _schema(value)
        if value["kind"] != "legacy-archive" or value["instance"] != name:
            raise ValueError("Invalid legacy archive identity")
        _id(value["operation"])
        files = value["files"]
        if type(files) is not dict or not 1 <= len(files) <= MAX_FILES:
            raise ValueError("Invalid archive file set")
        if not {"config.json", "versions.json", "source.sha256", "status.json", "deployment.json"} <= files.keys():
            raise ValueError("Incomplete legacy archive")
        total = 0
        for filename, item in files.items():
            _relative(filename)
            if filename.split("/")[0] in ("secrets.json", "legacy", "generations"):
                raise ValueError("Forbidden archive member")
            total += len(self._bound(item, prefix + "files/" + filename))
            if total > MAX_ARCHIVE_BYTES:
                raise ValueError("Legacy archive exceeds limits")
        self._bound(value["credentials"], f"instances/{name}/secrets.json")
        config = _config(self._bound(files["config.json"]), name)
        if config.get("onlyoffice_plugins") and "plugins.json" not in files:
            raise ValueError("Missing archived plugin lock")
        if _status(_json(self._bound(files["status.json"])))["state"] != "ready":
            raise ValueError("Archived enrollment was not ready")
        return value

    def seal_generation(self, name, generation, operation, *, archive, evidence, recover=False):
        """Seal initial legacy enrollment; no successor/upgrade generations yet.

        evidence is {relative filename: exact bytes}, including policy.json and
        resources.json. Retain source policy/worker/inventory material here; no
        evidence is synthesized from the running checkout or host. recover=True
        requires identical retained inputs under the same pending operation.
        """
        _id(name, True)
        _id(generation)
        intent = self._require_intent(operation, name)
        if intent["action"] != "enroll":
            raise ValueError("Sealing requires enrollment intent")
        original = self._archive(name, archive)
        if original["operation"] != operation:
            raise ValueError("Archive belongs to a different operation")
        if type(evidence) is not dict or not {"policy.json", "resources.json"} <= evidence.keys() or len(evidence) > MAX_FILES:
            raise ValueError("Missing source policy/resource evidence")
        total = 0
        for filename, data in evidence.items():
            _relative(filename)
            if type(data) is not bytes or len(data) > MAX_FILE_BYTES:
                raise ValueError("Invalid evidence bytes")
            total += len(data)
        if total > MAX_ARCHIVE_BYTES:
            raise ValueError("Evidence exceeds limits")
        _json(evidence["policy.json"])
        _json(evidence["resources.json"])
        prefix = f"instances/{name}/generations/{generation}"
        if self._present(prefix) and not recover:
            raise ValueError("Generation already exists; explicit recovery required")
        references = {filename: dict(path=prefix + "/evidence/" + filename, sha256=_hash(data))
                      for filename, data in evidence.items()}
        files = original["files"]
        copies = {}
        payload = {"evidence/" + key: data for key, data in evidence.items()}
        for filename in ("config.json", "versions.json", "plugins.json"):
            if filename in files:
                payload[filename] = self._bound(files[filename])
                copies[filename] = dict(path=prefix + "/" + filename, sha256=_hash(payload[filename]))
            else:
                copies[filename] = None
        manifest = dict(schema_version=1, kind="instance-generation", entity_kind="instance", entity_id=name,
                        generation_id=generation, predecessor=None, operation=operation, origin="legacy-enrollment",
                        recipe=None, config=copies["config.json"], versions=copies["versions.json"], plugins=copies["plugins.json"],
                        archive=archive, evidence=references, credentials=original["credentials"],
                        provenance=dict(source_sha256=self._source(self._bound(files["source.sha256"])),
                                        policy_sha256=references["policy.json"]["sha256"], policy=references["policy.json"]),
                        resources=references["resources.json"])
        snapshot = f"maintenance/operations/{operation}/generation-{name}-{generation}"
        if recover and self._present(prefix) and not self._present(snapshot + "-plan.json"):
            raise ValueError("Partial generation has no retained snapshot plan")
        context = dict(instance=name, operation=operation, kind="instance-generation", generation=generation, archive=archive)
        self._snapshot(snapshot, context, payload, recover=recover)
        self._partial_tree(prefix, {**payload, "manifest.json": _encode(manifest)})
        for filename, data in payload.items():
            relative = prefix + "/" + filename
            self._mkdir(str(PurePosixPath(relative).parent))
            self._write_once(relative, data, recover=recover)
        return self._write_once(prefix + "/manifest.json", _encode(manifest), recover=recover)

    def _generation(self, name, reference):
        value = _json(self._bound(reference))
        if value.get("kind") == "maintenance-generation":
            from .maintenance_generations import validate_generation
            return validate_generation(self, name, reference, value)
        _fields(value, "schema_version kind entity_kind entity_id generation_id predecessor operation origin recipe config versions plugins archive evidence credentials provenance resources")
        _schema(value)
        generation = _id(value["generation_id"])
        prefix = f"instances/{name}/generations/{generation}/"
        _reference(reference, prefix + "manifest.json")
        if (value["kind"] != "instance-generation" or value["entity_kind"] != "instance" or value["entity_id"] != name
                or value["predecessor"] is not None or value["recipe"] is not None or value["origin"] != "legacy-enrollment"):
            raise ValueError("Unsupported generation identity/origin")
        _id(value["operation"])
        archive = self._archive(name, value["archive"])
        if archive["operation"] != value["operation"] or value["credentials"] != archive["credentials"]:
            raise ValueError("Generation archive/credential binding differs")
        for key in ("config", "versions", "plugins"):
            filename = key + ".json"
            original = archive["files"].get(filename)
            if original is None and key == "plugins":
                if value[key] is not None:
                    raise ValueError("Generation invented a plugin lock")
                continue
            data = self._bound(value[key], prefix + filename)
            _json(data)
            if value[key]["sha256"] != original["sha256"]:
                raise ValueError("Initial generation changed original inputs")
        evidence = value["evidence"]
        if type(evidence) is not dict or not {"policy.json", "resources.json"} <= evidence.keys() or len(evidence) > MAX_FILES:
            raise ValueError("Incomplete generation evidence")
        total = 0
        for filename, item in evidence.items():
            _relative(filename)
            total += len(self._bound(item, prefix + "evidence/" + filename))
            if total > MAX_ARCHIVE_BYTES:
                raise ValueError("Generation evidence exceeds limits")
        _fields(value["provenance"], "source_sha256 policy_sha256 policy")
        if (value["provenance"]["source_sha256"] != self._source(self._bound(archive["files"]["source.sha256"]))
                or value["provenance"]["policy_sha256"] != evidence["policy.json"]["sha256"]
                or value["provenance"]["policy"] != evidence["policy.json"] or value["resources"] != evidence["resources.json"]):
            raise ValueError("Generation provenance/evidence differs")
        _json(self._bound(value["provenance"]["policy"]))
        _json(self._bound(value["resources"]))
        return value

    def _resolve_entry(self, name, entry):
        _id(name, True)
        self._entry_shape(name, entry)
        kind = entry.get("kind")
        prefix = f"instances/{name}/"
        if kind == "removed":
            _fields(entry, "kind retained status")
            if type(entry["retained"]) is not dict or entry["retained"].get("kind") not in ("legacy", "managed"):
                raise ValueError("Invalid retained tombstone")
            previous = self._resolve_entry(name, entry["retained"])
            if _status(entry["status"])["state"] != "removed":
                raise ValueError("Tombstone must be removed")
            return Resolved(**{**previous.__dict__, "kind": kind, "status": entry["status"]})
        if kind == "legacy":
            _fields(entry, "kind config status source")
            data = self._bound(entry["config"], prefix + "config.json")
            status = _status(_json(self._bound(entry["status"], prefix + "status.json")))
            source = self._source(self._bound(entry["source"], prefix + "source.sha256")) if entry["source"] is not None else None
            if source is None and (status["state"] not in ("configured", "removing", "removed") or not self.unprovisioned(name)):
                raise ValueError("Legacy deployment has no source binding")
            if source is None and self._present(prefix + "source.sha256"):
                raise ValueError("Legacy source appeared outside its graph binding")
            manifest, versions, plugins = None, None, None
            provenance = dict(source_sha256=source, policy_sha256=None, policy=None)
            config_path = entry["config"]["path"]
        elif kind == "managed":
            _fields(entry, "kind generation status")
            registration = _json(self._read(prefix + "config.json"))
            _schema(registration)
            if registration != descriptor(name, entry["generation"]):
                raise ValueError("Managed registration descriptor differs from graph")
            manifest = self._generation(name, entry["generation"])
            data = self._bound(manifest["config"])
            status = _status(entry["status"])
            provenance = manifest["provenance"]
            config_path = manifest["config"]["path"]
            versions = self.root / manifest["versions"]["path"]
            plugins = self.root / manifest["plugins"]["path"] if manifest["plugins"] else None
        else:
            raise ValueError("Unknown lifecycle graph entry kind")
        return Resolved(name, kind, data, _config(data, name), status, provenance,
                        self.root / prefix, self.root / config_path, versions, plugins, manifest)

    def unprovisioned(self, name):
        """A missing source is valid only before any provisioning evidence exists."""
        _id(name, True)
        prefix = f"instances/{name}/"
        return not any(self._present(prefix + filename) for filename in
                       ("deployment.json", "inputs.sha256", "inventory.json", "complete",
                        name + "nc.creating.json", name + "oo.creating.json"))

    def _entries(self, entries):
        if type(entries) is not dict or len(entries) > MAX_FILES:
            raise ValueError("Invalid graph instance map")
        directory = self._path("instances")
        self._check(directory.lstat(), directory=True)
        names = set()
        for path in directory.iterdir():
            if path.name.startswith(".pending-"):
                continue
            _id(path.name, True)
            self._check(path.lstat(), directory=True)
            names.add(path.name)
        if set(entries) != names:
            raise ValueError("Graph instance set differs from registered directories")
        intent = self.pending()
        if intent is not None and intent["action"] == "maintenance":
            from .maintenance_generations import validate_pending_entries
            validate_pending_entries(self, intent, entries)
        return {name: self._resolve_entry(name, entry) for name, entry in entries.items()}

    @staticmethod
    def _graph_reference(reference):
        _reference(reference)
        if not re.fullmatch(r"lifecycle/graphs/[a-z][a-z0-9-]{0,63}\.json", reference["path"]):
            raise ValueError("Invalid graph reference path")

    @staticmethod
    def _entry_shape(name, entry):
        _id(name, True)
        if type(entry) is not dict:
            raise ValueError("Invalid graph entry")
        prefix = f"instances/{name}/"
        kind = entry.get("kind")
        if kind == "legacy":
            _fields(entry, "kind config status source")
            _reference(entry["config"], prefix + "config.json")
            _reference(entry["status"], prefix + "status.json")
            if entry["source"] is not None:
                _reference(entry["source"], prefix + "source.sha256")
        elif kind == "managed":
            _fields(entry, "kind generation status")
            _reference(entry["generation"])
            if not re.fullmatch(re.escape(prefix) + r"generations/[a-z][a-z0-9-]{0,63}/manifest\.json", entry["generation"]["path"]):
                raise ValueError("Invalid managed generation path")
            _status(entry["status"])
        elif kind == "removed":
            _fields(entry, "kind retained status")
            if type(entry["retained"]) is not dict or entry["retained"].get("kind") not in ("legacy", "managed"):
                raise ValueError("Invalid retained tombstone")
            Store._entry_shape(name, entry["retained"])
            if _status(entry["status"])["state"] != "removed":
                raise ValueError("Tombstone must be removed")
        else:
            raise ValueError("Unknown lifecycle graph entry kind")

    def graph(self, *, validate_evidence=True):
        """Return a full graph; strict reads refuse pending operations.

        The fenced structural view is for explicit reconciliation/graph assembly,
        never effective configuration lookup. It cannot authorize a new mutation.
        """
        pending = self.pending()
        if validate_evidence:
            if pending is not None:
                raise ValueError("Lifecycle mutation pending; explicit recovery required")
        elif pending is None:
            raise ValueError("Structural graph access requires a pending intent")
        return self._graph(validate_evidence=validate_evidence)

    def _graph(self, *, validate_evidence):
        reference = self._active()
        if reference is None:
            raise ValueError("No committed lifecycle graph")
        value = _json(self._bound(reference))
        _fields(value, "schema_version kind graph_id operation predecessor instances")
        _schema(value)
        _id(value["graph_id"])
        _id(value["operation"])
        _reference(reference, f"lifecycle/graphs/{value['graph_id']}.json")
        if value["kind"] != "instance-graph":
            raise ValueError("Unsupported lifecycle graph kind")
        if value["predecessor"] is not None:
            self._graph_reference(value["predecessor"])
            self._bound(value["predecessor"])
        if type(value["instances"]) is not dict or len(value["instances"]) > MAX_FILES:
            raise ValueError("Invalid graph instance map")
        for name, entry in value["instances"].items():
            self._entry_shape(name, entry)
        if validate_evidence:
            self._entries(value["instances"])
        return value

    def resolve(self, name, graph=None):
        """Resolve against a pinned full graph, refusing a changed active pointer.

        A supplied snapshot must equal the hash-verified current graph. It avoids
        revalidating every other entity; the selected entry's evidence is always
        checked. Call graph() once before passing it to repeated registry reads.
        """
        _id(name, True)
        if self.pending() is not None:
            raise ValueError("Lifecycle mutation pending; explicit recovery required")
        active = self._active()
        if graph is None:
            graph = self.graph()
        else:
            current = self._graph(validate_evidence=False)
            if type(graph) is not dict or _encode(graph) != _encode(current):
                raise ValueError("Supplied graph is not the current committed snapshot")
        entries = graph["instances"]
        if name not in entries:
            raise ValueError("Unknown lifecycle instance")
        resolved = self._resolve_entry(name, entries[name])
        result = dict(resolved.__dict__)
        result["config"] = (self.config_loader(resolved.config_bytes, resolved.provenance)
                            if self.config_loader else resolved.config_document)
        result["evidence_path"] = (self.root / f"instances/{name}/legacy/files"
                                   if resolved.manifest else resolved.instance_path)
        if self.pending() is not None or self._active() != active:
            raise ValueError("Lifecycle graph changed during lookup")
        return result

    def commit(self, graph_id, entries, operation):
        """Seal one complete graph then atomically publish its hash-bound pointer."""
        _id(graph_id)
        intent = self._require_intent(operation)
        if intent["action"] == "maintenance":
            raise ValueError("Maintenance graph publication requires its operation-bound chain")
        active = self._active(allow_unpublished=intent["base_graph"] is None)
        if active != intent["base_graph"]:
            raise ValueError("Intent base graph changed; explicit recovery required")
        self._entries(entries)
        previous = {}
        if active is not None:
            previous = _json(self._bound(active))["instances"]
            for name in set(previous) | set(entries):
                if previous.get(name) != entries.get(name) and name not in intent["instances"]:
                    raise ValueError("Graph changes an instance outside this intent")
        for name, entry in entries.items():
            retained = entry["retained"] if entry["kind"] == "removed" else entry
            before = previous.get(name, {})
            before = before["retained"] if before.get("kind") == "removed" else before
            if (retained["kind"] == "managed" and retained["generation"] != before.get("generation")
                    and self._generation(name, retained["generation"])["kind"] == "maintenance-generation"):
                raise ValueError("Successor publication requires its native maintenance graph chain")
        value = dict(schema_version=1, kind="instance-graph", graph_id=graph_id,
                     operation=operation, predecessor=active, instances=entries)
        self._mkdir("lifecycle/graphs")
        path = f"lifecycle/graphs/{graph_id}.json"
        if self._present(path):
            if self._read(path) != _encode(value):
                raise ValueError("Immutable graph differs from requested commit")
            reference = self.reference(path)
        else:
            reference = self._put(path, value)
        self._put("lifecycle/active.json", dict(schema_version=1, graph=reference), replace=True)
        return reference
