"""Private host registry, atomic journals and serialized instance operations."""

from contextlib import contextmanager
from datetime import datetime, timezone
import base64
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import uuid

from .config import Config, STATE_DIR, SCHEMA_VERSION


def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def atomic_write(path, text, mode=0o600):
    """Never truncate the last good journal/config; fsync file and directory."""
    path = Path(path)
    if path.is_symlink():
        raise ValueError("Refusing to replace a symlink with managed state")
    fd, temporary = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)  # Only our uncommitted temporary file.


def atomic_json(path, value):
    atomic_write(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def private_directory(path):
    path = Path(path)
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError(f"Unsafe private directory: {path}")
    else:
        path.mkdir(mode=0o700)
    return path


def private_json(path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError(f"Expected an owner-only regular state file: {path}")
    return json.loads(path.read_text())


def config_digest(config):
    return hashlib.sha256(config.to_json().encode()).hexdigest()


class Registry:
    def __init__(self, root=STATE_DIR):
        self.root = Path(root)
        self._locked = False
        self._recovery = False

    def _store(self):
        from .generations import Store
        def load(data, provenance):
            if "derivation" in provenance:
                from .maintenance_generations import provenance_policy
                provenance_policy(store, provenance)
            elif provenance.get("policy") is not None:
                from .paths import RESOURCES
                retained = store._bound(provenance["policy"])
                if retained != (RESOURCES / "versions.json").read_bytes():
                    raise ValueError("Retained generation policy requires its original reader; no policy reinterpretation is supported")
            return Config.from_json(data.decode())
        store = Store(self.root, config_loader=load)
        return store

    def lifecycle_enabled(self):
        path = self.root / "lifecycle"
        fence = self.root / "maintenance/pending.json"
        return path.exists() or path.is_symlink() or fence.exists() or fence.is_symlink()

    def status(self, instance):
        if self.lifecycle_enabled():
            return self._store().resolve(instance)["status"]
        from .dashboard import _read
        return _read(self.instance_path(instance) / "status.json")

    def evidence_path(self, instance, filename):
        if filename not in ("config.json", "versions.json", "plugins.json", "source.sha256", "status.json"):
            raise ValueError("Unsupported intended-state record")
        if self.lifecycle_enabled():
            store = self._store()
            resolved = store.resolve(instance)
            if filename == "status.json":
                return resolved["instance_path"] / filename
            if filename == "config.json":
                return resolved["config_path"]
            if filename in ("versions.json", "plugins.json") and resolved[filename[:-5] + "_path"]:
                return resolved[filename[:-5] + "_path"]
            return resolved["evidence_path"] / filename
        return self.instance_path(instance) / filename

    def lifecycle_names(self):
        return sorted(self._store().graph()["instances"])

    def initialize(self):
        private_directory(self.root)
        for name in ("instances", "transactions", "network", "backups", "removed"):
            private_directory(self.root / name)

    @contextmanager
    def locked(self, *, recovery=False, create=True):
        if type(create) is not bool:
            raise ValueError("Invalid operation-lock initialization policy")
        if create:
            self.initialize()
        else:
            info = self.root.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077
                    or self.root.resolve(strict=True) != self.root):
                raise ValueError("Existing private registry is required")
        flags = os.O_RDWR | os.O_NOFOLLOW | (os.O_CREAT if create else os.O_NONBLOCK)
        descriptor = os.open(self.root / "operation.lock", flags, 0o600)
        with os.fdopen(descriptor, "w") as lock:
            info = os.fstat(lock.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077 or info.st_nlink != 1):
                raise ValueError("Unsafe global operation lock")
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError("Another installer/backup/restore operation is active on this host") from None
            previous = self._locked, self._recovery
            self._locked, self._recovery = True, recovery
            try:
                if self.lifecycle_enabled() and not recovery:
                    if self._store().pending() is not None:
                        raise ValueError("Lifecycle mutation pending; explicit recovery required")
                    from .maintenance import entry_guard
                    entry_guard("mutation", registry=self)
                yield
            finally:
                self._locked, self._recovery = previous

    def instance_path(self, instance):
        if not re.fullmatch(r"[a-z][a-z0-9]{0,7}", instance):
            raise ValueError("Invalid instance identifier")
        return self.root / "instances" / instance

    def load(self, instance):
        if self.lifecycle_enabled():
            store = self._store()
            resolved = store.resolve(instance)
            config = resolved["config"]
            journal = self.instance_path(instance) / "deployment.json"
            expected = self._deployment_digest(store, resolved)
            if journal.exists() and private_json(journal).get("config_sha256") != expected:
                raise ValueError("A registered deployment's immutable configuration/schema changed")
            return config
        path = self.instance_path(instance)
        if not path.is_dir() or path.is_symlink():
            raise ValueError(f"Unknown instance: {instance}")
        config = Config.from_json(json.dumps(private_json(path / "config.json")))
        if config.instance != instance:
            raise ValueError("Instance identity does not match its registry directory")
        journal = path / "deployment.json"
        if journal.exists() and private_json(journal).get("config_sha256") != config_digest(config):
            raise ValueError("A registered deployment's immutable configuration/schema changed")
        return config

    @staticmethod
    def _deployment_digest(store, resolved):
        manifest = resolved["manifest"]
        if manifest is not None and manifest["kind"] == "maintenance-generation":
            initial = Config.from_json(store._bound(manifest["originals"]["config"]).decode())
            return config_digest(initial)
        return config_digest(resolved["config"])

    def deployment_config_digest(self, instance):
        """Original installation-journal binding, distinct from effective config."""
        if not self.lifecycle_enabled():
            return config_digest(self.load(instance))
        store = self._store()
        return self._deployment_digest(store, store.resolve(instance))

    def version_policy(self, instance):
        """Read the exact validated effective policy; never select a new version."""
        from .versions import load_policy
        if not self.lifecycle_enabled():
            self.load(instance)
            return load_policy()
        store = self._store()
        resolved = store.resolve(instance)
        if "derivation" in resolved["provenance"]:
            from .maintenance_generations import provenance_policy
            return provenance_policy(store, resolved["provenance"])
        return load_policy()

    def entries(self, *, include_removed=False):
        if self.lifecycle_enabled():
            store = self._store()
            graph = store.graph()
            entries = [store.resolve(name, graph=graph) for name in sorted(graph["instances"])]
            if store.graph() != graph:
                raise ValueError("Lifecycle graph changed during registry inspection")
            return [(entry["config"], entry["status"]) for entry in entries
                    if include_removed or entry["status"]["state"] != "removed"]
        directory = self.root / "instances"
        if not directory.exists():
            return []
        entries = []
        for path in sorted(directory.iterdir()):
            if path.name.startswith(".pending-"):
                continue  # Interrupted unpublished registration, never an active instance.
            config = self.load(path.name)
            status = private_json(path / "status.json")
            if include_removed or status["state"] != "removed":
                entries.append((config, status))
        return entries

    def configs(self, *, exclude=None):
        return [config for config, status in self.entries()
                if config.instance != exclude and status["state"] not in ("configured", "removed")]

    def network_configs(self, *, exclude=None):
        active = self.root / "network/active"
        if not active.exists():
            return []
        transaction = private_json(active / "firewall-transition.json")
        return [self.load(name) for name in transaction["instances"] if name != exclude]

    def save_new(self, config, secrets):
        config.validate()
        config.require_jail_backend("Instance registration")
        if self.lifecycle_enabled():
            config.require_native_backend("Lifecycle-enabled instance registration")
            return self._register(config, secrets)
        path = self.instance_path(config.instance)
        if path.exists():
            raise ValueError("Instance name is already registered; use Resume, not a second installation")
        pending = Path(tempfile.mkdtemp(prefix=".pending-", dir=path.parent))
        atomic_json(pending / "config.json", json.loads(config.to_json()))
        atomic_json(pending / "secrets.json", secrets)
        atomic_json(pending / "status.json", {"state": "configured", "updated": timestamp()})
        os.rename(pending, path)
        descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return path

    def set_status(self, instance, status, **details):
        if status not in ("configured", "installing", "failed", "ready", "removing", "removed"):
            raise ValueError("Unknown registry state")
        value = {"state": status, "updated": timestamp(), **details}
        if self.lifecycle_enabled():
            return self._metadata(instance, "status.json", self._encode(value))
        atomic_json(self.instance_path(instance) / "status.json", value)

    def write_source(self, instance, text):
        """Publish source identity through the graph when lifecycle is enabled."""
        if self.lifecycle_enabled():
            return self._metadata(instance, "source.sha256", text.encode())
        atomic_write(self.instance_path(instance) / "source.sha256", text)

    @staticmethod
    def _encode(value):
        return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()

    def _require_lock(self, *, recovery=False):
        if not self._locked or (recovery and not self._recovery):
            raise ValueError("Lifecycle mutation requires the global operation lock and explicit recovery authorization")

    @staticmethod
    def _executor():
        from .maintenance import executor_identity
        return executor_identity()

    @staticmethod
    def _source_identity():
        from .deploy import source_digest
        return source_digest().strip()

    @staticmethod
    def _reference(name, filename, data):
        return {"path": f"instances/{name}/{filename}", "sha256": hashlib.sha256(data).hexdigest()}

    def _start(self, store, name, action):
        self._require_lock()
        operation = "registry-" + uuid.uuid4().hex
        return store.prepare_intent(operation, action, [name], self._executor())

    def _payload(self, store, intent, entries, files, *, staged=None, credentials=None):
        value = dict(schema_version=1, kind="registry-mutation", operation=intent["operation"],
                     instance=intent["instances"][0], base_graph=intent["base_graph"],
                     entries=entries, files=files, staged=staged, credentials=credentials)
        directory = f"maintenance/operations/{intent['operation']}"
        reference = store._put(directory + "/registry.json", value)
        store._put(directory + "/registry-inputs.json", {
            "schema_version": 1, "payload": reference, "intent": store.reference(directory + "/intent.json")})
        return value

    def _register(self, config, secrets):
        self._require_lock()
        store = self._store()
        graph = store.graph()
        name = config.instance
        path = self.instance_path(name)
        if name in graph["instances"] or path.exists() or path.is_symlink():
            raise ValueError("Instance name is already registered; use Resume, not a second installation")
        intent = self._start(store, name, "register")
        staged = f"maintenance/operations/{intent['operation']}/registration"
        # Secrets remain in this owner-only staging directory, which is renamed
        # into place. Neither graph nor operation payload contains their values.
        pending = store._mkdir(staged)
        data = {"config.json": self._encode(json.loads(config.to_json())),
                "status.json": self._encode({"state": "configured", "updated": timestamp()})}
        for filename, contents in data.items():
            atomic_write(pending / filename, contents.decode())
        atomic_json(pending / "secrets.json", secrets)
        credentials = hashlib.sha256((pending / "secrets.json").read_bytes()).hexdigest()
        entries = copy.deepcopy(graph["instances"])
        entries[name] = {"kind": "legacy", "config": self._reference(name, "config.json", data["config.json"]),
                         "status": self._reference(name, "status.json", data["status.json"]), "source": None}
        files = {filename: {"before": None, "after": base64.b64encode(contents).decode()}
                 for filename, contents in data.items()}
        payload = self._payload(store, intent, entries, files, staged=staged, credentials=credentials)
        store.activate_intent(intent)
        self._apply_registry(store, intent, payload)
        return path

    def _metadata(self, name, filename, contents):
        self._require_lock()
        store = self._store()
        graph = store.graph()
        if name not in graph["instances"]:
            raise ValueError("Unknown lifecycle instance")
        resolved = store.resolve(name, graph=graph)
        entry = copy.deepcopy(graph["instances"][name])
        if filename == "source.sha256":
            source = store._source(contents)
            if source != self._source_identity():
                raise ValueError("Source publication requires the original installer artifact")
            previous = resolved["provenance"]["source_sha256"]
            if previous is not None:
                if previous != source:
                    raise ValueError("Source identity cannot change; retain the original installer artifact")
                return
            if entry["kind"] != "legacy":
                raise ValueError("Only a configured legacy registration may acquire a source identity")
            entry["source"] = self._reference(name, filename, contents)
        else:
            status = json.loads(contents)
            from .generations import _status
            _status(status)
            if (resolved["provenance"]["source_sha256"] is None
                    and (status["state"] not in ("configured", "removing", "removed") or not store.unprovisioned(name))):
                raise ValueError("A deployed registry status requires the original source binding")
            if entry["kind"] == "removed" and status["state"] != "removed":
                raise ValueError("Removed instance names remain reserved")
            retained = entry["retained"] if entry["kind"] == "removed" else entry
            if retained["kind"] == "legacy":
                retained["status"] = self._reference(name, filename, contents)
            elif entry["kind"] != "removed":
                retained["status"] = status
            if status["state"] == "removed":
                entry = {"kind": "removed", "retained": retained, "status": status}
        path = f"instances/{name}/{filename}"
        before = store._read(path) if store._present(path) else None
        if filename == "source.sha256" and before is not None:
            raise ValueError("Unbound source file cannot be adopted into the lifecycle graph")
        entries = copy.deepcopy(graph["instances"])
        entries[name] = entry
        intent = self._start(store, name, "status")
        files = {filename: {"before": base64.b64encode(before).decode() if before is not None else None,
                            "after": base64.b64encode(contents).decode()}}
        payload = self._payload(store, intent, entries, files)
        store.activate_intent(intent)
        self._apply_registry(store, intent, payload)

    def _apply_registry(self, store, intent, payload):
        """Replay only exact retained metadata inputs, never infer/adopt a state."""
        self._require_lock()
        name, operation = payload["instance"], intent["operation"]
        current = store.graph(validate_evidence=False)
        base = json.loads(store._bound(intent["base_graph"]))
        expected = dict(schema_version=1, kind="instance-graph", graph_id=operation,
                        operation=operation, predecessor=intent["base_graph"], instances=payload["entries"])
        if current != base and current != expected:
            raise ValueError("Registry recovery graph differs from retained before/after inputs")
        for other in set(base["instances"]) | set(payload["entries"]):
            if other != name and base["instances"].get(other) != payload["entries"].get(other):
                raise ValueError("Registry recovery changes unrelated instances")
        files = {}
        for filename, pair in payload["files"].items():
            if filename not in ("config.json", "status.json", "source.sha256") or set(pair) != {"before", "after"}:
                raise ValueError("Invalid registry recovery file set")
            files[filename] = (base64.b64decode(pair["before"], validate=True) if pair["before"] is not None else None,
                               base64.b64decode(pair["after"], validate=True))
        # The payload cannot authorize arbitrary graph edits: derive its sole
        # allowed change again from the committed base and exact file bytes.
        if intent["action"] == "register":
            if set(files) != {"config.json", "status.json"}:
                raise ValueError("Invalid retained registration inputs")
            planned = {"kind": "legacy", "config": self._reference(name, "config.json", files["config.json"][1]),
                       "status": self._reference(name, "status.json", files["status.json"][1]), "source": None}
            if json.loads(files["status.json"][1])["state"] != "configured":
                raise ValueError("Registration must remain configured")
        else:
            if name not in base["instances"] or len(files) != 1 or "config.json" in files:
                raise ValueError("Invalid retained metadata mutation")
            planned = copy.deepcopy(base["instances"][name])
            retained = planned["retained"] if planned["kind"] == "removed" else planned
            filename, (before, after) = next(iter(files.items()))
            key = "source" if filename == "source.sha256" else "status"
            if retained["kind"] == "legacy":
                expected_before = self._reference(name, filename, before) if before is not None else None
                if retained[key] != expected_before:
                    raise ValueError("Registry before bytes are not bound by the committed graph")
                retained[key] = self._reference(name, filename, after)
            if key == "source":
                if planned["kind"] != "legacy" or before is not None or store._source(after) != self._source_identity():
                    raise ValueError("Source publication is not bound to its original executor")
            else:
                status = json.loads(after)
                if planned["kind"] == "removed" and status["state"] != "removed":
                    raise ValueError("Cannot revive a removed registration")
                if retained["kind"] == "managed" and planned["kind"] != "removed":
                    retained["status"] = status
                if status["state"] == "removed":
                    planned = {"kind": "removed", "retained": retained, "status": status}
        if payload["entries"].get(name) != planned:
            raise ValueError("Registry after graph differs from the exact permitted metadata change")
        path = self.instance_path(name)
        # A fenced replay still refuses unrelated drift before touching metadata.
        names = set()
        for directory in (self.root / "instances").iterdir():
            if directory.name.startswith(".pending-"):
                continue
            self.instance_path(directory.name)
            store._check(directory.lstat(), directory=True)
            names.add(directory.name)
        expected_names = set(base["instances"])
        if intent["action"] == "register" and (path.exists() or path.is_symlink()):
            expected_names.add(name)
        if names != expected_names:
            raise ValueError("Registry recovery found unbound instance directories")
        for other, entry in base["instances"].items():
            retained = entry["retained"] if entry["kind"] == "removed" else entry
            if other != name or retained["kind"] == "managed":
                store._resolve_entry(other, entry)
            else:
                store._bound(retained["config"])
                if retained["source"] is not None:
                    store._bound(retained["source"])
        if payload["staged"] is not None:
            if (intent["action"] != "register" or name in base["instances"]
                    or payload["staged"] != f"maintenance/operations/{operation}/registration"
                    or set(files) != {"config.json", "status.json"}
                    or any(before is not None for before, after in files.values())):
                raise ValueError("Invalid retained registration inputs")
            staged = self.root / payload["staged"]
            if (staged.exists() or staged.is_symlink()) and (path.exists() or path.is_symlink()):
                raise ValueError("Ambiguous staged registration")
            directory = path if path.exists() or path.is_symlink() else staged
            if directory.exists() or directory.is_symlink():
                private_directory(directory)
            if not directory.is_dir() or set(p.name for p in directory.iterdir()) != {"config.json", "status.json", "secrets.json"}:
                raise ValueError("Partial or unknown registration files require explicit assessment")
            for filename, (_, after) in files.items():
                if store._read(str((directory / filename).relative_to(self.root))) != after:
                    raise ValueError("Staged registration differs from exact retained inputs")
            secret = store._read(str((directory / "secrets.json").relative_to(self.root)))
            if hashlib.sha256(secret).hexdigest() != payload["credentials"]:
                raise ValueError("Registration credential binding changed")
            if directory == staged:
                os.rename(staged, path)
                store._sync(path.parent)
                store._sync(staged.parent)
        else:
            if intent["action"] != "status" or name not in base["instances"] or len(files) != 1 or "config.json" in files:
                raise ValueError("Invalid retained metadata mutation")
            # Check every input before publishing any replacement.
            for filename, (before, after) in files.items():
                relative = f"instances/{name}/{filename}"
                actual = store._read(relative) if store._present(relative) else None
                if actual not in (before, after):
                    raise ValueError("Registry metadata differs from exact retained before/after inputs")
            for filename, (_, after) in files.items():
                atomic_write(path / filename, after.decode())
        # Validate all evidence before making the complete graph authoritative.
        store._entries(payload["entries"])
        if current == base:
            store.commit(operation, payload["entries"], operation)
        store.finish(operation)

    def recover_registry(self, pending):
        """Explicit same-executor recovery for a fenced registry-only mutation."""
        self._require_lock(recovery=True)
        store = self._store()
        if not isinstance(pending, dict) or store.pending() != pending or pending["executor_sha256"] != self._executor():
            raise ValueError("Registry recovery requires the original executor and exact pending intent")
        relative = f"maintenance/operations/{pending['operation']}/registry.json"
        binding = json.loads(store._read(f"maintenance/operations/{pending['operation']}/registry-inputs.json"))
        if (set(binding) != {"schema_version", "payload", "intent"} or binding["schema_version"] != 1
                or binding["intent"] != store.reference(f"maintenance/operations/{pending['operation']}/intent.json")):
            raise ValueError("Registry recovery inputs are not bound to the pending intent")
        payload = json.loads(store._bound(binding["payload"], relative))
        if (set(payload) != {"schema_version", "kind", "operation", "instance", "base_graph", "entries", "files", "staged", "credentials"}
                or payload["schema_version"] != 1 or payload["kind"] != "registry-mutation"
                or payload["operation"] != pending["operation"] or [payload["instance"]] != pending["instances"]
                or payload["base_graph"] != pending["base_graph"]):
            raise ValueError("Invalid retained registry recovery inputs")
        self._apply_registry(store, pending, payload)

    def host(self):
        path = self.root / "host.json"
        return private_json(path) if path.exists() else None

    def save_host(self, config):
        if self.lifecycle_enabled():
            self._require_lock()
            self._store().graph()
        keys = ("pool", "external_interface", "management_network", "management_port", "host_reserved_mb")
        value = {key: getattr(config, key) for key in keys}
        value.update(schema_version=SCHEMA_VERSION, bastille_root=config.bastille_root)
        current = self.host()
        if current and 'vm_manager' in current:
            # Optional native VM tooling is shared. Preserve its owned marker;
            # ordinary native/none installs do not probe or reinitialize it.
            value['vm_manager'] = current['vm_manager']
        if current and current != value:
            raise ValueError("This instance conflicts with the managed host's shared pool/network/resource settings")
        atomic_json(self.root / "host.json", value)


def recover_registry(registry, pending):
    """Maintenance's explicit recovery hook; caller owns the recovery lock."""
    return registry.recover_registry(pending)


class Journal:
    def __init__(self, path, config, progress=None):
        self.path = Path(path)
        self.progress = progress or (lambda current, total, label: print(f"[{current}/{total}] {label}", flush=True))
        self.data = private_json(self.path) if self.path.exists() else {
            "schema_version": SCHEMA_VERSION, "config_sha256": config_digest(config), "steps": {}, "created": timestamp()}
        if self.data.get("schema_version") != SCHEMA_VERSION or self.data.get("config_sha256") != config_digest(config):
            raise ValueError("Resume refused: saved configuration/schema changed; do not replay phases against different resources")

    def save(self):
        atomic_json(self.path, self.data)

    def run(self, steps, *, checks=None):
        """Actions must be explicitly idempotent; never infer success from absence of an error log."""
        for index, (name, action) in enumerate(steps, 1):
            previous = self.data["steps"].get(name, {})
            if previous.get("state") == "complete":
                if checks and name in checks:
                    checks[name]()
                self.progress(index, len(steps), name + " — completed checkpoint; skipped")
                continue
            self.progress(index, len(steps), name)
            record = {"state": "running", "attempt": previous.get("attempt", 0) + 1, "started": timestamp()}
            self.data["steps"][name] = record
            self.save()
            try:
                action()
            except BaseException as error:
                record.update(state="failed", failed=timestamp(), error_type=type(error).__name__)
                self.save()
                raise
            record.update(state="complete", completed=timestamp())
            self.save()
