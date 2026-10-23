"""Source-bound maintenance metadata, not native execution authority.

NativeState requires an already-held Registry lock on every call. It records a
new execution-* intent; the maint-* preparation and its recipe=None stay inert.
Only this operation's original graph and explicit closed graph successors are
readable while fenced. No general reader, boot permission or recipe is enabled.
Store's terminal.json remains the lifecycle terminal (not a native journal).
"""

from copy import deepcopy
import re

from .generations import (Store, MAX_FILES, MAX_FILE_BYTES, _config, _digest, _encode, _fields,
                          _hash, _id, _json, _reference, _schema, _status)


def validate_intent(value):
    """Strict separate intent schema; called by Store's action dispatcher."""
    _fields(value, "schema_version kind operation action instances executor_sha256 base_graph inputs")
    if (type(value["schema_version"]) is not int or value["schema_version"] != 2
            or value["kind"] != "native-maintenance-intent" or value["action"] != "maintenance"):
        raise ValueError("Unsupported native maintenance intent")
    _id(value["operation"])
    if not value["operation"].startswith("execution-"):
        raise ValueError("Native maintenance requires a new execution identifier")
    if type(value["instances"]) is not list or len(value["instances"]) != 1:
        raise ValueError("Native maintenance requires exactly one instance")
    _id(value["instances"][0], True)
    _digest(value["executor_sha256"])
    Store._graph_reference(value["base_graph"])
    _reference(value["inputs"], f"maintenance/operations/{value['operation']}/native-inputs.json")
    return value


def _graph(store, reference):
    Store._graph_reference(reference)
    value = _json(store._bound(reference))
    _fields(value, "schema_version kind graph_id operation predecessor instances")
    _schema(value)
    _id(value["graph_id"])
    _id(value["operation"])
    _reference(reference, f"lifecycle/graphs/{value['graph_id']}.json")
    if value["kind"] != "instance-graph" or type(value["instances"]) is not dict or len(value["instances"]) > MAX_FILES:
        raise ValueError("Invalid bound maintenance graph")
    if value["predecessor"] is not None:
        Store._graph_reference(value["predecessor"])
        store._bound(value["predecessor"])
    for name, entry in value["instances"].items():
        store._entry_shape(name, entry)
    return value


class NativeState:
    """Metadata adapter; executor is the exact current executor_record().

    Callers check recipe admission, cache authenticity and native safety evidence
    separately. A recipe descriptor here binds inputs, never grants permission.
    begin is deliberately not an implicit retry of an unpublished preparation.
    commit_closed retries only identical bytes with an exact predecessor.
    """

    def __init__(self, registry, executor):
        self.registry = registry
        self.store = Store(registry.root)
        self.executor = deepcopy(executor)

    def _lock(self):
        self.registry._require_lock()

    def _initial_records(self, records, instance):
        """Validate/freeze trusted native receipts before any execution writes.

        None preserves metadata-only callers. Concrete acceptance sessions supply
        both observations and, for SourceAdmission, the captured candidate ref.
        These fixed private records confer no additional execution authority.
        """
        if records is None:
            return {}
        required = {"admission.json", "source-observations.json"}
        if type(records) is not dict or set(records) not in (required, required | {"candidate-reference.json"}):
            raise ValueError("Invalid native initial receipt inventory")
        admission = records["admission.json"]
        _fields(admission, "startup evidence")
        startup = admission["startup"]
        if (type(startup) is not dict or set(startup) != {instance + "nc", instance + "oo"}
                or any(type(value) is not dict for value in startup.values())
                or type(records["source-observations.json"]) is not dict):
            raise ValueError("Invalid native initial observation shape")
        for inventory in startup.values():
            for name, digest in inventory.items():
                if type(name) is not str or not name:
                    raise ValueError("Invalid native startup observation")
                _digest(digest)
        self.store._bound(admission["evidence"])
        if "candidate-reference.json" in records:
            self.store._bound(records["candidate-reference.json"])
        try:
            encoded = {name: _encode(value) for name, value in records.items()}
        except (TypeError, ValueError, RecursionError):
            raise ValueError("Invalid native initial receipt encoding") from None
        if any(len(data) > MAX_FILE_BYTES for data in encoded.values()):
            raise ValueError("Native initial receipt exceeds byte limit")
        return encoded

    def begin(self, operation, instance, *, preparation, recipe, initial_records=None):
        self._lock()
        store = self.store
        _id(operation)
        _id(instance, True)
        if not operation.startswith("execution-") or store.pending() is not None:
            raise ValueError("Native maintenance requires a new idle execution intent")
        if type(recipe) is not dict or not recipe:
            raise ValueError("Missing recipe descriptor")
        receipts = self._initial_records(initial_records, instance)
        # Use the preparation's existing strict parser without changing its schema.
        from .maintenance_operations import load_operation, _network_binding
        _reference(preparation)
        match = re.fullmatch(r"maintenance/operations/(maint-[a-z0-9-]+)/operation\.json", preparation["path"])
        if match is None:
            raise ValueError("Native execution requires an inert preparation owner")
        store._bound(preparation)
        parent, plan, _ = load_operation(self.registry, match[1])
        graph = store.graph()
        base = store._active()
        entry = graph["instances"].get(instance)
        if (parent["instance"] != instance or parent["executor"] != self.executor
                or entry is None or entry["kind"] != "managed" or entry["status"]["state"] != "ready"
                or plan["bindings"]["graph"] != base or plan["bindings"]["generation"] != entry["generation"]
                or plan["bindings"]["network"] != _network_binding(store)):
            raise ValueError("Preparation differs from exact source/executor/instance/network")
        manifest = store._generation(instance, entry["generation"])
        if (manifest["versions"] != plan["bindings"]["versions"]
                or manifest["provenance"]["source_sha256"] != self.executor["source_sha256"]):
            raise ValueError("Preparation differs from original generation source/versions")
        directory = f"maintenance/operations/{operation}"
        if store._present(directory):
            raise ValueError("Execution identifier already exists")
        originals = {}
        # Read and validate everything before retaining any execution records.
        for name in graph["instances"]:
            resolved = store.resolve(name, graph=graph)
            files = {}
            for filename in ("config.json", "versions.json", "plugins.json", "source.sha256"):
                key = filename[:-5] + "_path"
                path = (resolved["config_path"] if filename == "config.json" else
                        resolved.get(key) if filename in ("versions.json", "plugins.json") else None)
                path = path or resolved["evidence_path"] / filename
                relative = str(path.relative_to(store.root))
                files[filename] = (store.reference(relative), store._read(relative)) if store._present(relative) else None
            originals[name] = (files, resolved["status"], resolved["provenance"])
        store._mkdir(directory)
        retained = {}
        for name, (files, status, provenance) in originals.items():
            prefix = directory + "/originals/" + name
            store._mkdir(prefix)
            retained[name] = dict(files={key: None if item is None else {
                "original": item[0], "retained": store._write(prefix + "/" + key, item[1])}
                for key, item in files.items()}, status=status,
                status_file=store._write(prefix + "/status.json", _encode(status)), provenance=provenance)
        inputs = dict(schema_version=1, kind="native-maintenance-inputs", operation=operation,
                      instance=instance, executor=self.executor, preparation=preparation,
                      cache_owner=parent["operation"], recipe=recipe, recipe_sha256=_hash(_encode(recipe)),
                      entries=graph["instances"], originals=retained, network=plan["bindings"]["network"],
                      host=store._write(directory + "/host.json", store._read("host.json"))
                      if store._present("host.json") else None)
        reference = store._put(directory + "/native-inputs.json", inputs)
        intent = dict(schema_version=2, kind="native-maintenance-intent", operation=operation,
                      action="maintenance", instances=[instance], executor_sha256=self.executor["executor_sha256"],
                      base_graph=base, inputs=reference)
        validate_intent(intent)
        self._inputs(intent)
        # Every original observation must survive a crash immediately after the
        # pending fence activates. Store writes fsync each file and its directory.
        for name, data in receipts.items():
            store._write_once(directory + "/" + name, data, recover=False)
        store._put(directory + "/intent.json", intent)
        store.activate_intent(intent)
        return deepcopy(intent)

    def _inputs(self, intent):
        store = self.store
        validate_intent(intent)
        value = _json(store._bound(intent["inputs"]))
        _fields(value, "schema_version kind operation instance executor preparation cache_owner recipe recipe_sha256 entries originals network host")
        _schema(value)
        if (value["kind"] != "native-maintenance-inputs" or value["operation"] != intent["operation"]
                or [value["instance"]] != intent["instances"] or value["executor"] != self.executor
                or intent["executor_sha256"] != self.executor["executor_sha256"]
                or type(value["recipe"]) is not dict or not value["recipe"]
                or _hash(_encode(value["recipe"])) != value["recipe_sha256"]):
            raise ValueError("Native maintenance inputs/executor/recipe differ")
        from .maintenance_operations import load_operation
        _id(value["cache_owner"])
        if not value["cache_owner"].startswith("maint-"):
            raise ValueError("Native cache owner is not a preparation")
        store._bound(value["preparation"], f"maintenance/operations/{value['cache_owner']}/operation.json")
        parent, plan, _ = load_operation(self.registry, value["cache_owner"])
        original = _graph(store, intent["base_graph"])
        target = original["instances"].get(value["instance"], {})
        if (parent["executor"] != self.executor or parent["instance"] != value["instance"]
                or plan["bindings"]["graph"] != intent["base_graph"]
                or target.get("kind") != "managed" or target["status"]["state"] != "ready"
                or plan["bindings"]["generation"] != target["generation"]
                or value["entries"] != original["instances"] or value["network"] != plan["bindings"]["network"]
                or type(value["originals"]) is not dict or set(value["originals"]) != set(value["entries"])):
            raise ValueError("Native original graph/preparation binding differs")
        directory = f"maintenance/operations/{intent['operation']}"
        for name, item in value["originals"].items():
            _fields(item, "files status status_file provenance")
            _fields(item["files"], "config.json versions.json plugins.json source.sha256")
            entry = value["entries"][name]
            retained = entry["retained"] if entry["kind"] == "removed" else entry
            manifest = store._generation(name, retained["generation"]) if retained["kind"] == "managed" else None
            for filename, pair in item["files"].items():
                expected = manifest.get(filename[:-5]) if manifest else None
                if manifest and filename == "source.sha256":
                    expected = store._archive(name, manifest["archive"])["files"][filename]
                if not manifest and filename in ("config.json", "source.sha256"):
                    expected = retained["config" if filename == "config.json" else "source"]
                if pair is None:
                    if expected is not None or filename == "config.json":
                        raise ValueError("Missing original maintenance input")
                    continue
                _fields(pair, "original retained")
                if manifest and expected is None:
                    raise ValueError("Invented original generation input")
                _reference(pair["original"])
                data = store._bound(pair["retained"], directory + "/originals/" + name + "/" + filename)
                if (pair["original"]["sha256"] != pair["retained"]["sha256"]
                        or expected is not None and pair["original"] != expected
                        or not manifest and pair["original"]["path"] != f"instances/{name}/{filename}"):
                    raise ValueError("Original maintenance file reference differs")
                if filename == "config.json":
                    _config(data, name)
            status = (entry["status"] if entry["kind"] in ("managed", "removed") else
                      _json(store._bound(entry["status"])))
            if _status(item["status"]) != status:
                raise ValueError("Original maintenance status differs")
            if store._bound(item["status_file"], directory + "/originals/" + name + "/status.json") != _encode(status):
                raise ValueError("Retained maintenance status differs")
            source = item["files"]["source.sha256"]
            provenance = manifest["provenance"] if manifest else dict(
                source_sha256=store._source(store._bound(source["retained"])) if source else None,
                policy_sha256=None, policy=None)
            if item["provenance"] != provenance:
                raise ValueError("Original maintenance provenance differs")
        manifest = store._generation(value["instance"], target["generation"])
        if (manifest["versions"] != plan["bindings"]["versions"]
                or manifest["provenance"]["source_sha256"] != self.executor["source_sha256"]):
            raise ValueError("Original generation source/versions differ")
        for reference in value["network"]["records"].values():
            store._bound(reference)
        if value["host"] is not None:
            _json(store._bound(value["host"], directory + "/host.json"))
        return value

    def _chain(self, intent, inputs):
        """Validate recorded successors without following an arbitrary active graph."""
        store = self.store
        previous = intent["base_graph"]
        authorized = [previous]
        for stage in ("validated-closed", "restored-closed"):
            path = f"maintenance/operations/{intent['operation']}/{stage}.json"
            if not store._present(path):
                continue
            step = _json(store._read(path))
            _fields(step, "schema_version kind operation intent stage predecessor graph")
            _schema(step)
            if (step["kind"] != "native-graph-step" or step["operation"] != intent["operation"]
                    or step["intent"] != store.reference(f"maintenance/operations/{intent['operation']}/intent.json")
                    or step["stage"] != stage or step["predecessor"] != previous):
                raise ValueError("Maintenance graph chain predecessor/identity differs")
            graph = _graph(store, step["graph"])
            if graph["operation"] != intent["operation"] or graph["predecessor"] != previous or step["graph"] in authorized:
                raise ValueError("Maintenance graph is not its recorded successor")
            self._entries(inputs, graph["instances"], restored=stage == "restored-closed")
            previous = step["graph"]
            authorized.append(previous)
        if store._active() not in authorized:
            raise ValueError("Active graph is outside the operation-bound chain")
        return authorized

    @staticmethod
    def _entries(inputs, entries, *, restored):
        original = inputs["entries"]
        if type(entries) is not dict or set(entries) != set(original):
            raise ValueError("Maintenance graph must retain all original instances")
        for name in original:
            Store._entry_shape(name, entries[name])
            if (name != inputs["instance"] or restored) and _encode(entries[name]) != _encode(original[name]):
                raise ValueError("Maintenance changed an unaffected/original recovery entry")
        if entries[inputs["instance"]]["kind"] != "managed":
            raise ValueError("Maintenance target must remain managed")

    def read(self, operation):
        self._lock()
        intent = self.store._require_intent(operation)
        inputs = self._inputs(intent)
        self._chain(intent, inputs)
        # Unaffected entries still resolve against their exact original bindings.
        for name, entry in inputs["entries"].items():
            if name != inputs["instance"]:
                self.store._resolve_entry(name, entry)
                for pair in inputs["originals"][name]["files"].values():
                    if pair is not None:
                        self.store._bound(pair["original"])
        names = set()
        directory = self.store._path("instances")
        self.store._check(directory.lstat(), directory=True)
        for path in directory.iterdir():
            if not path.name.startswith(".pending-"):
                _id(path.name, True)
                self.store._check(path.lstat(), directory=True)
                names.add(path.name)
        if names != set(inputs["entries"]):
            raise ValueError("Native original instance directory coverage differs")
        return intent, inputs

    def view(self, operation):
        self.read(operation)
        return NativeView(self, operation)

    def commit_closed(self, operation, stage, graph_id, entries, *, expected_predecessor):
        """Seal a closed graph; caller supplies native validation/closure separately."""
        intent, inputs = self.read(operation)
        if stage not in ("validated-closed", "restored-closed"):
            raise ValueError("Unsupported maintenance graph stage")
        _id(graph_id)
        self._entries(inputs, entries, restored=stage == "restored-closed")
        store = self.store
        directory = f"maintenance/operations/{operation}"
        preceding = intent["base_graph"]
        if stage == "validated-closed" and store._present(directory + "/restored-closed.json"):
            raise ValueError("Cannot publish validation after restoration")
        if stage == "restored-closed" and store._present(directory + "/validated-closed.json"):
            preceding = _json(store._read(directory + "/validated-closed.json"))["graph"]
        if expected_predecessor != preceding:
            raise ValueError("Maintenance commit requires the exact expected predecessor")
        graph = dict(schema_version=1, kind="instance-graph", graph_id=graph_id, operation=operation,
                     predecessor=preceding, instances=entries)
        reference = dict(path=f"lifecycle/graphs/{graph_id}.json", sha256=_hash(_encode(graph)))
        if reference == preceding or store._active() not in (preceding, reference):
            raise ValueError("Maintenance commit cannot rebase a changed active graph")
        store._entries(entries)
        # Graph first: an interrupted orphan is inert and exact retry is safe.
        store._write_once(reference["path"], _encode(graph), recover=True)
        step = dict(schema_version=1, kind="native-graph-step", operation=operation,
                    intent=store.reference(directory + "/intent.json"), stage=stage,
                    predecessor=preceding, graph=reference)
        store._write_once(directory + "/" + stage + ".json", _encode(step), recover=True)
        self._chain(intent, inputs)
        store._put("lifecycle/active.json", dict(schema_version=1, graph=reference), replace=True)
        return reference

    def finish(self, operation, outcome="complete"):
        """Explicit lifecycle finalization, after caller verifies external cleanup."""
        intent, inputs = self.read(operation)
        chain = self._chain(intent, inputs)
        if outcome == "cancelled":
            expected = intent["base_graph"]
        elif outcome in ("complete", "recovered"):
            stage = "validated-closed" if outcome == "complete" else "restored-closed"
            step = _json(self.store._read(f"maintenance/operations/{operation}/{stage}.json"))
            expected = step["graph"]
            if expected != chain[-1]:
                raise ValueError("Maintenance terminal does not match final chain stage")
        else:
            raise ValueError("Unsupported maintenance terminal outcome")
        if self.store._active() != expected:
            raise ValueError("Maintenance terminal graph differs")
        return self.store.finish(operation, outcome)


class NativeView:
    """Read-only original Registry interface, valid only under its pending lock.

    Each lookup rechecks the immutable operation and authorized graph chain. No
    current-pointer resolution or mutable object is cached as recovery authority.
    """

    def __init__(self, state, operation):
        self._state, self._operation = state, operation
        self.root = state.store.root

    def _inputs(self):
        return self._state.read(self._operation)[1]

    def instance_path(self, name):
        if name not in self._inputs()["originals"]:
            raise ValueError("Instance outside native original view")
        return self.root / "instances" / name

    def evidence_path(self, name, filename):
        originals = self._inputs()["originals"]
        if name not in originals:
            raise ValueError("Evidence outside native original view")
        if filename == "status.json":
            return self.root / originals[name]["status_file"]["path"]
        if filename not in originals[name]["files"]:
            raise ValueError("Evidence outside native original view")
        pair = originals[name]["files"][filename]
        if pair is None:
            raise ValueError("Original evidence was not recorded")
        return self.root / pair["retained"]["path"]

    def load(self, name):
        inputs = self._inputs()
        if name not in inputs["originals"]:
            raise ValueError("Instance outside native original view")
        item = inputs["originals"][name]
        data = self._state.store._bound(item["files"]["config.json"]["retained"])
        # Reuse the Registry's explicit policy-bound loader, not its graph reader.
        return self._state.registry._store().config_loader(data, deepcopy(item["provenance"]))

    def status(self, name):
        originals = self._inputs()["originals"]
        if name not in originals:
            raise ValueError("Instance outside native original view")
        return deepcopy(originals[name]["status"])

    def version_policy(self, name):
        """Effective policy from the bound original graph, including successors."""
        self.load(name)  # Validate the exact retained configuration/provenance.
        provenance = self._inputs()["originals"][name]["provenance"]
        if "derivation" in provenance:
            from .maintenance_generations import provenance_policy
            return provenance_policy(self._state.store, provenance)
        from .versions import load_policy
        return load_policy()

    def deployment_config_digest(self, name):
        """Keep the original installation binding while target descriptors change."""
        config = self.load(name)
        entry = self._inputs()["entries"][name]
        retained = entry["retained"] if entry["kind"] == "removed" else entry
        store = self._state.store
        manifest = store._generation(name, retained["generation"]) if retained["kind"] == "managed" else None
        return self._state.registry._deployment_digest(store, {"manifest": manifest, "config": config})

    def entries(self, *, include_removed=False):
        return [(self.load(name), self.status(name)) for name in sorted(self._inputs()["originals"])
                if include_removed or self.status(name)["state"] != "removed"]

    def network_configs(self, *, exclude=None):
        inputs = self._inputs()
        transaction = _json(self._state.store._bound(inputs["network"]["records"]["firewall-transition.json"]))
        names = transaction.get("instances")
        if type(names) not in (list, dict) or any(type(name) is not str for name in names) or not set(names) <= inputs["originals"].keys():
            raise ValueError("Original network contains unrecorded instances")
        return [self.load(name) for name in names if name != exclude]

    def host(self):
        reference = self._inputs()["host"]
        return _json(self._state.store._bound(reference)) if reference else None
