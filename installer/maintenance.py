"""Explicit lifecycle enrollment. No migration recipe or upgrade executor."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import uuid

from .paths import PROJECT_ROOT
from .state import Registry


def executor_identity():
    """Do not redefine the historical module/resource source digest."""
    from .deploy import source_digest
    return hashlib.sha256(source_digest().encode() + (PROJECT_ROOT / "install.sh").read_bytes()).hexdigest()


def entry_guard(command, *, registry=None):
    """Current-entrypoint fence, including the shell's pre-bootstrap dispatch."""
    registry = registry or Registry()
    if not registry.lifecycle_enabled():
        return
    if command in ("menu", "list", "status", "check-updates", "check-security", "maintenance", "resolve"):
        return  # Inspection/recovery dispatch validates its own bounded records.
    from .dashboard import _read, _directory
    from .generations import Store
    store = Store(registry.root)
    if store.pending() is not None:
        raise ValueError("Lifecycle mutation pending; explicit recovery required")
    root = registry.root / "lifecycle"
    _directory(root)
    executor = _read(root / "executor.json")
    if executor != executor_record():
        raise ValueError("Lifecycle mutation requires its retained original executor and payload path")
    store.graph()


def require_instance_adapter(registry, instance):
    """No historical worker or shell is executed as an implicit adapter."""
    if not registry.lifecycle_enabled():
        return
    from .deploy import source_digest
    registry.load(instance)
    path = registry.evidence_path(instance, "source.sha256")
    if not path.exists() and registry.status(instance)["state"] in ("configured", "removing", "removed"):
        return
    from .generations import Store
    store = Store(registry.root)
    relative = str(path.relative_to(store.root))
    if store._read(relative) != source_digest().encode():
        raise ValueError("No reviewed lifecycle adapter for this historical instance source")


def executor_record():
    from .deploy import source_digest
    from .versions import load_policy, policy_hash
    return {"schema_version": 1, "source_sha256": source_digest().strip(),
            "executor_sha256": executor_identity(), "payload_path": str(PROJECT_ROOT),
            "policy_sha256": policy_hash(load_policy())}


def boot_check(root, instance, jail, executor):
    """Read-only boot permission; the caller must still run the storage/PF guard."""
    registry = Registry(Path(root))
    if executor != executor_identity():
        raise ValueError("Lifecycle boot executor changed")
    if registry.lifecycle_enabled():
        from .generations import Store
        intent = Store(registry.root).pending()
        if intent is not None:
            if intent["action"] == "enroll":
                from .enrollment_start import boot_permission
            elif intent["action"] == "maintenance":
                from .maintenance_fence import boot_permission
            else:
                raise ValueError("Lifecycle mutation pending; jail boot refused")
            boot_permission(registry, intent, instance, jail, executor)
            return  # The unchanged storage/PF guard still runs after this check.
    entry_guard("boot", registry=registry)
    config = registry.load(instance)
    if jail not in (config.nextcloud_jail, config.onlyoffice_jail):
        raise ValueError("Unregistered jail boot refused")
    if registry.status(instance)["state"] in ("configured", "removing", "removed"):
        raise ValueError("Instance state forbids jail start")


def status(registry):
    """Bounded inspection, including an interrupted first graph publication."""
    from .dashboard import _directory
    result = {"schema_version": 1, "lifecycle": "legacy", "pending": None,
              "graph": None, "error": None, "execution_authorized": False,
              "preparation_operations": []}
    if not registry.lifecycle_enabled():
        return result
    result["lifecycle"] = "initialized"
    try:
        from .generations import Store
        _directory(registry.root / "lifecycle", optional=True)
        _directory(registry.root / "maintenance")
        store = Store(registry.root)
        from .maintenance_operations import list_operations
        result["preparation_operations"] = list_operations(registry)
        intent = store.pending()
        if intent is not None:
            result["pending"] = {key: intent[key] for key in ("operation", "action", "instances")}
        graph = store.graph()
        result["graph"] = {"instances": sorted(graph["instances"])}
    except (ValueError, OSError, TypeError, KeyError):
        result["error"] = "Lifecycle state is incomplete, pending or unsafe; use the retained artifact and explicit recovery."
    return result


class _EnrollmentView:
    """Read-only, exact pre-intent graph view for this enrollment's probes.

    It cannot initialize, write, acquire a mutation lock, or invoke a historical
    entrypoint. All documents are copied from hash-bound operation inputs.
    """
    def __init__(self, registry, store, plan):
        from .config import Config
        from .generations import _encode, _hash, _status
        from .versions import load_policy
        self.root = registry.root
        self._configs = {}
        self._statuses = {}
        self._paths = {}
        self._policies = {}
        self._deployment_digests = {}
        for name, item in plan["originals"].items():
            raw = store._bound(item["config"])
            status = _status(json.loads(store._bound(item["status"])))
            entry = plan["entries"].get(name)
            manifest = None
            paths = {key + ".json": store.root / item[key]["path"] for key in ("config", "status")}
            if entry is not None:
                store._entry_shape(name, entry)
                retained = entry["retained"] if entry["kind"] == "removed" else entry
                if retained["kind"] == "managed":
                    # Resolve ONLY the generation sealed into the original plan.
                    # The live registration/graph may already have changed during
                    # this enrollment; general pending readers remain fenced.
                    manifest = store._generation(name, retained["generation"])
                    if (raw != store._bound(manifest["config"])
                            or _encode(status) != _encode(entry["status"])):
                        raise ValueError("Enrollment originals differ from their managed entry")
                    archive = store._archive(name, manifest["archive"])
                    paths.update({filename: store.root / ref["path"]
                                  for filename, ref in archive["files"].items()
                                  if filename not in ("config.json", "status.json")})
                    paths.update({key + ".json": store.root / manifest[key]["path"]
                                  for key in ("versions", "plugins") if manifest[key] is not None})
                elif (retained["config"]["sha256"] != _hash(raw)
                      or (entry["kind"] == "removed" and _encode(status) != _encode(entry["status"]))
                      or (entry["kind"] != "removed" and retained["status"]["sha256"] != item["status"]["sha256"])):
                    raise ValueError("Enrollment originals differ from their legacy entry")
            policy = load_policy()
            if manifest is not None:
                provenance = manifest["provenance"]
                config = registry._store().config_loader(raw, deepcopy(provenance))
                if "derivation" in provenance:
                    from .maintenance_generations import provenance_policy
                    policy = provenance_policy(store, provenance)
            else:
                config = Config.from_json(raw.decode())
            if config.instance != name:
                raise ValueError("Enrollment original instance identity differs")
            self._configs[name] = config
            self._statuses[name] = status
            self._paths[name] = paths
            self._policies[name] = policy
            self._deployment_digests[name] = registry._deployment_digest(store, {"manifest": manifest, "config": config})

    def instance_path(self, name):
        if name not in self._configs:
            raise ValueError("Instance outside enrollment evidence")
        return self.root / "instances" / name

    def load(self, name):
        self.instance_path(name)
        return deepcopy(self._configs[name])

    def status(self, name):
        self.instance_path(name)
        return deepcopy(self._statuses[name])

    def version_policy(self, name):
        self.instance_path(name)
        return deepcopy(self._policies[name])

    def deployment_config_digest(self, name):
        self.instance_path(name)
        return self._deployment_digests[name]

    def evidence_path(self, name, filename):
        path = self.instance_path(name)
        return self._paths[name].get(filename, path / filename)

    def entries(self, *, include_removed=False):
        return [(self.load(name), self.status(name)) for name in sorted(self._configs)
                if include_removed or self._statuses[name]["state"] != "removed"]

    def network_configs(self, *, exclude=None):
        from .state import private_json
        transaction = private_json(self.root / "network/active/firewall-transition.json")
        return [self.load(name) for name in transaction["instances"] if name != exclude]

    def host(self):
        from .state import private_json
        return private_json(self.root / "host.json")


def _deployment(registry, name, runner):
    from .deploy import Deployment
    from .main import load_secrets
    return Deployment(registry.load(name), load_secrets(registry.instance_path(name) / "secrets.json"),
                      runner, registry=registry)


def register(registry, name, runner, *, confirmation):
    """Explicit same-artifact enrollment, serialized with existing operations."""
    if confirmation != "ENROLL " + name:
        raise ValueError("Enrollment requires exact ENROLL NAME confirmation")
    registry.instance_path(name)  # Strict identity validation before any writes.
    from . import enrollment
    from .generations import Store, _encode
    with registry.locked():
        store = Store(registry.root)
        if store.pending() is not None:
            raise ValueError("Pending lifecycle mutation requires explicit recovery")
        graph = store.graph() if registry.lifecycle_enabled() else None
        if graph and graph["instances"].get(name, {}).get("kind") != "legacy":
            raise ValueError("Only a ready legacy entry can be enrolled")
        d = _deployment(registry, name, runner)
        evidence = enrollment.check(d)
        if evidence.get("eligible") is not True:
            raise ValueError("Enrollment requires an original first-readiness baseline; no retrofit is allowed")
        # Every extant pair must already recognize the durable pending fence.
        # Configured entries have no jail resources; incomplete operations must
        # first use their existing resume/removal workflow.
        entries = registry.entries(include_removed=True)
        for config, state in entries:
            if state["state"] in ("configured", "removed"):
                continue
            if state["state"] != "ready":
                raise ValueError("Complete or remove interrupted installations before host enrollment")
            other = d if config.instance == name else _deployment(registry, config.instance, runner)
            if graph and graph["instances"][config.instance]["kind"] == "managed":
                enrollment.validate_guard(other, dispatcher=PROJECT_ROOT / "installer/maintenance.py")
            else:
                enrollment.validate_original_guard(other)
        operation = "enroll-" + uuid.uuid4().hex
        directory = "maintenance/operations/" + operation
        store._mkdir(directory)
        originals = {}
        for config, state in entries:
            # Sealed private inputs precede the pending fence. Orphaned staged
            # inputs have no authority and are never automatically adopted.
            source = registry.evidence_path(config.instance, "config.json")
            raw = store._read(str(source.relative_to(store.root)))
            originals[config.instance] = {
                "config": store._write(directory + "/" + config.instance + "-config.json", raw),
                "status": store._write(directory + "/" + config.instance + "-status.json", _encode(state))}
        plan = {"schema_version": 1, "instance": name, "operation": operation,
                "executor": executor_record(), "generation": "initial-" + uuid.uuid4().hex,
                "graph": "graph-" + uuid.uuid4().hex, "originals": originals,
                "entries": graph["instances"] if graph else {c.instance: store.legacy_entry(c.instance) for c, _ in entries},
                "assessment": evidence,
                "evidence": {
                    "policy.json": store._write(directory + "/policy.json", (PROJECT_ROOT / "resources/versions.json").read_bytes()),
                    "resources.json": store._write(directory + "/resources.json", _encode(evidence))}}
        reference = store._put(directory + "/enrollment.json", plan)
        store._put(directory + "/enrollment-inputs.json", {"schema_version": 1, "plan": reference})
        intent = store.begin(operation, "enroll", [name], executor_identity())
        _continue_enrollment(registry, runner, intent)


def _continue_enrollment(registry, runner, intent):
    from . import enrollment
    from .generations import Store, _json, _encode, descriptor
    store = Store(registry.root)
    operation = intent["operation"]
    directory = "maintenance/operations/" + operation
    anchor = _json(store._read(directory + "/enrollment-inputs.json"))
    if set(anchor) != {"schema_version", "plan"} or anchor["schema_version"] != 1:
        raise ValueError("Unsupported enrollment input binding")
    plan = _json(store._bound(anchor["plan"], directory + "/enrollment.json"))
    if (set(plan) != {"schema_version", "instance", "operation", "executor", "generation", "graph",
                     "originals", "entries", "assessment", "evidence"}
            or plan["schema_version"] != 1 or plan["operation"] != operation
            or intent["action"] != "enroll" or intent["instances"] != [plan["instance"]]
            or intent["executor_sha256"] != executor_identity() or plan["executor"] != executor_record()
            or plan["assessment"].get("eligible") is not True):
        raise ValueError("Enrollment recovery requires its exact original inputs and executor")
    name = plan["instance"]
    from .enrollment_start import _binding
    _binding(registry, intent, supplied_plan=plan)
    view = _EnrollmentView(registry, store, plan)
    d = _deployment(view, name, runner)
    # Config may already be the exact descriptor after an interrupted commit;
    # all other evidence must remain byte-identical to the pre-intent assessment.
    for filename, expected in plan["assessment"]["artifacts"].items():
        path = view.evidence_path(name, filename)
        if hashlib.sha256(store._read(str(path.relative_to(store.root)))).hexdigest() != expected:
            raise ValueError("Enrollment original evidence changed; recovery refused")
    store._mkdir("lifecycle")
    executor_path = "lifecycle/executor.json"
    if store._present(executor_path):
        if _json(store._read(executor_path)) != plan["executor"]:
            raise ValueError("Conflicting lifecycle executor")
    else:
        store._put(executor_path, plan["executor"])
    enrollment.install_guard(d, dispatcher=PROJECT_ROOT / "installer/maintenance.py", intent=intent)
    archive = store.archive_legacy(name, operation, recover=True)
    generation = store.seal_generation(name, plan["generation"], operation, archive=archive,
                                       evidence={key: store._bound(ref) for key, ref in plan["evidence"].items()},
                                       recover=True)
    registration = descriptor(name, generation)
    current_config = _json(store._read(f"instances/{name}/config.json"))
    if current_config != registration:
        if store._read(f"instances/{name}/config.json") != store._bound(plan["originals"][name]["config"]):
            raise ValueError("Legacy lookup changed outside enrollment")
        store._write(f"instances/{name}/config.json", _encode(registration), replace=True)
    entries = {**plan["entries"], name: {"kind": "managed", "generation": generation,
                                      "status": view.status(name)}}
    active = store._active(allow_unpublished=True)
    if active != intent["base_graph"]:
        committed = store.graph(validate_evidence=False)
        if committed["operation"] != operation or committed["instances"] != entries or committed["graph_id"] != plan["graph"]:
            raise ValueError("Enrollment graph changed outside its intent")
    else:
        store.commit(plan["graph"], entries, operation)
    enrollment.validate_guard(d, dispatcher=PROJECT_ROOT / "installer/maintenance.py")
    from .enrollment_start import validation_starts
    with validation_starts(registry, d, intent, plan):
        enrollment.recheck(d, intent=intent)
        store.finish(operation)


def recover(registry, runner, *, confirmation):
    if confirmation != "RECOVER-LIFECYCLE":
        raise ValueError("Lifecycle recovery requires exact RECOVER-LIFECYCLE confirmation")
    from .generations import Store
    from .state import recover_registry
    with registry.locked(recovery=True):
        store = Store(registry.root)
        pending = store.pending()
        if pending is None:
            raise ValueError("No pending lifecycle transition")
        if pending["executor_sha256"] != executor_identity():
            raise ValueError("Recovery requires the original lifecycle executor")
        if pending["action"] == "enroll":
            _continue_enrollment(registry, runner, pending)
        else:
            recover_registry(registry, pending)


def dispatch(args, registry, runner, ui):
    if args.action == "status":
        report = status(registry)
        ui.message(json.dumps(report, indent=2, sort_keys=True))
        return 1 if report["error"] else 0
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise ValueError("Lifecycle enrollment/recovery requires an interactive terminal")
    if args.action == "register":
        ui.message("Enrollment archives original evidence, installs lifecycle-aware boot guards and replaces the legacy lookup.\n"
                   "No applications, packages, jail layout or PF topology are upgraded. Retain this exact artifact at its current path.\n"
                   "Validation may start only the original pair if it stops during this transition; unchanged applications may serve users.\n"
                   "Historical entrypoints are unsupported after enrollment. Native M2 acceptance is NOT RUN.")
        phrase = ui.input(f"Type ENROLL {args.instance} to continue")
        register(registry, args.instance, runner, confirmation=phrase)
        ui.message("Lifecycle enrollment complete. No upgrade path is authorized.")
    elif args.action == "recover":
        ui.message("Recovery only completes the same source-bound metadata/boot-guard transition; it never rolls back application data.\n"
                   "If enrollment was interrupted with its jails stopped, this may start only the original recorded pair for validation.\n"
                   "The unchanged applications may serve normal users; this is not an isolated upgrade or writer fence.")
        phrase = ui.input("Type RECOVER-LIFECYCLE to continue")
        recover(registry, runner, confirmation=phrase)
        ui.message("Lifecycle metadata recovery completed; application acceptance remains separate.")
    else:
        raise ValueError("Unsupported maintenance action; no upgrade executor exists")
    return 0
