"""Maintenance phase records, not installation replay or execution authority.

The pure transition functions model destructive/publication boundaries. The
preparation journal permits native phases only through a shipped, reviewed recipe;
M3 deliberately ships none. The separate NativeJournal is a source-bound data
writer, not execution admission. A JSON field can never authorize execution.
"""

from copy import deepcopy

from .generations import Store, _digest, _encode, _fields, _hash, _id, _json, _reference, _schema
from .state import timestamp


PHASES = frozenset(("staging", "staged", "approved", "draining", "quiesced",
                    "recovery-ready", "migrating", "awaiting-reboot", "validating",
                    "committed-closed", "opening", "complete", "cancelled",
                    "restoring", "restored-closed", "recovery-opening", "recovered",
                    "recovery-required"))
TERMINAL = frozenset(("complete", "cancelled", "recovered"))
EDGES = {
    "staging": {"staged", "cancelled"},
    "staged": {"approved", "cancelled"},
    "approved": {"draining", "cancelled"},
    "draining": {"quiesced", "cancelled"},
    "quiesced": {"recovery-ready", "cancelled"},
    "recovery-ready": {"migrating", "validating", "restoring", "cancelled"},
    "migrating": {"validating", "awaiting-reboot", "restoring"},
    "awaiting-reboot": {"validating"},
    "validating": {"committed-closed", "restoring"},
    "committed-closed": {"opening", "restoring"},
    "opening": {"complete"},
    "restoring": {"restored-closed"},
    "restored-closed": {"recovery-opening"},
    "recovery-opening": {"recovered"},
}
REQUIRED = {
    "staged": {"artifacts"}, "approved": {"approval", "admission"},
    "draining": {"ingress"}, "quiesced": {"drain", "shutdown", "closure"},
    "recovery-ready": {"recovery_set", "closure"}, "migrating": {"recipe", "closure"},
    "awaiting-reboot": {"reboot"}, "validating": {"closure", "validation_permission"},
    "committed-closed": {"readiness", "graph", "network", "closure"},
    "opening": {"readiness", "graph", "network", "closure"},
    "complete": {"post_open", "consistency"},
    "restoring": {"restore_assessment", "closure"},
    "restored-closed": {"restored_set", "post_restore", "graph", "network", "closure"},
    "recovery-opening": {"fingerprint", "readiness", "graph", "network", "closure"},
    "recovered": {"post_open", "consistency"},
}
ERRORS = frozenset(("staging-failed", "preflight-failed", "capture-failed", "restore-failed",
                    "validation-failed", "closure-lost", "interrupted", "publication-uncertain"))
EVIDENCE_KEYS = frozenset().union(*REQUIRED.values(), {"original_services", "consistency", "closure_removed"})

# Future entries must be fixed implementation objects with source/destination,
# fencing, native acceptance and recovery review. Never load recipes from JSON,
# operator files, downloaded scripts or a report's execution_authorized field.
REVIEWED_NATIVE_RECIPES = {}


def require_native_recipe(operation):
    identifier = operation.get("recipe") if isinstance(operation, dict) else None
    recipe = REVIEWED_NATIVE_RECIPES.get(identifier) if type(identifier) is str else None
    if recipe is None:
        raise ValueError("Native maintenance is blocked: no reviewed, natively accepted recipe; upgrade execution is unavailable")
    return recipe


def initial(operation_ref):
    _reference(operation_ref)
    return {"schema_version": 1, "kind": "maintenance-journal", "operation": operation_ref,
            "phase": "staging", "last_safe_phase": "staging", "sequence": 0,
            "publication_may_have_begun": False, "recovery_publication_may_have_begun": False,
            "steps": {}, "evidence": {}, "error": None, "updated": timestamp()}


def validate(value):
    _fields(value, "schema_version kind operation phase last_safe_phase sequence publication_may_have_begun recovery_publication_may_have_begun steps evidence error updated")
    _schema(value)
    _reference(value["operation"])
    if (value["kind"] != "maintenance-journal" or type(value["phase"]) is not str or value["phase"] not in PHASES
            or type(value["last_safe_phase"]) is not str or value["last_safe_phase"] not in PHASES or value["last_safe_phase"] == "recovery-required"
            or type(value["sequence"]) is not int or value["sequence"] < 0
            or any(type(value[key]) is not bool for key in ("publication_may_have_begun", "recovery_publication_may_have_begun"))
            or not isinstance(value["updated"], str) or len(value["updated"]) > 40
            or value["error"] is not None and (type(value["error"]) is not str or value["error"] not in ERRORS)):
        raise ValueError("Invalid maintenance journal state")
    if (value["phase"] != "recovery-required" and (value["last_safe_phase"] != value["phase"] or value["error"] is not None)
            or value["phase"] == "recovery-required" and value["error"] is None):
        raise ValueError("Inconsistent maintenance failure boundary")
    if value["phase"] in ("opening", "complete") and not value["publication_may_have_begun"]:
        raise ValueError("Missing durable publication marker")
    if value["phase"] in ("recovery-opening", "recovered") and not value["recovery_publication_may_have_begun"]:
        raise ValueError("Missing durable recovery publication marker")
    if type(value["evidence"]) is not dict or len(value["evidence"]) > 32:
        raise ValueError("Invalid maintenance evidence")
    for key, ref in value["evidence"].items():
        if key not in EVIDENCE_KEYS:
            raise ValueError("Unknown maintenance evidence kind")
        _reference(ref)
    if type(value["steps"]) is not dict or len(value["steps"]) > 1024:
        raise ValueError("Invalid maintenance step inventory")
    for name, step in value["steps"].items():
        _id(name)
        _fields(step, "state replay attempts observation precondition")
        if (step["state"] not in ("running", "complete", "uncertain") or step["replay"] not in ("never", "idempotent")
                or type(step["attempts"]) is not int or step["attempts"] < 1):
            raise ValueError("Invalid maintenance step")
        if step["observation"] is not None:
            _reference(step["observation"])
        _reference(step["precondition"])
        if step["state"] == "complete" and step["observation"] is None:
            raise ValueError("Completion requires observed evidence")
    return value


def transition(record, phase, evidence=None):
    """Pure phase validation; this function grants NO execution permission."""
    value = deepcopy(validate(record))
    if phase not in PHASES or phase == "recovery-required":
        raise ValueError("Use an explicit failure record for interrupted maintenance")
    current = value["phase"]
    if current in TERMINAL:
        raise ValueError("Terminal maintenance cannot be replayed")
    if current == "recovery-required":
        # No guessed replay of migration/restoration after an uncertain action.
        previous = value["last_safe_phase"]
        allowed = {"staging", "cancelled"} if previous == "staging" else {"restoring"}
        if previous in ("opening", "recovery-opening"):
            allowed = {"complete"} if previous == "opening" else {"recovered"}
    else:
        allowed = EDGES.get(current, set())
    if phase not in allowed:
        raise ValueError("Unsupported maintenance phase transition")
    supplied = {} if evidence is None else evidence
    if type(supplied) is not dict:
        raise ValueError("Maintenance transition requires typed evidence references")
    required = REQUIRED.get(phase, set())
    if phase == "cancelled" and current not in ("staging", "staged") and value["last_safe_phase"] != "staging":
        required = {"original_services", "consistency", "closure_removed"}
    if not required <= supplied.keys():
        raise ValueError("Maintenance transition lacks required safety evidence")
    for key, ref in supplied.items():
        if key not in EVIDENCE_KEYS:
            raise ValueError("Unknown maintenance evidence kind")
        _reference(ref)
    if phase == "restoring" and (value["publication_may_have_begun"] or value["recovery_publication_may_have_begun"]):
        raise ValueError("Publication may have begun; destructive recovery is not authorized")
    if phase == "cancelled" and (value["publication_may_have_begun"] or value["recovery_publication_may_have_begun"]):
        raise ValueError("Publication may have begun; cancellation cannot discard writes")
    if phase in ("committed-closed", "restored-closed", "opening", "recovery-opening", "complete", "recovered"):
        if any(step["state"] != "complete" for step in value["steps"].values()):
            raise ValueError("Uncertain/running steps prevent publication or completion")
    value["publication_may_have_begun"] |= phase == "opening"
    value["recovery_publication_may_have_begun"] |= phase == "recovery-opening"
    value.update(phase=phase, last_safe_phase=phase, error=None, sequence=value["sequence"] + 1, updated=timestamp())
    value["evidence"].update(supplied)
    return validate(value)


def failure(record, code, *, closure_lost=False):
    value = deepcopy(validate(record))
    if value["phase"] in TERMINAL or code not in ERRORS or type(closure_lost) is not bool:
        raise ValueError("Invalid maintenance failure")
    if value["phase"] != "recovery-required":
        value["last_safe_phase"] = value["phase"]
    if closure_lost or code in ("closure-lost", "publication-uncertain"):
        value["publication_may_have_begun"] = True
    for step in value["steps"].values():
        if step["state"] == "running" and step["replay"] == "never":
            step["state"] = "uncertain"
    value.update(phase="recovery-required", error=code, sequence=value["sequence"] + 1, updated=timestamp())
    return validate(value)


def start_step(record, name, *, replay, precondition):
    value = deepcopy(validate(record))
    _id(name)
    _reference(precondition)
    if value["phase"] in TERMINAL or replay not in ("never", "idempotent"):
        raise ValueError("Unsupported maintenance step")
    previous = value["steps"].get(name)
    if previous and (previous["replay"] != replay or replay == "never" or previous["state"] == "complete"):
        raise ValueError("Completed or uncertain destructive steps cannot be replayed")
    value["steps"][name] = {"state": "running", "replay": replay,
                            "attempts": previous["attempts"] + 1 if previous else 1,
                            "observation": None, "precondition": precondition}
    value.update(sequence=value["sequence"] + 1, updated=timestamp())
    return validate(value)


def complete_step(record, name, observation):
    value = deepcopy(validate(record))
    _reference(observation)
    if name not in value["steps"] or value["steps"][name]["state"] != "running" or value["phase"] in TERMINAL:
        raise ValueError("Step completion requires a current running attempt and observed evidence")
    value["steps"][name].update(state="complete", observation=observation)
    value.update(sequence=value["sequence"] + 1, updated=timestamp())
    return validate(value)


class OperationJournal:
    def __init__(self, registry, operation, operation_ref):
        self.registry, self.store = registry, Store(registry.root)
        self.operation = _id(operation)
        self.reference = _reference(operation_ref, f"maintenance/operations/{operation}/operation.json")
        self.path = f"maintenance/operations/{operation}/journal.json"

    def read(self):
        value = validate(_json(self.store._read(self.path)))
        if value["operation"] != self.reference:
            raise ValueError("Maintenance journal belongs to another immutable operation")
        self.store._bound(self.reference)
        for ref in value["evidence"].values():
            self.store._bound(ref)
        for step in value["steps"].values():
            self.store._bound(step["precondition"])
            if step["observation"] is not None:
                self.store._bound(step["observation"])
        terminal_path = f"maintenance/operations/{self.operation}/terminal.json"
        if self.store._present(terminal_path):
            expected = {"schema_version": 1, "kind": "maintenance-terminal", "operation": self.reference,
                        "phase": value["phase"], "journal": self.store.reference(self.path)}
            if value["phase"] not in TERMINAL or _json(self.store._read(terminal_path)) != expected:
                raise ValueError("Retained maintenance terminal changed")
        return value

    def _write(self, value, *, create=False):
        self.registry._require_lock()
        validate(value)
        self.store._bound(self.reference)
        if self.store._present(f"maintenance/operations/{self.operation}/terminal.json"):
            raise ValueError("A sealed maintenance terminal record cannot be changed")
        self.store._put(self.path, value, replace=not create)

    def initialize(self):
        if self.store._present(self.path):
            return self.read()
        value = initial(self.reference)
        self._write(value, create=True)
        return value

    def advance(self, phase, evidence=None):
        previous = self.read()
        inert = (previous["phase"] in ("staging", "staged") or
                 previous["phase"] == "recovery-required" and previous["last_safe_phase"] == "staging")
        if not inert or phase not in ("staging", "staged", "cancelled"):
            require_native_recipe(_json(self.store._bound(self.reference)))
        for ref in (evidence or {}).values():
            self.store._bound(ref)
        value = transition(previous, phase, evidence)
        self._write(value)
        return value

    def fail(self, code, *, closure_lost=False):
        self._write(failure(self.read(), code, closure_lost=closure_lost))

    def step_start(self, name, *, replay, precondition):
        previous = self.read()
        if previous["phase"] != "staging" or replay != "idempotent":
            require_native_recipe(_json(self.store._bound(self.reference)))
        self.store._bound(precondition)
        self._write(start_step(previous, name, replay=replay, precondition=precondition))

    def step_complete(self, name, observation):
        previous = self.read()
        if previous["phase"] != "staging":
            require_native_recipe(_json(self.store._bound(self.reference)))
        self.store._bound(observation)
        self._write(complete_step(previous, name, observation))

    def terminal(self):
        self.registry._require_lock()
        value = self.read()
        if value["phase"] not in TERMINAL:
            raise ValueError("Maintenance is not terminal")
        record = {"schema_version": 1, "kind": "maintenance-terminal", "operation": self.reference,
                  "phase": value["phase"], "journal": self.store.reference(self.path)}
        relative = f"maintenance/operations/{self.operation}/terminal.json"
        if self.store._present(relative):
            if _json(self.store._read(relative)) != record:
                raise ValueError("Retained maintenance terminal changed")
            return self.store.reference(relative)
        return self.store._put(relative, record)


# Separate schemas deliberately leave the inert preparation journal/readers alone.
# These records describe effects; neither their presence nor any JSON flag admits
# a recipe. Native orchestration must separately admit a fixed implementation.
NATIVE_EDGES = {
    "capture": {"quiesced", "cancelled"},
    "quiesced": {"recovery-ready", "cancelled"},
    "recovery-ready": {"migrating", "validating", "restoring", "cancelled", "recovery-reclosing"},
    "migrating": {"validating", "awaiting-reboot", "restoring", "recovery-reclosing"},
    "awaiting-reboot": {"validating", "restoring", "recovery-reclosing"},
    "validating": {"committed-closed", "restoring", "recovery-reclosing"},
    "committed-closed": {"opening", "restoring", "recovery-reclosing"},
    "recovery-reclosing": {"recovery-reclosing", "recovery-reclosed"},
    "recovery-reclosed": {"restoring", "recovery-reclosing"},
    "opening": {"complete"},
    "restoring": {"restored-closed"},
    "restored-closed": {"recovery-validating"},
    "recovery-validating": {"recovery-opening"},
    "recovery-opening": {"recovered"},
}
NATIVE_PHASES = frozenset(NATIVE_EDGES) | TERMINAL | {"recovery-required"}
NATIVE_REQUIRED = {key: set(value) for key, value in REQUIRED.items() if key in NATIVE_PHASES}
NATIVE_REQUIRED.update({
    # An operator acknowledgement is NOT automatic ONLYOFFICE drain evidence.
    "quiesced": {"offline_acknowledgement", "admission", "ingress", "shutdown", "closure"},
    # Dataset completion precedes canary writes and graph publication.
    "restored-closed": {"restored_set", "closure"},
    "recovery-validating": {"restored_set", "closure", "validation_permission"},
    "recovery-opening": {"post_restore", "fingerprint", "readiness", "graph", "network", "closure"},
    "recovery-reclosing": {"reclosure_request", "closure"},
    "recovery-reclosed": {"reclosure", "shutdown", "closure"},
    "cancelled": {"original_services", "consistency", "closure_removed"},
})
NATIVE_EVIDENCE_KEYS = frozenset().union(*NATIVE_REQUIRED.values(), {"original_restore_consent"})
MAX_NATIVE_HISTORY = 2048
NATIVE_ERRORS = ERRORS | {"migration-failed", "reconciliation-failed"}


def native_initial(intent_ref, inputs_ref, recipe_sha256):
    value = initial(intent_ref)
    value.update(schema_version=2, kind="native-maintenance-journal", inputs=inputs_ref,
                 recipe_sha256=recipe_sha256, phase="capture", last_safe_phase="capture", history=[])
    return native_validate(value)


def _native_step(step):
    _fields(step, "state replay attempts observation precondition phase recovery")
    if (type(step["state"]) is not str or step["state"] not in ("running", "complete", "uncertain", "superseded")
            or type(step["replay"]) is not str or step["replay"] not in ("never", "idempotent")
            or type(step["attempts"]) is not int or step["attempts"] < 1
            or type(step["phase"]) is not str or step["phase"] not in NATIVE_EDGES):
        raise ValueError("Invalid native maintenance step")
    _reference(step["precondition"])
    if step["observation"] is not None:
        _reference(step["observation"])
    if step["state"] == "complete" and step["observation"] is None:
        raise ValueError("Completion requires observed evidence")
    if step["state"] == "superseded":
        _reference(step["recovery"])
        if step["phase"] not in ("migrating", "awaiting-reboot", "validating", "recovery-reclosing"):
            raise ValueError("Only migration/validation attempts may be superseded")
    elif step["recovery"] is not None:
        raise ValueError("Unexpected step recovery reference")


def _native_evidence(evidence):
    if type(evidence) is not dict or not evidence.keys() <= NATIVE_EVIDENCE_KEYS:
        raise ValueError("Invalid native maintenance evidence")
    for ref in evidence.values():
        _reference(ref)


def native_validate(value):
    _fields(value, "schema_version kind operation inputs recipe_sha256 phase last_safe_phase sequence publication_may_have_begun recovery_publication_may_have_begun steps evidence error updated history")
    if type(value["schema_version"]) is not int or value["schema_version"] != 2 or value["kind"] != "native-maintenance-journal":
        raise ValueError("Unsupported native maintenance journal")
    _reference(value["operation"])
    _reference(value["inputs"])
    _digest(value["recipe_sha256"])
    if (any(type(value[key]) is not str or value[key] not in NATIVE_PHASES for key in ("phase", "last_safe_phase"))
            or value["last_safe_phase"] == "recovery-required"
            or type(value["sequence"]) is not int or value["sequence"] < 0
            or any(type(value[key]) is not bool for key in ("publication_may_have_begun", "recovery_publication_may_have_begun"))
            or type(value["updated"]) is not str or len(value["updated"]) > 40
            or value["error"] is not None and (type(value["error"]) is not str or value["error"] not in NATIVE_ERRORS)):
        raise ValueError("Invalid native maintenance state")
    if (value["phase"] == "recovery-required" and value["error"] is None
            or value["phase"] != "recovery-required" and (value["last_safe_phase"] != value["phase"] or value["error"] is not None)):
        raise ValueError("Inconsistent native maintenance failure boundary")
    if value["last_safe_phase"] in ("opening", "complete") and not value["publication_may_have_begun"]:
        raise ValueError("Missing durable publication marker")
    if value["last_safe_phase"] in ("recovery-opening", "recovered") and not value["recovery_publication_may_have_begun"]:
        raise ValueError("Missing durable recovery publication marker")
    _native_evidence(value["evidence"])
    if type(value["steps"]) is not dict or len(value["steps"]) > 1024:
        raise ValueError("Invalid native step inventory")
    for name, step in value["steps"].items():
        _id(name)
        _native_step(step)
    history = value["history"]
    if type(history) is not list or len(history) > MAX_NATIVE_HISTORY or len(history) != value["sequence"]:
        raise ValueError("Invalid or exhausted native maintenance history")
    for sequence, event in enumerate(history, 1):
        _fields(event, "sequence event phase error evidence name step")
        if (type(event["sequence"]) is not int or event["sequence"] != sequence
                or type(event["event"]) is not str or event["event"] not in ("transition", "failure", "step-start", "step-complete", "supersede")
                or type(event["phase"]) is not str or event["phase"] not in NATIVE_PHASES
                or event["error"] is not None and (type(event["error"]) is not str or event["error"] not in NATIVE_ERRORS)):
            raise ValueError("Invalid native maintenance history event")
        _native_evidence(event["evidence"])
        if event["event"] in ("step-start", "step-complete", "supersede"):
            _id(event["name"])
            _native_step(event["step"])
        elif event["name"] is not None or event["step"] is not None:
            raise ValueError("Invalid native history step")
    if history and (history[-1]["phase"] != value["phase"] or history[-1]["error"] != value["error"]):
        raise ValueError("Native history does not match checkpoint")
    return value


def _native_event(value, event, *, evidence=None, name=None):
    value.update(sequence=value["sequence"] + 1, updated=timestamp())
    value["history"].append(dict(sequence=value["sequence"], event=event, phase=value["phase"],
        error=value["error"], evidence=deepcopy(evidence or {}), name=name,
        step=deepcopy(value["steps"][name]) if name is not None else None))
    return native_validate(value)


def native_transition(record, phase, evidence=None):
    """Pure transitions. Restored validation never implicitly re-enters rollback."""
    value = deepcopy(native_validate(record))
    if type(phase) is not str or phase not in NATIVE_PHASES or phase == "recovery-required":
        raise ValueError("Unsupported native maintenance phase")
    current = value["phase"]
    if current in TERMINAL:
        raise ValueError("Terminal maintenance cannot be replayed")
    previous = value["last_safe_phase"]
    if current == "recovery-required":
        allowed = {
            "capture": {"cancelled"}, "quiesced": {"cancelled"},
            "recovery-ready": {"restoring", "cancelled"},
            "restoring": {"restoring"},
            "restored-closed": {"restored-closed", "recovery-validating"},
            "recovery-validating": {"recovery-validating"},
            "opening": {"complete"}, "recovery-opening": {"recovered"},
        }.get(previous, {"restoring"})
        if previous in ("recovery-ready", "migrating", "awaiting-reboot", "validating", "committed-closed",
                        "recovery-reclosing", "recovery-reclosed"):
            allowed = allowed | {"recovery-reclosing"}
        if previous == "recovery-reclosing":
            allowed = {"recovery-reclosing", "recovery-reclosed"}
    else:
        allowed = NATIVE_EDGES.get(current, set())
    if (phase == "restoring" and previous == "recovery-reclosing" and type(evidence) is dict
            and "original_restore_consent" in evidence):
        allowed = allowed | {"restoring"}
    if phase not in allowed:
        raise ValueError("Unsupported native maintenance phase transition")
    supplied = {} if evidence is None else evidence
    _native_evidence(supplied)
    if not NATIVE_REQUIRED.get(phase, set()) <= supplied.keys():
        raise ValueError("Native transition lacks required safety evidence")
    for key in ("offline_acknowledgement", "recovery_set", "restored_set"):
        if key in supplied and key in value["evidence"] and supplied[key] != value["evidence"][key]:
            raise ValueError("Native transition cannot replace pinned recovery/offline evidence")
    if phase in ("restoring", "cancelled", "recovery-reclosing", "recovery-reclosed") and (value["publication_may_have_begun"] or value["recovery_publication_may_have_begun"]):
        raise ValueError("Publication may have begun; destructive recovery/cancellation is forbidden")
    if phase in ("migrating", "validating", "restoring", "recovery-reclosing", "recovery-reclosed") and "recovery_set" not in value["evidence"]:
        raise ValueError("A captured recovery set is mandatory before migration or restoration")
    if phase == "restoring" and current == "recovery-required" and previous == "restoring":
        if supplied["restore_assessment"] != value["evidence"].get("restore_assessment"):
            raise ValueError("Partial restoration must retain its pinned assessment")
    if phase in ("committed-closed", "restored-closed", "opening", "recovery-opening", "complete", "recovered"):
        if any(step["state"] not in ("complete", "superseded") for step in value["steps"].values()):
            raise ValueError("Uncertain/running steps prevent publication or completion")
    if phase == "restored-closed" and "restored_set" in value["evidence"] and supplied["restored_set"] != value["evidence"]["restored_set"]:
        raise ValueError("Restored checkpoint differs from step reconciliation")
    if phase == "recovery-validating" and supplied["restored_set"] != value["evidence"].get("restored_set"):
        raise ValueError("Restored validation must retain the exact restored set")
    if phase == "recovery-reclosing":
        # Re-quiescence never resumes or completes the interrupted updater.
        for step in value["steps"].values():
            if step["state"] == "running":
                step["state"] = "uncertain"
    value["publication_may_have_begun"] |= phase == "opening"
    value["recovery_publication_may_have_begun"] |= phase == "recovery-opening"
    value.update(phase=phase, last_safe_phase=phase, error=None)
    value["evidence"].update(deepcopy(supplied))
    return _native_event(value, "transition", evidence=supplied)


def native_failure(record, code, *, closure_lost=False):
    value = deepcopy(native_validate(record))
    if value["phase"] in TERMINAL or type(code) is not str or code not in NATIVE_ERRORS or type(closure_lost) is not bool:
        raise ValueError("Invalid native maintenance failure")
    if closure_lost or code in ("closure-lost", "publication-uncertain"):
        value["publication_may_have_begun"] = True
    for step in value["steps"].values():
        if step["state"] == "running":
            step["state"] = "uncertain"
    value.update(phase="recovery-required", error=code)
    return _native_event(value, "failure")


def native_start_step(record, name, *, replay, precondition):
    value = deepcopy(native_validate(record))
    _id(name)
    _reference(precondition)
    if value["phase"] not in NATIVE_EDGES or type(replay) is not str or replay not in ("never", "idempotent"):
        raise ValueError("Unsupported native maintenance step")
    previous = value["steps"].get(name)
    if previous:
        if (previous["replay"] != replay or replay == "never" or previous["state"] == "superseded"
                or previous["phase"] != value["phase"] or previous["precondition"] != precondition
                or previous["state"] == "complete" and value["phase"] != "restoring"):
            raise ValueError("Completed or uncertain destructive steps cannot be replayed")
    value["steps"][name] = dict(state="running", replay=replay, attempts=previous["attempts"] + 1 if previous else 1,
        observation=None, precondition=deepcopy(precondition), phase=value["phase"], recovery=None)
    return _native_event(value, "step-start", name=name)


def native_complete_step(record, name, observation):
    value = deepcopy(native_validate(record))
    _id(name)
    _reference(observation)
    step = value["steps"].get(name)
    if (step is None or step["state"] != "running" or step["phase"] != value["phase"]
            or value["phase"] not in NATIVE_EDGES):
        raise ValueError("Step completion requires a current running attempt and observed evidence")
    step.update(state="complete", observation=deepcopy(observation))
    return _native_event(value, "step-complete", name=name)


def native_supersede_steps(record, recoveryref):
    value = deepcopy(native_validate(record))
    _reference(recoveryref)
    if value["phase"] != "restoring":
        raise ValueError("Only a restored set can supersede migration attempts while restoring")
    if any(step["phase"] == "restoring" and step["state"] != "complete" for step in value["steps"].values()):
        raise ValueError("Incomplete restore members cannot supersede migration attempts")
    if "restored_set" in value["evidence"] and value["evidence"]["restored_set"] != recoveryref:
        raise ValueError("Restored set cannot change during reconciliation")
    for name, step in value["steps"].items():
        if step["phase"] in ("migrating", "awaiting-reboot", "validating", "recovery-reclosing") and step["state"] != "superseded":
            step.update(state="superseded", recovery=deepcopy(recoveryref))
            value["evidence"]["restored_set"] = deepcopy(recoveryref)
            _native_event(value, "supersede", evidence={"restored_set": recoveryref}, name=name)
    return native_validate(value)


class NativeJournal:
    """Source-bound native data writer, NEVER recipe execution admission.

    ``native`` is the caller's NativeState adapter; ``recipe`` is its exact
    descriptor (or a fixed implementation object's descriptor() result). The
    orchestrator must gate that implementation independently. There is no JSON
    force flag or catalog override here. Each call requires the Registry lock.
    """

    def __init__(self, registry, operation, operation_ref, recipe, *, native):
        self.registry, self.store = registry, Store(registry.root)
        self.operation = _id(operation)
        if not operation.startswith("execution-"):
            raise ValueError("Native journal requires an execution identifier")
        self.reference = deepcopy(_reference(operation_ref, f"maintenance/operations/{operation}/intent.json"))
        self.native = native
        self.recipe = recipe
        self.path = f"maintenance/operations/{operation}/native-journal.json"
        self.terminal_path = f"maintenance/operations/{operation}/native-terminal.json"

    def _binding(self):
        self.registry._require_lock()
        if self.native.registry is not self.registry:
            raise ValueError("Native journal adapter belongs to another registry")
        intent, inputs = self.native.read(self.operation)
        if _json(self.store._bound(self.reference)) != intent:
            raise ValueError("Native journal belongs to another immutable intent")
        descriptor = self.recipe if type(self.recipe) is dict else self.recipe.descriptor()
        if (type(descriptor) is not dict or descriptor != inputs["recipe"]
                or _hash(_encode(descriptor)) != inputs["recipe_sha256"]):
            raise ValueError("Native journal requires the exact stored recipe descriptor/hash")
        return intent, inputs

    def _bound(self, value):
        native_validate(value)
        intent, inputs = self._binding()
        if (value["operation"] != self.reference or value["inputs"] != intent["inputs"]
                or value["recipe_sha256"] != inputs["recipe_sha256"]):
            raise ValueError("Native journal input/recipe binding differs")
        self.store._bound(value["inputs"])
        for evidence in [value["evidence"], *(event["evidence"] for event in value["history"])]:
            for ref in evidence.values():
                self.store._bound(ref)
        steps = [*value["steps"].values(), *(event["step"] for event in value["history"] if event["step"] is not None)]
        for step in steps:
            for key in ("precondition", "observation", "recovery"):
                if step[key] is not None:
                    self.store._bound(step[key])
        return value

    def _terminal_record(self, value):
        return dict(schema_version=1, kind="native-maintenance-terminal", operation=self.reference,
                    phase=value["phase"], journal=self.store.reference(self.path))

    def read(self):
        value = self._bound(_json(self.store._read(self.path)))
        if self.store._present(self.terminal_path):
            if value["phase"] not in TERMINAL or _json(self.store._read(self.terminal_path)) != self._terminal_record(value):
                raise ValueError("Retained native maintenance terminal changed")
        return value

    def _write(self, value, *, create=False):
        self._bound(value)
        if self.store._present(self.terminal_path):
            raise ValueError("A sealed native maintenance terminal record cannot be changed")
        self.store._put(self.path, value, replace=not create)
        return value

    def initialize(self):
        if self.store._present(self.path):
            return self.read()
        intent, inputs = self._binding()
        return self._write(native_initial(self.reference, intent["inputs"], inputs["recipe_sha256"]), create=True)

    def advance(self, phase, evidence=None):
        return self._write(native_transition(self.read(), phase, evidence))

    def fail(self, code, *, closure_lost=False):
        return self._write(native_failure(self.read(), code, closure_lost=closure_lost))

    def step_start(self, name, *, replay, precondition):
        return self._write(native_start_step(self.read(), name, replay=replay, precondition=precondition))

    def step_complete(self, name, observation):
        return self._write(native_complete_step(self.read(), name, observation))

    def supersede_steps(self, recoveryref):
        return self._write(native_supersede_steps(self.read(), recoveryref))

    def terminal(self):
        value = self.read()
        if value["phase"] not in TERMINAL:
            raise ValueError("Native maintenance is not terminal")
        record = self._terminal_record(value)
        if self.store._present(self.terminal_path):
            return self.store.reference(self.terminal_path)
        return self.store._put(self.terminal_path, record)
