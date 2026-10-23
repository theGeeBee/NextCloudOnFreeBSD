"""Read-only native operation history; never a live recovery eligibility probe."""

from .generations import Store, _hash, _encode, _id, _json
from .maintenance_journal import native_validate, TERMINAL
from .maintenance_state import validate_intent


def inspect(registry, operation):
    """Authenticate bounded retained records without locks, writes or native calls.

    A recorded snapshot/validation proof does not establish today's live identity
    or restore eligibility. Even terminal history grants no execution authority.
    """
    _id(operation)
    if not operation.startswith("execution-"):
        raise ValueError("Expected native execution operation identifier")
    store = Store(registry.root)
    directory = "maintenance/operations/" + operation
    pending = store.pending()
    intent_ref = store.reference(directory + "/intent.json")
    intent = validate_intent(_json(store._bound(intent_ref)))
    if intent["operation"] != operation:
        raise ValueError("Native inspection intent differs")
    inputs = _json(store._bound(intent["inputs"], directory + "/native-inputs.json"))
    # The full inputs are validated by the native controller before execution;
    # this inspector displays only strict, hash-bound public identity fields.
    if (inputs.get("operation") != operation or inputs.get("instance") != intent["instances"][0]
            or _hash(_encode(inputs.get("recipe"))) != inputs.get("recipe_sha256")):
        raise ValueError("Native inspection input binding differs")
    journal_path = directory + "/native-journal.json"
    journal_ref = store.reference(journal_path) if store._present(journal_path) else None
    journal = native_validate(_json(store._bound(journal_ref))) if journal_ref else None
    if journal:
        if (journal["operation"] != intent_ref or journal["inputs"] != intent["inputs"]
                or journal["recipe_sha256"] != inputs["recipe_sha256"]):
            raise ValueError("Native inspection journal binding differs")
        for evidence in [journal["evidence"], *(event["evidence"] for event in journal["history"])]:
            for ref in evidence.values():
                store._bound(ref)
        for step in [*journal["steps"].values(), *(event["step"] for event in journal["history"] if event["step"] is not None)]:
            for name in ("precondition", "observation", "recovery"):
                if step[name] is not None:
                    store._bound(step[name])
    terminal_path = directory + "/native-terminal.json"
    sealed = store._present(terminal_path)
    if sealed:
        terminal = _json(store._read(terminal_path))
        if (not journal or journal["phase"] not in TERMINAL or terminal != dict(
                schema_version=1, kind="native-maintenance-terminal", operation=intent_ref,
                phase=journal["phase"], journal=journal_ref)):
            raise ValueError("Native inspection terminal differs")
    if ((pending is not None and pending.get("operation") == operation and pending != intent)
            or store.pending() != pending or store.reference(directory + "/intent.json") != intent_ref
            or journal_ref != (store.reference(journal_path) if store._present(journal_path) else None)):
        raise ValueError("Native maintenance changed during read-only inspection")
    return dict(schema_version=1, operation=operation, instance=intent["instances"][0],
        phase=journal["phase"] if journal else "intent-recorded", error=journal["error"] if journal else None,
        pending=pending == intent, journal_sealed=sealed,
        recovery_manifest_recorded=bool(journal and "recovery_set" in journal["evidence"]),
        native_resources_verified=False, restore_eligible=False,
        native_execution_authorized=False, upgrade_execution_authorized=False,
        publication_may_have_begun=journal["publication_may_have_begun"] if journal else False,
        recovery_publication_may_have_begun=journal["recovery_publication_may_have_begun"] if journal else False,
        warnings=["Retained journal inspection only; live resources and current restore eligibility are not verified.",
                  "An offline acknowledgment is not automatic editor-drain proof."])
