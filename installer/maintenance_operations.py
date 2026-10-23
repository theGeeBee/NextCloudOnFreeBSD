"""M3 recovery preparation: plans, inert artifact staging and inspection.

There is no reviewed native recipe. Applying, capturing, restoring or reopening
through the operator entrypoint remains blocked pending native fencing/restore
acceptance. Enrollment's permissive starts are never reused for maintenance.
"""

from copy import deepcopy
import os
import re
import uuid

from .generations import Store, _digest, _fields, _id, _json, _reference, _schema
from .maintenance import executor_record, entry_guard, require_instance_adapter
from .maintenance_journal import OperationJournal
from .paths import PROJECT_ROOT


NETWORK_RECORDS = ("firewall-transition.json", "firewall-confirmed", "pf-filter.expected",
                   "pf-nat.expected", "pf-jails.expected", "pf-noninternet.expected")
WARNINGS = [
    "Recovery preparation is not an upgrade plan or authorization to stop/restore services.",
    "Source staging does not retain package archives; exact package availability is rechecked from signed catalogs.",
    "Live drift, clean shutdown, writer/ingress closure, capacity and independent recovery copies require native preflight.",
    "Native maintenance acceptance is NOT RUN; no executable native recipe is shipped.",
]


def _network_binding(store):
    link = store._path("network/active")
    if not link.is_symlink():
        raise ValueError("Maintenance requires an existing committed network pointer")
    target = os.readlink(link)
    try:
        relative = str(type(store.root)(target).relative_to(store.root))
    except ValueError:
        raise ValueError("Network pointer is outside managed transactions") from None
    if not re.fullmatch(r"transactions/[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", relative):
        raise ValueError("Unsupported committed network identity")
    records = {name: store.reference(relative + "/" + name) for name in NETWORK_RECORDS}
    if os.readlink(link) != target:
        raise ValueError("Committed network changed during inspection")
    return {"target": relative, "records": records}


def bindings(registry, name):
    """Read one authoritative source view; never initialize or repair it."""
    if not registry.lifecycle_enabled():
        raise ValueError("Recovery preparation requires explicit lifecycle enrollment")
    entry_guard("mutation", registry=registry)  # Read-only exact-executor test.
    store = Store(registry.root)
    graph = store.graph()
    entry = graph["instances"].get(name)
    if entry is None or entry["kind"] != "managed" or entry["status"]["state"] != "ready":
        raise ValueError("Recovery preparation requires a ready managed generation")
    require_instance_adapter(registry, name)
    config = registry.load(name)
    config.require_native_backend("Legacy maintenance")
    from .resolution import validate_plan
    versions_path = str(registry.evidence_path(name, "versions.json").relative_to(store.root))
    versions = validate_plan(config, _json(store._read(versions_path)), policy=registry.version_policy(name))
    result = {"graph": store._active(), "generation": entry["generation"],
              "versions": store.reference(versions_path), "executor": executor_record(),
              "network": _network_binding(store)}
    if graph != store.graph() or result["graph"] != store._active():
        raise ValueError("Lifecycle graph changed during recovery planning")
    return result, config, versions


def _conflicts(registry):
    # Reuse the conservative cross-instance pending-work checks. This is private
    # metadata inspection, not verification of running application health.
    from .updates import _save_conflicts
    _save_conflicts(registry)


def assess(registry, name, *, target=None):
    registry.instance_path(name)
    report = {"schema_version": 1, "instance": name, "status": "blocked", "plan": None,
              "blockers": [], "warnings": list(WARNINGS), "execution_authorized": False,
              "native_acceptance": "not-run"}
    if target is not None:
        if not isinstance(target, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,79}", target):
            raise ValueError("Invalid maintenance target profile")
        report["blockers"].append("No reviewed source-to-destination recipe exists; a compatible destination does not authorize migration.")
        return report
    try:
        from .maintenance_staging import required_artifacts
        retained, config, versions = bindings(registry, name)
        _conflicts(registry)
        # Recovery is the coherent 14-member snapshot/export, not package
        # reinstallation. The reviewed first patch has an empty package
        # transaction and revalidates exact availability from a fresh signed
        # catalog; pkg's opaque 2$ archive sums must never be mislabeled SHA256.
        specs = required_artifacts(None, PROJECT_ROOT)
        report["plan"] = {"schema_version": 1, "kind": "recovery-preparation-plan", "plan_id": None,
                          "instance": name, "bindings": retained, "artifacts": specs,
                          "recipe": None,
                          "upgrade_execution_authorized": False,
                          "native_execution_authorized": False, "native_acceptance": "not-run"}
        report["status"] = "staging-only"
    except (ValueError, OSError, RuntimeError, KeyError, TypeError):
        report["blockers"].append("Source/graph/locks/network evidence or pending-operation checks failed; retain the original artifact and inspect private state.")
    return report


def validate_plan(plan, *, saved=True):
    from .maintenance_staging import validate_specs
    _fields(plan, "schema_version kind plan_id instance bindings artifacts recipe upgrade_execution_authorized native_execution_authorized native_acceptance")
    _schema(plan)
    _id(plan["instance"], True)
    if (plan["kind"] != "recovery-preparation-plan" or plan["recipe"] is not None
            or plan["upgrade_execution_authorized"] is not False or plan["native_execution_authorized"] is not False
            or plan["native_acceptance"] != "not-run"):
        raise ValueError("Unsupported maintenance plan or execution authority")
    if saved:
        _id(plan["plan_id"])
    elif plan["plan_id"] is not None:
        raise ValueError("Unexpected already-saved plan")
    bound = plan["bindings"]
    _fields(bound, "graph generation versions executor network")
    for key in ("graph", "generation", "versions"):
        _reference(bound[key])
    _fields(bound["executor"], "schema_version source_sha256 executor_sha256 payload_path policy_sha256")
    _schema(bound["executor"])
    for key in ("source_sha256", "executor_sha256", "policy_sha256"):
        _digest(bound["executor"][key])
    payload = bound["executor"]["payload_path"]
    if not isinstance(payload, str) or not payload.startswith("/") or len(payload) > 1024 or any(ord(c) < 32 for c in payload):
        raise ValueError("Invalid retained executor path")
    _fields(bound["network"], "target records")
    if (not isinstance(bound["network"]["target"], str)
            or not re.fullmatch(r"transactions/[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", bound["network"]["target"])
            or type(bound["network"]["records"]) is not dict
            or set(bound["network"]["records"]) != set(NETWORK_RECORDS)):
        raise ValueError("Incomplete retained network binding")
    for key, ref in bound["network"]["records"].items():
        _reference(ref, bound["network"]["target"] + "/" + key)
    validate_specs(plan["artifacts"])
    return plan


def _revalidate(registry, plan):
    from .maintenance_staging import required_artifacts
    validate_plan(plan)
    current, config, versions = bindings(registry, plan["instance"])
    if current != plan["bindings"] or required_artifacts(None, PROJECT_ROOT) != plan["artifacts"]:
        raise ValueError("Recovery plan is stale; review and save a new plan, never automatically rebase")
    _conflicts(registry)


def save_plan(registry, plan, *, confirmation):
    validate_plan(plan, saved=False)
    if confirmation != "SAVE-MAINTENANCE " + plan["instance"]:
        raise ValueError("Saving requires exact SAVE-MAINTENANCE NAME confirmation")
    with registry.locked():
        saved = deepcopy(plan)
        saved["plan_id"] = "plan-" + uuid.uuid4().hex
        _revalidate(registry, saved)
        store = Store(registry.root)
        store._mkdir("maintenance/plans")
        return store._put("maintenance/plans/" + saved["plan_id"] + ".json", saved)


def load_plan(store, plan_id):
    _id(plan_id)
    path = "maintenance/plans/" + plan_id + ".json"
    plan = validate_plan(_json(store._read(path)))
    if plan["plan_id"] != plan_id:
        raise ValueError("Maintenance plan identity mismatch")
    return plan, store.reference(path)


def load_operation(registry, operation):
    store = Store(registry.root)
    _id(operation)
    path = f"maintenance/operations/{operation}/operation.json"
    value = _json(store._read(path))
    _fields(value, "schema_version kind operation instance plan executor recipe effects")
    _schema(value)
    if (value["kind"] != "recovery-preparation-operation" or value["operation"] != operation
            or value["recipe"] is not None or value["effects"] != ["private-artifact-staging"]):
        raise ValueError("Unsupported maintenance operation")
    _id(value["instance"], True)
    plan = validate_plan(_json(store._bound(value["plan"])))
    _reference(value["plan"], "maintenance/plans/" + plan["plan_id"] + ".json")
    if plan["instance"] != value["instance"] or value["executor"] != plan["bindings"]["executor"]:
        raise ValueError("Maintenance operation/plan provenance mismatch")
    return value, plan, OperationJournal(registry, operation, store.reference(path))


def _stage(registry, operation, plan, journal, package_directory):
    from .maintenance_staging import stage, verify_stage
    _revalidate(registry, plan)
    previous = journal.initialize()
    if previous["phase"] == "recovery-required" and previous["last_safe_phase"] == "staging":
        journal.advance("staging")
    elif previous["phase"] != "staging":
        raise ValueError("Only unfinished inert staging can be continued")
    try:
        receipt = stage(registry.root, operation["operation"], plan["artifacts"], package_directory,
                         PROJECT_ROOT, registry=registry, **_artifact_bindings(registry, operation, plan))
        _revalidate(registry, plan)
        verify_stage(registry.root, operation["operation"], plan["artifacts"], receipt,
                     **_artifact_bindings(registry, operation, plan))
        journal.advance("staged", {"artifacts": receipt})
    except (ValueError, OSError, RuntimeError, KeyError, TypeError):
        journal.fail("staging-failed")
        raise ValueError("Artifact staging failed for " + operation["operation"] +
                         "; retained partial bytes may only be continued with the same plan and executor") from None
    return operation_status(registry, operation["operation"])


def _artifact_bindings(registry, operation, plan):
    # The immutable versions reference remains part of the plan/executor binding,
    # but source-only staging deliberately makes no package-archive completeness
    # claim. Candidate preflight re-queries the complete signed pkg catalog.
    return {"versions_plan": None, "plan_sha256": operation["plan"]["sha256"],
            "source_sha256": operation["executor"]["source_sha256"],
            "executor_sha256": operation["executor"]["executor_sha256"]}


def stage_plan(registry, plan_id, package_directory, *, confirmation):
    if confirmation != "STAGE-MAINTENANCE " + plan_id:
        raise ValueError("Staging requires exact STAGE-MAINTENANCE PLAN-ID confirmation")
    with registry.locked():
        store = Store(registry.root)
        plan, reference = load_plan(store, plan_id)
        _revalidate(registry, plan)
        operation = "maint-" + uuid.uuid4().hex
        directory = f"maintenance/operations/{operation}"
        store._mkdir(directory)
        value = {"schema_version": 1, "kind": "recovery-preparation-operation", "operation": operation,
                 "instance": plan["instance"], "plan": reference, "executor": executor_record(),
                 "recipe": None, "effects": ["private-artifact-staging"]}
        op_ref = store._put(directory + "/operation.json", value)
        journal = OperationJournal(registry, operation, op_ref)
        return _stage(registry, value, plan, journal, package_directory)


def continue_staging(registry, operation, package_directory, *, confirmation):
    if confirmation != "CONTINUE-MAINTENANCE " + operation:
        raise ValueError("Continuation requires exact CONTINUE-MAINTENANCE OP-ID confirmation")
    with registry.locked():
        value, plan, journal = load_operation(registry, operation)
        if value["executor"] != executor_record():
            raise ValueError("Continuation requires the original retained executor")
        return _stage(registry, value, plan, journal, package_directory)


def cancel(registry, operation, *, confirmation):
    if confirmation != "CANCEL-MAINTENANCE " + operation:
        raise ValueError("Cancellation requires exact CANCEL-MAINTENANCE OP-ID confirmation")
    with registry.locked():
        value, plan, journal = load_operation(registry, operation)
        if value["executor"] != executor_record():
            raise ValueError("Cancellation requires the original executor")
        record = journal.initialize()
        if record["phase"] != "cancelled":
            if (record["publication_may_have_begun"] or record["recovery_publication_may_have_begun"]
                    or record["phase"] not in ("staging", "staged", "recovery-required")
                    or record["phase"] == "recovery-required" and record["last_safe_phase"] != "staging"):
                raise ValueError("Cancellation cannot unwind native effects or publication; explicit recovery assessment required")
            journal.advance("cancelled")
        journal.terminal()
    return _operation_status(registry, operation, tolerate_cancelled_cache=True)


def operation_status(registry, operation):
    if operation.startswith("execution-"):
        from .maintenance_inspection import inspect
        return inspect(registry, operation)
    return _operation_status(registry, operation)


def prepare_target(registry, operation, artifacts, runner, *, confirmation):
    """Explicit inert target inspection, before a native intent or boot fence.

    It authenticates local public application archives and queries signed package
    metadata. It never installs software, stops services or authorizes migration.
    """
    from pathlib import Path
    from .maintenance_admission import SourceAdmission
    from .maintenance_candidate import collect
    from .maintenance_state import NativeState
    from .nextcloud_update import _file, MAX_ARCHIVE
    from .operations import _database_guard
    from .maintenance import _deployment
    if confirmation != "PREPARE-TARGET " + operation:
        raise ValueError("Target inspection requires exact PREPARE-TARGET OP-ID confirmation")
    files = {
        "target_zip": ("nextcloud-35.0.2.zip", MAX_ARCHIVE),
        "target_asc": ("nextcloud-35.0.2.zip.asc", 65536),
        "target_sig": ("nextcloud-35.0.2.zip.sig", 2048),
        "source_asc": ("nextcloud-35.0.1.tar.bz2.asc", 65536),
        "public_key": ("nextcloud.asc", 1024 * 1024),
        "connector_archive": ("connector.archive", MAX_ARCHIVE),
    }
    paths = {key: Path(artifacts).absolute() / name for key, (name, _) in files.items()}
    with registry.locked():
        entry_guard("mutation", registry=registry)
        value, _, journal = load_operation(registry, operation)
        if value["executor"] != executor_record() or journal.read()["phase"] != "staged":
            raise ValueError("Target inspection requires the exact staged source preparation")
        # Validate every fixed input before any artifact staging or native probe.
        for key, (_, limit) in files.items():
            with _file(paths[key], limit):
                pass
        native = NativeState(registry, executor_record())
        deployment = _deployment(registry, value["instance"], runner)
        with _database_guard(deployment):
            captured = collect(deployment, operation, source_admission=SourceAdmission(native), **paths)
            record = _json(native.store._bound(captured.reference))
        report = record["report"]
        return dict(schema_version=1, operation=operation, instance=value["instance"],
                    status=report["status"], blockers=list(report["blockers"]),
                    execution_authorized=False, native_execution_authorized=False,
                    upgrade_execution_authorized=False, native_acceptance="not-run", saved=True,
                    warnings=["Target artifacts and observations were retained privately; no live mutation or boot fence was started.",
                              "Candidate eligibility is not native execution authority; revalidation and acceptance are mandatory."])


def _operation_status(registry, operation, *, tolerate_cancelled_cache=False):
    value, plan, journal = load_operation(registry, operation)
    store = Store(registry.root)
    record = journal.read() if store._present(journal.path) else None
    authenticated = False
    error = record["error"] if record else None
    if record and "artifacts" in record["evidence"]:
        from .maintenance_staging import verify_stage
        # Cancellation has already durably sealed its inert terminal record.
        # Report cache damage without suggesting that cancellation was undone.
        # Operation/plan/journal metadata integrity remains strict above.
        kwargs = _artifact_bindings(registry, value, plan)
        try:
            verify_stage(registry.root, operation, plan["artifacts"], record["evidence"]["artifacts"], **kwargs)
            authenticated = True
        except (ValueError, OSError, RuntimeError, KeyError, TypeError):
            if not (tolerate_cancelled_cache and record["phase"] == "cancelled"
                    and store._present(f"maintenance/operations/{operation}/terminal.json")):
                raise
            error = "cancelled-cache-authentication-failed"
    return {"schema_version": 1, "operation": operation, "instance": value["instance"],
            "phase": record["phase"] if record else "staging-not-started",
            "error": error,
            "artifacts_authenticated": authenticated,
            "recovery_capture_complete": False, "independent_copy_verified": False,
            "writer_fencing_verified": False, "native_acceptance": "not-run",
            "upgrade_execution_authorized": False, "native_execution_authorized": False,
            "publication_may_have_begun": record["publication_may_have_begun"] if record else False,
            "recovery_publication_may_have_begun": record["recovery_publication_may_have_begun"] if record else False,
            "warnings": list(WARNINGS)}


def list_operations(registry):
    """Bounded metadata-only overview; detailed status rehashes the cache."""
    store = Store(registry.root)
    if not store._present("maintenance/operations"):
        return []
    directory = store._path("maintenance/operations")
    store._check(directory.lstat(), directory=True)
    names = []
    for path in directory.iterdir():
        if len(names) >= 1024:
            raise ValueError("Maintenance history exceeds overview bound; inspect an exact operation")
        names.append(path.name)
    result = []
    for name in sorted(names):
        if name.startswith("execution-"):
            try:
                value = operation_status(registry, name)
                result.append({key: value[key] for key in ("operation", "instance", "phase", "error")})
            except (ValueError, OSError, TypeError, KeyError):
                result.append(dict(operation=name, instance=None, phase="incomplete",
                                   error="Native operation evidence is incomplete or unsafe; no effects are inferred."))
            continue
        if not name.startswith("maint-"):
            continue  # Enrollment/registry intent history is a different schema.
        _id(name)
        row = {"operation": name, "instance": None, "phase": "incomplete", "error": None}
        try:
            value, _, journal = load_operation(registry, name)
            row["instance"] = value["instance"]
            if store._present(journal.path):
                record = journal.read()
                row.update(phase=record["phase"], error=record["error"])
            else:
                row["phase"] = "staging-not-started"
        except (ValueError, OSError, TypeError, KeyError):
            row["error"] = "Retained operation metadata is incomplete or unsafe; no effects are inferred."
        result.append(row)
    return result


def assess_recovery(registry, operation):
    result = operation_status(registry, operation)
    result.update(restore_eligible=False, blockers=["No reviewed native recovery recipe or accepted writer/ingress fencing protocol exists."])
    if result["publication_may_have_begun"] or result["recovery_publication_may_have_begun"]:
        result["blockers"].append("Publication may have begun; do not discard subsequent writes or replay a destructive restore.")
    return result


def apply(registry, operation, *, runner=None, backup_dataset=None, confirm=None):
    # The coordinator checks its compiled recipe BEFORE locks, consent, state
    # reads or native calls. Inert preparations never supply recipe authority.
    from .maintenance_execution import apply as execute
    return execute(registry, runner, operation, backup_dataset, confirm)
