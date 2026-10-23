"""Concrete fixed-recipe maintenance coordinator.

``apply`` is the production entry: admission precedes even local state reads.
``acceptance_apply`` is a trusted Python-only disposable acceptance entry, with
no CLI route, recipe argument or force flag. Its caller must already have target
approval; ``confirm(phrase)`` must return the operator's actual entered text.
Neither entry enrolls a recipe in the native acceptance catalog.

Continuation is explicit: ``acceptance_continue`` never invokes the updater;
``acceptance_restore`` requires fresh bound destructive-recovery consent. The
corresponding production functions retain the same admission gate. Failures keep
private evidence and the pending fence for assessment; they never auto-restore.
"""

from . import bounded_process, maintenance_candidate as candidates
from . import maintenance_generations as generations, maintenance_native as native
from . import maintenance_preflight as preflight, maintenance_update as patch
from . import maintenance_validation as validation, nextcloud_update as update
from . import recovery_export as export
from .generations import Store, _encode, _fields, _hash, _id, _json, _schema, descriptor
from .maintenance import executor_record
from .maintenance_admission import SourceAdmission
from .maintenance_publication import Publication
from .maintenance_state import NativeState


DENIED = "Maintenance execution refused; retain private operation evidence for assessment"
ARTIFACTS = {
    "target_zip": "nextcloud-35.0.2.zip",
    "target_asc": "nextcloud-35.0.2.zip.asc",
    "target_sig": "nextcloud-35.0.2.zip.sig",
    "source_asc": "nextcloud-35.0.1.tar.bz2.asc",
    "public_key": "nextcloud.asc",
}


def _require(value):
    if not value:
        raise ValueError(DENIED)


def _admit():
    # The identifier is compiled, never obtained from operator recipe JSON.
    return native.production_admission({"recipe": preflight.RECIPE_ID})


def _answer(confirm, phrase):
    _require(callable(confirm) and type(phrase) is str)
    answer = confirm(phrase)
    _require(type(answer) is str and answer == phrase)
    return answer


def load_candidate(store, preparation):
    """Strict private deserialization only; live revalidation is still mandatory.

    The fixed preparation path is the authority for the receipt reference, not a
    caller's hash. This does not renew timestamps or authenticate archive bytes.
    """
    captured = candidates.load(store, preparation)
    record = _json(store._bound(captured.reference))
    _require(type(record["report"]) is dict and record["report"].get("eligible") is True
             and type(record["report"].get("candidate")) is dict)
    return captured


def _harness(registry):
    return SourceAdmission(NativeState(registry, executor_record()))


def apply(registry, runner, preparation, backup_dataset, confirm):
    """Production entry; currently refused by the intentionally empty catalog."""
    _admit()
    return acceptance_apply(registry, runner, preparation, backup_dataset, confirm)


def acceptance_apply(registry, runner, preparation, backup_dataset, confirm):
    """Approved disposable harness only; fixed admission and actual consent."""
    _require(callable(confirm))
    export._name(backup_dataset)
    store = Store(registry.root)
    captured = load_candidate(store, preparation)
    parent = store.reference("maintenance/operations/" + preparation + "/operation.json")
    with native.acceptance_session(registry, runner, harness=_harness(registry),
                                   preparation=parent, candidate=captured) as n:
        return _execute(n, captured, backup_dataset, confirm)


def _export(n, backup_dataset):
    """Keep the export receipt DOCUMENT separate from its local StoreRef."""
    raw = export.export(n, backup_dataset)
    _fields(raw, "root path sha256 size")
    # Retain immediately, including when verification/rehearsal subsequently fails.
    receipt = n.record("execution-export-receipt", raw)
    verified = export.verify(n, raw)
    _require(verified["evidencecopyverified"] is True and verified["receipt"] == raw)
    n.record("execution-export-verified", verified)
    rehearsed = export.rehearse(n, raw)
    _require(rehearsed["evidencecopyverified"] is True and rehearsed["restorestream_rehearsal"] is True
             and rehearsed["receipt"] == raw)
    rehearsal = n.record("execution-export-rehearsed", rehearsed)
    n.record("execution-export-complete", dict(receipt=receipt, rehearsal=rehearsal))
    return receipt


def _copy_receipt(n):
    completed = _json(n.store._read(n.directory + "/execution-export-complete.json"))
    _fields(completed, "receipt rehearsal")
    receipt = completed["receipt"]
    _require(receipt == n.store.reference(n.directory + "/execution-export-receipt.json"))
    raw = _json(n.store._bound(receipt))
    _fields(raw, "root path sha256 size")
    rehearsal = _json(n.store._bound(completed["rehearsal"]))
    _require(rehearsal["receipt"] == raw and rehearsal["restorestream_rehearsal"] is True
             and rehearsal["evidencecopyverified"] is True)
    return receipt


def _execute(n, captured, backup_dataset, confirm):
    _, inputs, journal = n.check()
    _require(journal["phase"] == "capture" and captured.operation == inputs["cache_owner"])
    _require(_json(n.store._read(n.directory + "/candidate-reference.json")) == captured.reference)
    root = n.d.jail_root(n.c.nextcloud_jail) / update.STAGING.lstrip("/") / captured.operation
    # Prepare authenticates these bytes again and stages under the NEW owner.
    prepared = patch.prepare(n, **{key: root / name for key, name in ARTIFACTS.items()},
                             runner=bounded_process.run, memory_mib=n.c.php_memory_mb)
    n.quiesce(_answer(confirm, n.offline_phrase()))
    n.capture()
    _export(n, backup_dataset)
    n.migrate(patch.NextcloudPatch(prepared, runner=bounded_process.run))
    journal = n.journal.read()
    n.journal.advance("validating", dict(closure=journal["evidence"]["closure"], validation_permission=n.profile()))
    return _validate_target(n)


def _successor_evidence(n, generation, files, effective):
    """Project real captured manifests AND current closed target observations."""
    intent, inputs, journal = n.check(closed=True)
    _require(journal["phase"] == "validating")
    retained = _json(n.store._read(n.directory + "/candidate-reference.json"))
    _fields(retained, "path sha256")
    _require(retained["path"] == "maintenance/operations/" + inputs["cache_owner"] + "/candidate.json")
    capture = _json(n.store._bound(retained))
    _require(capture["preparation"] == inputs["preparation"] and capture["recipe"] == inputs["recipe"])
    candidate = capture["report"]["candidate"]
    predecessor = inputs["entries"][n.c.instance]["generation"]
    previous = n.store._generation(n.c.instance, predecessor)
    original = n.store._bound(previous["config"])
    plan = _json(n.store._bound(previous["versions"]))
    bindings = generations.inspection_bindings(n.store, predecessor, intent, inputs, original, plan)
    generations._candidate(candidate, bindings, plan)
    for key in ("observations", "repository"):
        _require(capture[key + "_sha256"] == candidate[key + "_sha256"] == preflight.digest(capture[key]))
    # This verifies actual hardened code against the authenticated target inventory,
    # completed updater effect chain, and the never-replay migration step.
    prepared, context, inventory, _, _ = validation._code(n, True)
    package_ref = validation._packages(n, plan, prepared)
    packages = _json(n.store._bound(package_ref))
    result = _json(n.store._read(n.directory + "/update-result.json"))
    _require(packages == result["runtime"]["full_packages"])
    status = validation._status(n, update.TARGET[1], True)
    _require(status.get("versionstring") == update.TARGET[0])
    apps = _json(n.backend.occ("app:list", "--output=json"))
    _fields(apps, "enabled disabled")
    _require(all(type(value) is dict for value in apps.values()) and not set(apps["enabled"]) & set(apps["disabled"]))
    patch._apps(context, inventory, apps)
    _require(apps == result["runtime"]["apps"])
    observed_apps = {**apps["enabled"], **apps["disabled"]}
    _require(observed_apps == {name: item["version"] for name, item in candidate["apps"].items()})
    hashes = {name: _hash(data) for name, data in files.items()}
    review = dict(schema_version=1, kind="nextcloud-successor-review", operation=n.operation, instance=n.c.instance,
        predecessor=predecessor, intent=n.journal.reference, recipe_sha256=inputs["recipe_sha256"],
        original_config_sha256=_hash(original), target_files=hashes, candidate_sha256=_hash(_encode(candidate)))
    readiness = dict(schema_version=1, kind="nextcloud-successor-readiness", operation=n.operation, instance=n.c.instance,
        config_sha256=hashes["config.json"], versions_sha256=hashes["versions.json"],
        nextcloud={key: status[key] for key in ("installed", "maintenance", "needsDbUpgrade", "version", "versionstring")},
        packages_sha256=preflight.digest(plan["packages"]), apps=observed_apps)
    n.record("execution-target-observations-" + _hash(_encode(readiness)), dict(
        candidate=retained, packages=package_ref, result=n.store.reference(n.directory + "/update-result.json"),
        status=status, apps=apps))
    n.check(closed=True)
    return {"candidate.json": _encode(candidate), "review.json": _encode(review),
            "effective.json": n.store._bound(effective), "readiness.json": _encode(readiness)}


def reconcile_descriptor(n, generation, *, restored=False):
    """Durable exact old/new descriptor transition; never move the active graph.

    Recovery accepts a successor descriptor only when THIS operation retained its
    exact before-write plan. Original deployment/config/source archives are inert.
    """
    intent, inputs = n.native.read(n.operation)
    n.registry._require_lock(recovery=True)
    journal = n.journal.read()
    _require(not journal["publication_may_have_begun"] and not journal["recovery_publication_may_have_begun"])
    _require(journal["phase"] in (("restored-closed", "recovery-validating") if restored else ("validating", "committed-closed")))
    name = inputs["instance"]
    original = inputs["entries"][name]["generation"]
    old = descriptor(name, original)
    new = descriptor(name, generation)
    path = "instances/" + name + "/config.json"
    forward_path = n.directory + "/descriptor-successor-before.json"
    if restored:
        _require(generation == original)
        if n.store._present(forward_path):
            forward = _json(n.store._read(forward_path))
            _fields(forward, "schema_version kind intent instance original expected")
            _schema(forward)
            _require(forward == dict(schema_version=1, kind="maintenance-registration-transition", intent=n.journal.reference,
                instance=name, original=old, expected=forward["expected"]))
            target = forward["expected"]["generation"]
            manifest = n.store._generation(name, target)
            _require(manifest["operation"] == n.operation and manifest["predecessor"] == original)
            _require(forward["expected"] == descriptor(name, target))
            old = forward["expected"]
        label = "descriptor-original"
    else:
        manifest = n.store._generation(name, generation)
        _require(manifest["operation"] == n.operation and manifest["predecessor"] == original
                 and manifest["intent"] == n.journal.reference)
        label = "descriptor-successor"
    expected = dict(schema_version=1, kind="maintenance-registration-transition", intent=n.journal.reference,
                    instance=name, original=old, expected=new)
    before = n.directory + "/" + label + "-before.json"
    retry = n.store._present(before)
    if retry:
        _require(_json(n.store._read(before)) == expected)
    current = n.store._read(path)
    # Recovery can encounter untouched original bytes even after a forward plan.
    allowed = (old, new) if retry or restored else (old,)
    _require(current in tuple(_encode(value) for value in allowed))
    reference = n.record(label + "-before", expected)
    if current != _encode(new):
        n.store._put(path, new, replace=True)
    _require(_json(n.store._read(path)) == new)
    return n.record(label + "-after", dict(before=reference, descriptor=n.store.reference(path)))


def _publish(n, generation, *, restored=False):
    publication = Publication(n, validator=validation.FixedValidator(), copies=validation.RecoveryCopyVerifier())
    receipt = _copy_receipt(n)
    manifest = n.journal.read()["evidence"]["recovery_set"]
    verified = publication.copies.validate(n, manifest, receipt)
    readiness = publication.validate_closed(generation, copy_receipt=receipt, copy_validation=verified)
    reconcile_descriptor(n, generation, restored=restored)
    commitment = publication.commit_closed(readiness)
    return _summary(n, publication.open(commitment))


def _validate_target(n):
    _require(n.journal.read()["phase"] == "validating")
    validation.stage_target_runtime(n)
    n.validate_closed(expected_version=update.TARGET[1])
    _, inputs = n.native.read(n.operation)
    previous = n.store._generation(n.c.instance, inputs["entries"][n.c.instance]["generation"])
    files = generations.proposed_files(n.store._bound(previous["config"]), _json(n.store._bound(previous["versions"])))
    generation = "patch-" + _hash(_encode([n.operation, inputs["recipe_sha256"]]))[:48]
    n.record("execution-generation", dict(generation=generation))
    effective = validation.effective_runtime_receipt(n, generation)
    evidence = _successor_evidence(n, generation, files, effective)
    reference = generations.seal_successor(n.native, n.operation, generation, target_files=files,
        validation_evidence=evidence, recover=n.store._present("instances/" + n.c.instance + "/generations/" + generation))
    n.record("execution-successor", dict(generation=reference))
    return _publish(n, reference)


def _summary(n, result):
    _require(result.get("state") in ("complete", "recovered", "cancelled") and result.get("ready") is True)
    return dict(operation=n.operation, instance=n.c.instance, state=result["state"], ready=True,
                native_acceptance="not-run", machine_drain_verified=False, unsaved_editor_work_covered=False)


def continue_execution(registry, runner, operation, confirm):
    _admit()
    return acceptance_continue(registry, runner, operation, confirm)


def acceptance_continue(registry, runner, operation, confirm):
    """Resume validation/forward publication only; never replay uncertain migration."""
    _id(operation)
    store = Store(registry.root)
    from .maintenance_journal import native_validate
    journal = native_validate(_json(store._read("maintenance/operations/" + operation + "/native-journal.json")))
    if journal["publication_may_have_begun"] or journal["recovery_publication_may_have_begun"]:
        from .maintenance_opening import publication_session
        with publication_session(registry, runner, operation) as publication:
            phrase = "CONTINUE-PUBLICATION " + operation
            result = publication.continue_publication(_answer(confirm, phrase))
            return _summary(publication.context, result)
    _answer(confirm, "CONTINUE-MAINTENANCE " + operation)
    with native.acceptance_session(registry, runner, harness=_harness(registry), operation=operation) as n:
        phase = n.journal.read()["phase"]
        if phase == "migrating":
            journal = n.journal.read()
            step = journal["steps"].get("reviewed-migration", {})
            _require(step.get("state") == "complete" and step.get("replay") == "never"
                     and step.get("attempts") == 1 and step.get("observation") ==
                     n.store.reference(n.directory + "/update-result.json"))
            n.journal.advance("validating", dict(closure=journal["evidence"]["closure"], validation_permission=n.profile()))
            phase = "validating"
        if phase == "validating":
            return _validate_target(n)
        if phase == "committed-closed":
            commitment = n.store.reference(n.directory + "/publication-commit-validated-closed.json")
            return _summary(n, Publication(n).open(commitment))
        if phase in ("restored-closed", "recovery-validating"):
            return _validate_original(n)
        raise ValueError("Maintenance continuation requires closed validation or forward publication; updater replay is forbidden")


def restore_original(registry, runner, operation, confirm):
    _admit()
    return acceptance_restore(registry, runner, operation, confirm)


def cancel_execution(registry, runner, operation, confirm):
    """Original-source cancellation only; production acceptance remains mandatory."""
    _admit()
    return acceptance_cancel(registry, runner, operation, confirm)


def acceptance_cancel(registry, runner, operation, confirm):
    """Trusted disposable harness: no snapshot rollback or updater replay."""
    from .maintenance_cancellation import cancel
    _id(operation)
    with native.acceptance_session(registry, runner, harness=_harness(registry), operation=operation) as n:
        result = cancel(n, _answer(confirm, "CANCEL-MAINTENANCE " + operation))
        return _summary(n, result)


def _validate_original(n):
    _, inputs = n.native.read(n.operation)
    original = inputs["entries"][n.c.instance]["generation"]
    reconcile_descriptor(n, original, restored=True)
    n.validate_closed(expected_version=update.SOURCE[1])
    return _publish(n, original, restored=True)


def acceptance_restore(registry, runner, operation, confirm):
    """Explicit original-set restore; never retry rollback after validation writes."""
    _id(operation)
    _require(callable(confirm))
    with native.acceptance_session(registry, runner, harness=_harness(registry), operation=operation) as n:
        journal = n.journal.read()
        _require(not journal["publication_may_have_begun"] and not journal["recovery_publication_may_have_begun"])
        phase = journal["last_safe_phase"] if journal["phase"] == "recovery-required" else journal["phase"]
        _require(phase not in ("restored-closed", "recovery-validating", "recovery-opening", "recovered"))
        assess = getattr(n, "assess_original_restore", None)
        restore = getattr(n, "restore_original", None)
        _require(callable(assess) and callable(restore))
        answer = _answer(confirm, "RESTORE-ORIGINAL " + operation + " DISCARD-CLOSED-CHANGES")
        if n.backend.pair_state() != "stopped":
            n.close_for_original_restore(answer)
    # Reopen after reclosure: no stale runtime/JID/boot proof survives this boundary.
    with native.acceptance_session(registry, runner, harness=_harness(registry), operation=operation) as n:
        assessment = n.assess_original_restore()
        _require(assessment.eligible)
        n.restore_original(answer, assessment=assessment)
        return _validate_original(n)
