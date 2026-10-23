"""Internal closed validation and forward-only publication, never CLI authority.

The native catalog remains empty. Trusted Python adapters must actually inspect
code/integrity, packages, effective public workers, OPcache restart, cache and
connector operation, and independently reverify the recovery copy. JSON receipts
alone cannot create readiness. Native acceptance has NOT RUN.

Runtime reconciliation belongs to the parent recipe, before validation: stage
only the exact successor public runtime/worker hashes, retain original metadata,
restart FPM after code replacement, and validate the effective generation. The
post-open adapter must use read-only, generation-aware verification (no staging).
Explicit publication continuation grants separately locked, operation-bound boot
permission after reboot. There is no rollback after the opening marker.
"""

from abc import ABC, abstractmethod
from copy import deepcopy
import json

from . import maintenance_fence as fence, recovery_sets as recovery
from .generations import _encode, _fields, _hash, _json, _reference
from .maintenance_journal import native_validate
from .maintenance_native import NativeContext, SERVICES


DENIED = "Maintenance publication refused; retain private evidence and the pending operation"
CLOSED_CHECKS = frozenset(("code", "integrity", "runtime", "packages", "fpm_restart", "cache", "connector"))
OPEN_CHECKS = frozenset(("deployment", "runtime", "packages", "cache", "connector"))
STEPS = ("maintenance-off", "original-profile", "application-services", "public-status", "scheduled-services", "post-open")


def _require(value):
    if not value:
        raise ValueError(DENIED)


class PublicationBlocked(ValueError):
    """Fixed prerequisite identifier, never native output or secret diagnostics."""

    def __init__(self, blocker):
        self.blocker = blocker
        super().__init__(DENIED + ": " + blocker)


class Validator(ABC):
    """Fixed trusted implementation, never imported from a document or path.

    Each method raises on failure and returns exactly the named operation-local
    private evidence references. closed must recheck actual code and effective
    workers against generation before executing application PHP, verify recorded
    occ integrity, and prove FPM was
    restarted AFTER that code was installed. Cache/connector checks use the
    parent's phase-specific secret stdin channel. No ready boolean is accepted.
    post_open must perform full read-only generation-aware integration checks;
    NativeContext.check is deliberately unavailable after the opening marker.
    """

    @abstractmethod
    def descriptor(self):
        """Exact source-bound native recipe descriptor."""

    @abstractmethod
    def closed(self, context, generation):
        """Return CLOSED_CHECKS references after live closed validation."""

    @abstractmethod
    def post_open(self, context, generation):
        """Return OPEN_CHECKS references after live public verification."""


class CopyVerifier(ABC):
    """Trusted backend adapter; metadata equality is not independent-copy proof."""

    @abstractmethod
    def recheck(self, context, manifest, receipt, validation):
        """Reverify local snapshot GUIDs and independent bytes/backend identities.

        Validate receipt AND validation proof against this manifest, including
        every stream and private evidence member. Return an operation-local ref
        to {manifest, receipt, validation, datasets, snapshots, evidence_files},
        with exact integer counts. No boolean or cached success is sufficient.
        This seam adapts the independent-copy module's strict native verifier.
        """


class _Readiness:
    def __init__(self, owner, reference):
        self.owner, self.reference = owner, reference


class Publication:
    """Lock-scoped publication for one existing NativeContext and fixed adapters."""

    def __init__(self, context, *, validator=None, copies=None):
        if validator is None or copies is None:
            from .maintenance_validation import FixedValidator, RecoveryCopyVerifier
            validator = FixedValidator() if validator is None else validator
            copies = RecoveryCopyVerifier() if copies is None else copies
        _require(isinstance(context, NativeContext) and isinstance(validator, Validator)
                 and isinstance(copies, CopyVerifier))
        self.context, self.validator, self.copies = context, validator, copies
        self.store = context.store

    def _local(self, reference):
        _reference(reference)
        _require(reference["path"].startswith(self.context.directory + "/"))
        return self.store._bound(reference)

    def _checks(self, value, names):
        _require(type(value) is dict and set(value) == names)
        for reference in value.values():
            self._local(reference)
        return value

    def _readiness(self, reference):
        value = _json(self._local(reference))
        _fields(value, "schema_version kind intent generation recovering version status checks independent_copy original_services journal graph boot jids")
        _require(type(value["schema_version"]) is int and value["schema_version"] == 1
                 and value["kind"] == "native-closed-readiness" and type(value["recovering"]) is bool
                 and value["version"] == ("35.0.1.1" if value["recovering"] else "35.0.2.2")
                 and value["intent"] == self.context.journal.reference)
        self._checks(value["checks"], CLOSED_CHECKS)
        self._local(value["independent_copy"])
        _require(value["original_services"] == self._original_services()[0])
        return value

    def _validation(self, generation, *, opened=False):
        try:
            callback = self.validator.post_open if opened else self.validator.closed
            return self._checks(callback(self.context, generation), OPEN_CHECKS if opened else CLOSED_CHECKS)
        except PublicationBlocked:
            raise
        except Exception:
            raise ValueError(DENIED) from None

    def _generation(self, inputs, generation, recovering):
        n = self.context
        original = inputs["entries"][n.c.instance]["generation"]
        manifest = self.store._generation(n.c.instance, generation)
        if recovering:
            _require(generation == original)
        else:
            from .maintenance_generations import validate_generation
            validate_generation(self.store, n.c.instance, generation, manifest)
            _require(manifest["predecessor"] == original and manifest["operation"] == n.operation
                     and manifest["intent"] == self.store.reference(n.directory + "/intent.json"))
        return manifest

    def _original_services(self):
        n = self.context
        ref = self.store.reference(n.directory + "/original-services.json")
        value = _json(self.store._bound(ref))
        _fields(value, "pair services")
        expected = {n.c.nextcloud_jail: SERVICES["nextcloud"], n.c.onlyoffice_jail: SERVICES["onlyoffice"]}
        _require(value["pair"] == {jail: "running" for jail in expected}
                 and type(value["services"]) is dict and set(value["services"]) == set(expected))
        for jail, services in expected.items():
            _require(type(value["services"][jail]) is dict and set(value["services"][jail]) == set(services)
                     and all(type(v) is bool for v in value["services"][jail].values()))
        # Public readiness cannot coexist with preserving a stopped web frontend.
        _require(value["services"][n.c.nextcloud_jail]["apache24"])
        return ref, value["services"]

    def _status(self, version, maintenance):
        value = json.loads(self.context.backend.occ("status", "--output=json"))
        _require(type(value) is dict and value.get("installed") is True
                 and value.get("maintenance") is maintenance and value.get("needsDbUpgrade") is False
                 and value.get("version") == version)
        return value

    def _copy(self, manifest, receipt, validation):
        n = self.context
        self.store._bound(receipt)
        self.store._bound(validation)
        rc = n._recovery_context(readonly=True)
        value = recovery.validate_manifest(rc, _json(self.store._bound(manifest)))
        try:
            reference = self.copies.recheck(n, manifest, receipt, validation)
        except PublicationBlocked:
            raise
        except Exception:
            raise ValueError(DENIED) from None
        observed = _json(self._local(reference))
        expected = dict(manifest=manifest, receipt=receipt, validation=validation,
                        datasets=len(value["datasets"]), snapshots=len(value["snapshots"]),
                        evidence_files=len(value["evidence"]))
        _require(_encode(observed) == _encode(expected))
        return reference

    def validate_closed(self, generation, *, copy_receipt, copy_validation):
        """Mint context-local readiness only after all mandatory live checks."""
        n = self.context
        intent, inputs, journal = n.check(closed=True)
        _require(journal["phase"] in ("validating", "recovery-validating")
                 and self.validator.descriptor() == inputs["recipe"]
                 and all(step["state"] in ("complete", "superseded") for step in journal["steps"].values()))
        recovering = journal["phase"] == "recovery-validating"
        self._generation(inputs, generation, recovering)
        original, _ = self._original_services()
        n.backend.owned_live()
        n.backend.closed_flags()
        n.backend.deny_probe()
        for jail in (n.c.nextcloud_jail, n.c.onlyoffice_jail):
            _require(not n.backend.running(jail, "cron") and not n.backend.running(jail, "sshd"))
        version = "35.0.1.1" if recovering else "35.0.2.2"
        checks = self._validation(generation)
        status = self._status(version, True)
        copy = self._copy(journal["evidence"]["recovery_set"], copy_receipt, copy_validation)
        n.check(closed=True)
        _require(n.journal.read() == journal)
        if recovering:
            step = journal["steps"].get("data-fingerprint")
            _require(step is not None and step["state"] == "complete")
        value = dict(schema_version=1, kind="native-closed-readiness", intent=n.journal.reference,
                     generation=generation, recovering=recovering, version=version, status=status,
                     checks=checks, independent_copy=copy, original_services=original,
                     journal=self.store.reference(n.journal.path), graph=self.store._active(),
                     boot=n.backend.output("sysctl", "-n", "kern.boottime"),
                     jids={jail: n.d.require_running_jail(jail) for jail in (n.c.nextcloud_jail, n.c.onlyoffice_jail)})
        reference = n.record("closed-readiness-" + _hash(_encode(value)), value)
        return _Readiness(self, reference)

    def commit_closed(self, readiness):
        """Commit exact successor/original entries, never change shared PF policy."""
        _require(type(readiness) is _Readiness and readiness.owner is self)
        n = self.context
        intent, inputs, journal = n.check(closed=True)
        proof = self._readiness(readiness.reference)
        stage = "restored-closed" if proof["recovering"] else "validated-closed"
        step_path = n.directory + "/" + stage + ".json"
        recorded_graph = (_json(self.store._read(step_path))["graph"] if self.store._present(step_path) else None)
        _require(proof["journal"] == self.store.reference(n.journal.path)
                 and self.store._active() in (proof["graph"], recorded_graph))
        self._generation(inputs, proof["generation"], proof["recovering"])
        self._live(proof)
        self._validation(proof["generation"])
        self._status(proof["version"], True)
        copied = _json(self._local(proof["independent_copy"]))
        self._copy(copied["manifest"], copied["receipt"], copied["validation"])
        _require(n.check(closed=True)[2] == journal
                 and all(step["state"] in ("complete", "superseded") for step in journal["steps"].values()))
        entries = deepcopy(inputs["entries"])
        entries[n.c.instance]["generation"] = proof["generation"]
        selection_path = n.directory + "/publication-selection-" + stage + ".json"
        selected = readiness.reference
        if self.store._present(selection_path):
            selection = _json(self.store._read(selection_path))
            _fields(selection, "readiness")
            selected = selection["readiness"]
            previous = self._readiness(selected)
            _require(all(previous[key] == proof[key] for key in ("generation", "recovering", "original_services", "boot", "jids")))
        else:
            n.record("publication-selection-" + stage, dict(readiness=selected))
        predecessor = intent["base_graph"]
        target = n.directory + "/validated-closed.json"
        if proof["recovering"] and self.store._present(target):
            predecessor = _json(self.store._read(target))["graph"]
        # Deterministic identity lets an interrupted graph write retry exact bytes.
        graph_id = "publication-" + _hash(_encode([n.operation, stage]))[:48]
        graph = n.native.commit_closed(n.operation, stage, graph_id, entries,
                                       expected_predecessor=predecessor)
        network = n.record("publication-network", inputs["network"])
        commitment = n.record("publication-commit-" + stage, dict(readiness=selected,
            graph=graph, network=network, closure=journal["evidence"]["closure"]))
        if not proof["recovering"]:
            n.journal.advance("committed-closed", _json(self._local(commitment)))
        return commitment

    def _live(self, proof):
        n = self.context
        from .maintenance_opening import current_identity
        identity = current_identity(n, proof)
        _require(n.backend.pair_state() == "running"
                 and n.backend.output("sysctl", "-n", "kern.boottime") == identity["boot"])
        n.backend.owned_live()
        _require({jail: n.d.require_running_jail(jail) for jail in identity["jids"]} == identity["jids"])

    def _publication_context(self):
        """Exact opening metadata/locks/PF; also usable before either jail starts."""
        from .enrollment_start import _held
        from .host import verify_managed_network
        from .maintenance_operations import _network_binding
        n = self.context
        _require(n.active)
        n.registry._require_lock(recovery=True)
        _held(self.store, f"instances/{n.c.instance}/database-operation.lock")
        intent, inputs = n.native.read(n.operation)
        journal = n.journal.read()
        _require(self.validator.descriptor() == inputs["recipe"] and self.store.pending() == intent
                 and journal["phase"] in ("opening", "recovery-opening", "complete", "recovered"))
        _require(_network_binding(self.store) == inputs["network"])
        verify_managed_network(n.d.registry, n.backend.runner)
        n.d.require_original_artifact()
        proof = self._readiness(journal["evidence"]["readiness"])
        _require(journal["phase"] in (("recovery-opening", "recovered") if proof["recovering"] else ("opening", "complete")))
        _require(journal["recovery_publication_may_have_begun" if proof["recovering"] else "publication_may_have_begun"])
        _require(proof["intent"] == n.journal.reference and self.store._active() == journal["evidence"]["graph"]
                 and _json(self._local(journal["evidence"]["network"])) == inputs["network"])
        self._generation(inputs, proof["generation"], proof["recovering"])
        stage = "restored-closed" if proof["recovering"] else "validated-closed"
        _require(_json(self.store._read(n.directory + "/" + stage + ".json"))["graph"] == self.store._active())
        graph = _json(self.store._bound(self.store._active()))
        _require(graph["instances"][n.c.instance]["generation"] == proof["generation"])
        return journal, proof

    def check_publication(self):
        """Narrow opening check; never weaken NativeContext.check for other work."""
        journal, proof = self._publication_context()
        self._live(proof)
        return journal, proof

    def continue_publication(self, confirmation):
        """Explicit reboot/partial-start continuation, then ordinary forward open."""
        return self.open(confirmation=confirmation)

    def _mark(self, commitment):
        n = self.context
        _, inputs, journal = n.check(closed=True)
        value = _json(self._local(commitment))
        _fields(value, "readiness graph network closure")
        proof = self._readiness(value["readiness"])
        stage = "restored-closed" if proof["recovering"] else "validated-closed"
        _require(commitment == self.store.reference(n.directory + "/publication-commit-" + stage + ".json"))
        _require(self.validator.descriptor() == inputs["recipe"] and value["graph"] == self.store._active()
                 and journal["phase"] == ("recovery-validating" if proof["recovering"] else "committed-closed"))
        self._live(proof)
        self._validation(proof["generation"])
        self._status(proof["version"], True)
        copied = _json(self._local(proof["independent_copy"]))
        self._copy(copied["manifest"], copied["receipt"], copied["validation"])
        self._original_services()
        n.backend.deny_probe()
        for jail in proof["jids"]:
            _require(not n.backend.running(jail, "cron") and not n.backend.running(jail, "sshd"))
        suffix = "original" if proof["recovering"] else "target"
        writers = n.record("publication-writers-stopped-" + suffix, dict(readiness=value["readiness"], services=["cron", "sshd"]))
        authorization = n.record("publication-authorized-" + suffix, dict(commitment=commitment, original_services=proof["original_services"]))
        _require(n.check(closed=True)[2] == journal)
        evidence = dict(value)
        if proof["recovering"]:
            evidence.update(post_restore=value["readiness"], fingerprint=journal["steps"]["data-fingerprint"]["observation"])
        phase = "recovery-opening" if proof["recovering"] else "opening"
        n.journal.advance(phase, evidence)  # MUST precede maintenance-off/files/services.
        return writers, authorization

    def _publication_record(self, journal):
        n = self.context
        # Do not advance NativeJournal until restore_profile finishes: fence binds
        # this exact current hash. Its own progress journal handles partial files.
        raw = self.store._read(n.journal.path)
        n.record("opening-journal", native_validate(_json(raw)))
        suffix = "original" if journal["phase"] == "recovery-opening" else "target"
        value = dict(schema_version=1, kind="native-publication-proof", intent=n.journal.reference,
                     profile=n.profile(), phase=journal["phase"], journal=self.store.reference(n.journal.path),
                     markers=dict(closed_validation=journal["evidence"]["readiness"],
                 writers_stopped=self.store.reference(n.directory + "/publication-writers-stopped-" + suffix + ".json"),
                 publication_authorized=self.store.reference(n.directory + "/publication-authorized-" + suffix + ".json")))
        return n.record("native-publication", value)

    def _public_status(self, version):
        """Host-direct frontend check, not external ingress/browser acceptance.

        Preserve the configured HTTPS authority/SNI/certificate and public port,
        while avoiding host self-rdr/router hairpin requirements. The same host
        connection is denied by the closed vhost before explicit publication.
        """
        n = self.context
        _require(n.c.tls_mode != "external")
        ca = ("--cacert", n.c.ca_file) if n.c.ca_file else ()
        result = n.backend.runner.run("curl", "--silent", "--show-error", "--fail", "--noproxy", "*", *ca,
            "--connect-to", f"{n.c.public_hostname}:{n.c.public_https_port}:{n.c.nextcloud_ip}:443",
            "--max-time", "20", n.c.public_url.rstrip("/") + "/status.php", hide_output=True, timeout=25)
        _require(result.returncode == 0 and type(result.stdout) is str and len(result.stdout) <= 4096)
        value = json.loads(result.stdout)
        _require(type(value) is dict and value.get("installed") is True and value.get("maintenance") is False
                 and value.get("needsDbUpgrade") is False and value.get("version") == version)
        return value

    def _services(self, original, *, scheduled):
        n = self.context
        order = ((n.c.nextcloud_jail, ("mysql-server", "redis", "php_fpm")),
                 (n.c.onlyoffice_jail, ("supervisord", "nginx")), (n.c.nextcloud_jail, ("apache24",)))
        if scheduled:
            order = tuple((jail, ("cron", "sshd")) for jail in original)
        for jail, services in order:
            for service in services:
                self.check_publication()
                if not original[jail][service]:
                    n.backend.stop(jail, service)
                elif not n.backend.running(jail, service):
                    n.backend.jailed(jail, "service", service, "onestart")
                elif service == "apache24":
                    n.backend.jailed(jail, "/usr/local/sbin/apachectl", "configtest")
                    n.backend.jailed(jail, "/usr/local/sbin/apachectl", "-k", "graceful")
                _require(bool(n.backend.running(jail, service)) == original[jail][service])

    def _progress(self, publication):
        from .maintenance_opening import progress_path
        path = progress_path(self.context)
        value = dict(schema_version=1, publication=publication, completed=[], running=None, evidence={})
        if self.store._present(path):
            value = _json(self.store._read(path))
            _fields(value, "schema_version publication completed running evidence")
            _require(type(value["completed"]) is list and type(value["evidence"]) is dict)
            count = len(value["completed"])
            _require(type(value["schema_version"]) is int and value["schema_version"] == 1
                     and value["publication"] == publication and value["completed"] == list(STEPS[:count])
                     and count <= len(STEPS) and set(value["evidence"]) == set(value["completed"])
                     and value["running"] in (None, STEPS[count] if count < len(STEPS) else None))
            for reference in value["evidence"].values():
                self._local(reference)
        return value

    def open(self, commitment=None, *, confirmation=None):
        """Start or continue opening; every effect is forward-only and idempotent.

        Keep the native opening checkpoint unchanged across failures. A separate
        strict progress record retains an interrupted step, rather than discarding
        uncertainty or asking NativeJournal to replay a destructive operation.
        """
        n = self.context
        try:
            if confirmation is not None:
                from .maintenance_opening import continue_publication
                continue_publication(self, confirmation)
            phase = n.journal.read()["phase"]
            if phase not in ("opening", "recovery-opening", "complete", "recovered"):
                _require(commitment is not None)
                self._mark(commitment)
            journal, proof = self.check_publication()
            _, original = self._original_services()
            from .maintenance_opening import progress_path as opening_progress_path
            progress_path = opening_progress_path(n)
            terminal_pending = journal["phase"] in ("complete", "recovered")
            if terminal_pending:
                from .maintenance_opening import terminal_binding
                terminal_binding(self.store, n.directory)
                publication = self.store.reference(n.directory + "/native-publication.json")
            else:
                publication = self._publication_record(journal)
            progress = self._progress(publication)
            for step in STEPS[len(progress["completed"]):]:
                self.check_publication()
                if step in STEPS[:4]:
                    for jail in original:
                        _require(not n.backend.running(jail, "cron") and not n.backend.running(jail, "sshd"))
                progress["running"] = step
                self.store._put(progress_path, progress, replace=self.store._present(progress_path))
                if step == "maintenance-off":
                    n.backend.occ("maintenance:mode", "--off")
                    observation = self._status(proof["version"], False)
                elif step == "original-profile":
                    fence.publication_profile(n.registry, n.profile(), publication=publication)
                    observation = dict(profile=n.profile())
                elif step in ("application-services", "scheduled-services"):
                    if step == "scheduled-services":
                        fence.publication_profile(n.registry, n.profile(), publication=publication,
                                                  progress=self.store.reference(progress_path))
                    self._services(original, scheduled=step == "scheduled-services")
                    observation = dict(services=n.backend.service_states())
                elif step == "public-status":
                    observation = self._public_status(proof["version"])
                else:
                    observation = self._validation(proof["generation"], opened=True)
                reference = n.record("opened-" + step + "-" + _hash(_encode(observation)), observation)
                progress["completed"].append(step)
                progress["evidence"][step] = reference
                progress["running"] = None
                self.store._put(progress_path, progress, replace=True)
            return self._finish(n.journal.read(), proof, original)
        except PublicationBlocked:
            raise
        except Exception:
            # No native.fail(): it would invalidate fence's exact opening hash and
            # prohibit safe idempotent continuation. The running step is durable.
            raise ValueError(DENIED) from None

    def _finish(self, journal, proof, original):
        n = self.context
        self.check_publication()
        publication = self.store.reference(n.directory + "/native-publication.json")
        published = _json(self._local(publication))
        _fields(published, "schema_version kind intent profile phase journal markers")
        opening = native_validate(_json(self.store._read(n.directory + "/opening-journal.json")))
        suffix = "original" if proof["recovering"] else "target"
        expected = dict(schema_version=1, kind="native-publication-proof", intent=n.journal.reference,
            profile=n.profile(), phase="recovery-opening" if proof["recovering"] else "opening",
            journal=dict(path=n.journal.path, sha256=_hash(_encode(opening))), markers=dict(
                closed_validation=journal["evidence"]["readiness"],
                 writers_stopped=self.store.reference(n.directory + "/publication-writers-stopped-" + suffix + ".json"),
                 publication_authorized=self.store.reference(n.directory + "/publication-authorized-" + suffix + ".json")))
        _require(_encode(published) == _encode(expected) and opening["phase"] == expected["phase"]
                 and opening["operation"] == n.journal.reference
                 and journal["history"][:len(opening["history"])] == opening["history"])
        progress = self._progress(publication)
        _require(progress["completed"] == list(STEPS) and progress["running"] is None)
        applied = _json(self.store._read(n.directory + "/profile-apply.json"))
        _require(_encode(applied) == _encode(dict(schema_version=1, profile=n.profile(), target="original",
                                                publication=publication, index=3, state="complete")))
        profile, _ = fence._profile(self.store, n.profile())
        fence._check_files(self.store, profile, "original")
        _require(n.backend.service_states() == original)
        status = self._public_status(proof["version"])
        self._status(proof["version"], False)
        checks = self._validation(proof["generation"], opened=True)
        consistency = dict(checks=checks, status=status, frontend_probe="host-direct-frontend",
                           external_ingress_verified=False, graph=self.store._active(), original_services=proof["original_services"])
        observation = n.record("public-consistency-" + _hash(_encode(consistency)), consistency)
        terminal = "recovered" if proof["recovering"] else "complete"
        if journal["phase"] != terminal:
            from .maintenance_journal import native_transition
            from .maintenance_opening import progress_path
            evidence = dict(post_open=progress["evidence"]["post-open"], consistency=observation)
            if self.store._present(n.directory + "/publication-finalization.json"):
                from .maintenance_opening import terminal_binding
                _, retained = terminal_binding(self.store, n.directory, prepared=True)
                evidence = retained["evidence"]
                final = retained["terminal"]
            else:
                final = native_transition(journal, terminal, evidence)
                # Seal the exact prospective terminal BEFORE advancing: a reboot at
                # either terminal write retains forward-only cleanup authority.
                n.record("publication-finalization", dict(schema_version=1, kind="native-publication-finalization",
                    intent=n.journal.reference, publication=publication,
                    opening=self.store.reference(n.directory + "/opening-journal.json"),
                    journal=dict(path=n.journal.path, sha256=_hash(_encode(final))), terminal=final, outcome=terminal,
                    graph=self.store._active(), progress=self.store.reference(progress_path(n)),
                    profile_apply=self.store.reference(n.directory + "/profile-apply.json"), evidence=evidence))
            # The normal bound writer validates the already sealed transition;
            # regenerating it would select a different wall-clock timestamp.
            n.journal._write(final)
        from .maintenance_opening import terminal_binding
        terminal_binding(self.store, n.directory)
        n.journal.terminal()
        n.native.finish(n.operation, terminal)
        return dict(state=terminal, ready=True, machine_drain_verified=False, unsaved_editor_work_covered=False,
                    restore_rehearsal_verified=False, frontend_probe="host-direct-frontend", external_ingress_verified=False)


def publication_session(registry, runner, operation):
    """Opening-only session; yields Publication under the host/database locks."""
    from .maintenance_opening import publication_session as session
    return session(registry, runner, operation)
