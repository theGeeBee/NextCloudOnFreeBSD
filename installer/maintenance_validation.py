"""Fixed NC 35.0.1 -> 35.0.2 observations; no catalog or CLI admission.

Call stage_target_runtime explicitly after migration, under the closed profile.
It changes only the five public runtime files in each jail. Helper/code changes,
generation sealing/descriptors and opening-session authority belong to the parent.
No deployment provisioning, package operation, cron start or manifest save occurs
here. Connector canaries write application state only inside the operator-approved
offline contract; they are not a proof that unsaved editors drained.
"""

from copy import deepcopy
from dataclasses import asdict
import json
from pathlib import Path
import re
from types import SimpleNamespace
import uuid

from . import maintenance_fence as fence, maintenance_generations as generations
from . import maintenance_preflight as policy, maintenance_update as patch
from . import nextcloud_update as update, recovery_sets as recovery
from .config import Config
from .deploy import Deployment
from .generations import _encode, _fields, _hash, _id, _json
from .maintenance_publication import Validator, CopyVerifier, PublicationBlocked
from .runtime_inventory import collect_php
from .versions import load_policy, package_upstream


ROOT_GID = 0


def _require(value, blocker="validation-binding-or-observation-drift"):
    if not value:
        raise PublicationBlocked(blocker)


def _record(n, name, value):
    return n.record(name + "-" + _hash(_encode(value)), value)


def _original(n, inputs):
    files = inputs["originals"][n.c.instance]["files"]
    raw = n.store._bound(files["config.json"]["retained"])
    retained = _json(n.store._bound(files["versions.json"]["retained"]))
    return raw, retained


def _payloads(n, inputs, target):
    raw, retained = _original(n, inputs)
    proposed = generations.proposed_files(raw, retained)
    config = generations.target_configuration(raw) if target else Config.from_json(raw.decode())
    plan = _json(proposed["versions.json"]) if target else retained
    return proposed, {group: generations.public_runtime_files(config, plan, group)
                      for group in ("nextcloud", "onlyoffice")}


def _roles(n):
    return (("nextcloud", n.c.nextcloud_jail), ("onlyoffice", n.c.onlyoffice_jail))


def _quiet(n, *, deny=True):
    n.check(closed=True)
    n.backend.owned_live()
    n.backend.closed_flags()
    for _, jail in _roles(n):
        _require(not n.backend.running(jail, "cron") and not n.backend.running(jail, "sshd"),
                 "validation-scheduled-writer-running")
    if deny:
        n.backend.deny_probe()


def stage_target_runtime(n):
    """Exact original -> compiled target, durable before writes, exact-only retry.

    Missing source payloads/helpers are blockers; do not use stage_payloads to
    repair them. Original bytes come from retained immutable input generation,
    never a newly adopted live baseline. Interrupted writes accept only those
    original bytes or these exact target bytes, with original ownership/modes.
    """
    try:
        _, inputs, journal = n.check(closed=True)
        _require(journal["phase"] == "validating", "target-runtime-requires-validating-phase")
        _quiet(n, deny=bool(n.backend.running(n.c.nextcloud_jail, "apache24")))
        _, original = _payloads(n, inputs, False)
        target_files, target = _payloads(n, inputs, True)
        entries = []
        for group, jail in _roles(n):
            for name in generations.PUBLIC_FILES:
                path = "root/cloud-installer/" + name
                entries.append(dict(jail=jail, path=path, original=_hash(original[group][name]),
                                    target=_hash(target[group][name])))
        plan = dict(schema_version=1, kind="maintenance-public-runtime-plan", intent=n.journal.reference,
                    source_generation=inputs["entries"][n.c.instance]["generation"], files=entries)
        path = n.directory + "/target-runtime-plan.json"
        retry = n.store._present(path)
        if retry:
            _require(_json(n.store._read(path)) == plan, "target-runtime-plan-drift")
        # Validate the complete pair before the first mutation/plan publication.
        metadata = []
        for entry in entries:
            data, mode, gid = fence._file(n.d.jail_root(entry["jail"]), entry["path"])
            _require(mode == 0o600 and gid == ROOT_GID and _hash(data) in (
                (entry["original"], entry["target"]) if retry else (entry["original"],)),
                "public-runtime-original-or-target-required")
            metadata.append(dict(entry, mode=mode, gid=gid))
        reference = n.record("target-runtime-plan", plan)
        progress = n.directory + "/target-runtime-progress.json"
        if n.store._present(progress):
            value = _json(n.store._read(progress))
            _fields(value, "schema_version plan index state")
            _require(type(value["schema_version"]) is int and value["schema_version"] == 1
                     and value["plan"] == reference and type(value["index"]) is int
                     and 0 <= value["index"] <= len(entries)
                     and value["state"] in ("writing", "complete")
                     and (value["state"] == "complete") == (value["index"] == len(entries)))
        for index, entry in enumerate(metadata):
            n.check(closed=True)
            n.store._put(progress, dict(schema_version=1, plan=reference, index=index, state="writing"),
                         replace=n.store._present(progress))
            root = n.d.jail_root(entry["jail"])
            data, mode, gid = fence._file(root, entry["path"])
            _require((mode, gid) == (0o600, ROOT_GID) and _hash(data) in (entry["original"], entry["target"]))
            group = "nextcloud" if entry["jail"] == n.c.nextcloud_jail else "onlyoffice"
            wanted = target[group][Path(entry["path"]).name]
            if data != wanted:
                fence._replace(root, entry, wanted)
            _require(fence._file(root, entry["path"]) == (wanted, 0o600, ROOT_GID))
        n.check(closed=True)
        n.store._put(progress, dict(schema_version=1, plan=reference, index=len(entries), state="complete"), replace=True)
        return n.record("target-runtime-complete", dict(plan=reference,
            target_files={name: _hash(data) for name, data in target_files.items()}))
    except PublicationBlocked:
        raise
    except Exception:
        raise PublicationBlocked("public-runtime-staging-failed") from None


def effective_runtime_receipt(n, generation, *, target=True):
    """Observe all public worker/helper hashes; target result matches effective.json.

    Useful before sealing the successor: this receipt observes files, not readiness.
    It never installs a missing helper or writes a jail file.
    """
    _id(generation)
    _, inputs = n.native.read(n.operation)
    proposed, payloads = _payloads(n, inputs, target)
    source = generations.source_hashes(inputs["executor"])
    jails = {}
    for group, jail in _roles(n):
        root = n.d.jail_root(jail)
        expected = {"/root/cloud-installer/" + path: digest for path, digest in source.items()}
        for name, data in payloads[group].items():
            path = "root/cloud-installer/" + name
            _require(fence._file(root, path) == (data, 0o600, ROOT_GID), "effective-public-runtime-drift")
            expected["/" + path] = _hash(data)
        if group == "nextcloud":
            expected["/usr/local/libexec/cloud-runtime-inventory.php"] = source["resources/jails/runtime-inventory.php"]
        for path, digest in expected.items():
            _require(_hash(fence._file(root, path.lstrip("/"))[0]) == digest, "effective-worker-helper-drift")
        jails[group] = dict(name=jail, files=expected)
    if target:
        value = dict(schema_version=1, kind="effective-public-worker-receipt", operation=n.operation,
                     instance=n.c.instance, generation=generation, executor_sha256=inputs["executor"]["executor_sha256"],
                     target_files={name: _hash(data) for name, data in proposed.items()}, jails=jails)
    else:
        value = dict(schema_version=1, kind="restored-public-worker-receipt", operation=n.operation,
                     generation=generation, jails=jails)
    return _record(n, "effective-runtime", value)


def _effect(n, event, binding):
    """Read a completed updater effect without invoking migration-phase authority."""
    ref = n.store.reference(n.directory + "/update-" + event + "-after.json")
    value = _json(n.store._bound(ref))
    _fields(value, "schema_version kind operation intent journal event state binding before")
    _require(type(value["schema_version"]) is int and value["schema_version"] == 1
             and value["kind"] == "nextcloud-update-effect" and value["operation"] == n.operation
             and value["intent"] == n.journal.reference and value["event"] == event
             and value["state"] == "after" and value["binding"] == binding
             and value["journal"]["path"] == n.journal.path, "completed-updater-effect-required")
    if event == "target-code-verified":
        _require(value["before"] is None)
        _effect(n, "target-integrity", binding)
    else:
        before = _json(n.store._bound(value["before"], n.directory + "/update-" + event + "-before.json"))
        expected = dict(value, state="before", before=None)
        if event == "stage-artifacts":
            expected["binding"] = before["binding"]  # Source identity precedes receipt creation.
        _require(before == expected, "updater-effect-pair-drift")
    return ref


def _inventory(value):
    _fields(value, "files directories")
    _require(type(value["files"]) is list and 0 < len(value["files"]) <= update.MAX_ENTRIES
             and type(value["directories"]) is list)
    files = []
    for item in value["files"]:
        _fields(item, "path size sha256 executable")
        patch._relative(item["path"])
        _require(type(item["size"]) is int and 0 <= item["size"] <= update.MAX_FILE
                 and type(item["executable"]) is bool
                 and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is not None)
        files.append(update.FileHash(**item))
    for directory in value["directories"]:
        if directory:
            patch._relative(directory)
    _require(len({item.path for item in files}) == len(files)
             and len(set(value["directories"])) == len(value["directories"]))
    return update.Inventory(tuple(files), tuple(value["directories"]))


def _code(n, target):
    path = n.directory + "/update-prepared.json"
    _require(n.store._present(path), "authenticated-update-preparation-required")
    prepared_ref = n.store.reference(path)
    prepared = _json(n.store._bound(prepared_ref))
    _fields(prepared, "schema_version kind operation intent preparation plan admission recipe memory_mib bundle observations custom config_metadata")
    _, inputs = n.native.read(n.operation)
    _require(type(prepared["schema_version"]) is int and prepared["schema_version"] == 1 and prepared["kind"] == "prepared-nextcloud-patch"
             and prepared["operation"] == n.operation and prepared["intent"] == n.journal.reference
             and prepared["admission"] == n.admission["evidence"] and prepared["recipe"] == patch.descriptor()
             and prepared["preparation"] == inputs["preparation"])
    n.store._bound(prepared["admission"])
    _require(_json(n.store._bound(prepared["preparation"]))["plan"] == prepared["plan"])
    n.store._bound(prepared["plan"])
    bundle = prepared["bundle"]
    _fields(bundle, "operation source artifacts source_inventory target_inventory signature receipt_sha256")
    decoded = update.decode_bundle(bundle)
    _require(bundle["operation"] == n.operation)
    root = n.d.jail_root(n.c.nextcloud_jail)
    uid = n.backend.jailed(n.c.nextcloud_jail, "id", "-u", "www").stdout.strip()
    gid = n.backend.jailed(n.c.nextcloud_jail, "id", "-g", "www").stdout.strip()
    _require(uid.isdigit() and gid.isdigit() and int(uid) > 0 and int(gid) > 0)
    c = SimpleNamespace(www_uid=int(uid), www_gid=int(gid), host=lambda path: root / path.lstrip("/"))
    receipt = update._read(c.host(update.STAGING + "/" + n.operation + "/receipt.json"), update.MAX_CENTRAL)
    _require(_hash(receipt) == bundle["receipt_sha256"], "authenticated-inventory-receipt-drift")
    expected = dict(source=bundle["source"], source_version=list(update.SOURCE), target_version=list(update.TARGET),
        operation=n.operation, key=update.RELEASE_KEY, artifacts=bundle["artifacts"],
        **update.inventory_receipt(decoded.source_inventory, decoded.target_inventory))
    _require(_json(receipt) == expected)
    authenticated = _effect(n, "stage-artifacts", bundle["receipt_sha256"])
    inventory = decoded.target_inventory if target else decoded.source_inventory
    observed = patch._code(c, inventory)
    patch._hardened(c, observed)
    _require(patch._custom(c) == prepared["custom"] and patch._config_metadata(c) == prepared["config_metadata"],
             "custom-app-or-config-metadata-drift")
    integrity = authenticated
    if target:
        result_ref = n.store.reference(n.directory + "/update-result.json")
        result = _json(n.store._bound(result_ref))
        _fields(result, "schema_version kind operation prepared receipt_sha256 target runtime hardened_sha256 custom_sha256 appstore maintenance native_acceptance publication_authorized")
        step = n.journal.read()["steps"].get("reviewed-migration", {})
        _require(type(result["schema_version"]) is int and result["schema_version"] == 1 and result["kind"] == "nextcloud-patch-result"
                 and result["operation"] == n.operation and result["prepared"] == prepared_ref
                 and result["receipt_sha256"] == bundle["receipt_sha256"] and result["target"] == list(update.TARGET)
                 and result["hardened_sha256"] == patch._hash(observed)
                 and result["custom_sha256"] == patch._hash(prepared["custom"])
                 and result["maintenance"] is True and result["publication_authorized"] is False
                 and step.get("state") == "complete" and step.get("observation") == result_ref
                 and step.get("phase") == "migrating" and step.get("replay") == "never" and step.get("attempts") == 1,
                 "completed-patch-code-result-required")
        integrity = _effect(n, "target-code-verified", bundle["receipt_sha256"])
        _effect(n, "code-hardened", patch._hash(update.inventory_record(inventory)))
        _effect(n, "final-runtime", bundle["receipt_sha256"])
        _effect(n, "adapter", prepared_ref["sha256"])
    return prepared, c, inventory, _record(n, "validated-code", dict(prepared=prepared_ref,
        authenticated=authenticated, target=target, inventory_sha256=patch._hash(observed))), integrity


def _view(n, plan):
    def jailed(jail, *args, **kwargs):
        return n.d.jail(jail, *args, hide_output=True, timeout=kwargs.get("timeout", 180),
                        check=kwargs.get("check", True))
    return SimpleNamespace(config=n.c, versions=plan, manifest={}, jail=jailed, jail_root=n.d.jail_root)


def _status(n, version, maintenance):
    value = _json(n.backend.occ("status", "--output=json"))
    _require(type(value) is dict and value.get("installed") is True and value.get("maintenance") is maintenance
             and value.get("needsDbUpgrade") is False and value.get("version") == version)
    return value


def _fpm(n, target):
    start = _json(n.store._read(n.directory + "/validation-started.json"))
    _fields(start, "attempt")
    attempt = _json(n.store._bound(start["attempt"]))
    _fields(attempt, "profile phase prior_state")
    _require(attempt["profile"] == n.profile() and attempt["phase"] == ("validating" if target else "recovery-validating")
             and attempt["prior_state"] in ("running", "stopped"), "closed-fpm-start-evidence-required")
    pid = n.backend.jailed(n.c.nextcloud_jail, "cat", "/var/run/php-fpm.pid").stdout.strip()
    rows = n.backend.running(n.c.nextcloud_jail, "php_fpm")
    _require(pid.isdigit() and int(pid) > 0 and any(row[0] == int(pid) and row[2] == "php-fpm" for row in rows),
             "current-fpm-master-required")
    return dict(start=start["attempt"], pid=int(pid), jid=n.d.require_running_jail(n.c.nextcloud_jail),
                boot=n.backend.output("sysctl", "-n", "kern.boottime"))


def _packages(n, plan, prepared):
    values = {}
    for group, jail in (("host", None), *_roles(n)):
        output = (n.backend.output("pkg", "query", "%n %v %o") if jail is None else
                  n.backend.jailed(jail, "pkg", "query", "%n %v %o").stdout)
        rows = [line.split() for line in output.splitlines() if line.strip()]
        _require(rows and all(len(row) == 3 for row in rows), "complete-package-inventory-required")
        values[group] = [dict(zip(("name", "version", "origin"), row)) for row in sorted(rows)]
    policy._actual_packages(values, plan)
    _require(values == prepared["observations"]["full_packages"], "original-package-closure-changed")
    return _record(n, "validated-packages", values)


def _http(n, plan):
    """Both peer paths retain SNI/CA verification; never trust forwarded peers."""
    _require(n.c.tls_mode != "external", "direct-tls-validation-required")
    host = n.c.public_hostname
    ca = ("--cacert", "/root/cloud-installer/tls/ca.pem") if n.c.ca_file else ()
    observed = {}
    for _, jail in _roles(n):
        ip = "127.0.0.1" if jail == n.c.nextcloud_jail else n.c.nextcloud_ip
        common = ("curl", "--silent", "--show-error", "--noproxy", "*", *ca, "--max-time", "20",
                  "--resolve", f"{host}:443:{ip}", "--header", "Host: " + host +
                  (f":{n.c.public_https_port}" if n.c.public_https_port != 443 else ""))
        status = _json(n.backend.jailed(jail, *common, "--fail", f"https://{host}/status.php").stdout)
        _require(status.get("installed") is True and status.get("maintenance") is False
                 and status.get("needsDbUpgrade") is False
                 and status.get("version") == (update.TARGET[1] if plan["applications"]["nextcloud"] == update.TARGET[0] else update.SOURCE[1]))
        _require(n.backend.jailed(jail, *common, "--fail", f"https://{host}/onlyoffice/healthcheck").stdout.strip() == "true")
        office = package_upstream(plan["applications"]["onlyoffice"])
        for path in ("internal/", "info/", "admin/", "example/", office + "-0/internal/", office + "-0/info/"):
            code = n.backend.jailed(jail, *common, "--output", "/dev/null", "--write-out", "%{http_code}",
                                    f"https://{host}/onlyoffice/{path}").stdout.strip()
            _require(code == "403", "private-office-http-endpoint-exposed")
        observed[jail] = status
    n.backend.jailed(n.c.nextcloud_jail, "python3", "-c", '''import socket, sys
for port in (8000, 8126):
    sock = socket.socket()
    sock.settimeout(3)
    try:
        sock.connect((sys.argv[1], port))
    except (TimeoutError, ConnectionError, OSError):
        pass
    else:
        raise SystemExit('Private office backend exposed')
    finally:
        sock.close()
''', n.c.onlyoffice_ip)
    return observed


def _integration(n, plan):
    view = _view(n, plan)
    Deployment.verify_database_configuration(view)  # Only a query; ephemeral manifest.
    Deployment.verify_connector_urls(view)
    _require(n.backend.jailed(n.c.nextcloud_jail, "mdo", "-u", "www", "/usr/local/bin/redis-cli", "-s",
                             "/var/run/redis/private/nextcloud.sock", "PING").stdout.strip() == "PONG",
             "private-www-redis-ping-failed")
    cache = _record(n, "validated-cache", dict(command="www-private-socket-PING", response="PONG"))
    Deployment.wait_for_office(view)
    processes = n.backend.jailed(n.c.onlyoffice_jail, "supervisorctl", "status", "ds:docservice", "ds:metrics").stdout
    _require(all(re.search(rf"(?m)^{name}\s+RUNNING\b", processes) for name in ("ds:docservice", "ds:metrics")))
    for jail, command in ((n.c.nextcloud_jail, ("php-fpm", "-t")),
                          (n.c.nextcloud_jail, ("apachectl", "configtest")), (n.c.onlyoffice_jail, ("nginx", "-t"))):
        n.backend.jailed(jail, *command)
    n.backend.occ("onlyoffice:documentserver", "--check")
    http = _http(n, plan)
    return cache, _record(n, "validated-connector", dict(database=view.manifest["database_configuration"],
        supervisor_sha256=_hash(processes.encode()), http=http, connector="onlyoffice:documentserver --check"))


class FixedValidator(Validator):
    """Compiled commands and authenticated full inventories, not supplied assertions."""

    def descriptor(self):
        return policy.recipe()

    def _binding(self, n, generation, *, opened):
        if not opened:
            _, inputs, journal = n.check(closed=True)
            _require(journal["phase"] in ("validating", "committed-closed", "recovery-validating"))
            _quiet(n)
        else:
            from .enrollment_start import _held
            from .host import verify_managed_network
            from .maintenance_operations import _network_binding
            _require(n.active)
            n.registry._require_lock(recovery=True)
            _held(n.store, f"instances/{n.c.instance}/database-operation.lock")
            intent, inputs = n.native.read(n.operation)
            journal = n.journal.read()
            _require(n.store.pending() == intent and journal["phase"] in ("opening", "recovery-opening", "complete", "recovered")
                     and n.store._active() == journal["evidence"]["graph"]
                     and _network_binding(n.store) == inputs["network"])
            graph = _json(n.store._bound(n.store._active()))
            _require(graph["instances"][n.c.instance]["generation"] == generation)
            verify_managed_network(n.d.registry, n.backend.runner)
            n.d.require_original_artifact()
            n.backend.owned_live()
        _require(inputs["recipe"] == self.descriptor(), "fixed-validation-recipe-required")
        manifest = n.store._generation(n.c.instance, generation)
        target = generation != inputs["entries"][n.c.instance]["generation"]
        if target:
            generations.validate_generation(n.store, n.c.instance, generation, manifest)
        _require(target == (journal["phase"] not in ("recovery-validating", "recovery-opening", "recovered")))
        return manifest, target

    def _observe(self, n, manifest, target):
        prepared, context, inventory, code, integrity = _code(n, target)
        plan = _json(n.store._bound(manifest["versions"]))
        packages = _packages(n, plan, prepared)
        effective = effective_runtime_receipt(n, manifest["generation_id"], target=target)
        if target:
            complete = _json(n.store._read(n.directory + "/target-runtime-complete.json"))
            _require(complete["plan"] == n.store.reference(n.directory + "/target-runtime-plan.json"))
            _require(n.store._bound(effective) == n.store._bound(manifest["evidence"]["effective.json"]),
                     "sealed-effective-workers-differ")
        before = _fpm(n, target)
        php = collect_php(_view(n, plan))
        policy._php(php, plan, generations.destination_policy() if target else load_policy())
        _require(php == prepared["observations"]["php"], "original-cli-and-fpm-runtime-changed")
        _require(_fpm(n, target) == before, "fpm-master-changed-during-validation")
        expected_db = package_upstream(plan["packages"]["nextcloud"][plan["roles"]["database"]]["version"])
        database = n.backend.jailed(n.c.nextcloud_jail, "/usr/local/bin/mariadb", "--no-defaults",
            "--protocol=socket", "--socket=/var/run/mysql/mysql.sock", "--user=root", "--batch",
            "--skip-column-names", "--execute", "SELECT VERSION()").stdout.strip()
        _require(database.startswith(expected_db + "-MariaDB") and database == prepared["observations"]["database"])
        apps = _json(n.backend.occ("app:list", "--output=json"))
        _fields(apps, "enabled disabled")
        _require(all(type(value) is dict for value in apps.values())
                 and all(set(apps[key]) == set(prepared["observations"]["apps"][key]) for key in apps))
        patch._apps(context, inventory, apps)
        runtime = _record(n, "validated-runtime", dict(effective=effective, php=php, database=database, apps=apps))
        return plan, dict(code=code, integrity=integrity, runtime=runtime, packages=packages,
                          fpm_restart=_record(n, "validated-fpm-restart", before))

    def closed(self, n, generation):
        attempt = None
        closure_lost = False
        try:
            manifest, target = self._binding(n, generation, opened=False)
            plan, checks = self._observe(n, manifest, target)
            version = update.TARGET[1] if target else update.SOURCE[1]
            _status(n, version, True)
            path = n.directory + "/validation-canary.json"
            if n.store._present(path):
                prior = _json(n.store._read(path))
                _fields(prior, "schema_version intent attempt state")
                _require(prior["schema_version"] == 1 and prior["intent"] == n.journal.reference
                         and prior["state"] == "closed", "unfinished-validation-canary")
                n.store._bound(prior["attempt"])
            _quiet(n)
            attempt = n.record("validation-canary-" + uuid.uuid4().hex, dict(
                kind="closed-validation-writers-opening", intent=n.journal.reference, generation=generation,
                profile=n.profile(), journal=n.store.reference(n.journal.path), normal_publication=False))
            progress = dict(schema_version=1, intent=n.journal.reference, attempt=attempt, state="opening-canary")
            n.store._put(path, progress, replace=n.store._present(path))  # Durable BEFORE occ --off.
            try:
                n.backend.occ("maintenance:mode", "--off")
                _status(n, version, False)
                try:
                    _quiet(n)
                except Exception:
                    closure_lost = True
                    raise
                checks["cache"], checks["connector"] = _integration(n, plan)
                try:
                    _quiet(n)
                except Exception:
                    closure_lost = True
                    raise
            finally:
                # Also after failed connector/PHP/HTTP checks. Numeric JID guards
                # forbid issuing this command into a replacement/stopped jail.
                n.backend.occ("maintenance:mode", "--on")
                _status(n, version, True)
                _quiet(n)
            n.store._put(path, dict(progress, state="closed"), replace=True)
            return checks
        except Exception as error:
            n.journal.fail("closure-lost" if closure_lost else "validation-failed", closure_lost=closure_lost)
            if attempt is None and isinstance(error, PublicationBlocked):
                raise error from None
            raise PublicationBlocked("closed-validation-failed-maintenance-restoration-required" if attempt else
                                     "closed-validation-prerequisite-failed") from None

    def post_open(self, n, generation):
        try:
            manifest, target = self._binding(n, generation, opened=True)
            plan, checks = self._observe(n, manifest, target)
            _status(n, update.TARGET[1] if target else update.SOURCE[1], False)
            cache, connector = _integration(n, plan)
            self._binding(n, generation, opened=True)
            return dict(runtime=checks["runtime"], packages=checks["packages"], cache=cache, connector=connector,
                        deployment=_record(n, "validated-public-deployment", checks))
        except Exception:
            raise PublicationBlocked("public-readonly-validation-failed") from None


class RecoveryCopyVerifier(CopyVerifier):
    """Concrete receipt adapter; injected function must perform live native reads.

    verify_retained(context, receipt_document) must rehash all streams/private
    evidence, verify independent topology/ownership and exact retained source
    dataset/snapshot GUIDs without a cold-source assertion or export/receive.
    It returns recovery_export.verify_retained's exact result schema. validate()
    retains the manifest/receipt/count binding after actual verification; recheck()
    repeats the native verification and compares that private validation proof.
    A boolean, prior success record or a cold-verifier context bypass is refused.
    """

    def __init__(self, verify_retained=None):
        _require(verify_retained is None or callable(verify_retained), "trusted-retained-copy-function-required")
        self.verify_retained = verify_retained

    def _observe(self, n, manifest, receipt):
        from . import recovery_export
        verifier = self.verify_retained or getattr(recovery_export, "verify_retained", None)
        _require(callable(verifier), "live-closed-retained-copy-verifier-unavailable")
        journal = n.check(closed=True)[2]
        _require(manifest == journal["evidence"]["recovery_set"]
                 == n.store.reference(n.directory + "/recovery/manifest.json"), "original-recovery-manifest-required")
        context = n._recovery_context(readonly=True)
        value = recovery.validate_manifest(context, _json(n.store._bound(manifest)))
        raw = _json(n.store._bound(receipt))
        _fields(raw, "root path sha256 size")
        expected = dict(manifest=manifest, receipt=raw, datasets=len(value["datasets"]),
                        snapshots=len(value["snapshots"]), evidence_files=len(value["evidence"]))
        _require(expected["datasets"] == expected["snapshots"] == 14)
        try:
            observed = verifier(n, deepcopy(raw))
        except Exception:
            raise PublicationBlocked("retained-copy-native-recheck-failed") from None
        _require(type(observed) is dict, "retained-copy-native-observation-drift")
        rehearsal = observed.get("restorestream_rehearsal")
        _require(type(rehearsal) is bool)
        _fields(observed, "evidencecopyverified restorestream_rehearsal fullapplicationrestorerehearsal threat_scope receipt physical_independence_unassessed"
                + (" rehearsal" if rehearsal else ""))
        _require(observed["evidencecopyverified"] is True and observed["fullapplicationrestorerehearsal"] is False
                 and observed["physical_independence_unassessed"] is True
                 and observed["threat_scope"] == recovery_export.SCOPE and observed["receipt"] == raw,
                 "retained-copy-native-observation-drift")
        if rehearsal:
            _fields(observed["rehearsal"], "path sha256 size")
        _require(n.check(closed=True)[2] == journal)
        _record(n, "retained-copy-native-observation", dict(manifest=manifest, result=observed))
        return expected

    def validate(self, n, manifest, receipt):
        """Retain the count-bound validation proof only after native reinspection."""
        return _record(n, "retained-copy-validation", self._observe(n, manifest, receipt))

    def recheck(self, n, manifest, receipt, validation):
        retained = _json(n.store._bound(validation))
        _fields(retained, "manifest receipt datasets snapshots evidence_files")
        expected = self._observe(n, manifest, receipt)
        _require(_encode(retained) == _encode(expected), "retained-copy-validation-binding-drift")
        return _record(n, "verified-publication-copy", dict(expected, receipt=receipt, validation=validation))
