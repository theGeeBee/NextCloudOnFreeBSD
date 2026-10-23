"""Bounded, advisory update reports; retained locks are never rewritten.

The default is an offline cache read. Explicit refresh uses disposable native
catalogs; explicit save is the only registry write. No installed-state solver or
migration recipe is implemented, and no report authorizes execution.
"""

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from . import compatibility, discovery, resolution, versions
from .state import atomic_json, config_digest, timestamp


SCHEMA_VERSION = 2
MAX_BYTES = 8 * 1024 * 1024
MAX_AGE_SECONDS = 24 * 60 * 60
STATUSES = {"unknown", "current-within-reviewed-policy", "available-unreviewed",
            "destination-supported-path-unavailable", "blocked"}
BINDINGS = {"config_sha256", "status_sha256", "versions_sha256", "source_sha256",
            "deployment_sha256", "policy_sha256", "inspector_source_sha256", "lifecycle_sha256"}


class InspectionError(ValueError):
    """Messages in this class are fixed diagnostics, never subprocess output."""


def _directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise InspectionError("Unsafe private evidence directory")


def _root(root):
    # Ancestors need not be private (e.g. /var/db), but cannot redirect lookup.
    for parent in (root, *root.parents):
        if parent.is_symlink():
            raise InspectionError("Symlink in registry path")
    _directory(root)
    _directory(root / "instances")


def _read(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > MAX_BYTES):
            raise InspectionError("Unsafe, linked or oversized private evidence file")
        data = stream.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise InspectionError("Oversized private evidence file")
        return data


def _json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise InspectionError("Duplicate evidence field")
            result[key] = value
        return result
    def invalid_constant(value):
        raise InspectionError("Non-JSON numeric constant in evidence")
    try:
        value = json.loads(data, object_pairs_hook=unique, parse_constant=invalid_constant)
    except RecursionError:
        raise InspectionError("Excessively nested evidence") from None
    if not isinstance(value, dict):
        raise InspectionError("Evidence must be a JSON object")
    return value


def _optional(path):
    try:
        return _read(path)
    except FileNotFoundError:
        # A dangling symlink is unsafe evidence, not an absent optional record.
        if path.is_symlink():
            raise InspectionError("Symlink in private evidence") from None
        return None


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def _context(registry, name):
    # This pure file digest does not instantiate Deployment or inspect the host.
    from .deploy import source_digest
    try:
        policy = registry.version_policy(name)
    except (ValueError, TypeError, KeyError):
        raise InspectionError("Unsupported inspection: retained configuration/policy requires its original reader or has invalid bindings") from None
    return policy, versions.policy_hash(policy), source_digest().strip()


def _snapshot(registry, name, policy_hash, source_hash):
    root = Path(registry.root).absolute()
    _root(root)
    path = root / "instances" / name
    _directory(path)
    raw = {key: _read(registry.evidence_path(name, filename)) for key, filename in
           (("config", "config.json"), ("status", "status.json"),
             ("versions", "versions.json"), ("source", "source.sha256"))}
    if registry.lifecycle_enabled():
        # Managed status is a graph projection, never the legacy status file.
        raw["status"] = json.dumps(registry.status(name), sort_keys=True).encode()
    plan = _json(raw["versions"])
    try:
        resolution._plan_inventory(plan)
    except (ValueError, TypeError, KeyError):
        raise InspectionError("Missing, corrupt or incomplete historical version lock") from None
    source = raw["source"].decode("ascii").strip()
    if not re.fullmatch(r"[a-f0-9]{64}", source):
        raise InspectionError("Invalid retained source identity")
    try:
        config = registry.load(name)
    except (ValueError, TypeError, KeyError):
        raise InspectionError("Unsupported inspection: retained configuration does not satisfy the current configuration/policy reader") from None
    if not config.native_office:
        raise InspectionError("Native update/security assessment is unsupported for this office_backend")
    if config.instance != name:
        raise InspectionError("Configuration instance identity mismatch")
    historical_policy = {"defaults": plan["constraints"], "targets": [plan["target"]]}
    if (versions.constraints(config, historical_policy) != plan["constraints"]
            or config.repository != plan["repository"]):
        raise InspectionError("Historical version lock does not match retained configuration constraints")
    status = _json(raw["status"])
    if status.get("state") not in ("configured", "installing", "failed", "ready", "removing", "removed"):
        raise InspectionError("Invalid retained instance status")
    journal = _optional(path / "deployment.json")
    if journal is not None:
        value = _json(journal)
        if (value.get("schema_version") != config.schema_version
                or value.get("config_sha256") != registry.deployment_config_digest(name)
                or not isinstance(value.get("steps"), dict)):
            raise InspectionError("Deployment journal/configuration binding is invalid")
    bindings = {key + "_sha256": _hash(raw[key]) for key in ("config", "status", "versions")}
    bindings.update(source_sha256=source, deployment_sha256=_hash(journal) if journal is not None else None,
                    policy_sha256=policy_hash, inspector_source_sha256=source_hash,
                    lifecycle_sha256=_hash(_read(root / "lifecycle/active.json")) if registry.lifecycle_enabled() else None)
    return config, status, plan, bindings


def _empty(name):
    return {"instance": name, "status": "unknown", "freshness": "missing", "checked_at": None,
            "installed_applications": {}, "candidate_applications": {}, "upstream_newer": {},
            "changes": [], "blockers": [], "errors": [], "warnings": [], "stale_reasons": [],
            "constraints": {}, "bindings": {}, "provenance": {},
            "shared_prerequisites": {"installed": {}, "candidate": {}},
            "execution_authorized": False, "migration_supported": False, "saved": False}


def _failure(report, code, message, *, blocked=False):
    report["errors"].append({"code": code, "message": message})
    report["status"] = "blocked" if blocked else "unknown"
    report["freshness"] = "unknown"


def _date(value):
    if not isinstance(value, str):
        raise InspectionError("Missing report timestamp")
    result = datetime.fromisoformat(value)
    if result.tzinfo is None:
        raise InspectionError("Report timestamp requires a timezone")
    return result


def _validate_report(value, name):
    """Reject incomplete/unknown cache schemas rather than trusting a status string."""
    if type(value.get("schema_version")) is int and value["schema_version"] == 1:
        # Read the known M1 schema without rewriting it or inventing a graph
        # binding. Normal freshness comparison marks an enrolled graph stale.
        value = deepcopy(value)
        historical = value.get("report")
        if not isinstance(historical, dict):
            raise InspectionError("Invalid historical update report")
        bindings = historical.get("bindings")
        if not isinstance(bindings, dict) or set(bindings) != BINDINGS - {"lifecycle_sha256"}:
            raise InspectionError("Incomplete historical update-report bindings")
        bindings["lifecycle_sha256"] = None
        value["schema_version"] = SCHEMA_VERSION
    if (set(value) != {"schema_version", "generated_at", "report"}
            or type(value["schema_version"]) is not int or value["schema_version"] != SCHEMA_VERSION):
        raise InspectionError("Unsupported update-report schema")
    generated = _date(value["generated_at"])
    report = value["report"]
    if not isinstance(report, dict) or set(report) != set(_empty(name)):
        raise InspectionError("Incomplete update report")
    if (report["instance"] != name or report["status"] not in STATUSES
            or report["execution_authorized"] is not False or report["migration_supported"] is not False
            or type(report["saved"]) is not bool or report["freshness"] not in ("fresh", "stale", "unknown")):
        raise InspectionError("Invalid advisory report identity/status")
    checked = _date(report["checked_at"])
    if checked > generated:
        raise InspectionError("Invalid report timestamp ordering")
    bindings = report["bindings"]
    if not isinstance(bindings, dict) or set(bindings) != BINDINGS:
        raise InspectionError("Incomplete update-report bindings")
    for key, value in bindings.items():
        if value is None and key in ("deployment_sha256", "lifecycle_sha256"):
            continue
        if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
            raise InspectionError("Invalid update-report binding")
    for field in ("installed_applications", "candidate_applications"):
        applications = report[field]
        if not isinstance(applications, dict) or (field == "installed_applications" and not applications):
            raise InspectionError("Missing report application identities")
        if applications:
            versions.object_fields(applications, ("nextcloud", "onlyoffice", "connector"), label="report applications")
            for app, version in applications.items():
                (versions.package_version if app == "onlyoffice" else versions.stable_version)(version)
    for field in ("blockers", "warnings", "stale_reasons"):
        if not isinstance(report[field], list) or any(not isinstance(item, str) for item in report[field]):
            raise InspectionError("Invalid report diagnostics")
    for field, keys in (("errors", {"code", "message"}), ("changes", {"component", "from", "to"})):
        if not isinstance(report[field], list) or any(not isinstance(item, dict) or set(item) != keys for item in report[field]):
            raise InspectionError("Invalid report comparison/diagnostics")
    if any(not isinstance(item[key], str) for item in report["errors"] for key in ("code", "message")):
        raise InspectionError("Invalid report error text")
    if any(not isinstance(item["component"], str) or not item["component"] for item in report["changes"]):
        raise InspectionError("Invalid comparison component")
    if report["errors"] and report["status"] not in ("unknown", "blocked"):
        raise InspectionError("Failed inspection cannot report an available/current destination")
    if report["status"] in ("current-within-reviewed-policy", "destination-supported-path-unavailable"):
        if not report["candidate_applications"] or report["blockers"]:
            raise InspectionError("Supported destination report is incomplete or blocked")
    if report["status"] == "current-within-reviewed-policy" and (report["changes"] or report["upstream_newer"]):
        raise InspectionError("Current report contains unreported changes/releases")
    if (not isinstance(report["constraints"], dict)
            or set(report["constraints"]) - {"version_families"} != set(versions.FIELDS)):
        raise InspectionError("Missing report constraints")
    try:
        versions.validate_families(report["constraints"].get("version_families", {}))
    except ValueError:
        raise InspectionError("Invalid report version families") from None
    provenance = report["provenance"]
    if (not isinstance(provenance, dict) or set(provenance) != {"installed_policy_sha256", "original_policy_available", "original_source_matches"}
            or not isinstance(provenance["installed_policy_sha256"], str)
            or not re.fullmatch(r"[a-f0-9]{64}", provenance["installed_policy_sha256"])
            or type(provenance["original_policy_available"]) is not bool
            or type(provenance["original_source_matches"]) is not bool):
        raise InspectionError("Missing report provenance")
    upstream = report["upstream_newer"]
    if not isinstance(upstream, dict) or set(upstream) - {"nextcloud", "onlyoffice"}:
        raise InspectionError("Invalid upstream release report")
    for values in upstream.values():
        if not isinstance(values, list):
            raise InspectionError("Invalid upstream release list")
        for version in values:
            versions.stable_version(version)
    shared = report["shared_prerequisites"]
    if not isinstance(shared, dict) or set(shared) != {"installed", "candidate"}:
        raise InspectionError("Missing shared prerequisite comparison")
    for packages in shared.values():
        if not isinstance(packages, dict):
            raise InspectionError("Invalid shared prerequisite inventory")
        if packages:
            # The report contains only selected host closure packages, not live OS health.
            first = next(iter(packages.values()))
            versions.object_fields(first, ("name", "version", "origin", "abi", "checksum", "dependencies"),
                                   label="shared prerequisite package")
            abi = versions.text(first["abi"], r"FreeBSD:[0-9]+:(?:[a-z0-9]+|\*)", "package ABI")
            if abi.endswith(":*"):
                abi = abi[:-1] + report["constraints"]["architecture"]
            compatibility.inventory(packages, abi)
    if not shared["installed"] or (report["candidate_applications"] and not shared["candidate"]):
        raise InspectionError("Incomplete shared prerequisite comparison")
    return deepcopy(report), generated


def _cached(root, name, bindings):
    directory = root / "update-reports"
    try:
        _directory(directory)
    except FileNotFoundError:
        return None
    data = _optional(directory / (name + ".json"))
    if data is None:
        return None
    report, generated = _validate_report(_json(data), name)
    now = datetime.now(timezone.utc)
    if generated > now or _date(report["checked_at"]) > now:
        raise InspectionError("Update report is dated in the future")
    reasons = [key for key in sorted(BINDINGS) if report["bindings"][key] != bindings[key]]
    if (now - _date(report["checked_at"])).total_seconds() > MAX_AGE_SECONDS:
        reasons.append("older-than-24-hours")
    report["stale_reasons"] = reasons
    report["freshness"] = "stale" if reasons else report["freshness"]
    report["saved"] = False
    return report


def _refresh(report, config, installed, policy, runner):
    report["checked_at"] = timestamp()
    report["freshness"] = "fresh"
    try:
        # Omit directory: discover owns TemporaryDirectory, outside registry state.
        discovered = discovery.discover(config, runner, policy=policy)
        compatibility.discovered_inputs(config, discovered, policy)
        for app in ("nextcloud", "onlyoffice"):
            newer = set()
            for version in discovered[app]:
                try:
                    if versions.stable_version(version) > versions.package_version(installed["applications"][app])[1]:
                        newer.add(version)
                except ValueError:
                    continue  # Stable upstream releases only, never prereleases.
            if newer:
                report["upstream_newer"][app] = sorted(newer, key=versions.stable_version)
    except (ValueError, RuntimeError, OSError, TypeError, KeyError) as error:
        # Native command/network diagnostics may contain arbitrary remote output.
        _failure(report, "discovery-failed", "Stable upstream/signed native package discovery failed (" + type(error).__name__ + ")")
        return
    try:
        candidate = resolution.resolve(config, discovered, policy=policy)
    except ValueError:
        report["status"] = "available-unreviewed" if report["upstream_newer"] else "blocked"
        report["blockers"].append("No obtainable destination satisfies the configured minimum/exact pins and reviewed compatibility policy.")
        return
    assessment = resolution.assess_upgrade(installed, candidate)
    report.update(candidate_applications=deepcopy(candidate["applications"]),
                  changes=assessment["changes"], blockers=assessment["blockers"])
    report["shared_prerequisites"]["candidate"] = deepcopy(candidate["packages"]["host"])
    if report["blockers"]:
        report["status"] = "blocked"
    elif report["changes"]:
        report["status"] = "destination-supported-path-unavailable"
    elif report["upstream_newer"]:
        report["status"] = "available-unreviewed"
    else:
        report["status"] = "current-within-reviewed-policy"


def _save_conflicts(registry):
    from .firewall import pending_transactions
    from .lifecycle import RUNTIME_STEPS
    root = Path(registry.root).absolute()
    _root(root)
    # Registry.locked initializes these; require existing state so saving cannot
    # silently initialize a nonexistent or incomplete registry.
    for name in ("transactions", "network", "backups", "removed"):
        _directory(root / name)
    if pending_transactions(root):
        raise InspectionError("Report save refused while a network transaction is unresolved")
    for path in sorted((root / "instances").iterdir()):
        _directory(path)
        if path.name.startswith(".pending-"):
            raise InspectionError("Report save refused during incomplete registration")
        status = registry.status(path.name)
        if status.get("state") not in ("ready", "removed"):
            raise InspectionError("Report save refused during pending installation/removal")
        config = registry.load(path.name)
        if config.instance != path.name:
            raise InspectionError("Report save refused: conflicting registry identity")
        restore = _optional(path / "restore.json")
        if restore is not None:
            record = _json(restore)
            if (record.get("schema_version") != 1 or record.get("state") != "complete"
                    or record.get("phase") != "validated" or record.get("instance") != path.name
                    or record.get("config_sha256") != config_digest(config)
                    or not isinstance(record.get("metadata"), dict)
                    or not isinstance(record.get("code_sha256"), dict) or not record["code_sha256"]
                    or not isinstance(record.get("paused"), dict) or not isinstance(record.get("started"), str)):
                raise InspectionError("Report save refused during pending or invalid restore")
            for key in ("source_manifest_sha256", "prebackup_manifest_sha256"):
                if not isinstance(record.get(key), str) or not re.fullmatch(r"[a-f0-9]{64}", record[key]):
                    raise InspectionError("Report save refused: incomplete restore identity")
        journals = {}
        for name in ("deployment.json", "removal.json", "purge.json"):
            data = _optional(path / name)
            if data is None:
                continue
            journal = _json(data)
            steps = journal.get("steps")
            if (journal.get("schema_version") != config.schema_version
                    or journal.get("config_sha256") != (registry.deployment_config_digest(path.name)
                        if name == "deployment.json" else config_digest(config))
                    or not isinstance(steps, dict) or not steps
                    or any(not isinstance(step, dict) or step.get("state") not in ("complete", "running", "failed")
                           for step in steps.values())):
                raise InspectionError("Report save refused: invalid installation/removal journal")
            journals[name] = journal
        removed = False
        if status["state"] == "removed":
            # Match lifecycle's retained tombstone/dataset and runtime-step
            # evidence. A status label alone cannot supersede failed work.
            tombstone = _json(_read(path / "removed.json"))
            if (tombstone.get("dataset") != config.dataset_root
                    or type(tombstone.get("data_retained")) is not bool
                    or tombstone.get("credentials_retained") is not True
                    or tombstone.get("backups_retained") is not True
                    or ("data_retained" in status and status["data_retained"] != tombstone["data_retained"])):
                raise InspectionError("Report save refused: invalid removal tombstone")
            removed = any(all(journal["steps"].get(step, {}).get("state") == "complete" for step in RUNTIME_STEPS)
                          for name, journal in journals.items() if name in ("removal.json", "purge.json"))
            if not removed:
                raise InspectionError("Report save refused: incomplete runtime removal evidence")
        for name, journal in journals.items():
            if removed and name == "deployment.json":
                continue  # Successful removal supersedes this retained install history.
            if any(step["state"] != "complete" for step in journal["steps"].values()):
                raise InspectionError("Report save refused during incomplete installation/removal journal")
        initialization = _optional(path / "initialization.json")
        if initialization is not None:
            record = _json(initialization)
            recoveries = record.get("recoveries")
            if (record.get("schema_version") != 1 or record.get("instance") != config.instance
                    or record.get("config_sha256") != registry.deployment_config_digest(path.name)
                    or record.get("state") not in ("prepared", "complete")
                    or not isinstance(recoveries, list)
                    or any(not isinstance(item, dict) or item.get("state") not in ("running", "failed", "complete")
                           for item in recoveries)):
                raise InspectionError("Report save refused: invalid initialization recovery journal")
            if not removed and (record["state"] != "complete" or (recoveries and recoveries[-1]["state"] != "complete")):
                raise InspectionError("Report save refused during incomplete initialization recovery")


def _host_summary(reports):
    packages = {}
    for report in reports:
        for kind, inventory in report["shared_prerequisites"].items():
            for name, package in inventory.items():
                item = packages.setdefault(name, {"name": name, "installed": [], "candidate": []})
                item[kind].append({"instance": report["instance"], "freshness": report["freshness"],
                                   "checked_at": report["checked_at"],
                                   **{key: package[key] for key in ("version", "origin", "abi", "checksum")}})
    return {"scope": "selected-shared-prerequisites-only", "selected_instances": [r["instance"] for r in reports],
            "prerequisites": [packages[name] for name in sorted(packages)],
            "os_update_health": "not-assessed", "security_advisories": "not-assessed", "support_eol": "not-assessed",
            "execution_authorized": False, "migration_supported": False}


def check_updates(registry, names, *, refresh=False, save_report=False, runner=None):
    """Return JSON-ready advisory reports for an explicit nonempty list of IDs.

    Per-instance failures are retained and set inspection_failed. Cache misses
    are unknown, not failures; unsafe/missing installation evidence is a failure.
    Saving requires explicit refresh and revalidates all bindings under the
    short global operation lock. No secret files or live application state are read.
    """
    if (not isinstance(names, list) or not names or any(not isinstance(name, str)
            or not re.fullmatch(r"[a-z][a-z0-9]{0,7}", name) for name in names)
            or len(names) != len(set(names))):
        raise ValueError("Update inspection requires an explicit nonempty list of distinct instance IDs")
    if save_report and not refresh:
        raise ValueError("Saving an update report requires explicit refresh")
    reports, snapshots = [], {}
    for name in names:
        report = _empty(name)
        reports.append(report)
        try:
            policy, policy_hash, source_hash = _context(registry, name)
            config, status, installed, bindings = _snapshot(registry, name, policy_hash, source_hash)
            snapshots[name] = bindings
            report.update(installed_applications=deepcopy(installed["applications"]), bindings=bindings,
                          constraints=versions.constraints(config, policy),
                          provenance={"installed_policy_sha256": installed["policy_sha256"],
                                      "original_policy_available": installed["policy_sha256"] == policy_hash,
                                      "original_source_matches": bindings["source_sha256"] == source_hash})
            report["shared_prerequisites"]["installed"] = deepcopy(installed["packages"]["host"])
            report["warnings"] = [resolution.MIGRATION_WARNING, resolution.NATIVE_WARNING, resolution.SECURITY_WARNING,
                                  "Current means within reviewed policy and configured minimum/exact pins, not latest upstream or security-current.",
                                  "Retained locks describe intended installation; live application/package drift, support/EOL and security advisories are not inspected."]
            if installed["policy_sha256"] != policy_hash:
                report["warnings"].append("Original policy provenance is unavailable: historical lock is structurally inspected only; current policy is used only for destination selection.")
            if refresh:
                if status["state"] != "ready":
                    report.update(status="blocked", checked_at=timestamp(), freshness="fresh")
                    report["blockers"].append("Update discovery requires a ready retained installation.")
                else:
                    if runner is None:
                        from .host import Runner
                        runner = Runner()
                    _refresh(report, config, installed, policy, runner)
            else:
                cached = _cached(Path(registry.root).absolute(), name, bindings)
                if cached is not None:
                    report.clear()
                    report.update(cached)
        except (ValueError, RuntimeError, OSError, TypeError, KeyError, UnicodeError) as error:
            message = str(error) if isinstance(error, InspectionError) else "Missing, unsafe or corrupt inspection evidence (" + type(error).__name__ + ")"
            _failure(report, "inspection-failed", message)
    # Recheck after the entire selection: discovering a later instance can take
    # time, during which an earlier instance's status/configuration may change.
    for report in reports:
        if report["instance"] not in snapshots or any(e["code"] == "inspection-failed" for e in report["errors"]):
            continue
        try:
            _, after_policy, after_source = _context(registry, report["instance"])
            if _snapshot(registry, report["instance"], after_policy, after_source)[3] != snapshots[report["instance"]]:
                raise InspectionError("Configuration/status/version/source/policy evidence changed during advisory inspection")
        except (ValueError, RuntimeError, OSError, TypeError, KeyError) as error:
            message = str(error) if isinstance(error, InspectionError) else "Inspection evidence became unavailable or invalid during advisory inspection"
            _failure(report, "inspection-failed", message)
    if save_report:
        try:
            if any(not r["checked_at"] or r["freshness"] == "stale" or not r["bindings"]
                   or any(e["code"] == "inspection-failed" for e in r["errors"]) for r in reports):
                raise InspectionError("Cannot save missing, stale or invalid report evidence; explicitly refresh first")
            _save_conflicts(registry)
            with registry.locked():
                _save_conflicts(registry)
                for report in reports:
                    _, policy_hash, source_hash = _context(registry, report["instance"])
                    if _snapshot(registry, report["instance"], policy_hash, source_hash)[3] != snapshots[report["instance"]]:
                        raise InspectionError("Report bindings changed before save")
                directory = Path(registry.root).absolute() / "update-reports"
                if not directory.exists() and not directory.is_symlink():
                    directory.mkdir(mode=0o700)
                _directory(directory)
                for report in reports:
                    path = directory / (report["instance"] + ".json")
                    previous = _optional(path)
                    if previous is not None:
                        _validate_report(_json(previous), report["instance"])
                for report in reports:
                    value = {"schema_version": SCHEMA_VERSION, "generated_at": timestamp(), "report": report}
                    _validate_report(value, report["instance"])
                    if len(json.dumps(value, indent=2, sort_keys=True).encode()) + 1 > MAX_BYTES:
                        raise InspectionError("Update report exceeds its private cache size limit")
                    atomic_json(directory / (report["instance"] + ".json"), value)
                    report["saved"] = True
        except (ValueError, RuntimeError, OSError, TypeError, KeyError) as error:
            message = str(error) if isinstance(error, InspectionError) else "Report save failed; private state/lock could not be validated"
            for report in reports:
                _failure(report, "save-failed", message, blocked=True)
    generated = timestamp()
    checked = [r["checked_at"] for r in reports if r["checked_at"]]
    return {"schema_version": SCHEMA_VERSION, "generated_at": generated,
            "checked_at": max(checked) if checked else None, "instances": reports,
            "host": _host_summary(reports), "inspection_failed": any(r["errors"] for r in reports),
            "execution_authorized": False, "migration_supported": False}
