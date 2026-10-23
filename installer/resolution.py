"""Pure candidate selection, retained-plan validation and non-executable upgrades."""

from copy import deepcopy
from types import SimpleNamespace

from . import compatibility
from .versions import (FIELDS, NC_FIELDS, GROUPS, NAME, TRIPLE, VM_BACKENDS, VM_ROLES, CONNECTOR_APPS, constraints, load_policy,
                       object_fields, office_backend, package_upstream, package_version, policy_hash, release_base, selected_profiles,
                       satisfies, stable_version, target, text, validate_policy, validate_office_runtime, validate_runtime_artifacts)


NATIVE_WARNING = "Source/catalog review only; native FreeBSD/QEMU acceptance has not been performed."
SECURITY_WARNING = "Compatibility is not a security claim; current advisories, support status and native package backports require separate review."
MIGRATION_WARNING = "No reviewed migration paths exist; compatibility is not authorization to execute an upgrade."
FAMILY_WARNING = ("Version-family selection permits compatible stable patches, not project certification of this exact combination. "
                  "New patches/package combinations may be independently untested. APPLY or --yes accepts this uncertainty, "
                  "never a failed compatibility, signature, checksum, dependency or runtime-layout check.")


def _family_warning(policy, profile):
    selected = next(item for item in policy["profiles"] if item["id"] == profile)
    return any("family" in rule for rule in selected["applications"].values())


def resolve(config, discovered, *, policy=None, installed=None):
    """Choose the newest compatible stable NC release and the one offered OO pkg.

    A repository snapshot has one version per package name. Rejected versions
    are never synthesized as obtainable historical packages. An installed plan
    adds downgrade checks; migration assessment remains explicitly non-executable.
    """
    policy = load_policy() if policy is None else validate_policy(policy)
    profiles = selected_profiles(config, policy)
    backend = office_backend(config)
    vm = backend in VM_BACKENDS
    effective = compatibility.discovered_inputs(config, discovered, policy)
    candidates = []
    for version in discovered["nextcloud"]:
        try:
            text(version, TRIPLE, "stable Nextcloud release")
        except ValueError:
            continue
        if satisfies(version, "nextcloud", effective):
            candidates.append(version)
    errors = []
    if backend != "onlyoffice":
        for nextcloud in sorted(set(candidates), key=stable_version, reverse=True):
            try:
                pieces = compatibility.validate(config, discovered, nextcloud, policy=policy)
            except ValueError as error:
                errors.append(str(error))
                continue
            applications = {"nextcloud": nextcloud}
            if vm:
                applications["connector"] = pieces["connector"]["version"]
            evidence = policy["evidence"] + (next(p["evidence"] for p in profiles if p["id"] == pieces["profile"]) if vm else [])
            plan = {"schema_version": 3 if vm else 2, "office_backend": backend, "target": deepcopy(discovered["target"]),
                    "repository": discovered["repository"], "constraints": effective,
                    "applications": applications, **pieces,
                    "policy_sha256": policy_hash(policy, backend),
                    "sources": sorted(set(discovered["sources"] + [item["url"] for item in evidence])),
                     "warnings": [NATIVE_WARNING, SECURITY_WARNING]}
            if _family_warning(policy, pieces["profile"]):
                plan["warnings"].append(FAMILY_WARNING)
            if vm:
                plan["warnings"].append("VM metadata inspection only: lifecycle/integration implementation and native editor acceptance remain incomplete; no deployment authorization.")
            if errors:
                plan["warnings"].append("Newer candidates were rejected by the configured constraints or reviewed compatibility policy.")
            if installed is not None:
                assessment = assess_upgrade(installed, plan)
                if assessment["blockers"]:
                    raise ValueError("Unsafe upgrade candidate: " + "; ".join(assessment["blockers"]))
                plan["warnings"].append(MIGRATION_WARNING)
            return plan
    offices = []
    for name in {profile["roles"]["onlyoffice"]["package"] for profile in profiles if "onlyoffice" in profile["roles"]}:
        record = discovered["packages"].get(name)
        if record is None:
            errors.append(f"Required ONLYOFFICE package {name} is unavailable")
            continue
        try:
            if not satisfies(record["version"], "onlyoffice", effective):
                errors.append(f"ONLYOFFICE package {name} violates the configured minimum or exact pin")
                continue
            offices.append((package_version(record["version"]), name, record))
        except ValueError:
            errors.append(f"ONLYOFFICE package {name} is not a stable numeric release")
    for nextcloud in sorted(set(candidates), key=stable_version, reverse=True):
        # Profiles may change the office package name, but discovery still offers
        # only one exact record per name, never a fabricated version list.
        for _, name, record in sorted(offices, key=lambda item: (item[0], item[1]), reverse=True):
            try:
                pieces = compatibility.validate(config, discovered, nextcloud, record["version"], policy=policy)
            except ValueError as error:
                errors.append(str(error))
                continue
            plan = {"schema_version": 1, "target": deepcopy(discovered["target"]),
                    "repository": discovered["repository"], "constraints": effective,
                    "applications": {"nextcloud": nextcloud, "onlyoffice": record["version"], "connector": pieces["connector"]["version"]},
                    **pieces, "policy_sha256": policy_hash(policy),
                    "sources": sorted(set(discovered["sources"] + [item["url"] for item in policy["evidence"]])),
                     "warnings": [NATIVE_WARNING, SECURITY_WARNING]}
            if _family_warning(policy, pieces["profile"]):
                plan["warnings"].append(FAMILY_WARNING)
            if plan["fonts_unavailable"]:
                plan["warnings"].append("Optional fonts unavailable: " + ", ".join(plan["fonts_unavailable"]))
            if errors:
                plan["warnings"].append("Newer candidates were rejected by the configured constraints or reviewed compatibility policy.")
            if installed is not None:
                assessment = assess_upgrade(installed, plan)
                if assessment["blockers"]:
                    raise ValueError("Unsafe upgrade candidate: " + "; ".join(assessment["blockers"]))
                plan["warnings"].append(MIGRATION_WARNING)
            return plan
    detail = "; ".join(dict.fromkeys(errors)) if errors else "No stable Nextcloud release satisfies the configured minimum or exact pin"
    raise ValueError("No compatible obtainable application/package set: " + detail)


def _plan_inventory(plan):
    """Require complete retained identity without assuming today's historical policy."""
    none = isinstance(plan, dict) and plan.get("schema_version") == 2
    vm = isinstance(plan, dict) and plan.get("schema_version") == 3
    common = ("schema_version", "target", "repository", "constraints", "applications", "profile",
              "roles", "roots", "packages", "sources", "policy_sha256", "warnings")
    extra = ("office_backend", "connector", "connector_app", "office_runtime", "artifacts") if vm else ("office_backend",) if none else ("connector", "fonts_unavailable")
    object_fields(plan, common + extra, label="resolved plan")
    if type(plan["schema_version"]) is not int or plan["schema_version"] != (3 if vm else 2 if none else 1):
        raise ValueError("Unsupported resolved-plan schema")
    if none and plan["office_backend"] != "none":
        raise ValueError("Resolved-plan schema 2 requires office_backend='none'")
    if vm and (plan["office_backend"] not in VM_BACKENDS or plan["connector_app"] != CONNECTOR_APPS[plan["office_backend"]]):
        raise ValueError("Resolved-plan schema 3 requires a matching VM backend and connector")
    if vm:
        validate_office_runtime(plan["office_runtime"])
        validate_runtime_artifacts(plan["office_runtime"], plan["artifacts"])
    groups = ("host", "nextcloud") if none or vm else GROUPS
    object_fields(plan["target"], ("release", "architecture", "abi", "pkgbase_keys"), label="plan target")
    release = release_base(plan["target"]["release"])
    text(plan["target"]["architecture"], r"[a-z0-9]+", "plan architecture")
    expected_abi = "FreeBSD:" + release.split(".")[0] + ":" + plan["target"]["architecture"]
    if plan["target"]["release"] != release or plan["target"]["abi"] != expected_abi:
        raise ValueError("Plan target/ABI identity is inconsistent")
    if vm and plan['target']['architecture'] != 'amd64':
        raise ValueError('VM image/host architecture is unsupported')
    if not isinstance(plan["target"]["pkgbase_keys"], list) or not plan["target"]["pkgbase_keys"]:
        raise ValueError("Missing retained pkgbase trust-key identity")
    for path in plan["target"]["pkgbase_keys"]:
        text(path, r"/[A-Za-z0-9_./-]+", "retained pkgbase key path")
        if ".." in path.split("/"):
            raise ValueError("Invalid retained pkgbase key path")
    if plan["repository"] not in ("latest", "quarterly"):
        raise ValueError("Invalid plan repository")
    text(plan["profile"], NAME, "plan profile")
    text(plan["policy_sha256"], r"[a-f0-9]{64}", "policy hash")
    object_fields(plan["constraints"], NC_FIELDS if none or vm else FIELDS, ("version_families",), label="effective plan constraints")
    own_policy = {"defaults": plan["constraints"], "targets": [plan["target"]]}
    config = SimpleNamespace(**plan["constraints"], office_backend=plan["office_backend"] if none or vm else "")
    if constraints(config, own_policy) != plan["constraints"]:
        raise ValueError("Plan constraints must be explicit and normalized")
    object_fields(plan["applications"], ("nextcloud", "connector") if vm else ("nextcloud",) if none else ("nextcloud", "onlyoffice", "connector"), label="plan applications")
    text(plan["applications"]["nextcloud"], TRIPLE, "retained Nextcloud version")
    if not none and not vm:
        package_version(plan["applications"]["onlyoffice"])
    for app in ("nextcloud",) if none or vm else ("nextcloud", "onlyoffice"):
        if not satisfies(plan["applications"][app], app, plan["constraints"]):
            raise ValueError("Retained applications violate their explicit constraints")
    if not none:
        compatibility.connector_record(plan["connector"], plan["connector_app"] if vm else "onlyoffice")
        if plan["applications"]["connector"] != plan["connector"]["version"]:
            raise ValueError("Retained connector application and signed release identities disagree")
    if not none and not vm:
        if not isinstance(plan["fonts_unavailable"], list):
            raise ValueError("Missing optional-font availability report")
        for name in plan["fonts_unavailable"]:
            text(name, NAME, "unavailable font package")
        if len(plan["fonts_unavailable"]) != len(set(plan["fonts_unavailable"])):
            raise ValueError("Duplicate unavailable font package")
    for field in ("sources", "warnings"):
        if not isinstance(plan[field], list) or not plan[field]:
            raise ValueError(f"Missing plan {field}")
        for value in plan[field]:
            if not isinstance(value, str) or not value or len(value) > 16384 or any(ord(char) < 32 or ord(char) == 127 for char in value):
                raise ValueError("Malformed plan " + field)
    object_fields(plan["packages"], groups, label="plan package groups")
    object_fields(plan["roots"], groups, label="plan root groups")
    merged = {}
    for group in groups:
        packages, roots = plan["packages"][group], plan["roots"][group]
        compatibility.inventory(packages, expected_abi)
        if not isinstance(roots, list) or not roots or len(roots) != len(set(map(str, roots))):
            raise ValueError(f"Missing or ambiguous {group} roots")
        for name in roots:
            text(name, NAME, "retained root")
        if compatibility.closure(packages, roots) != packages:
            raise ValueError(f"Retained {group} packages do not equal their dependency closure")
        for name, record in packages.items():
            if name in merged and merged[name] != record:
                raise ValueError(f"Conflicting retained package identity for {name}")
            merged[name] = record
    roles = ("manager", "php", "database", "database_client", "web", "cache")
    required_roles = roles + VM_ROLES if vm else roles if none else roles + ("onlyoffice",)
    object_fields(plan["roles"], required_roles, label="plan roles")
    for role, name in plan["roles"].items():
        text(name, NAME, "role package name")
        group = "host" if role == "manager" or role.startswith("vm_") else "onlyoffice" if role == "onlyoffice" else "nextcloud"
        if name not in plan["packages"][group]:
            raise ValueError(f"Retained {role} identity is missing from {group}")
    compatibility.family_constraints(plan["constraints"].get("version_families", {}),
                                     plan["applications"], plan["roles"], merged)
    if none or vm:
        if vm:
            for role in ('php','database','database_client'):
                package_version(merged[plan['roles'][role]]['version'])
        if merged[plan["roles"]["database"]]["version"] != merged[plan["roles"]["database_client"]]["version"]:
            raise ValueError("Retained database server/client versions disagree")
        if vm and (not compatibility.in_range(plan["applications"]["nextcloud"], compatibility.version_spec(plan["connector"]["platformVersionSpec"]))
                   or not compatibility.connector_php_allows(merged[plan["roles"]["php"]]["version"], plan["connector"]["phpVersionSpec"])):
            raise ValueError("Retained VM connector excludes selected Nextcloud/PHP")
        return merged
    if merged[plan["roles"]["onlyoffice"]]["version"] != plan["applications"]["onlyoffice"]:
        raise ValueError("Retained ONLYOFFICE application/package identities disagree")
    if set(plan["fonts_unavailable"]) & plan["packages"]["onlyoffice"].keys():
        raise ValueError("A retained font package is also reported unavailable")
    for field, version in (("platformVersionSpec", plan["applications"]["nextcloud"]),
                           ("phpVersionSpec", merged[plan["roles"]["php"]]["version"])):
        if not compatibility.in_range(version, compatibility.version_spec(plan["connector"][field])):
            raise ValueError("Retained connector excludes the recorded application/runtime")
    return merged


def validate_plan(config, plan, policy=None):
    """Revalidate exact retained choices, without discovery or selecting replacements."""
    policy = load_policy() if policy is None else validate_policy(policy)
    backend = office_backend(config)
    packages = _plan_inventory(plan)
    if backend != plan.get("office_backend", "onlyoffice"):
        raise ValueError("Retained resolution office backend changed")
    if plan["policy_sha256"] != policy_hash(policy, backend):
        raise ValueError("Version policy changed; retained resolution requires its original reviewed policy")
    effective = constraints(config, policy)
    if plan["constraints"] != effective or plan["target"] != target(policy, effective["freebsd_release"], effective["architecture"]):
        raise ValueError("Retained resolution constraints or target changed")
    discovered = {"schema_version": plan["schema_version"], "target": plan["target"], "repository": plan["repository"],
                  "nextcloud": [plan["applications"]["nextcloud"]], "packages": packages,
                  "sources": plan["sources"], "extra_roots": plan["roots"]}
    if backend != "onlyoffice":
        discovered["office_backend"] = backend
        if backend in VM_BACKENDS:
            discovered.update(connector_app=plan["connector_app"],
                              connectors={plan["applications"]["nextcloud"]: [plan["connector"]]},
                              artifacts={plan["profile"]: plan["artifacts"]})
    else:
        discovered.update(onlyoffice=[package_upstream(plan["applications"]["onlyoffice"])],
                          connectors={plan["applications"]["nextcloud"]: [plan["connector"]]},
                          fonts_unavailable=plan["fonts_unavailable"])
    pieces = compatibility.validate(config, discovered, plan["applications"]["nextcloud"], plan["applications"].get("onlyoffice"), policy=policy)
    for field, value in pieces.items():
        if plan[field] != value:
            raise ValueError(f"Retained resolution {field} no longer matches the reviewed policy/closure")
    evidence = policy["evidence"] + (next(p["evidence"] for p in selected_profiles(config, policy) if p["id"] == plan["profile"]) if backend in VM_BACKENDS else [])
    if not {item["url"] for item in evidence}.issubset(plan["sources"]) or NATIVE_WARNING not in plan["warnings"]:
        raise ValueError("Retained resolution is missing policy evidence or acceptance status")
    return deepcopy(plan)


def assess_upgrade(installed_plan, candidate):
    """Compare complete plans; never authorize or execute an upgrade/migration.

    A changed opaque dependency version cannot be ordered safely and is blocked.
    Unchanged opaque versions are valid identities, not guessed semver values.
    """
    _plan_inventory(installed_plan)
    _plan_inventory(candidate)
    changes, blockers = [], []
    old_backend = installed_plan.get("office_backend", "onlyoffice")
    new_backend = candidate.get("office_backend", "onlyoffice")
    if old_backend != new_backend:
        return {"schema_version": 1, "status": "blocked", "execution_authorized": False,
                "migration_supported": False,
                "changes": [{"component": "office_backend", "from": old_backend, "to": new_backend}],
                "blockers": ["Office backend changes require a separately reviewed migration"],
                "warnings": [MIGRATION_WARNING]}
    if old_backend in VM_BACKENDS:
        return {"schema_version": 1, "status": "blocked", "execution_authorized": False,
                "migration_supported": False, "changes": [],
                "blockers": ["VM backend upgrade/maintenance assessment is unsupported"], "warnings": [MIGRATION_WARNING]}

    def change(component, old, new, key=None):
        if old == new:
            return
        changes.append({"component": component, "from": deepcopy(old), "to": deepcopy(new)})
        if key is not None:
            try:
                if key(new) < key(old):
                    blockers.append(f"Downgrade refused for {component}: {old} -> {new}")
            except ValueError:
                blockers.append(f"Cannot safely order changed dependency {component}: {old} -> {new}")

    for field in ("target", "repository", "profile", "roles", "roots", "constraints", "policy_sha256", "connector", "fonts_unavailable"):
        if old_backend == "none" and field in ("connector", "fonts_unavailable"):
            continue
        change(field, installed_plan[field], candidate[field])
    old_target, new_target = installed_plan["target"], candidate["target"]
    if stable_version(new_target["release"].split("-")[0]) < stable_version(old_target["release"].split("-")[0]):
        blockers.append("FreeBSD release downgrade refused")
    if new_target["architecture"] != old_target["architecture"]:
        blockers.append("Architecture changes require a separately reviewed migration")
    for app in ("nextcloud",) if old_backend == "none" else ("nextcloud", "onlyoffice", "connector"):
        change("applications." + app, installed_plan["applications"][app], candidate["applications"][app],
               package_version if app == "onlyoffice" else stable_version)
    for group in ("host", "nextcloud") if old_backend == "none" else GROUPS:
        old, new = installed_plan["packages"][group], candidate["packages"][group]
        for name in sorted(old.keys() | new.keys()):
            component = f"packages.{group}.{name}"
            if name not in new:
                change(component, old[name], None)
                blockers.append(f"Installed dependency removal requires a reviewed migration: {component}")
            elif name not in old:
                change(component, None, new[name])
            else:
                change(component + ".version", old[name]["version"], new[name]["version"], package_version)
                for field in ("origin", "abi", "dependencies", "checksum"):
                    change(component + "." + field, old[name][field], new[name][field])
                if old[name]["origin"] != new[name]["origin"]:
                    blockers.append(f"Package origin changed for {component}; replacement identity is not established")
                if old[name]["version"] == new[name]["version"] and old[name]["dependencies"] != new[name]["dependencies"]:
                    blockers.append(f"Dependency metadata changed without a package version change: {component}")
                if old[name]["version"] == new[name]["version"] and old[name]["checksum"] != new[name]["checksum"]:
                    blockers.append(f"Same-version package checksum changed; manual review required: {component}")
    return {"schema_version": 1, "status": "blocked" if blockers else "manual-review",
            "execution_authorized": False, "migration_supported": False,
            "changes": changes, "blockers": blockers, "warnings": [MIGRATION_WARNING]}
