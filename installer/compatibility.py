"""Pure, fail-closed application/profile and exact package-graph checks."""

from copy import deepcopy
import re
from urllib.parse import urlsplit

from .versions import (GROUPS, NAME, ORIGIN, TRIPLE, VM_BACKENDS, CONNECTOR_APPS, connector_php_spec, constraints, in_range,
                       in_family, load_policy, object_fields, office_backend, package_upstream, selected_profiles,
                       satisfies, stable_version, target, text, validate_policy, validate_runtime_artifacts)


VERSION = r"[A-Za-z0-9._+][A-Za-z0-9_+.,~:-]*"
CHECKSUM = r"(?=.{1,256}\Z)(?:[0-9]+\$[A-Za-z0-9]+|[A-Fa-f0-9]{64})"


def profile_roots(config, profile):
    """Names/origins to query, before repository-specific origin resolution."""
    roots = deepcopy(profile["roots"])
    for rule in profile["roles"].values():
        for group in rule["groups"]:
            roots[group].append(rule["package"])
    roots["nextcloud"].extend(name.replace("{suffix}", profile["php_suffix"])
                              for name in profile["php_extensions"])
    features = {"acme": getattr(config, "tls_mode", "acme") == "acme",
                "zsh": getattr(config, "jail_ssh", False) and getattr(config, "ssh_shell", "sh") == "zsh",
                "ssh_admin": getattr(config, "jail_ssh", False) and getattr(config, "ssh_admin", False),
                "antivirus": getattr(config, "antivirus", False)}
    for feature, enabled in features.items():
        if enabled:
            if feature not in profile["optional_roots"]:
                raise ValueError(f"Selected profile has no reviewed package roots for {feature}")
            for group, names in profile["optional_roots"][feature].items():
                roots[group].extend(names)
    return {group: sorted(set(names)) for group, names in roots.items()}


def package_roots(config, policy=None):
    """Union of target profiles' required names/origins for discovery adapters."""
    policy = load_policy() if policy is None else validate_policy(policy)
    backend = office_backend(config)
    roots = {group: set() for group in (GROUPS if backend == "onlyoffice" else ("host", "nextcloud"))}
    for profile in selected_profiles(config, policy):
        for group, names in profile_roots(config, profile).items():
            roots[group].update(names)
    if backend == "onlyoffice":
        roots["onlyoffice"].update(policy["fonts"]["required"])
    return {group: sorted(names) for group, names in roots.items()}


def inventory(packages, abi):
    if not isinstance(packages, dict) or not packages:
        raise ValueError("A nonempty, unambiguous package inventory is required")
    for name, record in packages.items():
        text(name, NAME, "package name")
        object_fields(record, ("name", "version", "origin", "abi", "checksum", "dependencies"), label="package " + name)
        if record["name"] != name:
            raise ValueError(f"Package identity does not match inventory key: {name}")
        text(record["version"], VERSION, "package version")
        text(record["origin"], ORIGIN, "package origin")
        text(record["abi"], r"FreeBSD:[0-9]+:(?:[a-z0-9]+|\*)", "package ABI")
        text(record["checksum"], CHECKSUM, "package checksum")
        # pkg NO_ARCH packages legitimately carry a wildcard architecture.
        if any(actual not in (expected, "*") for actual, expected in zip(record["abi"].split(":"), abi.split(":"))):
            raise ValueError(f"Wrong ABI for {name}: {record['abi']}; expected {abi}")
        if not isinstance(record["dependencies"], dict):
            raise ValueError(f"Ambiguous or malformed dependency map for {name}")
        for dependency, required in record["dependencies"].items():
            text(dependency, NAME, "dependency name")
            object_fields(required, ("version", "origin"), label="dependency " + dependency)
            text(required["version"], VERSION, "dependency version")
            text(required["origin"], ORIGIN, "dependency origin")
    return packages


def closure(packages, roots):
    """Exact version/origin closure; a cycle is finite and does not hide missing nodes."""
    result, pending = {}, list(roots)
    while pending:
        name = pending.pop()
        if name in result:
            continue
        if name not in packages:
            raise ValueError(f"Required package {name} is unavailable; refresh discovery or select a supported repository")
        record = packages[name]
        result[name] = deepcopy(record)
        for dependency, required in record["dependencies"].items():
            offered = packages.get(dependency)
            if offered is None or any(offered[field] != required[field] for field in ("version", "origin")):
                raise ValueError(f"Missing/conflicting dependency {name} -> {dependency}-{required['version']} ({required['origin']})")
            pending.append(dependency)
    return {name: result[name] for name in sorted(result)}


def discovered_inputs(config, discovered, policy):
    backend = office_backend(config)
    none, vm = backend == "none", backend in VM_BACKENDS
    common = ("schema_version", "target", "repository", "nextcloud", "packages", "sources")
    extra = ("office_backend",) if none else ("office_backend", "connector_app", "connectors", "artifacts") if vm else ("onlyoffice", "connectors")
    object_fields(discovered, common + extra,
                  ("extra_roots", "fonts_unavailable") if backend == "onlyoffice" else ("extra_roots",), label="discovery result")
    if type(discovered["schema_version"]) is not int or discovered["schema_version"] != (3 if vm else 2 if none else 1):
        raise ValueError("Unsupported discovery schema")
    if backend != "onlyoffice" and discovered["office_backend"] != backend:
        raise ValueError("Discovery office backend does not match configuration")
    if vm and (discovered["connector_app"] != CONNECTOR_APPS[backend] or not isinstance(discovered["artifacts"], dict)):
        raise ValueError("VM discovery connector/artifact context does not match backend")
    effective = constraints(config, policy)
    expected = target(policy, effective["freebsd_release"], effective["architecture"])
    if discovered["target"] != expected:
        raise ValueError("Discovered target does not match the selected release/architecture/ABI")
    if discovered["repository"] not in ("latest", "quarterly") or discovered["repository"] != getattr(config, "repository", None):
        raise ValueError("Discovered repository does not match configuration")
    for field in ("nextcloud", "onlyoffice", "sources") if backend == "onlyoffice" else ("nextcloud", "sources"):
        values = discovered[field]
        if not isinstance(values, list) or not values:
            raise ValueError(f"Discovery requires nonempty {field}")
        for value in values:
            text(value, r"[^\x00-\x1f\x7f]+", "discovered " + field)
    if not none and not isinstance(discovered["connectors"], dict):
        raise ValueError("Discovery requires per-Nextcloud connector metadata")
    for version, records in discovered.get("connectors", {}).items():
        text(version, TRIPLE, "connector platform version")
        if not isinstance(records, list):
            raise ValueError("Connector releases must be a list")
    if "fonts_unavailable" in discovered:
        missing = discovered["fonts_unavailable"]
        if not isinstance(missing, list):
            raise ValueError("Missing-font metadata must be a list of package names")
        for name in missing:
            text(name, NAME, "unavailable font package")
        if len(missing) != len(set(missing)):
            raise ValueError("Duplicate unavailable font package")
    inventory(discovered["packages"], expected["abi"])
    return effective


def _resolve_roots(requirements, packages):
    roots = {}
    for group, names in requirements.items():
        selected = []
        for name in names:
            if "/" in name:
                matches = [key for key, record in packages.items() if record["origin"] == name]
                if len(matches) != 1:
                    raise ValueError(f"Required origin {name} is missing or ambiguous in the selected repository")
                name = matches[0]
            selected.append(name)
        roots[group] = sorted(set(selected))
    return roots


def version_spec(value):
    """Only an inclusive numeric floor plus an exclusive ceiling is understood."""
    text(value, r">=(" + TRIPLE + r") +<(" + TRIPLE + ")", "connector version specification (>=N.N.N <N.N.N)")
    lower, upper = re.fullmatch(r">=(" + TRIPLE + r") +<(" + TRIPLE + ")", value).groups()
    if stable_version(lower) >= stable_version(upper):
        raise ValueError("Connector version specification is empty or reversed")
    return {"min": lower, "max_exclusive": upper}


def connector_record(record, app_id="onlyoffice"):
    if app_id not in CONNECTOR_APPS.values():
        raise ValueError("Unsupported integrated connector ID")
    object_fields(record, ("version", "phpVersionSpec", "platformVersionSpec", "isNightly",
                           "signatureDigest", "download", "signature", "certificate"), label="signed connector release")
    text(record["version"], TRIPLE, "stable connector version")
    if record["isNightly"] is not False or record["signatureDigest"] != "sha512":
        raise ValueError("Connector must be stable and carry a sha512 app-store signature")
    if app_id == "onlyoffice":
        version_spec(record["phpVersionSpec"])
    else:
        connector_php_spec(record["phpVersionSpec"])
    version_spec(record["platformVersionSpec"])
    text(record["download"], r"https://[^\s]+", "connector HTTPS download")
    parsed = urlsplit(record["download"])
    if not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise ValueError("Invalid connector download identity")
    for field in ("signature", "certificate"):
        value = record[field]
        if not isinstance(value, str) or not value.strip() or len(value) > 65536 or "\0" in value:
            raise ValueError(f"Missing or malformed connector {field}")
    return record


def connector_php_allows(version, declaration):
    connector_php_spec(declaration)
    if declaration == "*":
        return True
    if " <" in declaration:
        return in_range(version, version_spec(declaration))
    return stable_version(package_upstream(version)) >= stable_version(declaration[2:])


def _connector(discovered, profile, nextcloud, php, families=None):
    records = discovered["connectors"].get(nextcloud)
    if not records:
        raise ValueError(f"Missing signed connector metadata for Nextcloud {nextcloud}; refine the exact pin or refresh discovery")
    selected, occurrences = [], {}
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("Malformed connector release record")
        try:
            text(record.get("version"), TRIPLE, "connector release")
        except ValueError:
            continue
        if not in_range(record["version"], profile["connector"]["version"]) or record.get("isNightly") is True:
            continue
        if families and "connector" in families and not in_family(record["version"], families["connector"]):
            continue
        app_id = profile["connector"].get("app_id", "onlyoffice")
        connector_record(record, app_id)
        occurrences[record["version"]] = occurrences.get(record["version"], 0) + 1
        for field, role, version in (("platformVersionSpec", "nextcloud", nextcloud),) if app_id != "onlyoffice" else (("platformVersionSpec", "nextcloud", nextcloud), ("phpVersionSpec", "php", php)):
            bounds = version_spec(record[field])
            if "family" not in profile["connector"]["version"] and bounds != profile["connector"][role]:
                raise ValueError(f"Connector {role} requirements differ from reviewed manifest")
        if "family" not in profile["connector"]["version"] and app_id != "onlyoffice" and record["phpVersionSpec"] != profile["connector"]["php_manifest"]:
            raise ValueError("Connector PHP declaration differs from reviewed manifest")
        if (not in_range(nextcloud, version_spec(record["platformVersionSpec"]))
                or not connector_php_allows(php, record["phpVersionSpec"])):
            continue
        selected.append(record)
    if selected and "family" in profile["connector"]["version"]:
        newest = max(stable_version(record["version"]) for record in selected)
        selected = [record for record in selected if stable_version(record["version"]) == newest]
    if len(selected) != 1 or occurrences[selected[0]["version"]] != 1:
        raise ValueError("No unique obtainable signed connector matches the reviewed compatibility profile")
    return deepcopy(selected[0])


def family_constraints(families, applications, roles, packages):
    """Recheck families against selected identities, including retained locks."""
    for component, family in families.items():
        if component in applications:
            if not in_family(applications[component], family):
                raise ValueError(f"Application {component} is outside configured family {family}")
            continue
        names = [roles[component]] if component in roles else [component]
        if component == "database":
            names.append(roles["database_client"])
        for name in names:
            if name not in packages:
                raise ValueError(f"Version family component/package {component} is not selected")
            if not in_family(packages[name]["version"], family):
                raise ValueError(f"Package {name}-{packages[name]['version']} is outside configured {component} family {family}")


def validate(config, discovered, nextcloud, onlyoffice=None, *, policy=None):
    """Return the selected profile, roles, roots and complete per-group inventories."""
    policy = load_policy() if policy is None else validate_policy(policy)
    effective = discovered_inputs(config, discovered, policy)
    backend = office_backend(config)
    none, vm = backend == "none", backend in VM_BACKENDS
    text(nextcloud, TRIPLE, "Nextcloud release")
    if backend != "onlyoffice":
        if onlyoffice is not None:
            raise ValueError("No native ONLYOFFICE version is permitted for this backend")
    else:
        upstream = package_upstream(onlyoffice)  # Reject pre-release application packages.
        text(upstream, TRIPLE, "ONLYOFFICE upstream release")
        if upstream not in discovered["onlyoffice"]:
            raise ValueError("ONLYOFFICE package upstream version is absent from stable release discovery")
    if nextcloud not in discovered["nextcloud"]:
        raise ValueError("Selected Nextcloud release is absent from discovery")
    applications = (("nextcloud", nextcloud), ("onlyoffice", onlyoffice)) if backend == "onlyoffice" else (("nextcloud", nextcloud),)
    if not all(satisfies(value, app, effective) for app, value in applications):
        raise ValueError("Application selection violates configured minima or exact pins")
    profiles = [profile for profile in selected_profiles(config, policy)
                if in_range(nextcloud, profile["applications"]["nextcloud"])
                and (backend != "onlyoffice" or in_range(onlyoffice, profile["applications"]["onlyoffice"]))]
    if len(profiles) != 1:
        selection = f"Nextcloud {nextcloud}" + (f", ONLYOFFICE {onlyoffice}" if backend == "onlyoffice" else f", office_backend={backend}")
        raise ValueError(f"No unique reviewed compatibility profile for {selection}; update reviewed policy or select supported versions")
    profile, packages = profiles[0], discovered["packages"]
    roles = {role: rule["package"] for role, rule in profile["roles"].items()}
    for role, rule in profile["roles"].items():
        record = packages.get(rule["package"])
        if record is None or record["origin"] != rule["origin"]:
            raise ValueError(f"Missing or wrong-origin {role} package: {rule['package']}")
        if "range" in rule and not in_range(record["version"], rule["range"]):
            raise ValueError(f"Incompatible {role} version {record['version']}; reviewed rule: {rule['range']}")
        if "version_exact" in rule and record["version"] != rule["version_exact"]:
            raise ValueError(f"Incompatible exact {role} package version")
    if backend == "onlyoffice" and packages[roles["onlyoffice"]]["version"] != onlyoffice:
        raise ValueError("Selected ONLYOFFICE version is not the available package; older repository versions cannot be assumed obtainable")
    if packages[roles["database"]]["version"] != packages[roles["database_client"]]["version"]:
        raise ValueError("Database server/client packages must have matching versions")
    for template in profile["php_extensions"]:
        name = template.replace("{suffix}", profile["php_suffix"])
        extension = packages.get(name)
        expected_php = {key: packages[roles["php"]][key] for key in ("version", "origin")}
        if extension is None or extension["dependencies"].get(roles["php"]) != expected_php:
            raise ValueError(f"PHP extension {name} lacks a matching runtime dependency; flavor compatibility cannot be established")
        if template in profile["extension_ranges"] and not in_range(extension["version"], profile["extension_ranges"][template]):
            raise ValueError(f"PHP extension {name} is outside its reviewed compatibility range")
    connector = None if none else _connector(discovered, profile, nextcloud, packages[roles["php"]]["version"], effective.get("version_families"))
    requirements = profile_roots(config, profile)
    if backend == "onlyoffice":
        requirements["onlyoffice"].extend(policy["fonts"]["required"])
    fonts_unavailable = []
    if backend == "onlyoffice" and getattr(config, "font_profile", "comprehensive") == "comprehensive":
        for name in policy["fonts"]["optional"]:
            if name in packages:
                requirements["onlyoffice"].append(name)
            else:
                fonts_unavailable.append(name)
    if "fonts_unavailable" in discovered and sorted(discovered["fonts_unavailable"]) != sorted(fonts_unavailable):
        raise ValueError("Discovered missing-font report disagrees with the package inventory")
    roots = _resolve_roots(requirements, packages)
    extras = discovered.get("extra_roots", {})
    object_fields(extras, (), tuple(requirements), label="extra root groups")
    for group, names in extras.items():
        if not isinstance(names, list) or len(names) != len(set(map(str, names))):
            raise ValueError("Extra roots must be unique package names")
        for name in names:
            text(name, NAME, "extra root name")
            if name in roots[group]:
                continue
            raise ValueError(f"Unapproved extra root {group}/{name}; select roots through the reviewed policy")
        roots[group] = sorted(roots[group])
    selected = {group: closure(packages, names) for group, names in roots.items()}
    # Constraints never add packages or replace pkg's dependency solution. Apply
    # optional names only to the authenticated closure that will actually install.
    merged = {name: record for group in selected.values() for name, record in group.items()}
    family_constraints(effective.get("version_families", {}),
                       dict(applications, **({"connector": connector["version"]} if connector else {})), roles, merged)
    if backend == "onlyoffice" and "webfonts" in selected["onlyoffice"] and not getattr(config, "accept_microsoft_fonts", False):
        raise ValueError("ONLYOFFICE requires webfonts: review docs/fonts.md and set accept_microsoft_fonts after accepting its EULA")
    if none:
        return {"profile": profile["id"], "roles": roles, "roots": roots, "packages": selected}
    if vm:
        proof = discovered["artifacts"].get(profile["id"])
        if isinstance(proof, dict) and proof.get("unavailable") is True:
            raise ValueError("Pinned VM image/container metadata is unavailable")
        validate_runtime_artifacts(profile["office_runtime"], proof)
        return {"profile": profile["id"], "roles": roles, "roots": roots, "packages": selected,
                "connector": connector, "connector_app": CONNECTOR_APPS[backend],
                "office_runtime": deepcopy(profile["office_runtime"]), "artifacts": deepcopy(proof)}
    return {"profile": profile["id"], "roles": roles, "roots": roots, "packages": selected,
            "connector": connector, "fonts_unavailable": sorted(fonts_unavailable)}
