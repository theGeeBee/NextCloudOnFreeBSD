"""Pure M4 destination inspection, separate from installation compatibility policy.

``assess`` consumes trusted, captured observations, not operator assertions. The
adapter must obtain complete pkg inventories, CLI and both *running* FPM pool
environments, native DB/occ results, signed repository metadata and availability,
and manifests from the authenticated destination archive. It must bind/recheck
the graph, generation, network and executor under the host operation lock. This
module neither captures nor authenticates those inputs and performs no effects.

No installed-state solver recipe exists yet. The sole candidate preserves every
package record and has an empty transaction; even a solver receipt cannot enable
package changes. Archive availability is distinct from signed catalog identity.
Eligibility permits inert staging only. No result or caller-supplied proof bit
can grant native execution. Reassess against freshly captured inputs before use.
"""

from copy import deepcopy
import hashlib
import json
import re

from . import compatibility, resolution
from .versions import (GROUPS, NAME, ORIGIN, TRIPLE, load_policy, object_fields,
                       package_upstream, text)


RECIPE_ID = "nc-35.0.1-to-35.0.2-inspection-v1"
MAX_OBSERVATION_AGE = 300
MAX_CATALOG_AGE = 3600
BINDING_FIELDS = ("config_sha256", "versions_sha256", "graph_sha256",
                  "generation_sha256", "network_sha256", "executor_sha256")
PHP_CONTEXTS = ("cli", "main_fpm", "callback_fpm")
# Original vendor build labels in the authenticated stable NC 35.0.1 tarball
# (SHA256 7ed305e880192d804ba83179a19dd22257679608d63161a611ce3f8a918d2aa6).
# Observation of these exact already-installed shipped labels is not selection
# of a prerelease. Destination/core/package/connector versions stay strict.
SOURCE_SHIPPED_BUILD_LABELS = {
    **dict.fromkeys(("admin_audit appstore cloud_federation_api comments contactsinteraction federation "
                    "files_external files_reminders files_trashbin files_versions lookup_server_connector "
                    "oauth2 profile provisioning_api settings sharebymail systemtags twofactor_backupcodes "
                    "updatenotification user_ldap user_status weather_status webhook_listeners").split(), "2.0.0-dev.0"),
    **dict.fromkeys("dav federatedfilesharing files_sharing".split(), "2.0.0-dev.1"),
    **dict.fromkeys("encryption files theming workflowengine".split(), "3.0.0-dev.0"),
    "dashboard": "8.0.0-dev.0",
}
# Required core/built-in modules cannot be inferred from installed php85-* ports.
# Extension-package names below are mapped separately to actual loaded modules.
BUILTIN_MODULES = ("core", "date", "hash", "json", "libxml", "openssl", "pcre",
                   "random", "reflection", "spl", "standard", "zend opcache")
EVIDENCE = tuple(
    {"url": url, "reviewed": "2026-10-15", "scope": scope}
    for url, scope in (
        ("https://github.com/nextcloud/server/blob/v35.0.2/lib/versioncheck.php",
         "PHP >=8.3 <8.6; byte-identical to v35.0.1, not a higher-PHP recipe."),
        ("https://github.com/nextcloud/server/blob/v35.0.1/lib/versioncheck.php",
         "Exact source PHP gate."),
        ("https://github.com/nextcloud/server/blob/v35.0.2/apps/settings/lib/SetupChecks/SupportedDatabase.php",
         "MariaDB supported major/minor 10.11 through 12.3; this recipe retains 12.3."),
        ("https://github.com/nextcloud/server/blob/v35.0.2/version.php",
         "Destination public 35.0.2, internal 35.0.2.2."),
        ("https://github.com/nextcloud/server/blob/v35.0.1/version.php",
         "Source public 35.0.1, internal 35.0.1.1."),
        ("https://github.com/nextcloud/server/blob/v35.0.2/apps/settings/lib/SetupChecks/PhpModules.php",
         "Tagged PHP module requirements unchanged from v35.0.1."),
        ("https://github.com/nextcloud/server/blob/v35.0.2/composer.json",
         "Tagged composer requirements byte-identical to v35.0.1."),
        ("https://github.com/ONLYOFFICE/onlyoffice-nextcloud/blob/v10.2.1/appinfo/info.xml",
         "Retained connector 10.2.1: PHP >=8.2 <8.6 and Nextcloud >=33 <36."),
        ("https://github.com/nextcloud/serverinfo/blob/v35.0.2/appinfo/info.xml",
         "Destination shipped serverinfo is 7.0.0."),
    )
)


def source_app_label(name, value):
    """Read fixed-source shipped metadata; never use for target discovery/bounds."""
    return (type(name) is str and type(value) is str and (re.fullmatch(TRIPLE, value) is not None
                                   or SOURCE_SHIPPED_BUILD_LABELS.get(name) == value))


def digest(value):
    """Canonical JSON input identity; never include raw observations in reports."""
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode()).hexdigest()


def recipe():
    """A fixed inspection schema, deliberately not a resolved installation plan."""
    return {"schema_version": 1, "id": RECIPE_ID,
            "target": {"release": "15.1-RELEASE", "architecture": "amd64", "abi": "FreeBSD:15:amd64"},
            "source": {"public": "35.0.1", "internal": "35.0.1.1"},
            "destination": {"public": "35.0.2", "internal": "35.0.2.2"},
            "php": {"min": "8.3.0", "max_exclusive": "8.6.0"},
            "retained_php_family": "8.5", "retained_database_family": "12.3",
            "onlyoffice": "9.4.0_4", "connector": "10.2.1",
            "package_changes": "forbidden", "native_acceptance": "not-run",
            "execution_authorized": False, "evidence": deepcopy(list(EVIDENCE))}


def required_modules(policy=None, profile=None):
    policy = load_policy() if policy is None else policy
    selected = [item for item in policy["profiles"]
                if item.get("office_backend", "onlyoffice") == "onlyoffice"
                and (profile is None or item["id"] == profile)]
    if len(selected) != 1:
        raise ValueError("Ambiguous runtime module profile")
    names = set(BUILTIN_MODULES)
    for template in selected[0]["php_extensions"]:
        name = template.split("}-", 1)[1].lower()
        names.add(name.removeprefix("pecl-"))
    return sorted(names)


def _fields(value, fields):
    object_fields(value, fields.split())


def _sha(value):
    text(value, r"[a-f0-9]{64}", "digest")


def _schema(value):
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ValueError("Unsupported schema")


def _fresh(value, now, age):
    if type(value) is not int or not 0 <= now - value <= age:
        raise ValueError("Stale observation")


def _actual_packages(value, retained):
    """The native deploy inventory is complete name/version/origin rows.

    Installed pkg rows do not prove an archive checksum. Only exact signed
    repository metadata and independently observed archive availability do that.
    Host extras are captured/bound but are outside the managed ports closure;
    jail extras are limited to pkg and exact reserved pkgbase name/origin pairs.
    """
    object_fields(value, GROUPS)
    for group in GROUPS:
        rows = value[group]
        if not isinstance(rows, list) or not rows:
            raise ValueError("Missing actual inventory")
        actual = {}
        for row in rows:
            _fields(row, "name version origin")
            text(row["name"], NAME, "package")
            text(row["version"], compatibility.VERSION, "package version")
            text(row["origin"], ORIGIN, "package origin")
            if row["name"] in actual:
                raise ValueError("Ambiguous actual inventory")
            actual[row["name"]] = row
        for name, record in retained["packages"][group].items():
            if actual.get(name) != {key: record[key] for key in ("name", "version", "origin")}:
                raise ValueError("Installed package drift")
        if group != "host":
            for name in actual.keys() - retained["packages"][group].keys():
                origin = actual[name]["origin"]
                if not ((name == "pkg" and origin == "ports-mgmt/pkg") or
                        (re.fullmatch(r"FreeBSD-[A-Za-z0-9_+.-]+", name) and origin == "base/" + name)):
                    raise ValueError("Unmanaged jail package")


def _php(value, retained, policy):
    object_fields(value, PHP_CONTEXTS)
    expected = package_upstream(retained["packages"]["nextcloud"][retained["roles"]["php"]]["version"])
    required = set(required_modules(policy, retained["profile"]))
    module_sets = []
    for context in PHP_CONTEXTS:
        record = value[context]
        _fields(record, "version sapi integer_size loaded_modules")
        text(record["version"], TRIPLE, "PHP version")
        if (record["version"] != expected or not expected.startswith("8.5.")
                or not compatibility.in_range(record["version"], recipe()["php"])
                or record["sapi"] != ("cli" if context == "cli" else "fpm-fcgi")
                or type(record["integer_size"]) is not int or record["integer_size"] != 8):
            raise ValueError("Unsupported or mismatched PHP")
        modules = record["loaded_modules"]
        if not isinstance(modules, list) or not modules:
            raise ValueError("Missing loaded modules")
        for name in modules:
            if name == "cgi-fcgi":
                if context == "cli":
                    raise ValueError("Unexpected CGI module in CLI runtime")
            else:
                text(name, r"[A-Za-z][A-Za-z0-9_ ]{0,63}", "loaded module")
        normalized = {name.lower() for name in modules}
        if len(normalized) != len(modules) or not required.issubset(normalized):
            raise ValueError("Required modules not loaded")
        # FPM advertises this SAPI marker; it is not a CLI-loadable extension.
        # Keep the raw inventory and required-module checks, excluding only the
        # marker from cross-context extension parity.
        module_sets.append(normalized - {"cgi-fcgi"})
    if any(modules != module_sets[0] for modules in module_sets):
        raise ValueError("PHP environments disagree")


def _database(value, retained):
    _fields(value, "vendor version isolation engines")
    expected = package_upstream(retained["packages"]["nextcloud"][retained["roles"]["database"]]["version"])
    if (value["vendor"] != "MariaDB" or value["version"] != expected
            or not expected.startswith("12.3.") or value["isolation"] != "READ-COMMITTED"
            or value["engines"] != ["InnoDB"]):
        raise ValueError("Database runtime is unsupported")


def _apps(value, manifests, artifact, php):
    """Manifest projection from authenticated source/target archives, no app values.

    Shipped apps require a paired source version and target manifest bound to the
    destination archive. The only retained non-shipped app reviewed here is the
    signed ONLYOFFICE connector; its observed artifact hash comes from the
    revalidated installed signature/retained archive receipt, never its version
    string alone. Unknown/custom apps, even disabled, fail closed.
    """
    if not isinstance(value, dict) or not value or not isinstance(manifests, dict):
        raise ValueError("Missing application inventory")
    if set(value) != set(manifests) or not {"onlyoffice", "serverinfo"}.issubset(value):
        raise ValueError("Application compatibility unknown")
    for name, app in value.items():
        text(name, r"[a-z][a-z0-9_]{0,63}", "app identifier")
        _fields(app, "version enabled provenance" + (" artifact_sha256" if name == "onlyoffice" else ""))
        if not source_app_label(name, app["version"]):
            raise ValueError("Invalid original application build label")
        if type(app["enabled"]) is not bool:
            raise ValueError("Invalid app state")
        manifest = manifests[name]
        _fields(manifest, "source_version version phpVersionSpec platformVersionSpec delivery artifact_sha256")
        if manifest["source_version"] != app["version"]:
            raise ValueError("Application version drift")
        text(manifest["version"], TRIPLE, "destination app version")
        for field, version in (("phpVersionSpec", php), ("platformVersionSpec", "35.0.2")):
            if not compatibility.in_range(version, compatibility.version_spec(manifest[field])):
                raise ValueError("Incompatible application")
        if name == "onlyoffice":
            if (app != {"version": "10.2.1", "enabled": True, "provenance": "appstore",
                        "artifact_sha256": artifact["connector"]["sha256"]}
                    or manifest["version"] != "10.2.1" or manifest["delivery"] != "retained"
                    or manifest["artifact_sha256"] != artifact["connector"]["sha256"]
                    or manifest["phpVersionSpec"] != ">=8.2.0 <8.6.0"
                    or manifest["platformVersionSpec"] != ">=33.0.0 <36.0.0"):
                raise ValueError("Connector drift")
        elif (app["provenance"] != "shipped" or manifest["delivery"] != "shipped"
              or manifest["artifact_sha256"] != artifact["nextcloud"]["sha256"]):
            raise ValueError("Unreviewed non-shipped application")
        if name == "serverinfo" and (app["version"] != "7.0.0" or manifest["version"] != "7.0.0"):
            raise ValueError("Wrong target serverinfo manifest")


def _repository(value, retained, bindings, now):
    _fields(value, "schema_version captured_at bindings target repository catalog_sha256 "
                  "trust packages available_packages artifacts apps package_transaction solver_receipt")
    _schema(value)
    _fresh(value["captured_at"], now, MAX_CATALOG_AGE)
    _sha(value["catalog_sha256"])
    # This is an adapter provenance discriminator, not verification by this module.
    if (value["bindings"] != bindings or value["target"] != retained["target"]
            or value["repository"] != retained["repository"]
            or value["trust"] != "native-pkg-signed-catalog"):
        raise ValueError("Repository provenance mismatch")
    compatibility.inventory(value["packages"], retained["target"]["abi"])
    if not isinstance(value["available_packages"], dict):
        raise ValueError("Missing archive availability")
    for name, checksum in value["available_packages"].items():
        text(name, NAME, "available archive")
        text(checksum, compatibility.CHECKSUM, "archive checksum")
        if name not in value["packages"] or checksum != value["packages"][name]["checksum"]:
            raise ValueError("Archive/catalog checksum mismatch")
    for group in GROUPS:
        selected = compatibility.closure(value["packages"], retained["roots"][group])
        if selected != retained["packages"][group]:
            raise ValueError("Package closure changed")
        for name, record in selected.items():
            if value["available_packages"].get(name) != record["checksum"]:
                raise ValueError("Exact archive unavailable")
    object_fields(value["artifacts"], ("nextcloud", "connector"))
    for kind, version, provenance in (("nextcloud", "35.0.2", "authenticated-release"),
                                      ("connector", "10.2.1", "appstore-sha512-signature")):
        artifact = value["artifacts"][kind]
        _fields(artifact, "version sha256 available_sha256 provenance" +
                (" internal_version" if kind == "nextcloud" else ""))
        _sha(artifact["sha256"])
        if (artifact["version"] != version or artifact["provenance"] != provenance
                or artifact["available_sha256"] != artifact["sha256"]):
            raise ValueError("Application artifact unavailable or changed")
        if kind == "nextcloud" and artifact["internal_version"] != "35.0.2.2":
            raise ValueError("Wrong destination internal version")


def assess(config, retained_plan, observations, repository, *, bindings, now, target="35.0.2"):
    """Return normalized blockers or an exact, non-executable staging candidate.

    All timestamps are integer Unix seconds supplied by the trusted adapter;
    future captures are rejected. Binding hashes are canonical JSON digests;
    config is hashed from ``json.loads(config.to_json())``. No raw input values or
    exception diagnostics are emitted, including on malformed nested records.
    """
    blockers = set()

    def check(code, callback):
        try:
            callback()
            return True
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
            blockers.add(code)
            return False

    result = {"schema_version": 1, "recipe": RECIPE_ID, "status": "blocked",
              "eligible": False, "execution_authorized": False,
              "native_acceptance": "not-run", "execution_blockers": ["native-recipe-unaccepted"],
              "blockers": [], "candidate": None}
    if type(now) is not int or now < 0:
        blockers.add("invalid-assessment-time")
    if target != "35.0.2":
        blockers.add("unreviewed-destination")

    policy = load_policy()

    def source():
        config.validate()
        resolution.validate_plan(config, retained_plan, policy)
        # Validate the source under its original constraints before compiling the
        # sole reviewed proposed target. An explicit source pin stays bound to
        # the captured config; the candidate grants no execution authority.
        from .maintenance_generations import target_plan
        target_plan(config.to_json().encode(), retained_plan)

    source_ok = check("source-plan-incompatible", source)

    def bound():
        object_fields(bindings, BINDING_FIELDS)
        for value in bindings.values():
            _sha(value)
        if (bindings["config_sha256"] != digest(json.loads(config.to_json()))
                or bindings["versions_sha256"] != digest(retained_plan)):
            raise ValueError("Input binding mismatch")

    check("source-binding-mismatch", bound)

    def observed():
        _fields(observations, "schema_version captured_at bindings packages php database nextcloud integrations")
        _schema(observations)
        _fresh(observations["captured_at"], now, MAX_OBSERVATION_AGE)
        if observations["bindings"] != bindings:
            raise ValueError("Observation source mismatch")

    observation_ok = check("observations-missing-stale-or-unbound", observed)
    if source_ok and observation_ok:
        check("installed-package-drift", lambda: _actual_packages(observations["packages"], retained_plan))
        check("php-runtime-incompatible", lambda: _php(observations["php"], retained_plan, policy))
        check("database-runtime-incompatible", lambda: _database(observations["database"], retained_plan))

        def ready():
            nc = observations["nextcloud"]
            _fields(nc, "installed maintenance needsDbUpgrade version versionstring apps")
            if (nc["installed"] is not True or nc["maintenance"] is not False
                    or nc["needsDbUpgrade"] is not False or nc["version"] != "35.0.1.1"
                    or nc["versionstring"] != "35.0.1"):
                raise ValueError("Nextcloud source not ready")

        check("nextcloud-not-ready-or-drifted", ready)

        def integrations():
            _fields(observations["integrations"], "external_storage unmanaged_integrations")
            if any(value is not False for value in observations["integrations"].values()):
                raise ValueError("Unreviewed external integration")

        check("unsupported-integration", integrations)

    repository_ok = source_ok and check("repository-or-artifact-unavailable",
        lambda: _repository(repository, retained_plan, bindings, now))
    if isinstance(repository, dict):
        if repository.get("package_transaction") != [] or repository.get("solver_receipt") is not None:
            blockers.add("package-transaction-unsupported")
    if repository_ok and observation_ok:
        check("application-compatibility-unknown", lambda: _apps(
            observations["nextcloud"]["apps"], repository["apps"], repository["artifacts"],
            package_upstream(retained_plan["packages"]["nextcloud"][retained_plan["roles"]["php"]]["version"])))
    result["blockers"] = sorted(blockers)
    if not blockers:
        result.update(status="staging-only", eligible=True)
        result["candidate"] = {
            "schema_version": 1, "kind": "destination-inspection-candidate", "recipe": recipe(),
            "bindings": deepcopy(bindings), "observations_sha256": digest(observations),
            "repository_sha256": digest(repository), "packages": deepcopy(retained_plan["packages"]),
            "roots": deepcopy(retained_plan["roots"]), "artifacts": deepcopy(repository["artifacts"]),
            "apps": deepcopy(repository["apps"]), "package_transaction": [],
            "execution_authorized": False}
    return result


def revalidate(candidate, config, retained_plan, observations, repository, *, bindings, now):
    """Recompute eligibility; a saved JSON eligibility/permission bit is not proof."""
    fresh = assess(config, retained_plan, observations, repository, bindings=bindings, now=now)
    if not fresh["eligible"] or candidate != fresh["candidate"]:
        raise ValueError("Destination inspection inputs changed or candidate is ineligible")
    return fresh
