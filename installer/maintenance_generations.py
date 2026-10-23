"""One compiled, source-bound successor format; no migration/recipe admission.

Only NC 35.0.1 -> 35.0.2 is representable. Installation selection is unchanged.
Target files and observed validation receipts are supplied by the trusted native
adapter, never captured or executed here. Storing them grants no boot, migration
or publication permission. The native recipe catalog remains independently empty.
"""

from copy import deepcopy
from dataclasses import replace

from . import compatibility, maintenance_preflight as candidate_policy, resolution
from .config import Config
from .generations import (MAX_ARCHIVE_BYTES, MAX_FILE_BYTES, _digest,
                          _encode, _fields, _hash, _id, _json, _reference, _schema)
from .paths import PROJECT_ROOT, RESOURCES
from .versions import constraints, load_policy, policy_hash, validate_policy


KIND = "maintenance-generation"
EVIDENCE = {"candidate.json", "review.json", "effective.json", "readiness.json"}
PUBLIC_FILES = ("runtime.json", "packages.lock", "packages.dependencies", "connector.json", "fonts-unavailable")
TARGET_FILES = {"config.json", "versions.json", "policy.json"} | {
    group + "/" + filename for group in ("nextcloud", "onlyoffice") for filename in PUBLIC_FILES}


def destination_policy():
    """Compile the single exact destination from this artifact's base policy.

    No policy argument, caller-supplied bounds, runtime selection or widened
    installation resource is accepted. Context/source binding is checked below.
    """
    policy = deepcopy(load_policy())
    policy["profiles"] = [item for item in policy["profiles"]
                          if item.get("office_backend", "onlyoffice") == "onlyoffice"]
    recipe = candidate_policy.recipe()
    if (recipe["id"] != "nc-35.0.1-to-35.0.2-inspection-v1"
            or recipe["source"] != {"public": "35.0.1", "internal": "35.0.1.1"}
            or recipe["destination"] != {"public": "35.0.2", "internal": "35.0.2.2"}
            or len(policy["profiles"]) != 1):
        raise ValueError("Unsupported compiled maintenance policy")
    profile = policy["profiles"][0]
    if (profile["id"] != "nc35-oo94-php85-mariadb123"
            or profile["applications"]["nextcloud"] != {"min": "35.0.0", "max_exclusive": "35.0.2"}
            or profile["php_suffix"] != "85" or profile["roles"]["database"]["package"] != "mariadb123-server"):
        raise ValueError("Maintenance base profile changed")
    profile["applications"]["nextcloud"] = {"exact": "35.0.2"}
    policy["evidence"].extend(item for item in recipe["evidence"] if item not in policy["evidence"])
    return validate_policy(policy)


def target_configuration(original):
    """Exact target pin only; original is retained bytes, not mutable live config.

    This is a proposed reviewed target, not permission to override a source pin.
    seal_successor requires a receipt binding the complete target file hashes.
    Preflight validates the original constraints first, then assesses only this
    exact reviewed target proposal; unrelated pins and transitions remain refused.
    """
    config = Config.from_json(original.decode())
    if config.nextcloud_exact not in ("", "35.0.1"):
        raise ValueError("Unsupported original Nextcloud pin")
    return replace(config, nextcloud_exact="35.0.2").validate()


def target_plan(original, retained):
    """Revalidate retained metadata and change only the compiled application edge."""
    config = Config.from_json(original.decode())
    source = resolution.validate_plan(config, retained)
    recipe = candidate_policy.recipe()
    if (source["applications"] != {"nextcloud": "35.0.1", "onlyoffice": recipe["onlyoffice"], "connector": "10.2.1"}
            or any(source["target"][key] != value for key, value in recipe["target"].items())):
        raise ValueError("Unsupported source application edge")
    target = target_configuration(original)
    policy = destination_policy()
    plan = deepcopy(source)
    plan["applications"]["nextcloud"] = "35.0.2"
    plan["constraints"] = constraints(target, policy)
    plan["policy_sha256"] = policy_hash(policy)
    plan["sources"] = sorted(set(plan["sources"]) | {item["url"] for item in policy["evidence"]})
    # validate_plan invokes pure compatibility.validate over the retained closure;
    # no catalog/solver/discovery input is synthesized or selected anew.
    return resolution.validate_plan(target, plan, policy=policy)


def public_runtime_files(config, plan, group):
    """Expected public staged bytes, matching Deployment.stage_payloads' format."""
    from .version_runtime import connector_text, dependency_text, package_text, runtime_versions
    if group not in ("nextcloud", "onlyoffice"):
        raise ValueError("Unknown runtime group")
    common = {key: getattr(config, key) for key in (
        "instance", "public_hostname", "admin_username", "admin_email", "timezone", "repository",
        "tls_mode", "acme_email", "php_memory_mb", "db_buffer_mb", "redis_memory_mb", "upload_max_mb", "font_profile")}
    common.update(nextcloud_ip=config.nextcloud_ip, onlyoffice_ip=config.onlyoffice_ip,
                  php_children=config.php_children, db_name="nextcloud", public_url=config.public_url,
                  storage_url=config.storage_url, proxy_networks=config.trusted_proxy_networks)
    if group == "onlyoffice":
        common = {key: common[key] for key in ("public_hostname", "public_url", "storage_url", "nextcloud_ip",
                                              "onlyoffice_ip", "repository", "tls_mode", "font_profile")}
        common.update(additional_fonts=bool(config.additional_fonts_dir), accept_microsoft_fonts=config.accept_microsoft_fonts)
    else:
        common.pop("instance")
        common.pop("font_profile")
    packages, dependencies = package_text(plan, group), dependency_text(plan, group)
    common["versions"] = runtime_versions(plan, packages, dependencies)
    return {"runtime.json": _encode(common), "packages.lock": packages.encode(),
            "packages.dependencies": dependencies.encode(), "connector.json": connector_text(plan).encode(),
            "fonts-unavailable": "".join(name + "\n" for name in plan["fonts_unavailable"]).encode()}


def proposed_files(original, retained):
    """Pure review material; callers supply actual retained bytes to the sealer."""
    config = target_configuration(original)
    plan = target_plan(original, retained)
    files = {"config.json": config.to_json().encode(), "versions.json": _encode(plan),
             "policy.json": _encode(destination_policy())}
    for group in ("nextcloud", "onlyoffice"):
        files.update({group + "/" + name: data for name, data in public_runtime_files(config, plan, group).items()})
    return files


def _context(store, name, predecessor, intent_ref):
    """Validate persisted lineage independent of the current active pointer."""
    from .maintenance import executor_record
    from .maintenance_state import NativeState, validate_intent
    from .state import Registry
    previous = _json(store._bound(predecessor))
    # This first edge cannot recurse into a guessed multi-step maintenance chain.
    if (type(previous.get("schema_version")) is not int or previous["schema_version"] != 1
            or previous.get("kind") != "instance-generation"):
        raise ValueError("Maintenance requires its original enrollment generation")
    previous = store._generation(name, predecessor)
    intent = validate_intent(_json(store._bound(intent_ref)))
    _reference(intent_ref, f"maintenance/operations/{intent['operation']}/intent.json")
    executor = executor_record()
    native = NativeState(Registry(store.root), executor)
    inputs = native._inputs(intent)  # Hash-bound read only; no pending-fence bypass/mutation.
    recipe = candidate_policy.recipe()
    if (inputs["instance"] != name or inputs["entries"][name]["generation"] != predecessor
            or inputs["recipe"] != recipe or inputs["recipe_sha256"] != _hash(_encode(recipe))
            or previous["provenance"]["source_sha256"] != executor["source_sha256"]
            or executor["policy_sha256"] != policy_hash(load_policy())
            or store._bound(previous["provenance"]["policy"]) != (RESOURCES / "versions.json").read_bytes()):
        raise ValueError("Successor recipe/predecessor/source/executor binding differs")
    archive = store._archive(name, previous["archive"])
    original = store._bound(previous["config"])
    initial = Config.from_json(store._bound(archive["files"]["config.json"]).decode())
    from .state import config_digest
    journal = _json(store._bound(archive["files"]["deployment.json"]))
    if (journal.get("schema_version") != initial.schema_version or journal.get("config_sha256") != config_digest(initial)
            or type(journal.get("steps")) is not dict):
        raise ValueError("Original deployment journal/configuration binding differs")
    return previous, intent, inputs, archive, original


def inspection_bindings(store, predecessor, intent, inputs, original, retained):
    """Canonical inspection bindings for a trusted source observation adapter."""
    return dict(config_sha256=candidate_policy.digest(_json(original)), versions_sha256=candidate_policy.digest(retained),
                graph_sha256=candidate_policy.digest(_json(store._bound(intent["base_graph"]))),
                generation_sha256=candidate_policy.digest(_json(store._bound(predecessor))),
                network_sha256=candidate_policy.digest(inputs["network"]), executor_sha256=intent["executor_sha256"])


def source_hashes(executor):
    """Complete public helper/worker inventory from the exact retained artifact."""
    from .maintenance_staging import _source
    specs, source, identity = _source(PROJECT_ROOT)
    if source != executor["source_sha256"] or identity != executor["executor_sha256"]:
        raise ValueError("Effective worker source/executor changed")
    return {item["path"].removeprefix("source/"): item["sha256"] for item in specs
            if item["path"] != "source/install.sh"}


def _candidate(value, bindings, retained):
    _fields(value, "schema_version kind recipe bindings observations_sha256 repository_sha256 packages roots artifacts apps package_transaction execution_authorized")
    _schema(value)
    if (value["kind"] != "destination-inspection-candidate" or _encode(value["recipe"]) != _encode(candidate_policy.recipe())
            or value["bindings"] != bindings or value["packages"] != retained["packages"]
            or value["roots"] != retained["roots"] or value["package_transaction"] != []
            or value["execution_authorized"] is not False):
        raise ValueError("Successor candidate differs from its exact retained source")
    for key in ("observations_sha256", "repository_sha256"):
        _digest(value[key])
    _fields(value["artifacts"], "nextcloud connector")
    for name, version in (("nextcloud", "35.0.2"), ("connector", "10.2.1")):
        item = value["artifacts"][name]
        _fields(item, "version sha256 available_sha256 provenance" + (" internal_version" if name == "nextcloud" else ""))
        _digest(item["sha256"])
        if (item["version"] != version or item["available_sha256"] != item["sha256"]
                or item["provenance"] != ("authenticated-release" if name == "nextcloud" else "appstore-sha512-signature")
                or name == "nextcloud" and item["internal_version"] != "35.0.2.2"):
            raise ValueError("Successor artifact binding differs")
    if type(value["apps"]) is not dict or not {"onlyoffice", "serverinfo"} <= value["apps"].keys() or len(value["apps"]) > 1024:
        raise ValueError("Missing destination application manifests")
    for name, app in value["apps"].items():
        _fields(app, "source_version version phpVersionSpec platformVersionSpec delivery artifact_sha256")
        # These are captured manifest projections, not permission to fetch apps.
        from .versions import text, TRIPLE, package_upstream
        text(name, r"[a-z][a-z0-9_]{0,63}", "application identity")
        text(app["version"], TRIPLE, "destination application version")
        if not candidate_policy.source_app_label(name, app["source_version"]):
            raise ValueError("Unreviewed original application build label")
        if (app["delivery"] != ("retained" if name == "onlyoffice" else "shipped")
                or app["artifact_sha256"] != value["artifacts"]["connector" if name == "onlyoffice" else "nextcloud"]["sha256"]
                or name == "onlyoffice" and (app["version"] != "10.2.1" or app["source_version"] != "10.2.1")
                or name == "serverinfo" and (app["version"] != "7.0.0" or app["source_version"] != "7.0.0")):
            raise ValueError("Unreviewed successor application")
        php = package_upstream(retained["packages"]["nextcloud"][retained["roles"]["php"]]["version"])
        for field, version in (("phpVersionSpec", php), ("platformVersionSpec", "35.0.2")):
            if not compatibility.in_range(version, compatibility.version_spec(app[field])):
                raise ValueError("Incompatible successor application manifest")


def _evidence(store, name, generation, predecessor, intent_ref, context, files, evidence):
    previous, intent, inputs, archive, original = context
    retained = _json(store._bound(previous["versions"]))
    candidate = _json(evidence["candidate.json"])
    _candidate(candidate, inspection_bindings(store, predecessor, intent, inputs, original, retained), retained)
    hashes = {key: _hash(data) for key, data in files.items()}
    review = _json(evidence["review.json"])
    expected = dict(schema_version=1, kind="nextcloud-successor-review", operation=intent["operation"], instance=name,
                    predecessor=predecessor, intent=intent_ref, recipe_sha256=inputs["recipe_sha256"],
                    original_config_sha256=_hash(original), target_files=hashes,
                    candidate_sha256=_hash(evidence["candidate.json"]))
    if _encode(review) != _encode(expected):
        raise ValueError("Successor requires exact reviewed target files and original configuration")
    config = target_configuration(original)
    expected_files = source_hashes(inputs["executor"])
    effective = _json(evidence["effective.json"])
    jails = {}
    for group, jail in (("nextcloud", config.nextcloud_jail), ("onlyoffice", config.onlyoffice_jail)):
        workers = {"/root/cloud-installer/" + path: digest for path, digest in expected_files.items()}
        workers.update({"/root/cloud-installer/" + filename: hashes[group + "/" + filename] for filename in PUBLIC_FILES})
        if group == "nextcloud":
            helper = "resources/jails/runtime-inventory.php"
            if helper not in expected_files:
                raise ValueError("Missing reviewed native runtime helper")
            workers["/usr/local/libexec/cloud-runtime-inventory.php"] = expected_files[helper]
        jails[group] = dict(name=jail, files=workers)
    expected = dict(schema_version=1, kind="effective-public-worker-receipt", operation=intent["operation"],
                    instance=name, generation=generation, executor_sha256=intent["executor_sha256"],
                    target_files=hashes, jails=jails)
    if _encode(effective) != _encode(expected):
        raise ValueError("Observed effective public workers/runtime differ from the reviewed target")
    readiness = _json(evidence["readiness.json"])
    expected = dict(schema_version=1, kind="nextcloud-successor-readiness", operation=intent["operation"], instance=name,
                    config_sha256=hashes["config.json"], versions_sha256=hashes["versions.json"],
                    nextcloud=dict(installed=True, maintenance=True, needsDbUpgrade=False, version="35.0.2.2", versionstring="35.0.2"),
                    packages_sha256=candidate_policy.digest(retained["packages"]),
                    apps={app: item["version"] for app, item in candidate["apps"].items()})
    if _encode(readiness) != _encode(expected):
        raise ValueError("Successor lacks exact closed target readiness evidence")


def seal_successor(native_state, operation, generation, *, target_files, validation_evidence, recover=False):
    """Seal reviewed metadata under the global lock and exact pending operation.

    Files are exact bytes: proposed_files() defines the public target set;
    validation_evidence requires candidate/review/effective/readiness JSON bytes.
    No receipt is generated here and no supplied field enables native execution.
    """
    intent, inputs = native_state.read(operation)
    _id(generation)
    name = inputs["instance"]
    store = native_state.store
    predecessor = inputs["entries"][name]["generation"]
    intent_ref = store.reference(f"maintenance/operations/{operation}/intent.json")
    context = _context(store, name, predecessor, intent_ref)
    if type(target_files) is not dict or set(target_files) != TARGET_FILES or type(validation_evidence) is not dict or set(validation_evidence) != EVIDENCE:
        raise ValueError("Incomplete successor target/evidence file set")
    payload = {**target_files, **{"evidence/" + key: data for key, data in validation_evidence.items()}}
    if any(type(data) is not bytes or len(data) > MAX_FILE_BYTES for data in payload.values()) or sum(map(len, payload.values())) > MAX_ARCHIVE_BYTES:
        raise ValueError("Successor evidence exceeds byte/type limits")
    previous, _, _, archive, original = context
    if target_files != proposed_files(original, _json(store._bound(previous["versions"]))):
        raise ValueError("Successor changes fields outside its compiled target")
    _evidence(store, name, generation, predecessor, intent_ref, context, target_files, validation_evidence)
    prefix = f"instances/{name}/generations/{generation}"
    references = {key: dict(path=prefix + "/" + key, sha256=_hash(data)) for key, data in payload.items()}
    original_refs = {"generation": predecessor, "config": archive["files"]["config.json"],
                     "versions": previous["versions"], "policy": previous["provenance"]["policy"],
                     "source": archive["files"]["source.sha256"], "deployment": archive["files"]["deployment.json"]}
    # The immutable original journal is not replaced with an effective-config hash.
    live = store.reference(f"instances/{name}/deployment.json")
    if live["sha256"] != original_refs["deployment"]["sha256"]:
        raise ValueError("Original deployment journal changed")
    provenance = dict(source_sha256=previous["provenance"]["source_sha256"],
                      policy_sha256=references["policy.json"]["sha256"], policy=references["policy.json"],
                      derivation=dict(predecessor=predecessor, intent=intent_ref, recipe_sha256=inputs["recipe_sha256"]))
    manifest = dict(schema_version=2, kind=KIND, entity_kind="instance", entity_id=name, generation_id=generation,
                    predecessor=predecessor, operation=operation, intent=intent_ref, origin="reviewed-nextcloud-patch",
                    recipe=dict(id=candidate_policy.RECIPE_ID, sha256=inputs["recipe_sha256"]),
                    config=references["config.json"], versions=references["versions.json"], policy=references["policy.json"],
                    plugins=previous["plugins"], archive=previous["archive"], credentials=previous["credentials"],
                    originals=original_refs, deployment=live, provenance=provenance,
                    resources=previous["resources"], evidence={key: references["evidence/" + key] for key in EVIDENCE},
                    runtime={group: {key: references[group + "/" + key] for key in PUBLIC_FILES} for group in ("nextcloud", "onlyoffice")})
    if store._present(prefix) and not recover:
        raise ValueError("Successor already exists; explicit exact recovery required")
    # Reuse bounded immutable byte snapshots, not enrollment generation sealing.
    snapshot = f"maintenance/operations/{operation}/successor-{generation}"
    if recover and store._present(prefix) and not store._present(snapshot + "-plan.json"):
        raise ValueError("Successor recovery has no retained byte snapshot")
    store._snapshot(snapshot, dict(kind=KIND, instance=name, operation=operation, predecessor=predecessor,
                                  generation=generation, intent=intent_ref), payload, recover=recover)
    store._partial_tree(prefix, {**payload, "manifest.json": _encode(manifest)})
    for filename, data in payload.items():
        relative = prefix + "/" + filename
        store._mkdir(relative.rsplit("/", 1)[0])
        store._write_once(relative, data, recover=recover)
    reference = store._write_once(prefix + "/manifest.json", _encode(manifest), recover=recover)
    validate_generation(store, name, reference, manifest)
    return reference


def validate_generation(store, name, reference, value):
    _fields(value, "schema_version kind entity_kind entity_id generation_id predecessor operation intent origin recipe config versions policy plugins archive credentials originals deployment provenance resources evidence runtime")
    if (type(value["schema_version"]) is not int or value["schema_version"] != 2 or value["kind"] != KIND
            or value["entity_kind"] != "instance" or value["entity_id"] != name or value["origin"] != "reviewed-nextcloud-patch"):
        raise ValueError("Unsupported maintenance generation schema/identity")
    generation = _id(value["generation_id"])
    prefix = f"instances/{name}/generations/{generation}/"
    _reference(reference, prefix + "manifest.json")
    context = _context(store, name, value["predecessor"], value["intent"])
    previous, intent, inputs, archive, original = context
    if (value["operation"] != intent["operation"] or value["recipe"] != dict(id=candidate_policy.RECIPE_ID, sha256=inputs["recipe_sha256"])
            or any(value[key] != previous[key] for key in ("plugins", "archive", "credentials", "resources"))):
        raise ValueError("Successor changed original operation/resources/credentials")
    expected_originals = dict(generation=value["predecessor"], config=archive["files"]["config.json"], versions=previous["versions"],
                              policy=previous["provenance"]["policy"], source=archive["files"]["source.sha256"],
                              deployment=archive["files"]["deployment.json"])
    if value["originals"] != expected_originals:
        raise ValueError("Successor original evidence binding differs")
    store._bound(value["deployment"], f"instances/{name}/deployment.json")
    if value["deployment"]["sha256"] != expected_originals["deployment"]["sha256"]:
        raise ValueError("Successor changed original deployment journal")
    files = {key + ".json": store._bound(value[key], prefix + key + ".json") for key in ("config", "versions", "policy")}
    _fields(value["runtime"], "nextcloud onlyoffice")
    for group, refs in value["runtime"].items():
        _fields(refs, " ".join(PUBLIC_FILES))
        files.update({group + "/" + key: store._bound(ref, prefix + group + "/" + key) for key, ref in refs.items()})
    if files != proposed_files(original, _json(store._bound(previous["versions"]))):
        raise ValueError("Unsupported successor configuration/versions/policy/runtime")
    _fields(value["evidence"], " ".join(EVIDENCE))
    evidence = {key: store._bound(ref, prefix + "evidence/" + key) for key, ref in value["evidence"].items()}
    if sum(map(len, (*files.values(), *evidence.values()))) > MAX_ARCHIVE_BYTES:
        raise ValueError("Successor evidence exceeds aggregate limit")
    _evidence(store, name, generation, value["predecessor"], value["intent"], context, files, evidence)
    expected = dict(source_sha256=previous["provenance"]["source_sha256"], policy_sha256=value["policy"]["sha256"],
                    policy=value["policy"], derivation=dict(predecessor=value["predecessor"], intent=value["intent"],
                                                         recipe_sha256=inputs["recipe_sha256"]))
    if value["provenance"] != expected:
        raise ValueError("Successor provenance differs")
    return value


def provenance_policy(store, provenance):
    """Validate the compiled derivative before Config's source-bound loader uses it."""
    _fields(provenance, "source_sha256 policy_sha256 policy derivation")
    derivation = provenance["derivation"]
    _fields(derivation, "predecessor intent recipe_sha256")
    predecessor = _json(store._bound(derivation["predecessor"]))
    name = _id(predecessor.get("entity_id"), True)
    previous, _, inputs, _, _ = _context(store, name, derivation["predecessor"], derivation["intent"])
    raw = store._bound(provenance["policy"])
    if (provenance["source_sha256"] != previous["provenance"]["source_sha256"]
            or provenance["policy_sha256"] != _hash(raw) or raw != _encode(destination_policy())
            or derivation["recipe_sha256"] != inputs["recipe_sha256"]):
        raise ValueError("Unreviewed derived policy provenance")
    return destination_policy()


def validate_pending_entries(store, intent, entries):
    """Store commit guard used by NativeState without changing its general reader."""
    inputs = _json(store._bound(intent["inputs"]))
    name = intent["instances"][0]
    original = inputs["entries"][name]
    entry = entries.get(name, {})
    if entry.get("kind") != "managed" or entry.get("generation") == original["generation"]:
        return  # Existing M3 original/restored paths retain their stricter wrapper checks.
    manifest = store._generation(name, entry["generation"])
    if (manifest.get("kind") != KIND or manifest["predecessor"] != original["generation"]
            or manifest["operation"] != intent["operation"]
            or manifest["intent"] != store.reference(f"maintenance/operations/{intent['operation']}/intent.json")):
        raise ValueError("Maintenance target is not this operation's exact successor")
