"""Cold coherent recovery primitives, not an operator entrypoint or recipe.

The maintenance parent owns approval, host/database locks, persistent boot/writer
fences and source/plan validation. Its reviewed adapter must supply a *fresh*
ColdBoundary at every checkpoint. M3 ships no such native adapter. No runner is
constructed here and no command is obtained from a manifest. Metadata copies are
retained evidence only: restoring shared graph/PF/credentials requires a future
selective reconciliation recipe, never copying old files over current state.

Schema 2's operator-assisted-offline contract covers only required editor changes
the operator has saved, closed and verified in Nextcloud. It neither verifies an
automatic ONLYOFFICE drain nor preserves unsaved/unconfirmed editor work. The
private acknowledgement is retained outside every rollback tree. It is not a
writer fence: capture still requires fresh clean shutdown and writer closure.
Explicit schema-2 original-set restoration may discard the current closed DB
without calling it clean, using the authenticated original clean capture instead.
"""

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Callable, Protocol

from .config import Config, datasets
from .state import atomic_json, config_digest


OWNER = "org.cloud-installer:instance"
MANAGER = "org.cloud-installer:owner"
TOKEN = "org.cloud-installer:recovery"
MAX_FILE = 16 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
ROLES = frozenset(("metadata", "credentials", "tls", "inputs", "source", "graph", "pf"))
HASH = re.compile(r"[a-f0-9]{64}\Z")
ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,79}\Z")
VERIFIED_DRAIN = "verified-drain"
OPERATOR_OFFLINE = "operator-assisted-offline"
ORIGINAL_CLEAN_SET = "original-clean-set/current-discardable"
OFFLINE_LIMITATION = ("I verified all required editor changes saved and closed in Nextcloud; "
                      "automatic ONLYOFFICE drain is not verified and unsaved or unconfirmed editor work is not covered.")


class RecoveryError(ValueError):
    """Bounded diagnostics: never include native output or credential bytes."""


class Runner(Protocol):
    def output(self, *args: str) -> str: ...
    def run(self, *args: str): ...


@dataclass(frozen=True)
class Resource:
    name: str
    mountpoint: str


@dataclass(frozen=True)
class Evidence:
    """Adapter-allowlisted, pinned private file, never a manifest-selected path.

    Role labels do not authorize reading arbitrary host files. The future native
    recipe must construct this allowlist from reviewed instance/source inputs.
    """
    name: str
    role: str
    path: Path
    sha256: str


@dataclass(frozen=True)
class OfflineAcknowledgement:
    """Caller-selected retained private file; never a manifest-selected read."""
    path: Path
    sha256: str


@dataclass(frozen=True)
class OriginalRestoreConsent:
    """Trusted adapter-selected references, never a JSON execution switch."""
    path: Path
    sha256: str
    manifest_sha256: str
    capture_anchor_sha256: str
    capture_closure: Evidence
    current_closure: Evidence


@dataclass(frozen=True)
class ColdBoundary:
    """Adapter attestation, not inferred from stopped jails or an empty response.

    binding must equal context.binding(); evidence_sha256 identifies the parent's
    CURRENT retained clean-shutdown/closure/fence journal evidence. For schema 2
    restore, capture_anchor_sha256 separately pins the immutable capture evidence;
    original_services always describes historical pre-capture service states.
    The parent rechecks its durable operation phase, locks, all-writer closure and
    publication markers on every callback, including after reboot. A JSON boolean
    or an acknowledgement alone is never a machine drain/closure attestation.
    """
    binding: dict
    phase: str
    evidence_sha256: str
    original_services: tuple[tuple[str, str], ...]
    clean_database_shutdown: bool
    office_drained: bool
    writers_frozen: bool
    persistent_boot_fence: bool
    locks_held: bool
    external_dependencies_covered: bool
    publication_may_have_begun: bool
    recovery_publication_may_have_begun: bool
    quiescence_mode: str = VERIFIED_DRAIN
    offline_acknowledgement_sha256: str | None = None
    capture_anchor_sha256: str | None = None
    restore_basis: str | None = None
    capture_closure_sha256: str | None = None
    restore_consent_sha256: str | None = None


@dataclass(frozen=True)
class RecoveryContext:
    """Trusted recipe inputs, not an execution capability deserialized from JSON.

    Local files are fsynced before checkpoint callbacks. After callback failure,
    the parent must reconcile its journal with those files before attesting a
    retry; callbacks must tolerate repeated completion notifications.
    """
    config: Config
    operation_id: str
    source_sha256: str
    executor_sha256: str
    plan_sha256: str
    graph_sha256: str
    pf_sha256: str
    directory: Path
    evidence: tuple[Evidence, ...]
    publication_may_have_begun: bool = False
    recovery_publication_may_have_begun: bool = False
    cold_boundary: Callable[["RecoveryContext", str], ColdBoundary] | None = None
    checkpoint: Callable[[str, str | None, str], None] | None = None
    schema_version: int = 1
    quiescence_mode: str = VERIFIED_DRAIN
    preparation_sha256: str | None = None
    offline_acknowledgement: OfflineAcknowledgement | None = None
    original_restore: OriginalRestoreConsent | None = None

    def binding(self):
        value = {"operation_id": self.operation_id, "instance": self.config.instance,
                 "config_sha256": config_digest(self.config),
                 **{key: getattr(self, key) for key in
                    ("source_sha256", "executor_sha256", "plan_sha256", "graph_sha256", "pf_sha256")}}
        if self.schema_version == 2:
            value.update(preparation_sha256=self.preparation_sha256,
                         quiescence_mode=self.quiescence_mode)
        return value

    @property
    def resources(self):
        return expected_resources(self.config)


@dataclass(frozen=True)
class RestoreAssessment:
    eligible: bool
    blockers: tuple[str, ...]
    manifest_sha256: str | None = None


def expected_resources(config):
    """Only the configured application tree and two dedicated thick-jail trees."""
    c = config.validate()
    result = [Resource(item.name, item.mountpoint) for item in datasets(c)]
    for jail in (c.nextcloud_jail, c.onlyoffice_jail):
        for suffix in ("", "/root"):
            result.append(Resource(f"{c.bastille_dataset}/jails/{jail}{suffix}",
                                   f"{c.bastille_root}/jails/{jail}{suffix}"))
    return tuple(result)


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _json_hash(value):
    return _digest(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def _require(condition, message):
    if not condition:
        raise RecoveryError(message)


def _hash(value):
    return isinstance(value, str) and HASH.fullmatch(value) is not None


def _number(value, positive=False):
    _require(isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]{0,19}", value)
             and (not positive or int(value) > 0), "Invalid numeric native identity")
    return int(value)


def _path(path, *, directory=False):
    path = Path(path)
    _require(path.is_absolute() and ".." not in path.parts, "Unsafe evidence path")
    for parent in reversed(path.parents):
        info = parent.lstat()
        _require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.geteuid())
                 and (not info.st_mode & 0o022 or info.st_mode & stat.S_ISVTX),
                 "Unsafe evidence ancestor")
    info = path.lstat()
    _require(info.st_uid == os.geteuid() and not info.st_mode & 0o077
             and (stat.S_ISDIR(info.st_mode) if directory else
                  stat.S_ISREG(info.st_mode) and info.st_nlink == 1), "Unsafe private evidence")
    return path


def _read(path):
    path = _path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                 and not info.st_mode & 0o077 and info.st_nlink == 1
                 and info.st_size <= MAX_FILE, "Unsafe or oversized private evidence")
        data = stream.read(MAX_FILE + 1)
    _require(len(data) <= MAX_FILE, "Oversized private evidence")
    return data


def _load(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            _require(key not in result, "Duplicate manifest field")
            result[key] = value
        return result
    return json.loads(_read(path), object_pairs_hook=unique)


def offline_acknowledgement_phrase(c: RecoveryContext):
    """Exact operator input; the adapter must obtain it, never auto-confirm it."""
    return (f"OFFLINE {c.operation_id} {c.config.instance} {c.source_sha256} "
            f"{c.preparation_sha256}: {OFFLINE_LIMITATION}")


def offline_acknowledgement_record(c: RecoveryContext):
    """Fixed private record shape for the caller to retain after exact consent.

    This pure shape helper does not establish consent or authorize any effects.
    Hash the actual retained file bytes when constructing OfflineAcknowledgement.
    """
    return {"schema_version": 1, "mode": OPERATOR_OFFLINE,
            "operation_id": c.operation_id, "instance": c.config.instance,
            "source_sha256": c.source_sha256, "preparation_sha256": c.preparation_sha256,
            "phrase": offline_acknowledgement_phrase(c),
            "unsaved_editor_work_covered": False, "machine_drain_verified": False}


def _contract(c):
    ack = c.offline_acknowledgement
    _require(isinstance(ack, OfflineAcknowledgement) and isinstance(ack.path, Path)
             and _hash(ack.sha256), "Pinned offline acknowledgement is required")
    return {"mode": OPERATOR_OFFLINE,
            "offline_acknowledgement": {"path": str(ack.path), "sha256": ack.sha256}}


def _acknowledgement(c):
    _contract(c)
    ack = c.offline_acknowledgement
    _require(ack.path.is_absolute() and ".." not in ack.path.parts
             and not any(ack.path.is_relative_to(r.mountpoint) for r in c.resources),
             "Offline acknowledgement must be outside the rollback trees")
    try:
        # Hash and parse the same bytes. Strict JSON equality also rejects bool/int
        # substitutions and extra fields without echoing private record contents.
        data = _read(ack.path)
        _require(_digest(data) == ack.sha256, "Offline acknowledgement hash changed")
        def unique(pairs):
            result = {}
            for key, value in pairs:
                _require(key not in result, "Duplicate offline acknowledgement field")
                result[key] = value
            return result
        value = json.loads(data, object_pairs_hook=unique)
        _require(_json_hash(value) == _json_hash(offline_acknowledgement_record(c)),
                 "Offline acknowledgement contract/binding changed")
    except Exception:
        raise RecoveryError("Offline acknowledgement is missing, unsafe, changed or invalid") from None


def original_restore_phrase(c):
    return f"RESTORE-ORIGINAL {c.operation_id} DISCARD-CLOSED-CHANGES"


def original_restore_record(c, manifest_sha256, capture_anchor_sha256, capture_closure, current_closure):
    """Pure consent shape; the adapter obtains the exact operator confirmation."""
    return dict(schema_version=1, kind="original-clean-set-restore-consent", binding=c.binding(),
                phrase=original_restore_phrase(c), restore_basis=ORIGINAL_CLEAN_SET,
                manifest_sha256=manifest_sha256, capture_anchor_sha256=capture_anchor_sha256,
                capture_closure=dict(path=str(capture_closure.path), sha256=capture_closure.sha256),
                current_closure=dict(path=str(current_closure.path), sha256=current_closure.sha256))


def _original_restore_consent(c):
    consent = c.original_restore
    _require(type(consent) is OriginalRestoreConsent and c.schema_version == 2 and c.quiescence_mode == OPERATOR_OFFLINE,
             "Original-set restore requires the typed schema-2 offline consent")
    _require(_hash(consent.manifest_sha256) and _hash(consent.capture_anchor_sha256), "Invalid original-set binding")
    _require(type(consent.capture_closure) is Evidence and type(consent.current_closure) is Evidence,
             "Typed original-set evidence references are required")
    for item in (consent, consent.capture_closure, consent.current_closure):
        _require(isinstance(item.path, Path) and item.path.is_absolute() and _hash(item.sha256)
                 and not any(item.path.is_relative_to(r.mountpoint) for r in c.resources), "Unsafe original-set consent reference")
        _require(_digest(_read(item.path)) == item.sha256, "Original-set consent evidence changed")
    _require(consent.capture_closure.sha256 != consent.current_closure.sha256
             and consent.current_closure.sha256 != consent.capture_anchor_sha256, "Historical closure cannot attest current closure")
    captured = _load(consent.capture_closure.path)
    _require(type(captured) is dict and captured.get("clean_database_shutdown") is True and captured.get("binding") == c.binding(),
             "Original capture lacks affirmative clean-shutdown evidence")
    current = _load(consent.current_closure.path)
    _require(type(current) is dict and current.get("clean_database_shutdown") is False and current.get("office_drained") is False
             and current.get("binding") == c.binding() and current.get("restore_basis") == ORIGINAL_CLEAN_SET,
             "Current discardable closure differs")
    expected = original_restore_record(c, consent.manifest_sha256, consent.capture_anchor_sha256,
                                       consent.capture_closure, consent.current_closure)
    _require(_json_hash(_load(consent.path)) == _json_hash(expected), "Original-set restore consent differs")
    return consent


def _context(c):
    _require(isinstance(c, RecoveryContext) and isinstance(c.config, Config), "Invalid recovery context")
    c.config.validate()
    _require(type(c.schema_version) is int and
             ((c.schema_version == 1 and c.quiescence_mode == VERIFIED_DRAIN
               and c.preparation_sha256 is None and c.offline_acknowledgement is None)
              or (c.schema_version == 2 and c.quiescence_mode == OPERATOR_OFFLINE
                  and _hash(c.preparation_sha256))), "Invalid recovery context contract")
    _require(isinstance(c.operation_id, str) and ID.fullmatch(c.operation_id), "Invalid recovery operation")
    _require(all(_hash(value) for key, value in c.binding().items() if key.endswith("sha256")),
             "Invalid recovery binding")
    _require(type(c.publication_may_have_begun) is bool
             and type(c.recovery_publication_may_have_begun) is bool, "Invalid publication state")
    _require(not c.publication_may_have_begun and not c.recovery_publication_may_have_begun,
             "Publication may have begun; normal rollback is forbidden")
    _require(callable(c.cold_boundary) and callable(c.checkpoint),
             "Reviewed cold-boundary adapter and durable parent checkpoints are required")
    _require(not any(Path(c.directory).is_relative_to(r.mountpoint) for r in c.resources),
             "Recovery evidence must be outside the rollback trees")
    _path(c.directory, directory=True)
    _require(isinstance(c.evidence, tuple) and 0 < len(c.evidence) <= 128
             and all(isinstance(e, Evidence) for e in c.evidence)
             and {e.role for e in c.evidence} == ROLES
             and len({e.name for e in c.evidence}) == len(c.evidence), "Incomplete private evidence coverage")
    for e in c.evidence:
        _require(isinstance(e.name, str) and ID.fullmatch(e.name) and _hash(e.sha256),
                 "Invalid private evidence specification")
        _require(Path(e.path).is_absolute() and ".." not in Path(e.path).parts
                 and not Path(e.path).is_relative_to(c.directory), "Unsafe evidence source path")
    if c.schema_version == 2:
        _acknowledgement(c)
    _require(c.original_restore is None or (type(c.original_restore) is OriginalRestoreConsent and c.schema_version == 2
                                           and c.quiescence_mode == OPERATOR_OFFLINE), "Invalid original restore capability")


def _boundary(c, action):
    _require(action in ("capture", "restore"), "Unknown recovery action")
    _context(c)
    try:
        proof = c.cold_boundary(c, action)
    except Exception:
        raise RecoveryError("Cold-boundary adapter failed; retain the stopped pair") from None
    _require(isinstance(proof, ColdBoundary) and proof.binding == c.binding()
             and _hash(proof.evidence_sha256), "Cold-boundary operation binding changed")
    restore_phases = {"recovery-required", "restoring", "datasets-restored"}
    if c.schema_version == 2 and c.quiescence_mode == OPERATOR_OFFLINE:
        restore_phases.add("recovery-reclosed")
    _require(proof.phase in ({"quiesced", "recovery-ready"} if action == "capture" else restore_phases),
             "Operation phase does not permit cold recovery")
    original = action == "restore" and c.original_restore is not None
    if original:
        consent = _original_restore_consent(c)
        _require(proof.clean_database_shutdown is False and proof.office_drained is False
                 and proof.restore_basis == ORIGINAL_CLEAN_SET and proof.capture_anchor_sha256 == consent.capture_anchor_sha256
                 and proof.capture_closure_sha256 == consent.capture_closure.sha256
                 and proof.restore_consent_sha256 == consent.sha256, "Original-set restore boundary differs")
    else:
        _require(c.original_restore is None and proof.clean_database_shutdown is True and proof.restore_basis is None
                 and proof.capture_closure_sha256 is None and proof.restore_consent_sha256 is None,
                 "Clean shutdown is mandatory outside explicit original-set restoration")
    _require(all(getattr(proof, key) is True for key in
                 ("writers_frozen", "persistent_boot_fence",
                   "locks_held", "external_dependencies_covered")), "Cold-boundary prerequisites are unproven")
    _require(proof.quiescence_mode == c.quiescence_mode, "Cold-boundary quiescence contract changed")
    if c.schema_version == 1:
        _require(proof.office_drained is True and proof.offline_acknowledgement_sha256 is None,
                 "Verified office drain is unproven")
    else:
        _require(proof.office_drained is False
                 and proof.offline_acknowledgement_sha256 == c.offline_acknowledgement.sha256,
                 "Operator offline acknowledgement/drain contract changed")
        if action != "capture":
            _require(_hash(proof.capture_anchor_sha256)
                     and proof.evidence_sha256 != proof.capture_anchor_sha256,
                     "Fresh restore closure and explicit capture anchor are required")
    _require(proof.capture_anchor_sha256 is None or _hash(proof.capture_anchor_sha256),
             "Invalid capture anchor")
    _require(proof.publication_may_have_begun is False
             and proof.recovery_publication_may_have_begun is False,
             "Publication may have begun; normal rollback is forbidden")
    _require(isinstance(proof.original_services, tuple) and len(proof.original_services) == 2
             and all(isinstance(row, tuple) and len(row) == 2 for row in proof.original_services)
             and {row[0] for row in proof.original_services} == {c.config.nextcloud_jail, c.config.onlyoffice_jail}
             and all(len(row) == 2 and row[1] in ("running", "stopped") for row in proof.original_services),
             "Original service states are missing")
    return proof


class NativeBackend:
    """Fixed argv only; runner injection is mandatory, including for inspection."""
    def __init__(self, runner: Runner):
        self.runner = runner

    def output(self, *args):
        try:
            text = self.runner.output(*args)
            _require(isinstance(text, str) and len(text) <= 4 * MAX_FILE and "\x00" not in text,
                     "Invalid native output")
            return text.strip()
        except Exception:
            raise RecoveryError("Native recovery probe failed or returned invalid evidence") from None

    def run(self, *args):
        try:
            result = self.runner.run(*args)
            _require(type(getattr(result, "returncode", None)) is int and result.returncode == 0,
                     "Native mutation failed")
        except Exception:
            raise RecoveryError("Native recovery mutation failed; retain the stopped pair and evidence") from None

    def get(self, name, key):
        return self.output("zfs", "get", "-Hp", "-o", "value", key, name)

    def mounted_identity(self, path):
        _require(isinstance(path, str) and 0 < len(path) <= 4096 and path.startswith("/")
                 and str(Path(path)) == path and ".." not in Path(path).parts, "Invalid mounted path")
        canonical = self.output("realpath", path)
        _require(canonical.startswith("/") and len(canonical) <= 4096 and str(Path(canonical)) == canonical
                 and ".." not in Path(canonical).parts, "Invalid canonical mount path")
        values = self.output("stat", "-f", "%d:%i", canonical).split(":")
        _require(len(values) == 2, "Invalid mounted identity")
        return canonical, (_number(values[0]), _number(values[1], True))

    def storage(self, c):
        points = {r.mountpoint: r.name for r in c.resources}
        names = {r.name: r.mountpoint for r in c.resources}
        jails = {name: f"{c.config.bastille_root}/jails/{name}/root"
                 for name in (c.config.nextcloud_jail, c.config.onlyoffice_jail)}
        seen = set()
        for line in self.output("jls", "-d", "jid", "name", "path", "dying").splitlines():
            row = line.split()
            _require(len(row) == 4 and row[0] not in seen and row[3] in ("true", "false"),
                     "Invalid live/dying jail inventory")
            _number(row[0], True)
            seen.add(row[0])
            _require(row[1] not in jails and not any(_related(row[2], p) for p in points),
                     "Affected jail is live or dying")
        mounts = []
        identities = None
        for line in self.output("mount", "-p").splitlines():
            row = line.split()
            _require(len(row) == 6 and row[1].startswith("/") and "\\" not in row[0] + row[1],
                     "Invalid or escaped mount inventory")
            mounts.append(row)
            if row[2] == "zfs" and row[0] in names:
                _require(row[1] == names[row[0]], "Recovery dataset has an unexpected mount alias")
            if row[2] == "nullfs":
                _require(not any(_related(row[0], p) or _related(row[1], p) for p in points),
                          "Related or covering nullfs mount remains")
                if identities is None:
                    identities = [self.mounted_identity(point) for point in points]
                    _require([path for path, _ in identities] == list(points), "Recovery mount alias changed")
                for path in row[:2]:
                    canonical, identity = self.mounted_identity(path)
                    _require(not any(_related(canonical, point) or identity[0] == actual[0]
                                     for point, actual in identities), "Canonical related nullfs alias remains")
            if any(row[1] == p or row[1].startswith(p + "/") for p in points):
                _require(row[1] in points and row[:3] == [points[row[1]], row[1], "zfs"],
                         "Unexpected covering mount inside recovery tree")
        return self._dataset_storage(c, mounts)

    def dataset_storage(self, c):
        """Full dataset identities/mounts only; this does not attest cold closure.

        Also used before stopping an owned live pair, whose expected nullfs mounts
        still exist. Capture/rollback must independently pass storage() above.
        """
        names = {r.name: r.mountpoint for r in c.resources}
        mounts = []
        for line in self.output("mount", "-p").splitlines():
            row = line.split()
            _require(len(row) == 6 and row[1].startswith("/") and "\\" not in row[0] + row[1],
                     "Invalid or escaped mount inventory")
            if row[2] == "zfs" and row[0] in names:
                _require(row[1] == names[row[0]], "Recovery dataset has an unexpected mount alias")
            mounts.append(row)
        return self._dataset_storage(c, mounts)

    def _dataset_storage(self, c, mounts):
        roots = _roots(c)
        for root in roots:
            actual = self.output("zfs", "list", "-H", "-o", "name", "-t", "filesystem,volume", "-r", root).splitlines()
            expected = {r.name for r in c.resources if r.name == root or r.name.startswith(root + "/")}
            _require(len(actual) == len(expected) and set(actual) == expected, "Unexpected dataset tree member")
        result = {}
        for r in c.resources:
            for key, value in ((OWNER, c.config.instance), (MANAGER, "cloud-installer"),
                               ("type", "filesystem"), ("origin", "-"),
                               ("mountpoint", r.mountpoint), ("mounted", "yes")):
                _require(self.get(r.name, key) == value, "Dataset ownership/type/mountpoint changed")
            _require(self.output("realpath", r.mountpoint) == r.mountpoint
                     and [row[:3] for row in mounts if row[1] == r.mountpoint] == [[r.name, r.mountpoint, "zfs"]],
                     "Dataset actual mount changed")
            df = self.output("df", "-P", r.mountpoint).splitlines()
            _require(len(df) == 2 and len(df[-1].split()) == 6
                     and df[-1].split()[0] == r.name and df[-1].split()[-1] == r.mountpoint,
                     "Dataset covering filesystem changed")
            guid = self.get(r.name, "guid")
            _number(guid, True)
            result[r.name] = {"mountpoint": r.mountpoint, "guid": guid}
        _require(len({v["guid"] for v in result.values()}) == len(result), "Duplicate dataset GUID")
        return result

    def capacity(self, c):
        # Parents include descendants. A full rewrite plus 10%/1GiB overhead is
        # conservative, not a reservation or a promise of future free capacity.
        used = sum(_number(self.get(root, "used")) for root in _roots(c))
        required = used + max(1024 ** 3, (used + 9) // 10)
        available = _number(self.get(c.config.pool, "available"))
        _require(available >= required, "Insufficient actual recovery capacity")
        for r in c.resources:
            local_used = _number(self.get(r.name, "used"))
            local_required = local_used + max(1024 ** 2, (local_used + 9) // 10)
            _require(_number(self.get(r.name, "available")) >= local_required,
                     "Insufficient actual dataset recovery capacity")
        return {"used_bytes": used, "available_bytes": available, "required_bytes": required}

    def snapshots(self, c, storage, *, restoring=False):
        inventory = {}
        for root in _roots(c):
            if restoring:
                _require(not self.output("zfs", "list", "-H", "-t", "bookmark", "-o", "name", "-r", root),
                         "Bookmark topology requires reconstruction")
            for line in self.output("zfs", "list", "-Hp", "-t", "snapshot", "-o",
                                    "name,guid,createtxg", "-r", root).splitlines():
                row = line.split()
                _require(len(row) == 3 and row[0] not in inventory and row[0].count("@") == 1
                         and row[0].split("@")[0] in storage, "Invalid snapshot inventory")
                _number(row[1], True)
                _number(row[2], True)
                inventory[row[0]] = {"guid": row[1], "createtxg": row[2]}
        found = {}
        for r in c.resources:
            name = _snapshot(c, r.name)
            if name not in inventory:
                continue
            _require(self.get(name, OWNER) == c.config.instance and self.get(name, MANAGER) == "cloud-installer"
                     and self.get(name, TOKEN) == c.operation_id, "Snapshot owner/operation changed")
            values = inventory[name]
            if restoring:
                _require(not any(other != name and other.split("@")[0] == r.name
                                 and int(meta["createtxg"]) >= int(values["createtxg"])
                                 for other, meta in inventory.items()), "Newer snapshot blocks nonrecursive rollback")
                # Refuse all holds/clones in the affected dataset's topology.
                for other in inventory:
                    if other.split("@")[0] == r.name:
                        _require(self.get(other, "clones") == "-" and self.get(other, "userrefs") == "0",
                                 "Snapshot clone/hold topology requires reconstruction")
            found[name] = values
        _require(not found or len(found) == len(storage), "Incomplete atomic snapshot set")
        _require(not found or (len({v["createtxg"] for v in found.values()}) == 1
                              and len({v["guid"] for v in found.values()}) == len(found)),
                 "Snapshot set is not one atomic transaction")
        return found

    def unchanged(self, c, dataset):
        # A supplementary drift check under the independently attested fence,
        # not proof of content equality or of an interrupted command completing.
        return _number(self.get(dataset, "written@" + _tag(c))) == 0


def _related(a, b):
    return a == b or a.startswith(b.rstrip("/") + "/") or b.startswith(a.rstrip("/") + "/")


def _roots(c):
    return (c.config.dataset_root, *(f"{c.config.bastille_dataset}/jails/{name}" for name in
                                   (c.config.nextcloud_jail, c.config.onlyoffice_jail)))


def _tag(c):
    return "cloud-installer-recovery-" + c.operation_id


def _snapshot(c, dataset):
    return dataset + "@" + _tag(c)


def _save(c, filename, value, phase, member=None):
    path = Path(c.directory) / filename
    if path.exists() or path.is_symlink():
        _path(path)
    atomic_json(path, value)
    try:
        c.checkpoint(phase, member, _json_hash(value))
    except Exception:
        raise RecoveryError("Parent recovery checkpoint failed; retain private artifacts and the stopped pair") from None


def _copies(c, *, capture=False):
    records, total = {}, 0
    directory = Path(c.directory) / "files"
    if capture and not directory.exists():
        directory.mkdir(mode=0o700)
    _path(directory, directory=True)
    for e in c.evidence:
        target = directory / e.name
        if capture:
            data = _read(e.path)
            _require(_digest(data) == e.sha256, "Private input hash changed")
            _require(total + len(data) <= MAX_TOTAL, "Oversized recovery evidence")
            if not target.exists() and not target.is_symlink():
                # A torn copy must never occupy its final name and poison retry.
                # The attested parent lock serializes publication in this directory.
                fd, temporary = tempfile.mkstemp(prefix=".pending-", dir=directory)
                try:
                    with os.fdopen(fd, "wb") as stream:
                        stream.write(data)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.replace(temporary, target)
                finally:
                    if os.path.exists(temporary):
                        os.unlink(temporary)
        data = _read(target)
        total += len(data)
        _require(total <= MAX_TOTAL and _digest(data) == e.sha256, "Private recovery copy hash/size changed")
        records[e.name] = {"role": e.role, "path": "files/" + e.name, "sha256": e.sha256, "size": len(data)}
    fd = os.open(directory, os.O_RDONLY)
    try:
        if capture:
            os.fsync(fd)
    finally:
        os.close(fd)
    return records


def validate_manifest(c, value, *, complete=True):
    """Pure schema/binding validation; native identities require assess_restore."""
    keys = {"schema_version", "binding", "state", "datasets", "snapshots", "evidence", "cold_boundary",
            "original_services", "capacity", "coverage", "restore_procedure"}
    if c.schema_version == 2:
        keys.add("quiescence")
    _require(isinstance(value, dict) and set(value) == keys and type(value["schema_version"]) is int
             and value["schema_version"] == c.schema_version and c.schema_version in (1, 2)
             and value["binding"] == c.binding()
             and value["state"] in (("complete",) if complete else ("prepared", "complete")),
             "Invalid recovery manifest schema/binding/state")
    _require(value["restore_procedure"] == "cold-nonrecursive-v1; parent reconciliation required"
             and _hash(value["cold_boundary"]), "Invalid recovery procedure/evidence")
    coverage = {"independent_copy_verified": False, "restore_rehearsal_verified": False}
    if c.schema_version == 2:
        _require(c.quiescence_mode == OPERATOR_OFFLINE and _hash(c.preparation_sha256)
                 and value["quiescence"] == _contract(c), "Invalid offline quiescence contract")
        coverage.update(unsaved_editor_work_covered=False, machine_drain_verified=False)
    else:
        _require(c.quiescence_mode == VERIFIED_DRAIN and c.offline_acknowledgement is None
                 and c.preparation_sha256 is None, "Invalid verified-drain contract")
    _require(value["coverage"] == coverage
             and all(v is False for v in value["coverage"].values()),
             "Independent-copy/rehearsal coverage needs separately reviewed evidence")
    expected = {r.name: r.mountpoint for r in c.resources}
    _require(isinstance(value["datasets"], dict) and set(value["datasets"]) == set(expected),
             "Recovery dataset set changed")
    for name, meta in value["datasets"].items():
        _require(isinstance(meta, dict) and set(meta) == {"mountpoint", "guid"}
                 and meta["mountpoint"] == expected[name], "Invalid recovery dataset")
        _number(meta["guid"], True)
    _require(len({m["guid"] for m in value["datasets"].values()}) == len(expected),
             "Duplicate recovery dataset GUID")
    snapshots = value["snapshots"]
    names = {_snapshot(c, name) for name in expected}
    _require(isinstance(snapshots, dict) and
             (not snapshots if value["state"] == "prepared" else set(snapshots) == names), "Invalid snapshot set")
    for meta in snapshots.values():
        _require(isinstance(meta, dict) and set(meta) == {"guid", "createtxg"}, "Invalid snapshot identity")
        for field in meta.values():
            _number(field, True)
    _require(not snapshots or (len({m["createtxg"] for m in snapshots.values()}) == 1
                              and len({m["guid"] for m in snapshots.values()}) == len(snapshots)),
             "Invalid atomic snapshot identities")
    services = value["original_services"]
    _require(isinstance(services, dict) and set(services) == {c.config.nextcloud_jail, c.config.onlyoffice_jail}
             and all(v in ("running", "stopped") for v in services.values()), "Invalid original services")
    capacity = value["capacity"]
    _require(isinstance(capacity, dict) and set(capacity) == {"used_bytes", "available_bytes", "required_bytes"}
             and all(type(v) is int and v >= 0 for v in capacity.values())
             and capacity["required_bytes"] == capacity["used_bytes"] + max(1024 ** 3, (capacity["used_bytes"] + 9) // 10)
             and capacity["available_bytes"] >= capacity["required_bytes"], "Invalid capacity evidence")
    evidence = value["evidence"]
    _require(isinstance(evidence, dict) and
             (not evidence if value["state"] == "prepared" else set(evidence) == {e.name for e in c.evidence}),
             "Invalid private evidence set")
    for e in c.evidence:
        if e.name not in evidence:
            continue
        meta = evidence[e.name]
        _require(isinstance(meta, dict) and set(meta) == {"role", "path", "sha256", "size"}
                 and meta["role"] == e.role and meta["path"] == "files/" + e.name
                 and meta["sha256"] == e.sha256 and type(meta["size"]) is int
                 and 0 <= meta["size"] <= MAX_FILE, "Invalid private evidence reference")
    _require(sum(m["size"] for m in evidence.values()) <= MAX_TOTAL, "Oversized recovery evidence")
    return value


def capture(c: RecoveryContext, backend: NativeBackend):
    """Capture/retry an atomic set under a continuously proven cold boundary."""
    try:
        proof = _boundary(c, "capture")
        storage = backend.storage(c)
        path = Path(c.directory) / "manifest.json"
        if path.exists() or path.is_symlink():
            value = validate_manifest(c, _load(path), complete=False)
            _require(value["datasets"] == storage, "Capture identity changed")
            _capture_identity(c, value, proof)
        else:
            _require(not backend.snapshots(c, storage), "Unjournaled snapshots cannot be adopted")
            _require(proof.capture_anchor_sha256 in (None, proof.evidence_sha256),
                     "Initial capture anchor changed")
            value = {"schema_version": c.schema_version, "binding": c.binding(), "state": "prepared", "datasets": storage,
                     "snapshots": {}, "evidence": {}, "cold_boundary": proof.evidence_sha256,
                     "original_services": dict(proof.original_services), "capacity": backend.capacity(c),
                      "coverage": {"independent_copy_verified": False, "restore_rehearsal_verified": False},
                      "restore_procedure": "cold-nonrecursive-v1; parent reconciliation required"}
            if c.schema_version == 2:
                value["quiescence"] = _contract(c)
                value["coverage"].update(unsaved_editor_work_covered=False, machine_drain_verified=False)
            _save(c, "manifest.json", value, "capture-prepared")
        found = backend.snapshots(c, storage)
        _require(value["state"] != "complete" or (found and found == value["snapshots"]),
                 "Completed recovery snapshots changed")
        if not found:
            backend.capacity(c)
            _capture_identity(c, value, _boundary(c, "capture"))
            _require(backend.storage(c) == storage, "Dataset identities changed")
            backend.run("zfs", "snapshot", "-o", f"{OWNER}={c.config.instance}", "-o",
                        f"{MANAGER}=cloud-installer", "-o", f"{TOKEN}={c.operation_id}",
                        *(_snapshot(c, r.name) for r in c.resources))
            found = backend.snapshots(c, storage)
            _require(bool(found), "Atomic snapshot set is missing")
        evidence = _copies(c, capture=value["state"] != "complete")
        _capture_identity(c, value, _boundary(c, "capture"))
        _require(backend.storage(c) == storage and backend.snapshots(c, storage) == found,
                 "Capture identities changed")
        value.update(state="complete", snapshots=found, evidence=evidence)
        validate_manifest(c, value)
        _save(c, "manifest.json", value, "capture-complete")
        return value
    except RecoveryError:
        raise
    except Exception:
        raise RecoveryError("Recovery capture failed; retain private artifacts and the stopped pair") from None


def _capture_identity(c, value, proof):
    anchor = proof.evidence_sha256
    if c.schema_version == 2 and proof.capture_anchor_sha256 is not None:
        anchor = proof.capture_anchor_sha256
    _require(value["cold_boundary"] == anchor
             and value["original_services"] == dict(proof.original_services), "Capture identity changed")


def _preflight(c, backend):
    proof = _boundary(c, "restore")
    value = validate_manifest(c, _load(Path(c.directory) / "manifest.json"))
    if c.original_restore is not None:
        _require(_json_hash(value) == _original_restore_consent(c).manifest_sha256, "Original restore manifest changed")
    anchor = proof.capture_anchor_sha256 if c.schema_version == 2 else proof.evidence_sha256
    _require(value["cold_boundary"] == anchor
             and value["original_services"] == dict(proof.original_services), "Recovery cold-boundary identity changed")
    _require(_copies(c) == value["evidence"], "Private evidence changed")
    _require(backend.storage(c) == value["datasets"], "Recovery dataset identities changed")
    _require(backend.snapshots(c, value["datasets"], restoring=True) == value["snapshots"],
             "Recovery snapshot identities changed")
    return value


def assess_restore(c: RecoveryContext, backend: NativeBackend):
    """Read-only preflight; missing native recipe proof is an explicit blocker."""
    try:
        value = _preflight(c, backend)
        _restore_journal(c, value, backend)
        return RestoreAssessment(True, (), _json_hash(value))
    except RecoveryError as error:
        return RestoreAssessment(False, (str(error),))
    except Exception:
        return RestoreAssessment(False, ("Recovery evidence is missing, unsafe or invalid",))


def _restore_journal(c, value, backend):
    path = Path(c.directory) / "restore.json"
    if not path.exists() and not path.is_symlink():
        return {"schema_version": 1, "binding": c.binding(), "manifest_sha256": _json_hash(value),
                "state": "restoring", "members": {r.name: "not-started" for r in c.resources}}
    record = _load(path)
    _require(isinstance(record, dict) and set(record) == {"schema_version", "binding", "manifest_sha256", "state", "members"}
             and type(record["schema_version"]) is int and record["schema_version"] == 1
             and record["binding"] == c.binding() and record["manifest_sha256"] == _json_hash(value)
             and record["state"] in ("restoring", "datasets-restored")
             and isinstance(record["members"], dict) and set(record["members"]) == set(value["datasets"])
             and all(v in ("not-started", "running", "complete") for v in record["members"].values()),
             "Invalid restore checkpoint")
    _require(record["state"] != "datasets-restored" or all(v == "complete" for v in record["members"].values()),
             "Incomplete restored-set checkpoint")
    for name, state in record["members"].items():
        if state == "complete":
            _require(backend.unchanged(c, name), "Completed restored member changed; refuse replay")
    return record


def restore(c: RecoveryContext, backend: NativeBackend):
    """Restore closed datasets only. Never start services or claim 'recovered'.

    Parent must separately prove selective graph/PF/credential reconciliation,
    application checks, supported data-fingerprint/client reconciliation and the
    recovery-publication checkpoint. This function cannot supply those proofs.
    """
    try:
        value = _preflight(c, backend)  # Entire set before the first rollback.
        record = _restore_journal(c, value, backend)
        for r in c.resources:
            state = record["members"][r.name]
            if state == "complete":
                continue
            _require(_preflight(c, backend) == value, "Recovery evidence changed during restore")
            # A running checkpoint cannot prove the command ran. Even zero
            # written bytes is not content equality. Reapply only this pinned,
            # nonrecursive target under the rechecked fence/topology.
            record["members"][r.name] = "running"
            _save(c, "restore.json", record, "restore-running", r.name)
            _require(_preflight(c, backend) == value, "Recovery evidence changed before rollback")
            _require(_restore_journal(c, value, backend) == record, "Restore checkpoint changed before rollback")
            backend.run("zfs", "rollback", _snapshot(c, r.name))
            _require(_preflight(c, backend) == value and backend.unchanged(c, r.name),
                     "Restored member verification failed")
            record["members"][r.name] = "complete"
            _save(c, "restore.json", record, "restore-complete", r.name)
        _require(_preflight(c, backend) == value and all(backend.unchanged(c, r.name) for r in c.resources),
                 "Restored set verification failed")
        record["state"] = "datasets-restored"
        _save(c, "restore.json", record, "datasets-restored")
        return {"state": "datasets-restored", "recovered": False, "manifest_sha256": _json_hash(value),
                "blockers": ["Parent graph/PF/credential reconciliation and application/data-fingerprint checks required",
                             "Parent fenced validation and recovery-publication finalization required"]}
    except RecoveryError:
        raise
    except Exception:
        raise RecoveryError("Recovery interrupted; retain private artifacts and the stopped pair") from None
