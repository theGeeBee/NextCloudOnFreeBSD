# Version discovery, compatibility and upgrade assessment

Version management is separate from installation execution. The existing two-jail
sequence, ownership checks, PF transactions, initialization recovery and exact
backup/restore rules remain in place. **This is not an automatic updater.**

## Central policy and configuration

### Maintaining fresh-install versions

For a new supported family or changed bounds/pins, change **policy data**, not
installer version literals. Stable releases already within supported families
can resolve without a per-patch policy edit. Review the tagged application's PHP/database/connector
requirements, target ABI/native package layout and complete signed pkg dependency
closure first. For a VM backend also verify the exact guest checksum, OCI index
and amd64 platform digest, product version and image configuration/layout evidence.
Do not infer support from a larger number, a tag name or an available download.

Update the selected profile/bounds/pins and dated evidence in
`resources/versions.json`; keep discovery independent of compatibility. Preserve
native legacy schema/hash fixtures and disjoint backend selection. Run the
future-policy fixtures in `test_backend_versions`/`test_vm_resolution`, selected
schema/worker tests and the combined offline suite, then collect bounded native
evidence for changed integration seams. New layouts/APIs need a reviewed adapter
change, not merely wider bounds. Synthetic future-version fixtures demonstrate
data-driven selection, not support for unreleased versions.

Only new installations resolve the newest stable compatible candidate allowed
by the supported family/profile, policy and operator minimum/exact pin. A failed
newer candidate may allow an older **still allowed, same-family** candidate;
never fall below minimum/pin or silently cross a family boundary.
Registered instances retain immutable `versions.json` and hashed dependency
locks. Resume never reselects, upgrades or silently repairs a missing/changed
locked artifact. Policy maintenance is not an installed-instance update service.

`resources/versions.json` is the authoritative, shipped version policy. It contains
default constraints, reviewed FreeBSD release/architecture targets, dependency
profiles, native-layout boundaries and dated evidence. Changing a constraint does
not add compatibility evidence. The reviewed baseline remains Nextcloud 35,
native ONLYOFFICE 9.4 Community, PHP 8.5, MariaDB 12.3 and Bastille 1.4.4 on
FreeBSD 15.1-RELEASE amd64. Consult the JSON for exact bounds and reviewed versions.

`office_backend` selects the version profile. Omission, `""` and `"onlyoffice"`
retain the native selection and schema-1 lock/runtime representation. `"none"`
has an explicit independent profile repeating the reviewed Nextcloud, PHP,
database, cache, web-server and Bastille requirements; it does not inherit from
the office profile. Its fresh-install application family is Nextcloud 35.
It selects only host and Nextcloud package closures, including Bastille, without
office/font roots, connector metadata or office upstream availability checks.

Euro-Office and Collabora use the common Nextcloud constraints and explicit
backend-specific metadata profiles. Discovery checks only their selected signed
connector and host/NC packages, the pinned Alpine checksum/availability, and the
pinned OCI index/platform manifest. It neither downloads image layers nor probes
bhyve. See [profile status](fresh-install-profiles.md) and the
[validation matrix](verification.md) for historical accepted artifacts and current
family-selection checks. A successful metadata plan is not a usable editor or
permission to skip native preflight, APPLY or supervised PF KEEP. The `none`
branch uses the shared single-jail installation path. Successful resolution does
not extend native maintenance/backup contracts to these profiles.

Schema-2 instance configuration accepts these additional string fields:

| Field | Meaning |
| --- | --- |
| `freebsd_release` | Selected jail/host RELEASE, without a patch suffix |
| `architecture` | Selected FreeBSD architecture; must have a reviewed target |
| `nextcloud_min` | Minimum stable upstream Nextcloud version |
| `onlyoffice_min` | Minimum stable upstream Document Server version |
| `nextcloud_exact` | Optional exact stable Nextcloud release |
| `onlyoffice_exact` | Optional exact Document Server upstream/package version |

The two `onlyoffice_*` constraints apply only to the native backend. The other
profiles retain the target and Nextcloud constraints, plus any applicable
`version_families` selection described below.

### Optional fresh-install family selection

`version_families` is a flat JSON object of numeric major or major/minor strings.
Keys identify an application/dependency role or an actual selected package name.
For a native ONLYOFFICE recipe, for example:

```json
{
  "version_families": {
    "nextcloud": "35",
    "php": "8.5",
    "database": "12.3",
    "onlyoffice": "9.4",
    "connector": "10.2",
    "manager": "1.4",
    "web": "2.4",
    "cache": "8",
    "nginx": "1.30"
  }
}
```

Use only keys applicable to the selected backend. `database` constrains both
client and server. A package-name key constrains that selected package; naming an
optional package does **not** select it or add a package root. Families are not
arbitrary package substitutions: configuration selects supported profiles and
package-family identities. A genuinely new family needs compatible policy
profiles and layout bounds, and code review where interfaces change; this field
cannot override hard compatibility checks.

Omitting the map or using `{}` preserves old configuration digests. Without an
explicit family override, defaults allow the whole Nextcloud 35 family,
ONLYOFFICE 9.4, Bastille 1.4 and backend connector families 10.2 (ONLYOFFICE),
11.0 (Euro-Office) or 12.0 (Collabora). PHP 8.5, MariaDB 12.3 and Apache 2.4
remain same-family. Redis keeps its original `4 <= version < 9` range unless
explicitly constrained: `"cache": "8"` above is an example, not a new default pin.
For VM tooling, `vm_manager` (vm-bhyve) 1.7 and `vm_image_tools` (qemu-tools)
11.1 families allow numeric patch releases;
opaque firmware versions remain exact. Alpine images, OCI digests and artifact
checksums remain exact too; no floating container tags are introduced.

Existing minimums, exact pins, policy bounds, signed connector requirements and
layout checks still intersect these selections. An empty intersection is an
error, not permission to fall back to another family. A family is a selection
boundary, **not certification of every exact combination** within it.

### Minimums and exact pins

Empty string values select policy defaults. The wizard exposes application minimums and
pins and records the detected target. For example, add the following fields to
an otherwise complete configuration **before registering an instance**:

```json
{
  "nextcloud_min": "35.0.1",
  "nextcloud_exact": "35.0.1",
  "onlyoffice_min": "9.4.0",
  "onlyoffice_exact": "9.4.0_4"
}
```

Do not edit a registered configuration or version lock to request an upgrade.
A higher minimum with no reviewed/available candidate produces an error, not a
fallback below the minimum. An exact pin must satisfy both the minimum and
compatibility policy. Prereleases are unsupported; there is no bypass flag.
Minimums accept one to three numeric components (`35`, `35.0`, `35.0.1`). Exact
Nextcloud pins require three components. An ONLYOFFICE three-component pin allows
the available FreeBSD revision of that upstream release; adding `_N` or `,N`
requires the **entire package version string** to match, including all suffixes.

Application versions are compared numerically, not lexically. FreeBSD package
revisions (`_N`) and epochs (`,N`) are distinct from upstream application versions.
Nextcloud's fourth internal build component is not its public archive version.
PECL extension versions are independent of the PHP runtime version; their PHP
flavor and package dependency edges must match instead.
Historical exact-version evidence includes Nextcloud **35.0.0/35.0.1**,
ONLYOFFICE upstream **9.4.0** and connector **10.2.1**; these are not the current
fresh-install patch ceiling. Family selection can admit a newer stable compatible
patch without claiming that its exact combination passed end-to-end acceptance.
The separate optional upgrade adapter supports the reviewed **35.0.1→35.0.2**
transition; fresh-install family policy does not broaden that adapter.

## Three separate responsibilities

### Discovery — what exists

`installer/discovery.py` reads:

- Explicit numeric archive names and detached-signature links in the official
  [Nextcloud release index](https://download.nextcloud.com/server/releases/).
  Mutable `latest-*` aliases and development branches are not release identities.
- Stable, non-draft releases from the official
  [ONLYOFFICE release API](https://api.github.com/repos/ONLYOFFICE/DocumentServer/releases?per_page=100).
  This bounded query reports upstream availability, not native FreeBSD support.
- The selected Nextcloud platform's signed-app metadata from the
  [Nextcloud app-store API](https://nextcloudappstore.readthedocs.io/en/latest/api/restapi.html).
- The selected official FreeBSD-ports branch using **native pkg fingerprint
  authentication**, an isolated private repository configuration/database/cache,
  and `rquery -U`. It does not install packages or alter the host package database.
  Explicit ABI selection is paired with the validated native userland OSVERSION
  (`uname -U`), so pkg does not guess the major release's `.0` baseline. Catalog
  update receives EOF on stdin: an unseen OS-version question must fail, not hang
  behind captured output. OS-version and signature checks remain enabled.

The signed pkg catalog is authoritative for native package availability: it
normally offers one current version per package name, not an archive of every
patch in a family. Nextcloud server archives and signed App Store connectors
are separate upstream sources, not pkg candidates; selection chooses their
newest stable compatible release within the allowed family and constraints.

Catalog records preserve package names, full versions, origins, canonical ABI,
archive checksums and dependency edges. Declared dependency counts detect truncated metadata. Legitimate
architecture-independent packages use an ABI such as `FreeBSD:15:*`; this does not
authorize native binaries for another architecture. Ambiguous package names are
unavailable, never collapsed with a last-record-wins rule.
Packages with unversioned dependency references are also unavailable, after
declared counts have been checked. No dependency version is inferred. Unrelated
unusable packages do not invalidate the whole catalog, but a selected closure
that needs one still fails before provisioning.
Archive checksums use pkg's native typed representation, not an assumed SHA256
encoding. The adapter uses the extended `%u` formatter, reviewed against pkg 2.8.4;
legacy `%X` is an internal digest, not the catalog archive checksum. An older pkg
without the required query interface fails closed and needs separate host review.

HTTPS responses, metadata size and request duration are bounded. Redirects cannot
downgrade TLS or leave the authoritative origin. Missing repositories, malformed
metadata and network failures have explicit diagnostics; no fabricated default
version, stale fallback, third-party package source or automatic ports build is used.

Discovery can apply requested minimums/pins to bound metadata queries. It does
**not** decide that a discovered release or dependency combination is compatible.
The ONLYOFFICE query covers the latest 100 release records. Connector queries are
limited to 32 Nextcloud releases satisfying the configured constraints; exceeding
that limit requires a narrower minimum/pin rather than unbounded network requests.

### Compatibility — what the implementation can support

`installer/compatibility.py` evaluates data without network requests or installation
commands. It checks the selected target and repository, explicit application and
dependency bounds, package origins/ABIs, complete dependency closure and the signed
connector's independent Nextcloud/PHP requirements. Missing evidence is refusal.

The policy is intentionally narrower than upstream's entire support matrix. NC35
documents several PHP/MariaDB families, but that does not prove that this worker's
configuration templates, SQL initialization, extension naming or FreeBSD packages
support all of them. Apache, PHP-FPM and MariaDB service paths are implementation
contracts, not arbitrary interchangeable package choices.

Likewise, ONLYOFFICE 9.4 Community's native embedded-conversion/memory-state layout
does not establish compatibility with upstream 10.0. Native port availability is
necessary but insufficient. A port for another architecture does not by itself add
a reviewed host/jail target.

### Resolution — which supported combination to use

`installer/resolution.py` combines discovered availability with independent
compatibility results. It selects the newest verified stable candidate within all
constraints and emits an inspectable JSON plan, including effective constraints,
target, selected applications/connector, dependency roles, exact per-location
package closures, evidence sources and the policy hash.

Before provisioning, native pkg performs solver **dry runs** in a private empty
database for the locked groups. An unavailable package, dependency conflict, OS
requirement failure or changed catalog record stops installation. Shared host
prerequisite and jail-worker dry-runs retain `-n` and add `-y`: pkg 2.8.4 otherwise
reports a valid plan as declined (exit 1). The isolated resolver DB remains empty,
and missing/conflicting packages still return failure. Shared host
prerequisites cannot be implicitly upgraded or downgraded for another instance.

A successful solver exit alone is insufficient: pkg can add shared-library
providers that are absent from declared dependency edges. The reviewed pkg2.8.4
C-locale dry-run summary must contain exactly the locked package names/versions,
matching action counts and no upgrades/removals or unrecognized actions. Changed
output formats fail closed; this is not a generic machine-readable pkg interface.
Native ONLYOFFICE9.4.0_4 testing identified `libcares.so.2` and `libuv.so.1` as such
requirements. The reviewed profile explicitly selects `dns/c-ares` and
`devel/libuv`, with exact catalog identities locked during new resolution. Existing
locks are never expanded automatically to absorb a successful solver's additions.

## Inspect without installing

```sh
# Pure static topology/constraint plan; no discovery or host changes:
sh install.sh plan examples/config.json

# On the selected FreeBSD target, with pkg/Python already installed:
sh install.sh resolve /absolute/path/to/config.json

# Offline on Linux or FreeBSD, using saved/mock discovery JSON:
sh install.sh resolve config.json --metadata discovery.json

# Read-only upgrade comparison against an explicitly supplied retained lock:
sh install.sh resolve proposed.json --metadata discovery.json --installed versions.json
```

`resolve` never provisions, installs dependencies, modifies a registry or performs
an upgrade. Live discovery writes only disposable catalog/cache files. `--metadata`
is for deterministic inspection/testing: its result is **not an authorization to
install**. The deployment workflow performs its own native authenticated discovery
and solver checks; it does not import operator-supplied plans.

The metadata interface is schema-versioned JSON containing `target`, `repository`,
`nextcloud`, `onlyoffice`, `connectors`, `packages` and `sources`. Tests supply
synthetic data through this same interface, independent of repository/network state.

Native metadata and plans retain schema 1. For `none`, metadata uses schema 2
with exactly `schema_version`, `office_backend: "none"`, `target`, `repository`,
`nextcloud`, `packages`, `sources`, and optional `extra_roots` (host/Nextcloud only).
Live discovery reads the Nextcloud index and signed FreeBSD catalog and retains
only the selected backend's required dependency closure. The shared catalog is
still queried as a whole; no office upstream or connector API is contacted.

The `none` resolved plan uses schema 2 and `office_backend: "none"`; applications
contain only `nextcloud`, roots/packages only `host` and `nextcloud`, and roles
only `manager`, `php`, `database`, `database_client`, `web`, `cache`. Connector,
office-version and font-availability sections are absent, not empty placeholders.
Other retained fields (target, repository, constraints, profile, policy hash,
sources and warnings) keep their existing meanings. Validation rejects extra
sections, mismatched backends, changed constraints, incomplete/conflicting closures
and policy drift. Upgrade comparisons explicitly block backend replacement.

VM metadata/plans use schema **3** with the explicit `office_backend` and
`connector_app` (`eurooffice` or `richdocuments`). Only `host` and `nextcloud`
package/root groups exist; no native office package, font report or sentinel
office version is added. `office_runtime` records `guest_image` (exact official
URL, SHA512, architecture, firmware/bootstrap/branch) and `container` (digest-only
reference, parent index digest, release label, architecture and frontend ports).
`artifacts` retains availability/provenance evidence bound to those identities.
Live discovery hashes the exact OCI index and selected linux/amd64 manifest;
bearer tokens remain request-local and are never recorded in plans or sources.
This is checksum/TLS availability evidence, not an OCI-signature or runtime claim.

The Euro-Office container record additionally pins `entrypoint_sha256`, reviewed
from digest-verified small OCI layers against its tagged standalone source. This
binds the persistence/JWT-file adapter's layout assumptions; it is not a substitute
for actually pulling/starting the image and checking the runtime version.
CODE similarly pins `configuration_sha256` for the XML read from its verified
application layer. Its adapter must start from those selected bytes and retain
isolation defaults while explicitly enforcing callback certificate verification
and the reviewed WOPI allowlist. A configuration hash is not operational approval.
Its `release` remains the reviewed image tag, while `product_version` records the
actual discovery/capabilities version. For the current pin these are26.04.5.1.1
and26.04.5.1 respectively; do not guess one by truncating the other.

VM connector profiles store the tagged `php_manifest` literally. Euro-Office11.0.6
declares `*`; richdocuments12.0.1 declares `>=8.3.0`, without a ceiling. Neither
widens the independent PHP8.5 role bound or changes native ONLYOFFICE's stricter
bounded-manifest validator. Numeric VM tooling uses its supported families;
exact `version_exact` retains the reviewed opaque `edk2-bhyve` version `g202508_3`;
no numeric ordering or lower fallback is invented for firmware.
VM-only dated evidence lives inside its profile, preserving the old
native/none policy projections and immutable locks.

The shared public NC wire frame adds only the actual VM backend/app ID and
connector version/hash to its common fields. Python/PHP/Lua validate the same
exact key set and backend/app relationship. VM connector install/finish uses the
selected backend's signed-app and integration checks; a wire-frame match alone
does not authorize activation.

Policy digests include the existing policy envelope and only the selected
backend's profiles. Adding the independent `none` profile therefore preserves
the historical native policy digest and native plan/runtime bytes. Existing locks
are not rewritten. Changes to shared policy data or the selected profiles still
require their original reviewed policy for retained-plan validation.

The pure `none` runtime representation contains `office_backend: "none"` and the
common Nextcloud/PHP/database/target/package-lock digest fields. It has no
`onlyoffice`, `connector` or `connector_sha256`. The shared worker accepts that
exact representation without office integration; no native acceptance is implied.

## Registry-aware update reports

Report schema 2 additionally binds the active lifecycle graph. Known
schema-1 caches remain readable without an invented graph reference or implicit
write; normal code/graph freshness checks make changed evidence stale. Enrolled
config/locks/status come from authoritative generation/graph lookup, never the
legacy registration descriptor or a stale status projection. A report still
does not authorize migration.

`check-updates NAME` reads a cached assessment bound to that retained instance.
`--all` covers registered non-removed instances; omitted scope prompts only with
a terminal. `--refresh` explicitly discovers current upstream versions and signed
native catalogs using existing pkg/Python on the reviewed FreeBSD host. It uses
disposable metadata directories, never active package databases. Without refresh,
there are no network/pkg probes, registry writes or operation locks.

Reports compare **retained intended versions**, not live installed drift. They
include application versions, dependency/root changes and exact native archive
checksums; same-version checksum changes are blocked for manual review. Candidate
selection remains within configured minima/exact pins and reviewed policy. Newer
upstream releases outside those bounds can be reported without approving them.
No fresh-install or installed-package upgrade solver is run by `check-updates`;
destination support here means metadata compatibility only.

| Status | Meaning |
| --- | --- |
| `unknown` | No saved report, or inspection/discovery failed; inspect errors/freshness |
| `current-within-reviewed-policy` | No change within the reviewed policy and configured constraints; not a security/upstream-current claim |
| `available-unreviewed` | Newer stable upstream releases exist without a selected supported change |
| `destination-supported-path-unavailable` | Metadata supports a changed destination; there is no implemented migration path |
| `blocked` | Comparison has blockers, installation is not ready, no destination is obtainable, or report saving was refused |

`execution_authorized` and `migration_supported` are always false. This report never emits
`reviewed-path-available`. The host summary covers only selected shared prerequisite
locks, not full host inventory, OS updates, support/EOL or security advisories.

`--refresh --save-report` explicitly saves the latest result under private
`update-reports/NAME.json`; it does not change config, source or version locks.
Saving rechecks bindings under the host operation lock and refuses pending
network/installation/removal/restore conflicts. Discovery failures can be saved
as failures, never as “up to date”. Cache reads mark results stale after 24 hours
or changes to configuration, status, deployment journal, retained versions/source,
current policy or inspector code. Stale results are historical, not current
authorization; rerun with explicit refresh. Malformed/unsafe cache records fail
inspection rather than silently falling back or repairing them.

Historical locks are structurally inspected even when their policy hash differs
from today's. Missing original-policy provenance is disclosed; current policy
is used for destination selection only. Configurations the current reader cannot
interpret, or missing/corrupt locks, produce inspection errors. Original-artifact
requirements for all existing mutation commands remain unchanged. Retain the
original artifact separately when using newer code for read-only inspection.

See [operational examples](operations.md#dashboard-and-update-reports). Complete
native report-path acceptance remains incomplete; discovery and save paths have
offline mocked coverage. Catalog/solver results in the [validation matrix](verification.md)
do not establish the complete report/cache workflow.

## Locked execution and Resume

The host saves `instances/NAME/versions.json` before ZFS/PF/jail/application
provisioning and displays it before `APPLY`. This is immutable selection evidence,
not the refreshable observed `inventory.json`. It is bound to the effective
constraints and policy. Preserve it with the original artifact and configuration.

The review always warns that the **resolved exact combination is not certified
as project-validated**. A new patch is not equivalent to end-to-end acceptance.
The existing `APPLY` approval (or recipe `--yes`) includes acceptance of this
warning, without another confirmation screen. Neither form of consent bypasses
hard validation, authenticated discovery, solver checks or exact locks.

Workers receive only public selected versions and hashed package/dependency lock
files. They recheck the target, signed repository records, dependency edges and
installed package identities; installation uses exact names/versions and `-U`.
They never run a blanket `pkg upgrade`. Optional SSH prerequisites and selected
fonts are included before application package inventories are finalized.
Thick pkgbase jails inherit the signed base-release package database. Packages in
the reserved `FreeBSD-*` namespace with the exact matching `base/FreeBSD-*` origin
are OS inventory, not extra ports. The application lock neither installs nor
updates them; the selected kernel/userland RELEASE is checked independently.

Nextcloud downloads a version-specific archive, retaining the existing detached
signature check against the pinned release signing key and authenticated-archive
resume checks. The code's actual version must match selection. Connector delivery
passes the exact retained certificate, signature and URL through a small pinned
fetcher to Nextcloud's native installer, retaining its CA/CRL, archive signature
and dependency checks. Public `connector.json` bytes are hash-bound and handed
to the unprivileged helper on a root-opened descriptor, never as executable data.

Forced native per-file integrity verification precedes every migration-capable
installation or enablement. A protected system-config receipt binds the signed
record and complete tree manifest; a copied `info.xml` or directory alone is not
authentication evidence. Interrupted/incomplete copies without that receipt fail
closed, without overwriting the tree. Preserve the state and obtain explicit
recovery review; after publication, `recover-install` is deliberately ineligible.
This limited manual-recovery case is preferable to adopting unauthenticated code
or erasing application data to make Resume succeed.

Resume reuses the saved selection, never discovers a newer replacement. If a
rolling repository no longer offers the locked dependency set, Resume refuses.
The lock is **not a retained binary package repository**: preserve a trusted
repository snapshot/artifacts operationally, or perform a separate recovery
assessment. Do not rewrite locks or lower constraints to make a retry pass.
Locks retain native package archive checksums as well as version/origin/ABI and
dependency identity. Discovery rechecks and workers reject a same-version catalog
rebuild with a changed checksum before installation. Native pkg authenticates the
catalog and verifies downloaded payloads against those sums; the tool does not
replace its verification with a custom checksum algorithm. Installed-version checks
are not a forensic attestation of every live file or locally edited configuration.

Old schema-2 configurations without the new fields keep their serialized digest;
existing journals are not rewritten or adopted. An older deployment lacking a
version lock requires its original artifact for provisioning/maintenance. Source
and runtime bindings remain strict. This change does not retrofit unknown
installed versions into a guessed lock or modify working instances.
The central `legacy_target` retains the historical release/architecture when old
configuration JSON omits every version field; changing future defaults must not
reinterpret those old jail reservations.

## Upgrade policy

The optional [native upgrade assistant](upgrade.md) implements the reviewed
**35.0.1→35.0.2** transition, plus compatible application-jail package updates
within its reviewed policy. An already-updated 35.0.2 instance can be assessed
for those package updates. It is not a permanent manager or an arbitrary-version
updater. The [experimental lifecycle controller](maintenance-recovery.md) is separate;
its native maintenance apply remains blocked.

Upgrades require an explicit, separately approved maintenance procedure. A
read-only assessment compares an installed lock with a resolved destination,
rejects downgrades and lists changes. **Destination compatibility is not migration
compatibility.** No migration execution is authorized by that report.

`resolve` and `check-updates` remain read-only discovery/assessment interfaces:
neither runs `occ upgrade` or authorizes execution. Only the explicit `upgrade`
workflow runs supported native package/application steps, including `occ upgrade`
for the reviewed transition, after consent and coherent stopped-jail ZFS snapshots.
On failure, restoration requires the user's explicit choice through
`upgrade INSTANCE --restore SNAPSHOT_REPORT`; it is never automatic.
Host OS, Bastille and jail-base upgrades are outside that assistant. Resume is
not an upgrade command. Sequential-major Nextcloud upgrades, database format
transitions, custom-app compatibility and automatic ONLYOFFICE document-state
draining need separate release-specific evidence and implementation review.

Retain coherent code/configuration/files/database/jail recovery sets, original
secrets and locks; close editors and establish a maintenance window. Existing
database restore still requires exact same-instance application/database versions.
A newer policy or compatible destination never relaxes that requirement.

## Adding supported versions

### Routine new-install maintenance

Edit **only `resources/versions.json`** when the upstream interfaces/layouts remain
compatible. `defaults.nextcloud_min` / `nextcloud_exact` request a new-install
version; native `onlyoffice_min` / `onlyoffice_exact` request Document Server.
These requests never approve compatibility or change an installed instance.

Approve the combination separately in the applicable explicit `profiles` entry:
`applications` bounds, `roles` package names/origins/ranges, `php_suffix`, required
`php_extensions` / `extension_ranges`, `roots` and `optional_roots`. Review the
complete signed FreeBSD dependency closure. Native office requires its explicit
font and shared-library roots as well as the connector's supported family and
Nextcloud/PHP manifest bounds. The independent `none` profile contains only NC
requirements; keep it reviewed separately rather than adding fake office groups.
Keep family/layout changes separate from unrelated backend feature changes.

Validate without provisioning:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -c 'from installer.versions import load_policy; load_policy(); print("policy OK")'
sh install.sh plan examples/config.json
sh install.sh plan examples/nextcloud-only.json
sh install.sh resolve config.json --metadata reviewed-discovery.json
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=.:tests python3 -m unittest test_backend_versions test_versions test_discovery -v
```

`reviewed-discovery.json` is the existing schema-versioned metadata interface,
not a second authoritative policy. `test_backend_versions` demonstrates disposable
synthetic future NC/PHP/database/dependency selections resolving with unchanged
algorithms, and rejects unsupported combinations. It does **not** approve those
versions for installation. Discovery/solver checks on the actual signed target
repository and separately authorized native acceptance are still required.

Code changes are necessary for changed service layouts, runtime/boot protocols,
configuration syntax, dependency interfaces or connector APIs. In particular the
signed connector helper intentionally depends on Nextcloud's `OC\Installer` and
AppFetcher interfaces: a major release must review those, not merely raise a pin.
VM pins and connector manifest declarations are in their explicit profiles. Update
`office_runtime.guest_image` / `container` and the selected connector data only
after source/availability review; keep immutable digest references and update the
dated profile evidence. Configuration/port/layout or authentication changes still
require code. Inspection plans alone never authorize native execution.

1. Obtain authoritative tagged requirements and release metadata. Check security
   advisories and support lifetimes separately from functional compatibility.
2. Add or amend a **bounded** profile in `resources/versions.json`, recording sources
   and review date. Do not widen a range merely because a version sorts higher.
3. For Nextcloud, review PHP/DB/web-server requirements, extensions, CLI/private
   APIs used by helpers, app-store connector bounds and signed archive layout.
4. For ONLYOFFICE, review the native port's runtime dependencies, license, package
   helpers, service/configuration paths, process model and private endpoint rules.
   A changed deployment method/layout requires implementation review, not just JSON.
5. For FreeBSD, add the exact release/architecture/ABI and release-specific trust
   requirements. Review Bastille/pkgbase, mdo/flua, jail/VNET/PF interfaces and verify
   actual binary availability for that target. Major ABI equality is not enough.
6. Add deterministic supported/rejected fixtures, including dependency conflicts,
   missing metadata, pins/minimums, repository drift and no-downgrade checks. Run
   the existing recovery, worker, lifecycle and extracted-artifact suites.
7. Select the affected native cases from the
   [integration checklist](freebsd-15.1.md#freebsd-integration-checklist) in a separate
   approved task before claiming live compatibility. Preserve historical artifact
   boundaries and remaining limits in the [validation matrix](verification.md);
   a policy edit does not require an unrelated broad VM campaign.

## Evidence and limitations

### Bounded native family validation — 2026-10-23

On a disposable FreeBSD 15.1-RELEASE amd64 guest, real signed catalogs and native
pkg 2.8.4 solver dry runs passed for all four profiles on `latest`, and for
Nextcloud-only on `quarterly`. The observed selection included Nextcloud 35.0.2,
PHP 8.5.12, matching MariaDB 12.3.3 client/server packages, Apache 2.4.69 and
Redis 8.10.2. The native office plan selected ONLYOFFICE 9.4.0_4; connector plans
selected 10.2.1, 11.0.6 and 12.0.1. These are dated observations, **not new pins**.

The corrected Nextcloud-only artifact completed all 18 fresh-install steps on an
8-GiB/2-vCPU guest, independent Verify, non-admin account creation and conditional
DAV upload/download with matching SHA256 over hostname-validated HTTPS. Normal
public removal completed four steps with independent SSH before KEEP; application
datasets were retained and immutable configuration/version/source hashes stayed
unchanged. The disposable guest and its storage were subsequently removed.

The existing base-only command was also exercised on FreeBSD without Git, Bash
or Python preinstalled. It verified the archive before extraction, then obtained
the existing prerequisite consent. A wrong digest was rejected before extraction.
Transport used a loopback-only SSH tunnel and an existing valid certificate;
this does not test public forwarding or ACME issuance/renewal.

The run exposed nested family-map ordering in the configuration digest. Nonempty
maps now serialize canonically before registration; empty/legacy digests retain
their original representation. No enrolled artifact, journal or lock was repaired
in place: the correction was tested on a fresh guest. Regression coverage includes
all six key-order permutations and refusal of actual value changes.

Office runtime installation/editing, host reboot, backup/restore and broader
maintenance acceptance were not repeated here. Metadata/solver success for an
office profile is not its end-to-end acceptance, and future patches remain subject
to the displayed unverified-combination warning and all hard validation checks.

Reviewed on **2026-10-14**: NC35 requirements and tagged runtime checks, the native
FreeBSD ports/catalogs, ONLYOFFICE 9.4 runtime layout and connector 10.2.1 manifest.
The upstream ONLYOFFICE 10.0 release is discoverable but not an approved native
deployment profile. Its security fixes have **not** been assessed for applicability
or backports to the reviewed FreeBSD 9.4 package. No `secure: true` claim is made.

FreeBSD remains outside Nextcloud's upstream-listed server OS set. Metadata-backed
candidate validation is not a vendor support guarantee or native execution test.
Bounded native observations and remaining limits are summarized in the
[validation matrix](verification.md), the [FreeBSD checklist](freebsd-15.1.md) and
[upgrade guide](upgrade.md). Historical accepted artifacts are distinct from the
October 23 family-selection source. These results do not establish arbitrary-version,
complete reboot/fault or production-readiness acceptance.
