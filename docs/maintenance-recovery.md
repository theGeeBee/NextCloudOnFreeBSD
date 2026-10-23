# Experimental maintenance and recovery reference

This describes the existing, gated lifecycle controller, **not** the optional
[native upgrade assistant](upgrade.md). Permanent enrollment, custom generation
state, exports and recovery-set machinery are not prerequisites of that assistant.
The controller's complete native capture/restore/reboot/fault acceptance remains
incomplete. Its production recipe catalog is empty; do not add an entry, edit
state or bypass a guard to make an operation run.

This reference is retained to explain existing state and refusal/recovery
boundaries. New operators should use the current [operations guide](operations.md)
and [upgrade assistant](upgrade.md), not enroll merely to upgrade applications.

## Operator-assisted offline boundary

Before downtime, the operator must save required edits, close documents and
confirm that required state is visible in Nextcloud, then give the exact
operation-bound acknowledgment. This is not an automatic ONLYOFFICE drain proof.
Unsaved browser edits and unconfirmed in-memory office work are outside snapshot
coverage. `office_drained` remains false for this acknowledgment contract.

Before any code replacement or migration, the controller must reject unsupported
transitions, close ordinary ingress/writers, establish clean database/pair
shutdown, capture and verify the complete coherent ZFS snapshot set, and keep
validation isolated until successful reopening. Acknowledgment never bypasses
identity, storage, locking, capacity, shutdown or publication checks.

Preparation requires actual free memory and the conservative 8-GiB-plus-target-
archive free-space margin on each checked filesystem. An existing small `nc-app`
quota may not provide that margin. Quota changes need explicit capacity review;
preparation never silently resizes datasets. Reclaimable ARC is not already-free
RAM for this gate.

## Retained preparation commands

Use the exact retained artifact and protected payload path on the reviewed
FreeBSD host, as root with Python already installed. Ready enrolled generations
require their own source adapter; older artifacts are not automatically eligible.
Never reconstruct missing locks or rewrite baselines from live versions.

```sh
sh install.sh maintenance plan --instance cloud --recovery-only --json
sh install.sh maintenance plan --instance cloud --recovery-only --save
sh install.sh maintenance stage PLAN-ID --artifacts /root/maintenance-packages
sh install.sh maintenance status
sh install.sh maintenance status OP-ID --json
sh install.sh maintenance continue OP-ID --artifacts /root/maintenance-packages
sh install.sh maintenance cancel OP-ID
sh install.sh maintenance recover OP-ID --assess --json
```

Substitute actual identifiers. Saving, staging, continuing and cancellation use
exact `SAVE-MAINTENANCE cloud`, `STAGE-MAINTENANCE PLAN-ID`,
`CONTINUE-MAINTENANCE OP-ID` and `CANCEL-MAINTENANCE OP-ID` confirmations.
`maintenance recover` without an operation ID is the separate enrollment-metadata
recovery described in [lifecycle state](lifecycle-state.md).

Preparation binds the ready generation, all-instance graph, version lock,
executor/source/policy and committed network evidence. It copies only public
payload bytes into a private cache, never credentials, and never executes them.
Plans, operations and journals remain private (`0700` directories, `0600` files),
atomic and fsynced. Partial staging continues only with identical inputs.
Cancellation retains receipts, partial bytes and audit history; no pruning is
automatic. Inert staging does not set the global pending boot fence.

Overview status is metadata only; detailed status rehashes staged artifacts.
Damaged or missing bytes fail authentication. A cancelled operation can report
`artifacts_authenticated: false` with `cancelled-cache-authentication-failed`:
that warning does not undo terminal cancellation. Corrupt operation metadata
still refuses cancellation.

The cache is **not a backup**: it contains no coherent application snapshot,
independent recovery copy or full package/pkgbase/release archive coverage.
`artifacts_authenticated` never means `restore_eligible`.

## Authenticated candidate inspection

A staged preparation can inspect the fixed target without creating native intent:

```sh
sh install.sh maintenance prepare-target OP-ID --artifacts /root/target-artifacts --json
```

This requires exact `PREPARE-TARGET OP-ID` confirmation and protected root-owned
local inputs: `nextcloud-35.0.2.zip`, its `.asc` and `.sig`,
`nextcloud-35.0.1.tar.bz2.asc`, pinned release key `nextcloud.asc`, and
`connector.archive` containing the unchanged signed app-store release. These
are local input names, not invented published assets or trusted checksums.
Signatures, versions, source archive and connector bytes are authenticated.

Inspection uses isolated signed package catalogs and checks the complete exact
host/both-jail dependency closures and empty package transaction. CLI and both FPM
pool observations must agree with reviewed requirements. It neither installs
packages nor stops services or arms a boot fence. Original observation timestamps
expire after 300 seconds; decoding a receipt cannot refresh age. Revalidation
under the same host/database locks is mandatory immediately before native intent.
Unknown or changed evidence remains blocked, not adopted as a baseline.

## Gated execution and interruption

The following operations refuse before consent, mutation or native calls while
the reviewed recipe catalog is empty:

```sh
sh install.sh maintenance apply OP-ID --backup-dataset backup/maintenance
sh install.sh maintenance continue execution-ID
sh install.sh maintenance recover execution-ID --restore-original
sh install.sh maintenance cancel execution-ID
```

Backend contracts require retained admission/candidate evidence before durable
intent, persistent ingress/cron/SSH/writer closure, clean shutdown and narrow
validation-start permissions bound to live locks and the current journal hash.
Enrollment-start permission permits ordinary traffic and cannot substitute for
isolated maintenance permission. Stale JSON permission files grant no authority.

Migration starts only database/cache services. Temporary FPM observation is
separately constrained; web/office/cron/SSH remain fenced. Apache graceful reload
is asynchronous: closed-profile readiness uses bounded authenticated checks,
not merely a successful reload exit. Identity/transport errors fail closed.

Continuation never replays an uncertain updater attempt. Publication markers are
durable before access can reopen; once publication may have begun, destructive
original-set restoration cannot discard subsequent writes. Pre-publication
restoration requires separate explicit loss acknowledgment. Cancellation is
restricted to the unchanged original generation before completed capture or a
migration attempt, with verified readiness before clearing its fence. Unsupported
cross-boot cancellation remains blocked for manual assessment.

Cross-boot re-quiescence requires fresh runtime and database shutdown evidence;
it never reuses another boot's clean-shutdown proof. Half-started/unrecognized
states refuse. Failed restoration leaves affected jails stopped. Original
all-instance views remain immutable; restored/successor graphs are new commits,
not resets of a global pointer. Metadata copies must never overwrite credentials,
shared PF or the graph blindly.

## Coherent recovery-set and copy contracts

The native paired-jail set contains **14 datasets**: the application parent and
nine children, plus both Bastille jail parents and roots. It includes user files,
databases/logs, office state and installed jail package databases, unlike the
four-dataset initialization checkpoint.

- Establish fresh clean database shutdown, continuous writer freeze, bound
  acknowledgment, live locks, persistent boot fence and exact stopped/dying jail,
  mount, ownership, dataset identity and capacity checks. Stopped jails alone do
  not establish coherence. Unknown external dependencies or keys block completeness.
- Capture with one nonrecursive multi-dataset snapshot command; bind exact GUIDs
  and bounded private metadata. Assess the entire set before any rollback and
  recheck each member at its durable checkpoint. Changed GUIDs/ownership, newer
  snapshots or blocking clones/holds refuse. Never delete newer snapshots or use
  recursive rollback to force restoration.
- Original-set restoration can discard a failed target whose database cleanliness
  is explicitly unproven, but only before publication with exact consent, fresh
  absence of writers/mount aliases and the original affirmative clean-capture
  evidence. This exception never weakens capture requirements.
- Partial restore stays stopped. Even backend `datasets-restored` is not a claim
  of application recovery; validate saved data, configuration and readiness before
  reopening.

An independent copy requires an explicitly selected, already owned dataset on a
different pool with local `org.cloud-installer:owner=cloud-installer` and
`org.cloud-installer:purpose=maintenance-recovery` properties. The adapter never
formats a disk or creates a pool. Unrelated descendants, aliases or unrecognized
mounts refuse; interrupted exports/receives remain private for assessment.

Hash-bound streams and host metadata are verified independently. Receive rehearsal
uses new unmounted datasets with `canmount=off`, `mountpoint=none` and no force
flags, then compares GUIDs. A receive rehearsal is not an application restore
drill. Different pools do not necessarily provide independent physical failure
domains; local snapshots are not off-host backups.

## Acceptance limits

Complete native capture/restore, isolated validation, safe publication,
cross-boot/fault recovery and unaffected-instance continuity remain incomplete.
See [validation limits](verification.md), [native utility contracts](freebsd-utilities.md)
and [testing boundaries](testing-boundaries.md). Offline coverage or saved plans
do not grant execution authority. Arbitrary power cuts, upstream internal crash
resilience, host/storage loss and unsaved editor durability are not established.
