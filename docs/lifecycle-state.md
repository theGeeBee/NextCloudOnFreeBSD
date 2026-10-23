# Experimental lifecycle state and explicit enrollment

> This documents an existing experimental implementation, not the optional upgrader. Permanent enrollment and
> original-executor eligibility are not requirements of the
> [native upgrade assistant](upgrade.md). Do not bypass existing
> deployed guards without a reviewed transition.

Enrollment introduces versioned state, **not an upgrade executor**. Thick
VNET jail layout, packages, application versions, PF topology and user data are
not changed by enrollment. Complete native enrollment/reboot/fault acceptance
remains incomplete; do not infer production readiness from offline tests.

[Recovery preparation](maintenance-recovery.md) adds inert plans and local
artifact staging. Its native fencing/recovery orchestration remains incomplete;
enrollment permissions are not maintenance validation permissions.

## Supported source boundary

The initial adapter supports ready schema-2 installations created by the exact
same retained installer artifact implementing enrollment. An older source identity is explicitly unsupported
until its evidence, readers, workers and guard transition receive a separate
adapter review. Missing locks are never reconstructed from installed versions.
Do not adopt unrecorded diagnostic changes as an intended baseline.

New installations attempt a bounded static-identity baseline during their first
readiness attempt. It records jail code/configuration, installed apps and plugins,
package/base identities and owned resources; it is not a whole-host integrity or
security attestation. Normal application data and background-job timestamps are
excluded. An unsupported layout or unstable observation produces an explicit
notice and private `enrollment-unavailable.json`; it does **not** weaken existing
installation checks or invent a baseline. That deployment remains ineligible for
enrollment. Verify/Resume never retrofit a missing baseline into a published
installation. This does not establish complete native enrollment acceptance.

Dated source review (2026-10-15): FreeBSD's
[`releng/15.1/etc/Makefile`](https://github.com/freebsd/freebsd-src/blob/releng/15.1/etc/Makefile)
installs `/etc/os-release -> ../var/run/os-release` and, when enabled,
`/etc/unbound -> ../var/unbound`.
[`rc.d/os-release`](https://github.com/freebsd/freebsd-src/blob/releng/15.1/libexec/rc/rc.d/os-release)
generates the release identity from `freebsd-version -u`. The baseline binds only
that exact runtime identity file and the explicitly observed unbound config
target—not arbitrary `/var/run` or mutable application data. This source review
does not establish native execution results.

The historical source digest algorithm remains unchanged. The lifecycle executor
also binds the shell entrypoint. Retain the complete unpacked artifact at its
original protected path: boot checks must not execute a changing checkout.

## Operator commands

```sh
sh install.sh maintenance status
sh install.sh maintenance register cloud
sh install.sh maintenance recover
```

Registration and recovery require an interactive terminal and exact typed
confirmation. They never install prerequisites or download an archive. Read the
displayed effect and blockers before approving. Do not manually edit a descriptor,
active graph, source hash, or pending record to get past a refusal.
The confirmations are `ENROLL NAME` and `RECOVER-LIFECYCLE` respectively.

Enrollment validates retained configuration, locks, source/input identity,
ownership and live evidence before publishing managed state. Unexpected plugins,
applications, package/configuration drift, incomplete operations and unsupported
evidence block rather than become a new intended baseline. The initial generation
records `legacy-enrollment` with no predecessor; it does not invent upgrade history.

## Authoritative state and privacy

Before lifecycle initialization, the existing registry remains authoritative.
After initialization, one atomic active graph names every legacy, managed and
removed instance. A corrupt or missing managed record never falls back to the
old configuration. Existing operation, PF and database locks retain their roles.

Enrollment preserves original evidence bytes in a sealed private archive, then
replaces the legacy configuration lookup with a typed registration descriptor.
The generation supplies effective configuration and immutable locks; observed
health and subsequent operation journals are separate. A retained status file
is not an alternative authority for a managed instance.

Directories remain owner-only `0700`, files `0600`. Credential content never
appears in graph/generation manifests, reports or jail payloads; private retained
archives and credential files must still be protected like backups. A state
archive is **not** an application-data backup or disaster-recovery set.
The original generated `secrets.json` stays in place, hash-referenced rather than
duplicated into the legacy archive or generation.

## Interruption and legacy entrypoints

Durable intent precedes state publication. Boot permission is fenced during the
guard transition; enrollment does not stop already-running applications or claim
to fence their writers. Migration requires separate maintenance fencing.
Interrupted enrollment remains closed to ordinary mutation until explicit recovery
under the same executor validates and completes the recorded transition. Never
delete a fence because its process is gone.

If a reboot or interruption stopped the original jails, explicit enrollment
recovery may start only that recorded pair for validation, after source, ownership
and PF checks. Permission requires both the global operation lock and a separate
operation-specific lock to be actively held; leftover permission JSON alone is
not authority. This is not isolated migration validation: the unchanged original
applications may serve normal users. No application data or schema is rolled back.

The generation-aware boot guard retains the existing actual-storage, ownership,
bridge and committed-PF checks. It adds lifecycle/source validation; it does not
weaken certificate validation or replace PF recovery with graph rollback.

Known historical config readers reject the registration descriptor. This is
**not a security boundary against root**: old shell bootstrap and independent
historical network recovery/workers cannot be retroactively made lifecycle-aware.
After enrollment, only the retained current manager is supported. Never launch
an old entrypoint/worker independently or restore the archived config into the
legacy lookup path. Unsupported source adapters are refused, not recursively run.
Descriptor refusal protects enrolled targets, not still-legacy targets on a mixed
host. Independent historical removers remain unsupported for **every** instance
on that host. Current-manager dispatch checks an instance's source adapter before
its native operations.

## Acceptance boundary

Offline coverage must exercise byte preservation, rejected references, conflicting
readers, mixed states, exact-source refusal and interruption ordering. Native
acceptance must separately verify both `exec.prepare` hooks, real boot denial at
every interrupted transition, completed enrollment starts, unaffected instances,
and routine management with the retained artifact. Complete native
enrollment/recovery acceptance remains incomplete.
