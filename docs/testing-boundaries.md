# Testing the installer and instance manager

**Upgrade workflow:** [optional native upgrade assistant](upgrade.md).
Contracts for experimental generation graphs,
persistent fences and custom recovery sets below apply only when testing that
existing implementation; they do not make those features requirements of the new
assistant. Future upgrade checks focus on native command integration and a working
result, with operator-owned recovery.

## Responsibility

This project orchestrates existing software. Its tests establish that **our code
selects, configures, invokes, isolates, records and recovers that software safely**.
They do not certify FreeBSD, Bastille, ZFS, Nextcloud, MariaDB, PostgreSQL, Redis,
PHP or Document Server implementations. A dependency failure can block a supported
integration without becoming a defect this project must repair upstream.

This boundary applies to all development and acceptance plans. It narrows claims
and redundant test work, not runtime safety checks or the evidence needed for an
advertised operation. Unsupported combinations remain unsupported.

## What we must prove

| Owned contract | Appropriate evidence |
| --- | --- |
| Input validation, compatibility decisions, typed plans and generated configuration | Deterministic unit/schema tests, version-matched utility fixtures and dependency-native configuration validation where our output is consumed. |
| Correct command, target identity, order and failure handling | Mocked command/exit contracts plus a bounded native integration for each executable recipe. Check actual resulting identity/status, not command success alone. |
| Authorization, locks, private secrets and resource ownership | Focused negative tests; native process/permission checks where platform behavior matters. Never operate on unrelated resources. |
| Journals, partial effects, reconciliation and uncertain-replay refusal | Detailed offline boundary coverage and representative controlled interruptions after real effects. Resume must not guess success or replay unsafe work. |
| Network, ingress, scheduled writers and boot permissions we generate | Actual allowed/denied probes and service/profile observations at the relevant transition; bounded controlled reboot when persistent boot behavior is part of the contract. |
| Coherent capture/export/restore and selective metadata publication | Verify the complete owned member set and identities, exported bytes/receive evidence, explicit restore and graph reconciliation. Saved fixture continuity demonstrates our data handling, not storage-engine certification. |
| Preserving unrelated managed instances | Targeted continuity and unchanged-owned-state checks during mutations affecting shared policy. Do not rerun every upstream feature on each instance. |

## Integration checks are seams, not upstream regression suites

Use the smallest representative fixture that detects a failure introduced by our
operation. Verify generated settings, readiness and a real request through the
managed path; use an application-native/API check when it proves the same claim
without a browser. Browser editing/save/callback/reopen is appropriate when it
tests integration we configure, not as a general office-format certification.

Do not automatically multiply each update/recovery case by all document formats,
fonts, applications, users, TLS modes or dependency versions. Select additional
cases only for a distinct owned branch or changed integration. Preserve existing
broader results as evidence, but do not make unrelated upstream feature coverage
a prerequisite for every change. Account/data fixtures may expose accidental
deletion or credential mix-ups; they do not certify upstream access-control logic.

## Outside this project's acceptance claim

- Arbitrary power cuts, physical-host/storage-controller failure, ZFS internals
  and database/filesystem crash durability.
- Correctness, performance or security certification of upstream application
  features, document formats, SQL engines, fonts, rendering or operating systems.
- Unsaved/unconfirmed editor durability, automatic editor draining not implemented
  here, and unsupported migrations or upgrades.
- Hypervisor certification or broad test-infrastructure development.

A controlled reboot tests our persisted permissions/continuation. An exception
may run cleanup; neither proves abrupt power-loss behavior. Omitted cases are
outside the stated claim or explicitly untested, never implicitly PASS. Keep
existing network-recovery guards and data-safety preflights intact.

## Work and evidence economy

1. Identify the changed owned contract and its observable postcondition.
2. Run the smallest relevant deterministic tests; fix the cause, not the guard.
3. Run one combined suite after code changes settle. Documentation-only scope
   changes require link/diff review, not a redundant full suite.
4. Exercise real dependency effects only where mocks cannot establish our seam.
   Reuse compatible retained evidence; repeat only what changed source invalidates.
5. Time-box dependency/harness diagnosis. Record external blockers and continue
   independent owned work; never patch enrolled immutable artifacts or fake proof.
6. Record exact artifacts, operations, results and limitations. Production support
   must not exceed the recipes and contracts actually verified.

The [validation guide](verification.md) records current claim limits. The
[FreeBSD checklist](freebsd-15.1.md#freebsd-integration-checklist) and
[maintenance reference](maintenance-recovery.md) apply these boundaries to native
integration and experimental recovery. Historical observations are not additional
future acceptance gates.
