# Nextcloud 35.0.1 to 35.0.2 updater reference

This reference records version-specific upstream requirements and updater safety
constraints. It does not approve arbitrary transitions. Operator commands and
the current supported boundary are in the [upgrade guide](upgrade.md).
Experimental controller enrollment/recovery requirements below must not be
confused with prerequisites of that optional assistant.

**Source review: 2026-10-15.** The fixed empty-package edge is public Nextcloud 35.0.1
(internal 35.0.1.1) to 35.0.2 (internal 35.0.2.2), with the complete installed
package closure, PHP 8.5, MariaDB 12.3, ONLYOFFICE and connector 10.2.1 unchanged.
Unknown apps, runtime drift or a required package replacement block this edge.

This is separate from installation selection. Do not widen
`resources/versions.json`'s installation bounds to authorize an inspection-only
candidate. Compatibility evidence does not enable a migration recipe.

## Tagged destination requirements

- [Official changelog](https://nextcloud.com/changelog/#35-0-2) and
  [release metadata](https://api.github.com/repos/nextcloud/server/releases/tags/v35.0.2)
  identify the stable 35.0.2 release dated 2026-10-15.
- [Target version.php](https://github.com/nextcloud/server/blob/v35.0.2/version.php)
  declares 35.0.2.2 and permits the 35.0 source line; the
  [source version.php](https://github.com/nextcloud/server/blob/v35.0.1/version.php)
  declares 35.0.1.1. The manager must check both public and internal identities.
- [Target PHP gate](https://github.com/nextcloud/server/blob/v35.0.2/lib/versioncheck.php)
  requires PHP >=8.3 and <8.6. This does not automatically approve a different
  PHP branch for this installer or this recipe.
- [Target database check](https://github.com/nextcloud/server/blob/v35.0.2/apps/settings/lib/SetupChecks/SupportedDatabase.php)
  bounds MariaDB major/minor to 10.11–12.3. The recipe retains its narrower reviewed
  MariaDB 12.3 package closure and checks actual InnoDB/isolation state.
- [Target module requirements](https://github.com/nextcloud/server/blob/v35.0.2/apps/settings/lib/SetupChecks/PhpModules.php)
  and [composer requirements](https://github.com/nextcloud/server/blob/v35.0.2/composer.json)
  were compared with their 35.0.1 counterparts. These, the PHP gate and database
  check were byte-identical during review. Actual loaded CLI and both FPM-pool
  modules still need observation; installed extension packages alone are not proof.
- [Connector 10.2.1](https://github.com/ONLYOFFICE/onlyoffice-nextcloud/blob/v10.2.1/appinfo/info.xml)
  permits PHP 8.2–8.5 and Nextcloud 33–35. Keep its authenticated bytes unchanged.
- [serverinfo](https://github.com/nextcloud/serverinfo/blob/v35.0.2/appinfo/info.xml)
  remains version 7.0.0 in the target core bundle. Its unchanged app-version string
  does not imply identical code. FreeBSD telemetry support remains limited.

The source/target release metadata had no added/removed migration IDs in the
compared app maps. This is **not** evidence that `occ upgrade` is unnecessary or
that repairs/application upgrade routines cannot write data.

## Source updater, not merely target updater

The upstream `nextcloud/updater` tags v35.0.1 and v35.0.2 resolved during review to
`eeb8f5cdf3655ce911c3add378b2fb17de38f38b`. Review used the source tag:

- [UpdateCommand.php](https://github.com/nextcloud/updater/blob/v35.0.1/lib/UpdateCommand.php)
  supports `--url`, `--signature`, `--no-upgrade` and noninteractive invocation.
  Use `--no-interaction --no-upgrade` together for code replacement; separately
  journal `occ upgrade`. Without `--no-upgrade`, batch mode can run migration and
  turn maintenance mode off automatically.
- [Updater.php](https://github.com/nextcloud/updater/blob/v35.0.1/lib/Updater.php)
  expects a **ZIP**, supports `file://`, and checks a base64 OpenSSL/SHA-512
  signature. The ZIP `.sig` is not the OpenPGP `.asc` used during installation.
  Retain pinned-PGP authentication as well as the updater-compatible signature,
  bind both to the exact staged ZIP, reject daily channels and never use
  `--no-verify` or `--ignore-state` as recovery shortcuts.
- The updater checks its effective user against the owner of `config/config.php`
  and requires writable code. Existing root:www, group-read-only code hardening
  therefore needs a narrowly journaled temporary permission transition under
  independently proven writer isolation. Do not change config ownership merely
  to run the updater as root. Re-harden before publication.
- The updater reads the complete ZIP into PHP memory for signature verification.
  Check CLI memory/capacity before downtime. Its downloader follows redirects;
  use only the manager's already authenticated local artifact during mutation.
- Its version check rejects downgrades but does not enforce our exact target.
  Independently verify the complete target code identity before migration.

Tagged source review alone is not proof of an installed PHAR's identity or
capabilities; authenticate it against the retained signed source before execution.

### Experimental controller adapter boundary

The internal adapter now requires a local source `.asc` signature in addition to
the target ZIP, `.asc`, `.sig` and pinned public key. It reauthenticates the retained
source tarball before trusting its core certificate or matching the installed
PHAR. Archive hashes alone are not substituted for signature verification.
Signed tar/ZIP inventories also bind executable-file classification: hardening
retains `0750` for executable code and `0640` for other code, matching fresh
installation. Neither local execute bits nor a decoded receipt grant permission.

Retained candidates have a strict, read-only decoder. Their graph/generation
bindings use canonical document digests, matching successor validation rather
than confusing those digests with stored-file hashes. Loading a receipt does not
refresh its age or replace locked live revalidation before the native intent.

Source admission compares original sealed first-readiness code/configuration
trees before running installed application code. The initial adapter is restricted
to provided TLS, the initial managed generation, no optional office plugins and
the unchanged reviewed connector/package closure. Native `at` spool ownership is
checked against the reviewed FreeBSD layout, not assumed to be root-owned.

The closed migration controller starts only database/cache services. The updater
adapter briefly starts hardened source FPM solely to re-observe its actual pools,
then stops it before permission/code changes. Target FPM is similarly observed
after migration/re-hardening. Apache, office, cron and SSH are not started by the
updater adapter. Unexpected running FPM is a refusal, not an assumed safe state.

Fixed updater calls use a bounded private subprocess transport: explicit clean
environment, bounded stdin/stdout/stderr, deadlines and owned-process-group
termination/reaping on timeout or cancellation. Diagnostics are not echoed.
Every mutation has durable before/after records; a prior attempt is not replayed
merely because an upstream exit status was zero or its `.step` file is absent.

These primitives and their integration tests do not register a production recipe.
Pre-fence candidate collection, recovery-copy verification, full closed validation,
safe publication and native acceptance remain independent completion gates.

### Crash/retry caveats

The updater's `.step` file is not an atomic/fsynced transaction journal. An
exception can delete it without restoring modified code; rollback for later
replacement steps is unimplemented upstream. Source review also found a step-12
failure path that can reach the `--no-upgrade` success return. Therefore neither
exit zero nor absence of `.step` proves completion. Preserve uncertain state and
require independent code/integrity probes or coherent recovery, not blind replay.

The [core updater](https://github.com/nextcloud/server/blob/v35.0.2/lib/private/Updater.php)
can consider app-store upgrades during `occ upgrade`. The recipe must temporarily
disable app-store fetching with an exact restored configuration change, preserving
the selected connector and reviewed app inventory. The target
[fetcher](https://github.com/nextcloud/server/blob/v35.0.2/lib/private/App/AppStore/Fetcher/Fetcher.php)
checks `appstoreenabled` before consuming cached app metadata.

## Snapshot and writer-isolation requirements

The approved initial recipe uses operator-assisted offline maintenance: bind the
operator's acknowledgment that required edits were saved/closed and verified in
Nextcloud; unsaved/unconfirmed editor work is explicitly outside the guarantee.
Do not label this as automatic drain. Before code replacement or database migration,
establish persistent writer/ingress fences, cleanly stop the database and pair,
then create and verify the **complete coherent ZFS snapshot set** (application,
database, persistent data, both jail trees and matching private metadata).
An updater code backup is not a substitute. Neither is the existing SQL/config
backup. Restore acceptance and independent-copy coverage remain separate gates.

ONLYOFFICE 9.4 observations under review include private
`/internal/connections/edit`, `/internal/cluster/inactive` and `/info/info.json`.
The tagged edit-count handler can catch errors and still return a default zero;
zero editors is not authoritative proof of completed conversions/final saves or
callbacks. Do not turn that observation into a drain permission. Automatic drain
and an upstream design proposal are separate work; the scoped offline recipe still
requires implemented, reviewed and natively accepted shutdown/isolation/recovery.

The controller's full native recovery/reboot/fault acceptance remains incomplete.
The optional assistant's bounded upgrade/restoration observations do not complete
that separate contract or validate dependency-changing transitions. See
[validation limits](verification.md) and [maintenance recovery](maintenance-recovery.md).
