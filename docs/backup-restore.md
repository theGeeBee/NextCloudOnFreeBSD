# Database backup, restore and user creation

Run `sh install.sh` on the FreeBSD **host**, select the instance, and choose the
database backup, database restore, or add-user operation. No Nextcloud
administrator browser login or separate worker-script invocation is needed.

## What the backup contains

The entire `nextcloud` database is backed up: **all users**, password hashes,
groups, shares, application settings, file metadata, **all address books and
contacts, and all calendars and calendar objects**. There is no per-user filter.
Installed app tables, views, triggers, routines and events are included. The
manifest inventories the actual table names and checks the core user, contact
and calendar tables before accepting a backup.

The complete Nextcloud `config/` directory is included as a private archive.
This preserves `instanceid`, `passwordsalt`, `secret`, database settings and
configuration-resident signing/encryption material. Treat the package as
sensitive: its database and configuration contain credentials and personal data.

**This is a database/configuration backup, not a full disaster-recovery backup.**
It excludes user file contents, file versions and trash, encryption keys located
in the data directory, custom-app code, themes, TLS material, host configuration
and ONLYOFFICE runtime/storage. It cannot recover deleted files. Contacts or
calendar attachments stored as files need the matching data backup too.
External identity providers and external storage remain separate systems.

For coherent full recovery, retain matching application/configuration and data
backups at the same quiesced point, including server-side encryption keys and
custom apps. Taking an unrelated live ZFS snapshot later does not establish
consistency with this SQL backup. This menu operation does not orchestrate those
additional snapshots or their off-host replication.

## Creating and retaining a package

The default host location is:

```text
/var/db/cloud-installer/backups/<instance>/<UTC-timestamp>/
    database.sql.gz
    nextcloud-config.tar.gz
    manifest.json
    COMPLETE
```

Directories are root-owned `0700`; files are root-owned `0600`. This tree is
outside the instance state and dataset removal scope. A custom destination, if
supplied by the host interface, must be a new absolute directory under an
existing root-private parent, outside the instance state, datasets and both jail roots. Symlinked
paths and linked/special files are refused. Existing packages are never replaced.

The operation records maintenance mode and the running states of `cron`,
`apache24` and `php_fpm`, enables maintenance, stops those writer services and
waits up to two minutes for existing `www` PHP CLI jobs to finish. MariaDB and
Redis remain available. All database base tables must use InnoDB. A host-side
instance lock prevents overlapping database operations in addition to the menu's
global operation lock.

MariaDB's Unix-socket root authentication is used inside the verified Nextcloud
jail. `mariadb-dump` runs with `--single-transaction --quick --routines --events
--triggers --hex-blob --default-character-set=utf8mb4 nextcloud`. SQL streams
directly through a checked numeric jail ID into host-side gzip, in bounded
chunks. No database password enters argv, an inherited environment, or a
temporary SQL file. Streaming has a one-hour timeout; failed child exit status,
empty output or a changed jail identity fails the operation.

SHA-256 digests cover both archives; `COMPLETE` contains the manifest's SHA-256.
The completion marker is published atomically only after successful capture and
recovery of the prior service/maintenance states. A failed attempt retains its
private incomplete directory without a usable marker. Configuration archives
are limited to 256 regular files, eight path components and 16 MiB expanded.

Copy complete packages to protected off-host storage and test recovery. Gzip and
checksums do **not** encrypt or authenticate a backup. Preserve private ownership
and permissions when copying it back. Retention/pruning is an operator policy;
neither successful restore nor instance removal automatically prunes this tree.

## Restoring

Select database restore, supply the package directory and type exactly
`RESTORE <instance>`, for example `RESTORE cloud`.

Restore is for a trusted package from the **same existing instance**, with:

- matching public URL (including any nonstandard port), hostname and Nextcloud instance ID;
- the exact Nextcloud and MariaDB versions and application-version inventory;
- matching table prefix and runtime identity (database credentials, Nextcloud
  secret/password salt, ONLYOFFICE JWT, database endpoint and data-directory settings);
- a compatible, coherently retained data directory.

This is deliberately not a cross-instance import, credential-rotation recovery
or upgrade procedure. In particular, it does not run `occ upgrade` or silently
adopt a package from a removed/recreated instance.

Before stopping services, the host checks ownership, regular-file constraints,
completion, all hashes, gzip integrity/expanded size, archive member paths and
version/identity compatibility. Archived PHP is not evaluated during validation.
**Only restore root-trusted packages:** checksums detect corruption, not a
malicious author who can replace both content and hashes. Import runs trusted
SQL as database root and restored PHP configuration will later execute as `www`.

With writers stopped and maintenance enabled, the first attempt makes a **fresh
pre-restore backup** in the retained host backup tree. It then atomically saves
the root-private `instances/<instance>/restore.json` journal before replacing
configuration or SQL. The journal contains `state: pending`, `phase: importing`, the exact source
path and manifest SHA-256, the retained pre-backup's path/hash, the original
validated metadata and maintenance/service states, the host configuration digest,
deployed version/signature-file hashes and a start timestamp. It contains no SQL,
passwords or PHP configuration contents.

Restore installs the trusted package's maintenance-enabled configuration, disables
SQL session binary/general/slow logging, drops and recreates the fixed `nextcloud`
database, and streams the saved SQL into it. Dropping the database removes tables
created after the selected backup. User files and dataset contents are not
rewound by this operation. Accounts and password hashes return to their backed-up
state, including removal of accounts created after that backup.

The configuration files are restored with private permissions and the dedicated
ephemeral Redis database is cleared of stale caches/locks. Successful
restoration checks status, schema inventory and core integrity and runs
`occ maintenance:data-fingerprint`. While maintenance is still enabled and all
writers are stopped, it durably publishes `phase: validated`. Only then does it
return services and maintenance mode to their original states and mark the
journal `state: complete`. The validated checkpoint prevents a crash during
writer restart or completion publication from causing a later retry to overwrite
legitimate post-restore writes. The fingerprint can cause client conflict
dialogs; reconcile clients against the recovered data. No automatic `files:scan`
is run. Check ordinary-user login, a contact, a calendar event and a document
open/save after a successful restore.

### Failure handling

Failure before the pending journal is saved restores the previous running and
maintenance states. Once replacement begins, failure stops cron/Apache/PHP-FPM,
retains the pending journal, and reports both the source and pre-restore package
paths. During `phase: importing`, maintenance stays enabled without running
`occ` against a partial database. During `phase: validated`, cleanup re-enables
maintenance through `occ` when the current database is healthy. If PHP fails or
writer shutdown/maintenance cannot be confirmed, the diagnostic requests host-root
inspection; archived configuration and SQL are never replayed as cleanup for a
validated restore. Backup, verification and user creation remain blocked while
a restore is pending.

**After correcting the failure, repeat Restore with the same absolute package
path and type `RESTORE <instance>` again.** Use the menu or repeat the same
single-entrypoint command, for example:

```sh
sh install.sh restore cloud /var/db/cloud-installer/backups/cloud/20261014T120000.000000Z
```

Substitute the exact path reported by your failed operation. A pending journal
authorizes only that source package, with its unchanged manifest and archive
hashes. The retained pre-backup must also remain intact. An identical package at
a different path, a rehashed replacement, or selection of the pre-backup itself
is refused while this transaction is pending. Keep both packages and the journal;
do not edit or delete the journal to bypass these checks. Choosing another recovery
source requires a separate host-root recovery assessment using those retained
artifacts, not a shortcut through this retry path.

The retry validates the original host configuration digest, exact live MariaDB
version, managed storage/network guard and current jail identity. It compares
the deployed `version.php`, `core/signature.json`, each originally enabled app's
`appinfo/info.xml`, and any app signature files with the hashes captured before
the first replacement. Changed versions, signatures, missing/ambiguous app paths
or unsafe journal ownership/permissions refuse the retry. Restore the original
reviewed configuration/code if those were changed; retry does not perform upgrades.

These preflight checks do **not** bootstrap PHP or query Nextcloud's partial
schema. Retry stops all writer services and waits for existing `www` PHP tasks to
drain, then follows the recorded phase:

- **`importing`: retry the data stage.** Restore the known maintenance-enabled
  configuration and replay the whole SQL import. This also handles a database
  left entirely absent between DROP and CREATE. After SQL succeeds, the normal
  status/schema/integrity/fingerprint checks run and the validated checkpoint is
  durably saved before any writer restarts.
- **`validated`: finalize only.** Recheck current Nextcloud metadata, compatibility
  and exact schema inventory; maintenance may already be off and user data may
  include new writes. Retry never imports SQL, restores archived configuration,
  flushes Redis or regenerates the data fingerprint. It durably republishes the
  validated checkpoint, restores only the original maintenance/service flags,
  and marks the journal complete. A changed or unhealthy database stops finalization
  rather than falling back to data replay.

Both phases reuse the **original** pre-restore backup; neither makes a new backup
of partial data or chooses a newer incomplete backup directory. Service recovery
uses the states from **before the first attempt**, even if a failed attempt or
restarted jail had different states. A validated-checkpoint write error leaves
writers stopped: a validated phase already visible after rename is respected,
and retries must make that checkpoint durable before starting writers. A failed
completion publication retains the validated phase, never an importing phase.
Journals with a missing or unrecognized phase are refused because they cannot
safely establish whether writers already resumed. Keep writers stopped until
recovery completes; rebooting is not a repair operation.

An arbitrary broken or unregistered installation without this pending journal
still requires a separately planned host-root disaster recovery. A completed
journal does not authorize replacing a later unknown partial database. This
narrow retry mechanism repairs only the installer's own recorded transaction
and still does not restore missing user files.

## Adding a normal Nextcloud user

Choose the add-user operation and enter a username, a password of at least
14 characters, and optional display name/email. The host sends a JSON object
over stdin to a `www`-owned PHP process. The installed helper invokes the
supported `occ user:add --password-from-env` command using Symfony `ArrayInput`;
`OC_PASS` is set and removed only inside that already-running PHP process.
Passwords never enter process arguments, shell source, the helper's output, or
a jail-side credentials file.

The helper does not request an administrator group and verifies the resulting
account is not an administrator. Existing users are not overwritten. The
operation requires normal application mode; it refuses maintenance mode.
User creation checks live `occ status`: Nextcloud must be installed, without a
pending database upgrade or restore. It does not require the original installer
artifact or compare Nextcloud/database versions against installation locks.
The live command/helper must succeed and verify the normal-user result; otherwise
the operation fails safely. Jail identity, private stdin transport and account
validation remain enforced. Backup/restore version and artifact checks are unchanged.
Provide credentials through the host menu/password manager rather than a shell
command. Adding an email address does not configure SMTP delivery.

## Evidence and validation

The [testing boundaries](testing-boundaries.md) define these gates: verify our actual backup/import/service commands, isolation, journal reconciliation and saved-fixture continuity, not database-engine internals. Reuse compatible historical evidence with its original artifact/case identity; it does not pass unrun failure cases. Native/API checks suffice for equivalent data and account claims without a repeated browser matrix.

Interfaces reviewed against Nextcloud 35 and FreeBSD 15.1 on 2026-10-14:

- [Nextcloud backup requirements](https://docs.nextcloud.com/server/stable/admin_manual/maintenance/backup.html)
- [Nextcloud restore and data fingerprint](https://docs.nextcloud.com/server/stable/admin_manual/maintenance/restore.html)
- [NC35 user:add implementation](https://github.com/nextcloud/server/blob/stable35/core/Command/User/Add.php)
- [NC35 console bootstrap](https://github.com/nextcloud/server/blob/stable35/console.php)
- [NC35 console application](https://github.com/nextcloud/server/blob/stable35/lib/private/Console/Application.php)
- [MariaDB mariadb-dump](https://mariadb.com/docs/server/clients-and-utilities/backup-restore-and-import-clients/mariadb-dump)
- [FreeBSD jexec(8)](https://man.freebsd.org/cgi/man.cgi?query=jexec&sektion=8)

`tests/test_operations.py` exercises streaming failures, jail replacement,
checksum/path rejection, exact service-state recovery, pre-restore retention,
journaled retry without premature PHP/database access, changed-source/code/config
rejection, partial-import isolation, finalization-only retries preserving new
post-restore writes, checkpoint-publication failures and stdin-only user credentials offline. Real FreeBSD
acceptance still needs an approved disposable installation: create two ordinary
users and distinct contacts/calendar events, back up, change those records,
restore and verify both accounts; interrupt an actual import at a representative
controller boundary, confirm writers remain stopped and the pre-restore package is
retained, then repeat the same confirmed restore and verify recovery and original
service states. Also interrupt after writer restart, add distinct DAV records,
then repeat Restore and verify finalization preserves those new records without
another SQL import, configuration restore, Redis flush or fingerprint change.
That post-writer-start negative case remains a native gate: observe that no
destructive reimport occurs and new saved records survive. Detailed DROP/CREATE
and checkpoint-write boundaries remain offline tests, not an exhaustive native
SQL-engine crash matrix.
