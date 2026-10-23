# Operations and recovery

Use **`sh install.sh`** on the FreeBSD host for the instance menu, or its commands below. `--plain` selects numbered prompts. The [validation matrix](verification.md) separates historical accepted artifacts from current family-selection checks and unrun cases. Full recovery acceptance and physical-hardware validation remain incomplete; select affected cases from the [integration checklist](freebsd-15.1.md#freebsd-integration-checklist) for separately approved testing.

## Routine operations

For classification of NC35 setup notices, the redo-log default and editor callback
diagnostics, see [administration checks](admin-checks.md). Verify reports drift;
it does not apply maintenance or suppress optional-feature warnings.

The dashboard and read-only update reports do not authorize upgrades. The optional
[native application upgrade assistant](upgrade.md) has a separate reviewed
boundary. Experimental [lifecycle enrollment](lifecycle-state.md) is not required
by that assistant. Host OS and jail-base upgrades remain administrator-managed.

## Dashboard and update reports

Opening the menu requires existing Python 3.11+, but performs no package
bootstrap, registry initialization, update discovery or mutation locking. On a
host without Python, explicitly run `install` or `configure` for prerequisite
consent. Selecting Install/Configure/Resume from the menu re-enters that same
artifact's shell entrypoint; existing mutation checks and locks still apply.

The dashboard shows registered state, public URLs, dedicated office dependencies,
pending operations, historical installation-readiness timestamps and cached
update freshness. **Ready is not live health.** Missing evidence remains unknown;
corrupt or unsupported records are inspection errors, not an invitation to adopt
jails/datasets. It does not refresh Verify or infer a verification timestamp from
inventory file modification times. The existing actions are filtered by retained
state; pending network recovery prevents ordinary mutation choices.

```sh
# Cached report only; unknown if none was saved:
sh install.sh check-updates cloud
# Explicit discovery, disposable signed catalogs, no registry writes:
sh install.sh check-updates --all --refresh --json
# Explicitly persist refreshed reports (short host operation lock):
sh install.sh check-updates --all --refresh --save-report
```

Without `NAME` or `--all`, scope is prompted only in a terminal. `--save-report`
requires `--refresh`; reports are not saved just by opening the menu. See
[report statuses and limitations](versions.md#registry-aware-update-reports).
Exit 0 means the assessment was read/generated (even if blocked or newer versions
exist), not that the installation is healthy. Exit 1 means inspection/discovery
or saving failed; invalid CLI arguments use exit 2. No report authorizes migration.
The dashboard/report path has offline validation only; complete native menu/discovery/save acceptance
has not been run.

## Existing instance operations

```sh
sh install.sh list
sh install.sh status cloud
sh install.sh verify cloud
sh install.sh add-user cloud
sh install.sh backup cloud
sh install.sh restore cloud /absolute/path/to/backup-package
```

`status` reports registry/phase state, not live service health. `verify` requires
a ready instance and the selected live jail identities (both for native
ONLYOFFICE; Nextcloud only for other profiles). It checks owned mounts/PF, local
services, Nextcloud status and selected document integration, and refreshes the
inventory. It does not install, upgrade or repair applications. External
DNS/proxy routing, browsers and reboot behavior require separate checks.

`add-user` invokes Nextcloud's supported `occ` user interface and verifies that the result is **not an administrator**. Use it for ordinary accounts without logging into the browser as admin. Generated user passwords are saved privately on the host; manually supplied passwords are not saved by the installer. See [user creation](backup-restore.md#adding-a-normal-nextcloud-user).

The NC35 helper registers commands using empty noninteractive input and passes
`user:add` options only when running that command. Command registration, stdin
credential lifetime and output suppression have deterministic coverage. Bounded
native account and DAV checks are not full disaster-recovery or fault-injection
coverage; see [validation limits](verification.md).

Provisioning, resume/recovery, removal, verification and backup/restore share the host's exclusive **`/var/db/cloud-installer/operation.lock`**. A concurrent operation fails rather than racing; database operations also use an instance lock. Do not remove the lock file to bypass an active operation. Manual administrative procedures must coordinate with this same lock.

## Registry and storage

| Location | Purpose |
| --- | --- |
| `/var/db/cloud-installer/host.json` | Shared pool/uplink/management/resource settings |
| `/var/db/cloud-installer/instances/NAME/config.json` | Saved schema-2 config, or an explicit enrolled registration descriptor |
| `…/secrets.json` | Generated administrator/database/JWT bundle, **host only** |
| `…/status.json`, `…/deployment.json` | Registry state and atomic phase journal |
| `…/source.sha256`, `…/inputs.sha256`, `…/inventory.json` | Deployment source/input bindings and recorded application/package checks |
| `…/versions.json` | Immutable resolved applications/connector, dependency closures, target and compatibility-policy hash |
| `…/initialization.json` | Unpublished initialization snapshot identities and recovery attempts |
| `…/restore.json` | Validated database-restore identity, original service state and recovery checkpoint |
| `…/removal.json`, `…/purge.json`, `…/removed.json` | Removal/purge checkpoints and retained audit evidence |
| `/var/db/cloud-installer/transactions/ID/` | Network before-images, confirmation/rollback state and expected PF snapshots |
| `/var/db/cloud-installer/network/active` | Pointer to the committed shared network transaction |
| `/var/db/cloud-installer/backups/NAME/` | Default private database/configuration packages |
| `/var/db/cloud-installer/update-reports/NAME.json` | Explicitly saved latest advisory report; not an installation lock or backup |
| `/var/db/cloud-installer/lifecycle/active.json` | Atomic authoritative lifecycle graph reference after explicit enrollment |
| `…/instances/NAME/legacy/`, `…/instances/NAME/generations/` | Sealed original evidence and immutable enrolled generation; not application backups |
| `/var/db/cloud-installer/maintenance/pending.json` | Durable metadata/guard mutation fence; never clear manually |
| `POOL/cloud-installer/bastille` → `/srv/cloud-installer/bastille` | Shared releases/cache and per-instance thick jail roots |
| `POOL/cloud-installer/instances/NAME` → `/srv/cloud-installer/instances/NAME` | Per-instance persistent application datasets |

Private host directories are `0700`, files `0600`. Protect off-host copies likewise. Neither the registry nor the phase journal is an application-data backup. Jail-local diagnostic/state directories are distinct from host state: Nextcloud uses `/var/db/cloud-installer`, ONLYOFFICE `/var/db/cloud-installer-onlyoffice`.

The generated bundle never enters either jail, including on failure or resume. Public `runtime.json` and copied code/templates contain no generated credentials. The host streams only the secrets needed by a phase through `jexec` with a verified, pinned numeric JID; identity is checked before and after. Applications necessarily retain native secrets: Nextcloud's protected `config.php` contains its DB password, its connector stores the sensitive JWT setting, and ONLYOFFICE's protected `local.json` contains its JWT. Treat application configuration and SQL backups as sensitive too.

## Additional instances

Choose **Install** again or run `sh install.sh install`. Each instance gets separate application datasets, credentials and profile-specific jail/VM resources and service rules. Native ONLYOFFICE uses two private bridges; Nextcloud-only has no office segment. The shared pool, uplink, management CIDR/port and host memory reserve must remain consistent. See [profile layouts](fresh-install-profiles.md).

The wizard suggests unused `/29` blocks/bridges and ports; preflight checks the host and registry for collisions. Memory planning adds all instance service budgets to one shared host reserve. Quotas are ceilings, not reserved space; account separately for snapshots, shared releases, package caches and off-host backup staging.

On the same host IPv4, additional instances normally use an external HTTPS proxy and an unused backend port such as 8080. Alternatively, select another **already assigned** host IPv4 for direct TLS. Host listener ports and public HTTPS ports are distinct settings, especially behind a router/proxy. Follow the [proxy guide](reverse-proxy.md).

An instance ID is 1–8 lowercase letters/digits, beginning with a letter. `cloud` yields Bastille IDs `cloudnc` and `cloudoo`; custom DNS short/FQDN hostnames can be longer and contain hyphens. Their OS hostnames are separate from the public certificate/DNS identity. Optional [jail SSH](ssh.md) is key-only and unprivileged unless the operator explicitly selects `doas` administration; zsh is an optional login shell, while workers remain `/bin/sh`.

## Resume and failure triage

```sh
sh install.sh configure
sh install.sh status cloud
sh install.sh resume cloud
```

`configure` saves a new instance without creating deployment resources. `resume` is for configured/interrupted instances, not a ready installation or an upgrade. It displays the plan and requires `APPLY`; a new network transition also requires timed `KEEP`.

Version discovery, independent compatibility validation and native solver dry runs
precede provisioning. The saved version lock is reused on Resume, never silently
updated to the repository's newest packages. See [version locks and assessment](versions.md).
Older deployments without this lock continue to require their original artifact;
the new resolver does not adopt or upgrade them.

1. Keep the original **schema-2 configuration, secrets and installer artifact**. `deployment.json` binds the configuration; `source.sha256` binds the installer modules/resources and `inputs.sha256` binds credentials and supplied certificate/key/font contents when deployment begins. Resume rejects changed inputs or implementation. Retain the exact artifact and inputs; do not switch checkouts or edit state to suppress a mismatch.
2. Read `status`, the last incomplete journal phase and root-private diagnostics. Completed phases are skipped only with the applicable resource checks; unfinished phases must be explicitly safe/idempotent to replay. A journal records completed effects, not merely commands attempted.
3. Correct the reported environmental problem without changing identity/storage/network contracts. Missing or changed ownership, jail identity, mount graph or committed PF must be investigated before retrying. A stopped/restarted jail cannot produce a successful no-op: wrapped commands check live name/root/JID.
4. Run `resume NAME` from the retained artifact. Failures preserve datasets/state and disable boot/stop this instance's managed jails; an already committed shared network policy remains committed.

**Partial Nextcloud table initialization is an uncertain state.** If tables/data exist without a complete matching installation, resume refuses rather than rerunning schema setup or wiping data. The phase journal is not a ZFS snapshot. Preserve evidence and use the restricted initialization recovery below if eligible; otherwise perform reviewed manual coherent recovery, or remove the failed instance retaining data and use a new name for a new deployment.

If the host reports another operation or a pending network transition, inspect the owning process/supervisor and retained transaction first. Keep console access. Do not run manual PF/rc changes concurrently with a transition or delete confirmation markers to force progress.

## Initialization recovery

```sh
sh install.sh recover-install cloud
# Confirmation: RESET-INITIALIZATION cloud
sh install.sh resume cloud
```

After the empty-database phase and before Nextcloud's initial schema setup, the installer quiesces writers and creates **one atomic four-dataset ZFS snapshot set**: `nc-app`, `nc-data`, `nc-database`, `nc-db-logs`. This is a narrow initial-setup checkpoint, not a scheduled backup of an operating service.

`recover-install` is permitted only when the **Nextcloud installation** journal phase is `running` or `failed`, never `complete`, and the **Nextcloud publication phase has never begun**. It requires unchanged configuration/source and **`RESET-INITIALIZATION cloud`**. An installation that is complete or has ever begun publication is ineligible even if a later step failed or the application now appears broken. Never edit markers to manufacture eligibility.

Recovery validates ownership, dataset/snapshot identity and saved snapshot GUIDs for all four datasets before rollback. It stops both jails of this instance and restores only that checkpoint. It does **not** force `zfs rollback -r/-R`; newer snapshots, clones/holds or changed ownership/identity cause refusal rather than deletion. Partial initialization writes are intentionally lost only after this explicit approval. If rollback fails partway, the jails remain stopped and the start guard stays blocked; resolve the cause and retry `recover-install`, or recover manually. Ordinary Resume cannot bypass a partial rollback. After successful recovery, use `resume NAME` from the original artifact; recovery does not publish or complete the installation itself.

The snapshots cannot reset an established Nextcloud service and are not a substitute for [database/configuration backups](backup-restore.md) or [coherent operating-data snapshots](#coherent-offline-snapshots).

## Shared network transitions

The installer renders one policy from all active instance configurations. Before changing bridges/rc/sysctls/PF, it records before-images and arms a detached supervisor with a 180-second deadline. The interactive process never owns the network mutation lock. On expiry/cancellation the supervisor terminates/reaps only its owned worker group before rollback, even if that worker is suspended while holding a lock.

Open a **second SSH session** and confirm `KEEP` before the deadline. The committed transaction becomes `network/active`; boot guards compare live PF filter/NAT/table snapshots, forwarding/filter sysctls, bridge membership and real ZFS ownership/mounts against it.

Before another transition, live snapshots and the on-disk policy must match the committed record. Rollback uses the committed policy source, never an edited disk copy, and checks the restored live snapshots before recording success. Drift is refused rather than silently merged.

- **First fresh-host cancellation:** restore saved configuration/sysctls, disable newly enabled PF, restore the proven-empty rules/state set and remove newly created bridges.
- **Addition/removal on a managed host:** reload the prior policy and restore the prior active pointer without disabling existing PF or flushing other instances' states. Remove only bridges created by the cancelled transaction.
- Packages, loaded modules and datasets are retained. A network rollback does not undo application writes. If restoration fails, inspect `firewall-rollback.log` and recover from the console before continuing.

### Expired or reboot-interrupted recovery

```sh
sh install.sh recover-network
# Confirmation: RECOVER
```

The watchdog normally handles a same-boot timeout automatically. This explicit operation covers an expired unresolved transaction or reboot/power loss during apply/partial commit. It compares saved/current **`kern.boottime`**: on the same boot the deadline must have expired; a changed boot allows recovery without comparing unrelated monotonic-clock values. It also refuses an active/held mutation lock and rechecks transaction state before restoring prior PF/host configuration and removing only unconfirmed new bridges.

Recovery loads PF/bridge kernel support under its recovery lock when needed, including a first transition that rebooted before persistent enablement. A module-load failure cannot be reported as successful recovery.

Any unresolved transaction blocks new mutations, including another install/resume. A confirmed transaction is not undone by this command. After recovery inspect the retained transaction, verify other instances remain reachable, then resume the affected installation or continue its removal as appropriate. Missing/unsafe recovery evidence needs manual review, not a forced PF disable.

System-notification SMTP delivery is explicitly disabled (`mail_smtpmode=null`).
Default jail egress allows the chosen DNS resolver and Internet TCP 80/443, not
SMTP or arbitrary private destinations. Selecting the Mail app adds only
Nextcloud outbound public IPv4 TCP 465/587/993; it does not configure notification
delivery or permit TCP 25, private mail destinations, office egress or inbound
mail. Enabling notifications/email password reset requires relay credentials/TLS
testing **and a reviewed generated-policy/guard extension**. There is no
post-install policy-update command. Editing `/etc/pf.cloud-installer.conf` or its
expected snapshots to bypass the guard is not a supported mail-enablement procedure.

## Removal

```sh
sh install.sh remove cloud
sh install.sh remove cloud --purge-data
```

The default requires **`REMOVE cloud`**. It disables jail boot, stops the two jails, commits a shared policy without their ingress/flows, invalidates only their endpoints' PF states, destroys their owned jail-root datasets, and removes their private bridges. **Application datasets and their snapshots remain for manual recovery**; this includes data/configuration under `nc-app` but not every file formerly in a jail root. Removal is not a backup or a later automatic re-adoption workflow.

After normal stop, removal waits up to **10 seconds per jail** only when that same
owned jail is still in the kernel's **dying** state. A single waiting message is
printed; disappearance is checked every 0.25 seconds, with bounded probe timeouts.
A still-live/replaced jail, uncertain kernel inventory or expired deadline still
refuses removal, retaining roots and the failed stop checkpoint. Retry the same
removal after normal teardown clears; an already-dying jail is not stopped again.
This does not add forced removal or change data retention. Replayed completed-stop
checkpoints and the final checks before destruction remain immediate refusal
gates. The deadline bounds this added wait, not the existing native stop command.

Mounted root/configuration identity and the exact Bastille inventory name must agree before destructive commands. Missing/unmounted jail configuration is refused, never prefix-completed to a different jail. Old purge journals cannot override completed runtime-removal evidence or claim reused network allocations.

`--purge-data` additionally requires **`PURGE cloud`** and permanently destroys the instance's owned application dataset tree **and snapshots**. Unexpected descendants/ownership cause refusal. Use the same removal operation to continue a checkpointed removal after resolving its reported cause. A later purge of an already removed instance touches only its retained application datasets, never IPs/bridges that another instance may have reused.

Both modes retain host configuration, credentials, diagnostics/audit records and existing backups indefinitely until a separate, deliberate operator retention action. The removed instance's name remains reserved, including after purge. Shared Bastille releases/storage, installed packages, devfs/boot infrastructure and the remaining managed host policy are not uninstalled, even after the last instance. Other instances must remain accessible throughout; test this explicitly.

## Database/configuration backup and restore

`backup NAME` captures the whole Nextcloud database and configuration, including **all users, contacts, address books, calendars and calendar objects**. It pauses writer services, streams SQL to the host and publishes a completion marker only after successful capture/service-state recovery. `restore NAME BACKUP` requires **`RESTORE NAME`**, exact compatible same-instance versions/identity and a trusted completed package; it retains a new pre-restore package. Failed destructive imports leave maintenance enabled and writer services stopped. See the full [backup/restore contract](backup-restore.md).

These packages exclude user file contents, versions/trash, data-directory encryption-key files, custom-app/theme code, TLS material, ONLYOFFICE storage and full host/deployment journals. They cannot establish a file-consistent recovery point on their own. The command does not schedule/prune/replicate backups, and its checksums do not encrypt or authenticate them.

The explicit `backup NAME` command supports scheduled, noninteractive host-root execution; it briefly pauses writers and does not bootstrap dependencies. Installation, removal and restore remain interactive. An interrupted owned restore records its validated input and pre-restore backup: after correcting the cause, repeat the same restore command and confirmation. Changed inputs/code/versions are refused rather than treating a partial database as a new healthy source. See the backup guide for recovery limits.

## Coherent offline snapshots

For complete recovery, develop and rehearse a **cold snapshot runbook** in addition to SQL/config packages. The installer has no full-filesystem backup/restore command. The following is an operator maintenance procedure, not a claim of a tested FreeBSD restore:

1. Close all editors and confirm saved documents; announce downtime. Record the instance, versions, boot/service states, current active transaction and original artifact. Coordinate external storage/identity systems separately.
2. Hold the same host operation lock throughout stopping, snapshotting, copying recovery metadata and restarting. On FreeBSD a root maintenance shell can take the existing lock with:
   ```sh
   lockf -k -n -t 0 /var/db/cloud-installer/operation.lock /bin/sh
   ```
   `-k` retains the lock file; `-n` refuses to create a missing one. Run the manual steps in that shell, then `exit` to release it. Do not invoke the installer from inside the locked shell. Ensure no pending network supervisor is still recovering a transition.
3. Enable Nextcloud maintenance mode as `www` using a checked live JID, stop/drain cron, Apache and PHP-FPM writers, and confirm office callbacks have finished. Stop ONLYOFFICE cleanly, then stop the Nextcloud jail including MariaDB. Verify both jails are absent from `jls`, clean database shutdown completed, and their persistent nullfs mounts are detached. Keep both stopped for the entire capture; host-side maintenance must not write into the datasets either.
4. Take recursive snapshots of **all application children and both jail-root trees** with one recorded label. For the example `pool=zroot`, `instance=cloud`, after the preceding checks:
   ```sh
   zfs snapshot -r zroot/cloud-installer/instances/cloud@offline-20261014T120000Z
   zfs snapshot -r zroot/cloud-installer/bastille/jails/cloudnc@offline-20261014T120000Z
   zfs snapshot -r zroot/cloud-installer/bastille/jails/cloudoo@offline-20261014T120000Z
   ```
   Choose a new label each time. The three commands form a coherent set only because all writers remain stopped; verify every expected snapshot exists before recording success. This captures physical MariaDB data/logs, Nextcloud config/code/custom apps and files/encryption keys together. Package caches/releases shared outside the jail trees need separate recovery coverage.
5. At that same frozen point, copy protected host registry/configuration/credentials/journals, the selected transaction and PF file, Bastille/devfs/storage-guard/rc configuration, TLS material and any required ZFS encryption keys to the recovery set. Shared host metadata describes **all** instances: never blindly roll it back to recover just one instance. Record which snapshots, package versions and metadata belong together.
6. Replicate the snapshots and metadata to protected independent storage; a snapshot in the original pool is not protection against pool loss. Define retention and verify off-host copies. Preserve all permissions and required encryption material.
7. Restart only after checking the current ownership/PF/storage guards. Restore prior maintenance/service states, release the lock, then run `sh install.sh verify cloud` and affected native/API saved-fixture checks, with representative browser callback/save integration where required by the [testing boundaries](testing-boundaries.md).

Restore the cold set together in an isolated rehearsal, using compatible jail/application versions and a reviewed host reconstruction procedure. Do not mix its older physical database with newer user files, or run a live recursive rollback while jails have mounted datasets. The normal SQL/config `restore` command does not accept ZFS snapshots or reconstruct removed instances. If pairing an SQL dump with a file backup instead, maintain **one continuous quiesced writer window** across both captures; an unrelated later snapshot is not coherent.

After a successful logical restore the installer runs `occ maintenance:data-fingerprint`; a manually reconstructed full restore needs the corresponding Nextcloud recovery step and client reconciliation too. Validate retained contacts/calendars, file checksums, versions and shares together through representative saved fixtures, including both accounts to detect mix-ups. Measure the actual recovery time and data-loss window; this is not a claim of storage-engine durability. See [Nextcloud 35 backup requirements](https://docs.nextcloud.com/server/35/admin_manual/maintenance/backup.html), [restore guidance](https://docs.nextcloud.com/server/35/admin_manual/maintenance/restore.html) and [FreeBSD lockf implementation](https://github.com/freebsd/freebsd-src/blob/releng/15.1/usr.bin/lockf/lockf.c).

## Production readiness

Apply the canonical [testing boundaries](testing-boundaries.md) to each recipe's gates: actual generated settings/command effects, ownership, isolation, recovery and saved-fixture continuity. Retain distinct mixed-instance PF/proxy cases; do not multiply unchanged seams across formats, fonts or browser sessions. A representative real callback/save check remains necessary where that integration is affected; equivalent native/API checks cover other claims. During maintenance, verify ordinary ingress is blocked while the privileged canary succeeds. Controlled reboot tests persisted permissions, not arbitrary power-cut or dependency-internal resilience; runtime recovery guards remain intact.

This is a **single-host deployment architecture**, with shared kernel, storage and PF failure domains. It supplies neither high availability/failover nor an availability SLO. Before production, complete and retain the [native acceptance evidence](freebsd-15.1.md#freebsd-integration-checklist), including multi-instance isolation, fault recovery and restore drills.

Set measurable SLOs and backup **RPO/RTO**, assign monitoring/on-call ownership, and monitor external HTTPS/DAV/document saves, certificate expiry/renewal, cron freshness, database/Redis/FPM health, memory/swap/ARC, pool health/free space, quotas/snapshots, service logs and backup age/restore results. A local healthcheck does not prove that users can save a document. Keep metrics and administrative endpoints private.

Review ONLYOFFICE Community's license/concurrency limits and the [font licenses](fonts.md) against the workload; installing the Community package does not provide Enterprise support or unlimited editing capacity. FreeBSD support must be assessed separately from upstream Linux requirements.

Core files are root-owned and the web core updater is disabled. Use the optional
[native upgrade assistant](upgrade.md) only within its reviewed application and
package boundary. Read-only `resolve ... --installed PLAN` assessment does not
authorize mutation. Plan host OS, Bastille, jail-base and unsupported application
transitions separately: review version paths and layouts, rehearse coherent
recovery, and validate affected integration. Do not use `resume` with a new
artifact, blanket package upgrades or journal edits as an upgrade mechanism.
