# Optional native application upgrade

Run from a current unpacked checkout/release on the supported FreeBSD host, as
root, with Python already installed. `upgrade` never bootstraps host packages.
It targets an installer-created, ready, **unenrolled** Nextcloud/ONLYOFFICE jail
pair. The original installer artifact and historical application version lock are
not prerequisites. Existing lifecycle enrollment, resource identity and pending
PF transaction guards still apply.

## Commands

```sh
sh install.sh upgrade cloud --plan
sh install.sh upgrade cloud
sh install.sh upgrade cloud --verify
```

Replace `cloud` with the instance name. The menu also offers **Upgrade
applications**. Full syntax:

```text
upgrade INSTANCE [--nextcloud VERSION] [--plan | --verify | --restore SNAPSHOT_REPORT] [--skip-packages]
```

The initial Nextcloud transition is **35.0.1 → 35.0.2**, with 35.0.2 the default
target. An already-updated 35.0.2 installation can be inspected for compatible
package updates. Arbitrary versions, downgrades and skipped major releases are
unsupported. Fresh-install selection follows [central version policy](versions.md)
and is separate from this upgrade adapter.

- `--plan` inspects the running installation and may refresh signed native pkg
  metadata: it is **not offline**. It does not stop services or install packages.
- Compatible application-jail package updates, including Document Server where
  supported by the reviewed policy, are considered by default. Availability alone
  does not prove compatibility. `--skip-packages` omits these updates. Host
  packages, host OS and jail-base upgrades are outside this command.
- Execution displays the selected plan and requires an interactive terminal and
  exactly `UPGRADE INSTANCE` once. There is no `--yes` switch. Save and close
  editors first; unsaved editor work is outside snapshot coverage.
- `--verify` performs read-only checks of **current live** versions, services,
  configuration, HTTPS and connector readiness. It works after upgrading without
  historical version locks, enrollment or permanent manager use. It does not
  refresh a package plan or execute an upgrade. These checks are not a browser
  editing/save test or comprehensive upstream certification.

`--plan` and `--verify` can run without a terminal. All modes retain host/platform
checks and operation/database serialization. `--archive` dispatch is unsupported
for `upgrade`; unpack and verify the payload first.

## Snapshot, upgrade, result

For a plan with changes, the assistant cleanly stops the affected services/jails
and captures one coherent native ZFS snapshot set before mutation. It then starts
the jails for the supported native package/application upgrade steps and checks
readiness. Expect brief downtime. A no-change plan does not pause services.

On upgrade failure, it stops the affected jails and reports the error plus a
restore command. **Restoration is the user's choice, never automatic.** To restore:

```sh
sh install.sh upgrade cloud --restore /absolute/path/to/snapshot/report.json
```

Confirm `RESTORE cloud` after reviewing that this discards changes since the
snapshot. The command restores the selected set, starts and verifies the original
system. If restoration fails, the affected jails stay stopped. A failure before
any snapshot/upgrade simply restores the prior service state. Inspect the report;
do not blindly repeat an uncertain migration.

The snapshot set is local recovery assistance, **not disaster recovery**. It does
not protect external storage, unsaved editor work or loss of the host/storage.
The operator remains responsible for independent backups and recovery beyond
the captured set. Package downgrade alone is not database rollback. This command
does not add a separate archive/export, backup-only or restore framework.

## Historical commands and validation status

Failure containment does not depend on saving diagnostic files. If private report
storage is unavailable, the upgrade still attempts its normal containment/recovery
path and returns a safe failure summary. `diagnostics_incomplete: true` or
`report_saved: false` means private evidence may be missing or stale; retain the
console summary. A failed stop is reported as requiring operator attention, not
as confirmed containment. Snapshot restoration remains an explicit operator choice.

Historical `verify`, `backup` and `restore` retain their original installation and
version-lock contracts. After upgrading, a refusal from those commands due to a
version/artifact mismatch does **not** establish that the upgraded installation is
broken. Use `upgrade INSTANCE --verify` for live post-upgrade checks. Do not treat
the historical backup/restore commands as current-version recovery support or
feed the new snapshot set to legacy `restore`. Historical installation records
are not silently rewritten to hide version changes.
`add-user` is a live Nextcloud operation: it does not compare versions with the
original installation lock. It remains available after upgrades when live readiness
checks and the supported account command succeed. It refuses maintenance mode,
pending database upgrades or restores, and verifies a non-admin result.

Bounded native checks exercised explicit snapshot restoration to 35.0.1 and a
subsequent CLI upgrade to 35.0.2, including HTTPS, connector readiness, preserved
data and browser edit/save/reopen. No package changes were selected, so
dependency-changing execution is not claimed tested. Broader source/target
versions remain outside this adapter; see [validation limits](verification.md).
