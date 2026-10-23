# Administration checks and validation limits

An empty Nextcloud warning panel is not proof of security, durability or working
document editing. `sh install.sh verify INSTANCE` reports supported readiness and
configuration checks without repairing drift, installing packages or upgrading.
After an application upgrade, use the live checks described in [upgrade](upgrade.md).

## Editor connectivity

For native ONLYOFFICE, distinguish the three connector addresses:

| Setting | Illustrative direct-TLS value | Purpose |
| --- | --- | --- |
| `DocumentServerUrl` | `https://cloud.example.org/onlyoffice/` | Browser-visible editor through the HTTPS frontend. |
| `DocumentServerInternalUrl` | `http://10.77.0.6:8081/` | Nextcloud-to-office private frontend. |
| `StorageUrl` | `https://cloud.example.org/` | Office-to-Nextcloud downloads and callbacks; private resolution preserves certificate hostname validation. |

Substitute the configured hostname and private addresses. External TLS instead
uses the explicitly trusted private HTTP callback transport. Do not copy those
settings into a direct-TLS deployment or disable certificate verification. Compare
effective URLs against the retained configuration before considering any change;
do not print JWTs or secret settings. Verification detects drift, not authority to
overwrite administrator changes.

Healthy services, HTTP healthchecks and a successful connector conversion check
do not prove browser WebSocket operation or saved-document persistence. Use a
normal account and a disposable document for a bounded edit/save/close/reopen
check. A test that bypasses public ingress does not validate DNS/router access.
See [browser troubleshooting](troubleshooting.md#editor-shows-placeholders-or-keeps-loading),
[ONLYOFFICE](onlyoffice.md) and [reverse proxies](reverse-proxy.md).

## Database checks

Fresh native configuration sets `innodb_log_file_size = 256M`; verification checks
the effective value is at least 128 MiB. This is redo-log disk capacity, not a PHP
or database-buffer allocation. `innodb_log_buffer_size` and `max_binlog_size` are
different settings. Changing the source template does not resize existing logs.
A live change requires approved maintenance, free-space/recovery checks and the
MariaDB-version-specific resize procedure. **Never delete redo files to resize.**
Keep flush-at-commit, doublewrite and binlog durability enabled.

A serverinfo replication warning does not itself establish a configured replica.
Review privileged replication status and the installed app rule before acting.
Do not create/reset replication, disable durable binlogging or grant application
replication privileges merely to silence a warning. MariaDB `server_id=1` plus
binlogging does not imply replication is configured.

## Setup warnings

| Check | Conservative handling |
| --- | --- |
| Errors in log | Investigate actual entries; do not clear logs to hide historical warnings. |
| Mimetype migrations | Run the required native migration under the appropriate installation/maintenance workflow; never fake completion flags. |
| AppAPI deploy daemon | ExApps require a separately reviewed architecture. Do not deploy an insecure placeholder to silence an unused-feature warning. |
| Two-factor enforcement | Establish enrollment and recovery policy before enforcing and potentially locking out administrators. |
| Default phone region | Use the intended ISO 3166-1 country code, not a guess from DNS, timezone or language. |
| Nextcloud server ID | `serverid`, `instanceid` and MariaDB `server_id` are different identities. Separate FPM pools do not imply multiple PHP servers. Do not regenerate identity to clear an advisory. |

The reviewed NC35 initial-install worker uses the narrow
`OC\Repair\RepairMimeTypes` step before publication and verifies no migration
remains. A published service requires explicit maintenance, not replay as initial
setup. `occ maintenance:repair --include-expensive` is broader: it can run enabled
apps' hooks and affect maintenance mode. It is not a routine Verify/Resume action.
Review the native class again before supporting another Nextcloud profile.

Do not treat generic `occ setupchecks` exit status as a boolean deployment gate:
app-provided checks may have side effects or report optional-feature notices.
Preserve categories, timestamps and unknown/error results. An available patch
release is not upgrade authority; follow [version policy](versions.md).

## Sources and limits

- [NC35 mimetype repair](https://github.com/nextcloud/server/blob/v35.0.1/lib/private/Repair/RepairMimeTypes.php).
- [NC35 general repair command](https://github.com/nextcloud/server/blob/v35.0.1/core/Command/Maintenance/Repair.php).
- [Validation limits](verification.md) and [testing boundaries](testing-boundaries.md).

These are diagnostic and safety guidelines, not a new native validation result,
full production acceptance, capacity certification or disaster-recovery claim.
