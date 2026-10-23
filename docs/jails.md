# Multi-instance jail deployment design

The target is a FreeBSD 15.1-RELEASE amd64 host with an existing healthy ZFS pool and static IPv4. The first instance needs a clean jail/firewall host; later instances extend only this installer's owned resources. Each instance has two thick VNET jails. At least 8 GiB RAM is required, 16 GiB or more recommended initially; additional instances must fit aggregate service budgets plus one host/ZFS ARC reserve.

Bounded native checks are not full production/recovery acceptance or proof of
capacity; see [validation limits](verification.md). Keep the host clock accurate
and update the OS separately; all jails share its kernel and clock. The two-jail
layout below describes native ONLYOFFICE; see [other profiles](fresh-install-profiles.md)
for one-jail and office-VM layouts.

## Manager and application placement

**Bastille 1.4.4** supplies thick VNET jail creation, pkgbase release bootstrap, persistent nullfs mounts and startup hooks with a small ports dependency footprint. The [reviewed port](https://github.com/freebsd/freebsd-ports/blob/main/sysutils/bastille/Makefile) has no declared additional runtime package dependencies. It is installed after the operator reviews the plan and types `APPLY`.

Maintenance evidence checked **2026-10-14**:

- [Bastille 1.4.4](https://github.com/BastilleBSD/bastille/releases/tag/1.4.4) was released **2026-07-12**; [upstream activity](https://github.com/BastilleBSD/bastille/commit/98b7fc5deaf4f757f276a3118e4abf9099e42f87) continued on **2026-09-16**.
- [AppJail 5.9.1](https://github.com/DtxdF/AppJail/releases/tag/v5.9.1) was released **2026-10-12**. Both projects are maintained; Bastille was selected for the required capabilities and minimal host package footprint.
- The installer checks the actual selected repository for the reviewed Bastille version before installation. Repository availability and installed versions may change after this review.

These are dated baseline identities. [Central version policy](versions.md)
separates discovery from compatibility and locks the selected applications,
connector, host prerequisites and per-jail dependency closures before provisioning.
The installation sequence below consumes that lock; it does not select mutable
latest versions or perform upgrades.

| Location | Responsibilities |
| --- | --- |
| Host | ZFS datasets, Bastille, Python orchestration, private bridges, routing and PF/NAT |
| `<instance>nc` | Apache HTTP/HTTPS, PHP 8.5 FPM, Nextcloud 35, MariaDB 12.3, Redis, cron and ACME when selected |
| `<instance>oo` | Native ONLYOFFICE Docs 9.4, nginx frontend, Supervisor `ds:docservice` and `ds:metrics` |

Workers run inside their jails at `/root/cloud-installer/resources/jails/{nextcloud,onlyoffice}.sh`. The mode-`0700` payload contains code/resources and **public-settings-only** `runtime.json`, still private-mode. Configuration is never sourced as shell code. The generated secret bundle stays on the host; phase-specific secrets travel only over stdin to a checked numeric `jexec` JID. ONLYOFFICE receives the JWT, not Nextcloud's administrator/database password.

Active templates are in `resources/templates/{nextcloud,onlyoffice}/`; `resources/jails/nextcloud-bootstrap.php` handles structured NC35 provisioning. `installer/{office,office_config}.py` renders reviewed office package configuration. Required native application secrets, such as Nextcloud's DB password and ONLYOFFICE's JWT, remain in protected application configuration; this is distinct from staging the installer credential bundle.

## Network policy

For the default RFC1918 block **`10.77.0.0/29`**:

```text
                         host external interface
                       PF redirects TCP 80 and 443
                                  |
                 host routes/NATs between private segments
                  /                               \
     bridge240: 10.77.0.1/30            bridge241: 10.77.0.5/30
                  |                               |
      Nextcloud: 10.77.0.2/30           ONLYOFFICE: 10.77.0.6/30
      gateway:   10.77.0.1              gateway:   10.77.0.5
```

Each bridge has only its jail's VNET endpoint and host gateway; **never add the physical uplink**. Different bridges prevent a direct layer-2 route around host PF. For another instance, for example `10.77.0.8/29`, the gateways/jails become `.9/.10` and `.13/.14` on different bridges. Preflight checks host routes/interfaces, registry allocations, ingress address/port pairs, jail identities/hostnames and storage ownership for conflicts.

| Source | Allowed destination |
| --- | --- |
| Configured management IPv4 CIDR | Host's configured SSH port |
| Public clients, direct TLS | Selected host HTTP/HTTPS ports → Nextcloud TCP 80/443 |
| Explicit trusted proxy IPv4 CIDRs, external TLS | Selected host HTTP backend port → Nextcloud TCP 80 |
| Nextcloud jail | ONLYOFFICE nginx TCP **8081** |
| ONLYOFFICE jail | Its paired Nextcloud TCP **443** with direct TLS, **80** with external TLS |
| Both jails | Selected DNS resolver TCP/UDP 53 and Internet HTTP/HTTPS for packages, apps and ACME |
| Management CIDR, optional jail SSH | Selected per-jail host ports → jail TCP 22, key-only |

Host administration/verification has explicit allowances. Other lateral traffic,
**inter-instance traffic**, private-network egress and unsolicited inbound traffic
are blocked. DNS is an intentional exception when the resolver is private.
DocService TCP **8000**, metrics TCP **8126**/UDP **8125**, database and cache
services are not public endpoints. Default egress has no mail allowance. Selecting
the Mail app adds only Nextcloud outbound public IPv4 TCP 465/587/993, disclosed
before APPLY: no TCP 25, private mail destinations, inbound mail service or office
mail egress. System-notification SMTP remains disabled.

The host loads bridge/epair/PF modules and persists associated settings. It uses `net.link.bridge.pfil_member=0`, `pfil_bridge=1`, `pfil_local_phys=0` and `pfil_onlyip=1`, explicit ingress **and egress** rules and interface-bound states. `set ruleset-optimization none` keeps normalized PF snapshots stable across reload/reboot. Initial forwarding activation follows confirmation. One generated PF policy covers **all active instances**; this is not a merge with arbitrary PF or Bastille redirect rules. Foreign PF/IPFW/Bastille deployments, conflicting devfs ruleset 13 and service-specific network overrides are refused.

The host/jails are **static IPv4-only** and host inbound IPv6 is blocked. With direct TLS, the public hostname needs exactly the expected host/router A address and no AAAA; the host ingress address remains its actual interface address behind NAT. Router forwarding must reach the selected instance ports, including public TCP 80 for ACME. Both jails resolve the public hostname internally to the private NC address for certificate-valid HTTPS callbacks on jail port 443, independently of a different public HTTPS port.

With **external TLS**, public DNS points to the proxy and can include IPv6. Only the selected narrow proxy IPv4 CIDRs may reach the HTTP backend; prefer `/32`. Nextcloud trusts that same list and forces the configured public HTTPS authority/port. ONLYOFFICE uses `http://<nc-private-ip>/` for callbacks. The proxy-to-host HTTP transport requires a trusted private LAN/VPN, not plaintext across the Internet. See the [Nginx example and header contract](reverse-proxy.md).

A detached supervisor is armed **before** loader/rc/sysctl network changes and bridge creation. It owns a separate process-group worker for applying and committing changes. The interactive installer never owns the mutation lock: suspension or loss of its SSH session cannot hold up recovery. At the 180-second transition deadline, or on cancellation/failure, the supervisor terminates/reaps its worker group **before** acquiring the rollback lock. This also handles a worker suspended while holding the lock; neither SSH nor unrelated processes are terminated. Native commands and IPC waits are bounded, and an expired/rolled-back transaction cannot apply again. Recovery still needs a functioning OS and supervisor; console access remains essential.

Existing SSH traffic is preserved in both directions, including server-first output from the current SSH tuple. When PF becomes active, open a **second SSH session**, confirm it works and type **`KEEP` before the displayed deadline**. Only confirmation persists PF/forwarding boot activation. The supervisor sends a committed result before the host installer may proceed to jail creation.

Without confirmation, rollback restores saved host configuration/sysctls and removes only newly created bridges. On the first fresh-host transaction it disables the newly enabled PF; on a managed host it **reloads the prior policy without disabling PF or flushing existing states**, preserving other instances. Module loads, installed packages and datasets remain. Later application failures stop only the affected instance's jails and retain the approved policy. Inspect private rollback diagnostics if restoration fails; avoid concurrent manual network/rc changes.

Transactions live in `/var/db/cloud-installer/transactions/`; `network/active` points to the committed transaction. New mutations refuse unresolved transactions. After a reboot/power loss or an expired transition not recovered by its watchdog, `sh install.sh recover-network` requires **`RECOVER`** and checks the saved/current `kern.boottime`, deadline and mutation lock before restoring prior policy. It refuses still-active transitions. See [network recovery](operations.md#shared-network-transitions).

## Storage layout

The wizard selects an existing pool and a 1–8 character instance ID matching `[a-z][a-z0-9]{0,7}`. Bastille 1.4.4 rejects hyphens/underscores in VNET jail IDs; the limit also keeps generated epair names within FreeBSD's interface-name limit. For `instance=cloud`, IDs are **`cloudnc`** and **`cloudoo`**. Custom jail hostnames can be DNS short names or FQDNs, including hyphens; they are distinct from IDs and do not change the public TLS identity.

For `pool=zroot`, shared Bastille is **`zroot/cloud-installer/bastille`**, mounted at **`/srv/cloud-installer/bastille`**. Releases/cache are shared; jail datasets are below `bastille/jails/<id>`, with roots at `/srv/cloud-installer/bastille/jails/<id>/root`. Application storage is **`zroot/cloud-installer/instances/cloud`**, mounted at **`/srv/cloud-installer/instances/cloud`**, with these children:

| Dataset child | Jail mount/use |
| --- | --- |
| `nc-app` | Nextcloud `/usr/local/www/nextcloud` |
| `nc-data` | Nextcloud `/var/nc-data` |
| `nc-database` | Nextcloud `/var/db/mysql` |
| `nc-db-logs` | Nextcloud `/var/log/mysql` |
| `nc-logs` | Nextcloud `/var/log` |
| `nc-tmp` | Nextcloud `/var/nc-tmp` |
| `office-runtime` | ONLYOFFICE `/var/db/onlyoffice` |
| `office-data` | ONLYOFFICE `/usr/local/www/onlyoffice/Data` |
| `office-logs` | ONLYOFFICE `/var/log` |

Storage is host-owned; shared/instance parent directories are root-only to prevent ordinary host accounts traversing raw jail/document-cache files. Data is nullfs-mounted before service/package initialization. Seed `/var/log` before mounting it, then mount nested DB logs. Each jail's `exec.prepare` hook runs **before filesystem mounts** and checks ZFS ownership properties, actual datasets/root filesystems, exact mountpoints and covering mounts; a directory cannot masquerade as persistent data.

The same hook requires this instance's allow-start marker, a confirmed **active shared** transaction, live PF matching its normalized filter/NAT/table snapshots, correct bridges and filtering/forwarding settings. A host rc script supplies ordering before Bastille; the per-jail hook enforces the checks even if an rc prerequisite fails. Set hooks using Bastille's native config API: its existing VNET scripts contain shell braces. Manual policy changes require deliberate implementation review and fresh verification, not edits to expected snapshots to bypass the guard.

Dataset quotas are capacity ceilings, not reserved free space or backups. Capacity review considers jail roots/releases, uploads, database logs and document working data as well as user files. Directly created datasets use `compression=lz4`, `atime=off`, `dedup=off`, `sync=standard`, `primarycache=all`, and a 16K database record size (128K for other roles); data/log/temp datasets disable executable/setuid files where appropriate. Never weaken synchronous-write durability to compensate for slow storage.

New installations default to **no installer-imposed quotas on any dataset**, including
application parents, user files, databases, logs, temporary/office storage and jail
roots. Optional positive caps are manually entered; `0` means no cap. The wizard
does not suggest fixed numbers or divide pool capacity into quota allocations.
Read-only inspection shows the actual destination's usable capacity and existing
parent limits. Allow space for selected applications, database/upload growth,
updates and snapshots; available capacity is not a workload guarantee.

There is no new dedicated/shared storage profile or quota-driven instance limit.
No ZFS reservations are created: data, logs or snapshots can fill storage and
interrupt services. Optional caps can contain individual consumers, but do not
reserve room for other services. Existing ancestor limits are not cleared.
Configurations without the new `storage_policy: "optional"` marker retain their
legacy quota semantics and serialized digest. No live quotas are resized.
Optional caps are applied after APPLY through the existing dataset-creation path;
installation phase ordering, mounts, package operations and services are unchanged.

The [database/configuration backup](backup-restore.md) includes all users' DAV records but excludes user files, data-directory encryption keys and full host/jail recovery state. Full recovery needs a [coherent offline snapshot set](operations.md#coherent-offline-snapshots), required keys and protected off-host copies. Default removal retains application datasets; `--purge-data` destroys them and their snapshots after exact confirmation. Neither operation prunes host credentials/backups/audit state or uninstalls shared resources.

## Service defaults and HTTPS

- **PHP-FPM:** total worker count comes from the PHP budget divided by the per-request memory allowance, with conservative initial/spare counts. New deployments require at least three workers: one callback worker for a total of three, two for larger totals; the remainder handles ordinary traffic. Private `/var/run/php-fpm/nextcloud.sock` and `office-callback.sock` sockets retain restrictive permissions and `clear_env = yes`. Apache selects the callback pool only for the paired office connection IP, preventing synchronous previews from occupying every callback slot. Budgets are initial estimates, not measured RSS or enforced jail memory caps; monitor memory/ARC and actual concurrency. See [callback capacity](onlyoffice.md#reserved-nextcloud-callback-capacity).
- **MariaDB:** buffer size and connections follow resource planning. Default durability keeps `innodb_flush_log_at_trx_commit=1`, `innodb_doublewrite=ON` and synchronous binlogs. Database files/logs have separate persistent datasets.
- **Redis:** private Unix socket, `maxmemory-policy noeviction`, and explicitly ephemeral Nextcloud cache/lock state (`save ""`, `appendonly no`). A full cache produces errors rather than evicting active locks; monitor it. Persistent user data belongs in Nextcloud/MariaDB.
- **TLS:** Direct modes terminate HTTPS at Apache. ACME uses HTTP-01 webroot and validates/reloads Apache on renewal; preserve challenge access. Provided PEM inputs must be root-owned, not group/other-writable and at most 1 MiB each; private keys require `0600` or stricter. Validate key, hostname, chain and at least seven days before expiry. Private-CA trust belongs in both applications and browsers. Supplied-certificate replacement is operator-managed. External mode terminates HTTPS at the proxy, with HTTP only inside the trusted backend network.
- **ONLYOFFICE:** `/onlyoffice/` is the public virtual path. nginx listens on its private jail IPv4 address at 8081. JWT and callback certificate verification remain enabled; the native backend ports stay isolated. See [the office guide](onlyoffice.md).
- **Application ownership:** after provisioning, Nextcloud core/shipped apps are `root:www`; only `config` and `custom_apps` remain writable by `www`. The web core updater is disabled. Use the separately reviewed [upgrade assistant](upgrade.md) within its supported boundary; other core upgrades and `.htaccess` regeneration require deliberate maintenance/permission planning.
- **Diagnostics/rotation:** bootstrap diagnostics are private in the jail's `/var/db/cloud-installer/`; service logs are on the log datasets. Treat them as sensitive. newsyslog uses service-appropriate log reopening; Supervisor bounds its own logs. Validate actual rotation on FreeBSD.
- **Fonts/SSH:** [Font profiles](fonts.md) resolve a broad licensed package catalog and optional operator-owned custom inputs. [Direct jail SSH](ssh.md) defaults to an unprivileged key-only `cloudop` account, with optional explicitly confirmed `doas` administration and zsh. FreeBSD's `operator` account is reserved. [Klara's shell overview](https://klarasystems.com/articles/interacting-with-freebsd-learning-the-fundamentals-of-the-freebsd-shell-2/) explains interactive-shell choice; it does not change the workers' `/bin/sh` contract.
- **Email:** system-notification delivery is disabled (`mail_smtpmode=null`), not silently queued. Enabling notifications requires relay authentication/TLS and reviewed managed policy; no post-install policy-update command is exposed. Optional Mail is a separate client integration with only the egress described above. Fresh app/font/plugin selections follow [configuration](configuration.md); post-install changes require separate maintenance planning.

## State, failures and boot

Acceptance follows the [testing boundaries](testing-boundaries.md): prove actual jail identities/mounts, generated settings, isolation, command effects and saved-fixture continuity for each affected recipe. Keep distinct mixed-instance PF/proxy branches. Use bounded controlled reboot for persisted start permissions; it does not prove power-cut or FreeBSD/ZFS internal resilience. Runtime guards for abruptly interrupted saved state remain mandatory.

`/var/db/cloud-installer/instances/NAME` holds `config.json`, host-only `secrets.json`, `status.json`, `deployment.json`, source binding and inventories. Directories are root-owned `0700`, private files `0600`. A global host lock serializes provisioning, resume, removal and backup/restore. Workers retain phase evidence/diagnostics in their private jail state, not a copy of the credential bundle.

`resume NAME` requires unchanged configuration and the original installer artifact/source hash; it checks owned resources and continues safe phase checkpoints. Uncertain partial Nextcloud tables are refused, not deleted. Before initial NC setup the installer takes a quiesced four-dataset checkpoint (app, data, database, DB logs). **`recover-install NAME`** can restore it only for an interrupted/incomplete initialization before publication has ever begun, after **`RESET-INITIALIZATION NAME`**; it is not an operating-service rollback. Newer snapshots, identity/ownership changes or ambiguous state require manual review. See [recovery restrictions](operations.md#initialization-recovery).

Jail autostart follows automated integration/restart checks. `sh install.sh verify NAME` (alias `--verify NAME`) rechecks a ready deployment. Both jails must have expected live names/roots; each wrapped `jexec` pins the same JID before/after, avoiding Bastille 1.4.4's successful stopped-jail `cmd` no-op. Empty package inventories and invalid/non-ready Nextcloud JSON fail verification. The affected [FreeBSD acceptance gates](freebsd-15.1.md#freebsd-integration-checklist) additionally require real external allowed/denied probes, multi-instance recovery and persisted boot checks. Native/API checks establish equivalent saved-data claims; one representative real browser callback/save/reopen checks the office integration where affected, not every document format. During maintenance validation, prove ordinary ingress remains blocked while the privileged canary succeeds.

## Native lifecycle sources

- [Bastille 1.4.4 bootstrap](https://github.com/BastilleBSD/bastille/blob/1.4.4/usr/local/share/bastille/bootstrap.sh), [creation](https://github.com/BastilleBSD/bastille/blob/1.4.4/usr/local/share/bastille/create.sh), [network generation](https://github.com/BastilleBSD/bastille/blob/1.4.4/usr/local/share/bastille/common.sh) and [configuration](https://github.com/BastilleBSD/bastille/blob/1.4.4/usr/local/etc/bastille/bastille.conf.sample).
- [FreeBSD 15.1 bridge filtering](https://github.com/freebsd/freebsd-src/blob/release/15.1.0/share/man/man4/bridge.4), [PF syntax](https://github.com/freebsd/freebsd-src/blob/release/15.1.0/share/man/man5/pf.conf.5), [jail startup order](https://github.com/freebsd/freebsd-src/blob/release/15.1.0/usr.sbin/jail/jail.c) and [gateway filtering example](https://docs.freebsd.org/en/books/handbook/firewalls/#pftut-gateway).
