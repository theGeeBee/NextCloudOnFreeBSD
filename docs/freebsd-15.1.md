# FreeBSD 15.1 compatibility and verification

The target is a **FreeBSD 15.1-RELEASE amd64 ZFS host**. Native ONLYOFFICE uses
two thick VNET jails; other [fresh-install profiles](fresh-install-profiles.md)
use one Nextcloud jail, with a dedicated office VM when selected. Bounded native
checks do not establish the complete matrix below, general recovery or production
capacity. See [current validation limits](verification.md) and the separate
[native upgrade assistant](upgrade.md). The first installation requires a clean
host; subsequent instances must pass shared-policy and ownership checks.

## Source review (2026-10-14)

| Area | Evidence / decision |
| --- | --- |
| Nextcloud 35 | [Requirements](https://docs.nextcloud.com/server/35/admin_manual/installation/system_requirements.html) list PHP 8.5 and MariaDB 12.3. [Release downloads](https://download.nextcloud.com/server/releases/) provide `latest-35.tar.bz2` and its detached signature. FreeBSD is not an upstream-listed server OS. |
| PHP packages | [`lang/php85`](https://github.com/freebsd/freebsd-ports/blob/main/lang/php85/Makefile) includes CLI/FPM. [`Mk/Uses/php.mk`](https://github.com/freebsd/freebsd-ports/blob/main/Mk/Uses/php.mk) defines extension names. IMAP is `php85-pecl-imap`; OPcache is built into PHP 8.5, not a separate package or `opcache.so`. |
| MariaDB | [`databases/mariadb123-server`](https://github.com/freebsd/freebsd-ports/blob/main/databases/mariadb123-server/Makefile) depends on the matching client. Its [rc script](https://github.com/freebsd/freebsd-ports/blob/main/databases/mariadb123-server/files/mysql-server.in) uses `mysql-server`, `mysql_enable`, `mariadb-install-db` and `/usr/local/etc/mysql/my.cnf`. |
| Binary availability | Official FreeBSD 15 amd64 [latest](https://pkg.freebsd.org/FreeBSD:15:amd64/latest/packagesite.pkg) and [quarterly](https://pkg.freebsd.org/FreeBSD:15:amd64/quarterly/packagesite.pkg) catalogs contained the reviewed PHP 8.5 dependencies, MariaDB 12.3 and ONLYOFFICE `9.4.0_4`. This dated catalog evidence does not guarantee another ABI/date. Package resolution and installed-version checks also run in the target environment. |
| Repositories | [FreeBSD 15.1 definitions](https://github.com/freebsd/freebsd-src/blob/releng/15.1/usr.sbin/pkg/FreeBSD.conf.quarterly-release) name `FreeBSD-ports`, `FreeBSD-ports-kmods` and `FreeBSD-base`. Application/host prerequisite installs are scoped to `FreeBSD-ports`. Bastille bootstraps jail base releases through its reviewed pkgbase support; host OS updates remain an administrative task. |
| Bastille | [1.4.4 release, 2026-07-12](https://github.com/BastilleBSD/bastille/releases/tag/1.4.4), [2026-09-16 activity](https://github.com/BastilleBSD/bastille/commit/98b7fc5deaf4f757f276a3118e4abf9099e42f87), [ports recipe](https://github.com/freebsd/freebsd-ports/blob/main/sysutils/bastille/Makefile) and [networking documentation](https://bastille.readthedocs.io/en/latest/chapters/networking.html). See [manager choice](jails.md#manager-and-application-placement), including current AppJail release evidence. |
| Run as `www` | Base [`mdo(1)`](https://github.com/freebsd/freebsd-src/blob/releng/15.1/usr.bin/mdo/mdo.1) supports root switching to a named user with supplementary groups. |
| Email | Delivery is explicitly disabled using NC35's documented [`mail_smtpmode=null`](https://github.com/nextcloud/server/blob/stable35/config/config.sample.php). This profile does not collect/verify SMTP relay credentials or permit SMTP egress; it must not silently queue undeliverable DMA messages. |
| HTTPS renewal | [`security/py-certbot`](https://github.com/freebsd/freebsd-ports/blob/main/security/py-certbot/Makefile) supplies Certbot. The jail worker uses [webroot authentication](https://eff-certbot.readthedocs.io/en/stable/using.html#webroot) and a scheduled renewal/deploy hook that validates and gracefully reloads Apache. |
| ONLYOFFICE | Native `www/onlyoffice-documentserver` 9.4.x and the compatible signed Nextcloud connector run in separate jails. [Port layout, sources and acceptance checks](onlyoffice.md). |
| Reverse proxy | [NC35 proxy documentation](https://docs.nextcloud.com/server/35/admin_manual/configuration_server/reverse_proxy_configuration.html) requires explicit trusted proxies, careful client-IP header handling and public URL overrides where needed. [Nginx WebSockets](https://nginx.org/en/docs/http/websocket.html) require forwarded Upgrade/Connection headers. See the [concrete external TLS configuration](reverse-proxy.md). |
| Recovery scope | [NC35 backup](https://docs.nextcloud.com/server/35/admin_manual/maintenance/backup.html) includes configuration, custom apps, data, themes and database; [restore](https://docs.nextcloud.com/server/35/admin_manual/maintenance/restore.html) includes maintenance/data-fingerprint handling. The menu's database/config backup covers only part of that scope. |
| Fonts and SSH | [Fonts](fonts.md) records actual package names, availability, licenses and native helper evidence. [Optional SSH](ssh.md) documents key-only defaults, explicit administrative privilege and zsh; [Klara's shell overview](https://klarasystems.com/articles/interacting-with-freebsd-learning-the-fundamentals-of-the-freebsd-shell-2/) explains interactive-shell selection independently of `/bin/sh` scripts. |

## Supported boundaries

Version selection now follows [central policy and independent discovery/compatibility](versions.md).
This dated evidence records the baseline, not a rule accepting every higher version.
Repository availability is rechecked with native authenticated metadata and solver
dry runs before provisioning; exact selection is retained for Resume.

- One `sh install.sh` host menu/CLI, with `--plain`, private schema-2 state, explicit bootstrap consent and reviewed-artifact distribution. Python preflight checks running kernel, architecture, aggregate memory/storage, networking and resource ownership.
- At least 8 GiB RAM, 16 GiB or more recommended initially. Additional instances must fit all budgets and reserve headroom; quotas/budgets are not performance guarantees or RCTL limits. Pools are selected, never created/formatted.
- Multiple installer-owned instances share Bastille and PF. Foreign firewall/Bastille adoption, OS/application upgrades and jail migration require separate plans. Safe phases can resume with immutable inputs/source; uncertain initial NC setup requires restricted explicit recovery or manual intervention.
- Host/jails use static IPv4. Direct TLS requires matching A/no AAAA; external proxies can provide public IPv4/IPv6 HTTPS while their HTTP backend is narrow-CIDR-restricted over a trusted LAN/VPN. Public HTTPS ports and private callback ports are independent.
- HTTPS can use jail ACME/provided certificates or external termination. FPM uses private sockets and memory-derived counts, reserving callback workers within the total allowance to prevent synchronous office previews starving their own downloads. Routing uses the paired office connection IP, not forwarded headers; see [callback capacity](onlyoffice.md#reserved-nextcloud-callback-capacity). MariaDB retains durable defaults; Redis is an ephemeral cache/lock service with `noeviction`.
- Persistent storage, boot guards, host-only credentials and journals follow [the jail design](jails.md). Global locking serializes provision/recovery/remove/backup/restore. Native application secrets are protected; runtime JSON contains only public settings.
- Apache's filesystem-mapped FPM handler requires normal `cgi.fix_pathinfo=1`
  behavior for DAV/OCS path suffixes. Legacy mode substituted rewritten
  `PATH_TRANSLATED` (for example `redirect:/index.php/...`) as the script and
  failed with403 despite successful login/status checks. The pool retains
  `security.limit_extensions=.php`; private/non-script paths must remain denied.
- Connector install/import use the NC35 public `OCP\Util::needUpgrade()` guard,
  as in the [tagged native console](https://github.com/nextcloud/server/blob/v35.0.1/lib/private/Console/Application.php).
  Native inspection on 2026-10-15 confirmed that the old `OC\Util` class no longer
  exists; using it failed before connector download. Archive/tree authentication,
  version pinning, sensitive JWT import and upgrade refusal remain required.
- Default removal retains app datasets; purge destroys app datasets/snapshots only after `PURGE NAME`. Host credentials, backups, audit state and reserved names remain. Shared resources are retained after the last removal.

## FreeBSD integration checklist

Apply the canonical [testing boundaries](testing-boundaries.md): gates cover each recipe's affected configuration, command effects, isolation and saved-data continuity. Select representative cases per distinct owned branch, not a cross-product of upstream features. Mixed-instance PF and direct/external-proxy branches remain required where affected. Reuse compatible retained evidence; historical results do not establish an unrun recipe. Broad format/font fidelity and concurrent co-editing are optional workload qualification.

Run affected cases only on an explicitly approved disposable FreeBSD 15.1 system
with console access and a recoverable baseline. Include a second client outside
the host, a management source, an untrusted source and an external proxy. Record
each case as not run/pass/fail, artifact hash, actual package versions, topology
and observations. Keep credentials/private logs out of reports. The full matrix
below has not passed. The two-jail commands below apply to native ONLYOFFICE;
never pass a VM identity to Bastille or require an office jail for `none`.

### Deployment and mixed-TLS matrix

| Case | Required setup/result |
| --- | --- |
| First instance | Clean host, direct ACME TLS with real HTTP-01 reachability; complete install, then browser/reboot/renewal checks |
| Additional direct TLS | Separate assigned host IPv4, provided certificate, custom short/FQDN jail hostnames; test normal and private-CA trust |
| External proxy on same host IPv4 | Unused HTTP backend port (for example 8080), explicit proxy `/32`, public HTTPS hostname with non-default public port |
| Public IPv6 at proxy | A/AAAA or IPv6-only frontend; proxy-to-host IPv4 works, host/jail IPv6 ingress remains denied; direct-TLS AAAA is refused |
| Mixed instances | Keep direct-TLS and external-TLS instances live together through add, cancel/rollback, resume, removal and host reboot |
| Configuration-only/artifact | Save then resume; invoke from another cwd; test reviewed archive/no target Git, plain/dialog modes and cancellation without accepting defaults |

1. Record `freebsd-version -u`, `freebsd-version -r`, `uname -m`, ZFS health/capacity, physical RAM and IPv4 route/DNS. Update/boot the host separately. Review schema-2 plans and [storage/network layout](jails.md).
2. Exercise bootstrap consent, menu/configuration, `APPLY`, numbered progress, and a second SSH session before `KEEP`. Only host prerequisites/Bastille belong on the host; application services belong in their jails. Reject duplicate ports on one address, overlapping private blocks/bridges, conflicting public/jail hostnames, foreign datasets and excessive aggregate budgets. Verify host reserve is counted once.
3. Inspect `bastille list`, ZFS ownership/properties, real host/jail mounts, nested log mount order, quota headroom, shared Bastille and per-instance application paths. Every private bridge must lack an uplink member. Inspect per-instance journals, shared active transaction and root-private modes. Confirm no generated `secrets.json` bundle or credential-bearing runtime JSON appears in payloads, logs, argv or diagnostics; necessary native DB/JWT configuration remains protected.
4. Verify both OS hostname views separately from the Bastille IDs, and verify that certificates/URLs still use the public hostname:
   ```sh
   jls -j cloudnc jid name path host.hostname
   jls -j cloudoo jid name path host.hostname
   bastille cmd cloudnc hostname
   bastille cmd cloudoo hostname
   sh install.sh verify cloud
   sh install.sh --verify team2
   ```
   Establish running jail identity before manual `bastille cmd`; Bastille 1.4.4 can report success after skipping a stopped jail. Substitute your actual IDs.

### Services and public applications

With both jail identities checked, use focused diagnostics as needed:

```sh
bastille cmd cloudnc php -v
bastille cmd cloudnc php -m
bastille cmd cloudnc apachectl configtest
bastille cmd cloudnc php-fpm -t
bastille cmd cloudnc mariadb -Nse 'SELECT VERSION(), @@innodb_flush_log_at_trx_commit, @@innodb_doublewrite'
bastille cmd cloudnc mdo -u www redis-cli -s /var/run/redis/private/nextcloud.sock ping
bastille cmd cloudnc mdo -u www php /usr/local/www/nextcloud/occ status
bastille cmd cloudnc crontab -u www -l
bastille cmd cloudoo nginx -t
bastille cmd cloudoo supervisorctl status
```

- Record Nextcloud 35, PHP 8.5, MariaDB 12.3, ONLYOFFICE 9.4 and `ds:docservice`/`ds:metrics` status. Check service logs, FPM socket/worker counts, MariaDB durability, Redis `noeviction`/persistence-off, cron freshness and actual log rotation.
- From a real external browser, test HTTPS trust, login, upload/download, WebDAV, administration overview and share links. For the proxy case verify the configured public scheme/hostname/port survives redirects, DAV discovery, CLI-generated links and document URLs; no mixed content, double `/onlyoffice/` prefix or redirect loops.
- Send forged forwarded headers through the proxy and confirm sanitized client-IP attribution/public authority. The HTTP backend must accept only selected proxy sources plus the intended private checks/callbacks. Test large/chunked uploads against proxy, PHP and temporary-storage limits.
- Complete [office integration acceptance](onlyoffice.md#freebsd-acceptance-checks): one representative real browser edit/save/close/download/reopen through the managed WebSocket/callback path. Check authenticated private callbacks on NC **443 for direct TLS / 80 for external TLS** for the applicable branches. Use API checks for equivalent claims; healthchecks alone do not establish persistence. Compare already-seeded DOCX/XLSX/PPTX hashes/markers together after update/restore rather than repeating a browser-format matrix.
- Check [font inventory](fonts.md), actual required/custom files and generated registries. Exercise license-consent refusal where the package requires Microsoft webfonts; unavailable optional fonts must be reported accurately. Mixed scripts/math, export fidelity and pagination are optional workload qualification.
- System-notification SMTP remains disabled. Optional Mail permits only the disclosed Nextcloud public TCP 465/587/993 egress, not notification setup or arbitrary mail flows. Do not claim notification/password-reset readiness or bypass the committed-policy guard; notifications need separate policy/relay review and testing.

### Isolation, SSH and boot

From both allowed and genuinely untrusted external sources, test the chosen host-address/port combinations. Direct TLS is public only on selected application ports. External-mode HTTP is proxy-only. Host SSH and optional jail SSH are management-CIDR-only. Office TCP 8081/8000/8126, UDP 8125 and database/cache/FPM must remain inaccessible externally; NC may reach only paired office 8081, not its native backends. Test **every cross-instance NC/OO pairing** and prohibited private-network egress. DNS to the selected resolver and Internet TCP 80/443 must still work. UDP silence alone does not prove filtering: inspect PF counters or controlled capture.

For optional SSH, exercise both jails with verified host keys, key-only `cloudop` login/SFTP, denial outside the management CIDR and rejection of root/password login/forwarding. Check the unprivileged default and, in a separate selected case, explicit `doas` administrative access. Test base sh and optional zsh, with correct custom OS hostnames before/after reboot. See [SSH acceptance](ssh.md#sources-and-acceptance).

For ACME, verify the challenge path and scheduled renewal, then run inside the checked Nextcloud jail:

```sh
bastille cmd cloudnc certbot renew --dry-run --run-deploy-hooks \
  --config-dir /usr/local/etc/letsencrypt --work-dir /var/db/letsencrypt \
  --logs-dir /var/log/letsencrypt \
  --deploy-hook /usr/local/libexec/cloud-certbot-deploy
```

Confirm Apache remains available and reloads. For provided TLS, test chain/hostname/expiry/key checks, private-CA trust and operator replacement; for external TLS verify the managed backend still works after proxy renewal. A bounded controlled reboot checks persisted permissions with mixed-TLS instances and the applicable uplink configuration. Verify actual mounts, PF snapshots/bridge membership, hostname/SSH, external denial, service settings and saved-fixture continuity through native/API checks; repeat browser checks only for a changed integration seam.

On controlled failure trials, remove access to a required dataset, alter an ownership property or force a PF load/snapshot mismatch. `exec.prepare` must refuse startup before nullfs mounts, even if rc ordering permits Bastille. A bare directory must never replace missing persistent data. Restore the controlled fixture, not fabricated expected-policy markers.

### Users, database restore and full recovery

1. Use `add-user` to create **two ordinary, non-admin users** without a browser admin login. Confirm authentication, no admin membership, distinct address books/contacts and calendars/events through CardDAV/CalDAV. These fixtures detect account/data mix-ups; no additional browser groupware app is required.
2. Create known files, versions, shares and documents; retain checksums. Back up database/config, change both users' DAV/database records, restore with exact confirmation, and verify **both** users' records, permissions and application state. Confirm the pre-restore package is retained and `maintenance:data-fingerprint` ran. Validate client reconciliation.
3. Demonstrate that the SQL/config package does not contain user file contents/encryption-key files or full deployment journals. Use a separately rehearsed [coherent offline snapshot set](operations.md#coherent-offline-snapshots) for matching files/config/code/database; an unrelated later file snapshot is not valid recovery evidence.
4. Test rejected corrupt/incomplete/wrong-instance/wrong-version packages, interrupted SQL import and service-state recovery failure. After destructive failure, maintenance must remain enabled and writers stopped; the menu must not claim successful rollback or continue against a partial schema. Retry the exact journaled restore package after correcting the cause. Once its durable data-restored checkpoint exists, recovery must only finish service restoration, never reimport SQL over post-restore writes. Preserve the pre-restore package for manual recovery.
5. Restore a complete cold recovery set on an isolated disposable environment, including required keys/host state/artifact. Verify the complete owned member set and saved file/DAV/share fixtures by native/API checks, with representative office callback/save integration where affected. Measure the observed data-loss window/recovery time; do not infer RPO/RTO or physical-failure resilience from backup creation success.

### Fault-injection matrix

Use recoverable trials and authentic retained checkpoints for representative
orchestration interruptions; cover detailed write boundaries offline. Record the
expected failure, retained state and recovery outcome, and observe another ready
instance where shared policy is affected. During isolated maintenance validation,
prove ordinary ingress remains blocked while privileged checks succeed. These
checks do not establish arbitrary power-cut or dependency-internal resilience.

| Injection | Required behavior |
| --- | --- |
| First PF transition, no `KEEP` | Restore config/sysctls, disable only newly enabled PF, remove only new bridges; retain datasets/packages and SSH access |
| Add instance, no `KEEP` | Reload prior policy/active pointer, keep PF enabled and existing instance accessible; no global state flush |
| Modify/truncate on-disk PF while the committed policy is still running | Refuse a new transition; never back up the changed file as the rollback authority. Restored live rules/tables must match the preceding committed snapshots |
| Suspend interactive process; separately suspend its network worker during apply/commit | Independent supervisor terminates/reaps only its owned worker group and recovers by deadline, including a suspended lock holder; no SSH/unrelated process kill |
| Controlled reboot with a genuine unresolved network transaction | Unresolved transaction blocks new mutations; `recover-network` plus `RECOVER` uses boot identity and restores prior policy; still-active same-boot/locked transactions refuse recovery. Runtime guards also handle abruptly interrupted saved state; this test does not prove power-cut durability |
| Immediately after PF commit, before deployment journal completion | Resume reconciles committed network evidence safely; other instances retain service; no duplicate/foreign bridge adoption |
| After package installation / during an unfinished safe worker phase | Same-artifact/config resume verifies ownership and completed effects, continues safe work without resetting data or changing credentials |
| During Nextcloud table creation | Ordinary resume refuses uncertain schema. Checkpoint exists for all four app/data/DB/log datasets; explicit `recover-install` plus `RESET-INITIALIZATION NAME` restores only eligible unpublished initialization, followed by Resume |
| Initialization recovery with newer snapshot, wrong GUID/owner, complete installation or publication ever started | Refuse before destructive rollback; never force-delete newer snapshots or reset an established service |
| Failure after some initialization datasets roll back | Keep the affected jail stopped, retain recovery evidence and require deliberate continuation/manual recovery |
| Changed config, source artifact, supplied fonts or credential binding | Refuse mismatched resume; preserve state/data; do not overwrite/adopt to make it fit |
| Repository rolls forward after resolution or during interrupted package work | Refuse unavailable/changed exact locks; never substitute a newer dependency or downgrade installed packages |
| Unsupported release/architecture, PHP/DB family, native office layout or unsigned/incompatible connector | Refuse before provisioning; preserve all existing instances and data |
| Stop either jail; replace JID during wrapped execution; empty status/inventory | `verify`/operation fails, including pre/post JID mismatch; no successful stopped-jail no-op |
| Concurrent provision/backup/restore/recovery | Global operation lock serializes mutations; concurrent caller fails cleanly |
| Remove one instance, then remove/purge the last | Default keeps app datasets; purge confirmation destroys only owned app datasets/snapshots. Remove only target endpoints' PF states; other instance stays accessible. Host credentials/backups/audit/name reservations and shared resources remain |
| Cancel purge, finish ordinary removal, reuse addresses/bridges for another instance, retry the older purge | Destroy only retained target data; never kill replacement-instance states or remove its bridges |
| Remove an unmounted/missing-config jail whose identifier prefixes another jail | Refuse before any Bastille mutation/destruction; no prefix-completion fallback |

**Still unproven:** the complete native matrix, real workload capacity, full
recovery/RPO/RTO and long-running operation. Non-amd64 packages, HardenedBSD,
native host/jail IPv6 and HA/failover are outside the reviewed target. Public IPv6
at an external proxy is a separate case, not native jail IPv6. The optional
[upgrade assistant](upgrade.md) has a narrowly reviewed source/target boundary;
it does not provide arbitrary OS, jail-base or application upgrades.
