# Native ONLYOFFICE Docs in a dedicated VNET jail

The single **`sh install.sh`** workflow provisions **`www/onlyoffice-documentserver` 9.4.x Community Edition** in a dedicated thick Bastille VNET jail for each Nextcloud 35 instance. Native FreeBSD binaries are used. All installation, resume, verification and removal operations belong to that host workflow.

Bounded native installation and browser checks are not complete production or
recovery acceptance; see [validation limits](verification.md). Isolation,
multi-instance recovery and workload qualification remain important. Community
Edition's license and concurrent-editing limits still apply; installing it does
not provide Enterprise support, high availability or unlimited editing capacity.

## Topology and exposure

For the wiki plugin comparison and actual FreeBSD package inventory, see
[ONLYOFFICE plugins](onlyoffice-plugins.md). A default-plugin name list does not
mean the corresponding plugin payloads are installed.

```text
Direct TLS:   Browser -> host PF -> Nextcloud jail Apache HTTPS:443
External TLS: Browser -> HTTPS proxy -> host PF -> Nextcloud Apache HTTP:80
                                           /onlyoffice/ -> office nginx:8081
                                                           -> DocService:8000

Nextcloud connector -> http://<office-private-ip>:8081/
Direct callback:   DocService -> https://<public-hostname>/ on private NC:443
External callback: DocService -> http://<nextcloud-private-ip>/ on NC:80
```

The two jails occupy separate private `/30` bridges. Host PF permits **NC -> OO TCP 8081** and **OO -> NC TCP 443** for direct TLS, or **80** for external TLS. It supplies no public redirect to the office service. Other instances remain isolated. Direct-TLS internal hostname resolution uses the private NC address while preserving certificate hostname validation; custom jail OS hostnames do not redefine that certificate identity. See [network policy](jails.md#network-policy).

With an [external HTTPS proxy](reverse-proxy.md), the browser URL remains `https://<public-hostname>[:public-port]/onlyoffice/`, while callbacks use the private NC HTTP URL. Restrict the proxy's HTTP backend to selected IPv4 CIDRs over a trusted private LAN/VPN. The edge must preserve WebSockets and sanitize forwarded headers; it must not duplicate Apache's `/onlyoffice` virtual-path prefix.

The native DocService calls `listen(port)` without a bind address; TCP **8000** may listen on all jail interfaces. Metrics uses UDP **8125** and TCP **8126**. These backends must stay inaccessible to untrusted clients and the Nextcloud jail. nginx intentionally listens on the office jail's private IP at **8081**, reachable only through the approved PF paths.

VNET provides a real loopback interface for vendor localhost upstreams. Historical shared-IP jail behavior can rewrite a loopback bind to the primary jail address; that topology is outside this design. Verify actual listeners and external filtering rather than treating a bind string as a firewall audit.

Apache exposes only the `/onlyoffice/` virtual path with the required forwarding headers and WebSocket support. Public `/internal`, `/info`, `/admin` and `/example` paths, including version-prefixed variants, are denied. The nginx internal/info locations also lose their loopback exception, so reverse-proxied requests cannot inherit local administrative access.

### Reserved Nextcloud callback capacity

Synchronous connector previews occupy a PHP worker while DocService fetches the
source file back from Nextcloud. A single saturated FPM pool can block its own
callbacks. The existing PHP worker allowance is split between ordinary requests
and a reserved `office_callback` pool: one callback worker for a total of three,
two for larger totals. New deployments require at least three workers so ordinary
HTTP self-checks also retain two web slots. Old two-worker schema-2 state remains
readable for inspection/lifecycle handling, not silently enlarged or re-provisioned.
The default three-worker allowance becomes two
ordinary plus one callback worker; memory limits and the total ceiling do not
increase. Database sizing continues to use the total allowance.

Both pools use protected Unix sockets, `clear_env = yes` and the same PHP-only
filesystem-mapped handler. In both TLS modes Apache selects the callback socket
only when `CONN_REMOTE_ADDR` is the paired office jail's private address. Neither
forwarded headers nor the requested URL can select it. No new network listener,
firewall exception, preview disabling or certificate-verification bypass is used.
This prevents the observed worker-starvation cycle, not all possible application
locks or capacity exhaustion; saturation and browser persistence still need tests.

A bounded native diagnostic exercised three concurrent DOCX previews plus a
status request. Pool tracing confirmed the real office peer used the reserved
pool while forged forwarded headers from a different peer did not. A representative
edit/save/download/reopen also passed; those checks do not establish mixed-TLS
acceptance or workload capacity.

## Reviewed 9.4 package behavior

Supervisor runs **`ds:docservice` and `ds:metrics`** as `onlyoffice:onlyoffice`. Community 9.4 embeds conversion in DocService and uses memory state. **Do not configure a separate SQL database, RabbitMQ, Redis or `ds:converter` service for ONLYOFFICE.** MariaDB and Redis belong to the Nextcloud jail.

Important native paths:

| Path | Purpose |
| --- | --- |
| `/usr/local/etc/onlyoffice/documentserver/local.json` | Local JWT/request/TLS/storage overrides |
| `/usr/local/etc/onlyoffice/documentserver/nginx/` | Vendor nginx frontend and static/cache/WebSocket includes |
| `/usr/local/etc/onlyoffice/documentserver/supervisor/` | Native `ds` group and two process definitions |
| `/usr/local/www/onlyoffice/documentserver/server/` | Native DocService, metrics and embedded conversion binaries |
| `/var/db/onlyoffice` | Persistent runtime/cache working area |
| `/usr/local/www/onlyoffice/Data` | Persistent document service data |
| `/var/log/onlyoffice/documentserver/` | Document/metrics/nginx logs on the office log dataset |

`resources/jails/onlyoffice.sh` runs inside the office jail after host storage/PF setup. It checks ownership and matching public inputs for new/resumed work, consumes the host's [resolved version/dependency lock](versions.md), rechecks the selected signed **FreeBSD-ports** records and rejects unexpected native layouts. nginx and Supervisor come from the package dependency closure. Fonts use the reviewed [package policy and inventory](fonts.md); no blanket package or host OS upgrade is performed. Discovery of upstream 10.0 does not authorize that unreviewed native layout.

Before starting services, the worker runs the FreeBSD-patched secure-link, font and cache helpers with restarts suppressed. The secure-link helper uses inherited `RESTART_CONDITION=false` rather than its broken argument parser: the installed9.4.0_4 script inspected on2026-10-15 does not advance arguments in its loop (earlier source review observed a double-shift variant). Secure-link generation runs **before** merging `local.json`, since that helper replaces `storage`. All active secret directives must agree with the backend, including all three server blocks in the native TLS template. Font generation skips the obsolete converter restart. `installer/office.py` preserves the generated secret and reviewed vendor includes, configures the private frontend and bounded service logs, then the worker validates nginx and starts Supervisor/nginx.

The comprehensive font profile is broad licensed package coverage, dynamically resolved against the selected repository, not literally every font. Additional operator-owned TTF/OTF/TTC files require suitable server-use/embedding rights. The reviewed document-server package itself depends on Microsoft `webfonts`, requiring the explicit license-consent handling described in [fonts](fonts.md#microsoft-fonts-require-explicit-consent). Rendering, pagination and export fidelity are optional workload qualification; package inventory does not guarantee them.

The installed cache-flush helper has the same non-advancing argument loop. It
also receives `RESTART_CONDITION=false` with **no command-line arguments**. Native
testing exposed a busy loop when passing `--restart false`; terminating only the
verified owned helper allowed the installer to retain state and stop both jails.

Optional editor plugins are not downloaded automatically. Review the port's plugin-manager instructions separately if plugins are required.

## JWT, callback TLS and state

After signed connector installation and sensitive configuration import, finish
restarts PHP-FPM before the conversion/callback check. NC35 caches app configuration
and routes in the FPM master's local APCu; CLI enable/import does not invalidate
that process's cache. Native reproduction on 2026-10-15 primed an app-disabled
HTTP404, enabled the app through `occ`, and still failed conversion until **only
PHP-FPM** was restarted. Both pools are restarted; no app/office/TLS/JWT check is
skipped. This is an installation-phase cache refresh, not a reason to restart
services during read-only verification.

Integration also waits for the native office health endpoint with the same
bounded check used by verification. Resume may skip the completed provisioning
phase while starting stopped jails; Supervisor's successful startup does not
mean DocService is ready. The subsequent conversion/JWT/callback check remains
mandatory and is not replaced by the health endpoint.

- A random JWT is shared across browser/inbox/outbox/session settings and the Nextcloud connector's `AuthorizationJWT` header. It reaches the applications over stdin to a checked, pinned `jexec` JID, never via argv, console output or a JWT-bearing `runtime.json`. Nextcloud stores the JWT as a sensitive app setting; ONLYOFFICE's native `local.json` is protected `root:onlyoffice`, `0640`.
- Connector URLs are public `https://<hostname>[:public-port]/onlyoffice/` and internal `http://<office-private-ip>:8081/`. Storage callbacks use `https://<hostname>/` on internal NC port 443 for direct TLS, or **`http://<nc-private-ip>/`** on 80 for external TLS. Public HTTPS port overrides must propagate through browser/document links, not change the private callback port.
- Certificate verification stays enabled in the connector and DocService. Direct provided private-CA certificates require the correct PEM trust bundle and `NODE_EXTRA_CA_CERTS`; never supply a private key as a CA bundle. Browsers must trust that CA too. External mode's intentional private HTTP transport does not disable verification on an HTTPS connection.
- Private-IP callbacks are deliberately enabled because Nextcloud has an RFC1918 address. Metadata-address allowance remains disabled; host PF restricts lateral/private destinations. This setting is not a substitute for filtering.
- Persistent office storage uses the `office-runtime`, `office-data` and `office-logs` datasets. Live editing state is nevertheless held in memory: close editors and confirm saved files before restarting or updating services.
- Host configuration/credentials/journal are under `/var/db/cloud-installer/instances/NAME` (`0700`, private files `0600`); the generated credential bundle never enters a jail. Jail-local `/var/db/cloud-installer-onlyoffice` retains public-input/source bindings, package/font inventories, configuration hashes and private diagnostics. Application-native JWT configuration is necessary and protected, not a copy of the host bundle.
- Resume requires the same configuration, installer source and supplied inputs. Ordered worker checkpoints allow safe incomplete work to continue; a completed office worker verifies unchanged configuration/fonts/packages instead of reinstalling. Uncertain Nextcloud schemas use the separate, restricted [initialization recovery](operations.md#initialization-recovery), not an office-data reset.

## FreeBSD acceptance checks

After installation, substitute your instance and jail IDs below. The installer checks live jail identities; before manual `bastille cmd` checks, establish both are actually running, since Bastille 1.4.4 can silently skip stopped jails:

```sh
sh install.sh verify cloud
jls -j cloudnc jid name path host.hostname
jls -j cloudoo jid name path host.hostname
bastille cmd cloudoo pkg info onlyoffice-documentserver
bastille cmd cloudoo pkg info -D onlyoffice-documentserver
bastille cmd cloudoo nginx -t
bastille cmd cloudoo service supervisord status
bastille cmd cloudoo supervisorctl status
bastille cmd cloudoo service nginx status
bastille cmd cloudoo sockstat -46l
bastille cmd cloudnc apachectl configtest
bastille cmd cloudnc mdo -u www php /usr/local/www/nextcloud/occ onlyoffice:documentserver --check
```

Apply the [testing boundaries](testing-boundaries.md). These gates prove our generated configuration and actual integration effects for the affected recipe. Select representative cases for distinct PF/proxy/callback branches; do not repeat unchanged seams across every format or user.

Also verify:

1. From the Nextcloud jail, `http://<office-private-ip>:8081/healthcheck` returns `true`; TCP 8000/8126 and UDP 8125 remain inaccessible across that boundary. Both native Supervisor processes are `RUNNING`.
2. From outside, `https://<hostname>[:public-port]/onlyoffice/healthcheck` returns `true` with a trusted certificate. Repeat through the external proxy, including its IPv6 frontend if present. Internal/info/admin/example URLs return denial, including version-prefixed forms. Direct office frontend/backend access is denied by PF; confirm UDP policy with counters/capture as necessary.
3. Use one representative document for a real browser edit/save/close/download/reopen through the configured WebSocket/callback path. A passing health endpoint or conversion check does not establish save-callback behavior. API checks may replace browser checks for equivalent claims; compare already-seeded format hashes/markers together after maintenance rather than repeating a browser-format matrix.
4. Check effective cron/database/cache settings, logs and saved file/DAV fixture continuity with ordinary accounts. Check selected [font files and generated registries](fonts.md). Concurrent co-editing, broad document corpora, mixed scripts, math, PDF fidelity, pagination and workload capacity are optional workload qualification, not installer acceptance gates.
5. Keep another instance active while installing/cancelling/removing one; its document session must remain usable. Verify inter-instance NC/office connections are denied, while each paired callback uses the configured port. Exercise the [network/resume fault matrix](freebsd-15.1.md#fault-injection-matrix).
6. Use a bounded controlled reboot to verify persisted boot/service permissions, certificate trust, external denial and saved-fixture continuity for affected direct/external-TLS branches. Repeat browser integration only where changed. During maintenance, verify ordinary ingress remains blocked while the privileged canary runs. A short backend startup delay may produce nginx 502 responses; persistent failures require investigation.

For later maintenance, reread `pkg info -D onlyoffice-documentserver`, compare changed package configuration and apply the affected gates above, reusing compatible retained evidence. Preserve `local.json` overrides, JWT, internal/info restrictions and the private nginx listener. A changed private CA requires updating the copied trust bundle and restarting DocService. The installer supplies no automatic upgrade or existing-deployment adoption workflow.

Review the actual installed Community build's license/concurrent-connection policy and the [vendor FAQ](https://helpcenter.onlyoffice.com/docs/faq.aspx) before sizing an organization. A supported commercial upgrade, migration or HA design requires a separate plan; this installer provisions the reviewed native Community package.

## Sources checked on 2026-10-14

- [FreshPorts: www/onlyoffice-documentserver](https://www.freshports.org/www/onlyoffice-documentserver/).
- [FreeBSD port Makefile](https://github.com/freebsd/freebsd-ports/blob/main/www/onlyoffice-documentserver/Makefile), [package instructions](https://github.com/freebsd/freebsd-ports/blob/main/www/onlyoffice-documentserver/files/pkg-message.in), [installed file list](https://github.com/freebsd/freebsd-ports/blob/main/www/onlyoffice-documentserver/pkg-plist), [Supervisor programs](https://github.com/freebsd/freebsd-ports/blob/main/www/onlyoffice-documentserver/files/ds-docservice.conf) and [port patches/helpers](https://github.com/freebsd/freebsd-ports/tree/main/www/onlyoffice-documentserver/files).
- Official FreeBSD 15 amd64 [latest](https://pkg.freebsd.org/FreeBSD:15:amd64/latest/packagesite.pkg) and [quarterly](https://pkg.freebsd.org/FreeBSD:15:amd64/quarterly/packagesite.pkg) catalogs contained **`onlyoffice-documentserver-9.4.0_4`** for the reviewed FreeBSD 15.1 target. Other architectures and actual installation behavior have not been tested here; the worker rechecks the live package version/layout.
- [ONLYOFFICE 9.4 changelog](https://github.com/ONLYOFFICE/DocumentServer/blob/v9.4.0/CHANGELOG.md#940), [Community runtime profile](https://github.com/ONLYOFFICE/server/blob/v9.4.0.129/Common/sources/runtime/profile.js), [configuration defaults](https://github.com/ONLYOFFICE/server/blob/v9.4.0.129/Common/config/default.json) and [DocService listener](https://github.com/ONLYOFFICE/server/blob/v9.4.0.129/DocService/sources/server.js).
- [Official Apache virtual-path proxy example](https://github.com/ONLYOFFICE/document-server-proxy/blob/master/apache/proxy-to-virtual-path.conf) and [packaged nginx restrictions](https://github.com/ONLYOFFICE/document-server-package/blob/v9.4.0.129/common/documentserver/nginx/includes/ds-docservice.conf.m4).
- [Official Nextcloud connector JWT/URL/check commands](https://github.com/ONLYOFFICE/onlyoffice-nextcloud) and [connector manifest](https://github.com/ONLYOFFICE/onlyoffice-nextcloud/blob/master/appinfo/info.xml). The reviewed **10.2.1** manifest supports NC35/PHP8.5; some Help Center prose still mentions an older connector capped at NC34. Installation uses the compatible signed app-store release without `--force`.
- [FreeBSD 15.1 jail IPv4 bind rewriting](https://github.com/freebsd/freebsd-src/blob/releng/15.1/sys/netinet/in_jail.c) and [ONLYOFFICE system requirements](https://helpcenter.onlyoffice.com/docs/installation/docs-community-sys-reqs.aspx).
