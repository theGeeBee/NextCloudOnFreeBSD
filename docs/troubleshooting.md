# Troubleshooting

Start with the symptom below. Check the browser and connection before changing
server configuration. This guide applies to installations on physical FreeBSD
hosts; QEMU and Linux workstation tooling are not deployment requirements.

| Symptom | Start here |
| --- | --- |
| Editor shows outlines/placeholders or keeps loading | [Browser and extension checks](#editor-shows-placeholders-or-keeps-loading) |
| Site cannot be reached, or only works with a forced IP | [DNS and connectivity](#site-cannot-be-reached) |
| Nextcloud loads but documents fail in every browser | [Document server checks](#documents-fail-in-every-browser) |
| Administration page reports setup/database warnings | [Administration warnings](#administration-warnings) |
| Installer refuses Resume or reports pending recovery | [Installation and recovery](#installation-and-recovery) |
| A newer Nextcloud version is available | [Update notifications](#update-notifications) |

## Editor shows placeholders or keeps loading

**Observed cause:** an operator confirmed that uBlock Origin prevented the editor
from loading in a normal Firefox session, while a private session worked. This
does not mean every uBlock installation or every loading failure has that cause;
the specific blocking filter was not identified.

1. Save any work in functioning editor tabs before reloading or closing them.
2. Try the same document and account in a private window or clean browser profile.
   Extensions may still run privately if explicitly permitted.
3. If that works, check content blockers/privacy extensions in the normal profile.
   For uBlock Origin, inspect its logger while reloading to identify blocked
   requests or CSP rules. As a diagnostic, use its site power button to temporarily
   pause filtering **only for your trusted Nextcloud site**, then reload.
4. If that resolves it, prefer a narrowly scoped exception for the responsible
   filter where possible, then re-enable other filtering and retest. A site-wide
   exception reduces protection on that site; do not disable protection globally.
5. If extensions are not responsible, try a cache-bypassing reload
   (**Ctrl+Shift+R** in Firefox). If necessary, clear stored data for this site only
   and sign in again. This logs you out and clears site-local preferences/tokens,
   potentially including plugin credentials; it does not delete server documents.

A message such as:

```text
Content-Security-Policy ... files_sharing-main.js ... default-src 'none'
```

is a diagnostic clue, not proof that DocumentServer is stopped or that the
server's CSP is wrong. Extensions can affect request/CSP handling, and a sharing
script error can be secondary to another failure. **Do not disable CSP, TLS
certificate verification or browser security to make the editor load.**

If it still fails, open developer tools (**F12**), inspect **Console** and
**Network**, enable **Disable cache** while the tools are open, and reload once.
Record the first relevant error, failed/pending resource path, HTTP status and
whether a WebSocket connection failed. Do not send cookies, authorization headers,
signed query strings or an unredacted HAR. See [reporting a problem](#reporting-a-problem).

After a fix, confirm more than the toolbar: create a disposable test document,
edit, save, close and reopen it. Never use an important document for destructive
diagnosis. A successful page load is not evidence of a successful save.

## Site cannot be reached

Replace the example hostname with your configured public hostname. From the
affected client, where curl is available:

```sh
curl -v --connect-timeout 5 --max-time 15 https://cloud.example.com/status.php
```

- HTTP200 with `installed: true`, `maintenance: false`, and `needsDbUpgrade: false`
  confirms that endpoint responded; it does not test document editing.
- Resolution to `0.0.0.0` or `::` is not the expected public destination. Check
  local overrides and DNS filtering with the network administrator. Flushing a
  client cache cannot fix a resolver that continues returning a blocked address.
- A certificate error requires checking hostname, time, certificate chain and
  TLS termination. Do not add `-k` or turn off certificate validation.
- A timeout/refusal does not identify the failing component by itself.

To separate DNS from reachability, an administrator can supply the known correct
**HTTPS frontend** address while retaining hostname/TLS verification. The IP below
is a documentation example, not an address to copy into your configuration:

```sh
curl -v --connect-timeout 5 --max-time 15 \
  --resolve cloud.example.com:443:192.0.2.10 \
  https://cloud.example.com/status.php
```

Account for any configured client proxy: it may resolve/connect elsewhere, so a
forced-address test through a proxy does not necessarily bypass DNS. Use direct
access only where network policy permits it. In external-TLS mode, test the HTTPS
frontend, not the private HTTP-only Nextcloud backend. Adjust ports if your public
URL uses a nonstandard port.

Compare results from the LAN and a genuinely external connection, such as a phone
with Wi-Fi off. Working LAN access does not prove WAN forwarding; a public-IP test
from inside the LAN may depend on router NAT loopback. Confirm current public IP,
router forwarding destination and frontend configuration before changing PF.
Packet capture can locate missing traffic, but share only sanitized headers.
Do not flush firewall rules or disable PF as a connectivity test.

## Documents fail in every browser

On the **FreeBSD host**, use the retained matching installer artifact and replace
`cloud` with the registered instance name:

```sh
sh install.sh status cloud
sh install.sh verify cloud
```

`status` is saved lifecycle state, not live health. `verify` checks the managed
jails, services and integration without upgrading or repairing them; it may run
a conversion check and refresh private inventory. Keep any reported failure for
diagnosis. A passed local check does not establish the browser/public network path.

There are three distinct ONLYOFFICE connector addresses:

- **DocumentServerUrl:** browser-visible HTTPS editor URL. Using the public
  Nextcloud hostname with `/onlyoffice/` is intentional in this architecture.
- **DocumentServerInternalUrl:** Nextcloud-to-office private frontend on TCP8081.
- **StorageUrl:** office-to-Nextcloud download/callback destination. Direct TLS
  requires the retained HTTPS hostname; external TLS uses the specifically
  configured trusted private callback transport.

Compare against the saved deployment, not guessed IPs or copied test-environment
settings. A direct-TLS callback changed to HTTP caused an observed conversion
failure even though DocumentServer's healthcheck succeeded. Correct settings only
after identifying the mismatch; keep JWT and certificate verification enabled.

See [ONLYOFFICE architecture](onlyoffice.md), [reverse-proxy configuration](reverse-proxy.md)
and the [administration checks](admin-checks.md). Do not restart both
jails as a first step: active editing sessions may contain unsaved work.

## Administration warnings

Not every notice is an installation failure. Check its version, severity and
applicability before acting:

- **Small InnoDB redo log:** check the effective `innodb_log_file_size`, not the
  similarly named log buffer or binlog limit. Live changes need a reviewed
  maintenance/resize procedure; never delete redo files.
- **Replica not running:** first establish whether replication is configured.
  The observed serverinfo7.0.0 check incorrectly alerted on a standalone MariaDB
  server. Do not start/reset replication just to clear that notice.
- **Mimetype migrations:** initial installation and published-service maintenance
  are different operations. Do not run expensive repairs automatically during
  Verify or merely set a completion flag.
- **AppAPI, 2FA, phone region and server ID:** these involve optional features,
  enrollment/security policy, locale or multi-server topology. Do not blindly
  enable services or enforce 2FA without recovery arrangements.
- **Errors in the log:** fixing a problem does not remove its historical entries.
  Check for new occurrences; do not erase logs to make the panel look clean.

Version-specific findings and current implementation limits are in
[administration checks](admin-checks.md).

## Installation and recovery

Preserve the original config, version locks, credentials, installer artifact and
private diagnostics. Do not edit journals or remove lock files to bypass a refusal.
Resume is for interrupted installation, **not** upgrades or general repair.
`recover-install` cannot reset a published service. An unresolved network
transaction needs its documented recovery workflow, not manual PF replacement.

Read [operations and recovery](operations.md) before making changes. Database/config
backup is not full disaster recovery; user files and other recovery material need
coherent coverage. Do not remove/reinstall an instance as a troubleshooting shortcut.

## Update notifications

A newer release is not automatically an approved migration target. Keep the web
updater disabled and do not run blanket package upgrades or rewrite retained
locks. Use the [current version-assessment workflow](versions.md). The
[native upgrade assistant](upgrade.md) supports reviewed transitions, not arbitrary
version changes.

## Reporting a problem

Include:

- Symptom, approximate time/timezone, steps to reproduce and expected behaviour.
- Browser/version, whether private mode works, and relevant extensions/filters.
- Application/connector versions, TLS mode, and whether LAN/external access differ.
- Sanitized `status`/`verify` failure, Console error and resource **path/status**.
- Whether a disposable document can load, edit, save and reopen independently.

Never publish passwords, JWTs, session cookies, private keys, recovery codes,
`secrets.json`, full application config, unredacted HAR files or raw private logs.
Review verbose curl output too: response headers may contain cookies. Strip
queries/tokens, personal filenames and document content from reports/screenshots.
