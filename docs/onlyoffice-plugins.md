# ONLYOFFICE plugin inventory

Inspected 2026-10-15 against the native FreeBSD package
`onlyoffice-documentserver-9.4.0_4` (Docs build 129). This is an inventory and
upstream review, not a claim that third-party integrations have been configured
or functionally tested. Full acceptance remains incomplete; focused plugin results
are recorded below.

## Baseline package contents before requested additions

Before additions, `/usr/local/www/onlyoffice/documentserver/sdkjs-plugins/` contained
only `marketplace/`, `v1/`, `plugin-list-default.json`, `pluginBase.js` and
`plugins.css`. The only installed standalone plugin configuration is
`marketplace/config.json`: **Plugin Manager**,
`asc.{AA2EA9B6-9EC2-415F-9762-634EE8D9A95E}`.

The default list names `ai`, `highlightcode`, `mendeley`, `ocr`, `photoeditor`,
`speech`, `speechrecognition`, `thesaurus`, `translator`, `youtube`, `zotero`.
**A name in that list is not an installed plugin.** None of those plugin directories
was present at inspection before installer-selected plugin additions.
The native package inventory agrees with the FreeBSD port packing list.
The native HTTP `/plugins.json` discovery endpoint independently returned only
the Marketplace configuration and an empty `autostart` list.

## Comparison with the upstream wiki

| Wiki entry | Baseline package state | Inclusion notes |
| --- | --- | --- |
| Highlight code | Not installed | Separate syntax-highlighting plugin |
| Macros | Integrated editor feature | Native MacrosDialog assets; do not install obsolete standalone plugin |
| Mendeley | Not installed | External bibliography service; account/application authorization |
| OCR | Not installed | Tesseract.js; review runtime/language downloads, not an offline guarantee |
| Photo editor | Not installed | Browser image editing; review third-party asset loading |
| Speech | Not installed | Web Speech API; voices/privacy depend on browser/OS/provider |
| Thesaurus | Not installed | External Big Huge Thesaurus service |
| Translator | Not installed | Selected text sent to Google Translate when used |
| YouTube | Not installed | External YouTube player/content |
| Zotero | Not installed | External Zotero library/authorization; current manifest requires Docs >=9.3 |
| EasyBib (Workspace list) | Not installed; upstream says nonfunctional | Citation API discontinued; installation cannot restore functionality |
| WordPress (Workspace list) | Not installed | External publishing/application authorization; not a bundled WordPress server |

AI and Speech Recognition are in this package's default list but not in the
wiki list. They are not implicitly selected by the standard plugin profile.

## Installer selection and privacy

The installer offers the 10 installable wiki plugins, excluding nonfunctional
EasyBib, with individual/all/none selections. Macros remains
built in. New wizard configurations default to the nine standard Docs plugins;
WordPress stays optional. Existing saved choices, including none, are preserved.
The initial inventory was read-only. The subsequent focused test installed all
10 and exercised Highlight code on a dedicated test document; no external account
was authorized and no publishing was performed. No firewall/TLS/CSP policy changed.

Implementation must use reviewed, pinned plugin artifacts and hashes rather than
mutable marketplace updates on every resume. Keep credentials out of public
runtime settings, avoid plugin autostart, preserve native authentication/TLS,
and distinguish installed/UI-visible plugins from functional external-service
tests. Use local test documents for those checks. Server PF does not govern
external requests made directly by a user's browser.

**WordPress privacy:** current source sends OAuth client secrets/tokens and
publishing requests through `plugins-services.onlyoffice.com/proxy` to WordPress.com.
Browser localStorage is used for some credentials in WordPress, Mendeley, Zotero
and Thesaurus. Installing a plugin is not approval to enter shared credentials or
publish any document. Account setup and external-service functional tests remain
separate and must use explicit user authorization.

## Evidence

- [Upstream wiki](https://github.com/ONLYOFFICE/DocumentServer/wiki/Plugins)
- [FreeBSD port](https://github.com/freebsd/freebsd-ports/tree/main/www/onlyoffice-documentserver):
  Makefile pins plugin SDK assets to `b26d001664d771df4f663d2d3ba7dd4a188b6cab`;
  `pkg-plist` lists Plugin Manager and the default list, not the individual add-ons.
- [Tagged Docs build logic](https://github.com/ONLYOFFICE/build_tools/blob/v9.4.0.129/scripts/deploy_server.py):
  generates a default list when plugins are not preinstalled.
- [Tagged Debian post-install logic](https://github.com/ONLYOFFICE/document-server-package/blob/v9.4.0.129/deb/template/postinst.m4):
  separately invokes pluginsmanager when enabled; this hook does not establish
  that FreeBSD installs those plugins.
- [Tagged native plugin-manager CLI](https://github.com/ONLYOFFICE/core/blob/v9.4.0.129/DesktopEditor/pluginsmanager/help.h):
  supports local `.plugin`/`.zip` artifacts; review native wrapper before use.
- [Plugin repository](https://github.com/ONLYOFFICE/onlyoffice.github.io/tree/master/sdkjs-plugins/content)
  and [EasyBib discontinuation notice](https://github.com/ONLYOFFICE/onlyoffice.github.io/blob/master/sdkjs-plugins/content/easybib/README.md).

Upstream `main`/`master` links are dated discovery evidence, not immutable plugin
locks or compatibility guarantees. The reviewed runtime lock is described below.

## Pinned payloads and native results — 2026-10-15

`resources/plugins/onlyoffice.json` pins official source commit
`f3263c055c25875874004463b46c2e6a7000a9fd` (2026-10-13), with sizes and SHA256 for
704 runtime/license files, totaling 32,421,775 bytes. Nine published `.plugin`
archives differ from the corresponding current source; Zotero has no archive at
this revision. All ten therefore use reviewed per-file payloads, including
upstream notices and dependency licenses. No npm build or arbitrary plugin
installer script is executed. Operators do not resolve mutable marketplace versions.

| Plugin | Pinned version | Native install / discovery / browser toolbar |
| --- | --- | --- |
| Highlight code | 1.0.3 | PASS |
| Mendeley | 1.0.4 | PASS |
| OCR | 2.1.1 | PASS |
| Photo editor | 1.0.4 | PASS |
| Speech | 2.0.2 | PASS |
| Thesaurus | 1.0.3 | PASS |
| Translator | 1.0.8 | PASS |
| WordPress | 1.0.2 | PASS |
| YouTube | 1.0.5 | PASS |
| Zotero | 1.1.0 | PASS |

Native install/verify/install/verify passed, demonstrating idempotent replay.
`/plugins.json` advertises all ten plus Plugin Manager with **empty autostart**.
Firefox visibly displayed all ten toolbar entries. Highlight code loaded its
SDK/UI, inserted test code, saved and closed; an independent verified-HTTPS DAV
download contained the exact insertion and original text. A fresh Firefox profile
reopened the document and visually confirmed both texts. This is not a claim
that every external service or browser speech provider works.

The plugins still reference external SDK,
CDN and service resources: pinned local files do **not** imply offline operation
or immutable remote JavaScript. No upstream plugin source was rewritten.

The focused native trial used separate diagnostic staging on a completed
deployment. Its immutable installer/config/version locks were not rewritten.
**A fresh end-to-end installation using the new plugin-selection artifact has
not been run.** The completed baseline's public Verify does not validate these
diagnostic additions; plugin receipt/hash verification is a separate check.

## Installation and verification behavior

Before provisioning, the host retains an immutable selected `plugins.json`,
downloads only those files into private `plugin-artifacts/`, and validates their
hashes and manifests against the reviewed Docs version. The lock and selected
public bytes are staged only in the office jail. A conditional journal phase
publishes root-owned static plugin directories with receipt-backed recovery;
foreign directories, symlinks, changed bytes or locks are refused rather than
adopted or silently overwritten. Verify is read-only and never downloads.

When plugins are selected, the office worker changes only the package's static
`documentserver` parent directory from service-account ownership to root ownership
after helpers finish, retaining mode0755 and the service group. This prevents
the service account from replacing the verified plugin directory. Generated
files, caches and application data are not recursively chowned. The native
focused trial verified this ownership before installing the plugins.

## Installer configuration

The wizard's document fonts/plugins section provides **Standard Docs (9)**, **None**, **All 10**, or
**Choose individual plugins**. The individual menu toggles entries and supports
select-all/select-none/done in both plain and dialog modes. Standard Docs is the new-install default;
existing choices are preserved when reviewing a configuration.

For static JSON planning, `onlyoffice_plugins` is a canonical alphabetical,
comma-separated string. For example:

```json
"onlyoffice_plugins": "highlightcode,ocr,photoeditor"
```

The full selection is
`highlightcode,mendeley,ocr,photoeditor,speech,thesaurus,translator,wordpress,youtube,zotero`.
Unknown names, duplicates and noncanonical ordering are rejected. An omitted or
empty value selects none and keeps legacy schema-2 serialization/digests readable.
The standard new-install selection is
`highlightcode,mendeley,ocr,photoeditor,speech,thesaurus,translator,youtube,zotero`.
Macros is already integrated; EasyBib is discontinued. Installation does not
enable autostart or authorize external service accounts.
Static planning does not download plugins, probe the host or write state.

Selection belongs to the immutable initial instance configuration, not a mutable
marketplace subscription. Resume must not acquire a different plugin selection
or rewrite a completed instance's original config/source locks. No post-install
plugin-update/reconfiguration command is currently provided.
