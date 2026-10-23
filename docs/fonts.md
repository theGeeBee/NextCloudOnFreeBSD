# Fonts for native ONLYOFFICE

The default `font_profile` is **`comprehensive`**: a broad, open-license collection for office documents, publishing, code, mathematics and multilingual text. `standard` installs the required core families only. The package policy is [`resources/packages/fonts.txt`](../resources/packages/fonts.txt), using **FreeBSD package names**, which sometimes differ from port directory names.

There is no finite installable set of “all fonts.” Commercial fonts, fonts absent from FreeBSD packages, new upstream releases and unsupported font features are outside this collection. Installed fonts also do not guarantee that every document preserves its original pagination or every Unicode character renders correctly.

## Coverage and footprint

| Collection | Examples and purpose |
| --- | --- |
| Required core | DejaVu; Liberation Sans/Serif/Mono; Arimo/Cousine/Tinos (`croscorefonts`); Caladea; Carlito; GNU FreeFont; Noto Sans/Serif/Mono (`noto-basic`) |
| Broad document families | `google-fonts`, Alegreya, Lato, Montserrat, Open Sans, Roboto, Source Sans/Serif, Clear Sans, IBM Plex, Ubuntu, Libertinus, Linux Libertine, URW Base35, Gentium, Charis and Andika |
| Multilingual | Noto extra scripts; regional Chinese (simplified, traditional and Hong Kong), Japanese and Korean sans/serif collections; Arabic, Hebrew, Indic and Southeast Asian families; SIL, Lohit, Padauk, Thai TLWG, Vazirmatn, Hanazono and WenQuanYi |
| Symbols and technical text | Noto symbols/music/math/emoji, GNU Unifont OTF, STIX, TeX Gyre math, JuliaMono, Source Code Pro, Fira Code, JetBrains Mono, Cascadia Code, Intel One Mono and other monospace families |

Caladea/Carlito and Liberation/Croscore provide useful substitutes for common Microsoft document fonts; they are not the proprietary originals. The FreeBSD `google-fonts` collection is a dated packaged snapshot, not every current font on Google Fonts. Noto metapackages install their script-specific dependencies.

On **2026-10-14**, the official **FreeBSD:15:amd64/latest** catalog contained **all 84 entries** in this policy (7 required and 77 optional). Their dependency closure contained 151 packages, approximately **4.22 GiB installed / 2.02 GiB downloaded**, excluding ONLYOFFICE itself, generated font previews/registries, the package cache and custom fonts. Budget additional disk space and allow time for indexing; these figures change with repository builds.

On **2026-10-18**, native pkg 2.8.4 in the running standard-profile ONLYOFFICE jail
simulated adding the 77 optional entries using `pkg install -n -U -r FreeBSD-ports`
with those package names. Its existing catalog resolved **124 new packages,
2 GiB download and 4 GiB additional installed space** (pkg-rounded totals), with
no proposed upgrades/removals. This is the incremental comprehensive-profile cost
on that VM, not the complete fresh-install dependency size above. No catalog
refresh, package download or installation occurred. Keep comprehensive optional
and default-selected; show resolved costs before installation consent.

A further one-off native **pkg 2.8.4** query on 2026-10-18 measured the raw
installed-size difference from one isolated signed FreeBSD:15:amd64/latest catalog.
Using `pkg rquery` `%sb` bytes and validated selected dependency closures, the
comprehensive-minus-standard difference was **4,320,889,146 bytes (4.024 GiB)**,
124 additional packages after excluding the common Document Server baseline.
Rounded to nearest GiB, the static menu label is **~+4 GiB installed vs standard**;
Standard is labeled **baseline**, not zero total disk use. The installer performs
no size query/calculation for this label. Package caches/generated outputs and
physical ZFS allocation are not this measurement.

The host resolver rechecks the selected `FreeBSD-ports` branch (`latest` or `quarterly`). It collects available packages before a dependency dry run, fails if a required package is absent, and explicitly reports unavailable optional packages. It locks exact catalog versions and the full dependency closure, shared with application/optional SSH selection. Workers recheck these locks and suppress automatic catalog refresh between preflight and installation. No host font packages or Python libraries are installed by this worker. See [version management](versions.md).

Required package versions in the reviewed catalog:

| Package | Version |
| --- | --- |
| `dejavu` | `2.37_4` |
| `liberation-fonts-ttf` | `2.1.5,2` |
| `croscorefonts` | `1.31.0_2` |
| `crosextrafonts-caladea` | `20130214_4` |
| `crosextrafonts-carlito` | `20130920_4` |
| `freefont-ttf` | `20120503_2` |
| `noto-basic` | `2.0_4` |

## Microsoft fonts require explicit consent

The selected open-license profile does **not** include `webfonts`. However, the reviewed official `onlyoffice-documentserver-9.4.0_4` package itself has a mandatory dependency on **`webfonts-0.30_15`**. That port uses a restrictive Microsoft core-font EULA, including redistribution restrictions; its `auto-accept` ports metadata is not operator consent.

The worker checks that dependency **before application/font installation** and refuses it unless the host public configuration supplies **`accept_microsoft_fonts: true`** after the operator has reviewed and accepted the applicable EULA. The flag defaults to false. Both font profiles require this consent when using the reviewed official ONLYOFFICE package. The installer neither bypasses dependencies nor silently treats those fonts as open-license. Review the [port license information](https://github.com/freebsd/freebsd-ports/blob/main/x11-fonts/webfonts/Makefile) and [Microsoft core-font EULA](https://corefonts.sourceforge.net/eula.htm).

The open-license packages have their own terms: primarily SIL OFL, Apache, MIT/BSD and font-specific permissive licenses, with GPL/AGPL and font-embedding exceptions where provided upstream. “Open-license” does not mean public domain. Retain their packaged license notices. A supplied commercial font requires appropriate rights for server use and document embedding.

## Additional TTF, OTF and TTC fonts

Set the host's `additional_fonts_dir` to a directory containing the font files. The host stages them into `/root/cloud-installer/fonts` in the ONLYOFFICE jail and sets public `runtime.json` field `additional_fonts` to true (a public absolute directory path is also accepted as an enabled indication). The worker always reads the fixed staged directory, never an arbitrary runtime-selected source path.

The same field is available in a [JSON recipe](configuration.md),
for example `"additional_fonts_dir": "/root/install-fonts"`. Supply the licensed
files at that absolute path on each destination host. The recipe carries the path,
not font contents or download URLs; existing validation/indexing is unchanged.

Only regular, non-executable **`.ttf`, `.otf` and `.ttc`** files are accepted, case-insensitively. The worker checks TrueType/OpenType/collection signatures and table-directory boundaries. Symlinks, special files, executables, control characters in paths, malformed headers and unrelated files are rejected. Keep license/readme files separately from this input directory. Header validation is not a full font-engine correctness check.

Accepted files are copied atomically into **`/usr/local/share/fonts/cloud-custom`**, retaining subdirectories, with directories `0755` and files `0644`. Inputs remain private in the payload. An existing unowned destination is refused. The worker saves the input names, sizes and SHA256 digests before copying; an interrupted copy can resume only with the same inputs.

ONLYOFFICE's upstream documentation additionally lists TTE, OTC and WOFF/WOFF2 support. This installer deliberately limits **operator-supplied** input to the three checked formats above. Packaged/system font inventories can contain the broader supported formats. Variable fonts, color emoji, shaping and font substitution are optional workload qualification in representative documents, not installer acceptance gates.

## Generation, inventory and resume

Inside the jail, the worker installs `onlyoffice-documentserver`, `python3`, `fontconfig` and the selected fonts through the scoped repository. After checking the reviewed native layout it:

1. Preserves the original package configuration once, then generates secure-link settings with restarts suppressed. A matching previously generated frontend/backend secret is reused on resume.
2. Validates/copies custom fonts, runs `fc-cache -f`, and runs the FreeBSD port's `documentserver-generate-allfonts.sh true` and `documentserver-flush-cache.sh --restart false`. The wrappers run under `sh -e` to surface failed native generators. The `true` argument suppresses the font wrapper's obsolete converter-restart branch.
3. Requires the core families in both fontconfig and the generated ONLYOFFICE `AllFonts.js` registries, plus a nonempty conversion selection file.
4. Renders protected service configuration using the JWT streamed on stdin, then starts and checks the two native Supervisor processes and nginx.

The port patches the engine's system-font search to include `/usr/local/share/fonts`. Its generator also includes the existing `/usr/local/www/onlyoffice/documentserver/core-fonts` and `/usr/local/www/onlyoffice/Data/custom-fonts` paths; the installer preserves those paths and the persistent Data mount.

Private jail state is **`/var/db/cloud-installer-onlyoffice`** (`0700`):

- `packages-plan`, `packages.installed`: selected package versions/origins and the complete installed package inventory.
- `fonts-unavailable`: optional packages absent from the chosen repository.
- `custom-fonts.json`: supplied-file paths, sizes and SHA256 digests.
- `fontconfig.tsv`: discovered family/style/file records.
- `fonts.json`: font paths, sizes, SHA256 digests, available fontconfig family/style metadata, package versions, optional absences and generated registry hashes. A file entry without fontconfig metadata is a discovered font file, not proof of editor support.
- `backups/`, per-attempt private diagnostics and ordered completion markers: retained original configuration and resume evidence.

The state fingerprint binds the public runtime, worker/rendering code, font policy and optional CA bundle. Resume refuses changed inputs and unowned deployments. Rendering uses a fresh private staging directory on each attempt; failures remove it, and a retry removes an owned staging directory left by an untrappable interruption. The installed `local.json` is the necessary application credential store (`root:onlyoffice`, `0640`); no complete credentials bundle or JWT-bearing runtime file is written in the jail. State retains only a SHA256 binding of the high-entropy JWT, not a second plaintext credential.

A completed worker run verifies package versions, font contents/registries, configuration, JWT and service health without reinstalling, regenerating or restarting. Adding fonts or changing the profile after completion is a maintenance operation, not a matching resume. Preserve the original payload/state until the host operation is complete.

## Evidence and acceptance

Sources inspected on **2026-10-14**:

- [Official FreeBSD 15 amd64 latest package catalog](https://pkg.freebsd.org/FreeBSD:15:amd64/latest/packagesite.pkg): actual package names, versions, dependency graph, licenses and sizes.
- [FreeBSD font ports](https://github.com/freebsd/freebsd-ports/tree/main/x11-fonts), especially [Google collection](https://github.com/freebsd/freebsd-ports/blob/main/x11-fonts/google-fonts/Makefile), [Noto collection](https://github.com/freebsd/freebsd-ports/blob/main/x11-fonts/noto/Makefile), [Noto extra scripts](https://github.com/freebsd/freebsd-ports/blob/main/x11-fonts/noto-extra/Makefile), [Caladea](https://github.com/freebsd/freebsd-ports/blob/main/x11-fonts/crosextrafonts-caladea-ttf/Makefile), [Carlito](https://github.com/freebsd/freebsd-ports/blob/main/x11-fonts/crosextrafonts-carlito-ttf/Makefile) and [STIX](https://github.com/freebsd/freebsd-ports/blob/main/x11-fonts/stix-fonts/Makefile): package-name differences and license terms.
- [ONLYOFFICE port dependencies](https://github.com/freebsd/freebsd-ports/blob/main/www/onlyoffice-documentserver/Makefile), [FreeBSD font-engine search paths](https://github.com/freebsd/freebsd-ports/blob/main/www/onlyoffice-documentserver/files/patch-core_DesktopEditor_fontengine_ApplicationFonts.cpp), [font-helper patch](https://github.com/freebsd/freebsd-ports/blob/main/www/onlyoffice-documentserver/files/patch-document-server-package_common_documentserver_bin_documentserver-generate-allfonts.sh.m4), and [upstream 9.4 font helper](https://github.com/ONLYOFFICE/document-server-package/blob/v9.4.0.129/common/documentserver/bin/documentserver-generate-allfonts.sh.m4).
- [ONLYOFFICE supported font types and font installation](https://helpcenter.onlyoffice.com/docs/installation/docs-community-install-fonts-linux.aspx): supported formats, generation and substitution behavior. Its Linux paths are adapted using the FreeBSD port evidence above.

Offline tests cover rendering, stdin credential boundaries, interrupted staging/copy recovery, unchanged-input verification and malformed/custom font rejection. Under the [testing boundaries](testing-boundaries.md), native gates verify selected package/custom-file inventories, hashes, required families, generated registries and helper effects on an approved disposable FreeBSD host. Retain exact results; these requirements do not claim a new native PASS. Use a representative document only where it tests changed font deployment integration. Broad DOCX/XLSX/PPTX rendering, mixed scripts, math, PDF fidelity and pagination are optional workload qualification; a successful healthcheck or inventory alone does not establish font fidelity.
