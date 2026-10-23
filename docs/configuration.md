# Repeatable installation from JSON

This is an input path to the existing installer, not a
new installation engine or a fully unattended mode.

## Workflow

```sh
cp examples/config.json settings.json
# Edit destination-specific settings before running on each host.
sh install.sh plan settings.json
sh install.sh install --config settings.json --yes --accept-licenses --accept-acme-terms
```

The example explicitly selects the nine standard Docs plugins (Macros is built
in; WordPress stays optional), comprehensive fonts, the eight Nextcloud apps and
no quotas. Edit hostname, network, pool, resource budgets and certificate/key/font
paths for each actual destination. Do not copy runtime identities or credentials.
Selected settings can be repeated; available compatible versions may differ across
installation dates. Resolution still produces the immutable per-instance lock.

`configure --config settings.json` loads through the same reader and preflight but
saves settings/credentials without provisioning. Continue with `resume INSTANCE`
using the original artifact and inputs. Consent flags belong to `install`, not to
resume, removal, recovery, restoration or upgrade.

## Familiar, explicit file semantics

- Use `--config FILE` or `--config=FILE`. Relative file paths resolve against the
  caller's working directory. Paths inside JSON remain absolute; no rebasing,
  environment substitution, automatic discovery or layered configuration.
- The file is authoritative: no wizard merge, recalculation or form fallback on
  invalid settings or failed preflight. Live host checks still validate its values.
- Use the existing schema-2 model. Omitted legacy fields keep their old semantics;
  copy the updated example to explicitly select current defaults. In particular,
  omitted/empty `onlyoffice_plugins` still means none in a manually supplied file.
  Existing installations and saved explicit empty/custom choices are not changed.
- File input must be a readable operator-owned regular file, not a final symlink,
  without group/other writes, at most 1 MiB. On the target the operator is root.
  `chmod 600 settings.json` is a suitable private mode; keep ownership appropriate.
- Duplicate JSON keys, unknown fields, malformed data and invalid settings fail
  nonzero without echoing supplied values/source lines. `plan FILE` remains the
  existing offline planner, not a live preflight or installer-state operation.

Host/platform guards still precede prerequisite bootstrap. A missing pkg/Python
may be installed with consent before Python validates the complete recipe; do not
interpret file input as a promise that invalid input can never trigger bootstrap.

## Optional version families

Fresh-install recipes may include a flat `version_families` object, for example:

```json
"version_families": {"nextcloud": "35", "php": "8.5", "database": "12.3"}
```

This is an entry in an otherwise complete recipe. Values are numeric major or
major/minor strings; use only backend-applicable role or selected-package keys.
`database` constrains client and server together. Package keys constrain packages
already selected, never enable optional ones. Omission or `{}` preserves legacy
configuration digests; nonempty maps serialize in canonical key order.

Family selections intersect minima, exact pins, hard policy and layout checks;
there is no silent cross-family fallback. The resolved exact combination is not
certified as project-validated. Existing APPLY or recipe `--yes` accepts that
warning, never bypasses validation or attended KEEP. Resume retains the original
artifact and exact lock. See [complete family semantics and defaults](versions.md#optional-fresh-install-family-selection)
and the [validation matrix](verification.md).

## Consent and fresh credentials

| Option | Exact scope |
| --- | --- |
| `--yes` | Approves missing pkg/Python bootstrap and APPLY; generates fresh private credentials and skips the post-install optional user question. |
| `--accept-licenses` | Accepts the disclosed required Microsoft webfonts EULA; does not select features or grant rights to supplied commercial fonts. |
| `--accept-acme-terms` | Accepts the separate Let's Encrypt agreement for an ACME installation. |

These flags require `install --config FILE`. `--yes` does not imply legal consent:
missing required licence/ACME consent fails clearly. Without it, existing private
password prompts and APPLY remain. `accept_microsoft_fonts: true` is also an
explicit saved consent selection. Supplied SSH administrative access still needs
its own confirmation even with `--yes`.

Passwords, JWTs and private-key contents are not JSON fields or CLI options. Only
paths to protected key files are settings. New generated credentials remain under
the protected host instance state; never distribute `secrets.json` as a recipe.
Saved `config.json` is reusable after editing identities/paths, but contains private
operational information such as email addresses and should not be published casually.

## Extra applications and fonts

### Fresh-install office selection

`office_backend` accepts exactly `onlyoffice`, `eurooffice`, `collabora`, or `none`.
Omission retains native ONLYOFFICE and historical serialized configuration hashes.
The selection is immutable; editing saved state is not a migration or a valid Resume.

The default [recipe](../examples/config.json) remains unchanged. Additional
[Nextcloud-only](../examples/nextcloud-only.json), [Euro-Office](../examples/eurooffice.json)
and [Collabora](../examples/collabora.json) examples are provided. See the
[profile guide](fresh-install-profiles.md) for support and validation limits. Shell
pkg/Python bootstrap may precede Python recipe validation, as documented above.
Static plans are not native acceptance or resource approval. `resolve`
records the policy's exact guest/container identities and signed connector metadata
without requiring a hypervisor; only selected native preflight can approve host resources.

`none` plans exactly one Nextcloud jail and one private `/30`, with no office
connector, runtime, network, fonts/plugins or callback allowance. Omit office-only
fields, including `office_memory_mb`, `onlyoffice_bridge`, `office_quota_gib`,
native font/licence/plugin fields and ONLYOFFICE version/hostname/SSH-port fields;
explicit irrelevant options are rejected. Ordinary Nextcloud app selections remain.
Administrators may later install a compatible connector and configure an external
server manually, entirely outside this installer's responsibilities. There is no
external-server URL, password field or fifth profile.

VM plans describe a dedicated Alpine/bhyve/Docker guest, **not** a second
Bastille jail. Offline planning does not acquire images or perform hypervisor
preflight. Native fonts, plugins, licence consent and office-jail hostname/SSH-port
fields are not VM options. Shared historical names `onlyoffice_bridge` and
`office_memory_mb` describe the planned office segment and total guest RAM.

VM recipes must select `office_vm_cpus` and `office_vm_disk_gib` explicitly for
execution; examples and wizard defaults use reviewed 2 vCPU/4096 MiB/16 GiB.
Omitted zero values remain readable for old offline previews, not execution
approval. These fields are omitted from legacy serialization/hashes. Native and `none` recipes reject
these VM-only fields. The finite guest disk capacity is displayed separately from
an optional `office_quota_gib` dataset cap. VM persistent storage is a single owned
`office-vm` dataset, never an office jail mount. Live preflight enforces reviewed
minimums, inspected CPU/pool capacity and guest-specific host requirements.

Office app IDs `onlyoffice`, `eurooffice`, `richdocuments`, `richdocumentscode`, and
`richdocumentscode_arm64` are reserved from installer-managed additional apps.
This provisioning restriction does not disable Nextcloud's Apps UI or prevent
later administrator-managed integrations. Historical configurations remain readable;
new provisioning must reject conflicts rather than install competing connectors.

Nextcloud-only installs do not require `--accept-licenses` (native Microsoft
webfonts), but ACME consent, optional SSH administration and attended PF KEEP are
unchanged. Generate only administrator/database credentials, with no JWT. Native
upgrade/maintenance/update/security assessment and database backup/restore remain
unsupported for this profile; use administrator-managed Nextcloud backup and
maintenance procedures. Status, read-only verify, live add-user and removal use
only the owned Nextcloud jail. Ordinary removal retains application datasets;
explicit PURGE retains its destructive confirmation. New Nextcloud-only instances
cannot be registered into an already lifecycle-enrolled host; no lifecycle format
extension or guessed native baseline is performed.

`nextcloud_apps` retains the reviewed built-in selection. Add other App Store IDs
through a distinct alphabetical, comma-separated field, for example:

```json
"additional_nextcloud_apps": "bookmarks,polls"
```

Do not repeat IDs from `nextcloud_apps`. IDs are lowercase letters/digits/underscores,
not arbitrary URLs, scripts or command options. The separately pinned `onlyoffice`
connector is not an additional-app target. Existing native `occ` compatibility and
signature checks, failure receipts and explicit recovery rules apply without force
or unstable-install flags. Selecting extras does not implicitly provision external
services or widen network policy; known Mail/antivirus selections retain their
existing disclosed egress/scanner/memory behavior.

Use `font_profile` (`standard` or `comprehensive`) and `additional_fonts_dir`, an
absolute host directory of licensed TTF/OTF/TTC files. Make those files available
on every destination; no remote font URLs or new font installer is introduced.
Existing validation, copying and native font-index generation are reused. See
[fonts](fonts.md) and [plugin selection](onlyoffice-plugins.md).

## Safety and verification

A terminal is still required. Each PF transition retains timed **KEEP after an
independent working SSH session**. No flag auto-confirms KEEP or changes timeout /
cancellation recovery. No YAML dependency, new schema, generic approval framework,
automatic rollback or broader unattended controller was added.

Offline planning validates the recipe, not the running destination. Native
preflight, installation and read-only verification remain separate steps. Bounded
profile checks do not establish additional App Store feature compatibility,
workload capacity or full recovery acceptance. See [validation limits](verification.md)
and [testing boundaries](testing-boundaries.md).
