# Independent security assessment

`check-security` is separate from compatibility and update availability. It never
installs software or authorizes a migration. No report means **unknown**, not safe.

```sh
sh install.sh check-security cloud
sh install.sh check-security --all --json
sh install.sh check-security cloud --refresh
sh install.sh check-security cloud --refresh --save-report --json
```

Cached inspection is read-only, without bootstrap or a mutation lock. Refresh is
explicit and uses bounded, verified HTTPS requests to the upstream GitHub advisory
API; redirects are refused for that provider. On FreeBSD it also uses the existing
reviewed native `pkg` to fetch VuXML and audit explicit retained package arguments
with isolated configuration, cache and database directories. Native libfetch's
redirect behavior applies to that download. No bootstrap or package installation
occurs, and no live installed-package database is queried or updated.
Saving requires both refresh and save flags, then a
short global lock and exact retained-state revalidation. Private reports and their
hash-bound normalized feeds are retained under `security-reports/NAME.json`.

## Coverage and limitations

- Nextcloud core comes from an upstream archive, not a Nextcloud package record.
  Its advisories are assessed independently of the native package inventory.
- The reviewed feed is the `nextcloud/security-advisories` repository's published
  security advisory API, matching package ecosystem `nextcloud`, name `Server`.
  The `nextcloud/server` advisory endpoint was empty during review; it is not used
  as evidence of absence of vulnerabilities.
- The inspected version is explicitly labeled **retained-intended-version**.
  This command does not claim that the live code matches its lock. Native upgrade
  preflight must separately verify observed application/runtime identities.
- Results distinguish `affected`, `no-known-advisories` and `unknown`, with
  coverage/freshness and provenance. Even a complete current feed is not a proof
  that no undisclosed vulnerabilities exist. Unknown coverage can coexist with
  known affected advisories.
- Missing, stale, incomplete, malformed or unsupported relevant ranges cannot
  produce a clean assessment. Some upstream multi-branch range strings are
  ambiguous; these remain unknown rather than being guessed from release numbers.
- Withdrawn advisories are excluded. Numeric final-version ranges use inclusive
  introduction and exclusive fixed versions, not lexicographic comparisons.
- Third-party apps, Enterprise-specific coverage and support/EOL are **not
  assessed** by this first provider. HTTPS provenance is not a signed-feed claim.
- Native `pkg audit` integration is pinned to reviewed pkg **2.8.4**. Other pkg
  versions, unavailable native execution, malformed/empty output and failed
  refresh produce unknown coverage. Audited arguments cover the retained host,
  Nextcloud and ONLYOFFICE package closures—not an observed whole-host inventory.
  An affected result legitimately exits 1; it is accepted only with matching,
  complete structured findings. A clean result requires nonempty explicit
  arguments and the exact successful result schema.
- Package evidence binds the exact arguments, VuXML digest and structured audit
  output. VuXML is HTTPS-sourced, not claimed to be cryptographically signed or
  exhaustive. Native pkg owns FreeBSD version/revision/epoch comparisons. Legacy
  schema-1 caches retain unknown package coverage; no audit is retroactively
  inferred from an old core-only report.

Refresh failures are reported as unknown, not as a successful new assessment.
Old reports become stale after 24 hours or relevant retained-state,
policy, source or lifecycle changes. Feed descriptions/configuration contents are
not printed; results expose bounded identifiers and upstream advisory links.

Compatibility, security and recovery readiness are separate decisions. A newer
release can fix a vulnerability yet still be an unsupported migration target.
Conversely, compatible packages do not establish security or support status.

Validation is offline/mocked, including transport boundaries, explicit native
command arguments, output parsing and private cache publication. Complete native
security-report/package-audit acceptance remains unestablished. Separate bounded
application upgrade and explicit snapshot-restoration checks passed; they do not
validate this assessment workflow. See the [validation matrix](verification.md).
