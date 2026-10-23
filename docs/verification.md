# Validation scope and limitations

The supported target is the release/architecture selected by
[`resources/versions.json`](../resources/versions.json). Offline tests establish
installer decisions and generated commands, not native FreeBSD operation.

## Validation matrix — October 23, 2026

**Historical accepted artifacts and the latest family-selection source are
different evidence sets.** A pass applies only to the tested artifact, recipe,
versions and topology. It is not transferred automatically to another patch or
profile. No new native validation was performed for this documentation refresh.

### Historical accepted artifacts

| Date / scope | Result | Boundary |
| --- | --- | --- |
| October 21: original native ONLYOFFICE installation, Nextcloud 35.0.1 | Verify and browser edit/save, DAV persistence and fresh reopen passed; operator accepted the visual check | Original retained installation, **not a fresh native-default installation of the latest source** |
| October 21 profile campaign: Nextcloud-only, Nextcloud 35.0.1 | Reduced Calendar/Contacts recipe installed; non-admin API/DAV and browser checks, controlled host reboot, post-reboot saved-file continuity and retained-data removal passed; operator accepted | Not every optional app or a full recovery test |
| Same profile campaign: Euro-Office, Nextcloud 35.0.1 | Fresh installation and Verify, signed connector 11.0.6, pinned server 9.3.5.37, browser edit/save/DAV/fresh reopen and operator visual acceptance passed; controlled host reboot and saved-document continuity passed | Bounded dedicated-VM integration; no full DR acceptance |
| Same profile campaign: Collabora CODE, Nextcloud 35.0.1 | Fresh installation and Verify, signed richdocuments 12.0.1, product 26.04.5.1, operator editing acceptance, controlled host reboot, saved-file continuity and stable proof identities passed | Initial browser automation attempts failed; manual acceptance came first. Corrected automation subsequently passed real edit/save/DAV/fresh reopen without changing the accepted server; rendered-text inspection remained manual |
| October 18: optional native upgrade assistant | Uninterrupted Nextcloud 35.0.1→35.0.2 and separately explicit 14-member ZFS snapshot restoration passed, including original document continuity and HTTPS/ONLYOFFICE checks | **No package changes were selected**; does not establish dependency-changing upgrades, arbitrary versions or full disaster recovery |

### Latest family-selection source — October 23

| Case | Result | Boundary |
| --- | --- | --- |
| Live authenticated discovery and native pkg 2.8.4 solver | **PASS:** all four profiles on `latest`, plus Nextcloud-only on `quarterly`, with real signed catalogs and isolated empty-database dry runs | Office profiles were metadata/solver checks only, not new runtime or editing acceptance |
| Observed selection | Nextcloud 35.0.2; PHP 8.5.12; matching MariaDB client/server 12.3.3; Apache 2.4.69; Redis 8.10.2. Native office plan: ONLYOFFICE 9.4.0_4; connector plans: 10.2.1 / 11.0.6 / 12.0.1 | Dated observations, **not exact default pins or certification of future patches**; unsupported Nextcloud 36 family refused |
| Corrected fresh Nextcloud-only installation | **PASS:** all 18 installation steps on a disposable FreeBSD 15.1 amd64 guest with 8 GiB / 2 vCPU; independent Verify passed twice and actual packages matched exact locks | Minimal recipe, not default all-app or office installation |
| Non-admin user and saved data | **PASS:** normal account creation, hostname-validated strict-TLS API identity, unauthenticated DAV 401, conditional PUT 201 and GET 200 with matching saved-file SHA256 | Direct test ingress with a valid reused certificate; no public-route claim |
| Ordinary removal | **PASS:** all four steps, independent SSH before KEEP, no remaining active/dying owned jail or bridge; application datasets retained and configuration/version/source hashes unchanged | Not PURGE or disaster recovery; disposal of the test VM later removed its test storage |
| FreeBSD-base-only archive transport | **PASS:** generated command on a host without preinstalled Git, Bash or Python; archive digest verified before extraction, then existing prerequisite consent offered | Loopback-only SSH tunnel and existing certificate; not a public download-route or ACME test |
| Wrong archive digest | **PASS:** wrong SHA256 refused before extraction, no payload created; subsequent Verify passed | Earlier tunnel/TLS failure was not counted as digest-refusal evidence |
| Family-map canonicalization | Corrected nonempty-map key ordering passed fresh installation and immutable-state checks; all six key-order permutations covered, actual value changes refused | Initial installation stopped on a digest mismatch; no existing artifact, journal or lock was patched to make it pass. Empty/legacy digests preserved |
| Frozen offline regression | **2,280 tests passed** for the corrected family-selection source | Mocked/unit coverage does not substitute for native operation; not a new test run of this public documentation snapshot |

### Remaining limits

| Area | Status |
| --- | --- |
| Office runtime install/edit/save/reopen on latest family-selection source | **NOT RUN**; historical office acceptance above remains bounded to its original artifacts |
| Host reboot on latest family-selection source | **NOT RUN**; historical reduced-profile reboot checks do not transfer to it |
| Public ingress/forwarding and ACME issuance/renewal in October 23 tests | **NOT RUN**; strict TLS used a reused certificate and private test transport |
| Dependency-package-changing native upgrade | **NOT RUN**; October 18 upgrade selected no package changes |
| Complete backup/restore, mixed-instance failure/recovery, reboot/fault and DR matrix | **INCOMPLETE**; logical database/configuration backups exclude user files and are not full DR |
| Experimental lifecycle/controller maintenance execution | **BLOCKED by existing guards**; separate from the optional native upgrade assistant, not a required revival of an older controller test campaign |
| Physical-host compatibility, workload capacity, upstream support and production certification | **NOT ESTABLISHED** |

No broad new VM campaign is implied by these limits. Further testing should be
separately approved and scoped to changed integration contracts. See
[profile boundaries](fresh-install-profiles.md), [family policy and native details](versions.md#bounded-native-family-validation--2026-10-23),
[upgrade restrictions](upgrade.md), [lifecycle state](lifecycle-state.md) and
[maintenance recovery](maintenance-recovery.md). Existing guards must not be bypassed.

## What to validate

Use the [FreeBSD integration checklist](freebsd-15.1.md#freebsd-integration-checklist)
and [testing boundaries](testing-boundaries.md). Record the actual artifact hash,
versions, selected profile, topology and each case as passed, failed or not run.
Keep credentials and private evidence out of public reports.

- Check ownership, actual mounts, package locks, live runtime identities and
  private state modes, not directory existence or empty command output.
- Check generated PF/proxy rules with real allowed and denied probes. Preserve
  another instance during shared-policy changes where that branch is affected.
- Check HTTPS, callbacks/WebSockets and a representative saved document where
  the office integration changes. Healthchecks alone do not establish persistence.
- Check coherent backup/restore with saved-data continuity before relying on that
  advertised recovery contract. Logical database/config backups are not full DR.
- Check controlled reboot for persisted permissions. It does not prove arbitrary
  power-cut resilience, physical-host loss recovery or upstream internals.

Unsupported or unrun cases remain explicit limitations, never implied passes.
Production operators remain responsible for independent backups, restore drills,
monitoring, security review and workload qualification.

## Offline checks

From a source checkout with the tests available:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
git diff --check
```

Tests must mock host/package execution rather than provision the workstation.
GNU utility output is not evidence of FreeBSD compatibility; use the reviewed
[native utility contracts](freebsd-utilities.md). A test-harness/resource failure
is neither a product failure nor a passing native acceptance case.
