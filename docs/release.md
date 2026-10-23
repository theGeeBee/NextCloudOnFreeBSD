# Release candidate 2026.10.23

This date-based candidate identifier does not change the Python packaging
metadata (`0.0.0.dev0`) or application version policy. Availability is established
by the maintainer's release announcement, not by this document. Use the versioned
URL below only after publication of the reviewed archive and its independently
trusted SHA256. No URL availability or signing guarantee is implied.

## Overview

The redesigned installer replaces the legacy host-service shell workflow with
isolated, version-aware Bastille deployments and one reviewed operator entrypoint.
It includes reusable JSON examples, private deployment records, timed PF
confirmation, recovery guidance and optional document-server profiles.

Fresh installations can select stable major or major.minor version families.
Nextcloud family `35` chooses the newest compatible available 35.x release,
never 36. Native FreeBSD pkg selects the configured repository's packages; exact
versions, signatures, dependency identities and checksums remain locked afterward.
The existing APPLY/`--yes` review discloses untested combinations and cannot
override hard compatibility or security failures. See [version selection](versions.md).

Existing legacy installations are not adopted or automatically migrated. Read
[requirements](../README.md#requirements) and [operations](operations.md) first.
The former `pre-install.sh`, `install_docserver.sh`, sourced shell configuration,
Linuxulator mounts and bundled full service configurations are retired. The
new workflow requires host-level orchestration, not execution inside an existing
jail. Automatic host boot-environment creation, self-signed/IP-first setup,
server-side encryption selection, notification-email setup and automatic external
storage backend setup are not retained as installer features. System notification
delivery remains disabled; the optional Mail app is a separate client integration.
The release preparation does not change application provisioning or approved
versions. See the reconciled [validation matrix](verification.md) and
[profile status](fresh-install-profiles.md) for historical end-to-end results,
current native family-selection evidence and explicit remaining limitations.

## Installation after separately approved publication

The primary user command is the standalone-script launcher on the
[release page](https://github.com/theGeeBee/NextCloudOnFreeBSD/releases/tag/v2026.10.23).
It verifies `bootstrap.sh` from a full public source commit; that script verifies
the original archive and invokes its unchanged `install.sh`. Follow the
[publication recipe](bootstrap.md) to keep script, archive and announcement pins
aligned. The published archive/tag are immutable; this source follow-up does not
replace them. The existing inline builder command below remains supported.

A publisher must choose a versioned HTTPS asset location and publish the exact
reviewed archive bytes and independently trusted SHA256. For example, on a
maintainer workstation with Python 3.11+:

```sh
# Review the versioned publication location and exact bytes before building.
# This command neither publishes anything nor verifies asset availability.
python3 tools/build-release.py \
  --output dist/NextCloudOnFreeBSD-2026.10.23.tar.gz \
  --url 'https://github.com/theGeeBee/NextCloudOnFreeBSD/releases/download/v2026.10.23/NextCloudOnFreeBSD-2026.10.23.tar.gz'
```

The builder prints the actual archive digest and a single FreeBSD-base-only
installation command pinned to those bytes. Publish that generated command
outside the archive, through a trusted channel. On the clean FreeBSD host, paste
the complete reviewed command as root in an interactive terminal. It uses base
`fetch`, `sha256` and `tar`, then invokes the verified payload's `install.sh install`.
No Git, Bash or preinstalled Python is needed for transport; missing pkg/Python
installation still requires consent from the existing installer.

Do not execute a placeholder, use a mutable branch/latest URL or pipe a downloaded
script into a shell. Do not substitute GitHub's automatic source archive: its
layout is not the release payload format.

For manual acquisition with an already published artifact:

```sh
# Confirm the published asset location and obtain its independently trusted digest.
URL='https://github.com/theGeeBee/NextCloudOnFreeBSD/releases/download/v2026.10.23/NextCloudOnFreeBSD-2026.10.23.tar.gz'
EXPECTED_SHA256='REPLACE_WITH_TRUSTED_64_HEXADECIMAL_SHA256'
umask 077
mkdir -m 700 release-2026.10.23 &&
  cd release-2026.10.23 &&
  fetch -o release.tar.gz "$URL" &&
  test "$(sha256 -q release.tar.gz)" = "$EXPECTED_SHA256" &&
  tar --no-same-owner --no-same-permissions -xzf release.tar.gz &&
  sh cloud-installer/install.sh install
```

Keep the extracted original payload for Resume and recovery. See the
[distribution guide](distribution.md) for transport guards and archive validation.
The archive's own checksum is intentionally not embedded in documents inside it.

The published installation command/digest must be distributed **outside** the
archive input tree. Rebuilding from different source/documentation changes the
digest, so do not substitute an older candidate archive or its checksum.

## Validation boundary

Release packaging is checked offline for syntax, regression behavior, deterministic
archive generation, payload completeness, documentation links and public-content
hygiene. Offline checks do not establish FreeBSD installation, network recovery,
application upgrade/restore or physical-target acceptance. No live installation,
VM operation or network change is part of this release preparation.
