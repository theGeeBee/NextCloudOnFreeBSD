# Release bootstrap

For a fresh installation, use the short command on the
[versioned release page](https://github.com/theGeeBee/NextCloudOnFreeBSD/releases/tag/v2026.10.23).
Run it as root in an interactive terminal on a supported FreeBSD host.

The command downloads **`bootstrap.sh` from a full public commit ID**, verifies
its SHA256, then runs the saved script. It does not pipe a download into a shell
or follow a mutable branch. No Git, Bash or preinstalled Python is required.

`bootstrap.sh` is transport only. It accepts no arguments and pins the reviewed
v2026.10.23 archive and its checksum. It checks root, FreeBSD, outside-jail,
terminal, lifecycle fences and safe cache ownership before acquiring the archive.
After checksum verification, it extracts into a new private retained directory
and invokes that payload's **unchanged `install.sh install`**. Existing prerequisite,
license, APPLY and KEEP approvals still apply. Keep the printed payload path for
later management; do not rerun the bootstrap for Resume, recovery or upgrades.

## Publishing recipe

1. Test and publish the reviewed release archive and SHA256. Never overwrite a
   published artifact. The current archive remains exactly the tested v2026.10.23
   bytes; adding this transport does not change its tag, recipe or runtime.
2. Pin that archive URL and checksum in `bootstrap.sh`. Keep its transport body
   aligned with the tested base-only transport in `tools/build-release.py`.
3. Run the standalone/bootstrap and release-command tests. Verify `install.sh`
   and the published archive are unchanged. Review and commit the bootstrap,
   generator, tests and documentation in development, then publish a clean public
   follow-up commit without importing private history.
4. Generate the short launcher using that **public commit** and script digest:

   ```sh
   python3 tools/bootstrap-command.py \
     --commit FULL_PUBLIC_COMMIT \
     --sha256 TRUSTED_BOOTSTRAP_SHA256
   ```

5. Put the generated command directly under **Install** in the release notes.
   Download its exact public script URL, check the digest and compare bytes before
   announcing it. The launcher checks the script digest; the script checks the
   archive digest. Distribute both through the trusted release announcement.

The published release is immutable, so this follow-up script is served from its
full public source commit, not added to or substituted inside the original asset.
Future releases must deliberately update both pins and repeat these checks.

The original generated inline command remains a supported, tested transport;
it is not the primary command advertised on the release page. The standalone
`install.sh --archive` route is separate and requires existing Python; see
[distribution](distribution.md). Do not replace either script's responsibilities
or loosen the existing archive/lifecycle guards.

The transport body is byte-aligned with the earlier native-tested inline command.
New script/launcher orchestration is covered by sandbox tests; native execution
of this new wrapper has not been repeated. This does not extend the release's
documented native or production acceptance claims.
