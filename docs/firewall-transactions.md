# Network transaction and recovery contract

`installer/firewall.py` is the network-only supervisor. The host controller must
hold its global operation lock, validate ownership and the prior live policy,
and create a new private transaction directory before calling `arm(state)`.
The interactive process never acquires the network mutation lock.

The transaction records prior forwarding/filter sysctls, immutable copies of
changed host files, **only newly created bridges**, the desired PF policy, a
monotonic confirmation deadline, and the host's `kern.boottime` identity.
For repeat changes it also records the previous committed transaction and PF
file. The private rollback copy must match that transaction's original policy
source exactly; a changed on-disk policy is never the rollback authority.
Existing instance traffic must remain protected throughout a transition.

The worker validates a candidate before atomically replacing the PF file. It
loads the policy and enables PF only for a fresh deployment. The operator must
verify a second SSH session and type `KEEP` before the deadline. Commit saves
normalized live PF snapshots, persists boot settings, atomically changes the
shared `network/active` pointer, then writes the final durable confirmation
marker. Startup guards fail closed during an incomplete pointer transition.

On failure, expiry or disconnect, the detached supervisor kills and reaps its
own worker process group **before** acquiring the rollback lock. This handles
a suspended worker without killing SSH or unrelated processes. Fresh rollback
disables newly enabled PF and restores the proven-empty rules/state set, so a
subsequent Resume does not mistake leftover unconfirmed rules for foreign policy.
Repeat rollback reloads the previous managed policy
without disabling PF or flushing other instances' states. Its restored live
filter/NAT/table snapshots must match the prior committed snapshots before
rollback can restore readiness, remove bridges or publish a success marker.
Only unconfirmed new
bridges are removed; no application data is rolled back.

FreeBSD expands bare `self` addresses while loading rules. Before a repeat rollback
reloads the old source, it validates **all newly-created bridges**, rejects foreign
members/IPv4 addresses, and withdraws only their exact recorded IPv4 addresses.
Otherwise identical old policy bytes would expand against the new host addresses
and fail snapshot restoration. This does not destroy a bridge or alter an existing
bridge; destruction still waits for verified restored snapshots. Absent interfaces
or already-withdrawn addresses support an interrupted recovery retry. Empty or
ambiguous interface inspection and any ownership uncertainty fail closed.

This ordering was exercised during the authorized Alpine probe on FreeBSD15.1
(2026-10-19). Explicit `recover-network` restored exact prior live snapshots after
the native defect was diagnosed; expected snapshots/immutable watchdog records
were not edited. See [bounded evidence](fresh-install-profiles.md).

`pending_transactions(root)` is read-only. New host operations must refuse
unresolved transactions. An administrator-confirmed `recover_pending(state,
current_boot)` handles a lost supervisor after reboot or an expired transaction:

- Same boot: the deadline must have expired; a still-held mutation lock fails
  immediately rather than blocking indefinitely.
- Different boot: the old process cannot still be applying changes, so recovery
  may proceed immediately.
- After the lock/eligibility checks, recovery loads missing PF/bridge kernel
  support. A first transition may have rebooted before PF boot enablement was
  committed; missing devices/sysctls must not turn recovery into a dead end.
- Missing boot identity, foreign pointers, unsafe files and failed restoration
  require manual attention. Do not edit confirmation markers to bypass guards.

The operator entrypoint exposes this as `sh install.sh recover-network` with
typed `RECOVER` confirmation. Keep console access available and do not make
concurrent manual network changes. This is **not** recovery from a crashed kernel
or damaged pool, and it is not application-data rollback.

Offline tests exercise the actual process-group/SIGSTOP protocol with harmless
children and mocked native commands. FreeBSD PF, reboot and live traffic
preservation still require the disposable-host acceptance tests.
