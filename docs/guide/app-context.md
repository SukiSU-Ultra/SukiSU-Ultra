# App Context: caller-maintained shared state

App Context (extension ID 5) is a bounded, volatile per-UID state store.
It does **not** detect foreground applications, synchronize KernelSU App Profiles,
subscribe to lifecycle events, or persist records. A profile ID is an opaque
number assigned by the producer, not an existing KernelSU profile reference.
The Manager snapshot viewer refreshes every five seconds while the page is
resumed, and supports pull-to-refresh and toolbar refresh in both UI modes.
Polling pauses in the background and while the test/debug panel is open.
Existing rows remain visible during refresh and on load failure.

## CLI

Run as root or the authorized manager using the matching ksud and kernel:

```sh
ksud extension app-context set-fg 10086 true
ksud extension app-context set-fg 10086 false
ksud extension app-context set-profile 10086 4294967295
ksud extension app-context set-tag 10086 0x8000000000000001
ksud extension app-context clear-tag 10086 0x1
ksud extension app-context query 10086 --json
ksud extension app-context list --json
ksud extension app-context remove 10086
# Administrative operation: deletes EVERY producer's records.
ksud extension app-context clear-all
```

Query/list without `--json` remain human-readable. Errors produce a nonzero
exit status, not a successful empty JSON result. Consumers must check status.

## Data and ownership contract

* UID and profile ID cover the full unsigned 32-bit range. Android users are
  distinguished by the full UID, not just the application ID. Shared-UID packages
  share one record. A UID is not a durable package identity.
* Foreground is a producer report, not an authoritative OS observation.
* Tags are 64 bits; set performs OR and clear performs AND-NOT atomically under
  the store lock. Decimal and `0x`/`0X` inputs are supported by the CLI.
* Every successful field write updates `last_update_ns`, including unchanged
  values. It is `ktime_get_ns()` (CLOCK_MONOTONIC, suspend excluded), **not Unix
  time**. No timestamp is comparable across reboots. Reads do not update it.
* Setting foreground, profile or tags creates a record with other fields zero.
  Query, clear-tag and remove fail with ENOENT for missing records. Clear-all is
  idempotent. Record deletion discards all fields.
* Maximum capacity is 512. Creating a new UID when full fails with ENOSPC and
  preserves all existing records. Existing records remain writable when full.
  There is no silent eviction, TTL or automatic uninstall handling.
* The producer must clear foreground when appropriate and remove records on
  teardown/uninstall/reassignment. If producers restart, they must reconcile
  their prior records. Do not infer freshness from existence alone.
* Foreground/profile use last-writer-wins. Producers must agree on an authority
  for those fields and on tag-bit allocation. There is no owner isolation,
  reference counting or access control per bit. A module must not clear another
  module's bits or remove its shared record. Clear-all is for administration.
* The extension uses the existing manager-or-root permission gate. It is not an
  unprivileged Android API. Kernel-internal helpers are sleepable and not exported
  as a stable loadable-module symbol ABI; external producers use the ioctl/ksud.
* The state is lost at reboot or KernelSU subsystem shutdown. It is intentionally
  excluded from sticky extension configuration persistence.

## Stable JSON v1

List returns an envelope, including when empty:

```json
{"version":1,"entries":[{"uid":10086,"foreground":true,"profile_id":4294967295,"tags":"0x8000000000000001","last_update_ns":"123456789"}]}
```

Query returns `{"version":1,"entry":{...}}`. UID/profile are JSON numbers,
foreground is boolean, tags are fixed-width 16-digit hexadecimal strings and
nanoseconds are unsigned decimal strings. String encoding preserves all 64 bits
in JavaScript and other consumers. The Manager accepts unknown additive fields,
but rejects unknown versions, duplicate UIDs and malformed records as a load
failure; it never silently drops records. CLI list ordering is ascending UID;
Manager ordering is foreground-first then UID. Package names are best-effort
annotations from one package-manager query; unresolved UIDs remain visible.

## UAPI

`uapi/extension.h` is the single source of truth. Rust uses generated bindgen
layouts and constants, not duplicated structs. Payloads use fixed-width integers
and explicitly aligned 64-bit fields. Outer/payload reserved **input** fields
must be zero; query entry is output and is fully initialized by the kernel.
Foreground accepts only 0 or 1. Unknown operations and invalid list buffers/counts
return EINVAL. Bad userspace memory returns EFAULT. Allocation failure returns
ENOMEM. Each list is a lock-protected snapshot, not live pointers. If its buffer
is too small it fails with ENOSPC instead of silently truncating; retry at the
published maximum capacity. Output is only valid on success.

Operations 1-7 are query, set-fg, set-profile, set-tag, clear-tag, list and remove;
operation 8 clears all records. The extension WIPE callback also clears all.
The extension does not have a sticky enable bit or support force-extension.

## In-app test and debug panel

Open App Context and tap the tools icon in the toolbar (available in both UI
modes). Choose a dedicated unused UID and confirm that no other producer will
write to it. Existing records are rejected instead of being adopted.

* **Run tests** checks zero defaults, query/list JSON, foreground transitions,
  full-width profile IDs, high/all tag bits, OR/AND-NOT, invalid CLI inputs,
  independent fields, timestamps, and removal. Its record is cleaned up on
  completion or failure when the ownership snapshot still matches.
* **Start debug session** creates a dedicated test record. Set foreground,
  profile and tag masks, query the raw JSON, then end the session to remove it.
  No arbitrary shell command, clear-all, or capacity test is exposed.
* Results can be selected and copied. Low-level diagnostics use English.
* Before each mutation/deletion the tool checks the last observed snapshot.
  If another producer changes it, mutation is refused. Use **Detach without
  deleting** to leave a conflicted record for manual inspection.

These checks are best effort: the UAPI has no exclusive-create, owner token or
compare-and-swap operation, so there is still a race between a snapshot check and
its write. Stop other writers for the chosen UID. Process death can leave the
test record behind; inspect that UID before manual removal. This panel is not a
replacement for concurrency, invalid-pointer or kernel fault-injection tests.
