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

## Atomic single-UID transactions and rollback

Requires a matching kernel and ksud with operations 9-12. Existing operations
1-8 and JSON v1 snapshots retain their layouts and behavior. New commands never
fall back to legacy writes when unsupported.

```sh
# Exclusive create: EEXIST if the UID is already present.
ksud extension app-context transact 199999 --create --foreground false --profile 42 --tags 0x1
# Read the current revision. All new commands emit JSON.
ksud extension app-context query-versioned 199999
# Substitute the revision STRING returned by the previous command.
ksud extension app-context transact 199999 --revision REVISION --foreground true --profile 123 --tags 0xffffffffffffffff
# Undo only the most recent transaction, using THAT transaction receipt.
ksud extension app-context rollback 199999 TRANSACTION_REVISION
# Delete only if the current revision still matches.
ksud extension app-context remove-versioned 199999 CURRENT_REVISION
```

Example receipt:

```json
{"version":1,"exists":true,"revision":"123","entry":{"uid":199999,"foreground":true,"profile_id":123,"tags":"0xffffffffffffffff","last_update_ns":"456"}}
```

Deletion (including undoing creation) returns `exists:false`, revision `"0"`
and `entry:null`. Revisions and timestamps are strings, not JSON numbers.

### Atomicity and undo contract

* A transaction replaces any nonempty selection of foreground, profile and tags
  under one mutex. Unselected fields remain unchanged. `--tags` replaces the
  mask; legacy set-tag/clear-tag still perform OR/AND-NOT.
* Use **either** exclusive create with expected revision zero, **or** an update
  with a nonzero current revision. The kernel checks existence/revision and
  applies all fields as one indivisible change. Stale updates, removal and undo
  return ESTALE and never overwrite another writer.
* Each successful transaction stores one kernel-owned previous snapshot. No
  userspace-supplied snapshot is trusted. Undo is single-level and one-shot:
  it restores the previous field values with a **new** revision and timestamp.
  Undoing creation removes the record. It is not an undo stack or redo system.
* Any later write, even an unchanged legacy value, advances the global revision
  and invalidates old receipts. Legacy writes invalidate undo entirely. A newer
  transaction replaces the previous undo snapshot. Successful rollback consumes
  undo. Failed operations preserve the record **and its undo snapshot**.
* Removal/clear-all discard undo. The revision counter is not reset by clearing
  or deleting records, preventing delete/recreate ABA within a subsystem lifetime.
  Counter exhaustion returns EOVERFLOW instead of reusing revisions. Receipts
  must be discarded after reboot or KernelSU reload; they are not durable IDs.
* Validation, allocation and user-copy failures commit nothing. New mutating
  ioctl paths copy the receipt to userspace while holding the store mutex,
  **before** the non-failing commit. A partial copy can leave garbage in the
  caller buffer; all output is invalid on error. Other readers/writers cannot
  observe a partially updated record. Kernel helper output is likewise valid
  only on success.
* A CLI output failure or process death **after a successful ioctl** does not
  roll back the kernel change. Keep the receipt; query-versioned can recover
  current state, but do not silently adopt another producer's revision.
* Revisions are conflict detection, not ownership/security tokens. All operations
  still use the manager-or-root gate. Authorized writers can query a revision or
  call legacy unconditional writes; this is not producer isolation.
* No multi-UID transaction, persistent undo journal or automatic crash recovery.

The new payloads use the same 8-byte command header/union offset as legacy
payloads. `ksu_app_context_entry` remains 32 bytes; transaction payload is 80
bytes and versioned payload is 64 bytes. Reserved fields and unselected input
values must be zero. Output fields are ignored on input.

## In-app test and debug panel

Open App Context and tap the tools icon in either UI mode. Confirm a dedicated
unused UID. Creation uses the kernel's exclusive-create operation; updates,
cleanup and undo send the last successful receipt's revision. No check/write
race or legacy fallback remains in the mutation path.

* **Run tests** covers the original field/JSON/boundary checks plus atomic
  multi-field replacement, exclusive-create rejection, stale update/delete/undo
  rejection, restoration and one-shot undo. It ends with conditional cleanup.
* **Start debug session** provides individual field/tag controls and an atomic
  all-fields action. For the latter, choose foreground and enter profile/tags;
  all three are replaced at once. **Undo latest transaction** restores the
  immediately preceding transaction, or deletes the record if creation was the
  latest transaction. **End and clean up** uses revision-checked deletion.
* A conflict leaves the receipt unchanged and stops mutation/cleanup. Use
  **Detach without deleting** for manual inspection; never reacquire the latest
  revision merely to force cleanup after external writes.
* Results can be selected/copied. Test outcomes and session safety messages
  follow the app language (English/Simplified Chinese); raw ksud errors and JSON
  remain unchanged. Process death may leave a record behind.

