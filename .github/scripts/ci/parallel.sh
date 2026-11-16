#!/bin/sh
# Work out how many compile jobs this container may run in parallel.
#
# Every job registers a slot file in /ci/slots and takes CORE_BUDGET / running
# slots: one job gets the whole machine, two get half each, eight get a quarter.
#
# The slot name is supplied by the caller and must be identical in the acquire
# and release steps (run id + matrix value), because a command substitution runs
# the function in a subshell and variables set inside it never reach the caller.
# Slots left behind by a killed job are pruned by age, so a crash cannot shrink
# everyone's share permanently.

CI_CORE_BUDGET="${CI_CORE_BUDGET:-32}"
CI_SLOT_DIR="${CI_SLOT_DIR:-/ci/slots}"

# ci_parallel_acquire [fallback] [slot-name] -> prints the parallelism
ci_parallel_acquire() {
	fallback="${1:-4}"
	name="${2:-$$}"

	if [ ! -d /ci ] || ! mkdir -p "$CI_SLOT_DIR" 2>/dev/null; then
		printf '%s\n' "$fallback"
		return 0
	fi

	if ! : >"$CI_SLOT_DIR/$name" 2>/dev/null; then
		printf '%s\n' "$fallback"
		return 0
	fi

	# Slots from jobs that were killed or cancelled.
	find "$CI_SLOT_DIR" -type f -mmin +120 -delete 2>/dev/null || true

	# Jobs of one matrix start together; give the others a moment to register so
	# they all compute the same share instead of the first one taking everything.
	sleep 2

	count=$(find "$CI_SLOT_DIR" -type f 2>/dev/null | wc -l)
	[ "$count" -ge 1 ] || count=1
	jobs=$((CI_CORE_BUDGET / count))
	[ "$jobs" -ge 1 ] || jobs=1
	printf '%s\n' "$jobs"
}

# ci_parallel_release [slot-name]
ci_parallel_release() {
	name="${1:-$$}"
	rm -f "$CI_SLOT_DIR/$name" 2>/dev/null || true
}
