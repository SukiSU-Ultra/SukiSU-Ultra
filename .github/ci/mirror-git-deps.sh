#!/usr/bin/env bash
# Refresh the bare mirrors of the Rust git dependencies.
#
#   bash .github/ci/mirror-git-deps.sh [output-dir]
#
# Runs on a machine that can reach github.com (this one cannot from inside WSL:
# the tunnel resolves github.com to ::1 and only proxies a fixed domain list).
# build-image.sh copies the result into the image and git rewrites the upstream
# URLs to these local paths.
#
# The pinned revisions come from Cargo.lock; a mirror clone does not always
# contain a commit that is only reachable from a PR branch, so the revs are
# fetched explicitly afterwards.
set -euo pipefail

out="${1:-/srv/forgejo-ci/git-mirrors}"
mkdir -p "$out"
cd "$out"

# name|url|extra revs to fetch
specs='
libc|https://github.com/rust-lang/libc|1a661633f11a261ff9c00b40875ef72f1cbec818
android_bootimg|https://github.com/5ec1cff/android_bootimg|150425b027c76ea104c82e408571651f2181b2c2
java-properties|https://github.com/KernelSU2/java-properties.git|
adb_client|https://github.com/KernelSU2/adb_client|d97a966435bebaa55017834869dec08150826aa7
ksu_props|https://github.com/KernelSU2/ksu_props|ddb6ee7294467f7f25bad2118e9e24eee104144b
rustix|https://github.com/KernelSU2/rustix.git|4a53fbc7cb7a07cabe87125cc21dbc27db316259
kernlog.rs|https://github.com/kstep/kernlog.rs|68caa7bf1e27baea35b00ebba786cafae0bca90f
'

printf '%s\n' "$specs" | while IFS='|' read -r name url revs; do
	[ -n "$name" ] || continue
	echo "== $name"
	if [ -d "${name}.git" ]; then
		git --git-dir="${name}.git" fetch -q --prune origin '+refs/*:refs/*'
	else
		git clone -q --mirror "$url" "${name}.git"
	fi
	for rev in $revs; do
		if ! git --git-dir="${name}.git" cat-file -e "$rev" 2>/dev/null; then
			# Not on a branch tip: ask for the object directly.
			git --git-dir="${name}.git" fetch -q origin "$rev"
		fi
		git --git-dir="${name}.git" cat-file -e "$rev"
		# Keep the commit reachable from a tag. A non-branch ref would be
		# dropped by the clone in the image (clones carry heads and tags only),
		# and an unreferenced commit is not transferred at all.
		git --git-dir="${name}.git" tag -f "pin-${rev%"${rev#????????????}"}" "$rev" >/dev/null
	done
done

du -sh "$out"/*.git
