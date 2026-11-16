#!/usr/bin/env bash
# Shared helpers for the self-hosted Forgejo runner.
#
# The workflows were originally written for github.com hosted runners and used
# marketplace actions for checkout, toolchain setup and artifact passing. This
# runner has no access to github.com, so every one of those actions is replaced
# with a plain script. Artifacts are exchanged through a host directory that the
# runner mounts into each job container (see CI_ARTIFACT_ROOT), because the
# runner has no artifact service of its own in this setup.

set -eu
# The job shell differs per image (bash on the hosted-like images, dash in
# the ddk-min container), so only enable pipefail where it exists.
if [ -n "${BASH_VERSION:-}" ]; then
	set -o pipefail
fi

CI_REMOTE="${CI_REMOTE:-https://git.zako.shirkneko.top:20004}"
CI_ARTIFACT_ROOT="${CI_ARTIFACT_ROOT:-/ci/runs/${GITHUB_RUN_ID:-local}}"

# ci_checkout [depth]
#   depth 1 (default) fetches just the triggering commit. depth 0 fetches all
#   branches and tags, which the version-code and changelog steps need.
ci_checkout() {
	local depth="${1:-1}"
	local auth="${TOKEN:-${GITHUB_TOKEN:-}}"

	git init -q .
	if [ -n "$auth" ]; then
		# Kept in a config value so the credential never shows up in
		# `git remote -v` or in error output.
		git config "http.${CI_REMOTE}/.extraHeader" "Authorization: token ${auth}"
	fi
	git remote add origin "${CI_REMOTE}/${GITHUB_REPOSITORY}.git"

	if [ "$depth" = "0" ]; then
		git fetch -q origin "+refs/heads/*:refs/remotes/origin/*" "+refs/tags/*:refs/tags/*"
	else
		git fetch -q --depth "$depth" origin "${GITHUB_SHA}"
	fi
	git checkout -q "${GITHUB_SHA}"
}

# ci_artifact_path NAME -> absolute directory for one artifact
ci_artifact_path() {
	printf '%s/%s\n' "$CI_ARTIFACT_ROOT" "$1"
}

# ci_artifact_put NAME PATH...
#   Copies files or directories into the artifact directory. Missing sources are
#   an error: a silent skip would hide a broken build.
ci_artifact_put() {
	local name="$1"
	shift
	local dest
	dest="$(ci_artifact_path "$name")"
	mkdir -p "$dest"
	local src
	for src in "$@"; do
		if [ ! -e "$src" ]; then
			echo "artifact source missing: $src" >&2
			return 1
		fi
		cp -a "$src" "$dest"/
	done
	echo "stored artifact ${name} in ${dest}"
}

# ci_artifact_get NAME DEST
ci_artifact_get() {
	local name="$1"
	local dest="$2"
	local src
	src="$(ci_artifact_path "$name")"
	if [ ! -d "$src" ]; then
		echo "artifact not found: ${name} (${src})" >&2
		return 1
	fi
	mkdir -p "$dest"
	cp -a "$src"/. "$dest"/
}

# ci_artifact_exists NAME
ci_artifact_exists() {
	[ -d "$(ci_artifact_path "$1")" ]
}
