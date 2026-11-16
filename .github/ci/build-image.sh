#!/usr/bin/env bash
# Build the shared CI image on the runner host.
#
#   bash .github/ci/build-image.sh [tag]
#
# The tag is what the runner label points at:
#   runner.labels: - "ubuntu-latest:docker://sukisu-ci:<tag>"
# Build a new tag after changing the Dockerfile, then update the label, so a run
# in progress keeps using the image it started with.
#
# Two things are staged into the build context because they cannot be fetched on
# this network (github.com resolves to ::1):
#   CI_GIT_MIRRORS   bare mirrors of the Rust git dependencies (default
#                    /srv/forgejo-ci/git-mirrors, built by mirror-git-deps.sh)
#   CI_GRADLE_ZIP    gradle-9.7.1-bin.zip (default /srv/forgejo-ci/dist)
# Neither is stored in the repository.
set -euo pipefail

tag="${1:-1}"
here="$(cd "$(dirname "$0")" && pwd)"
mirrors="${CI_GIT_MIRRORS:-/srv/forgejo-ci/git-mirrors}"
gradle_zip="${CI_GRADLE_ZIP:-/srv/forgejo-ci/dist/gradle-9.7.1-bin.zip}"
kpm_dir="${CI_KPM_DIR:-/srv/forgejo-ci/kpm}"

if [ ! -d "$mirrors" ]; then
	echo "missing git mirrors: ${mirrors}" >&2
	echo "run .github/ci/mirror-git-deps.sh first (needs github.com access)" >&2
	exit 1
fi
if [ ! -d "$kpm_dir" ]; then
	echo "missing KPM tools: ${kpm_dir}" >&2
	exit 1
fi
if [ ! -f "$gradle_zip" ]; then
	echo "missing ${gradle_zip}" >&2
	echo "download gradle-9.7.1-bin.zip from gradle-distributions and place it there" >&2
	exit 1
fi

ctx="$(mktemp -d)"
trap 'rm -rf "$ctx"' EXIT

cp "${here}/Dockerfile" "${ctx}/Dockerfile"
cp -a "$mirrors" "${ctx}/git-mirrors"
mkdir -p "${ctx}/dist"
cp "$gradle_zip" "${ctx}/dist/gradle-9.7.1-bin.zip"
cp -a "$kpm_dir" "${ctx}/kpm"

docker build \
	--pull \
	-t "sukisu-ci:${tag}" \
	-f "${ctx}/Dockerfile" \
	"${ctx}"

docker image inspect "sukisu-ci:${tag}" --format 'built {{.RepoTags}} {{.Size}} bytes'
