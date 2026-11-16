# Self-hosted runner CI

These workflows run on a Forgejo Actions runner inside WSL on a Windows host, with
no access to `github.com`. Every `uses:` that pointed at a marketplace action has
been replaced with a plain `run:` step.

## Workflow layout

Each stage is its own workflow, so any of them can be dispatched alone:

| File | Builds | Notes |
| --- | --- | --- |
| `build-lkm.yml` | `*_kernelsu.ko` for 8 KMIs | matrix, calls `ddk-lkm.yml`, uses the `ddk-min` images |
| `ksud.yml` | `ksud` | all four targets by default, subset via `targets=` |
| `ksuinit.yml` | `ksuinit` | |
| `manager.yml` | the manager APK | build + repack/sign (no spoofed variant) |
| `publish.yml` | — | rolling `manager-ci` build and Telegram upload, one job |
| `release.yml` | — | orchestrates the stages, then assembles `/ci/runs/<id>/release` |
| `shellcheck.yml`, `clippy.yml`, `clang-format.yml`, `rustfmt.yml` | — | lint jobs |

`manager.yml` and `publish.yml` take `artifacts_run=<id>`, which seeds this run's
artifact directory from an earlier run. That makes repackaging take minutes
instead of rebuilding the native chain.

## One image for everything

`.github/ci/Dockerfile` builds `sukisu-ci:<tag>` from `catthehacker/ubuntu` and
bakes in JDK 21, the Android SDK (`platforms;android-37.0`,
`build-tools;37.0.0`, `cmake;3.22.1`, `cmake;3.31.6`), NDK `29.0.14206865`,
`libclang-21-dev`, Gradle 9.7.1, stable Rust with clippy/rustfmt plus the Android
targets, `nightly`/`nightly-2026-09-23` with `rust-src`, the KPM tools, and
git/curl/python3/zip/openssl/shellcheck/clang-format.

Installing that per job cost several gigabytes of downloads per run and left the
runner idle while a 1.5 GB NDK unpacked. A job now starts in seconds and its only
work is the build itself.

```bash
# on the runner host (WSL), from the repository root
bash .github/ci/build-image.sh 6
```

Then point the runner at it:

```ini
# /etc/forgejo-runner/config.yml
runner:
  labels:
    - "ubuntu-latest:docker://sukisu-ci:6"
  capacity: 4
container:
  options: "--add-host=host.docker.internal:host-gateway --volume /srv/forgejo-ci:/ci"
  valid_volumes:
    - /srv/forgejo-ci
```

`capacity: 4` with `MAKEFLAGS=-j6` / `CARGO_BUILD_JOBS=6` per job keeps four
concurrent jobs inside a 32-core host. Build a new tag instead of overwriting
one, so a running job keeps the image it started with.

## What replaces what

| Was | Now |
| --- | --- |
| `actions/checkout` | a shared bare mirror in `/ci/repo-cache`, cloned with `--shared` |
| `actions/setup-java`, `android-actions/setup-android`, `nttld/setup-ndk`, `Swatinem/rust-cache` | baked into the image; each job runs a `Check toolchain` step |
| `actions/upload-artifact`, `actions/download-artifact` | `ci_artifact_put` / `ci_artifact_get` from `.github/scripts/ci/common.sh` |
| `softprops/action-gh-release` | files collected under `${CI_ARTIFACT_ROOT}/release` |
| `gh release` publishing | split APKs copied to `${CI_ARTIFACT_ROOT}/manager-ci/<sha>` |

## Things this network cannot reach

`github.com` and `raw.githubusercontent.com` resolve to `::1` here (the tunnel
only proxies a fixed domain list), and `services.gradle.org` redirects to
`github.com`. Nothing in the pipeline may depend on them:

- **Rust git dependencies** — seven crates come from git on `github.com`.
  `.github/ci/mirror-git-deps.sh` mirrors them into `/srv/forgejo-ci/git-mirrors`
  with the revisions `Cargo.lock` pins tagged, the image bakes them in, and
  `git url.<mirror>.insteadOf` plus `cargo net.git-fetch-with-cli` redirect the
  fetches.
- **Gradle** — `gradle-wrapper.properties` would download its distribution from
  `github.com`. The image ships Gradle 9.7.1 and the workflows call `gradle`
  instead of `./gradlew`.
- **KPM tools** — `:app:downloadKpmTools` fetches `kptools-android` and `kpimg`
  from `raw.githubusercontent.com`. The workflow sets `KPM_TOOLS_BASE_URL` to the
  release assets of the mirrored KernelPatch repo, and the image also carries a
  copy at `/opt/kpm-tools` that the job seeds into `app/build/generated/kpmTools`
  after `gradle clean`.

## Artifact transport

The runner has no artifact service, so jobs exchange files through a host
directory mounted into every job container:

```
/ci/repo-cache/                bare mirror per repository, shared by all jobs
/ci/runs/<run_id>/<artifact>/  per-run artifacts
/ci/runs/<run_id>/release/     packaged release files
/ci/runs/<run_id>/manager-ci/  rolling CI APKs
/ci/tools/cargo/               cargo registry + git cache
/ci/tools/gradle/              Gradle user home
```

On Windows the same tree is visible at `\\wsl$\Debian\srv\forgejo-ci`.

`valid_volumes` matters: act silently drops a `--volume` it has not been told to
allow, and the job then writes to a throwaway `/ci` inside the container.

## Secrets and variables

Signing uses repository **variables** (`KEYSTORE` as base64, `KEY_ALIAS`,
`KEYSTORE_PASSWORD`, `KEY_PASSWORD`) with the same names accepted as secrets.
Telegram upload reads `BOT_TOKEN` and `CHAT_ID`, plus `MESSAGE_THREAD_ID` for
normal builds and `MESSAGE_RELEASES_THREAD_ID` for releases; it is skipped when
`BOT_TOKEN` or `CHAT_ID` is empty. Only the single Manager variant is published.

## Disabled workflows

Renamed to `*.yml.disabled`; Forgejo and GitHub both ignore those names.

- `npm.yml` publishes to the npm registry with provenance — needs an OIDC token
  from GitHub that does not exist here.
- `ksud-extra.yml` builds with `cross`, installed from a pinned `github.com`
  commit, and needs a Docker socket inside the job container. Nothing calls it.
- `builtzygisk.yml` builds `external/BuiltZygisk`, a submodule hosted on
  `github.com`. `ksud.yml` therefore runs with `pack_builtzygisk: false` and ksud
  is built without the embedded zygisk payload.

## Commit signing

Commits are signed with GPG (`commit.gpgsign=true`, key
`1C7DD4CE810618C3`). Forgejo only shows the *Verified* badge when the public key
is registered on the account, which also requires proving ownership: the key's
email address is not on the account, so the key was added with a signature over
the challenge token that the API returns.

```bash
# register (or replace) the key on the account
gpg --armor --export 1C7DD4CE810618C3 > pubkey.asc
curl -X POST -H "Authorization: token $FORGEJO_TOKEN"   -H 'Content-Type: application/json'   -d "$(jq -Rs '{armored_public_key: .}' pubkey.asc)"   https://git.zako.shirkneko.top:20004/api/v1/user/gpg_keys
# if it answers "None of the emails ... could be found", sign the token it prints
printf '%s' '<token>' | gpg --armor --detach-sign > token.asc
# and add "armored_signature": "<token.asc contents>" to the JSON body
```
