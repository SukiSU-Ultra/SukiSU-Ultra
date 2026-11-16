# Single toolchain image for every non-DDK job.
#
# The first version of the self-hosted CI installed rustup, the Android SDK and
# the NDK inside each job container. That meant several gigabytes of downloads
# per run (twice for clippy, once per ksud target, once for the manager) and the
# runner sat idle while a 1.5 GB NDK unpacked. Everything is baked here instead:
# a job starts in seconds and only the repository work remains.
#
# The kernel jobs keep using ghcr.io/ylarod/ddk-min:<kmi>-<release>, because that
# image carries the kernel source trees, not just a toolchain.
#
# Build:  bash .github/ci/build-image.sh [tag]

FROM catthehacker/ubuntu:act-latest

ARG CMDLINE_TOOLS_VERSION=11076708
ARG ANDROID_PLATFORM=platforms;android-37.0
ARG ANDROID_BUILD_TOOLS=build-tools;37.0.0
ARG ANDROID_NDK=ndk;29.0.14206865
ARG RUST_NIGHTLY=nightly-2026-09-23

# bindgen (ksud's ksu_uapi.h) needs libclang with its own resource directory.
# Pointing at the NDK copy made clang miss its builtin stddef.h, so the
# distribution libclang-21 is used instead, like the hosted images did.
ENV DEBIAN_FRONTEND=noninteractive \
    ANDROID_SDK_ROOT=/opt/android-sdk \
    ANDROID_HOME=/opt/android-sdk \
    ANDROID_NDK_HOME=/opt/android-sdk/ndk/29.0.14206865 \
    LIBCLANG_PATH=/usr/lib/llvm-21/lib \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 \
    PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        openjdk-21-jdk-headless \
        curl ca-certificates unzip zip xz-utils file \
        python3 git openssl \
        make ninja-build gcc libc6-dev \
        shellcheck clang-format rsync patch \
        libclang-21-dev; \
    rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------- Rust
# Prebuilt std is not published for every nightly target; build-std covers
# the missing ones, so `rustup target add` failures there are not fatal.
# The toolchain lives in CARGO_HOME/bin, which is already on PATH above.
RUN set -eux; \
    curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal \
        --default-toolchain stable --no-modify-path; \
    rustup component add clippy rustfmt; \
    rustup toolchain install "${RUST_NIGHTLY}" --profile minimal --component rust-src; \
    rustup toolchain install nightly --profile minimal --component rustfmt; \
    rustup target add \
        aarch64-linux-android \
        armv7-linux-androideabi \
        x86_64-linux-android; \
    for t in aarch64-linux-android armv7-linux-androideabi \
             x86_64-linux-android riscv64-linux-android; do \
        rustup target add --toolchain "${RUST_NIGHTLY}" "$t" || true; \
    done; \
    rustup default stable

# Kept in its own layer so a change here does not invalidate the toolchain above
# (re-downloading rustup over this tunnel is flaky). BuiltZygisk's zygiskd is a
# Rust crate cross-compiled through cargo-ndk.
ENV CARGO_NET_RETRY=10
RUN cargo install cargo-ndk --locked

# ---------------------------------------------------------------- Android SDK
# One layer: the SDK and NDK are the bulk of the image.
RUN set -eux; \
    tmp="$(mktemp -d)"; \
    curl -fsSL -o "$tmp/cmdline-tools.zip" \
        "https://dl.google.com/android/repository/commandlinetools-linux-${CMDLINE_TOOLS_VERSION}_latest.zip"; \
    mkdir -p "${ANDROID_SDK_ROOT}/cmdline-tools"; \
    unzip -q "$tmp/cmdline-tools.zip" -d "$tmp"; \
    mv "$tmp/cmdline-tools" "${ANDROID_SDK_ROOT}/cmdline-tools/latest"; \
    rm -rf "$tmp"; \
    yes | "${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin/sdkmanager" --licenses >/dev/null || true; \
    "${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin/sdkmanager" --install \
        "${ANDROID_PLATFORM}" \
        "${ANDROID_BUILD_TOOLS}" \
        "${ANDROID_NDK}" \
        "platform-tools" \
        "cmake;3.22.1" \
        "cmake;3.31.6" \
        "cmake;4.1.2" \
        "ndk;27.2.12479018" \
        >/dev/null; \
    rm -rf "${ANDROID_SDK_ROOT}/.temp"

# ---------------------------------------------------------------- KPM tools
# app/build.gradle.kts downloads these from raw.githubusercontent.com, which is
# unreachable here; the task skips the download when both files already exist and
# the manager workflow copies them in after `gradle clean`.
COPY kpm/ /opt/kpm-tools/
RUN set -eux; test -s /opt/kpm-tools/kptools-android; test -s /opt/kpm-tools/kpimg

# ---------------------------------------------------------------- Gradle
# gradle-wrapper.properties points at services.gradle.org, which 307s to
# github.com; that host is mapped to ::1 here. The same distribution is baked in
# and the workflows call `gradle` instead of ./gradlew.
COPY dist/gradle-9.7.1-bin.zip /tmp/gradle.zip
RUN set -eux;     unzip -q /tmp/gradle.zip -d /opt;     ln -sfn /opt/gradle-9.7.1 /opt/gradle;     rm -f /tmp/gradle.zip;     /opt/gradle/bin/gradle --version

ENV PATH="/opt/gradle/bin:${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin:${ANDROID_SDK_ROOT}/platform-tools:${ANDROID_SDK_ROOT}/build-tools/37.0.0:${ANDROID_SDK_ROOT}/cmake/3.31.6/bin:${PATH}"

# ---------------------------------------------------------------- git mirrors
# Seven Rust dependencies come from git repositories on github.com, which this
# network resolves to ::1 (the tunnel only proxies a fixed domain list). Bare
# mirrors are baked in and git rewrites the URLs, so cargo never talks to
# github.com. Refresh with .github/ci/mirror-git-deps.sh on a machine that can.
COPY git-mirrors/ /opt/git-mirrors/

RUN set -eux; \
    printf '[net]\n# git-fetch-with-cli makes cargo shell out to git, which is what lets the\n# insteadOf rewrites below take effect.\ngit-fetch-with-cli = true\n' \
        > "${CARGO_HOME}/config.toml"; \
    git config --system url."file:///opt/git-mirrors/libc.git".insteadOf \
        "https://github.com/rust-lang/libc"; \
    git config --system url."file:///opt/git-mirrors/android_bootimg.git".insteadOf \
        "https://github.com/5ec1cff/android_bootimg"; \
    git config --system url."file:///opt/git-mirrors/java-properties.git".insteadOf \
        "https://github.com/KernelSU2/java-properties.git"; \
    git config --system url."file:///opt/git-mirrors/adb_client.git".insteadOf \
        "https://github.com/KernelSU2/adb_client"; \
    git config --system url."file:///opt/git-mirrors/ksu_props.git".insteadOf \
        "https://github.com/KernelSU2/ksu_props"; \
    git config --system url."file:///opt/git-mirrors/rustix.git".insteadOf \
        "https://github.com/KernelSU2/rustix.git"; \
    git config --system url."file:///opt/git-mirrors/kernlog.rs.git".insteadOf \
        "https://github.com/kstep/kernlog.rs"; \
    git config --system url."file:///opt/git-mirrors/rustix-jm.git".insteadOf \
        "https://github.com/JingMatrix/rustix"; \
    git ls-remote file:///opt/git-mirrors/libc.git HEAD >/dev/null; \
    cat /etc/gitconfig

# Fail the image build, not a later job, if something is missing.
RUN set -eux; \
    java -version; \
    cargo --version; rustc --version; cargo clippy --version; rustfmt --version; \
    rustup toolchain list; \
    sdkmanager --version; \
    gradle --version | head -3; \
    apksigner --version; \
    cmake --version; \
    python3 --version; git --version; zip --version | head -2; \
    shellcheck --version | head -2; clang-format --version; \
    test -x "${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin/clang"
