#!/usr/bin/env python3
"""Local Android Rust builds; Python 3.10+, Rust/rustup and Android NDK required."""
import argparse
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
ARCHES = {
    "arm64": "aarch64-linux-android",
    "x86_64": "x86_64-linux-android",
    "riscv64": "riscv64-linux-android",
}
ALIASES = {"aarch64": "arm64", "arm64-v8a": "arm64", **{v: k for k, v in ARCHES.items()}}


def run(command, env=None, capture=False):
    print("+ " + subprocess.list2cmdline([str(x) for x in command]), flush=True)
    return subprocess.run([str(x) for x in command], cwd=ROOT, env=env, check=True,
                          text=True, stdout=subprocess.PIPE if capture else None)


def version_key(path):
    return tuple(int(x) if x.isdigit() else 0 for x in path.name.split("."))


def find_ndk(explicit):
    if explicit:
        candidates = [Path(explicit).expanduser()]
    else:
        candidates = [Path(os.environ[k]).expanduser() for k in
                      ("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT") if os.environ.get(k)]
        sdk_roots = [Path(os.environ[k]) for k in ("ANDROID_HOME", "ANDROID_SDK_ROOT")
                     if os.environ.get(k)]
        local = ROOT / "manager/local.properties"
        if local.is_file():
            for line in local.read_text(encoding="utf-8").splitlines():
                if line.startswith("sdk.dir="):
                    value = line.split("=", 1)[1].replace("\\:", ":").replace("\\\\", "\\")
                    sdk_roots.append(Path(value))
        home = Path.home()
        sdk_roots += [home / "AppData/Local/Android/Sdk", home / "Android/Sdk",
                      home / "Library/Android/sdk"]
        for sdk in sdk_roots:
            if (sdk / "ndk").is_dir():
                candidates += sorted((p for p in (sdk / "ndk").iterdir() if p.is_dir()),
                                     key=version_key, reverse=True)
            candidates.append(sdk / "ndk-bundle")
    for candidate in candidates:
        if (candidate / "toolchains/llvm/prebuilt").is_dir():
            return candidate.resolve()
    raise RuntimeError("Android NDK not found. Pass --ndk PATH or set ANDROID_NDK_HOME.")


def host_tools(ndk):
    tags = {"Windows": ["windows-x86_64"], "Linux": ["linux-x86_64"],
            "Darwin": ["darwin-arm64", "darwin-x86_64"]}.get(platform.system(), [])
    for tag in tags:
        tools = ndk / "toolchains/llvm/prebuilt" / tag
        if tools.is_dir():
            return tools
    raise RuntimeError(f"No NDK tools for host {platform.system()}/{platform.machine()}")


def require_file(path):
    if not path.is_file():
        raise RuntimeError(f"Required NDK tool/file missing: {path}")
    return path


def build_environment(tools, triple, api):
    env = os.environ.copy()
    binary = tools / "bin"
    win = platform.system() == "Windows"
    suffix = ".cmd" if win else ""
    clang = require_file(binary / ("clang.exe" if win else "clang"))
    cc = require_file(binary / f"{triple}{api}-clang{suffix}")
    cxx = require_file(binary / f"{triple}{api}-clang++{suffix}")
    ar = require_file(binary / ("llvm-ar.exe" if win else "llvm-ar"))
    key = triple.replace("-", "_")
    env["PATH"] = str(binary) + os.pathsep + env.get("PATH", "")
    env["ANDROID_NDK_HOME"] = str(tools.parents[3])
    env[f"CC_{key}"] = str(cc)
    env[f"CXX_{key}"] = str(cxx)
    env[f"AR_{key}"] = str(ar)
    env[f"CARGO_TARGET_{key.upper()}_LINKER"] = str(cc)
    # Explicit include paths are needed for bindgen on Windows hosts too.
    includes = [tools / "sysroot/usr/include", tools / "sysroot/usr/include" / triple]
    flags = [f"--target={triple}{api}"]
    for include in includes:
        flags += ["-isystem", '"' + include.as_posix() + '"']
    env[f"BINDGEN_EXTRA_CLANG_ARGS_{key}"] = " ".join(flags)
    libraries = [binary, tools / "lib", tools / "lib64"]
    for directory in libraries:
        if any(directory.glob("*clang*.dll")) or any(directory.glob("libclang.*")):
            env["LIBCLANG_PATH"] = str(directory)
            break
    else:
        if not env.get("LIBCLANG_PATH"):
            raise RuntimeError("libclang not found in the NDK; set LIBCLANG_PATH to its directory.")
    env.setdefault("KSU_LKM_BOOTSTRAP_CC", str(clang))
    return env, clang


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python userspace/build.py
  python userspace/build.py --arch x86_64 --debug
  python userspace/build.py --arch arm64 --action check --offline
  python userspace/build.py --package ksuinit --install-target
  python userspace/build.py --ndk D:/Android/Sdk/ndk/29.0.14206865
  python userspace/build.py --arch riscv64 --install-target

Only Android targets are configured. RISC-V uses the CI nightly + build-std.
Dependencies/targets may require network access unless already cached.
No repository config, APK native libraries or embedded assets are overwritten.
""")
    parser.add_argument("--arch", default="arm64", help="arm64 (default), x86_64, riscv64, or Android Rust triple")
    parser.add_argument("--package", choices=["ksud", "ksuinit"], default="ksud")
    parser.add_argument("--action", choices=["build", "check", "clippy"], default="build")
    parser.add_argument("--debug", action="store_true", help="Use debug profile (default: release)")
    parser.add_argument("--ndk", help="Android NDK root; otherwise auto-detect")
    parser.add_argument("--api", type=int, help="Android API (default 26; RISC-V requires 35+)")
    parser.add_argument("--toolchain", help="Rust toolchain; RISC-V default nightly-2026-09-23")
    parser.add_argument("--install-target", action="store_true", help="Install missing toolchain/target (RISC-V: rust-src)")
    parser.add_argument("--offline", action="store_true", help="Cargo offline; cannot combine with --install-target")
    parser.add_argument("--jobs", type=int)
    parser.add_argument("--output-dir", type=Path, help="Copy successful build artifact here; default dist/userspace/<arch>/<profile>")
    parser.add_argument("--dry-run", action="store_true", help="Validate NDK and print configuration without running cargo/rustup")
    args = parser.parse_args(argv)
    args.arch = ALIASES.get(args.arch, args.arch)
    if args.arch not in ARCHES:
        parser.error("Unsupported arch; choose arm64, x86_64 or riscv64")
    if args.jobs is not None and args.jobs < 1:
        parser.error("--jobs must be positive")
    if args.offline and args.install_target:
        parser.error("--offline cannot combine with --install-target")
    args.api = args.api if args.api is not None else (35 if args.arch == "riscv64" else 26)
    if args.api < (35 if args.arch == "riscv64" else 21):
        parser.error("API must be >=21, or >=35 for RISC-V")
    if args.arch == "riscv64":
        args.toolchain = args.toolchain or "nightly-2026-09-23"
        if not args.toolchain.startswith("nightly"):
            parser.error("RISC-V requires a nightly toolchain for build-std")
    return args


def main(argv=None):
    args = parse_args(argv)
    if not shutil.which("cargo") or not shutil.which("rustup"):
        raise RuntimeError("Install Rust with rustup first, then restart your terminal.")
    ndk = find_ndk(args.ndk)
    tools = host_tools(ndk)
    triple = ARCHES[args.arch]
    env, clang = build_environment(tools, triple, args.api)
    # Respect an externally configured target directory, but resolve it against
    # the repository root, like Cargo invoked below.
    target_dir = Path(env.get("CARGO_TARGET_DIR", str(ROOT / "target")))
    if not target_dir.is_absolute():
        target_dir = ROOT / target_dir
    env["CARGO_TARGET_DIR"] = str(target_dir.resolve())
    cargo = ["cargo"] + (["+" + args.toolchain] if args.toolchain else [])
    rustup_tc = ["--toolchain", args.toolchain] if args.toolchain else []
    command = cargo + [args.action, "--manifest-path", str(ROOT / "Cargo.toml"),
                       "--package", args.package, "--target", triple, "--locked"]
    if not args.debug:
        command.append("--release")
    if args.offline:
        command.append("--offline")
    if args.jobs:
        command += ["--jobs", str(args.jobs)]
    if args.arch == "riscv64":
        command += ["--config", str(ROOT / ".github/riscv64-cargo.toml"), "-Z", "build-std=std,panic_abort"]
    if args.package == "ksuinit":
        # Match CI: init is a static executable, not an ordinary Android daemon.
        resource = (tools / "lib/clang")
        versions = sorted(resource.iterdir(), key=version_key, reverse=True)
        arch = {"arm64": "aarch64", "x86_64": "x86_64", "riscv64": "riscv64"}[args.arch]
        builtins = next((v / f"lib/linux/libclang_rt.builtins-{arch}-android.a" for v in versions
                         if (v / f"lib/linux/libclang_rt.builtins-{arch}-android.a").is_file()), None)
        if builtins is None:
            raise RuntimeError("Cannot find NDK static compiler builtins for ksuinit")
        extra = ["-C", "target-feature=+crt-static", "-C", "link-arg=-Wl,-z,max-page-size=16384",
                 "-C", "link-arg=-Wno-unused-command-line-argument", "-C", "link-arg=" + str(builtins)]
        existing = env.get("CARGO_ENCODED_RUSTFLAGS")
        if existing is None:
            existing = "\x1f".join(shlex.split(env.get("RUSTFLAGS", "")))
        env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(([existing] if existing else []) + extra)
    print(f"NDK: {ndk}\nTarget: {triple}, API {args.api}\nPackage: {args.package}", flush=True)
    if args.dry_run:
        for key in sorted(env):
            if key.startswith(("CC_", "CXX_", "AR_", "CARGO_TARGET_", "BINDGEN_EXTRA_CLANG_ARGS_")) or key in ("LIBCLANG_PATH", "CARGO_ENCODED_RUSTFLAGS"):
                print(f"{key}={env[key]}")
        print("Command: " + subprocess.list2cmdline(command))
        return 0
    if args.install_target:
        if args.toolchain:
            run(["rustup", "toolchain", "install", args.toolchain, "--profile", "minimal"], env)
        if args.arch == "riscv64":
            run(["rustup", "component", "add", "rust-src"] + rustup_tc, env)
        else:
            run(["rustup", "target", "add", triple] + rustup_tc, env)
    elif args.arch != "riscv64":
        installed = run(["rustup", "target", "list", "--installed"] + rustup_tc, env, capture=True).stdout.splitlines()
        if triple not in installed:
            raise RuntimeError(f"Rust target {triple} missing. Run again with --install-target.")
    run(command, env)
    if args.action == "build":
        profile = "debug" if args.debug else "release"
        artifact = target_dir / triple / profile / args.package
        require_file(artifact)
        destination = args.output_dir or ROOT / "dist/userspace" / args.arch / profile
        destination = destination.expanduser().resolve()
        destination.mkdir(parents=True, exist_ok=True)
        output = destination / args.package
        if artifact.resolve() != output:
            shutil.copy2(artifact, output)
        print(f"\nBuilt: {artifact}\nCopied: {output}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except subprocess.CalledProcessError as error:
        print(f"Build command failed (exit {error.returncode}).", file=sys.stderr)
        sys.exit(error.returncode or 1)
    except (OSError, RuntimeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)
