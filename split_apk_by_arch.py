#!/usr/bin/env python3
"""Split a multi-arch APK into one single-arch APK per architecture.

For each requested architecture, all lib/<other-arch>/ entries are dropped,
the remaining entries are copied verbatim, then the result is zipaligned
(16 KB page alignment) and re-signed with apksigner.

Output naming keeps the full original name and inserts the arch before the
build type, e.g.:

    SukiSU_v4.2.1-r1_41050-release.apk
        -> SukiSU_v4.2.1-r1_41050-arm64-v8a-release.apk
    SukiSU_v4.2.1-r1_41050-release-spoofed.apk
        -> SukiSU_v4.2.1-r1_41050-arm64-v8a-release-spoofed.apk

Signing options mirror repack_apk.py so existing secrets/keys keep working.
"""

import argparse
import os
import sys
import tempfile
from pathlib import Path
from typing import List, Optional
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

# Reuse the helpers already present in repack_apk.py to keep behavior
# identical (SDK discovery, command execution, workspace root).
from repack_apk import (
    find_android_tool,
    run_cmd,
    workspace_root,
)


def list_apk_arches(apk_path: Path) -> List[str]:
    arches: List[str] = []
    seen = set()
    with ZipFile(apk_path, "r") as zin:
        for name in zin.namelist():
            if not name.startswith("lib/"):
                continue
            parts = name.split("/")
            if len(parts) >= 3 and parts[1] and parts[1] not in seen:
                seen.add(parts[1])
                arches.append(parts[1])
    return arches


def split_single_arch(
    apk_path: Path,
    out_unsigned_path: Path,
    keep_arch: str,
) -> None:
    """Write an APK that keeps only lib/<keep_arch>/ entries."""
    with ZipFile(apk_path, "r") as zin, ZipFile(out_unsigned_path, "w") as zout:
        for info in zin.infolist():
            name = info.filename
            if name.startswith("lib/"):
                parts = name.split("/")
                # Drop any library belonging to a different architecture.
                if len(parts) >= 3 and parts[1] and parts[1] != keep_arch:
                    continue

            data = zin.read(name)
            new_info = ZipInfo(filename=name, date_time=info.date_time)
            new_info.compress_type = info.compress_type
            new_info.external_attr = info.external_attr
            new_info.comment = info.comment
            new_info.create_system = info.create_system
            new_info.extra = info.extra
            if info.compress_type == ZIP_DEFLATED:
                zout.writestr(new_info, data, compress_type=ZIP_DEFLATED)
            else:
                zout.writestr(new_info, data)


def resolve_arches(apk_path: Path, requested: List[str]) -> List[str]:
    if requested:
        # Preserve requested order, drop duplicates.
        out: List[str] = []
        seen = set()
        for a in requested:
            if a and a not in seen:
                seen.add(a)
                out.append(a)
        return out

    discovered = list_apk_arches(apk_path)
    if not discovered:
        raise RuntimeError(f"No native libraries found in {apk_path}")
    return discovered


def build_output_name(apk: Path, arch: str, override_prefix: Optional[str]) -> str:
    """Build '<base>-<arch>-<buildType>[-spoofed].apk' from the input APK name.

    Input  : SukiSU_v4.2.1-r1_41050-release.apk
    Output : SukiSU_v4.2.1-r1_41050-arm64-v8a-release.apk

    Input  : SukiSU_v4.2.1-r1_41050-release-spoofed.apk
    Output : SukiSU_v4.2.1-r1_41050-arm64-v8a-release-spoofed.apk

    If the input has no recognizable build type, fall back to
    '<stem>-<arch>.apk'.
    """
    stem = override_prefix if override_prefix else apk.stem

    # Peel off known trailing tags, innermost first.
    tail = ""
    for tag in ("-spoofed",):
        if stem.endswith(tag):
            tail = tag + tail
            stem = stem[: -len(tag)]

    build_type = ""
    for bt in ("-release", "-debug"):
        if stem.endswith(bt):
            build_type = bt
            stem = stem[: -len(bt)]
            break

    return f"{stem}-{arch}{build_type}{tail}.apk"


def sign_apk(
    unsigned: Path,
    aligned: Path,
    signed: Path,
    keystore: Path,
    key_alias: str,
    keystore_pass: str,
    key_pass: str,
) -> None:
    zipalign = find_android_tool("zipalign")
    if zipalign is None:
        raise FileNotFoundError("zipalign not found in PATH or Android SDK build-tools")
    run_cmd(
        [str(zipalign), "-P", "16", "-f", "4", str(unsigned), str(aligned)],
        "zipalign failed",
    )

    apksigner = find_android_tool("apksigner")
    if apksigner is None:
        raise FileNotFoundError("apksigner not found in PATH or Android SDK build-tools")
    run_cmd(
        [
            str(apksigner),
            "sign",
            "--v1-signing-enabled", "false",
            "--v2-signing-enabled", "true",
            "--v3-signing-enabled", "false",
            "--v4-signing-enabled", "false",
            "--ks", str(keystore.resolve()),
            "--ks-key-alias", key_alias,
            "--ks-pass", f"pass:{keystore_pass}",
            "--key-pass", f"pass:{key_pass}",
            "--out", str(signed),
            str(aligned),
        ],
        "apksigner failed",
    )


def do_split(args: argparse.Namespace) -> int:
    apk = Path(args.apk).resolve()
    if not apk.exists():
        raise FileNotFoundError(f"APK not found: {apk}")

    arches = resolve_arches(apk, args.arch or [])
    print(f"[INFO] Input APK : {apk}")
    print(f"[INFO] Arch list : {', '.join(arches)}")

    out_dir = Path(args.out_dir).resolve() if args.out_dir else workspace_root() / "dist" / "split"
    out_dir.mkdir(parents=True, exist_ok=True)

    keystore = Path(args.keystore_path).resolve()
    if not keystore.exists():
        raise FileNotFoundError(f"Keystore not found: {keystore}")

    for arch in arches:
        out_name = build_output_name(apk, arch, args.output_prefix)
        signed_path = out_dir / out_name
        if signed_path.exists():
            signed_path.unlink()

        with tempfile.TemporaryDirectory() as tmp_dir_str:
            tmp_dir = Path(tmp_dir_str)
            unsigned = tmp_dir / f"{arch}-unsigned.apk"
            aligned = tmp_dir / f"{arch}-aligned.apk"

            split_single_arch(apk, unsigned, arch)
            sign_apk(
                unsigned,
                aligned,
                signed_path,
                keystore,
                args.key_alias,
                args.keystore_pass,
                args.key_pass,
            )

        print(f"[OK] {arch:<16} -> {signed_path}")

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Split a multi-arch APK into per-architecture signed APKs."
    )
    parser.add_argument("-i", "--apk", required=True, help="Input multi-arch APK")
    parser.add_argument(
        "-a", "--arch", action="append",
        help="Architecture(s) to emit; repeat or use comma list. Default: every arch in the APK.",
    )
    parser.add_argument("-o", "--out-dir", help="Output directory (default: dist/split)")
    parser.add_argument(
        "-n", "--output-prefix",
        help=(
            "Override the output name base (default: input APK stem). "
            "Arch and build type are still inserted automatically."
        ),
    )
    parser.add_argument("-K", "--keystore-path", required=True, help="Keystore path")
    parser.add_argument("-A", "--key-alias", required=True, help="Key alias")
    parser.add_argument("-P", "--keystore-pass", required=True, help="Keystore password")
    parser.add_argument("-S", "--key-pass", required=True, help="Private key password")
    return parser


def main() -> int:
    os.chdir(workspace_root())
    parser = build_parser()
    args = parser.parse_args()
    try:
        return do_split(args)
    except Exception as exc:  # noqa: BLE001
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
