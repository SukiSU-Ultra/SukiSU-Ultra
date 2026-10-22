#!/usr/bin/env python3
"""No compiler/network needed: python -m unittest discover -s userspace -p 'test_build.py'."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("android_build", Path(__file__).with_name("build.py"))
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class BuildScriptTests(unittest.TestCase):
    def test_defaults_and_aliases(self):
        args = build.parse_args([])
        self.assertEqual((args.arch, args.api, args.package), ("arm64", 26, "ksud"))
        self.assertEqual(build.parse_args(["--arch", "aarch64-linux-android"]).arch, "arm64")
        args = build.parse_args(["--arch", "riscv64"])
        self.assertEqual(args.api, 35)
        self.assertTrue(args.toolchain.startswith("nightly"))

    def test_reject_invalid_combinations(self):
        for argv in [["--jobs", "0"], ["--arch", "armv7"], ["--api", "20"],
                     ["--offline", "--install-target"],
                     ["--arch", "riscv64", "--api", "26"],
                     ["--arch", "riscv64", "--toolchain", "stable"]]:
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    build.parse_args(argv)

    def test_environment_handles_spaces_without_global_changes(self):
        with tempfile.TemporaryDirectory(prefix="NDK with spaces ") as tmp:
            ndk = Path(tmp)
            tools = ndk / "toolchains/llvm/prebuilt/windows-x86_64"
            binary = tools / "bin"
            binary.mkdir(parents=True)
            for name in ["clang.exe", "aarch64-linux-android26-clang.cmd",
                         "aarch64-linux-android26-clang++.cmd", "llvm-ar.exe", "libclang.dll"]:
                (binary / name).touch()
            before = os.environ.copy()
            with patch.object(build.platform, "system", return_value="Windows"):
                self.assertEqual(build.find_ndk(str(ndk)), ndk.resolve())
                self.assertEqual(build.host_tools(ndk), tools)
                env, _ = build.build_environment(tools, "aarch64-linux-android", 26)
            self.assertEqual(env["ANDROID_NDK_HOME"], str(ndk))
            self.assertIn('-isystem "', env["BINDGEN_EXTRA_CLANG_ARGS_aarch64_linux_android"])
            self.assertEqual(env["LIBCLANG_PATH"], str(binary))
            self.assertEqual(os.environ.copy(), before)

    def test_invalid_explicit_ndk_does_not_silently_fall_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(RuntimeError):
                build.find_ndk(tmp)


if __name__ == "__main__":
    unittest.main()
