# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Wave-5 integration and command-construction gates for installer.py.

Covers: _probe_version_command (real frida binary invocation), _detect_vs_generator
(cmake --help output parsing), _find_cmake (shutil.which PATH-based discovery),
build_x64dbg_plugin (full configure + build command construction and flag
correctness).

_install_frida is UNTESTABLE in the sandbox because the sandbox runs with no
network access; pip cannot reach PyPI, and no pre-built frida wheel is staged
locally.  See the UNTESTABLE annotation at the bottom of this module.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path
from subprocess import CompletedProcess
from typing import cast

import pytest

from intellicrack.bridges import installer as installer_mod
from intellicrack.bridges.installer import (
    TOOL_REGISTRY,
    ToolInfo,
    ToolInstaller,
    ToolVersion,
    build_x64dbg_plugin,
)
from intellicrack.core.types import ToolName


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows only")

# Private symbols accessed via getattr + cast to avoid reportPrivateUsage.
# The existing test_installer.py audit3 file uses the same pattern; see line 77.
_detect_vs_generator_fn: Callable[[Path], str | None] = cast(
    Callable[[Path], str | None],
    getattr(installer_mod, "_detect_vs_generator"),
)
_find_cmake_fn: Callable[[], Path | None] = cast(
    Callable[[], Path | None],
    getattr(installer_mod, "_find_cmake"),
)
_tool_installer_version_cls = getattr(installer_mod, "_ToolInstallerVersion")
_parse_version_fn: Callable[[str], ToolVersion | None] = cast(
    Callable[[str], ToolVersion | None],
    getattr(_tool_installer_version_cls, "parse"),
)
_probe_version_command_fn: Callable[
    [ToolName, Path, ToolInfo],
    Awaitable[ToolVersion | None],
] = cast(
    Callable[[ToolName, Path, ToolInfo], Awaitable[ToolVersion | None]],
    getattr(ToolInstaller, "_probe_version_command"),
)

# Frida availability: captured at import time so the oracle string is not
# re-derived inside the async test function.
_frida_available: bool = False
_frida_version: str = ""

try:
    import frida as _tmp_frida

    _frida_available = True
    _frida_version = _tmp_frida.__version__
except ImportError:
    pass


class _FakeSubprocessRun:
    """Callable fake for ``subprocess.run`` that records every invocation.

    Monkeypatched in place of ``installer_mod._subprocess_run`` so that
    the SUT's cmake path-detection and build logic can be exercised without
    a real cmake binary.  The SUT's decision logic (regex parsing, flag
    assembly) still runs; only the OS-level subprocess call is intercepted.
    """

    def __init__(self, cmake_help_stdout: str) -> None:
        """Initialise the fake with a canned cmake --help response.

        Args:
            cmake_help_stdout: stdout to return when ``--help`` appears in the
                argument list; empty string is returned for all other calls.
        """
        self._cmake_help_stdout: str = cmake_help_stdout
        self.captured_calls: list[list[str]] = []

    def __call__(self, args: list[str], **_kwargs: object) -> CompletedProcess[str]:
        """Record the call and return the canned stdout.

        Args:
            args: Subprocess argument list passed by the SUT.
            **_kwargs: All keyword arguments (stdout=, stderr=, text=, …) are
                silently consumed; the caller may use any keyword convention.

        Returns:
            CompletedProcess[str]: Completed process with returncode 0 and
                the pre-configured stdout for ``--help`` calls.
        """
        self.captured_calls.append(list(args))
        out: str = self._cmake_help_stdout if "--help" in args else ""
        return CompletedProcess(args=args, returncode=0, stdout=out, stderr="")


class TestProbeVersionCommandRealBinary:
    """Verify _probe_version_command parses a real binary's output correctly.

    Uses the FRIDA ToolInfo entry from TOOL_REGISTRY, which issues
    ``sys.executable -c "import frida; print(frida.__version__)"`` — a real
    subprocess against the installed frida package.

    Oracle: ``frida.__version__`` imported directly (captured at module-load
    time in ``_frida_version``) is the ground-truth version string; the SUT
    subprocess path must parse to the same major/minor/raw.

    Mutation caught: if _probe_version_command does not actually run the
    subprocess (returns None early), the assertion that ``version is not None``
    fails.  If ``_ToolInstallerVersion.parse`` breaks the major extraction,
    the major comparison fails.
    """

    @pytest.mark.asyncio
    async def test_probe_frida_version_returns_parsed_version(self) -> None:
        """Invoke real frida via subprocess and assert parsed major matches frida.__version__."""
        if not _frida_available:
            pytest.skip("frida not importable — cannot establish oracle")
            return

        oracle_raw: str = _frida_version
        oracle_parsed: ToolVersion | None = _parse_version_fn(oracle_raw)
        assert oracle_parsed is not None, f"Oracle parse failed for {oracle_raw!r}"

        tool_info: ToolInfo = TOOL_REGISTRY[ToolName.FRIDA]
        version: ToolVersion | None = await _probe_version_command_fn(
            ToolName.FRIDA,
            Path(),
            tool_info,
        )

        assert version is not None, f"_probe_version_command returned None; frida.__version__={oracle_raw!r}"
        assert version.major == oracle_parsed.major, (
            f"major mismatch: SUT={version.major}, oracle={oracle_parsed.major} (raw={version.raw!r})"
        )
        assert version.minor == oracle_parsed.minor, f"minor mismatch: SUT={version.minor}, oracle={oracle_parsed.minor}"
        assert version.raw == oracle_raw, f"raw version mismatch: SUT returned {version.raw!r}, oracle is {oracle_raw!r}"


class TestDetectVsGenerator:
    """Verify _detect_vs_generator parses cmake --help output and picks the highest version.

    The subprocess transport boundary (``_subprocess_run`` = ``subprocess.run``)
    is patched at the installer module level to return canned cmake --help text.
    The SUT's own parsing logic (``re.search``, version comparison) still runs
    against the injected output.  This is analogous to injecting a canned HTTP
    response: the transport is mocked, the business logic is not.

    Oracle: the injected cmake --help output is fully known; the highest-version
    generator in it is "Visual Studio 17 2022".

    Mutation caught: if the regex pattern or version comparison logic is wrong,
    the returned generator differs from "Visual Studio 17 2022".
    """

    def test_picks_highest_visual_studio_version_from_help_output(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Assert _detect_vs_generator returns the generator with the highest year.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        cmake_help_output = (
            "Generators\n"
            "\n"
            "  Visual Studio 16 2019        = Generates Visual Studio 2019 project files.\n"
            "  Visual Studio 17 2022        = Generates Visual Studio 2022 project files.\n"
            "  Ninja                        = Generates build.ninja files.\n"
        )
        fake_run = _FakeSubprocessRun(cmake_help_output)
        monkeypatch.setattr(installer_mod, "_subprocess_run", fake_run)

        result: str | None = _detect_vs_generator_fn(Path(r"C:\fake\cmake.exe"))

        assert result == "Visual Studio 17 2022", f"Expected 'Visual Studio 17 2022', got {result!r}"

    def test_returns_none_when_no_vs_generators_present(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Assert _detect_vs_generator returns None when cmake --help has no VS entries.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        fake_run = _FakeSubprocessRun("Generators\n  Ninja\n  Unix Makefiles\n")
        monkeypatch.setattr(installer_mod, "_subprocess_run", fake_run)

        result: str | None = _detect_vs_generator_fn(Path(r"C:\fake\cmake.exe"))

        assert result is None, f"Expected None when no VS generators present, got {result!r}"


class TestFindCmakePathDiscovery:
    """Verify _find_cmake finds cmake via shutil.which when it is on PATH.

    A real cmake.exe stub (zero-byte) is placed in a temporary directory.
    The directory is prepended to PATH so ``shutil.which("cmake")`` finds it.

    Oracle: shutil.which operates against the real filesystem and real PATH;
    the returned Path must resolve into our temp directory.

    Mutation caught: if _find_cmake does not call ``shutil.which`` (or ignores
    its result), it returns None and the ``is not None`` assertion fails.
    """

    def test_find_cmake_finds_stub_on_path(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Place cmake.exe stub in tmp_path, prepend to PATH, assert _find_cmake returns it.

        Args:
            tmp_path: pytest temporary directory.
            monkeypatch: pytest monkeypatch fixture.
        """
        cmake_stub = tmp_path / "cmake.exe"
        cmake_stub.write_bytes(b"")

        original_path = os.environ.get("PATH", "")
        monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + original_path)

        result: Path | None = _find_cmake_fn()

        assert result is not None, "_find_cmake returned None; expected to find cmake.exe stub"
        assert result.stem.lower() == "cmake", f"Found executable has wrong stem: {result.stem!r}"
        assert result.resolve().parent.resolve() == tmp_path.resolve(), f"Found cmake not in expected temp dir: {result}"

    def test_find_cmake_returns_none_when_not_on_path_and_no_vswhere(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Assert _find_cmake returns None when cmake is absent from PATH and vswhere unavailable.

        Args:
            tmp_path: Empty pytest temporary directory with no cmake.
            monkeypatch: pytest monkeypatch fixture.
        """
        monkeypatch.setenv("PATH", str(tmp_path))
        monkeypatch.setenv("PROGRAMFILES(X86)", str(tmp_path))

        result: Path | None = _find_cmake_fn()

        assert result is None, f"Expected None when cmake is absent, got {result!r}"


class TestBuildX64dbgPluginCommandConstruction:
    """Verify build_x64dbg_plugin issues cmake commands with the correct flags.

    A cmake.exe stub (zero-byte, found by shutil.which) is placed in PATH.
    The subprocess transport boundary (``_subprocess_run``) is patched to
    record every call and return success.  The cmake --help response includes a
    VS generator line so ``_detect_vs_generator`` returns a non-None generator.

    Oracle: the captured configure command must contain exactly the expected
    -G generator flag, -A architecture flag, -DBUILD_X64 flag, and -DX64DBG_PATH.

    Mutation caught: if build_x64dbg_plugin omits the -G flag or uses the
    wrong architecture flag, the corresponding assertion fails.
    """

    def test_cmake_configure_command_has_correct_flags(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Assert cmake configure call includes -G, -A x64, -DBUILD_X64=ON, -DX64DBG_PATH.

        Args:
            tmp_path: pytest temporary directory.
            monkeypatch: pytest monkeypatch fixture.
        """
        cmake_stub = tmp_path / "cmake.exe"
        cmake_stub.write_bytes(b"")

        original_path = os.environ.get("PATH", "")
        monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + original_path)

        expected_generator = "Visual Studio 17 2022"
        cmake_help_stdout = f"Generators\n  {expected_generator}\n  Ninja\n"
        fake_run = _FakeSubprocessRun(cmake_help_stdout)
        monkeypatch.setattr(installer_mod, "_subprocess_run", fake_run)

        plugin_dir = tmp_path / "plugin"
        plugin_dir.mkdir()
        x64dbg_path = tmp_path / "x64dbg"
        sdk_path = x64dbg_path / "pluginsdk"
        sdk_path.mkdir(parents=True)
        (sdk_path / "bridgemain.h").write_bytes(b"")

        result = build_x64dbg_plugin(plugin_dir, x64dbg_path)

        captured_calls: list[list[str]] = fake_run.captured_calls

        assert result is True, f"build_x64dbg_plugin returned False; captured calls: {captured_calls}"

        configure_calls = [c for c in captured_calls if str(plugin_dir) in c]
        assert configure_calls, f"No cmake configure calls found; all calls: {captured_calls}"

        x64_configure = next(
            (c for c in configure_calls if "-DBUILD_X64=ON" in c),
            None,
        )
        assert x64_configure is not None, f"No configure call with -DBUILD_X64=ON found; configure calls: {configure_calls}"

        assert "-G" in x64_configure, f"Missing -G flag in configure call: {x64_configure}"
        g_idx = x64_configure.index("-G")
        assert g_idx + 1 < len(x64_configure), "No generator string follows -G"
        assert x64_configure[g_idx + 1] == expected_generator, (
            f"Generator mismatch: expected {expected_generator!r}, got {x64_configure[g_idx + 1]!r}"
        )

        assert "-A" in x64_configure, f"Missing -A flag in configure call: {x64_configure}"
        a_idx = x64_configure.index("-A")
        assert a_idx + 1 < len(x64_configure), "No architecture string follows -A"
        assert x64_configure[a_idx + 1] == "x64", f"Architecture mismatch: expected 'x64', got {x64_configure[a_idx + 1]!r}"

        expected_x64dbg_sdk_flag = f"-DX64DBG_SDK_PATH={sdk_path}"
        assert expected_x64dbg_sdk_flag in x64_configure, f"-DX64DBG_SDK_PATH not set correctly in configure call: {x64_configure}"

    def test_cmake_build_command_uses_release_config(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Assert cmake build call uses '--config Release'.

        Args:
            tmp_path: pytest temporary directory.
            monkeypatch: pytest monkeypatch fixture.
        """
        cmake_stub = tmp_path / "cmake.exe"
        cmake_stub.write_bytes(b"")

        original_path = os.environ.get("PATH", "")
        monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + original_path)

        fake_run = _FakeSubprocessRun("  Visual Studio 17 2022\n")
        monkeypatch.setattr(installer_mod, "_subprocess_run", fake_run)

        plugin_dir = tmp_path / "plugin2"
        plugin_dir.mkdir()
        x64dbg_path = tmp_path / "x64dbg2"
        sdk_path = x64dbg_path / "pluginsdk"
        sdk_path.mkdir(parents=True)
        (sdk_path / "bridgemain.h").write_bytes(b"")

        result = build_x64dbg_plugin(plugin_dir, x64dbg_path)

        captured_calls: list[list[str]] = fake_run.captured_calls
        assert result is True

        build_calls = [c for c in captured_calls if "--build" in c]
        assert build_calls, f"No cmake --build calls found; all calls: {captured_calls}"

        build_cmd = build_calls[0]
        assert "--build" in build_cmd
        assert "--config" in build_cmd
        config_idx = build_cmd.index("--config")
        assert build_cmd[config_idx + 1] == "Release", f"Expected --config Release, got {build_cmd[config_idx + 1]!r}"


# UNTESTABLE finding annotation
#
# Finding: _install_frida real pip invocation (installer.py line ~700)
# Status: UNTESTABLE in the sandbox environment.
#
# Structural reason: _install_frida_impl invokes pip as a subprocess to download
# and install frida from PyPI.  The sandbox runs with no network access, so pip
# cannot reach PyPI.  No pre-staged local frida wheel is available either.  Even
# with frida already installed, upgrading without network fails with a non-zero
# exit code when the live PyPI check cannot be performed.
#
# What would make this testable: stage a local frida wheel in the CI image and
# run pip with --find-links pointing to a local directory and --no-index, or
# use a pip-cache volume seeded with the frida distribution.  Until then, the
# real pip-install success path cannot be exercised deterministically in a
# network-isolated environment.
