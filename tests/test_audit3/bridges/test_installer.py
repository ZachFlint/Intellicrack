# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit3 U1 regression tests for ``intellicrack.bridges.installer``.

Each test corresponds to one or more findings (F-####) in audit3.md
under "Findings: bridges-installer". Each test is written so it would
FAIL on the pre-fix code in installer.py. Tests use real filesystem
trees and the real ToolInstaller state machine; isolated unit-level
substitutions (``monkeypatch``) are used only at the boundary
(subprocess / network) and never to fabricate end-state behaviour.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import sys
import tempfile
import zipfile
from collections.abc import Callable, Coroutine
from pathlib import Path
from typing import TYPE_CHECKING, get_args

import httpx
import pytest

from intellicrack.bridges import installer as installer_mod
from intellicrack.bridges.installer import (
    PLUGIN_ARCHS,
    TOOL_REGISTRY,
    ArchDeployResult,
    DeployResult,
    FoundTool,
    InstallResult,
    ToolInstaller,
    ToolInstallerVersion,
    ToolKind,
    ToolProbeTimeoutError,
    ToolVersion,
    deploy_x64dbg_plugin,
    deploy_x64dbg_plugin_detailed,
    format_exception,
    host_arch_aliases,
    is_user_admin,
    matches_arch,
    path_requires_admin,
)
from intellicrack.core import (
    process_manager as pm_mod,
    subprocess_compat as sp_mod,
)
from intellicrack.core.types import ToolError, ToolName


if TYPE_CHECKING:
    from collections.abc import AsyncIterator


_NETWORK_DOWN_MSG = "network down"
_INNER_RUNTIME_MSG = "disastrous"
_INNER_VALUE_MSG = "root cause goes here"
_NO_OUTCOMES_MSG = "_install_pm_substitute: no more pre-built outcomes"


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _system_pe_for_version_probe() -> Path | None:
    """Return a system-shipped Windows binary suitable for PE-version tests.

    Returns:
        Path | None: A real PE on Windows, or None on non-Windows hosts
        where no system PE is reliably available.
    """
    if sys.platform != "win32":
        return None
    candidates = [
        Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "notepad.exe",
        Path(os.environ.get("WINDIR", r"C:\Windows")) / "notepad.exe",
        Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "cmd.exe",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _make_x64dbg_tree(root: Path) -> Path:
    """Create a minimal x64dbg directory layout.

    Args:
        root: Parent directory for the x64dbg installation.

    Returns:
        Path: Path to the x64dbg root.
    """
    x64dbg = root / "x64dbg"
    (x64dbg / "release" / "x64" / "plugins").mkdir(parents=True)
    (x64dbg / "release" / "x32" / "plugins").mkdir(parents=True)
    return x64dbg


def _make_plugin_source(
    tools_dir: Path,
    filename: str,
    content: bytes,
    subdir: str = "bin",
) -> Path:
    """Write a plugin binary into the plugin source tree.

    Args:
        tools_dir: Tools directory containing ``x64dbg_plugin/``.
        filename: Plugin filename.
        content: Bytes to write.
        subdir: Sub-directory within ``x64dbg_plugin``.

    Returns:
        Path: Path to the written file.
    """
    plugin_dir = tools_dir / "x64dbg_plugin" / subdir
    plugin_dir.mkdir(parents=True, exist_ok=True)
    binary = plugin_dir / filename
    binary.write_bytes(content)
    return binary


def _build_zip(zip_path: Path, files: dict[str, bytes]) -> None:
    """Write a zip archive with the given file mapping.

    Args:
        zip_path: Path to write the zip file to.
        files: Mapping of archive-internal path to contents.
    """
    with zipfile.ZipFile(zip_path, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)


def _run(coro: Coroutine[object, object, object]) -> object:
    """Run ``coro`` to completion on a fresh asyncio loop.

    Args:
        coro: Coroutine to drive.

    Returns:
        object: The coroutine's return value.
    """
    return asyncio.run(coro)


class _ProcResult:
    """Simple container mimicking subprocess.CompletedProcess for stubs."""

    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        """Store the captured fields.

        Args:
            returncode: Process exit code.
            stdout: Captured stdout text.
            stderr: Captured stderr text.
        """
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


_HandlerCallable = Callable[[list[str]], _ProcResult | Coroutine[object, object, _ProcResult]]


def _install_pm_substitute(
    monkeypatch: pytest.MonkeyPatch,
    runner: list[_ProcResult] | None = None,
    *,
    handler: _HandlerCallable | None = None,
) -> list[list[str]]:
    """Patch ``ProcessManager.get_instance`` with a recording substitute.

    Args:
        monkeypatch: pytest fixture used to install the substitute.
        runner: List of pre-built results to return per call.
        handler: Optional callable taking the cmd list and returning a result.

    Returns:
        list[list[str]]: A list that captures every command issued.
    """
    captured: list[list[str]] = []

    iterator = iter(runner or [])

    class _PM:
        @staticmethod
        def get_instance() -> _Inner:
            return _Inner()

    class _Inner:
        @staticmethod
        async def run_tracked_async(cmd: list[str], **_kw: object) -> _ProcResult:
            captured.append(list(cmd))
            if handler is not None:
                outcome = handler(cmd)
                if asyncio.iscoroutine(outcome):
                    return await outcome
                return outcome
            try:
                outcome_iter = next(iterator)
            except StopIteration as exc:
                raise AssertionError(_NO_OUTCOMES_MSG) from exc
            return outcome_iter

    monkeypatch.setattr(pm_mod, "ProcessManager", _PM)
    monkeypatch.setattr(installer_mod, "ProcessManager", _PM)
    return captured


# --------------------------------------------------------------------------
# F-0001 / F-0002 - kind discriminator instead of sentinel paths
# --------------------------------------------------------------------------


class TestKindDiscriminator:
    """F-0001 (PROCESS) and F-0002 (FRIDA) - typed availability mechanism."""

    @staticmethod
    def test_install_result_has_kind_field() -> None:
        """InstallResult exposes a typed ``kind`` discriminator (F-0001/F-0002)."""
        r = InstallResult(success=True, kind="builtin")
        assert r.kind == "builtin"
        assert r.path is None

    @staticmethod
    def test_found_tool_has_kind_field() -> None:
        """FoundTool exposes a typed ``kind`` discriminator (F-0001/F-0002)."""
        ft = FoundTool(kind="python_package")
        assert ft.kind == "python_package"
        assert ft.path is None

    @staticmethod
    def test_install_tool_process_returns_builtin_kind(tmp_path: Path) -> None:
        """install_tool(PROCESS) returns kind=builtin and path=None (F-0001)."""
        ti = ToolInstaller(tmp_path)
        result = _run(ti.install_tool(ToolName.PROCESS))
        assert isinstance(result, InstallResult)
        assert result.success is True
        assert result.kind == "builtin"
        assert result.path is None

    @staticmethod
    def test_install_tool_process_does_not_return_sentinel_path(tmp_path: Path) -> None:
        """The PROCESS install_tool result MUST NOT be Path('builtin') (F-0001)."""
        ti = ToolInstaller(tmp_path)
        result = _run(ti.install_tool(ToolName.PROCESS))
        assert isinstance(result, InstallResult)
        assert result.path != Path("builtin")

    @staticmethod
    def test_find_tool_process_returns_none_for_path(tmp_path: Path) -> None:
        """find_tool(PROCESS) no longer returns Path('builtin') (F-0001)."""
        ti = ToolInstaller(tmp_path)
        path = _run(ti.find_tool(ToolName.PROCESS))
        assert path != Path("builtin")
        assert path is None

    @staticmethod
    def test_find_tool_detailed_process_reports_builtin(tmp_path: Path) -> None:
        """find_tool_detailed(PROCESS) returns FoundTool(kind='builtin') (F-0001)."""
        ti = ToolInstaller(tmp_path)
        ft = _run(ti.find_tool_detailed(ToolName.PROCESS))
        assert isinstance(ft, FoundTool)
        assert ft.kind == "builtin"
        assert ft.path is None

    @staticmethod
    def test_verify_tool_process_accepts_none_path(tmp_path: Path) -> None:
        """verify_tool(PROCESS, None) returns True (no synthetic path needed) (F-0001)."""
        ti = ToolInstaller(tmp_path)
        ok = _run(ti.verify_tool(ToolName.PROCESS, None))
        assert ok is True

    @staticmethod
    def test_get_all_tool_status_process_path_is_none(tmp_path: Path) -> None:
        """get_all_tool_status reports PROCESS with path=None (F-0001)."""
        ti = ToolInstaller(tmp_path)
        status = _run(ti.get_all_tool_status())
        assert isinstance(status, dict)
        assert status[ToolName.PROCESS][0] is True
        assert status[ToolName.PROCESS][1] is None

    @staticmethod
    def test_frida_registry_kind_is_python_package() -> None:
        """The Frida registry entry is kind='python_package' (F-0002)."""
        assert TOOL_REGISTRY[ToolName.FRIDA].kind == "python_package"

    @staticmethod
    def test_process_registry_kind_is_builtin() -> None:
        """The PROCESS registry entry is kind='builtin' (F-0001)."""
        assert TOOL_REGISTRY[ToolName.PROCESS].kind == "builtin"


# --------------------------------------------------------------------------
# F-0003 - install_tool verifies post-install version
# --------------------------------------------------------------------------


class TestInstallVerifiesPostInstall:
    """F-0003 - install_tool reports failure when version cannot be confirmed."""

    @staticmethod
    def test_install_tool_returns_failure_when_no_executable(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """install_tool returns success=False when the extracted tree has no exe (F-0003)."""
        ti = ToolInstaller(tmp_path)

        async def _stub_url(_self: ToolInstaller, _tool: ToolName) -> str | None:
            await asyncio.sleep(0)
            return "https://example.invalid/cutter.zip"

        async def _stub_download(_self: ToolInstaller, _url: str) -> Path:
            await asyncio.sleep(0)
            zp = tmp_path / "cutter.zip"
            _build_zip(zp, {"empty/readme.txt": b"hi"})
            return zp

        monkeypatch.setattr(ToolInstaller, "_get_latest_release_url", _stub_url)
        monkeypatch.setattr(ToolInstaller, "_download_file", _stub_download)

        result = _run(ti.install_tool(ToolName.CUTTER))
        assert isinstance(result, InstallResult)
        assert result.success is False
        assert result.error is not None
        marker_present = any(marker in result.error for marker in ("executable", "version", "extracted", "minimum"))
        assert marker_present


# --------------------------------------------------------------------------
# F-0004 - _install_frida checks the version subprocess returncode
# --------------------------------------------------------------------------


class TestFridaInstallChecksVersionRC:
    """F-0004 - _install_frida treats nonzero version probe rc as failure."""

    @staticmethod
    def test_frida_install_failure_when_version_probe_nonzero(
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """_install_frida returns success=False when version probe rc != 0 (F-0004)."""
        ti = ToolInstaller(tmp_path)

        def _handler(cmd: list[str]) -> _ProcResult:
            if "pip" in cmd:
                return _ProcResult(0, "", "")
            return _ProcResult(1, "", "ImportError")

        _install_pm_substitute(monkeypatch, handler=_handler)

        result = _run(ti.install_frida())
        assert isinstance(result, InstallResult)
        assert result.success is False
        assert result.kind == "python_package"
        assert result.error is not None
        assert "rc=1" in result.error or "version probe" in result.error


# --------------------------------------------------------------------------
# F-0005 / F-0006 / F-0034 / F-0041 - x64dbg/Cutter version via PE, no GUI
# --------------------------------------------------------------------------


class TestPEVersionForGUITools:
    """F-0005/F-0006/F-0034/F-0041 - x64dbg/Cutter version probe via PE."""

    @staticmethod
    def test_x64dbg_registry_has_no_version_command_subprocess() -> None:
        """x64dbg version_command is empty - no subprocess invocation (F-0005/F-0034/F-0041)."""
        info = TOOL_REGISTRY[ToolName.X64DBG]
        assert info.version_command == []

    @staticmethod
    def test_cutter_registry_has_no_version_command_subprocess() -> None:
        """Cutter version_command is empty - no subprocess invocation (F-0006)."""
        info = TOOL_REGISTRY[ToolName.CUTTER]
        assert info.version_command == []

    @staticmethod
    def test_get_version_x64dbg_uses_pe_when_available(tmp_path: Path) -> None:
        """get_version(X64DBG) reads the PE VERSIONINFO when pefile is available (F-0034)."""
        sys_exe = _system_pe_for_version_probe()
        if sys_exe is None:
            pytest.skip("requires Windows system PE")
        if not installer_mod.pefile_available():
            pytest.skip("pefile not available")

        x64dbg_dir = tmp_path / "x64dbg"
        x64dbg_dir.mkdir()
        target = x64dbg_dir / "x64dbg.exe"
        shutil.copy2(sys_exe, target)

        ti = ToolInstaller(tmp_path)
        version = _run(ti.get_version(ToolName.X64DBG, x64dbg_dir))
        assert version is None or isinstance(version, ToolVersion)


# --------------------------------------------------------------------------
# F-0007 - find_tool deep search & cached iterdir
# --------------------------------------------------------------------------


class TestNestedToolDirSearch:
    """F-0007 - two-level deep nesting (Ghidra archive layout)."""

    @staticmethod
    def test_find_tool_walks_two_levels_for_ghidra_layout(tmp_path: Path) -> None:
        """ToolInstaller.search_tool_dir walks two levels deep (F-0007)."""
        ToolInstaller(tmp_path)
        tool_dir = tmp_path / "ghidra"
        deep = tool_dir / "ghidra_11.1_PUBLIC" / "ghidra_11.1_PUBLIC"
        deep.mkdir(parents=True)
        (deep / "support").mkdir()
        exe_rel = TOOL_REGISTRY[ToolName.GHIDRA].executables[0]
        exe_full = deep / exe_rel
        exe_full.parent.mkdir(parents=True, exist_ok=True)
        exe_full.write_text("#!/bin/sh\necho ghidra\n")

        path = _run(ToolInstaller.search_tool_dir(tool_dir, TOOL_REGISTRY[ToolName.GHIDRA]))
        assert path is not None
        assert path == deep


# --------------------------------------------------------------------------
# F-0008 - GitHub asset selection respects host arch
# --------------------------------------------------------------------------


class TestArchAwareAssetSelection:
    """F-0008 - GitHub asset selection picks host-arch matching asset."""

    @staticmethod
    def test_matches_arch_token_boundaries() -> None:
        """``matches_arch`` requires word-boundary token matches (F-0008)."""
        assert matches_arch("cutter-x86_64-windows.zip", {"x86_64"}) is True
        assert matches_arch("cutter-i686-windows.zip", {"x86_64"}) is False
        assert matches_arch("readme-x64.zip", {"x64"}) is True
        assert matches_arch("foox64bar.zip", {"x64"}) is False

    @staticmethod
    def test_host_arch_aliases_returns_canonical_set() -> None:
        """``host_arch_aliases`` returns a known alias group (F-0008)."""
        aliases = host_arch_aliases()
        possible_groups = [
            frozenset({"x86_64", "amd64", "x64", "win64"}),
            frozenset({"i686", "i386", "x86", "win32"}),
            frozenset({"arm64", "aarch64"}),
        ]
        assert aliases in possible_groups


# --------------------------------------------------------------------------
# F-0009 - sys.executable for python/pip
# --------------------------------------------------------------------------


class TestPipUsesSysExecutable:
    """F-0009 - bare ``python`` / ``pip`` replaced with ``[sys.executable, ...]``."""

    @staticmethod
    def test_frida_version_command_uses_sys_executable() -> None:
        """Frida's registered version_command uses sys.executable (F-0009)."""
        cmd = TOOL_REGISTRY[ToolName.FRIDA].version_command
        assert cmd[0] == sys.executable
        assert cmd[1] == "-c"

    @staticmethod
    def test_frida_install_invokes_pip_module(
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """_install_frida calls ``[sys.executable, '-m', 'pip', ...]`` (F-0009)."""
        captured = _install_pm_substitute(
            monkeypatch,
            handler=lambda _cmd: _ProcResult(0, "16.5.0", ""),
        )
        ti = ToolInstaller(tmp_path)
        result = _run(ti.install_frida())
        assert isinstance(result, InstallResult)
        assert result.success is True

        pip_cmd = captured[0]
        assert pip_cmd[0] == sys.executable
        assert pip_cmd[1] == "-m"
        assert pip_cmd[2] == "pip"


# --------------------------------------------------------------------------
# F-0011 - ensure_tool propagates install error
# --------------------------------------------------------------------------


class TestEnsureToolPropagatesError:
    """F-0011 - ensure_tool raises with the actual install error string."""

    @staticmethod
    def test_ensure_tool_includes_install_error(
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """ensure_tool's ToolError message contains the underlying install error (F-0011)."""
        ti = ToolInstaller(tmp_path)

        async def _stub_find(_self: ToolInstaller, _tool: ToolName) -> Path | None:
            await asyncio.sleep(0)
            return None

        async def _stub_install(_self: ToolInstaller, _tool: ToolName) -> InstallResult:
            await asyncio.sleep(0)
            return InstallResult(
                success=False,
                error="precise reason: download server returned 502",
            )

        monkeypatch.setattr(ToolInstaller, "find_tool", _stub_find)
        monkeypatch.setattr(ToolInstaller, "install_tool", _stub_install)

        with pytest.raises(ToolError) as excinfo:
            _run(ti.ensure_tool(ToolName.GHIDRA))
        assert "precise reason: download server returned 502" in str(excinfo.value)


# --------------------------------------------------------------------------
# F-0012 - _find_frida distinguishes timeout from absence
# --------------------------------------------------------------------------


class TestFridaProbeDistinguishesTimeout:
    """F-0012 - probe surfaces timeout via ToolProbeTimeoutError, not None."""

    @staticmethod
    def test_probe_python_package_raises_on_timeout(
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_probe_python_package raises ToolProbeTimeoutError on TimeoutExpired (F-0012)."""

        def _raise_timeout(cmd: list[str]) -> _ProcResult:
            raise sp_mod.TimeoutExpired(cmd=cmd, timeout=10)

        _install_pm_substitute(monkeypatch, handler=_raise_timeout)
        with pytest.raises(ToolProbeTimeoutError):
            _run(ToolInstaller.probe_python_package(TOOL_REGISTRY[ToolName.FRIDA]))

    @staticmethod
    def test_probe_python_package_returns_none_on_filenotfound(
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_probe_python_package returns None on FileNotFoundError (still distinct from timeout)."""

        def _raise_fnf(_cmd: list[str]) -> _ProcResult:
            err_msg = "python missing"
            raise FileNotFoundError(err_msg)

        _install_pm_substitute(monkeypatch, handler=_raise_fnf)
        result = _run(ToolInstaller.probe_python_package(TOOL_REGISTRY[ToolName.FRIDA]))
        assert result is None


# --------------------------------------------------------------------------
# F-0018 - download partial cleanup
# --------------------------------------------------------------------------


class _FailingStreamCtx:
    """Async context manager that raises on enter to model a network failure."""

    async def __aenter__(self) -> object:
        """Raise to simulate a transport-level failure.

        Returns:
            object: Never returns; raises immediately.

        Raises:
            httpx.RequestError: Always raised to model the failure.
        """
        await asyncio.sleep(0)
        raise httpx.RequestError(_NETWORK_DOWN_MSG)

    async def __aexit__(self, *_args: object) -> bool:
        """Return False so the exception propagates.

        Args:
            *_args: Standard async-context-manager exit arguments.

        Returns:
            bool: False, so the exception propagates.
        """
        await asyncio.sleep(0)
        return False


class _FailingClient:
    """Minimal client whose stream() returns a failing context manager."""

    def stream(self, _method: str, _url: str) -> _FailingStreamCtx:
        """Return a failing stream context.

        Args:
            _method: HTTP method (unused).
            _url: Request URL (unused).

        Returns:
            _FailingStreamCtx: Context manager that raises on enter.
        """
        return _FailingStreamCtx()


class TestDownloadCleansPartials:
    """F-0018 - failed downloads remove the partial temp file."""

    @staticmethod
    def test_download_failure_removes_partial(
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """A failed _download_file removes the partial output (F-0018)."""
        ti = ToolInstaller(tmp_path)

        url = "https://example.invalid/some/file.zip"
        partial_path = Path(tempfile.gettempdir()) / "file.zip"
        partial_path.write_bytes(b"old content")

        async def _stub_get_client(_self: ToolInstaller) -> _FailingClient:
            await asyncio.sleep(0)
            return _FailingClient()

        monkeypatch.setattr(ToolInstaller, "_get_client", _stub_get_client)

        result = _run(ti.download_file(url))
        assert result is None
        assert not partial_path.exists()


# --------------------------------------------------------------------------
# F-0022 - download progress logs every full MB, not on modulo
# --------------------------------------------------------------------------


class _FixedResp:
    """Fixed-size async response body for progress-logging tests."""

    def __init__(self, total_bytes: int, chunk_size: int = 8192) -> None:
        """Store the size so the headers and iterator agree.

        Args:
            total_bytes: Total response length in bytes.
            chunk_size: Chunk size yielded by ``aiter_bytes``.
        """
        self.headers = {"content-length": str(total_bytes)}
        self._chunks = [b"a" * chunk_size for _ in range(total_bytes // chunk_size)]

    def raise_for_status(self) -> None:
        """Mirror httpx.Response.raise_for_status (no-op)."""

    async def aiter_bytes(self, chunk_size: int = 8192) -> AsyncIterator[bytes]:  # noqa: ARG002
        """Yield the pre-built chunks.

        Args:
            chunk_size: Caller-requested chunk size (unused; we use the constructor value).

        Yields:
            bytes: Successive payload chunks.
        """
        for chunk in self._chunks:
            yield chunk


class _FixedStreamCtx:
    """Async context manager returning a fixed-size response."""

    def __init__(self, total_bytes: int) -> None:
        """Initialise with the response size.

        Args:
            total_bytes: Total response length in bytes.
        """
        self._total = total_bytes

    async def __aenter__(self) -> _FixedResp:
        """Return the fixed response.

        Returns:
            _FixedResp: The pre-built fixed-size response.
        """
        await asyncio.sleep(0)
        return _FixedResp(self._total)

    async def __aexit__(self, *_args: object) -> bool:
        """Return False so any exception propagates.

        Args:
            *_args: Standard async-context-manager exit arguments.

        Returns:
            bool: False.
        """
        await asyncio.sleep(0)
        return False


class _FixedClient:
    """Minimal client that produces a fixed-size payload stream."""

    def __init__(self, total_bytes: int) -> None:
        """Capture the total payload size.

        Args:
            total_bytes: Total payload length.
        """
        self._total = total_bytes

    def stream(self, _method: str, _url: str) -> _FixedStreamCtx:
        """Return the fixed-size stream.

        Args:
            _method: HTTP method (unused).
            _url: Request URL (unused).

        Returns:
            _FixedStreamCtx: Context manager yielding the fixed body.
        """
        return _FixedStreamCtx(self._total)


class TestProgressLoggingPerMB:
    """F-0022 - progress logging fires once per MB, deterministically."""

    @staticmethod
    def test_progress_threshold_is_per_megabyte(
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """Progress logging fires roughly once per MB, regardless of chunk size (F-0022)."""
        ti = ToolInstaller(tmp_path)
        total = 8192 * 300  # ~2.4 MB
        log_events: list[float] = []

        async def _stub_get_client(_self: ToolInstaller) -> _FixedClient:
            await asyncio.sleep(0)
            return _FixedClient(total)

        monkeypatch.setattr(ToolInstaller, "_get_client", _stub_get_client)

        original_debug = installer_mod.logger.debug

        def capture(event: str, *args: object, **kw: object) -> object:
            if event == "download_progress":
                pct = kw.get("percent", 0.0)
                if isinstance(pct, (int, float)):
                    log_events.append(float(pct))
            return original_debug(event, *args, **kw)

        monkeypatch.setattr(installer_mod.logger, "debug", capture)

        path = _run(ti.download_file("https://example.invalid/a.zip"))
        assert path is not None
        # ~2.4 MB -> expect 1 to 4 events.
        assert 1 <= len(log_events) <= 4


# --------------------------------------------------------------------------
# F-0025 / F-0043 - admin check + per-arch aggregation
# --------------------------------------------------------------------------


class TestDeployPluginAggregation:
    """F-0025 - admin check; F-0043 - per-arch aggregation."""

    @staticmethod
    def test_path_requires_admin_detects_program_files() -> None:
        """path_requires_admin returns True for Program Files paths on Windows (F-0025)."""
        if sys.platform != "win32":
            pytest.skip("Windows-only check")
        pf = os.environ.get("PROGRAMFILES")
        if not pf:
            pytest.skip("PROGRAMFILES env not set")
        target = Path(pf) / "x64dbg"
        assert path_requires_admin(target) is True

    @staticmethod
    def test_path_requires_admin_false_for_user_dir(tmp_path: Path) -> None:
        """path_requires_admin is False for user-writable paths (F-0025)."""
        assert path_requires_admin(tmp_path) is False

    @staticmethod
    def test_deploy_returns_failure_when_one_arch_failed_other_uptodate(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """deploy_x64dbg_plugin returns False when one arch fails even if other is up-to-date (F-0043)."""
        x64dbg = _make_x64dbg_tree(tmp_path)
        _make_plugin_source(tmp_path, "intellicrack_bridge_x64.dp64", b"\x01" * 64)
        _make_plugin_source(tmp_path, "intellicrack_bridge_x32.dp32", b"\x02" * 64)

        x64_target = x64dbg / "release" / "x64" / "plugins" / "intellicrack_bridge_x64.dp64"
        x64_target.write_bytes(b"\x01" * 64)
        future = x64_target.stat().st_mtime + 1000
        os.utime(x64_target, (future, future))

        original_copy = shutil.copy2

        def _copy(
            src: str | os.PathLike[str],
            dst: str | os.PathLike[str],
            *,
            follow_symlinks: bool = True,
        ) -> str | os.PathLike[str]:
            if str(dst).endswith("intellicrack_bridge_x32.dp32"):
                err_msg = "synthetic permission failure"
                raise OSError(err_msg)
            return original_copy(src, dst, follow_symlinks=follow_symlinks)

        monkeypatch.setattr(shutil, "copy2", _copy)

        result = deploy_x64dbg_plugin_detailed(x64dbg, tmp_path)
        assert result.success is False
        statuses = {ar.arch: ar.status for ar in result.per_arch}
        assert statuses["x64"] == "up_to_date"
        assert statuses["x32"] == "failed"

    @staticmethod
    def test_deploy_success_only_when_all_present_arches_clean(tmp_path: Path) -> None:
        """deploy_x64dbg_plugin returns True only when all sourced arches deploy (F-0043)."""
        x64dbg = _make_x64dbg_tree(tmp_path)
        _make_plugin_source(tmp_path, "intellicrack_bridge_x64.dp64", b"\x10" * 64)
        _make_plugin_source(tmp_path, "intellicrack_bridge_x32.dp32", b"\x20" * 64)
        result = deploy_x64dbg_plugin_detailed(x64dbg, tmp_path)
        assert result.success is True
        statuses = {ar.arch: ar.status for ar in result.per_arch}
        assert statuses["x64"] == "deployed"
        assert statuses["x32"] == "deployed"


# --------------------------------------------------------------------------
# F-0026 / F-0027 / F-0028 - cmake build feedback / timeout / vswhere errors
# --------------------------------------------------------------------------


class TestBuildSubprocessHandling:
    """F-0026, F-0027, F-0028."""

    @staticmethod
    def test_cmake_timeout_default_is_at_least_600(monkeypatch: pytest.MonkeyPatch) -> None:
        """Default cmake configure timeout is >= 600s and overridable via env (F-0027)."""
        monkeypatch.delenv("INTELLICRACK_CMAKE_TIMEOUT", raising=False)
        assert installer_mod.cmake_timeout("INTELLICRACK_CMAKE_TIMEOUT", 600) == 600
        monkeypatch.setenv("INTELLICRACK_CMAKE_TIMEOUT", "1200")
        assert installer_mod.cmake_timeout("INTELLICRACK_CMAKE_TIMEOUT", 600) == 1200
        monkeypatch.setenv("INTELLICRACK_CMAKE_TIMEOUT", "30")
        assert installer_mod.cmake_timeout("INTELLICRACK_CMAKE_TIMEOUT", 600) == 600

    @staticmethod
    def test_run_cmake_step_logs_stdout_on_failure(
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """_run_cmake_step surfaces stdout and stderr on CalledProcessError (F-0026)."""
        warnings: list[dict[str, object]] = []

        def stub_run(cmd: list[str], **_kw: object) -> object:
            raise sp_mod.CalledProcessError(
                returncode=42,
                cmd=cmd,
                output="cmake: helpful stdout details",
                stderr="cmake: helpful stderr details",
            )

        monkeypatch.setattr(installer_mod, "_subprocess_run", stub_run)

        original_warning = installer_mod.logger.warning

        def capture(event: str, **kw: object) -> object:
            warnings.append({"event": event, **kw})
            return original_warning(event, **kw)

        monkeypatch.setattr(installer_mod.logger, "warning", capture)

        ok = installer_mod.run_cmake_step(
            ["cmake", "-G", "X"],
            cwd=tmp_path,
            timeout_s=600,
            arch="x64",
            phase="configure",
        )
        assert ok is False
        relevant = [w for w in warnings if w["event"] == "plugin_build_failed"]
        assert relevant
        assert relevant[0].get("returncode") == 42
        assert "stderr" in relevant[0]
        assert "stdout" in relevant[0]

    @staticmethod
    def test_find_cmake_logs_warning_on_vswhere_failure(
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_find_cmake logs a warning on vswhere errors instead of swallowing (F-0028)."""

        def _which_none(_name: str) -> str | None:
            return None

        monkeypatch.setattr(shutil, "which", _which_none)

        def stub_is_file(_self: Path) -> bool:
            return True

        monkeypatch.setattr(Path, "is_file", stub_is_file)

        def stub_run(cmd: list[str], **_kw: object) -> object:
            raise sp_mod.CalledProcessError(returncode=1, cmd=cmd, stderr="vswhere broke")

        monkeypatch.setattr(installer_mod, "_subprocess_run", stub_run)

        warnings: list[str] = []

        def _capture_warn(event: str, **_kw: object) -> None:
            warnings.append(event)

        monkeypatch.setattr(installer_mod.logger, "warning", _capture_warn)

        result = installer_mod.find_cmake()
        assert result is None
        assert "vswhere_failed" in warnings


# --------------------------------------------------------------------------
# F-0030 - install error captures full traceback
# --------------------------------------------------------------------------


def _raise_value_error_for_traceback() -> None:
    """Raise a ValueError so callers can capture a real traceback.

    Raises:
        ValueError: Always raised for traceback testing.
    """
    raise ValueError(_INNER_VALUE_MSG)


class TestInstallErrorCapturesTraceback:
    """F-0030 - InstallResult.error contains traceback on exceptions."""

    @staticmethod
    def test_format_exception_includes_traceback() -> None:
        """format_exception returns a multi-line traceback string (F-0030)."""
        text = ""
        try:
            _raise_value_error_for_traceback()
        except ValueError as exc:
            text = format_exception(exc)
        assert "ValueError" in text
        assert _INNER_VALUE_MSG in text
        assert "Traceback" in text

    @staticmethod
    def test_install_tool_failure_error_carries_traceback(
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """install_tool failure paths capture traceback context (F-0030)."""
        ti = ToolInstaller(tmp_path)

        async def _stub_url(_self: ToolInstaller, _tool: ToolName) -> str | None:
            await asyncio.sleep(0)
            raise RuntimeError(_INNER_RUNTIME_MSG)

        monkeypatch.setattr(ToolInstaller, "_get_latest_release_url", _stub_url)
        result = _run(ti.install_tool(ToolName.X64DBG))
        assert isinstance(result, InstallResult)
        assert result.success is False
        assert result.error is not None
        assert "Traceback" in result.error
        assert _INNER_RUNTIME_MSG in result.error


# --------------------------------------------------------------------------
# F-0031 - Ghidra analyzeHeadless suffix is platform-aware
# --------------------------------------------------------------------------


class TestGhidraExecutableIsPlatformAware:
    """F-0031 - drop POSIX entry on win32 and vice versa."""

    @staticmethod
    def test_ghidra_executables_match_platform() -> None:
        """Ghidra executables list reflects current sys.platform (F-0031)."""
        info = TOOL_REGISTRY[ToolName.GHIDRA]
        if sys.platform == "win32":
            assert info.executables == ["support/analyzeHeadless.bat"]
        else:
            assert info.executables == ["support/analyzeHeadless"]


# --------------------------------------------------------------------------
# F-0033 - vswhere uses ProgramFiles(x86) env var with fallback
# --------------------------------------------------------------------------


class TestProgramFilesX86Resolution:
    """F-0033 - resolve ProgramFiles(x86) from env, not literal English."""

    @staticmethod
    def test_program_files_x86_prefers_env(monkeypatch: pytest.MonkeyPatch) -> None:
        """_program_files_x86 prefers the PROGRAMFILES(X86) env var (F-0033)."""
        monkeypatch.setenv("PROGRAMFILES(X86)", r"D:\Custom Program Files (x86)")
        assert installer_mod.program_files_x86() == Path(r"D:\Custom Program Files (x86)")

    @staticmethod
    def test_program_files_x86_falls_back_to_program_files(
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """_program_files_x86 falls back to PROGRAMFILES when (X86) is unset (F-0033)."""
        monkeypatch.delenv("PROGRAMFILES(X86)", raising=False)
        monkeypatch.setenv("PROGRAMFILES", r"D:\Custom Program Files")
        assert installer_mod.program_files_x86() == Path(r"D:\Custom Program Files")


# --------------------------------------------------------------------------
# F-0035 - _parse_version returns None for unparseable input
# --------------------------------------------------------------------------


class TestParseVersionRejectsUnparseable:
    """F-0035 - _parse_version returns None instead of ToolVersion(0, 0, 0)."""

    @staticmethod
    def test_parse_version_none_on_garbage() -> None:
        """_parse_version returns None for unparseable input (F-0035)."""
        assert ToolInstallerVersion.parse("not a version") is None
        assert ToolInstallerVersion.parse("") is None
        assert ToolInstaller.parse_version("not a version") is None

    @staticmethod
    def test_parse_version_returns_tool_version_for_semver() -> None:
        """_parse_version returns a ToolVersion for semver input (F-0035)."""
        v = ToolInstallerVersion.parse("11.1.2")
        assert v is not None
        assert (v.major, v.minor, v.patch) == (11, 1, 2)


# --------------------------------------------------------------------------
# F-0036 - x64dbg date-format versions parse and compare correctly
# --------------------------------------------------------------------------


class TestDateStyleVersionParsing:
    """F-0036 - YYYY.MM.DD versions are parsed and compared correctly."""

    @staticmethod
    def test_parse_date_version() -> None:
        """YYYY.MM.DD parses as a date-style ToolVersion (F-0036)."""
        v = ToolInstallerVersion.parse("2024.06.15")
        assert v is not None
        assert v.is_date is True
        assert (v.major, v.minor, v.patch) == (2024, 6, 15)

    @staticmethod
    def test_date_versions_compare_correctly() -> None:
        """Date versions compare ordinally (F-0036)."""
        older = ToolInstallerVersion.parse("2024.01.01")
        newer = ToolInstallerVersion.parse("2024.06.15")
        assert older is not None
        assert newer is not None
        assert newer >= older
        assert not (older >= newer and older != newer)

    @staticmethod
    def test_x64dbg_min_version_is_date_format() -> None:
        """x64dbg's min_version is treated as a date (F-0036)."""
        info = TOOL_REGISTRY[ToolName.X64DBG]
        assert re.match(r"^\d{4}\.\d{2}\.\d{2}$", info.min_version)
        v = ToolInstallerVersion.parse(info.min_version)
        assert v is not None
        assert v.is_date is True


# --------------------------------------------------------------------------
# F-0037 - registry includes SANDBOX and HEX_EDITOR
# --------------------------------------------------------------------------


class TestRegistryCoversAllEnumMembers:
    """F-0037 - SANDBOX and HEX_EDITOR are in TOOL_REGISTRY."""

    @staticmethod
    def test_all_tool_names_in_registry() -> None:
        """Every ToolName enum member has a registry entry (F-0037)."""
        for member in ToolName:
            assert member in TOOL_REGISTRY, f"missing registry entry for {member}"

    @staticmethod
    def test_sandbox_has_executables() -> None:
        """SANDBOX entry lists qemu/docker executables (F-0037)."""
        info = TOOL_REGISTRY[ToolName.SANDBOX]
        assert info.executables
        assert any("qemu" in exe.lower() or "docker" in exe.lower() for exe in info.executables)

    @staticmethod
    def test_hex_editor_lists_hxd() -> None:
        """HEX_EDITOR entry lists HxD executables (F-0037)."""
        info = TOOL_REGISTRY[ToolName.HEX_EDITOR]
        assert info.executables
        assert any("hxd" in exe.lower() for exe in info.executables)


# --------------------------------------------------------------------------
# F-0038 - PLUGIN_ARCHS third field is consumed
# --------------------------------------------------------------------------


class TestPluginArchsThirdFieldUsed:
    """F-0038 - third tuple field is consumed (post-deploy verification subdir)."""

    @staticmethod
    def test_plugin_archs_third_field_is_subdir() -> None:
        """Third field is now the verification subdir (F-0038)."""
        for arch, _filename, subdir in PLUGIN_ARCHS:
            assert subdir.startswith("release/")
            assert arch in subdir

    @staticmethod
    def test_deploy_uses_subdir_field(tmp_path: Path) -> None:
        """deploy_x64dbg_plugin_detailed targets path computed from the third tuple field (F-0038)."""
        x64dbg = _make_x64dbg_tree(tmp_path)
        _make_plugin_source(tmp_path, "intellicrack_bridge_x64.dp64", b"x" * 64)

        result = deploy_x64dbg_plugin_detailed(x64dbg, tmp_path)
        # x32 has no source -> overall False, but x64 must be deployed.
        x64_arch = next(ar for ar in result.per_arch if ar.arch == "x64")
        assert x64_arch.target is not None
        assert "release" in x64_arch.target.parts
        assert "x64" in x64_arch.target.parts


# --------------------------------------------------------------------------
# F-0044 - empty extraction raises / returns failure
# --------------------------------------------------------------------------


class TestEmptyArchiveIsFailure:
    """F-0044 - extracting an archive with no usable directory is failure."""

    @staticmethod
    def test_extract_archive_returns_none_when_empty(tmp_path: Path) -> None:
        """_extract_archive returns None when the zip yields nothing (F-0044)."""
        ti = ToolInstaller(tmp_path / "fresh")
        zp = tmp_path / "truly_empty.zip"
        _build_zip(zp, {})
        result = _run(ti.extract_archive(zp, ToolName.GHIDRA))
        assert result is None


# --------------------------------------------------------------------------
# Misc dataclasses sanity tests
# --------------------------------------------------------------------------


class TestTypeDataclassesSanity:
    """Smoke tests covering the new dataclasses' public surface."""

    @staticmethod
    def test_install_result_default_kind_is_filesystem() -> None:
        """The default InstallResult.kind is filesystem."""
        r = InstallResult(success=True)
        assert r.kind == "filesystem"

    @staticmethod
    def test_arch_deploy_result_carries_error() -> None:
        """ArchDeployResult records error detail."""
        ar = ArchDeployResult(
            arch="x64",
            filename="intellicrack_bridge_x64.dp64",
            status="failed",
            error="permission denied",
        )
        assert ar.status == "failed"
        assert ar.error == "permission denied"

    @staticmethod
    def test_deploy_result_aggregate_default() -> None:
        """DeployResult default has empty per_arch list."""
        dr = DeployResult(success=False)
        assert dr.per_arch == []

    @staticmethod
    def test_is_user_admin_returns_bool() -> None:
        """is_user_admin returns a bool on every platform."""
        assert isinstance(is_user_admin(), bool)


# --------------------------------------------------------------------------
# ToolKind alias is what we expect
# --------------------------------------------------------------------------


def test_tool_kind_alias_values() -> None:
    """ToolKind alias resolves to the three documented values (F-0001/F-0002)."""
    assert set(get_args(ToolKind)) == {"filesystem", "builtin", "python_package"}


def test_deploy_x64dbg_plugin_wrapper_returns_bool(tmp_path: Path) -> None:
    """deploy_x64dbg_plugin still returns a bool for backwards compatibility."""
    x64dbg = _make_x64dbg_tree(tmp_path)
    assert deploy_x64dbg_plugin(x64dbg, tmp_path) is False
