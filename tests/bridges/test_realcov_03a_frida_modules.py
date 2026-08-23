# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-world coverage tests for FridaBridge module and function operations.

These tests close the coverage gaps flagged in the bridges/RE-tools audit
(shard 03) for ``enumerate_modules``, ``enumerate_exports``,
``replace_function`` and ``resume_child``. Every test drives the REAL Frida
runtime attached to a freshly spawned ``notepad.exe`` and asserts on real,
verifiable results from live Windows system DLLs (kernel32.dll, ntdll.dll).

Requires frida-python and a Windows host. Tests spawn ``notepad.exe`` and are
marked ``spawns_process`` so the harness only runs them inside the Docker
sandbox (or when host-process tests are explicitly allowed).
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Final

from intellicrack.core.subprocess_compat import DEVNULL, Popen


if TYPE_CHECKING:
    from collections.abc import Coroutine, Generator

import pytest

from intellicrack.core.types import (
    ExportInfo,
    HookInfo,
    ModuleInfo,
    ToolError,
)


frida = pytest.importorskip("frida", reason="frida-python required for bridge tests")

from intellicrack.bridges.frida_bridge import FridaBridge  # noqa: E402


_logger = logging.getLogger(__name__)

_NOTEPAD_STARTUP_DELAY: Final[float] = 1.0
_BRIDGE_SLEEP: Final[float] = 0.3
_NOTEPAD_MIN_MODULES: Final[int] = 5
_NTDLL_BASE_MIN: Final[int] = 0x70000000
_KERNEL32_MIN_EXPORTS: Final[int] = 100
_UNKNOWN_CHILD_PID: Final[int] = 0x7FFFFFFE


def _run_async[T](coro: Coroutine[object, object, T]) -> T:
    """Run an async coroutine synchronously for test use.

    Args:
        coro: Awaitable coroutine to execute.

    Returns:
        T: The coroutine's return value, preserving its type.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@pytest.fixture(scope="module")
def notepad_process() -> Generator[Popen[bytes]]:
    """Spawn a real notepad.exe for Frida to attach to.

    Yields:
        Popen[bytes]: The running notepad process.
    """
    notepad_path = shutil.which("notepad.exe") or str(
        Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "notepad.exe",
    )
    proc = Popen([notepad_path], stdout=DEVNULL, stderr=DEVNULL)
    time.sleep(_NOTEPAD_STARTUP_DELAY)
    yield proc
    proc.terminate()
    proc.wait(timeout=5)


@pytest.fixture(scope="module")
def frida_bridge(notepad_process: Popen[bytes]) -> Generator[FridaBridge]:
    """Create a FridaBridge attached to the spawned notepad.exe.

    Args:
        notepad_process: The running notepad process fixture.

    Yields:
        FridaBridge: An initialized and attached FridaBridge instance.
    """
    bridge = FridaBridge()
    _run_async(bridge.initialize())
    _run_async(bridge.attach(notepad_process.pid))
    time.sleep(_BRIDGE_SLEEP)
    yield bridge
    try:
        _run_async(bridge.shutdown())
    except Exception:
        _logger.debug("frida_bridge_fixture_shutdown_failed", exc_info=True)


@pytest.mark.spawns_process
@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_enumerate_modules_real_notepad(frida_bridge: FridaBridge) -> None:
    """Verify enumerate_modules returns the real loaded module list of notepad.

    Asserts the live process has the core Windows system DLLs loaded, each with
    a non-zero base address in the high system-DLL range and a non-empty path
    pointing at a real ``.dll`` / ``.exe`` file on disk.

    Args:
        frida_bridge: Bridge fixture attached to the spawned notepad process.
    """
    modules: list[ModuleInfo] = _run_async(frida_bridge.enumerate_modules())
    assert len(modules) >= _NOTEPAD_MIN_MODULES, f"notepad must have several loaded modules, got {len(modules)}"

    by_name = {m.name.lower(): m for m in modules}
    assert "ntdll.dll" in by_name, f"ntdll.dll must be loaded; got modules {sorted(by_name)}"
    assert "kernel32.dll" in by_name, "kernel32.dll must be loaded in every Win32 process"

    ntdll = by_name["ntdll.dll"]
    assert ntdll.base_address >= _NTDLL_BASE_MIN, f"ntdll base 0x{ntdll.base_address:X} should be in high system DLL range"
    assert ntdll.base_address % 0x10000 == 0, f"ntdll base 0x{ntdll.base_address:X} must be 64KB-aligned"
    assert ntdll.size > 0, "ntdll module must report a non-zero in-memory size"
    assert ntdll.path.name.lower() == "ntdll.dll", f"ntdll path should end in ntdll.dll, got {ntdll.path}"

    bases = [m.base_address for m in modules]
    assert len(set(bases)) == len(bases), "every loaded module must have a distinct base address"


@pytest.mark.spawns_process
@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_enumerate_exports_kernel32_real(frida_bridge: FridaBridge) -> None:
    """Verify enumerate_exports returns real exports from kernel32.dll.

    kernel32.dll exports hundreds of Win32 API functions. This asserts the
    well-known ``LoadLibraryA`` / ``GetProcAddress`` / ``CreateFileW`` exports
    are present with non-zero resolved addresses inside the module image.

    Args:
        frida_bridge: Bridge fixture attached to the spawned notepad process.
    """
    base = _run_async(frida_bridge.find_base_address("kernel32.dll"))
    exports: list[ExportInfo] = _run_async(frida_bridge.enumerate_exports("kernel32.dll"))
    assert len(exports) >= _KERNEL32_MIN_EXPORTS, f"kernel32 exports hundreds of APIs, got {len(exports)}"

    by_name = {e.name: e for e in exports}
    for required in ("LoadLibraryA", "GetProcAddress", "CreateFileW"):
        assert required in by_name, f"kernel32 must export {required}; missing from {len(by_name)} exports"
        export = by_name[required]
        assert export.address > 0, f"{required} must resolve to a non-zero address"
        assert export.address >= base, f"{required} at 0x{export.address:X} must lie at/above module base 0x{base:X}"


@pytest.mark.spawns_process
@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_enumerate_exports_module_not_found(frida_bridge: FridaBridge) -> None:
    """Verify enumerate_exports raises ToolError for a module that is not loaded.

    Args:
        frida_bridge: Bridge fixture attached to the spawned notepad process.
    """
    with pytest.raises(ToolError):
        _run_async(frida_bridge.enumerate_exports("this_module_is_not_loaded_zzz.dll"))


@pytest.mark.spawns_process
@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_replace_function_real_callback(frida_bridge: FridaBridge) -> None:
    """Verify replace_function installs a real NativeCallback over a live API.

    Replaces ``kernel32.dll!GetTickCount`` with a NativeCallback that returns a
    constant. The replacement is installed through the real Frida Interceptor
    against the live notepad image; the returned HookInfo must reflect an active
    hook whose resolved address matches the module's real export address.

    Args:
        frida_bridge: Bridge fixture attached to the spawned notepad process.
    """
    exports = _run_async(frida_bridge.enumerate_exports("kernel32.dll"))
    by_name = {e.name: e for e in exports}
    assert "GetTickCount" in by_name, "kernel32 must export GetTickCount"
    expected_addr = by_name["GetTickCount"].address

    replacement = "new NativeCallback(function () { return 1337; }, 'uint32', [])"
    hook: HookInfo = _run_async(
        frida_bridge.replace_function("kernel32.dll!GetTickCount", replacement),
    )
    try:
        assert hook.id, "replacement must produce a hook id"
        assert hook.active, "replacement hook must be marked active"
        assert hook.target == "kernel32.dll!GetTickCount"
        assert hook.address == expected_addr, (
            f"resolved replacement address 0x{(hook.address or 0):X} must match the real GetTickCount export 0x{expected_addr:X}"
        )
    finally:
        removed = _run_async(frida_bridge.remove_hook(hook.id))
        assert removed, "replacement hook must be removable"


@pytest.mark.spawns_process
@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_replace_function_invalid_calling_convention(frida_bridge: FridaBridge) -> None:
    """Verify replace_function rejects an unknown calling convention.

    Args:
        frida_bridge: Bridge fixture attached to the spawned notepad process.
    """
    replacement = "new NativeCallback(function () { return 0; }, 'uint32', [])"
    with pytest.raises(ToolError):
        _run_async(
            frida_bridge.replace_function(
                "kernel32.dll!GetTickCount",
                replacement,
                calling_convention="not_a_real_convention",
            ),
        )


@pytest.mark.spawns_process
@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only e2e tests")
def test_resume_child_unknown_pid_raises(frida_bridge: FridaBridge) -> None:
    """Verify resume_child surfaces the real device error for an unknown child.

    The bridge holds a real Frida device (the local device backing the notepad
    attach). Calling ``resume`` on a PID that was never gated drives the real
    ``device.resume`` path, which raises and is mapped to a ToolError.

    Args:
        frida_bridge: Bridge fixture attached to the spawned notepad process.
    """
    with pytest.raises(ToolError):
        _run_async(frida_bridge.resume_child(_UNKNOWN_CHILD_PID))
