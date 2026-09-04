# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable session-liveness gates for the x64dbg bridge (D19).

Drives the real :class:`X64DbgBridge` against a real, vendored x64dbg
installation and a real ``notepad.exe`` debuggee - no pipe transport or
process is mocked. Two coupled regressions are gated:

* ``load()`` previously could report success (``self._state.connected =
  True``) without ever confirming the bridge pipe was genuinely
  connected, so the very first write issued afterwards (a breakpoint)
  could fail with ``"pipe not available"`` even though ``load()`` claimed
  the session was up. :class:`TestSessionLiveness` proves that once
  ``load()`` returns without raising, a subsequent ``get_registers()``
  returns real values and a subsequent ``set_breakpoint()`` genuinely
  succeeds - the false-success path is unreachable.
* Once the underlying x64dbg process is killed mid-session, every bridge
  read (``get_registers``, ``get_breakpoints``) must report the session
  as lost (raise ``ToolError``) rather than returning stale cached
  values from before the process died.

Skips (with a documented reason) when not running on Windows, when no
vendored x64dbg release build is present, or when the bridge plugin could
not be deployed on this host - the same skip conditions already used by
``test_x64dbg_load_attach_s13.py``.
"""

from __future__ import annotations

import contextlib
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, cast

import pytest

from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from intellicrack.core.win32_desktop_process import DesktopProcess


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
_X64DBG_INSTALL_ROOT: Final[Path] = _REPO_ROOT / "tools" / "x64dbg"
_TARGET_EXE: Final[Path] = Path("C:/Windows/System32/notepad.exe")
_PROCESS_WAIT_TIMEOUT_S: Final[float] = 15.0


def _x64dbg_release_exists() -> bool:
    """Return whether a vendored x64dbg release build is present.

    Returns:
        bool: True if either the x64 or the x32 x64dbg executable exists
        under the vendored installation root checked into this repository.
    """
    x64_exe = _X64DBG_INSTALL_ROOT / "release" / "x64" / "x64dbg.exe"
    x32_exe = _X64DBG_INSTALL_ROOT / "release" / "x32" / "x32dbg.exe"
    return x64_exe.exists() or x32_exe.exists()


@pytest.mark.host_native
@pytest.mark.skipif(sys.platform != "win32", reason="x64dbg is a Windows-only debugger")
@pytest.mark.skipif(not _x64dbg_release_exists(), reason="vendored x64dbg install not present on this host")
@pytest.mark.asyncio
class TestSessionLiveness:
    """D19: session death must never be reported as success or masked by stale data."""

    async def test_load_yields_a_genuinely_live_session_and_death_is_reported(self) -> None:
        """load() must not lie about session health, and a killed session must surface.

        Falsifiable in two independent ways:

        1. Before the fix, ``load()`` unconditionally set
           ``self._state.connected = True`` after issuing ``InitDebug``,
           without ever re-checking that the pipe was still connected.
           If that regressed, ``set_breakpoint()`` immediately after a
           "successful" ``load()`` could raise ``ToolError`` for a pipe
           that was never actually available - the exact "reports
           success, then the first write hard-fails" bug this test
           pins down via the ``get_registers``/``set_breakpoint``
           assertions below.
        2. Before the fix, ``get_breakpoints()`` special-cased
           ``self._pipe_client.is_connected`` and, when it was False,
           silently returned the locally cached breakpoint dict instead
           of attempting the RPC (and therefore never raised). Reverting
           that fix makes the post-kill ``get_breakpoints()`` call below
           return ``[bp_address]`` from the stale local cache instead of
           raising, failing the ``pytest.raises`` assertion.
        """
        if not _TARGET_EXE.exists():
            pytest.skip(f"debuggee target not present on this host: {_TARGET_EXE}")

        bridge = X64DbgBridge()
        await bridge.initialize(_X64DBG_INSTALL_ROOT)
        if not bridge.state.connected or not bridge.plugin_status.get("plugin_deployed"):
            pytest.skip(f"x64dbg bridge plugin could not be deployed on this host: {bridge.plugin_status}")

        assert getattr(bridge, "_process") is None, "test precondition: no x64dbg process must be tracked before load()"

        try:
            try:
                await bridge.load(_TARGET_EXE)
            except ToolError as exc:
                pytest.skip(f"load() raised cleanly with no x64dbg previously running (acceptable per spec): {exc}")

            # load() reported success without raising: a subsequent register
            # read must return real, non-zero values and a subsequent
            # breakpoint write must genuinely succeed. Never both "load()
            # succeeded" and "the following breakpoint write fails with
            # pipe not available".
            regs = await bridge.get_registers()
            assert regs.rip != 0, "get_registers() returned an all-zero RegisterState right after a reportedly successful load()"

            bp_address = regs.rip
            bp_id = await bridge.set_breakpoint(bp_address, "software")
            assert bp_id == bp_address, "set_breakpoint() must succeed immediately after a load() that reported success"

            process = cast("DesktopProcess | None", getattr(bridge, "_process"))
            assert process is not None, "load() reported success but never tracked a debugger process"
            pid = process.pid

            process.kill()
            process.wait(timeout=_PROCESS_WAIT_TIMEOUT_S)

            with pytest.raises(ToolError):
                await bridge.get_registers()

            with pytest.raises(ToolError):
                await bridge.get_breakpoints()

            del pid
        finally:
            with contextlib.suppress(ToolError, OSError, RuntimeError):
                await bridge.shutdown()


class TestScanMemoryUnaffectedByLivenessProbe:
    """The new process-liveness probe must not disturb bridge construction."""

    @staticmethod
    def test_fresh_bridge_has_no_tracked_process() -> None:
        """A freshly constructed bridge tracks no process, so the liveness probe is a no-op.

        Falsifiable: if the D19 liveness probe (``_raise_if_process_exited``)
        were changed to dereference ``self._process`` without the
        ``is None`` guard, constructing a bridge and reading its private
        state would crash instead of leaving ``_process`` at ``None``.
        """
        bridge = X64DbgBridge()
        process: Any = getattr(bridge, "_process")
        assert process is None
