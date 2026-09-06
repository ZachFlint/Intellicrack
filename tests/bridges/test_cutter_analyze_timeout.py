# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gate for the Cutter/rizin bridge analysis-timeout defect (D16).

:meth:`CutterBridge.analyze` used to dispatch ``aa``/``aaa``/``aaaa`` through
``_r2_cmd`` with no explicit ``command_timeout``, so the call inherited the
module-wide :data:`intellicrack.bridges.cutter.R2_COMMAND_TIMEOUT` of 5.0
seconds. Full analysis on any real-world binary routinely takes far longer
than 5 seconds, so ``analyze()`` always timed out and raised ``ToolError``
before rizin finished building the function list -- static analysis was
effectively unusable through the bridge.

This test drives the real ``rizin``/``radare2`` backend against a real PE
executable and asserts that a ``"normal"`` (``aaa``) analysis pass completes
without raising, and that :meth:`CutterBridge.get_functions` subsequently
reports a non-empty function list. Reverting the level-scaled
``command_timeout`` fix (back to the bare 5.0 s default) reliably reproduces
the timeout on any target large enough to need more than a few seconds of
``aaa`` analysis, which real executables always are, so this test goes RED
against the pre-fix code.
"""

from __future__ import annotations

import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest
import pytest_asyncio

from intellicrack.bridges import cutter as cutter_mod
from intellicrack.bridges.cutter import CutterBridge
from intellicrack.core.types import ToolError
from tests._helpers.real_binaries import FixtureUnavailableError, resolve_real_pe_exe


if TYPE_CHECKING:
    from collections.abc import AsyncIterator

pytestmark = [pytest.mark.spawns_process, pytest.mark.asyncio]

_AUDIT_TARGET_PATH: Final[Path] = Path(tempfile.gettempdir()) / "ic_audit_targets" / "ida_9.4.exe"


async def _make_bridge_or_skip() -> CutterBridge:
    """Build a bridge whose backend is available, or skip the test.

    Mirrors the discovery-and-skip helper in ``test_realcov_03c_cutter.py``:
    probes the real backend through :meth:`CutterBridge.is_available` rather
    than a bare ``shutil.which`` check, so a stored ``tool_path`` fallback is
    honored the same way production code honors it.

    Returns:
        CutterBridge: A fresh bridge with a confirmed rizin/radare2 backend.
    """
    bridge = CutterBridge()
    if not await bridge.is_available():
        pytest.skip("rizin/radare2 backend not discoverable on PATH")
    return bridge


def _resolve_analysis_target() -> Path:
    """Resolve a real, sizeable PE executable to drive full analysis against.

    Prefers the committed S19 live-audit target (``ida_9.4.exe``), a large
    real-world executable whose ``aaa`` analysis pass reliably exceeds the
    old 5-second default. Falls back to a real System32 executable when the
    audit target is not present on this machine, so the gate is never
    unconditionally skipped over a missing fixture file -- only over a
    genuinely absent rizin/radare2 backend.

    Returns:
        Path: Absolute path to a real, on-disk PE executable.
    """
    if _AUDIT_TARGET_PATH.is_file():
        return _AUDIT_TARGET_PATH

    try:
        return resolve_real_pe_exe()
    except FixtureUnavailableError as exc:
        pytest.skip(str(exc))


@pytest_asyncio.fixture
async def analysis_bridge() -> AsyncIterator[CutterBridge]:
    """Provide an initialized, real-backend-connected :class:`CutterBridge`.

    Yields:
        CutterBridge: A bridge whose :meth:`CutterBridge.initialize` has
        already run against the genuine rizin/radare2 backend on ``PATH``.
    """
    bridge = await _make_bridge_or_skip()
    await bridge.initialize()
    try:
        yield bridge
    finally:
        await bridge.shutdown()


class TestAnalyzeTimeout:
    """Gate D16: ``analyze()`` must not inherit the bare 5 s command timeout."""

    async def test_normal_analysis_completes_and_finds_functions(
        self,
        analysis_bridge: CutterBridge,
    ) -> None:
        """A ``"normal"`` (``aaa``) analysis pass must finish without raising.

        Drives the real ``load_binary`` -> ``analyze`` -> ``get_functions``
        pipeline against a real PE target through the genuine rizin/radare2
        backend. With the pre-fix bare 5 s ``command_timeout``, ``analyze``
        would raise ``ToolError`` on any target this large well before rizin
        finished; with the level-scaled timeout in place, analysis completes
        and ``get_functions`` reports a real, non-empty function list.

        Args:
            analysis_bridge: Fixture providing an initialized, connected
                bridge against the real backend.
        """
        target = _resolve_analysis_target()

        await analysis_bridge.load_binary(target)

        start = time.monotonic()
        try:
            await analysis_bridge.analyze(level="normal")
        except ToolError as exc:
            elapsed = time.monotonic() - start
            pytest.fail(
                f"analyze(level='normal') raised ToolError after {elapsed:.1f}s analyzing {target.name}: {exc}",
            )

        functions = await analysis_bridge.get_functions()
        assert len(functions) > 0, f"expected at least one function from analyzing {target.name}"

    async def test_analyze_raises_tool_error_without_loaded_binary(self) -> None:
        """``analyze()`` must still raise ``ToolError`` when no binary is loaded.

        Confirms the timeout fix did not weaken the pre-existing "no binary
        loaded" guard: calling ``analyze`` on a freshly constructed,
        never-``load_binary``-ed bridge must fail fast rather than attempt a
        long-running analysis against nothing.
        """
        bridge = await _make_bridge_or_skip()
        with pytest.raises(ToolError, match="no binary loaded"):
            await bridge.analyze(level="normal")


def test_analysis_timeout_scheme_exceeds_default_command_timeout() -> None:
    """Every level-scaled analysis timeout must exceed the bare command default.

    Reads the real module-level analysis-timeout mapping (no double, no
    restatement of its values) via ``getattr`` -- the same indirection
    :mod:`test_ghidra_analyze_timeout` uses to reach the sibling bridge's
    private timeout knobs -- and asserts each entry is comfortably larger
    than the 5 s command default ``analyze`` used to inherit. This is a
    fast, deterministic companion to the real-backend gate above: it fails
    immediately if the timeout constants are ever reverted to values at or
    near the old default, without needing a rizin install.
    """
    analysis_timeouts: dict[str, float] = getattr(cutter_mod, "_ANALYSIS_TIMEOUT")
    default_command_timeout: float = getattr(cutter_mod, "_R2_COMMAND_TIMEOUT")
    default_analysis_timeout: float = getattr(cutter_mod, "_DEFAULT_ANALYSIS_TIMEOUT")

    assert analysis_timeouts
    for level, timeout in analysis_timeouts.items():
        assert timeout > default_command_timeout * 10, (
            f"analysis timeout for level {level!r} ({timeout}s) is not comfortably above the {default_command_timeout}s command default"
        )
    assert analysis_timeouts["normal"] == default_analysis_timeout
