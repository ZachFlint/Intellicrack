# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for the 2026-07-02 GUI audit findings in ``cutter_panel``.

Each test targets one audit finding and fails against the pre-fix behaviour:

* ``M3``: ``_cleanup`` called the blocking ``run_bridge_coroutine`` with no
  ``timeout_s`` for the bridge ``shutdown()`` RPC, so a wedged r2pipe backend
  froze the calling (GUI) thread inside ``future.result(timeout=None)``
  forever. Post-fix the call passes ``timeout_s=_SHUTDOWN_TIMEOUT_S``, so
  ``_cleanup`` returns within that bound even when ``shutdown()`` never
  resolves, and the resulting ``TimeoutError`` is caught and logged rather
  than propagating.
* ``M42``: the function tree (``_func_tree``) had no header resize mode, so
  Qt's default ``stretchLastSection`` made the near-empty "Size" column
  consume all leftover width while the variable-length "Name" column stayed
  pinned at its narrow default and got elided, with no tooltip fallback.
  Post-fix the header disables stretch-last-section, stretches the Name
  column, sizes Address/Size to their contents, and every row gets a full-name
  tooltip.

All tests drive a real :class:`CutterPanel` under an offscreen
``QApplication``; no widget behaviour is mocked. The M3 reproduction runs
``_cleanup`` on a background thread and bounds the ``Thread.join`` wait so a
pre-fix regression (an unbounded blocking wait) fails deterministically
instead of hanging the test process forever.
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import TYPE_CHECKING, cast

import pytest
from PyQt6.QtWidgets import QApplication, QHeaderView

import intellicrack.ui.panels.cutter_panel as cutter_panel_mod
from intellicrack.core.types import FunctionInfo
from intellicrack.ui.panels.cutter_panel import CutterPanel


if TYPE_CHECKING:
    from intellicrack.bridges.cutter import CutterBridge


pytestmark = pytest.mark.usefixtures("qapp")

_M3_TEST_TIMEOUT_S: float = 0.25
_M3_JOIN_MARGIN_S: float = 4.0


class _ReadyBridgeState:
    """Fake bridge state that always reports itself as ready.

    Mirrors the subset of :class:`~intellicrack.bridges.base.BridgeState`
    that ``CutterPanel._cleanup`` reads: only ``is_ready`` is consulted
    before the shutdown RPC is dispatched.
    """

    def is_ready(self) -> bool:
        """Report the fake bridge as connected and running.

        Returns:
            bool: Always ``True``, so ``_cleanup`` proceeds to shut down.
        """
        return True


class _HangingShutdownBridge:
    """Fake Cutter bridge whose ``shutdown`` coroutine never resolves.

    Reproduces a wedged r2pipe backend: the RPC starts (recorded via
    ``shutdown_started``) but the awaited event is never set, so the
    coroutine itself never completes on its own.
    """

    def __init__(self) -> None:
        """Initialise the fake bridge with a permanently-ready state."""
        self.state = _ReadyBridgeState()
        self.shutdown_started = threading.Event()

    async def shutdown(self) -> None:
        """Mark that shutdown was invoked, then await forever."""
        self.shutdown_started.set()
        await asyncio.Event().wait()


def test_m3_cleanup_bounds_wait_on_wedged_bridge_shutdown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_cleanup`` must not block its caller forever on a wedged ``shutdown``.

    Pre-fix, ``run_bridge_coroutine(self._bridge.shutdown())`` was called
    with no ``timeout_s``, which resolves to an unbounded
    ``future.result(timeout=None)`` wait in ``async_bridge.py``; a bridge
    whose ``shutdown()`` coroutine never completes would freeze whichever
    thread called ``_cleanup`` (the GUI thread for a normal panel-close
    action) indefinitely. This test drives ``_cleanup`` on a background
    thread and bounds the ``join`` wait to a small multiple of the
    (monkeypatched, short) shutdown timeout: pre-fix the thread is still
    alive after the join deadline because the wait never times out;
    post-fix ``run_bridge_coroutine`` raises ``TimeoutError`` (a subclass of
    the ``OSError`` caught by ``_cleanup``) once the configured timeout
    elapses, so the thread finishes promptly and without propagating an
    exception.

    Args:
        monkeypatch: Fixture used to shrink the module's shutdown-timeout
            constant so the gate runs quickly regardless of production value.
    """
    monkeypatch.setattr(cutter_panel_mod, "_SHUTDOWN_TIMEOUT_S", _M3_TEST_TIMEOUT_S)

    panel = CutterPanel()
    bridge = _HangingShutdownBridge()
    panel._bridge = cast("CutterBridge", bridge)

    outcome: dict[str, RuntimeError | ConnectionError | OSError | None] = {}

    def _invoke_cleanup() -> None:
        """Call the panel's teardown hook and record any leaked exception.

        ``_cleanup`` itself only ever catches ``(RuntimeError,
        ConnectionError, OSError)`` -- the same tuple that
        ``asyncio.TimeoutError``/``TimeoutError`` belongs to -- so that is
        the exact set this harness must observe leaking if the fix's
        ``timeout_s`` wiring were removed.
        """
        try:
            panel._cleanup()
        except (RuntimeError, ConnectionError, OSError) as exc:
            outcome["exception"] = exc
        else:
            outcome["exception"] = None

    worker = threading.Thread(target=_invoke_cleanup, daemon=True)
    started = time.monotonic()
    worker.start()
    join_deadline = _M3_TEST_TIMEOUT_S + _M3_JOIN_MARGIN_S
    worker.join(timeout=join_deadline)
    elapsed = time.monotonic() - started

    assert not worker.is_alive(), (
        f"_cleanup() did not return within {join_deadline:.2f}s of a wedged bridge "
        "shutdown; run_bridge_coroutine is still blocking with no effective "
        "timeout_s, matching the pre-fix unbounded future.result(timeout=None) wait"
    )
    assert elapsed < join_deadline, "_cleanup() must return well before the join deadline"
    assert bridge.shutdown_started.is_set(), "the fake bridge's shutdown() must actually have been invoked"
    assert outcome["exception"] is None, (
        f"_cleanup() must catch the shutdown TimeoutError internally, not raise it: {outcome['exception']!r}"
    )


def test_m42_func_tree_header_stretches_name_not_size_column() -> None:
    """The function tree header must stretch Name, not the trailing Size column.

    Pre-fix, ``_func_tree`` never called ``setSectionResizeMode`` or
    ``setStretchLastSection(False)``, so Qt's default
    ``stretchLastSection=True`` made the near-empty "Size" column (index 2)
    consume all leftover width while "Name" (index 0) -- which holds real,
    often long, function/symbol names -- stayed pinned at its narrow
    ``Interactive`` default. Post-fix the header disables stretch-last-
    section and explicitly stretches column 0 while sizing columns 1/2 to
    their contents.

    Asserts:
        The concrete Qt resize-mode configuration is exactly the fixed one,
        not merely "some" configuration.
    """
    panel = CutterPanel()
    header = panel._func_tree.header()

    assert header is not None, "the function tree must expose a header"
    assert header.stretchLastSection() is False, "stretchLastSection must be disabled so the Size column no longer auto-expands"
    assert header.sectionResizeMode(0) == QHeaderView.ResizeMode.Stretch, "the Name column (index 0) must stretch to absorb leftover width"
    assert header.sectionResizeMode(1) == QHeaderView.ResizeMode.ResizeToContents, (
        "the Address column (index 1) must size to its content, not stretch"
    )
    assert header.sectionResizeMode(2) == QHeaderView.ResizeMode.ResizeToContents, (
        "the Size column (index 2) must size to its content, not stretch"
    )


def test_m42_long_function_name_gets_full_tooltip_and_wide_name_column(
    qapp: QApplication,
) -> None:
    """A long demangled function name must get a tooltip and the widest column.

    Pre-fix there was no per-item tooltip, so a name elided by the narrow
    Interactive-width Name column had no way to be read short of manually
    dragging the header. Post-fix every row's ``Name`` cell carries a
    ``toolTip`` equal to the full, unelided name, and -- because the header
    now stretches column 0 instead of column 2 -- the rendered Name column is
    measurably wider than the Size column once real data is loaded into a
    reasonably wide panel.

    Args:
        qapp: Session QApplication fixture used to pump the resize/layout
            events needed for the header to compute real section widths.
    """
    _ = qapp
    long_name = "std::__1::basic_string<char, std::char_traits<char>, std::allocator<char>>::operator[]"
    functions = [
        FunctionInfo(
            name=long_name,
            address=0x401000,
            size=128,
            calling_convention="cdecl",
            return_type="unknown",
            parameters=[],
            local_variables=[],
        ),
        FunctionInfo(
            name="main",
            address=0x402000,
            size=64,
            calling_convention="cdecl",
            return_type="unknown",
            parameters=[],
            local_variables=[],
        ),
    ]

    panel = CutterPanel()
    panel.resize(900, 600)
    panel.show()
    QApplication.processEvents()

    panel._apply_functions(functions)
    QApplication.processEvents()

    tree = panel._func_tree
    assert tree.topLevelItemCount() == 2, "both functions must be inserted into the tree"

    long_item = tree.topLevelItem(0)
    assert long_item is not None
    assert long_item.text(0) == long_name, "the Name cell must hold the full, unelided name"
    assert long_item.toolTip(0) == long_name, "the Name cell must carry a tooltip with the full name as an elision fallback"

    header = tree.header()
    assert header is not None
    name_width = header.sectionSize(0)
    size_width = header.sectionSize(2)
    assert name_width > size_width, (
        f"the Name column ({name_width}px) must be rendered wider than the Size "
        f"column ({size_width}px); pre-fix stretchLastSection made Size consume "
        "the leftover width instead"
    )
