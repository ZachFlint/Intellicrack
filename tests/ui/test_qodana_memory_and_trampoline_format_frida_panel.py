# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gates for the memory-op address formatting in ``frida_panel``.

Covers three 2026-09-20 Qodana findings in ``FridaPanel``:

* ``PyStringFormatInspection`` on ``_on_write_memory``: the parsed ``addr``
  (``int | None``) is read again inside an ``on_success`` closure handed to
  ``run_bridge_coroutine_logged``; the guard above the closure narrows it in
  the enclosing scope but static analysis cannot prove that survives into the
  closure. The handler now rebinds the narrowed value to an explicitly
  ``int``-typed local (``resolved_addr``) before the closure and the bridge
  call.
* The same finding on ``_on_copy_memory`` for both ``src`` and ``dst``
  (rebound to ``resolved_src``/``resolved_dst``).
* ``PyStringFormatInspection`` (``Any | None``) on
  ``_on_replace_function_fast_installed``: ``getattr(result,
  "original_trampoline", None)`` on a bare ``object`` yields ``Any | None``
  with no guarantee the attribute is actually an ``int``. The handler now
  uses ``isinstance(trampoline, int)`` instead of an ``is not None`` check,
  which is a genuine runtime guard against a malformed or wrong-shaped
  result, not just a type-checker satisfaction.

All tests drive real ``FridaPanel`` methods end-to-end and assert on the
exact console text and the exact arguments forwarded to the bridge, so a
regression that captures a stale/wrong value, swaps ``src``/``dst``, or
reverts the ``isinstance`` guard back to a bare ``is not None`` (which would
let a non-int ``original_trampoline`` reach the ``:X`` format spec and raise
``TypeError``) fails loudly.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast

import pytest

from intellicrack.core.types import HookInfo
from intellicrack.ui.panels import frida_panel as frida_panel_module
from intellicrack.ui.panels.frida_panel import FridaPanel


if TYPE_CHECKING:
    from collections.abc import Coroutine

    from PyQt6.QtWidgets import QApplication

    from intellicrack.bridges.frida_bridge import FridaBridge

pytestmark = pytest.mark.usefixtures("qapp")


class _RecordingFridaBridge:
    """Stand-in bridge recording exactly which arguments each call forwarded."""

    def __init__(self) -> None:
        """Initialise an empty call log per method name."""
        self.calls: dict[str, tuple[object, ...]] = {}

    async def write_memory(self, address: int, data: bytes) -> int:
        """Record a ``write_memory`` call.

        Args:
            address: Target address.
            data: Bytes to write.

        Returns:
            int: Number of bytes written.
        """
        self.calls["write_memory"] = (address, data)
        return len(data)

    async def copy_memory(self, dst_address: int, src_address: int, size: int) -> bool:
        """Record a ``copy_memory`` call.

        Args:
            dst_address: Destination address.
            src_address: Source address.
            size: Number of bytes to copy.

        Returns:
            bool: Always True.
        """
        self.calls["copy_memory"] = (dst_address, src_address, size)
        return True


def _drive(
    coro: Coroutine[Any, Any, Any],
    on_success: object = None,
    on_error: object = None,
    parent: object = None,
    **_kwargs: object,
) -> None:
    """Synchronously drive a bridge coroutine so the success lambda runs in-thread.

    Args:
        coro: Coroutine produced by the bridge call.
        on_success: Success callback, invoked synchronously with the result.
        on_error: Unused error callback.
        parent: Unused Qt parent argument.
        **_kwargs: Remaining wrapper keyword arguments (event, logger, level, context).
    """
    del on_error, parent
    loop = asyncio.new_event_loop()
    try:
        result = loop.run_until_complete(coro)
    finally:
        loop.close()
    if on_success is not None:
        cast("Any", on_success)(result)


def _make_panel(qapp: QApplication, bridge: _RecordingFridaBridge) -> FridaPanel:
    """Build a real ``FridaPanel`` wired to a recording bridge double.

    Args:
        qapp: The shared offscreen QApplication fixture.
        bridge: The recording bridge double to attach.

    Returns:
        FridaPanel: A freshly constructed, bridge-attached panel.
    """
    _ = qapp
    panel = FridaPanel()
    panel._bridge = cast("FridaBridge", bridge)
    return panel


def test_write_memory_renders_narrowed_address_and_forwards_it(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_on_write_memory``'s success closure formats the real parsed address.

    Args:
        qapp: The shared offscreen QApplication fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    monkeypatch.setattr(frida_panel_module, "run_bridge_coroutine_logged", _drive)
    bridge = _RecordingFridaBridge()
    panel = _make_panel(qapp, bridge)
    panel._mem_write_addr.setText("0x2000")
    panel._mem_write_data.setText("de ad be ef")

    panel._on_write_memory()

    assert bridge.calls["write_memory"] == (0x2000, b"\xde\xad\xbe\xef")
    lines = panel._console.toPlainText().splitlines()
    assert lines[-1] == "[+] Wrote 4 bytes to 0x2000"


def test_copy_memory_renders_narrowed_addresses_and_forwards_them(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_on_copy_memory``'s success closure formats both real parsed addresses in order.

    Regression target: the src/dst rebind must not swap the two values --
    the bridge call and the rendered message must each show src and dst in
    their original, non-transposed positions.

    Args:
        qapp: The shared offscreen QApplication fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    monkeypatch.setattr(frida_panel_module, "run_bridge_coroutine_logged", _drive)
    bridge = _RecordingFridaBridge()
    panel = _make_panel(qapp, bridge)
    panel._mem_copy_src.setText("0x3000")
    panel._mem_copy_dst.setText("0x4000")
    panel._mem_copy_size.setValue(64)

    panel._on_copy_memory()

    assert bridge.calls["copy_memory"] == (0x4000, 0x3000, 64)
    lines = panel._console.toPlainText().splitlines()
    assert lines[-1] == "[+] Copied 64 bytes: 0x3000 -> 0x4000"


def test_replace_function_fast_installed_renders_integer_trampoline(qapp: QApplication) -> None:
    """A well-formed ``HookInfo`` with an int ``original_trampoline`` is rendered as hex.

    Args:
        qapp: The shared offscreen QApplication fixture.
    """
    panel = _make_panel(qapp, _RecordingFridaBridge())
    result = HookInfo(
        id="hook-1", target="kernel32!CreateFileW", address=0x1000,
        script_id="s1", active=True, original_trampoline=0x7FFE0000,
    )

    panel._on_replace_function_fast_installed("pending-1", "kernel32!CreateFileW", result)

    lines = panel._console.toPlainText().splitlines()
    assert lines[-1] == "[+] Original trampoline: 0x7FFE0000"


def test_replace_function_fast_installed_skips_non_int_trampoline_without_crashing(
    qapp: QApplication,
) -> None:
    """A malformed result whose ``original_trampoline`` is not an int must not crash or render it.

    Regression target: reverting the ``isinstance(trampoline, int)`` guard
    back to a bare ``is not None`` check would let this non-int value reach
    ``f"...:X}"`` and raise ``TypeError`` (formatting an ``Any``-typed,
    non-numeric value with a hex format spec).

    Args:
        qapp: The shared offscreen QApplication fixture.
    """
    panel = _make_panel(qapp, _RecordingFridaBridge())
    malformed_result = SimpleNamespace(id="hook-2", address=0x2000, original_trampoline="not-a-pointer")

    panel._on_replace_function_fast_installed("pending-2", "kernel32!VirtualAlloc", malformed_result)

    text = panel._console.toPlainText()
    assert "Original trampoline" not in text
    lines = text.splitlines()
    assert lines[-1] == "[+] Function replaced (fast): kernel32!VirtualAlloc at 0x2000"
