# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gates for the Frida panel's instruction-disassembly control.

``FridaBridge.disassemble_instruction`` (backed by Frida's ``Instruction.parse``)
was a real, registered bridge method (``frida.disassemble_instruction`` in
``tool_definition()``) with zero references anywhere under ``src/intellicrack/ui`` --
an operator of the Frida panel had no way to disassemble a single instruction at
an address even though the AI orchestrator could. The fix adds
``InstructionDisassembleControls`` to the Memory section's "Disassemble" tab.

The end-to-end test drives the real widget against a ``FridaBridge`` self-attached
to the running test process (the same self-attach pattern already used by
``tests/bridges/completeness/frida/test_frida_panel_wiring.py`` for this same class
of L3 gap), cross-checking every rendered field against an independently fetched
``InstructionInfo`` for the identical address. The invalid-address, no-bridge, and
not-attached error paths are verified against a real, unattached ``FridaBridge``
needing no process interaction at all.

Requires a Windows host and frida-python.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.types import IntellicrackError
from intellicrack.ui.panels import async_bridge as async_bridge_module
from intellicrack.ui.panels.frida_instrumentation_tab import InstructionDisassembleControls


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Generator

    from PyQt6.QtWidgets import QWidget

    from intellicrack.bridges.frida_bridge import FridaBridge

try:
    from intellicrack.bridges.frida_bridge import FridaBridge

    _frida_available: bool = True
except ImportError:
    _frida_available = False


_logger = logging.getLogger(__name__)

pytestmark = pytest.mark.usefixtures("qapp")

_DISPATCH_EXCEPTIONS: tuple[type[BaseException], ...] = (
    IntellicrackError,
    *async_bridge_module.WORKER_DEFAULT_EXCEPTIONS,
    asyncio.CancelledError,
)


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


@pytest.fixture
def synchronous_dispatch(monkeypatch: pytest.MonkeyPatch) -> list[Coroutine[object, object, object]]:
    """Replace ``run_bridge_coroutine_async`` with a synchronous, draining capture.

    Args:
        monkeypatch: Pytest monkeypatch fixture.

    Returns:
        list[Coroutine[object, object, object]]: List that records every
        coroutine the control tried to dispatch, in dispatch order.
    """
    captured: list[Coroutine[object, object, object]] = []
    drain_loop = asyncio.new_event_loop()

    def fake_dispatch(
        coro: Coroutine[object, object, object],
        on_success: Callable[[object], None] | None = None,
        on_error: Callable[[object], None] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Drain a dispatched coroutine synchronously instead of on a background QThread.

        Args:
            coro: Bridge coroutine the control tried to dispatch.
            on_success: Success callback to invoke with the coroutine's result.
            on_error: Error callback to invoke with a raised exception.
            parent: Qt parent argument from the real dispatch signature (unused).
        """
        del parent
        captured.append(coro)
        try:
            result = drain_loop.run_until_complete(coro)
        except _DISPATCH_EXCEPTIONS as exc:
            if on_error is not None:
                on_error(exc)
            return
        if on_success is not None:
            on_success(result)

    monkeypatch.setattr(async_bridge_module, "run_bridge_coroutine_async", fake_dispatch)
    return captured


@pytest.fixture
def require_frida() -> None:
    """Skip the current test when frida-python is not installed."""
    if not _frida_available:
        pytest.skip("frida-python required for this test")


@pytest.fixture
def attached_bridge() -> Generator[FridaBridge]:
    """Create a FridaBridge self-attached to the running test process.

    Yields:
        FridaBridge: An initialized bridge attached to the current process.
    """
    bridge = FridaBridge()
    _run_async(bridge.initialize())
    _run_async(bridge.attach(os.getpid()))
    yield bridge
    try:
        _run_async(bridge.shutdown())
    except IntellicrackError:
        _logger.debug("attached_bridge_fixture_shutdown_failed", exc_info=True)


@pytest.mark.usefixtures("require_frida")
@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge/GUI integration test")
class TestInstructionDisassembleControlsAgainstRealProcess:
    """The Disassemble control must reach the real bridge and render every real field."""

    @staticmethod
    def test_disassemble_button_renders_every_field_matching_ground_truth(
        synchronous_dispatch: list[Coroutine[object, object, object]],
        attached_bridge: FridaBridge,
    ) -> None:
        """Clicking Disassemble must render the exact InstructionInfo fields for the address.

        Resolves ``kernel32.dll``'s real base address in the self-attached
        process, fetches its ``InstructionInfo`` directly from the bridge as
        ground truth, then drives the real ``InstructionDisassembleControls``
        widget for the identical address and asserts every rendered label --
        address, next address, size, mnemonic, operands, and full string --
        matches that ground truth exactly.

        Falsifiable: before this control existed there was no GUI path to
        ``disassemble_instruction`` at all; a regression that leaves the
        button unwired, drops the address parse, or renders only the
        mnemonic (leaving the other fields blank or stale) fails one of the
        field-equality assertions below.

        Args:
            synchronous_dispatch: Captures and drains dispatched coroutines.
            attached_bridge: Bridge fixture self-attached to this process.
        """
        base_address = _run_async(attached_bridge.find_base_address("kernel32.dll"))
        assert base_address > 0

        expected = _run_async(attached_bridge.disassemble_instruction(base_address))
        assert expected.mnemonic, "a real decoded instruction must have a non-empty mnemonic"
        assert expected.next_address == expected.address + expected.size

        controls = InstructionDisassembleControls()
        try:
            controls.set_bridge(attached_bridge)
            controls._disasm_addr_input.setText(hex(base_address))

            controls._disasm_btn.click()

            assert len(synchronous_dispatch) == 1, "the Disassemble button must dispatch exactly one bridge coroutine"
            assert controls._disasm_btn.isEnabled() is True

            assert controls._disasm_address_label.text() == f"0x{expected.address:X}"
            assert controls._disasm_next_label.text() == f"0x{expected.next_address:X}"
            assert controls._disasm_size_label.text() == str(expected.size)
            assert controls._disasm_mnemonic_label.text() == expected.mnemonic
            assert controls._disasm_opstr_label.text() == expected.op_str
            assert controls._disasm_string_label.text() == expected.string
            assert controls._status_label.text() == "Disassembled"
        finally:
            controls.deleteLater()


@pytest.mark.usefixtures("require_frida")
class TestInstructionDisassembleControlsErrorPaths:
    """Error paths must surface real bridge/parse failures without crashing or dispatching."""

    @staticmethod
    def test_invalid_address_text_shows_error_and_does_not_dispatch(
        synchronous_dispatch: list[Coroutine[object, object, object]],
    ) -> None:
        """Unparseable address text must be rejected before any bridge dispatch.

        Args:
            synchronous_dispatch: Captures and drains dispatched coroutines.
        """
        controls = InstructionDisassembleControls()
        try:
            controls.set_bridge(FridaBridge())
            controls._disasm_addr_input.setText("not_an_address")

            controls._disasm_btn.click()

            assert not synchronous_dispatch, "an unparseable address must never reach the bridge"
            assert controls._status_label.text() == "Invalid address"
            assert controls._disasm_btn.isEnabled() is True
        finally:
            controls.deleteLater()

    @staticmethod
    def test_no_bridge_shows_error_and_does_not_dispatch(
        synchronous_dispatch: list[Coroutine[object, object, object]],
    ) -> None:
        """Clicking Disassemble with no bridge attached must not raise or dispatch.

        Args:
            synchronous_dispatch: Captures and drains dispatched coroutines.
        """
        controls = InstructionDisassembleControls()
        try:
            controls._disasm_addr_input.setText("0x401000")

            controls._disasm_btn.click()

            assert not synchronous_dispatch
            assert controls._status_label.text() == "No bridge available"
        finally:
            controls.deleteLater()

    @staticmethod
    def test_unattached_bridge_failure_is_surfaced_and_button_reenabled(
        synchronous_dispatch: list[Coroutine[object, object, object]],
    ) -> None:
        """A real ``ToolError`` from a not-attached bridge must be shown, not swallowed.

        Uses a genuine, unattached ``FridaBridge`` (no process interaction
        required): ``disassemble_instruction`` synchronously raises a real
        ``ToolError`` because ``_session`` is ``None``, exercising the real
        error path rather than a mocked one.

        Args:
            synchronous_dispatch: Captures and drains dispatched coroutines.
        """
        controls = InstructionDisassembleControls()
        try:
            controls.set_bridge(FridaBridge())
            controls._disasm_addr_input.setText("0x401000")

            controls._disasm_btn.click()

            assert len(synchronous_dispatch) == 1
            assert controls._status_label.text().startswith("Disassemble failed:")
            assert controls._disasm_btn.isEnabled() is True
        finally:
            controls.deleteLater()
