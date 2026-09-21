# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gates for the breakpoint-config address plumbing in ``x64dbg_advanced_tab``.

Covers the 2026-09-20 Qodana ``PyStringFormatInspection`` findings: each of
``X64DbgAdvancedTab``'s eight breakpoint-config handlers (
``_on_configure_breakpoint``, ``_on_set_logging_breakpoint``,
``_on_set_breakpoint_log_condition``, ``_on_set_breakpoint_command_condition``,
``_on_set_breakpoint_singleshot``, ``_on_set_breakpoint_silent``,
``_on_reset_breakpoint_hit_count``, ``_on_set_breakpoint_name``) parses the
address field once via ``_bpcfg_address() -> int | None``, guards it with
``if address is None: return``, then reads it again inside an
``on_success=lambda ...`` closure handed to ``run_bridge_coroutine_logged``.
Static analysis cannot prove the guard survives into the closure, so each
handler now rebinds the narrowed value to an explicitly ``int``-typed local
(``addr``) before building the closure and the bridge call. These tests drive
each handler end-to-end -- real widget, real bridge double, real lambda
execution -- and assert on the exact rendered status text and the exact
address forwarded to the bridge, so a future edit that captures the wrong
variable, a stale value, or drops the rebind produces either a visibly wrong
message or a ``TypeError`` from formatting ``None``, not a silent pass.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, cast

import pytest

from intellicrack.ui.panels import x64dbg_advanced_tab as x64dbg_advanced_tab_module
from intellicrack.ui.panels.x64dbg_advanced_tab import X64DbgAdvancedTab


if TYPE_CHECKING:
    from collections.abc import Coroutine

    from PyQt6.QtWidgets import QApplication

    from intellicrack.bridges.x64dbg import X64DbgBridge

pytestmark = pytest.mark.usefixtures("qapp")

_TEST_ADDRESS = 0x401000
_TEST_ADDRESS_HEX = "401000"


class _RecordingX64DbgBridge:
    """Stand-in bridge recording exactly which arguments each call forwarded."""

    def __init__(self) -> None:
        """Initialise an empty call log per method name."""
        self.calls: dict[str, tuple[object, ...]] = {}

    async def configure_breakpoint(
        self,
        address: int,
        *,
        condition: str | None = None,
        log_text: str | None = None,
        command: str | None = None,
        fast_resume: bool = False,
    ) -> dict[str, Any]:
        """Record a ``configure_breakpoint`` call.

        Args:
            address: Breakpoint address.
            condition: Break condition, if any.
            log_text: Log text, if any.
            command: On-hit command, if any.
            fast_resume: Fast-resume flag.

        Returns:
            dict[str, Any]: An empty success payload.
        """
        self.calls["configure_breakpoint"] = (address, condition, log_text, command, fast_resume)
        return {}

    async def set_logging_breakpoint(self, address: int, log_text: str, *, non_stopping: bool = True) -> dict[str, Any]:
        """Record a ``set_logging_breakpoint`` call.

        Args:
            address: Breakpoint address.
            log_text: Log text.
            non_stopping: Non-stopping flag.

        Returns:
            dict[str, Any]: An empty success payload.
        """
        self.calls["set_logging_breakpoint"] = (address, log_text, non_stopping)
        return {}

    async def set_breakpoint_log_condition(self, address: int, condition: str) -> dict[str, Any]:
        """Record a ``set_breakpoint_log_condition`` call.

        Args:
            address: Breakpoint address.
            condition: Log-gating condition.

        Returns:
            dict[str, Any]: An empty success payload.
        """
        self.calls["set_breakpoint_log_condition"] = (address, condition)
        return {}

    async def set_breakpoint_command_condition(self, address: int, condition: str) -> dict[str, Any]:
        """Record a ``set_breakpoint_command_condition`` call.

        Args:
            address: Breakpoint address.
            condition: Command-gating condition.

        Returns:
            dict[str, Any]: An empty success payload.
        """
        self.calls["set_breakpoint_command_condition"] = (address, condition)
        return {}

    async def set_breakpoint_singleshot(self, address: int, *, enabled: bool = True) -> dict[str, Any]:
        """Record a ``set_breakpoint_singleshot`` call.

        Args:
            address: Breakpoint address.
            enabled: Singleshot flag.

        Returns:
            dict[str, Any]: An empty success payload.
        """
        self.calls["set_breakpoint_singleshot"] = (address, enabled)
        return {}

    async def set_breakpoint_silent(self, address: int, *, enabled: bool = True) -> dict[str, Any]:
        """Record a ``set_breakpoint_silent`` call.

        Args:
            address: Breakpoint address.
            enabled: Silent flag.

        Returns:
            dict[str, Any]: An empty success payload.
        """
        self.calls["set_breakpoint_silent"] = (address, enabled)
        return {}

    async def reset_breakpoint_hit_count(self, address: int, new_count: int = 0) -> dict[str, Any]:
        """Record a ``reset_breakpoint_hit_count`` call.

        Args:
            address: Breakpoint address.
            new_count: Hit count to reset to.

        Returns:
            dict[str, Any]: An empty success payload.
        """
        self.calls["reset_breakpoint_hit_count"] = (address, new_count)
        return {}

    async def set_breakpoint_name(self, address: int, name: str = "") -> dict[str, Any]:
        """Record a ``set_breakpoint_name`` call.

        Args:
            address: Breakpoint address.
            name: Display name to set.

        Returns:
            dict[str, Any]: An empty success payload.
        """
        self.calls["set_breakpoint_name"] = (address, name)
        return {}


def _drive(
    coro: Coroutine[Any, Any, Any],
    on_success: object = None,
    on_error: object = None,
    parent: object = None,
    **_kwargs: object,
) -> None:
    """Synchronously drive a bridge coroutine so the success lambda runs in-thread.

    Mirrors the production dispatcher's callback contract but runs the
    coroutine to completion immediately, so the test observes the real
    ``on_success`` closure's rendered output deterministically.

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


def _make_tab(qapp: QApplication, bridge: _RecordingX64DbgBridge) -> X64DbgAdvancedTab:
    """Build a real ``X64DbgAdvancedTab`` wired to a recording bridge double.

    Args:
        qapp: The shared offscreen QApplication fixture.
        bridge: The recording bridge double to attach.

    Returns:
        X64DbgAdvancedTab: A freshly constructed, bridge-attached advanced tab.
    """
    _ = qapp
    tab = X64DbgAdvancedTab()
    tab.set_bridge(cast("X64DbgBridge", bridge))
    tab._bpcfg_addr_input.setText(hex(_TEST_ADDRESS))
    return tab


def test_configure_breakpoint_renders_narrowed_address_and_forwards_it(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_on_configure_breakpoint``'s success closure formats the real parsed address.

    Args:
        qapp: The shared offscreen QApplication fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    monkeypatch.setattr(x64dbg_advanced_tab_module, "run_bridge_coroutine_logged", _drive)
    bridge = _RecordingX64DbgBridge()
    tab = _make_tab(qapp, bridge)

    tab._on_configure_breakpoint()

    assert bridge.calls["configure_breakpoint"][0] == _TEST_ADDRESS
    assert tab._bpcfg_status_label.text() == f"[+] Breakpoint at 0x{_TEST_ADDRESS_HEX} configured"


def test_set_logging_breakpoint_renders_narrowed_address_and_forwards_it(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_on_set_logging_breakpoint``'s success closure formats the real parsed address.

    Args:
        qapp: The shared offscreen QApplication fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    monkeypatch.setattr(x64dbg_advanced_tab_module, "run_bridge_coroutine_logged", _drive)
    bridge = _RecordingX64DbgBridge()
    tab = _make_tab(qapp, bridge)
    tab._bpcfg_log_input.setText("hit!")

    tab._on_set_logging_breakpoint()

    assert bridge.calls["set_logging_breakpoint"][0] == _TEST_ADDRESS
    assert tab._bpcfg_status_label.text() == f"[+] Logging breakpoint set at 0x{_TEST_ADDRESS_HEX}"


def test_set_breakpoint_log_condition_renders_narrowed_address_and_forwards_it(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_on_set_breakpoint_log_condition``'s success closure formats the real parsed address.

    Args:
        qapp: The shared offscreen QApplication fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    monkeypatch.setattr(x64dbg_advanced_tab_module, "run_bridge_coroutine_logged", _drive)
    bridge = _RecordingX64DbgBridge()
    tab = _make_tab(qapp, bridge)
    tab._bpcfg_logcond_input.setText("eax == 1")

    tab._on_set_breakpoint_log_condition()

    assert bridge.calls["set_breakpoint_log_condition"][0] == _TEST_ADDRESS
    assert tab._bpcfg_status_label.text() == f"[+] Log condition set at 0x{_TEST_ADDRESS_HEX}"


def test_set_breakpoint_command_condition_renders_narrowed_address_and_forwards_it(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_on_set_breakpoint_command_condition``'s success closure formats the real parsed address.

    Args:
        qapp: The shared offscreen QApplication fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    monkeypatch.setattr(x64dbg_advanced_tab_module, "run_bridge_coroutine_logged", _drive)
    bridge = _RecordingX64DbgBridge()
    tab = _make_tab(qapp, bridge)
    tab._bpcfg_cmdcond_input.setText("ebx == 0")

    tab._on_set_breakpoint_command_condition()

    assert bridge.calls["set_breakpoint_command_condition"][0] == _TEST_ADDRESS
    assert tab._bpcfg_status_label.text() == f"[+] Command condition set at 0x{_TEST_ADDRESS_HEX}"


@pytest.mark.parametrize("checked", [True, False])
def test_set_breakpoint_singleshot_renders_narrowed_address_and_forwards_it(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch, *, checked: bool,
) -> None:
    """``_on_set_breakpoint_singleshot``'s success closure formats the real parsed address.

    Args:
        qapp: The shared offscreen QApplication fixture.
        monkeypatch: Pytest monkeypatch fixture.
        checked: Whether the Singleshot checkbox is checked.
    """
    monkeypatch.setattr(x64dbg_advanced_tab_module, "run_bridge_coroutine_logged", _drive)
    bridge = _RecordingX64DbgBridge()
    tab = _make_tab(qapp, bridge)
    tab._bpcfg_singleshot_check.setChecked(checked)

    tab._on_set_breakpoint_singleshot()

    assert bridge.calls["set_breakpoint_singleshot"] == (_TEST_ADDRESS, checked)
    assert tab._bpcfg_status_label.text() == f"[+] Singleshot set to {checked} at 0x{_TEST_ADDRESS_HEX}"


@pytest.mark.parametrize("checked", [True, False])
def test_set_breakpoint_silent_renders_narrowed_address_and_forwards_it(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch, *, checked: bool,
) -> None:
    """``_on_set_breakpoint_silent``'s success closure formats the real parsed address.

    Args:
        qapp: The shared offscreen QApplication fixture.
        monkeypatch: Pytest monkeypatch fixture.
        checked: Whether the Silent checkbox is checked.
    """
    monkeypatch.setattr(x64dbg_advanced_tab_module, "run_bridge_coroutine_logged", _drive)
    bridge = _RecordingX64DbgBridge()
    tab = _make_tab(qapp, bridge)
    tab._bpcfg_silent_check.setChecked(checked)

    tab._on_set_breakpoint_silent()

    assert bridge.calls["set_breakpoint_silent"] == (_TEST_ADDRESS, checked)
    assert tab._bpcfg_status_label.text() == f"[+] Silent set to {checked} at 0x{_TEST_ADDRESS_HEX}"


def test_reset_breakpoint_hit_count_renders_narrowed_address_and_forwards_it(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_on_reset_breakpoint_hit_count``'s success closure formats the real parsed address.

    Args:
        qapp: The shared offscreen QApplication fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    monkeypatch.setattr(x64dbg_advanced_tab_module, "run_bridge_coroutine_logged", _drive)
    bridge = _RecordingX64DbgBridge()
    tab = _make_tab(qapp, bridge)

    tab._on_reset_breakpoint_hit_count()

    assert bridge.calls["reset_breakpoint_hit_count"][0] == _TEST_ADDRESS
    assert tab._bpcfg_status_label.text() == f"[+] Hit count reset at 0x{_TEST_ADDRESS_HEX}"


def test_set_breakpoint_name_renders_narrowed_address_and_forwards_it(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_on_set_breakpoint_name``'s success closure formats the real parsed address.

    Args:
        qapp: The shared offscreen QApplication fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    monkeypatch.setattr(x64dbg_advanced_tab_module, "run_bridge_coroutine_logged", _drive)
    bridge = _RecordingX64DbgBridge()
    tab = _make_tab(qapp, bridge)
    tab._bpcfg_name_input.setText("my_breakpoint")

    tab._on_set_breakpoint_name()

    assert bridge.calls["set_breakpoint_name"] == (_TEST_ADDRESS, "my_breakpoint")
    assert tab._bpcfg_status_label.text() == f"[+] Name set at 0x{_TEST_ADDRESS_HEX}"


def test_all_eight_handlers_return_silently_when_address_field_is_invalid(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every handler must bail out before touching the bridge when the address is unparsable.

    Companion negative case: confirms the ``if address is None: return`` guard
    that the rebind sits behind is still reached on bad input, so none of the
    eight handlers dereferences the address or calls the bridge.

    Args:
        qapp: The shared offscreen QApplication fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    monkeypatch.setattr(x64dbg_advanced_tab_module, "run_bridge_coroutine_logged", _drive)
    bridge = _RecordingX64DbgBridge()
    tab = _make_tab(qapp, bridge)
    tab._bpcfg_addr_input.setText("not-a-hex-address")
    tab._bpcfg_log_input.setText("hit!")
    tab._bpcfg_logcond_input.setText("eax == 1")
    tab._bpcfg_cmdcond_input.setText("ebx == 0")
    tab._bpcfg_name_input.setText("my_breakpoint")

    tab._on_configure_breakpoint()
    tab._on_set_logging_breakpoint()
    tab._on_set_breakpoint_log_condition()
    tab._on_set_breakpoint_command_condition()
    tab._on_set_breakpoint_singleshot()
    tab._on_set_breakpoint_silent()
    tab._on_reset_breakpoint_hit_count()
    tab._on_set_breakpoint_name()

    assert bridge.calls == {}
