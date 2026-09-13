# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L3 gate tests for the x64dbg Memory Map tab's Set Protection control.

``set_memory_protection`` is a fully implemented and registered bridge
method with a matching Memory Map toolbar control (``_protect_addr_input``/
``_protect_rights_combo``/``_protect_guard_check``/``_protect_btn``) in
``x64dbg_panel.py``. This module gates two independent things: the exact
``setpagerights`` command framing (via the fake pipe boundary, no real
process required) and the real post-command verification against a genuine
process's address space (via ``get_memory_regions``'s real ``VirtualQueryEx``
walk, which this bridge-completeness test package's own ``conftest``
documents as unable to run inside the Docker sandbox - so that second class
skips there by design, the same way ``test_x64dbg_load_attach_s13.py``'s
real-process gate does).
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import pytest
from PyQt6.QtWidgets import QCheckBox, QComboBox, QLineEdit, QPlainTextEdit, QPushButton

from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.ui.panels.x64dbg_panel import X64DbgPanel

from .conftest import install_fake_pipe, ok, priv, pump_until


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="x64dbg is a Windows-only debugger bridge")

_RESIDUAL_REFRESH_RPCS = frozenset(
    {
        "reg_all",
        "reg_get",
        "register_list",
        "bp_list",
        "thread_list",
        "module_list",
        "memmap",
        "watch_list",
        "wp_list",
        "stack_trace",
    },
)

_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[4]
_X64DBG_INSTALL_ROOT: Final[Path] = _REPO_ROOT / "tools" / "x64dbg"
_TARGET_EXE: Final[Path] = Path("C:/Windows/System32/notepad.exe")
_ALLOC_SIZE: Final[int] = 4096


def _x64dbg_release_exists() -> bool:
    """Return whether a vendored x64dbg release build is present.

    Returns:
        bool: True if either the x64 or the x32 x64dbg executable exists
        under the vendored installation root checked into this repository.
    """
    x64_exe = _X64DBG_INSTALL_ROOT / "release" / "x64" / "x64dbg.exe"
    x32_exe = _X64DBG_INSTALL_ROOT / "release" / "x32" / "x32dbg.exe"
    return x64_exe.exists() or x32_exe.exists()


@pytest.fixture
def wired_panel(qapp: QApplication) -> tuple[X64DbgPanel, X64DbgBridge]:
    """Build a panel with a real bridge attached (no live plugin pipe, no attached process).

    Args:
        qapp: Session QApplication fixture.

    Returns:
        tuple[X64DbgPanel, X64DbgBridge]: The panel and its attached bridge.
    """
    del qapp
    panel = X64DbgPanel()
    bridge = X64DbgBridge()
    setattr(bridge, "_x64dbg_path", Path("C:/tmp/x64dbg.exe"))
    setattr(getattr(bridge, "_state"), "connected", True)
    panel.set_bridge(bridge)
    return panel, bridge


class TestSetProtectionButtonSendsExactSetPageRightsCommand:
    """Clicking Set Protection must send the exact ``setpagerights`` command framing."""

    @staticmethod
    def test_readonly_with_guard_checked_sends_g_prefixed_command(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """Selecting ReadOnly with Guard checked must send ``setpagerights <addr>, GReadOnly``.

        Falsifiable: if ``_on_set_memory_protection`` dropped the "G" guard
        prefix, read a different combo, or the bridge built the rights
        argument incorrectly, the recorded ``exec`` command would not
        match ``setpagerights 0x401000, GReadOnly`` exactly. Because this
        test's bridge has no real attached process, the bridge's own
        post-command verification (via ``get_memory_regions``, a real
        ``VirtualQueryEx`` walk) necessarily fails afterward - that
        failure is expected and asserted on here too, so this test does
        not mask it by stopping short of the real failure path.

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                assert params.get("command") == "setpagerights 0x401000, GReadOnly"
                return ok("")
            if command == "status":
                return ok({"paused": True, "debugging": True})
            if command in _RESIDUAL_REFRESH_RPCS:
                return ok({})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        addr_input = priv(panel, "_protect_addr_input", QLineEdit)
        rights_combo = priv(panel, "_protect_rights_combo", QComboBox)
        guard_check = priv(panel, "_protect_guard_check", QCheckBox)
        protect_btn = priv(panel, "_protect_btn", QPushButton)
        console_output = priv(panel, "_console_output", QPlainTextEdit)

        try:
            addr_input.setText("0x401000")
            rights_combo.setCurrentIndex(5)
            assert rights_combo.currentData() == "read_only"
            guard_check.setChecked(True)
            protect_btn.click()
            pump_until(qapp, lambda: "Set Protection failed" in console_output.toPlainText())

            exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
            assert "setpagerights 0x401000, GReadOnly" in exec_cmds
            assert "[-] Set Protection failed" in console_output.toPlainText()
        finally:
            panel.deleteLater()

    @staticmethod
    def test_execute_without_guard_sends_unprefixed_command(
        wired_panel: tuple[X64DbgPanel, X64DbgBridge],
        qapp: QApplication,
    ) -> None:
        """Selecting Execute with Guard unchecked must send ``setpagerights <addr>, Execute`` (no "G").

        Falsifiable: if ``_on_set_memory_protection`` always prepended
        "G" regardless of the checkbox state, the recorded ``exec``
        command would carry a spurious guard flag instead of matching
        ``setpagerights 0x402000, Execute`` exactly.

        Args:
            wired_panel: Panel/bridge pair fixture.
            qapp: Session QApplication fixture.
        """
        panel, bridge = wired_panel

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                assert params.get("command") == "setpagerights 0x402000, Execute"
                return ok("")
            if command == "status":
                return ok({"paused": True, "debugging": True})
            if command in _RESIDUAL_REFRESH_RPCS:
                return ok({})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        getattr(panel, "_update_controls_state")()
        addr_input = priv(panel, "_protect_addr_input", QLineEdit)
        rights_combo = priv(panel, "_protect_rights_combo", QComboBox)
        guard_check = priv(panel, "_protect_guard_check", QCheckBox)
        protect_btn = priv(panel, "_protect_btn", QPushButton)
        console_output = priv(panel, "_console_output", QPlainTextEdit)

        try:
            addr_input.setText("0x402000")
            rights_combo.setCurrentIndex(0)
            assert rights_combo.currentData() == "execute"
            guard_check.setChecked(False)
            protect_btn.click()
            pump_until(qapp, lambda: "Set Protection failed" in console_output.toPlainText())

            exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
            assert "setpagerights 0x402000, Execute" in exec_cmds
            assert "GExecute" not in exec_cmds
        finally:
            panel.deleteLater()


@pytest.mark.skipif(not _x64dbg_release_exists(), reason="vendored x64dbg install not present on this host")
@pytest.mark.asyncio
class TestSetMemoryProtectionRealVerification:
    """``set_memory_protection`` must genuinely change and verify real page protection."""

    async def test_setting_read_only_on_an_allocated_page_is_observed_by_get_memory_regions(self) -> None:
        """Allocate a real RW page, set it read-only, and confirm ``get_memory_regions`` reports ``r--``.

        Falsifiable: before a correct implementation, either the
        ``setpagerights`` command would never be sent (so the real page
        stays RW and this assertion fails), or the verification step
        could claim ``verified=True`` without the real protection having
        changed at all (the exact failure mode the revert-to-RED probe
        for this item exercises) - in both cases the real,
        non-test-double ``get_memory_regions`` call below would not
        report ``"r--"`` for this region.
        """
        if not _TARGET_EXE.exists():
            pytest.skip(f"debuggee target not present on this host: {_TARGET_EXE}")

        bridge = X64DbgBridge()
        await bridge.initialize(_X64DBG_INSTALL_ROOT)
        if not bridge.state.connected or not bridge.plugin_status.get("plugin_deployed"):
            pytest.skip(f"x64dbg bridge plugin could not be deployed on this host: {bridge.plugin_status}")

        try:
            await bridge.load(_TARGET_EXE)
            assert bridge.attached_pid is not None, "load() left attached_pid unset; cannot allocate/protect memory"

            address = await bridge.allocate_memory(_ALLOC_SIZE, "rw")

            result = await bridge.set_memory_protection(address, "read_only")
            assert result["verified"] is True, f"set_memory_protection did not report verified=True: {result}"

            regions = await bridge.get_memory_regions()
            region = next((r for r in regions if r.base_address <= address < r.base_address + r.size), None)
            assert region is not None, f"allocated region at {hex(address)} missing from get_memory_regions() after set_memory_protection"
            assert region.protection == "r--", (
                f"region at {hex(address)} reports protection {region.protection!r} after set_memory_protection(..., 'read_only'), expected 'r--'"
            )
        finally:
            await bridge.shutdown()
