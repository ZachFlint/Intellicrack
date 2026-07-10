# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L1/L2/L3 gate tests for the x64dbg ``restart`` feature and the ``disassemble_at`` dispatch fix.

Covers ``audit/bridge-completeness/agent-01-x64dbg-execution-control.md`` row 4
(restart, previously MISSING at all three layers) and the dispatch defect
documented in ``audit/bridge-completeness/agent-02-x64dbg-state-manipulation.md``
("Orphan / defect note"): the registered tool-def was named
``x64dbg.disassemble`` while the only matching bridge method was
``disassemble_at``, so every AI/orchestration call to ``x64dbg.disassemble``
raised ``ToolError`` unconditionally, and would additionally have failed the
``static_analysis`` capability gate because ``X64DbgBridge`` never declared
``supports_static_analysis``.

Regression coverage:

* G-restart -- a real ``restart()`` method re-issues ``InitDebug`` against
  the bridge's own stored ``_binary_path``/``_launch_args`` and verifies the
  debugger actually returned to a paused state before reporting success. A
  registered ``x64dbg.restart`` tool-def makes it AI-dispatchable, and a
  toolbar "Restart" button wires it into the panel.
* G-disassemble -- the tool-def name was renamed from ``x64dbg.disassemble``
  to ``x64dbg.disassemble_at`` (matching the real method), and
  ``X64DbgBridge`` now declares ``supports_static_analysis=True`` so the
  capability gate in ``ToolRegistry.execute_tool_call`` no longer blocks it.
"""

from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import pytest
from PyQt6.QtWidgets import QPlainTextEdit, QPushButton

from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ToolError, ToolName
from intellicrack.ui.panels.x64dbg_panel import X64DbgPanel

from .conftest import install_fake_pipe, ok, priv, pump_until


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication

    from intellicrack.bridges.base import DisassemblyLine


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


@pytest.fixture
def bridge() -> X64DbgBridge:
    """Construct a fresh, unattached bridge instance.

    Returns:
        X64DbgBridge: A bridge with no attached PID and no pipe client.
    """
    return X64DbgBridge()


@pytest.fixture
def registry(tmp_path: Path) -> ToolRegistry:
    """Build a real, empty ``ToolRegistry`` rooted at a scratch tools directory.

    Args:
        tmp_path: Pytest-managed temporary tools directory.

    Returns:
        ToolRegistry: A freshly constructed registry with no bridges registered.
    """
    return ToolRegistry(tools_dir=tmp_path)


class TestRestartBridgeMethodL1:
    """L1: ``restart()`` performs the real re-init and verifies via ``status`` polling.

    Falsifiable: deleting ``X64DbgBridge.restart`` (or reverting it to a stub
    that returns ``{"success": True}`` without sending ``InitDebug`` or
    polling ``status``) makes every assertion below fail or raise
    ``AttributeError``.
    """

    @staticmethod
    @pytest.mark.asyncio
    async def test_restart_without_prior_load_raises_tool_error(bridge: X64DbgBridge) -> None:
        """Calling ``restart()`` before any ``load()`` must raise ``ToolError``.

        Falsifiable: if the ``self._binary_path is None`` guard at the top of
        ``restart()`` were removed, this call would instead try to build an
        ``InitDebug`` command with a ``None`` path and raise a different,
        uncontrolled exception (or silently no-op), not the documented
        ``ToolError``. Broken production line: the
        ``if self._binary_path is None: raise ToolError(...)`` guard in
        ``X64DbgBridge.restart`` (``bridges/x64dbg.py``).

        Args:
            bridge: Fresh, never-loaded bridge fixture.
        """
        with pytest.raises(ToolError, match="no binary has been loaded"):
            await bridge.restart()

    @staticmethod
    @pytest.mark.asyncio
    async def test_restart_reissues_init_debug_with_stored_path_and_args(bridge: X64DbgBridge) -> None:
        """``restart()`` must re-issue ``InitDebug`` with the exact path/args stored by ``load()``.

        Independent oracle: the literal path and args strings this test
        supplies directly to the private state before calling ``restart()``.
        Falsifiable: if ``restart()`` built its ``InitDebug`` command from
        anything other than ``self._binary_path``/``self._launch_args`` (e.g.
        a hardcoded string, or omitted the args clause), the exact-string
        assertion on the recorded ``exec`` command fails. Broken production
        line: ``cmd = f'InitDebug "{path.as_posix()}"'`` /
        ``if self._launch_args: cmd += f', "{self._launch_args}"'`` in
        ``X64DbgBridge.restart``.

        Args:
            bridge: Fresh bridge fixture.
        """
        target_path = Path("C:/tmp/gate_target.exe")
        setattr(bridge, "_binary_path", target_path)
        setattr(bridge, "_launch_args", "--flag value")

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                return ok("")
            if command == "reg_get":
                return ok("0")
            if command == "status":
                return ok({"paused": True, "debugging": True})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)

        result = await bridge.restart()

        exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
        expected_cmd = f'InitDebug "{target_path.as_posix()}", "--flag value"'
        assert expected_cmd in exec_cmds, f"'{expected_cmd}' must be sent via exec; got {exec_cmds!r}"
        assert result["success"] is True
        assert result["path"] == str(target_path)
        assert result["verified"] is True

    @staticmethod
    @pytest.mark.asyncio
    async def test_restart_without_launch_args_omits_args_clause(bridge: X64DbgBridge) -> None:
        """When no launch args were stored, ``InitDebug`` must be sent with only the path.

        Falsifiable: if the ``if self._launch_args:`` guard were removed and
        an empty/`None` args clause were always appended, the exact-string
        command assertion (with no trailing comma-quoted segment) fails.
        Broken production line: the conditional args-append in
        ``X64DbgBridge.restart``.

        Args:
            bridge: Fresh bridge fixture.
        """
        target_path = Path("C:/tmp/gate_target_noargs.exe")
        setattr(bridge, "_binary_path", target_path)
        setattr(bridge, "_launch_args", None)

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return ok("")
            if command == "reg_get":
                return ok("0")
            if command == "status":
                return ok({"paused": True, "debugging": True})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        await bridge.restart()

        exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
        expected_cmd = f'InitDebug "{target_path.as_posix()}"'
        assert expected_cmd in exec_cmds
        assert not any(cmd.startswith(expected_cmd) and cmd != expected_cmd for cmd in exec_cmds), (
            f"no args clause must be appended when _launch_args is None; got {exec_cmds!r}"
        )

    @staticmethod
    @pytest.mark.asyncio
    async def test_restart_raises_tool_error_when_never_paused(bridge: X64DbgBridge) -> None:
        """``restart()`` must raise ``ToolError`` if ``status`` never reports paused.

        Falsifiable: if the verification poll (``_wait_for_running_state``)
        were removed and ``restart()`` unconditionally returned success after
        sending ``InitDebug``, this call would return normally instead of
        raising. Broken production line: the
        ``if observed is True: raise ToolError(...)`` branch at the end of
        ``X64DbgBridge.restart``.

        Args:
            bridge: Fresh bridge fixture.
        """
        setattr(bridge, "_binary_path", Path("C:/tmp/gate_never_paused.exe"))
        setattr(bridge, "_launch_args", None)
        setattr(bridge, "VERIFY_TIMEOUT", 0.05)
        setattr(bridge, "VERIFY_POLL_INTERVAL", 0.01)

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return ok("")
            if command == "reg_get":
                return ok("0")
            if command == "status":
                return ok({"paused": False, "debugging": True})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        install_fake_pipe(bridge, responder)
        with pytest.raises(ToolError, match="restart verification failed"):
            await bridge.restart()


class TestRestartToolDefL2:
    """L2: ``x64dbg.restart`` is a registered, dispatchable ``ToolFunction``.

    Falsifiable: removing the ``ToolFunction(name="x64dbg.restart", ...)``
    entry from the tool-def property makes the containment assertion fail;
    if the tool-def were re-added under a name not matching the real method
    (repeating the historical ``disassemble``/``disassemble_at`` mismatch),
    the dispatch test would raise ``ToolError`` instead of returning.
    """

    @staticmethod
    def test_restart_tool_def_registered(bridge: X64DbgBridge) -> None:
        """The ``x64dbg.restart`` ``ToolFunction`` must exist and match a real bridge method.

        Args:
            bridge: Fresh bridge fixture.
        """
        names = {f.name for f in bridge.tool_definition.functions}
        assert "x64dbg.restart" in names
        assert callable(bridge.restart)

    @staticmethod
    @pytest.mark.asyncio
    async def test_restart_dispatchable_via_tool_registry(bridge: X64DbgBridge, registry: ToolRegistry) -> None:
        """``x64dbg.restart`` must dispatch through ``ToolRegistry.execute_tool_call`` and run for real.

        Falsifiable: if the tool-def name did not match the ``restart``
        attribute, ``execute_tool_call``'s ``getattr(bridge, attr_name)``
        lookup would return ``None`` and this call would raise
        ``ToolError`` for an unknown function instead of returning a result
        with ``success=True``. Broken production line: the
        ``getattr(bridge, attr_name, None)`` dispatch in
        ``ToolRegistry.execute_tool_call`` combined with the
        ``x64dbg.restart`` tool-def name in ``bridges/x64dbg.py``.

        Args:
            bridge: Fresh bridge fixture.
            registry: Real, empty ToolRegistry fixture.
        """
        registry.register_bridge(ToolName.X64DBG, bridge)
        target_path = Path("C:/tmp/gate_dispatch.exe")
        setattr(bridge, "_binary_path", target_path)
        setattr(bridge, "_launch_args", None)

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return ok("")
            if command == "reg_get":
                return ok("0")
            if command == "status":
                return ok({"paused": True, "debugging": True})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        install_fake_pipe(bridge, responder)

        result = await registry.execute_tool_call("x64dbg", "x64dbg.restart", {})

        assert isinstance(result, dict)
        assert result["success"] is True
        assert result["path"] == str(target_path)


class TestRestartGuiL3:
    """L3: the toolbar Restart button calls ``X64DbgBridge.restart`` for real.

    Falsifiable: if ``_on_restart`` were rewired to call ``load()`` again (or
    any method other than ``restart``), the fake pipe's ``exec`` command
    list would never contain the ``InitDebug`` re-issue this test asserts,
    and the console/status-label text this test checks would differ.
    """

    @staticmethod
    def test_restart_button_exists_and_is_wired(qapp: QApplication) -> None:
        """A toolbar ``_restart_btn`` must exist and be connected to ``_on_restart``.

        Args:
            qapp: Session QApplication fixture.
        """
        del qapp
        panel = X64DbgPanel()
        try:
            assert hasattr(panel, "_restart_btn")
            restart_btn = priv(panel, "_restart_btn", QPushButton)
            assert restart_btn.text() == "Restart"
            receivers = restart_btn.receivers(restart_btn.clicked)
            assert receivers >= 1, "the Restart button's clicked signal must have at least one connected slot"
        finally:
            panel.deleteLater()

    @staticmethod
    def test_restart_button_click_invokes_bridge_restart_and_updates_console(qapp: QApplication) -> None:
        """Clicking Restart must run the real ``bridge.restart()`` coroutine and report success in the console.

        Args:
            qapp: Session QApplication fixture used to pump the Qt event loop
                so the cross-thread async result can be delivered.
        """
        panel = X64DbgPanel()
        bridge = X64DbgBridge()
        target_path = Path("C:/tmp/gate_gui_restart.exe")
        setattr(bridge, "_binary_path", target_path)
        setattr(bridge, "_launch_args", None)
        setattr(bridge, "_attached_pid", 1234)

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return ok("")
            if command == "status":
                return ok({"paused": True, "debugging": True})
            if command in _RESIDUAL_REFRESH_RPCS:
                return ok({})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = install_fake_pipe(bridge, responder)
        restart_btn = priv(panel, "_restart_btn", QPushButton)
        console_output = priv(panel, "_console_output", QPlainTextEdit)

        try:
            panel.set_bridge(bridge)
            restart_btn.click()

            pump_until(qapp, lambda: "restarted" in console_output.toPlainText().lower())

            exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
            assert any(cmd.startswith("InitDebug") for cmd in exec_cmds), (
                f"clicking Restart must drive bridge.restart(), which issues InitDebug; got {exec_cmds!r}"
            )
            assert "restarted" in console_output.toPlainText().lower()
        finally:
            panel.deleteLater()


class TestDisassembleAtDispatchRegression:
    """L1+L2 regression: ``x64dbg.disassemble_at`` dispatches and disassembles real code.

    Falsifiable: if the tool-def name were reverted to ``x64dbg.disassemble``
    (not matching the real ``disassemble_at`` method), or if
    ``supports_static_analysis`` were reverted to unset, the
    ``ToolRegistry.execute_tool_call`` call below would raise ``ToolError``
    (unknown function, or missing-capability) instead of returning real
    ``DisassemblyLine`` records decoded by Capstone from this test process's
    own executable image.
    """

    @staticmethod
    def test_disassemble_tool_def_name_is_disassemble_at(bridge: X64DbgBridge) -> None:
        """The registered tool-def must be named ``x64dbg.disassemble_at``, never the broken ``x64dbg.disassemble``.

        Args:
            bridge: Fresh bridge fixture.
        """
        names = {f.name for f in bridge.tool_definition.functions}
        assert "x64dbg.disassemble_at" in names
        assert "x64dbg.disassemble" not in names

    @staticmethod
    def test_bridge_declares_static_analysis_capability(bridge: X64DbgBridge) -> None:
        """``X64DbgBridge`` must declare ``supports_static_analysis=True`` so the capability gate passes.

        Falsifiable: if ``supports_static_analysis`` were reverted to its
        default (``False``), this assertion fails directly, and the dispatch
        test below would raise ``ToolError`` for a missing capability.

        Args:
            bridge: Fresh bridge fixture.
        """
        assert bridge.capabilities.supports_static_analysis is True

    @staticmethod
    @pytest.mark.asyncio
    async def test_disassemble_at_dispatches_and_decodes_real_process_memory(
        bridge: X64DbgBridge,
        registry: ToolRegistry,
    ) -> None:
        """Dispatching ``x64dbg.disassemble_at`` through the real registry must decode real instructions.

        Attaches to the current test-runner process (a real, live PID) and
        disassembles its own loaded module code via the bridge's Capstone
        fallback path (exercised because no plugin pipe is deployed). The
        independent oracle is that Capstone -- a real, trusted disassembler
        -- must successfully decode at least one instruction from
        genuinely-executable process memory, and that every returned
        address lies within the requested range.

        Args:
            bridge: Fresh bridge fixture.
            registry: Real, empty ToolRegistry fixture.
        """
        registry.register_bridge(ToolName.X64DBG, bridge)
        bridge.attached_pid = os.getpid()

        kernel32 = ctypes.windll.kernel32
        get_module_handle = kernel32.GetModuleHandleW
        get_module_handle.restype = ctypes.c_void_p
        module_base = get_module_handle(None)
        assert module_base, "GetModuleHandleW(None) must resolve the current process's own module base"

        result = await registry.execute_tool_call(
            "x64dbg",
            "x64dbg.disassemble_at",
            {"address": int(module_base), "count": 5},
        )

        assert isinstance(result, list)
        lines = cast("list[DisassemblyLine]", result)
        assert len(lines) > 0, "Capstone must decode at least one real instruction from live process memory"
        for line in lines:
            assert line.address >= int(module_base)
            assert line.mnemonic, "every decoded DisassemblyLine must carry a real mnemonic string"
            assert line.bytes_str, "every decoded DisassemblyLine must carry its real encoded bytes"
