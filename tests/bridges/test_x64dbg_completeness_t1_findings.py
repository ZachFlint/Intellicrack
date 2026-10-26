# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Completeness tests for ``intellicrack.bridges.x64dbg``.

Covers exception breakpoints, breakpoint command selection by breakpoint type, patch export with verified output, and preview-only ``assemble_at``.

- ``set_exception_config``: ``break`` issues a first-chance exception breakpoint, ``log`` issues an all-chance, logged, fast-resumed one, and ``ignore`` raises instead of sending an undocumented value.
- Breakpoint condition, log, command, fast-resume, enable and disable branch on the target breakpoint type and emit the matching hardware (``bphwcond``, ``bphe``, ``bphd``, ...) or memory (``bpmcond``, ``bpme``, ``bpmd``, ...) command family. The condition set is verified through a ``bp_list`` readback.
- ``export_patches`` supplies the three-argument ``savedata`` command spanning every applied patch and verifies that the output file exists before reporting success.
- ``assemble_at`` returns the encoded bytes without writing them to memory.

Each test scripts an in-process fake pipe client to replay deterministic plugin responses, so the bridge's command selection and verification logic runs end to end without launching x64dbg.exe.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from pathlib import Path


_HW_ADDR = 0x401000
_MEM_ADDR = 0x402000
_EXC_ACCESS_VIOLATION = 0xC0000005
_EXC_BREAKPOINT = 0x80000003

_Responder = Callable[[str, "dict[str, Any] | None"], "dict[str, Any]"]


class _FakePipeClient:
    """In-process substitute for ``NamedPipeClient``.

    Records every ``(command, params)`` pair the bridge sends and
    returns a canned response produced by a caller-supplied responder
    callable, in the style of the other fake pipe clients.
    """

    def __init__(self, responder: _Responder) -> None:
        """Initialize with a scripted responder callable.

        Args:
            responder: Callable ``(command, params) -> dict`` returning
                the canned plugin response.
        """
        self._responder = responder
        self.sent: list[tuple[str, dict[str, Any] | None]] = []

    @property
    def is_connected(self) -> bool:
        """Report the fake pipe as always connected.

        Returns:
            bool: Always ``True``.
        """
        return True

    async def send_command(self, command: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Record the request and return the scripted response.

        Args:
            command: RPC command name forwarded by the bridge.
            params: Optional parameter dict forwarded by the bridge.

        Returns:
            dict[str, Any]: Canned response from the responder.
        """
        self.sent.append((command, params))
        return self._responder(command, params)

    async def close(self) -> None:
        """No-op close to satisfy the ``NamedPipeClient`` interface."""


class _PlaceholderProcess:
    """Sentinel satisfying ``self._process is not None`` bridge guards."""

    def poll(self) -> int | None:
        """Report process status the way :class:`subprocess.Popen.poll` does.

        Returns:
            int | None: Always ``None``, indicating this stand-in debugger
            process is still running.
        """
        return None

    pid: int = 0


def _install_fake_pipe(bridge: X64DbgBridge, responder: _Responder) -> _FakePipeClient:
    """Attach a fake pipe client to a bridge and mark the plugin as deployed.

    Args:
        bridge: Bridge instance to configure.
        responder: Callable returning a canned response for each command.

    Returns:
        _FakePipeClient: The attached fake client for post-call assertion.
    """
    fake = _FakePipeClient(responder)
    setattr(bridge, "_pipe_client", fake)
    setattr(bridge, "_plugin_deployed", True)
    setattr(bridge, "_process", _PlaceholderProcess())
    return fake


def _success(result: object = None) -> dict[str, Any]:
    """Build a successful canned plugin response envelope.

    Args:
        result: Payload to place under the ``result`` key.

    Returns:
        dict[str, Any]: A ``{"id": 1, "success": True, "result": result}`` envelope.
    """
    return {"id": 1, "success": True, "result": result}


def _exec_commands(fake: _FakePipeClient) -> list[str]:
    """Collect every script string dispatched through the ``exec`` RPC.

    Args:
        fake: The fake pipe client recording the bridge's sends.

    Returns:
        list[str]: The ``command`` strings from every recorded ``exec`` send.
    """
    commands: list[str] = []
    for name, params in fake.sent:
        if name == "exec" and params is not None:
            script = params.get("command")
            if isinstance(script, str):
                commands.append(script)
    return commands


@pytest.fixture
def bridge() -> X64DbgBridge:
    """Construct a fresh, unattached bridge instance.

    Returns:
        X64DbgBridge: A bridge with no attached PID.
    """
    return X64DbgBridge()


@pytest.mark.asyncio
class TestSetExceptionConfigChanceMapping:
    """``set_exception_config`` uses real chance-scoped exception breakpoints."""

    async def test_break_sends_first_chance_exception_bpx(self, bridge: X64DbgBridge) -> None:
        """``handling='break'`` sends ``SetExceptionBPX <code>, first``.

        A numeric mapping such as ``{"break": 1, ...}`` sends ``SetExceptionBPX 0xc0000005, 1`` instead, so
        the exact-string assertion below fails.

        Args:
            bridge: Fixture bridge instance.
        """
        fake = _install_fake_pipe(bridge, lambda _c, _p: _success())
        result = await bridge.set_exception_config(_EXC_ACCESS_VIOLATION, "break")

        assert ("exec", {"command": "SetExceptionBPX 0xc0000005, first"}) in fake.sent
        assert result == {"success": True, "code": "0xc0000005", "handling": "break"}

    async def test_log_sends_all_chance_log_action_and_fast_resume(self, bridge: X64DbgBridge) -> None:
        """``handling='log'`` sets an all-chance, fast-resumed, logged exception breakpoint.

        A numeric mapping sends only
        ``SetExceptionBPX 0x80000003, 2`` (a stopping second-chance
        breakpoint) and never issues ``SetExceptionBreakpointLog`` or
        ``SetExceptionBreakpointFastResume``, so these three assertions fail.

        Args:
            bridge: Fixture bridge instance.
        """
        fake = _install_fake_pipe(bridge, lambda _c, _p: _success())
        result = await bridge.set_exception_config(_EXC_BREAKPOINT, "log")

        sent = _exec_commands(fake)
        assert "SetExceptionBPX 0x80000003, all" in sent
        assert 'SetExceptionBreakpointLog 0x80000003, "Exception 0x80000003 occurred at {cip}"' in sent
        assert "SetExceptionBreakpointFastResume 0x80000003, 1" in sent
        assert result == {"success": True, "code": "0x80000003", "handling": "log"}

    async def test_ignore_raises_without_sending_anything(self, bridge: X64DbgBridge) -> None:
        """``handling='ignore'`` raises instead of sending an undocumented chance value.

        A numeric ``handling_map`` sends
        ``SetExceptionBPX 0xc0000005, 0`` and returns success instead of
        raising, so ``pytest.raises`` fails and ``fake.sent`` is non-empty.

        Args:
            bridge: Fixture bridge instance.
        """
        fake = _install_fake_pipe(bridge, lambda _c, _p: _success())
        with pytest.raises(ToolError, match="no scriptable command"):
            await bridge.set_exception_config(_EXC_ACCESS_VIOLATION, "ignore")
        assert fake.sent == []

    async def test_unknown_handling_mode_raises(self, bridge: X64DbgBridge) -> None:
        """An unrecognised ``handling`` value raises rather than defaulting to break.

        A``handling_map.get(handling, 1)`` fallback silently defaults an unknown mode to a first-chance break breakpoint instead
        of raising, so ``pytest.raises`` fails.

        Args:
            bridge: Fixture bridge instance.
        """
        fake = _install_fake_pipe(bridge, lambda _c, _p: _success())
        with pytest.raises(ToolError, match="Unknown exception handling mode"):
            await bridge.set_exception_config(_EXC_ACCESS_VIOLATION, "bogus")
        assert fake.sent == []


@pytest.mark.asyncio
class TestBreakpointTypeCommandFamilies:
    """Breakpoint condition, log, command, fast-resume, enable and disable pick the right command family."""

    async def test_set_breakpoint_condition_uses_hardware_family(self, bridge: X64DbgBridge) -> None:
        """``set_breakpoint(..., bp_type="hardware", condition=...)`` sends ``bphwcond``.

        An unconditional ``bpcond`` command in ``set_breakpoint`` makes the ``bphwcond`` assertion
        fail and the forbidden ``bpcond`` string appear instead.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command in {"bp_set", "exec"}:
                return _success()
            if command == "bp_list":
                return _success(
                    [{"address": hex(_HW_ADDR), "type": "hardware", "enabled": True, "hitCount": 0, "breakCondition": "eax==1"}],
                )
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        bp_id = await bridge.set_breakpoint(_HW_ADDR, bp_type="hardware", condition="eax==1")

        assert bp_id == _HW_ADDR
        sent = _exec_commands(fake)
        assert 'bphwcond 0x401000, "eax==1"' in sent
        assert not any(cmd.startswith("bpcond ") for cmd in sent)

    async def test_set_breakpoint_condition_verification_raises_when_debugger_ignored_it(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """A condition that ``bp_list`` reports as unset raises instead of a false success.

        Without the ``_verify_breakpoint_condition`` call in ``set_breakpoint``, success is returned unconditionally, so
        ``pytest.raises`` observes no exception and fails.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command in {"bp_set", "exec"}:
                return _success()
            if command == "bp_list":
                return _success(
                    [{"address": hex(_MEM_ADDR), "type": "memory", "enabled": True, "hitCount": 0, "breakCondition": ""}],
                )
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        with pytest.raises(ToolError, match="condition verification failed"):
            await bridge.set_breakpoint(_MEM_ADDR, bp_type="memory", condition="1==1")

    async def test_configure_breakpoint_uses_hardware_family_for_every_property(self, bridge: X64DbgBridge) -> None:
        """``configure_breakpoint`` on a hardware breakpoint uses the hardware command family.

        ``configure_breakpoint`` resolves the type from the local registry that :meth:`~intellicrack.bridges.x64dbg.X64DbgBridge.set_breakpoint` populates, so this test first sets a real hardware breakpoint through the public API before configuring it.

        Unconditional software commands would send ``SetBreakpointLog``, ``SetBreakpointCommand``, ``SetBreakpointFastResume`` and ``bpcond`` instead, failing every assertion below.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command in {"bp_set", "exec"}:
                return _success()
            if command == "bp_list":
                return _success(
                    [{"address": hex(_HW_ADDR), "type": "hardware", "enabled": True, "hitCount": 0, "breakCondition": "1==1"}],
                )
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        await bridge.set_breakpoint(_HW_ADDR, bp_type="hardware")
        await bridge.configure_breakpoint(_HW_ADDR, condition="1==1", log_text="hit", command="run", fast_resume=True)

        sent = _exec_commands(fake)
        assert 'bphwcond 0x401000, "1==1"' in sent
        assert 'SetHardwareBreakpointLog 0x401000, "hit"' in sent
        assert 'SetHardwareBreakpointCommand 0x401000, "run"' in sent
        assert "SetHardwareBreakpointFastResume 0x401000, 1" in sent
        assert not any(cmd.startswith(("bpcond ", "SetBreakpointLog", "SetBreakpointCommand", "SetBreakpointFastResume")) for cmd in sent)

    async def test_enable_breakpoint_uses_hardware_command(self, bridge: X64DbgBridge) -> None:
        """``enable_breakpoint`` on a hardware breakpoint sends ``bphe``, not ``be``.

        A hardcoded ``be`` command in ``enable_breakpoint`` makes the ``bphe`` assertion fail.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command in {"bp_set", "exec"}:
                return _success()
            if command == "bp_list":
                return _success(
                    [{"address": hex(_HW_ADDR), "type": "hardware", "enabled": True, "hitCount": 0, "breakCondition": ""}],
                )
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        await bridge.set_breakpoint(_HW_ADDR, bp_type="hardware")
        result = await bridge.enable_breakpoint(_HW_ADDR)

        assert result["success"] is True
        assert ("exec", {"command": f"bphe {hex(_HW_ADDR)}"}) in fake.sent
        assert ("exec", {"command": f"be {hex(_HW_ADDR)}"}) not in fake.sent

    async def test_disable_breakpoint_uses_memory_command(self, bridge: X64DbgBridge) -> None:
        """``disable_breakpoint`` on a memory breakpoint sends ``bpmd``, not ``bd``.

        A hardcoded ``bd`` command in ``disable_breakpoint`` makes the ``bpmd`` assertion fail.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command in {"bp_set", "exec"}:
                return _success()
            if command == "bp_list":
                return _success(
                    [{"address": hex(_MEM_ADDR), "type": "memory", "enabled": False, "hitCount": 0, "breakCondition": ""}],
                )
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        await bridge.set_breakpoint(_MEM_ADDR, bp_type="memory")
        result = await bridge.disable_breakpoint(_MEM_ADDR)

        assert result["success"] is True
        assert ("exec", {"command": f"bpmd {hex(_MEM_ADDR)}"}) in fake.sent
        assert ("exec", {"command": f"bd {hex(_MEM_ADDR)}"}) not in fake.sent


@pytest.mark.asyncio
class TestExportPatches:
    """``export_patches`` supplies real ``savedata`` arguments and verifies the output."""

    async def test_dumps_minimal_span_and_verifies_output_file(self, bridge: X64DbgBridge, tmp_path: Path) -> None:
        """The dumped span covers every patch and the written file is confirmed on disk.

        A one-argument ``savedata "{path}"`` sends
        a different command string and this responder's ``savedata`` branch
        (matched by the exact three-argument prefix) never fires, so the
        output file is never written and the verification poll times out.

        Args:
            bridge: Fixture bridge instance.
            tmp_path: Pytest-provided temporary directory.
        """
        output_file = tmp_path / "patches.bin"
        dump_bytes = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "patch_list":
                return _success(
                    [
                        {"address": "0x401000", "oldByte": 0x90, "newByte": 0xCC},
                        {"address": "0x401005", "oldByte": 0x00, "newByte": 0x01},
                    ],
                )
            if command == "exec":
                cmd_text = (params or {}).get("command", "")
                if isinstance(cmd_text, str) and cmd_text.startswith(f'savedata "{output_file}", 0x401000, 0x6'):
                    output_file.write_bytes(dump_bytes)
                return _success()
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        result = await bridge.export_patches(str(output_file))

        assert result == {"success": True, "path": str(output_file), "address": "0x401000", "size": 6}
        assert ("exec", {"command": f'savedata "{output_file}", 0x401000, 0x6'}) in fake.sent
        assert output_file.read_bytes() == dump_bytes

    async def test_raises_when_no_patches_applied(self, bridge: X64DbgBridge, tmp_path: Path) -> None:
        """No applied patches raises instead of issuing a meaningless ``savedata`` call.

        An implementation that issues ``savedata`` and reports success with zero patches applied fails here: ``pytest.raises`` would
        observe no exception.

        Args:
            bridge: Fixture bridge instance.
            tmp_path: Pytest-provided temporary directory.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "patch_list":
                return _success([])
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        with pytest.raises(ToolError, match="No patches are currently applied"):
            await bridge.export_patches(str(tmp_path / "empty.bin"))
        assert all(name != "exec" for name, _ in fake.sent)

    async def test_raises_when_output_file_never_appears(self, bridge: X64DbgBridge, tmp_path: Path) -> None:
        """A ``savedata`` command that never actually writes the file raises.

        An implementation that ignores ``_send_command``'s result and always reports success fails this test. Removing the ``_await_file_written`` verification call (or its raise) makes ``pytest.raises`` observe no exception even though ``output_file`` is never created.

        Args:
            bridge: Fixture bridge instance.
            tmp_path: Pytest-provided temporary directory.
        """
        bridge.VERIFY_TIMEOUT = 0.05
        bridge.VERIFY_POLL_INTERVAL = 0.005
        output_file = tmp_path / "never_written.bin"

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "patch_list":
                return _success([{"address": "0x401000", "oldByte": 0x90, "newByte": 0xCC}])
            if command == "exec":
                return _success()
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        with pytest.raises(ToolError, match="was not written"):
            await bridge.export_patches(str(output_file))
        assert not output_file.exists()


@pytest.mark.asyncio
class TestAssembleAtPreviewOnly:
    """``assemble_at`` is preview-only and must never touch process memory."""

    async def test_assemble_at_does_not_call_write_memory(self, bridge: X64DbgBridge, monkeypatch: pytest.MonkeyPatch) -> None:
        """``assemble_at`` returns the encoded bytes without invoking ``write_memory``.

        Restoring an ``await self.write_memory(address, assembled)`` call makes the patched ``write_memory`` spy get invoked,
        failing the ``not called`` assertion.

        Args:
            bridge: Fixture bridge instance.
            monkeypatch: Pytest monkeypatch fixture.
        """
        pytest.importorskip("keystone", reason="keystone-engine not installed")

        calls: list[tuple[int, bytes]] = []

        async def _spy_write_memory(address: int, data: bytes) -> int:
            await asyncio.sleep(0)
            calls.append((address, data))
            return len(data)

        monkeypatch.setattr(bridge, "write_memory", _spy_write_memory)

        encoded = await bridge.assemble_at(_HW_ADDR, "nop")

        assert encoded == b"\x90"
        assert not calls
