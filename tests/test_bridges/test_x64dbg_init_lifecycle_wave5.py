# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Wave 5 lifecycle gates: initialize, load, attach, detach, spawn, shutdown.

Each test drives the real ``X64DbgBridge`` method through a fake transport
boundary (for pipe-side paths) or live Win32 APIs (for native-only paths) and
asserts exact state transitions and RPC framing.  No production code is
patched or replaced — only the named-pipe transport boundary is faked.

Findings closed:
    1  initialize(tool_path) — path storage and connection-state logic
    2  load(path, args) — InitDebug command framing and binary_loaded state
    3  attach(pid) — PID-0 arch-detection error
    4  detach() — detach command framing and attached-pid clearance
    5  spawn(path, args) — delegates to load with correct args
    6  shutdown() — finalization clears attached-pid despite close() errors
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import pytest

from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import Callable


_PYTHON_EXE: Final[Path] = Path(sys.executable)
_CANNED_PID_HEX: Final[str] = "0x1234"
_CANNED_PID_INT: Final[int] = 0x1234


class _FakePipeClient:
    """In-process substitute for ``NamedPipeClient``.

    Records every ``(command, params)`` pair the bridge sends in ``self.sent``
    and returns canned responses from the caller-supplied responder callable.
    """

    def __init__(
        self,
        responder: Callable[[str, dict[str, Any] | None], dict[str, Any]],
    ) -> None:
        """Initialise with a scripted responder callable.

        Args:
            responder: Maps ``(command, params)`` to a canned response dict.
        """
        self._responder = responder
        self.sent: list[tuple[str, dict[str, Any] | None]] = []

    @property
    def is_connected(self) -> bool:
        """Report as always connected.

        Returns:
            bool: Always ``True``.
        """
        return True

    async def send_command(
        self,
        command: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
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
        """No-op close to satisfy the NamedPipeClient interface."""


class _PlaceholderProcess:
    """Sentinel satisfying ``self._process is not None`` bridge guards.

    Allows bridge methods that raise ``ToolError("x64dbg not running")`` when
    ``_process is None`` to reach the pipe layer without spawning x64dbg.exe.
    """

    pid: int = 0


def _install_fake_pipe(
    bridge: X64DbgBridge,
    responder: Callable[[str, dict[str, Any] | None], dict[str, Any]],
) -> _FakePipeClient:
    """Attach a fake pipe client to a bridge and mark the plugin as deployed.

    Args:
        bridge: Bridge instance to configure.
        responder: Callable returning a canned response for each command.

    Returns:
        _FakePipeClient: The attached fake client, available for post-call
            assertions on its ``sent`` list.
    """
    fake = _FakePipeClient(responder)
    setattr(bridge, "_pipe_client", fake)
    setattr(bridge, "_plugin_deployed", True)
    setattr(bridge, "_process", _PlaceholderProcess())
    return fake


def _load_responder(
    command: str,
    params: dict[str, Any] | None,
) -> dict[str, Any]:
    """Return canned responses for load / spawn pipe interactions.

    Handles ``exec`` (empty output) and ``reg_get`` (fake PID ``0x1234``).
    Any other command receives a null-result success response so the bridge
    can continue to its return value.

    Args:
        command: RPC command name.
        params: Optional parameter dict.

    Returns:
        dict[str, Any]: Canned success response.
    """
    del params
    if command == "reg_get":
        return {"success": True, "result": _CANNED_PID_HEX}
    return {"success": True, "result": ""}


@pytest.fixture
def bridge() -> X64DbgBridge:
    """Construct a fresh, unattached bridge instance.

    Returns:
        X64DbgBridge: Bridge with no attached PID and no pipe client.
    """
    return X64DbgBridge()


@pytest.mark.asyncio
class TestInitialize:
    """Gate ``initialize`` — path storage and connection-state logic."""

    async def test_none_path_leaves_x64dbg_path_none(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """``initialize(None)`` stores ``None`` and leaves state.connected=False.

        Oracle: x64dbg.py:2056 ``self._x64dbg_path = tool_path`` and the
        ``BridgeState`` default (``connected=False``).
        Mutation caught: removing the ``_x64dbg_path = tool_path`` assignment
        (or inadvertently setting ``connected=True``) → assertion fails.

        Args:
            bridge: Fresh bridge fixture.
        """
        await bridge.initialize(None)
        assert bridge.x64dbg_path is None
        assert bridge.state.connected is False

    async def test_nonexistent_dir_stores_path_but_stays_disconnected(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """A directory without x64dbg.exe stores the path but does not connect.

        Oracle: x64dbg.py:2071 ``if x64_exe.exists() or x32_exe.exists()``
        guards ``self._state.connected = True`` — non-existent path never
        reaches that branch.
        Mutation caught: setting ``connected = True`` unconditionally or
        storing the wrong path value → assertion fails.

        Args:
            bridge: Fresh bridge fixture.
        """
        fake_dir = Path("C:/nonexistent_x64dbg_dir_wave5_init")
        await bridge.initialize(fake_dir)
        assert bridge.x64dbg_path == fake_dir
        assert bridge.state.connected is False


@pytest.mark.skipif(sys.platform != "win32", reason="PE architecture detection reads a Windows PE")
@pytest.mark.asyncio
class TestLoad:
    """Gate ``load`` — InitDebug command framing and state update."""

    async def test_nonexistent_file_raises_tool_error_containing_not_found(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """``load`` with a non-existent path raises ``ToolError`` before the pipe.

        Oracle: x64dbg.py:2744 ``if not await asyncio.to_thread(path.exists):``
        raises ``ToolError(f"File not found: {path}")``.
        Mutation caught: removing the existence guard → ``ToolError`` is not
        raised and the test fails.

        Args:
            bridge: Fresh bridge fixture.
        """
        with pytest.raises(ToolError, match=r"not found"):
            await bridge.load(Path("C:/no_such_binary_wave5_test.exe"))

    async def test_sends_initdebug_with_exact_posix_path(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """``load`` sends the exact ``InitDebug "…"`` command through the pipe.

        Oracle: x64dbg.py:2755 ``cmd = f'InitDebug "{path.as_posix()}"'``.
        Mutation caught: using ``path.name`` or ``str(path)`` instead of
        ``as_posix()`` → command string changes → exact-tuple assertion fails.

        Args:
            bridge: Fresh bridge fixture.
        """
        fake = _install_fake_pipe(bridge, _load_responder)
        await bridge.load(_PYTHON_EXE)

        expected_cmd: str = f'InitDebug "{_PYTHON_EXE.as_posix()}"'
        assert ("exec", {"command": expected_cmd}) in fake.sent

    async def test_sets_binary_loaded_state_after_success(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """After a successful ``load`` the bridge sets ``state.binary_loaded``.

        Oracle: x64dbg.py:2777 ``self._state.binary_loaded = True``.
        Mutation caught: removing that assignment → ``state.binary_loaded``
        stays ``False`` → assertion fails.

        Args:
            bridge: Fresh bridge fixture.
        """
        _install_fake_pipe(bridge, _load_responder)
        await bridge.load(_PYTHON_EXE)
        assert bridge.state.binary_loaded is True


@pytest.mark.skipif(
    sys.platform != "win32",
    reason="arch detection calls Win32 OpenProcess which requires Windows",
)
@pytest.mark.asyncio
class TestAttach:
    """Gate ``attach`` — architecture detection and ToolError for PID 0."""

    async def test_pid_zero_raises_cannot_detect_architecture(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """``attach(0)`` raises ``ToolError`` because OpenProcess(pid=0) always fails.

        Oracle: Windows API contract — ``OpenProcess(PROCESS_QUERY_INFORMATION,
        False, 0)`` returns NULL; x64dbg.py:2869 ``if is_64 is None: raise
        ToolError("x64dbg cannot detect architecture for pid …")``.
        Mutation caught: removing the ``is_64 is None`` guard → the bridge
        proceeds to ``_start_debugger`` instead → different exception or none.

        Args:
            bridge: Fresh bridge fixture.
        """
        with pytest.raises(ToolError, match=r"cannot detect architecture"):
            await bridge.attach(0)


@pytest.mark.asyncio
class TestDetach:
    """Gate ``detach`` — send detach command and clear attached-pid state."""

    async def test_sends_detach_command_and_clears_attached_pid(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """``detach`` sends ``("exec", {"command": "detach"})`` and clears the pid.

        Oracle: x64dbg.py:2976 ``await self._send_command("detach")`` and
        x64dbg.py:2978 ``self._attached_pid = None``.
        Mutation caught: renaming the command to ``"Detach"`` → exact-string
        assertion fails; removing ``_attached_pid = None`` → pid assertion fails.

        Args:
            bridge: Fresh bridge fixture.
        """
        bridge.attached_pid = 9999

        def _simple_responder(
            command: str,
            _params: dict[str, Any] | None,
        ) -> dict[str, Any]:
            del command
            return {"success": True, "result": ""}

        fake = _install_fake_pipe(bridge, _simple_responder)
        await bridge.detach()

        assert bridge.attached_pid is None
        assert bridge.state.process_attached is False
        assert ("exec", {"command": "detach"}) in fake.sent


@pytest.mark.skipif(sys.platform != "win32", reason="PE detection requires a valid Windows PE binary")
@pytest.mark.asyncio
class TestSpawn:
    """Gate ``spawn`` — delegates to load with correct args, returns PID."""

    async def test_sends_initdebug_with_quoted_args_and_returns_pid(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """``spawn`` builds the command line correctly and returns the parsed PID.

        Oracle: x64dbg.py:4414 ``args_str = self._build_cmdline(args)``;
        x64dbg.py:2757 ``cmd += f', "{args}"'``; PID parsed from
        ``_CANNED_PID_HEX`` via ``int(pid_result, 0)`` = ``_CANNED_PID_INT``.
        Mutation caught: not appending args → command mismatch; not returning
        ``_attached_pid`` → wrong PID returned.

        Args:
            bridge: Fresh bridge fixture.
        """
        fake = _install_fake_pipe(bridge, _load_responder)
        returned_pid = await bridge.spawn(_PYTHON_EXE, ["--version"])

        exe_posix: str = _PYTHON_EXE.as_posix()
        expected_cmd: str = f'InitDebug "{exe_posix}", "--version"'
        assert ("exec", {"command": expected_cmd}) in fake.sent
        assert returned_pid == _CANNED_PID_INT


@pytest.mark.asyncio
class TestShutdown:
    """Gate ``shutdown`` — finalization clears attached-pid and propagates errors."""

    async def test_clears_attached_pid(self, bridge: X64DbgBridge) -> None:
        """``shutdown`` sets ``attached_pid`` to ``None`` via finalization.

        Oracle: x64dbg.py:2184 ``self._attached_pid = None`` inside
        ``_run_shutdown_finalization``, which runs in a ``finally`` block.
        Mutation caught: removing that assignment → the property still returns
        the pre-shutdown PID → assertion fails.

        Args:
            bridge: Fresh bridge fixture.
        """
        bridge.attached_pid = 5678
        await bridge.shutdown()
        assert bridge.attached_pid is None

    async def test_oserror_in_close_propagates_but_attached_pid_is_still_cleared(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """A ``close()`` error propagates AND ``attached_pid`` is still cleared.

        Installs a fake pipe whose ``close()`` raises ``OSError`` to trigger the
        cleanup-error path, then asserts that:
        (a) the error is re-raised as ``OSError``
        (b) ``attached_pid`` is ``None`` because ``_run_shutdown_finalization``
            runs in a ``finally`` block even when ``_close_connection`` raised.

        Oracle: x64dbg.py:2103-2115 ``try/_run_shutdown_phase``/``finally``
        ``_run_shutdown_finalization``; x64dbg.py:2184 ``_attached_pid = None``.
        Mutation caught: moving ``_attached_pid = None`` inside the try-block
        that the OSError aborts → the PID is not cleared → assertion fails.

        Args:
            bridge: Fresh bridge fixture.
        """

        class _ErrorPipeClient:
            @property
            def is_connected(self) -> bool:
                return True

            async def close(self) -> None:
                msg = "pipe close failed"
                raise OSError(msg)

            async def send_command(
                self,
                command: str,
                params: dict[str, Any] | None = None,
            ) -> dict[str, Any]:
                del command, params
                return {"success": True, "result": ""}

        setattr(bridge, "_pipe_client", _ErrorPipeClient())
        setattr(bridge, "_plugin_deployed", True)
        bridge.attached_pid = 7777

        with pytest.raises(OSError, match=r"pipe close failed"):
            await bridge.shutdown()

        assert bridge.attached_pid is None
