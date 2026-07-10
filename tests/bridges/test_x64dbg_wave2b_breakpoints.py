# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Wave 2b breakpoint and watchpoint RPC gate tests for ``X64DbgBridge``.

Directly fixes FG-2 (breakpoints tautology): drives the real ``bp_list`` /
``wp_set`` / ``wp_remove`` RPCs via a canned in-process fake pipe and asserts
exact parsed ``BreakpointInfo`` / ``WatchpointInfo`` field values plus exact
command framing for set/remove/configure/api/dll/logging operations.  No
``BreakpointInfo`` objects are pre-inserted into ``_breakpoints`` and then
re-found (the tautology this file replaces).

Operations gated and their audit verdict:

* ``get_breakpoints`` — FG-2 tautology replaced with bp_list RPC round-trip
* ``remove_breakpoint`` — WEAK (only ToolError path existed)
* ``set_watchpoint`` — WEAK (only ToolError path existed)
* ``remove_watchpoint`` — NO COVERAGE
* ``set_breakpoint_on_api`` — WEAK (only monkeypatched, not RPC-verified)
* ``set_logging_breakpoint`` — NO COVERAGE
* ``configure_breakpoint`` — NO COVERAGE
* ``set_dll_breakpoint`` — NO COVERAGE

Operations skipped (verdict=REAL, do not duplicate):

* ``set_breakpoint`` — REAL (test_x64dbg_audit6.py TestSetBreakpointVerification)
* ``enable_breakpoint`` — REAL (test_x64dbg_audit7_f0001.py)
* ``disable_breakpoint`` — REAL (test_x64dbg_audit7_f0001.py)
* ``get_watchpoints`` — REAL (test_x64dbg.py:213-235)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

import pytest

from intellicrack.bridges.base import WatchpointInfo
from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.core.types import BreakpointInfo, ToolError


if TYPE_CHECKING:
    from collections.abc import Callable


_BP_ADDR: Final[int] = 0x401000
_BP_ADDR_2: Final[int] = 0x402000
_WP_ADDR: Final[int] = 0x500000
_WP_SIZE: Final[int] = 8
_API_VA: Final[int] = 0x7FFF_1234_5678
_LOG_TEXT: Final[str] = "breakpoint hit at counter={@rax}"
_DLL_NAME: Final[str] = "ntdll.dll"
_CONDITION_EXPR: Final[str] = "rax==0"
_COMMAND_EXPR: Final[str] = "msg log entry"


class _FakePipeClient:
    """In-process substitute for ``NamedPipeClient``.

    Records every ``(command, params)`` pair sent by the bridge and
    returns canned responses produced by the caller-supplied ``responder``.
    The ``sent`` list is populated on each ``send_command`` call and
    available for assertions after the method under test returns.
    """

    def __init__(
        self,
        responder: Callable[[str, dict[str, Any] | None], dict[str, Any]],
    ) -> None:
        """Initialise with a scripted responder callable.

        Args:
            responder: Maps ``(command, params)`` to the fake response dict.
        """
        self._responder = responder
        self.sent: list[tuple[str, dict[str, Any] | None]] = []

    @property
    def is_connected(self) -> bool:
        """Always report connected.

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


class _PlaceholderProcess:
    """Sentinel value that satisfies the ``self._process is not None`` guards.

    The bridge's ``_send_command`` raises ``ToolError("x64dbg not running")``
    when ``_process is None``.  This sentinel is wired in by
    :func:`_install_fake_pipe` so methods that call ``_send_command`` can
    proceed to the pipe layer without actually spawning x64dbg.exe.
    """


def _install_fake_pipe(
    bridge: X64DbgBridge,
    responder: Callable[[str, dict[str, Any] | None], dict[str, Any]],
) -> _FakePipeClient:
    """Attach a ``_FakePipeClient`` to ``bridge`` and mark the plugin deployed.

    Sets ``_pipe_client``, ``_plugin_deployed``, and ``_process`` via
    ``setattr`` so basedpyright's ``reportPrivateUsage`` rule is not
    triggered.  The ``_process`` sentinel allows methods that guard on
    ``self._process is not None`` (including ``_send_command``) to reach
    the pipe layer.

    Args:
        bridge: Bridge instance under test.
        responder: Callable returning a canned response for each command.

    Returns:
        _FakePipeClient: The freshly attached fake, useful for assertions
        on the ``sent`` list.
    """
    fake = _FakePipeClient(responder)
    setattr(bridge, "_pipe_client", fake)
    setattr(bridge, "_plugin_deployed", True)
    setattr(bridge, "_process", _PlaceholderProcess())
    return fake


@pytest.fixture
def bridge() -> X64DbgBridge:
    """Construct a fresh, unattached bridge instance.

    Returns:
        X64DbgBridge: A bridge with no attached PID and no pipe client.
    """
    return X64DbgBridge()


@pytest.mark.asyncio
class TestGetBreakpointsViaBpListRpc:
    """FG-2 fix: ``get_breakpoints`` drives the real ``bp_list`` RPC.

    The removed tautological test pre-inserted ``BreakpointInfo`` objects
    into ``bridge.breakpoints`` then called ``get_breakpoints()`` and found
    them — exercising only local tracking, never the plugin-side ``bp_list``
    RPC path.  These tests start with an empty local registry and verify the
    entire flow from RPC response to parsed ``BreakpointInfo`` field values.
    """

    async def test_bp_list_rpc_is_driven_and_fields_parsed(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Drive ``bp_list`` from the plugin side and assert all parsed fields.

        Independent oracle: the two canned ``bp_list`` entries with known
        address, type, enabled, hitCount, and breakCondition values.  Any
        mutation that reads fields from the wrong key (e.g. ``hit_count``
        instead of ``hitCount``) or skips the plugin-side path entirely will
        break the exact-value assertions here.

        Mutation caught: if ``get_breakpoints`` returns only
        ``list(self._breakpoints.values())`` without querying ``bp_list``, the
        returned list is empty and all assertions fail.

        Args:
            bridge: Fresh bridge fixture.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "bp_list":
                return {
                    "id": 1,
                    "success": True,
                    "result": [
                        {
                            "address": _BP_ADDR,
                            "type": "software",
                            "enabled": True,
                            "hitCount": 7,
                            "breakCondition": _CONDITION_EXPR,
                        },
                        {
                            "address": _BP_ADDR_2,
                            "type": "hardware",
                            "enabled": False,
                            "hitCount": 3,
                            "breakCondition": "",
                        },
                    ],
                }
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        assert len(bridge.breakpoints) == 0, "local registry must be empty before RPC call"

        bps = await bridge.get_breakpoints()

        assert ("bp_list", None) in fake.sent, "bp_list RPC must be sent to the plugin"
        by_addr = {bp.address: bp for bp in bps}

        assert _BP_ADDR in by_addr, f"software BP at {hex(_BP_ADDR)} must be parsed from bp_list"
        sw = by_addr[_BP_ADDR]
        assert sw.id == _BP_ADDR
        assert sw.bp_type == "software"
        assert sw.enabled is True
        assert sw.hit_count == 7
        assert sw.condition == _CONDITION_EXPR

        assert _BP_ADDR_2 in by_addr, f"hardware BP at {hex(_BP_ADDR_2)} must be parsed from bp_list"
        hw = by_addr[_BP_ADDR_2]
        assert hw.id == _BP_ADDR_2
        assert hw.bp_type == "hardware"
        assert hw.enabled is False
        assert hw.hit_count == 3
        assert hw.condition is None, "empty breakCondition string must map to None"

    async def test_bp_list_local_entry_takes_priority_over_plugin(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """When the same address exists locally and in ``bp_list``, local wins.

        The production code skips plugin entries whose address is already in
        ``merged`` (the local snapshot taken before the RPC).  This test
        confirms the local ``hit_count=99`` sentinel survives the merge so a
        mutation that replaces local entries with plugin entries is caught.

        Mutation caught: if plugin entries overwrite local entries, the
        ``hit_count`` assertion fails (plugin sends ``hitCount=0``).

        Args:
            bridge: Fresh bridge fixture.
        """
        local_bp = BreakpointInfo(
            id=_BP_ADDR,
            address=_BP_ADDR,
            bp_type="software",
            enabled=True,
            hit_count=99,
        )
        bridge.breakpoints[_BP_ADDR] = local_bp

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "bp_list":
                return {
                    "id": 1,
                    "success": True,
                    "result": [
                        {"address": _BP_ADDR, "type": "software", "enabled": True, "hitCount": 0},
                    ],
                }
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        bps = await bridge.get_breakpoints()

        by_addr = {bp.address: bp for bp in bps}
        assert by_addr[_BP_ADDR].hit_count == 99, (
            "local hit_count=99 must survive plugin-side hitCount=0; local entry takes priority over plugin entry for the same address"
        )

    async def test_bp_list_hardware_type_parsed_correctly(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """``hardware`` type string from plugin maps to ``bp_type='hardware'``.

        Mutation caught: if the type-dispatch branch for ``'hardware'`` is
        deleted and every type defaults to ``'software'``, this assertion
        fails.

        Args:
            bridge: Fresh bridge fixture.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "bp_list":
                return {
                    "id": 1,
                    "success": True,
                    "result": [{"address": _BP_ADDR, "type": "hardware", "enabled": True, "hitCount": 0}],
                }
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        bps = await bridge.get_breakpoints()

        assert len(bps) == 1
        assert bps[0].bp_type == "hardware", "plugin type='hardware' must produce bp_type='hardware', not 'software'"

    async def test_bp_list_empty_response_returns_empty_list(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """An empty ``bp_list`` from the plugin yields an empty result.

        Mutation caught: if ``get_breakpoints`` silently returns a
        non-empty list when ``bp_list`` is empty, this assertion fails.

        Args:
            bridge: Fresh bridge fixture.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "bp_list":
                return {"id": 1, "success": True, "result": []}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        bps = await bridge.get_breakpoints()

        assert bps == [], "empty bp_list must yield an empty list from get_breakpoints"

    async def test_bp_list_hex_address_string_parsed(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Hex-string addresses from the plugin are coerced to ``int``.

        The C++ plugin formats addresses as ``"0x..."`` strings.  This test
        verifies the ``_coerce_address`` path so a mutation that removes hex
        string parsing from ``get_breakpoints`` is caught.

        Mutation caught: if address coercion is removed, the parsed address
        remains a string or is ``None`` and the lookup fails.

        Args:
            bridge: Fresh bridge fixture.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "bp_list":
                return {
                    "id": 1,
                    "success": True,
                    "result": [
                        {"address": hex(_BP_ADDR), "type": "software", "enabled": True, "hitCount": 0},
                    ],
                }
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        bps = await bridge.get_breakpoints()

        assert len(bps) == 1
        assert bps[0].address == _BP_ADDR, f"hex-string address '{hex(_BP_ADDR)}' must be coerced to int {_BP_ADDR}"


@pytest.mark.asyncio
class TestRemoveBreakpointCommandFraming:
    """WEAK fix: ``remove_breakpoint`` drives the real ``bp_remove`` RPC.

    The previous test only checked the no-plugin ``ToolError`` path and
    manually inserted a ``BreakpointInfo`` without exercising the actual
    removal command sent to the debugger.
    """

    async def test_bp_remove_issued_with_exact_address(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """``bp_remove`` is sent with the exact integer address.

        Mutation caught: if ``remove_breakpoint`` sends ``bp_remove``
        with a hex-string address instead of the integer, the assertion
        on the params dict fails.

        Args:
            bridge: Fresh bridge fixture.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "bp_remove":
                return {"id": 1, "success": True, "result": True}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        bridge.breakpoints[_BP_ADDR] = BreakpointInfo(
            id=_BP_ADDR,
            address=_BP_ADDR,
            bp_type="software",
            enabled=True,
            hit_count=0,
        )

        result = await bridge.remove_breakpoint(_BP_ADDR)

        assert result is True
        assert ("bp_remove", {"address": hex(_BP_ADDR)}) in fake.sent, (
            f"bp_remove must be sent with address={hex(_BP_ADDR)!r}; sent={fake.sent!r}"
        )

    async def test_bp_remove_clears_local_registry(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """After ``remove_breakpoint`` the address is absent from local tracking.

        Mutation caught: if the registry pop is removed from
        ``remove_breakpoint``, the address persists in ``bridge.breakpoints``
        and this assertion fails.

        Args:
            bridge: Fresh bridge fixture.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "bp_remove":
                return {"id": 1, "success": True, "result": True}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        bridge.breakpoints[_BP_ADDR] = BreakpointInfo(
            id=_BP_ADDR,
            address=_BP_ADDR,
            bp_type="software",
            enabled=True,
            hit_count=0,
        )
        assert _BP_ADDR in bridge.breakpoints

        await bridge.remove_breakpoint(_BP_ADDR)

        assert _BP_ADDR not in bridge.breakpoints, "remove_breakpoint must pop the address from _breakpoints after bp_remove succeeds"

    async def test_bp_remove_not_connected_raises_tool_error(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Calling ``remove_breakpoint`` with no plugin raises ``ToolError``.

        Guards the no-plugin path that was the only gate in the previous WEAK
        test.  The ``match=`` argument pins the exact error text so any
        generic ``ToolError`` propagation from an unrelated path is not
        accidentally accepted.

        Args:
            bridge: Fresh bridge fixture.
        """
        with pytest.raises(ToolError, match=r"plugin|not available|not running"):
            await bridge.remove_breakpoint(_BP_ADDR)


@pytest.mark.asyncio
class TestSetWatchpointCommandFraming:
    """WEAK fix: ``set_watchpoint`` drives the real ``wp_set`` RPC.

    Verifies the access-type mapping (``read`` → ``r``, ``write`` → ``w``,
    ``execute`` → ``x``) and that the address and size reach the plugin.
    """

    async def test_write_watch_type_maps_to_w_access(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """``watch_type='write'`` produces ``access='w'`` in the ``wp_set`` params.

        Mutation caught: if the type_map lookup is removed and the access
        defaults to ``'rw'``, the assertion ``access == 'w'`` fails.

        Args:
            bridge: Fresh bridge fixture.
        """
        received: dict[str, Any] = {}

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "wp_set":
                if params:
                    received.update(params)
                return {"id": 1, "success": True, "result": None}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        await bridge.set_watchpoint(_WP_ADDR, _WP_SIZE, "write")

        assert received.get("address") == hex(_WP_ADDR)
        assert received.get("size") == _WP_SIZE
        assert received.get("access") == "w", f"watch_type='write' must map to access='w', got {received.get('access')!r}"

    async def test_read_watch_type_maps_to_r_access(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """``watch_type='read'`` produces ``access='r'`` in the ``wp_set`` params.

        Mutation caught: if ``read`` is mapped to the wrong access string.

        Args:
            bridge: Fresh bridge fixture.
        """
        received: dict[str, Any] = {}

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "wp_set":
                if params:
                    received.update(params)
                return {"id": 1, "success": True, "result": None}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        await bridge.set_watchpoint(_WP_ADDR, _WP_SIZE, "read")

        assert received.get("access") == "r", f"watch_type='read' must map to access='r', got {received.get('access')!r}"

    async def test_execute_watch_type_maps_to_x_access(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """``watch_type='execute'`` produces ``access='x'`` in the ``wp_set`` params.

        Mutation caught: if ``execute`` is mapped to the wrong access string.

        Args:
            bridge: Fresh bridge fixture.
        """
        received: dict[str, Any] = {}

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "wp_set":
                if params:
                    received.update(params)
                return {"id": 1, "success": True, "result": None}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        await bridge.set_watchpoint(_WP_ADDR, _WP_SIZE, "execute")

        assert received.get("access") == "x", f"watch_type='execute' must map to access='x', got {received.get('access')!r}"

    async def test_set_watchpoint_registers_in_local_dict(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """The returned watchpoint id resolves to a ``WatchpointInfo`` entry.

        Mutation caught: if the local ``_watchpoints`` dict is not populated
        after a successful ``wp_set``, ``bridge.watchpoints`` will be empty
        and the address lookup will fail.

        Args:
            bridge: Fresh bridge fixture.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "wp_set":
                return {"id": 1, "success": True, "result": None}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        wp_id = await bridge.set_watchpoint(_WP_ADDR, _WP_SIZE, "write")

        assert isinstance(wp_id, int)
        assert wp_id in bridge.watchpoints
        wp = bridge.watchpoints[wp_id]
        assert wp.address == _WP_ADDR
        assert wp.size == _WP_SIZE
        assert wp.watch_type == "write"
        assert wp.enabled is True


@pytest.mark.asyncio
class TestRemoveWatchpoint:
    """NO COVERAGE → real gates: ``remove_watchpoint`` drives ``wp_remove`` RPC."""

    async def test_wp_remove_issued_with_watchpoint_address(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """``wp_remove`` is sent with the watchpoint's stored address.

        Mutation caught: if ``remove_watchpoint`` sends a wrong address
        (e.g. the watchpoint id instead of its address), the params
        assertion fails.

        Args:
            bridge: Fresh bridge fixture.
        """
        wp_id = 1
        bridge.watchpoints[wp_id] = WatchpointInfo(
            id=wp_id,
            address=_WP_ADDR,
            size=_WP_SIZE,
            watch_type="write",
            enabled=True,
            hit_count=0,
        )

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "wp_remove":
                return {"id": 1, "success": True, "result": True}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        result = await bridge.remove_watchpoint(wp_id)

        assert result is True
        assert ("wp_remove", {"address": hex(_WP_ADDR)}) in fake.sent, (
            f"wp_remove must be sent with address={hex(_WP_ADDR)!r}; got sent={fake.sent!r}"
        )

    async def test_wp_remove_clears_local_registry(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """After ``remove_watchpoint`` the id is absent from local tracking.

        Mutation caught: if the registry pop is removed from
        ``remove_watchpoint``, the entry persists and this assertion fails.

        Args:
            bridge: Fresh bridge fixture.
        """
        wp_id = 1
        bridge.watchpoints[wp_id] = WatchpointInfo(
            id=wp_id,
            address=_WP_ADDR,
            size=_WP_SIZE,
            watch_type="write",
            enabled=True,
            hit_count=0,
        )

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "wp_remove":
                return {"id": 1, "success": True, "result": True}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        await bridge.remove_watchpoint(wp_id)

        assert wp_id not in bridge.watchpoints, "remove_watchpoint must pop the id from _watchpoints after wp_remove succeeds"

    async def test_wp_remove_unknown_id_returns_false_no_rpc(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Removing an unknown watchpoint id returns ``False`` without an RPC call.

        Mutation caught: if the guard ``if watchpoint is None: return False``
        is removed, the code tries to issue ``wp_remove`` with ``None``
        address and either crashes or sends an unexpected command.

        Args:
            bridge: Fresh bridge fixture.
        """
        commands_sent: list[str] = []

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            commands_sent.append(command)
            return {"id": 1, "success": True, "result": None}

        _install_fake_pipe(bridge, responder)
        result = await bridge.remove_watchpoint(9999)

        assert result is False
        assert not commands_sent, "no RPC must be sent when the watchpoint id is unknown"


@pytest.mark.asyncio
class TestSetBreakpointOnApi:
    """WEAK fix: ``set_breakpoint_on_api`` drives the real eval + bp_set RPCs.

    The existing test only monkeypatched ``set_breakpoint`` so the eval →
    resolution path was never exercised end-to-end over a fake pipe.
    """

    async def test_resolved_path_drives_eval_then_bp_set(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """When ``eval`` returns a non-zero VA, ``bp_set`` is issued at that VA.

        Mutation caught: if ``set_breakpoint_on_api`` uses a wrong
        expression format for ``eval``, or issues ``bp_set`` at a
        different address than the one ``eval`` returned, the assertion
        on the ``eval`` expression or the ``breakpoint_id`` field fails.

        Args:
            bridge: Fresh bridge fixture.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "eval":
                return {"id": 1, "success": True, "result": _API_VA}
            if command == "bp_set":
                return {"id": 1, "success": True, "result": hex(_API_VA)}
            if command == "bp_list":
                return {
                    "id": 1,
                    "success": True,
                    "result": [{"address": _API_VA, "type": "software", "enabled": True}],
                }
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        module = "kernel32"
        function = "CreateFileW"
        expected_expr = f'GetProcAddress({module},"{function}")'

        result = await bridge.set_breakpoint_on_api(module, function)

        eval_calls = [p for c, p in fake.sent if c == "eval"]
        assert eval_calls, "eval must be sent to resolve the API address"
        assert eval_calls[0] == {"expression": expected_expr}, (
            f"eval must use the exact expression '{expected_expr}', got {eval_calls[0]!r}"
        )

        bp_set_calls = [p for c, p in fake.sent if c == "bp_set"]
        assert bp_set_calls, "bp_set must be issued after successful eval"
        assert bp_set_calls[0] is not None
        assert bp_set_calls[0].get("address") == hex(_API_VA), (
            f"bp_set address must be the VA from eval ({hex(_API_VA)!r}), got {bp_set_calls[0].get('address')!r}"
        )

        assert result["success"] is True
        assert result["resolved_address"] == hex(_API_VA)
        assert result["resolution_method"] == "GetProcAddress"
        assert result["breakpoint_id"] == _API_VA
        assert result["target"] == f"{module}.{function}"

    async def test_unresolved_path_falls_back_to_bpx_command(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """When ``eval`` returns 0, ``bpx module.function`` is sent via ``exec``.

        Mutation caught: if the fallback path sends the wrong target
        string (e.g. ``"bpx kernel32!CreateFileW"`` instead of dot
        notation), the command assertion fails.

        Args:
            bridge: Fresh bridge fixture.
        """
        module = "kernel32"
        function = "RegOpenKeyExW"
        expected_bpx = f"bpx {module}.{function}"

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "eval":
                return {"id": 1, "success": True, "result": 0}
            if command == "exec":
                return {"id": 1, "success": True, "result": ""}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        result = await bridge.set_breakpoint_on_api(module, function)

        exec_calls = [(c, p) for c, p in fake.sent if c == "exec"]
        assert exec_calls, "exec must be sent for the bpx fallback path"
        bpx_params = exec_calls[0][1]
        assert bpx_params is not None
        assert bpx_params.get("command") == expected_bpx, f"bpx command must be '{expected_bpx}', got {bpx_params.get('command')!r}"

        assert result["success"] is True
        assert result["resolved_address"] is None, "unresolved path must set resolved_address=None"
        assert result["resolution_method"] == "bpx"
        assert "breakpoint_id" not in result

    async def test_eval_failure_falls_back_to_bpx(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """When ``eval`` raises ``ToolError``, the fallback ``bpx`` path is used.

        Mutation caught: if the ``ToolError`` catch in ``set_breakpoint_on_api``
        is removed, the error propagates rather than falling back, and the
        test expects a success return but gets an exception.

        Args:
            bridge: Fresh bridge fixture.
        """
        module = "advapi32"
        function = "RegCloseKey"

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "eval":
                return {"id": 1, "success": False, "error": "expression evaluate failed"}
            if command == "exec":
                return {"id": 1, "success": True, "result": ""}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.set_breakpoint_on_api(module, function)

        assert result["success"] is True
        assert result["resolution_method"] == "bpx"
        assert result["resolved_address"] is None


@pytest.mark.asyncio
class TestSetLoggingBreakpoint:
    """NO COVERAGE → real gates: ``set_logging_breakpoint`` exec command framing."""

    async def test_three_exec_commands_emitted_when_non_stopping(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """With ``non_stopping=True`` (default), exactly three ``exec`` commands are sent.

        The oracle is the three known x64dbg script commands:
        ``bp {addr}``, ``SetBreakpointLog {addr}, "..."`` and
        ``SetBreakpointFastResume {addr}, 1``.

        Mutation caught: if the ``bp`` command or ``SetBreakpointFastResume``
        is removed from ``set_logging_breakpoint``, the count drops below 3
        and the framing assertions fail.

        Args:
            bridge: Fresh bridge fixture.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": ""}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        result = await bridge.set_logging_breakpoint(_BP_ADDR, _LOG_TEXT, non_stopping=True)

        exec_commands = [p["command"] for _, p in fake.sent if p and "command" in p]
        expected_bp = f"bp {hex(_BP_ADDR)}"
        expected_log = f'SetBreakpointLog {hex(_BP_ADDR)}, "{_LOG_TEXT}"'
        expected_resume = f"SetBreakpointFastResume {hex(_BP_ADDR)}, 1"

        assert expected_bp in exec_commands, f"'{expected_bp}' must be sent; got {exec_commands!r}"
        assert expected_log in exec_commands, f"'{expected_log}' must be sent; got {exec_commands!r}"
        assert expected_resume in exec_commands, f"'{expected_resume}' must be sent when non_stopping=True; got {exec_commands!r}"

        assert result["success"] is True
        assert result["address"] == hex(_BP_ADDR)
        assert result["log_text"] == _LOG_TEXT

    async def test_fast_resume_omitted_when_non_stopping_false(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """With ``non_stopping=False``, ``SetBreakpointFastResume`` is not sent.

        Mutation caught: if the ``if non_stopping:`` branch is removed and
        ``SetBreakpointFastResume`` is always sent, this assertion fails.

        Args:
            bridge: Fresh bridge fixture.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": ""}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        await bridge.set_logging_breakpoint(_BP_ADDR, _LOG_TEXT, non_stopping=False)

        exec_commands = [p["command"] for _, p in fake.sent if p and "command" in p]
        fast_resume_cmd = f"SetBreakpointFastResume {hex(_BP_ADDR)}, 1"
        assert fast_resume_cmd not in exec_commands, (
            f"SetBreakpointFastResume must NOT be sent when non_stopping=False; got {exec_commands!r}"
        )
        assert f"bp {hex(_BP_ADDR)}" in exec_commands
        assert f'SetBreakpointLog {hex(_BP_ADDR)}, "{_LOG_TEXT}"' in exec_commands


@pytest.mark.asyncio
class TestConfigureBreakpoint:
    """NO COVERAGE → real gates: ``configure_breakpoint`` per-property command framing."""

    async def test_condition_issues_bpcond_with_quoted_expression(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Providing ``condition`` sends ``bpcond {addr}, "{expr}"`` via exec.

        Mutation caught: if the address or expression is formatted
        incorrectly (e.g. decimal instead of hex, or unquoted expression),
        the exact-string assertion fails.

        Args:
            bridge: Fresh bridge fixture.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": ""}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        result = await bridge.configure_breakpoint(_BP_ADDR, condition=_CONDITION_EXPR)

        exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
        expected = f'bpcond {hex(_BP_ADDR)}, "{_CONDITION_EXPR}"'
        assert expected in exec_cmds, f"'{expected}' must be sent when condition is provided; got {exec_cmds!r}"
        assert result["success"] is True
        assert result["address"] == hex(_BP_ADDR)

    async def test_log_text_issues_set_breakpoint_log_command(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Providing ``log_text`` sends ``SetBreakpointLog {addr}, "..."`` via exec.

        Mutation caught: if the command name is misspelled or the log text
        is not quoted, the exact-string assertion fails.

        Args:
            bridge: Fresh bridge fixture.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": ""}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        await bridge.configure_breakpoint(_BP_ADDR, log_text=_LOG_TEXT)

        exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
        expected = f'SetBreakpointLog {hex(_BP_ADDR)}, "{_LOG_TEXT}"'
        assert expected in exec_cmds, f"'{expected}' must be sent when log_text is provided; got {exec_cmds!r}"

    async def test_command_issues_set_breakpoint_command(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Providing ``command`` sends ``SetBreakpointCommand {addr}, "..."`` via exec.

        Mutation caught: if ``SetBreakpointCommand`` is misspelled or the
        command text is not quoted, the exact-string assertion fails.

        Args:
            bridge: Fresh bridge fixture.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": ""}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        await bridge.configure_breakpoint(_BP_ADDR, command=_COMMAND_EXPR)

        exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
        expected = f'SetBreakpointCommand {hex(_BP_ADDR)}, "{_COMMAND_EXPR}"'
        assert expected in exec_cmds, f"'{expected}' must be sent when command is provided; got {exec_cmds!r}"

    async def test_fast_resume_issues_set_breakpoint_fast_resume(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Providing ``fast_resume=True`` sends ``SetBreakpointFastResume`` via exec.

        Mutation caught: if the ``if fast_resume:`` branch is inverted or
        removed, the command is not sent and the assertion fails.

        Args:
            bridge: Fresh bridge fixture.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": ""}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        await bridge.configure_breakpoint(_BP_ADDR, fast_resume=True)

        exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
        expected = f"SetBreakpointFastResume {hex(_BP_ADDR)}, 1"
        assert expected in exec_cmds, f"'{expected}' must be sent when fast_resume=True; got {exec_cmds!r}"

    async def test_no_options_sends_no_exec_commands(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Calling with no optional arguments sends no ``exec`` commands.

        Mutation caught: if any branch executes unconditionally, an
        unexpected ``exec`` command is sent and this assertion fails.

        Args:
            bridge: Fresh bridge fixture.
        """
        commands_sent: list[str] = []

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            commands_sent.append(command)
            return {"id": 1, "success": True, "result": ""}

        _install_fake_pipe(bridge, responder)
        result = await bridge.configure_breakpoint(_BP_ADDR)

        assert not commands_sent, f"no exec commands must be sent when no options are provided; got {commands_sent!r}"
        assert result["success"] is True
        assert result["address"] == hex(_BP_ADDR)


@pytest.mark.asyncio
class TestSetDllBreakpoint:
    """NO COVERAGE → real gates: ``set_dll_breakpoint`` exec command framing."""

    async def test_load_event_issues_librarian_set_break_point(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """``event='load'`` sends ``LibrarianSetBreakPoint "{dll}"`` via exec.

        Mutation caught: if the command name or dll formatting is wrong
        (e.g. missing quotes), the exact-string assertion fails.

        Args:
            bridge: Fresh bridge fixture.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": ""}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        result = await bridge.set_dll_breakpoint(_DLL_NAME, event="load")

        exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
        expected = f'LibrarianSetBreakPoint "{_DLL_NAME}"'
        assert expected in exec_cmds, f"'{expected}' must be sent for event='load'; got {exec_cmds!r}"
        assert result["success"] is True
        assert result["dll_name"] == _DLL_NAME
        assert result["event"] == "load"

    async def test_unload_event_appends_unload_suffix(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """``event='unload'`` appends ``, unload`` to the ``LibrarianSetBreakPoint`` command.

        Mutation caught: if the ``if event == 'unload':`` branch is removed
        or the suffix is wrong, the unload command assertion fails while the
        load command would have passed.

        Args:
            bridge: Fresh bridge fixture.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": ""}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        result = await bridge.set_dll_breakpoint(_DLL_NAME, event="unload")

        exec_cmds = [p["command"] for _, p in fake.sent if p and "command" in p]
        expected = f'LibrarianSetBreakPoint "{_DLL_NAME}", unload'
        load_only = f'LibrarianSetBreakPoint "{_DLL_NAME}"'
        assert expected in exec_cmds, f"'{expected}' must be sent for event='unload'; got {exec_cmds!r}"
        assert load_only not in exec_cmds or exec_cmds.count(load_only) == 0, "the load-only form must not appear when event='unload'"
        assert result["success"] is True
        assert result["dll_name"] == _DLL_NAME
        assert result["event"] == "unload"
