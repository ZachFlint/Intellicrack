# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Coverage-gap tests for the x64dbg bridge trace, scripting, anti-debug and handle surfaces.

x64dbg is not installed in the test container, so every expectation here is derived
independently of the bridge and drives only what is reachable without a debugger:

* the documented PEB layout (``BeingDebugged`` at +0x02, ``ProcessHeap`` at +0x30 and
  ``NtGlobalFlag`` at +0xBC on x64) and the heap flag offsets, exercised against real memory
  of the test process through ``ReadProcessMemory`` / ``WriteProcessMemory``;
* the documented ``IMAGE_RESOURCE_DIRECTORY`` and ``SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX`` byte
  layouts, packed here with ``struct``;
* real Windows APIs: the kernel handle table, the process token and the memory map of a real
  child process that holds a known marker in a mapped view whose address the child reports;
* a real named-pipe server child from ``tests/_helpers`` for the wire-level cases.

Cases that need a plugin reply the real pipe server cannot produce (an ``unknown_command``
error, a ``status`` payload, a ``thread_detail`` list) run against ``ScriptedBridge``, a
subclass of the real ``X64DbgBridge`` that replaces only the transport boundary
(``_send_pipe_command`` and ``_send_command``); every line above that boundary is the
production code under test. Lines that need a running debugger are intentionally not covered.
"""

from __future__ import annotations

import asyncio
import contextlib
import ctypes
import msvcrt
import os
import struct
import subprocess
import sys
import time
import uuid
from ctypes import wintypes
from typing import TYPE_CHECKING, Any, cast

import pytest

from intellicrack.bridges import x64dbg as x64dbg_module
from intellicrack.bridges.named_pipe_client import NamedPipeClient, PipeConfig
from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.core.types import ToolError
from tests._helpers import realcov_pipe_server as pipe_server


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Awaitable, Callable, Iterator, Mapping
    from pathlib import Path

    from intellicrack.bridges.x64dbg import PipeCommandResult


type PipeReply = PipeCommandResult | ToolError

_SERVER_MODULE = "tests._helpers.realcov_pipe_server"
_PIPE_READY_TIMEOUT_S = 10.0
_MARKER_TEXT = "CRITCOV_X64DBG_03_MARKER"
_MARKER = _MARKER_TEXT.encode("ascii")
_MARKER_RULE = f'rule critcov_marker {{ strings: $m = "{_MARKER_TEXT}" condition: $m }}'
_ALWAYS_RULE = "rule critcov_always { condition: true }"
_UNMAPPED_ADDRESS = 0x1000
_ALL_ONES_64 = 0xFFFF_FFFF_FFFF_FFFF
_CHILD_SOURCE = (
    "import ctypes, mmap, sys\n"
    f"marker = b'{_MARKER_TEXT}'\n"
    "view = mmap.mmap(-1, 65536)\n"
    "view[:len(marker)] = marker\n"
    "print(ctypes.addressof(ctypes.c_char.from_buffer(view)), flush=True)\n"
    "sys.stdin.read()\n"
)

_new_labels: Callable[[], object] = cast("Callable[[], object]", getattr(x64dbg_module, "_ResourcePathLabels"))

_BEYOND_WITHIN_FAMILY: list[tuple[str, str]] = [
    ("trace_into_beyond_coverage", "TraceIntoBeyondTraceCoverage"),
    ("trace_over_beyond_coverage", "TraceOverBeyondTraceCoverage"),
    ("trace_into_within_coverage", "TraceIntoIntoTraceCoverage"),
    ("trace_over_within_coverage", "TraceOverIntoTraceCoverage"),
]
_RPC_MISSING_TRACE: list[tuple[str, str]] = [
    *_BEYOND_WITHIN_FAMILY,
    ("trace_into", "TraceIntoConditional"),
    ("trace_over", "TraceOverConditional"),
]
_STEP_KINDS: list[tuple[str, str]] = [
    ("into", "TraceIntoConditional"),
    ("over", "TraceOverConditional"),
]
_NT_GLOBAL_FLAG_CASES: list[tuple[PipeCommandResult, dict[str, bool]]] = [
    (0x70, {"peb_being_debugged": True, "nt_global_flag_set": True}),
    (0x0, {"peb_being_debugged": True, "nt_global_flag_set": False}),
    ("0x70", {"peb_being_debugged": True}),
]
_HEX_INT_CASES: list[tuple[object, int | None]] = [
    (True, None),
    (False, None),
    (7, 7),
    ("0x10", 16),
    ("", None),
    (None, None),
    (2.5, None),
]
_NAME_STRING_CASES: list[tuple[bytes, int, str | None]] = [
    (b"\x01", 0, None),
    (struct.pack("<H", 4) + "ab".encode("utf-16-le"), 0, None),
    (struct.pack("<H", 3) + "VER".encode("utf-16-le"), 0, "VER"),
]
_UNUSABLE_THREAD_RESULTS: list[PipeCommandResult] = [None, 0, "0x0", 2.5]


class ScriptedBridge(X64DbgBridge):
    """Real ``X64DbgBridge`` whose pipe transport answers from a script.

    Only the two methods that cross the process boundary to the debugger are replaced:
    ``_send_pipe_command`` returns (or raises) the scripted reply for the RPC name, and
    ``_send_command`` records the console command text. Every caller above them runs
    unmodified, so the command text built by the production code is what ``sent_commands``
    holds. Each instance keeps its scripted ``replies`` per RPC name (a ``ToolError`` value is
    raised), every ``(rpc_name, params)`` pair requested in ``sent_rpcs``, and every console
    command text in ``sent_commands``.

    Attributes:
        VERIFY_TIMEOUT: Shortened post-condition polling window so absent-RPC cases stay fast.
        VERIFY_POLL_INTERVAL: Shortened interval between post-condition polls.
    """

    VERIFY_TIMEOUT = 0.2
    VERIFY_POLL_INTERVAL = 0.02

    def __init__(self, replies: Mapping[str, PipeReply]) -> None:
        """Create the bridge with its scripted RPC replies.

        Args:
            replies: Reply (or ``ToolError`` to raise) keyed by RPC name.
        """
        super().__init__()
        self.replies: dict[str, PipeReply] = dict(replies)
        self.sent_rpcs: list[tuple[str, dict[str, Any] | None]] = []
        self.sent_commands: list[str] = []

    async def _send_pipe_command(
        self,
        command: str,
        params: dict[str, Any] | None = None,
    ) -> PipeCommandResult:
        """Return the scripted reply for ``command``.

        Args:
            command: RPC name requested by the production code.
            params: RPC parameters requested by the production code.

        Returns:
            PipeCommandResult: The scripted reply.

        Raises:
            ToolError: When the scripted reply is an error.
        """
        await asyncio.sleep(0)
        self.sent_rpcs.append((command, params))
        reply = self.replies[command]
        if isinstance(reply, ToolError):
            raise ToolError(reply.message, tool_name=reply.tool_name, details=dict(reply.details))
        return reply

    async def _send_command(self, command: str) -> str:
        """Record the console command text instead of sending it.

        Args:
            command: Console command text built by the production code.

        Returns:
            str: Always an empty command output.
        """
        await asyncio.sleep(0)
        self.sent_commands.append(command)
        return ""


class ExplodingCloseClient(NamedPipeClient):
    """Real ``NamedPipeClient`` whose teardown fails the way a faulted transport does."""

    async def close(self) -> None:
        """Fail the close.

        Raises:
            RuntimeError: Always.
        """
        await asyncio.sleep(0)
        msg = "pipe teardown exploded"
        raise RuntimeError(msg)


def _unknown_command() -> ToolError:
    """Build the error a plugin build without the requested RPC reports.

    Returns:
        ToolError: Error carrying the ``unknown_command`` x64dbg error code.
    """
    return ToolError("unknown command", tool_name="x64dbg", details={"x64dbg_error_code": "unknown_command"})


def _remote_error() -> ToolError:
    """Build the error a plugin reports for a command that genuinely failed.

    Returns:
        ToolError: Error carrying the ``remote_error`` x64dbg error code.
    """
    return ToolError("plugin refused the command", tool_name="x64dbg", details={"x64dbg_error_code": "remote_error"})


def _async_method(obj: object, name: str) -> Callable[..., Awaitable[Any]]:
    """Resolve an async method by name, public or private.

    Args:
        obj: Object that owns the method.
        name: Method name.

    Returns:
        Callable[..., Awaitable[Any]]: The bound method.
    """
    return cast("Callable[..., Awaitable[Any]]", getattr(obj, name))


@contextlib.asynccontextmanager
async def _attached_to_self(bridge: X64DbgBridge) -> AsyncGenerator[X64DbgBridge]:
    """Attach ``bridge`` to the test process and release its handles afterwards.

    Args:
        bridge: Bridge to attach.

    Yields:
        X64DbgBridge: The attached bridge.
    """
    bridge.attached_pid = os.getpid()
    try:
        yield bridge
    finally:
        await bridge.shutdown()


def _wait_for_pipe(pipe_name: str) -> None:
    """Block until the named pipe exists, using the real ``WaitNamedPipeW``.

    Args:
        pipe_name: Endpoint the child server hosts.

    Raises:
        ToolError: If the pipe never appears within the readiness deadline.
    """
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.WaitNamedPipeW.restype = wintypes.BOOL
    kernel32.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
    deadline = time.monotonic() + _PIPE_READY_TIMEOUT_S
    while time.monotonic() < deadline:
        if kernel32.WaitNamedPipeW(pipe_name, 200):
            return
        time.sleep(0.05)
    msg = f"Server pipe {pipe_name} never became available"
    raise ToolError(msg)


def _stop_child(child: subprocess.Popen[Any]) -> None:
    """Terminate and reap a child process.

    Args:
        child: Child started by a fixture.
    """
    if child.poll() is None:
        child.terminate()
    try:
        child.wait(timeout=10)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=10)


@pytest.fixture
def echo_pipe_bridge() -> Iterator[X64DbgBridge]:
    """Yield a bridge pointed at a real named-pipe server child that answers every RPC with success.

    Tests that use it must close the connection themselves in a ``finally``.

    Yields:
        X64DbgBridge: Bridge whose pipe name is the child server's endpoint.
    """
    pipe_name = rf"\\.\pipe\intellicrack_critcov_x64dbg03_{uuid.uuid4().hex}"
    server = subprocess.Popen(
        [sys.executable, "-m", _SERVER_MODULE, pipe_name, pipe_server.MODE_ECHO_SUCCESS],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_for_pipe(pipe_name)
        bridge = X64DbgBridge()
        setattr(bridge, "_PIPE_NAME", pipe_name)
        setattr(bridge, "_plugin_deployed", True)
        yield bridge
    finally:
        _stop_child(server)


@pytest.fixture
def marker_child() -> Iterator[tuple[int, int]]:
    """Yield a child process that holds a known marker in a mapped view.

    The child prints the address of the view's first byte, which is where the marker sits.

    Yields:
        tuple[int, int]: The child's pid and the address of the marker inside it.
    """
    child = subprocess.Popen(
        [sys.executable, "-c", _CHILD_SOURCE],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        assert child.stdout is not None
        address = int(child.stdout.readline())
        yield child.pid, address
    finally:
        if child.stdin is not None:
            child.stdin.close()
        _stop_child(child)
        if child.stdout is not None:
            child.stdout.close()


@pytest.mark.asyncio
async def test_get_watches_propagates_plugin_unavailable() -> None:
    """A bridge without a deployed plugin raises instead of reporting an empty watch list."""
    bridge = X64DbgBridge()
    with pytest.raises(ToolError, match="x64dbg bridge plugin not available") as excinfo:
        await bridge.get_watches()
    assert excinfo.value.details["x64dbg_error_code"] == "plugin_unavailable"


@pytest.mark.asyncio
async def test_get_watches_returns_empty_when_watch_rpc_is_unknown() -> None:
    """A plugin build without the ``watch_list`` RPC yields an empty list, not an error."""
    bridge = ScriptedBridge({"watch_list": _unknown_command()})
    assert await bridge.get_watches() == []
    assert bridge.sent_rpcs == [("watch_list", None)]


@pytest.mark.asyncio
@pytest.mark.spawns_process
async def test_get_watches_returns_empty_for_non_list_payload_over_real_pipe(echo_pipe_bridge: X64DbgBridge) -> None:
    """A dict payload over a real pipe is not a watch list and must not be returned as one.

    Args:
        echo_pipe_bridge: Bridge connected to the real echo-success pipe server.
    """
    try:
        assert await echo_pipe_bridge.get_watches() == []
    finally:
        await _async_method(echo_pipe_bridge, "_close_connection")()


@pytest.mark.asyncio
@pytest.mark.spawns_process
async def test_plugin_list_returns_empty_for_non_list_payload_over_real_pipe(echo_pipe_bridge: X64DbgBridge) -> None:
    """A dict payload over a real pipe is not a plugin list and must not be returned as one.

    Args:
        echo_pipe_bridge: Bridge connected to the real echo-success pipe server.
    """
    try:
        assert await echo_pipe_bridge.plugin_list() == []
    finally:
        await _async_method(echo_pipe_bridge, "_close_connection")()


@pytest.mark.asyncio
async def test_verify_hit_count_skips_when_bp_list_is_unknown() -> None:
    """An older plugin without ``bp_list`` makes the verification report ``False`` (skipped)."""
    bridge = ScriptedBridge({"bp_list": _unknown_command()})
    verified = await _async_method(bridge, "_verify_breakpoint_hit_count")(0x401000, "software", 0)
    assert verified is False


@pytest.mark.asyncio
async def test_verify_hit_count_reraises_other_bp_list_errors() -> None:
    """Any ``bp_list`` failure other than an unknown RPC propagates with its message and code intact."""
    bridge = ScriptedBridge({"bp_list": _remote_error()})
    with pytest.raises(ToolError, match="plugin refused the command") as excinfo:
        await _async_method(bridge, "_verify_breakpoint_hit_count")(0x401000, "software", 0)
    assert excinfo.value.details == {"x64dbg_error_code": "remote_error"}


@pytest.mark.asyncio
@pytest.mark.spawns_process
async def test_verify_hit_count_rejects_non_list_bp_list_over_real_pipe(echo_pipe_bridge: X64DbgBridge) -> None:
    """A ``bp_list`` payload that is not a list is a protocol violation.

    Args:
        echo_pipe_bridge: Bridge connected to the real echo-success pipe server.
    """
    try:
        with pytest.raises(ToolError, match="bp_list returned dict, expected list") as excinfo:
            await _async_method(echo_pipe_bridge, "_verify_breakpoint_hit_count")(0x401000, "software", 0)
    finally:
        await _async_method(echo_pipe_bridge, "_close_connection")()
    assert excinfo.value.details["x64dbg_error_code"] == "protocol_violation"
    assert excinfo.value.details["address"] == "0x401000"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bp_list",
    [
        [],
        ["not-a-dict", {"address": "0x500000", "hitCount": 3}, {"address": None, "hitCount": 0}],
    ],
)
async def test_verify_hit_count_fails_when_address_absent_from_bp_list(bp_list: list[object]) -> None:
    """A breakpoint missing from ``bp_list`` after the reset is reported as a failed verification.

    Args:
        bp_list: ``bp_list`` payload that holds no entry for the breakpoint address.
    """
    bridge = ScriptedBridge({"bp_list": bp_list})
    with pytest.raises(ToolError, match="address 0x401000 not present in bp_list after reset") as excinfo:
        await _async_method(bridge, "_verify_breakpoint_hit_count")(0x401000, "software", 0)
    assert excinfo.value.details == {
        "x64dbg_error_code": "remote_error",
        "address": "0x401000",
        "bp_type": "software",
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(("method", "native"), _RPC_MISSING_TRACE)
async def test_trace_reports_unverified_when_status_rpc_is_missing(method: str, native: str) -> None:
    """Without a ``status`` RPC the trace is sent but cannot be verified.

    Args:
        method: Bridge method under test.
        native: Native x64dbg command that method must send.
    """
    bridge = ScriptedBridge({"status": _unknown_command()})
    result = await _async_method(bridge, method)(max_steps=7)
    assert result == {"success": True, "max_steps": 7, "verified": False}
    assert bridge.sent_commands == [f"{native} 0, 7"]


@pytest.mark.asyncio
@pytest.mark.parametrize(("method", "native"), _BEYOND_WITHIN_FAMILY)
async def test_trace_family_raises_when_debugger_never_runs(method: str, native: str) -> None:
    """A debugger that stays paused after the trace command makes the verification fail.

    Args:
        method: Coverage-trace method under test.
        native: Native x64dbg command that method must send.
    """
    bridge = ScriptedBridge({"status": {"debugging": True, "paused": True}})
    with pytest.raises(ToolError, match=f"{method} verification failed") as excinfo:
        await _async_method(bridge, method)(condition="rax==1", max_steps=12)
    assert excinfo.value.details == {
        "x64dbg_error_code": "timeout",
        "max_steps": 12,
        "expected_running": True,
        "observed_running": False,
    }
    assert bridge.sent_commands == [f'{native} "rax==1", 12']


@pytest.mark.asyncio
@pytest.mark.parametrize(("method", "native"), _BEYOND_WITHIN_FAMILY)
async def test_trace_family_verifies_when_debugger_runs(method: str, native: str) -> None:
    """A debugger that reports running after the trace command verifies the trace.

    Args:
        method: Coverage-trace method under test.
        native: Native x64dbg command that method must send.
    """
    bridge = ScriptedBridge({"status": {"debugging": True, "paused": False}})
    result = await _async_method(bridge, method)(max_steps=12)
    assert result == {"success": True, "max_steps": 12, "verified": True}
    assert bridge.sent_commands == [f"{native} 0, 12"]


@pytest.mark.asyncio
@pytest.mark.parametrize(("step_type", "native"), _STEP_KINDS)
async def test_step_count_reports_unverified_when_status_rpc_is_missing(step_type: str, native: str) -> None:
    """Without a ``status`` RPC a counted step is sent but cannot be verified.

    Args:
        step_type: ``into`` or ``over``.
        native: Native x64dbg command that step type must send.
    """
    bridge = ScriptedBridge({"status": _unknown_command()})
    result = await bridge.step_count(5, step_type)
    assert result == {"success": True, "count": 5, "step_type": step_type, "verified": False}
    assert bridge.sent_commands == [f"{native} 0, 5"]


@pytest.mark.asyncio
@pytest.mark.parametrize(("step_type", "native"), _STEP_KINDS)
async def test_animate_start_reports_unverified_when_status_rpc_is_missing(step_type: str, native: str) -> None:
    """Without a ``status`` RPC animation is started with the documented budget but cannot be verified.

    Args:
        step_type: ``into`` or ``over``.
        native: Native x64dbg command that step type must send.
    """
    bridge = ScriptedBridge({"status": _unknown_command()})
    result = await bridge.animate_start(step_type)
    assert result == {"success": True, "step_type": step_type, "verified": False}
    assert bridge.sent_commands == [f"{native} 0, 1000000000"]


@pytest.mark.asyncio
async def test_animate_stop_reports_unverified_when_status_rpc_is_missing() -> None:
    """Without a ``status`` RPC the ``pause`` that stops animation cannot be verified."""
    bridge = ScriptedBridge({"status": _unknown_command()})
    assert await bridge.animate_stop() == {"success": True, "verified": False}
    assert bridge.sent_commands == ["pause"]


@pytest.mark.asyncio
async def test_restart_reports_unverified_when_status_rpc_is_missing(tmp_path: Path) -> None:
    """A restart on a plugin without ``status`` re-issues ``InitDebug`` and records the new pid.

    Args:
        tmp_path: Directory that holds the loaded binary path.
    """
    target = tmp_path / "target.exe"
    bridge = ScriptedBridge({"reg_get": "0x1f4", "status": _unknown_command()})
    bridge.binary_path = target
    result = await bridge.restart()
    assert result == {"success": True, "path": str(target), "verified": False}
    assert bridge.sent_commands == [f'InitDebug "{target.as_posix()}"']
    assert ("reg_get", {"name": "$pid"}) in bridge.sent_rpcs
    assert bridge.attached_pid == 500
    assert bridge.state.target_pid == 500
    assert bridge.state.process_attached is True
    assert bridge.state.target_path == target


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", ["armed", None, ["word"]])
async def test_set_trace_record_rejects_non_dict_payload(payload: PipeCommandResult) -> None:
    """A ``trace_record_set`` reply that is not a dict is a protocol violation.

    Args:
        payload: Reply that is not a dict.
    """
    bridge = ScriptedBridge({"trace_record_set": payload})
    with pytest.raises(ToolError, match="trace_record_set returned a non-dict payload for 0x401000") as excinfo:
        await bridge.set_trace_record(0x401000)
    assert excinfo.value.details == {"x64dbg_error_code": "protocol_violation", "address": "0x401000"}
    assert ("trace_record_set", {"address": "0x401000", "type": "word"}) in bridge.sent_rpcs


@pytest.mark.asyncio
@pytest.mark.parametrize(("size", "shown"), [(0, "0"), (-5, "-5")])
async def test_analyze_entropy_rejects_non_positive_size(size: int, shown: str) -> None:
    """A region size of zero or less is rejected before any memory is read.

    Args:
        size: Non-positive region size.
        shown: How that size appears in the error message.
    """
    bridge = X64DbgBridge()
    with pytest.raises(ToolError, match=f"size must be positive, got {shown}"):
        await bridge.analyze_entropy(0x1000, size)


@pytest.mark.asyncio
async def test_yara_scan_rejects_empty_inline_rule_even_with_a_path() -> None:
    """An empty inline rule is rejected even when a rule path accompanies it."""
    bridge = X64DbgBridge()
    with pytest.raises(ToolError, match="YARA rule must be non-empty"):
        await bridge.yara_scan(rule_path="ignored.yar", rule_text="")


@pytest.mark.asyncio
async def test_yara_scan_rejects_missing_rule_file(tmp_path: Path) -> None:
    """A rule path that does not exist is reported with the offending path.

    Args:
        tmp_path: Directory in which the rule file does not exist.
    """
    missing = tmp_path / "missing.yar"
    bridge = X64DbgBridge()
    with pytest.raises(ToolError) as excinfo:
        await bridge.yara_scan(rule_path=str(missing))
    assert str(excinfo.value) == f"YARA rule file not found: {missing}"


@pytest.mark.asyncio
async def test_yara_scan_rejects_empty_rule_file(tmp_path: Path) -> None:
    """A rule file with no bytes is rejected.

    Args:
        tmp_path: Directory that holds the empty rule file.
    """
    rule_file = tmp_path / "empty.yar"
    rule_file.write_bytes(b"")
    bridge = X64DbgBridge()
    with pytest.raises(ToolError, match="YARA rule file is empty"):
        await bridge.yara_scan(rule_path=str(rule_file))


@pytest.mark.asyncio
async def test_yara_scan_skips_a_window_with_non_positive_size() -> None:
    """A scan window of negative size never reaches the memory read and yields no matches."""
    async with _attached_to_self(X64DbgBridge()) as bridge:
        assert await bridge.yara_scan(rule_text=_ALWAYS_RULE, address=_UNMAPPED_ADDRESS, size=-1) == []


@pytest.mark.asyncio
async def test_yara_scan_survives_an_unreadable_window() -> None:
    """A window that cannot be read is logged and skipped rather than aborting the scan."""
    async with _attached_to_self(X64DbgBridge()) as bridge:
        assert await bridge.yara_scan(rule_text=_ALWAYS_RULE, address=_UNMAPPED_ADDRESS, size=16) == []


@pytest.mark.asyncio
@pytest.mark.spawns_process
async def test_yara_scan_finds_marker_across_regions_of_a_real_process(marker_child: tuple[int, int]) -> None:
    """Scanning every readable region of a real child finds the marker at the address the child reported.

    Args:
        marker_child: Pid of the child and the address of the marker inside its mapped view.
    """
    pid, marker_address = marker_child
    bridge = X64DbgBridge()
    bridge.attached_pid = pid
    try:
        results = await bridge.yara_scan(rule_text=_MARKER_RULE)
        read_back = await bridge.read_memory(marker_address, len(_MARKER))
    finally:
        await bridge.shutdown()
    assert {"rule": "critcov_marker", "address": hex(marker_address), "matched_bytes": _MARKER.hex()} in results
    assert all(entry["rule"] == "critcov_marker" and entry["matched_bytes"] == _MARKER.hex() for entry in results)
    assert read_back == _MARKER


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "args", "command", "expected"),
    [
        (
            "script_load",
            (r"C:\scripts\unpack.txt",),
            r'scriptload "C:\scripts\unpack.txt"',
            {"success": True, "path": r"C:\scripts\unpack.txt", "verified": False},
        ),
        ("script_run", (), "scriptrun", {"success": True, "verified": False}),
        (
            "script_cmd",
            ("mov rax, 1",),
            'scriptcmd "mov rax, 1"',
            {"success": True, "line": "mov rax, 1", "verified": False},
        ),
    ],
)
async def test_script_commands_report_unverified_without_error_register(
    method: str,
    args: tuple[str, ...],
    command: str,
    expected: dict[str, object],
) -> None:
    """Without the ``script.iserror()`` evaluator a script command is sent but cannot be verified.

    Args:
        method: Script method under test.
        args: Arguments passed to the method.
        command: Console command the method must send.
        expected: Result the method must return.
    """
    bridge = ScriptedBridge({"eval": _unknown_command()})
    result = await _async_method(bridge, method)(*args)
    assert result == expected
    assert bridge.sent_commands == [command]
    assert ("eval", {"expression": "script.iserror()"}) in bridge.sent_rpcs


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["script_abort", "script_step"])
async def test_script_rpc_commands_report_unverified_without_error_register(method: str) -> None:
    """Without the ``script.iserror()`` evaluator an abort or step RPC cannot be verified.

    Args:
        method: ``script_abort`` or ``script_step``.
    """
    bridge = ScriptedBridge({method: None, "eval": _unknown_command()})
    assert await _async_method(bridge, method)() == {"success": True, "verified": False}
    assert (method, None) in bridge.sent_rpcs


@pytest.mark.asyncio
async def test_plugin_load_reports_unverified_without_plugin_rpcs() -> None:
    """Without ``plugin_list`` and ``plugin.find`` a plugin load is sent but cannot be verified."""
    path = r"C:\plugins\scylla_hide.dp64"
    bridge = ScriptedBridge({"plugin_list": _unknown_command(), "eval": _unknown_command()})
    result = await bridge.plugin_load(path)
    assert result == {"success": True, "path": path, "verified": False}
    assert bridge.sent_commands == [f'plugload "{path}"']
    assert ("eval", {"expression": 'plugin.find("scylla_hide")'}) in bridge.sent_rpcs


@pytest.mark.asyncio
async def test_plugin_unload_reports_unverified_without_plugin_rpcs() -> None:
    """Without ``plugin_list`` and ``plugin.find`` a plugin unload is sent but cannot be verified."""
    bridge = ScriptedBridge({"plugin_list": _unknown_command(), "eval": _unknown_command()})
    result = await bridge.plugin_unload("scylla_hide")
    assert result == {"success": True, "name": "scylla_hide", "verified": False}
    assert bridge.sent_commands == ['plugunload "scylla_hide"']


@pytest.mark.asyncio
async def test_get_handles_lists_a_real_open_handle(tmp_path: Path) -> None:
    """The handle table of the test process lists a file handle this test just opened.

    Args:
        tmp_path: Directory that holds the file the test keeps open.
    """
    bridge = X64DbgBridge()
    bridge.attached_pid = os.getpid()
    with (tmp_path / "held.bin").open("wb") as held:
        handle_value = msvcrt.get_osfhandle(held.fileno())
        entries = await bridge.get_handles()
    assert hex(handle_value) in {entry["handle"] for entry in entries}
    expected_keys = {"handle", "object", "granted_access", "object_type_index", "handle_attributes"}
    assert all(set(entry) == expected_keys for entry in entries)


def test_parse_handle_buffer_stops_at_truncated_buffer() -> None:
    """Handle entries the buffer cannot hold are ignored and only the target pid's entries are returned."""
    header = struct.pack("<QQ", 3, 0)
    first = struct.pack("<QQQIHHII", 0xFFFF800012345678, 1234, 0x44, 0x1F01FF, 0, 37, 2, 0)
    other = struct.pack("<QQQIHHII", 0xFFFF800087654321, 5678, 0x48, 0x120089, 0, 40, 0, 0)
    parse = cast(
        "Callable[[bytes, int], list[dict[str, Any]]]",
        getattr(X64DbgBridge, "_parse_handle_buffer"),
    )
    assert parse(header + first + other, 1234) == [
        {
            "handle": "0x44",
            "object": "0xffff800012345678",
            "granted_access": "0x1f01ff",
            "object_type_index": 37,
            "handle_attributes": 2,
        },
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(("nt_global_flag", "expected_checks"), _NT_GLOBAL_FLAG_CASES)
async def test_detect_anti_debug_ignores_non_integer_nt_global_flag(
    nt_global_flag: PipeCommandResult,
    expected_checks: dict[str, bool],
) -> None:
    """The ``NtGlobalFlag`` check is derived only from an integer flag value.

    Args:
        nt_global_flag: ``ntGlobalFlag`` value in the scripted PEB.
        expected_checks: Checks the bridge must report for that value.
    """
    peb: dict[str, object] = {"address": "0x7ff6a000", "beingDebugged": 1, "ntGlobalFlag": nt_global_flag}
    bridge = ScriptedBridge({"peb_read": peb})
    result = await bridge.detect_anti_debug()
    assert result == {"success": True, "checks": expected_checks, "peb": peb}


@pytest.mark.asyncio
async def test_patch_anti_debug_reports_every_failed_write_and_read() -> None:
    """Unwritable PEB fields are reported per check with the failing address, and the call is not a success."""
    peb: dict[str, object] = {"address": _UNMAPPED_ADDRESS}
    bridge = ScriptedBridge({"peb_read": peb})
    checks = ["being_debugged", "nt_global_flag", "heap_flags", "process_heap_flags"]
    async with _attached_to_self(bridge):
        result = await bridge.patch_anti_debug(checks=checks)
    heap_error = "read PEB.ProcessHeap failed: ReadProcessMemory failed at 0x1030"
    assert result["success"] is False
    assert result["status"] == {
        "being_debugged": False,
        "nt_global_flag": False,
        "heap_flags": False,
        "process_heap_flags": False,
    }
    assert result["errors"] == {
        "being_debugged": "WriteProcessMemory failed at 0x1002",
        "nt_global_flag": "WriteProcessMemory failed at 0x10BC",
        "heap_flags": heap_error,
        "process_heap_flags": heap_error,
    }


@pytest.mark.asyncio
async def test_patch_anti_debug_rejects_boolean_peb_address() -> None:
    """A boolean PEB address is not an address, so no patch is attempted."""
    bridge = ScriptedBridge({"peb_read": {"address": True}})
    result = await bridge.patch_anti_debug()
    message = "PEB base address missing or malformed in peb_read response"
    assert result["success"] is False
    assert result["errors"] == {
        "being_debugged": message,
        "nt_global_flag": message,
        "heap_flags": message,
    }


@pytest.mark.parametrize(("raw", "expected"), _HEX_INT_CASES)
def test_coerce_hex_int_accepts_only_integers_and_numeric_strings(raw: object, expected: int | None) -> None:
    """Booleans and non-numeric values are not integers; ints and numeric strings are.

    Args:
        raw: Value handed to the coercion.
        expected: Integer the coercion must return, or ``None``.
    """
    coerce = cast("Callable[[object], int | None]", getattr(X64DbgBridge, "_coerce_hex_int"))
    assert coerce(raw) == expected


@pytest.mark.asyncio
async def test_patch_anti_debug_reports_a_null_process_heap() -> None:
    """A PEB whose ``ProcessHeap`` pointer is null cannot have its heap flags cleared."""
    peb = (ctypes.c_ubyte * 0x100)()
    bridge = ScriptedBridge({"peb_read": {"address": hex(ctypes.addressof(peb))}})
    async with _attached_to_self(bridge):
        result = await bridge.patch_anti_debug(checks=["heap_flags"])
    assert result["success"] is False
    assert result["status"] == {"heap_flags": False}
    assert result["errors"] == {"heap_flags": "PEB.ProcessHeap is null"}


@pytest.mark.asyncio
async def test_patch_anti_debug_reports_an_unwritable_process_heap() -> None:
    """A ``ProcessHeap`` pointer into unmapped memory fails the flag write and reports where."""
    peb = (ctypes.c_ubyte * 0x100)()
    struct.pack_into("<Q", peb, 0x30, _UNMAPPED_ADDRESS)
    bridge = ScriptedBridge({"peb_read": {"address": hex(ctypes.addressof(peb))}})
    async with _attached_to_self(bridge):
        result = await bridge.patch_anti_debug(checks=["heap_flags"])
    assert result["success"] is False
    assert result["status"] == {"heap_flags": False}
    assert result["errors"] == {"heap_flags": "write heap flags failed: WriteProcessMemory failed at 0x1070"}


@pytest.mark.asyncio
async def test_patch_anti_debug_clears_only_the_heap_flag_fields_in_real_memory() -> None:
    """HeapFlags and ForceFlags are zeroed in real memory and the bytes around them are untouched."""
    heap = (ctypes.c_ubyte * 0x100)()
    for offset in range(0x68, 0x80, 8):
        struct.pack_into("<Q", heap, offset, _ALL_ONES_64)
    peb = (ctypes.c_ubyte * 0x100)()
    struct.pack_into("<Q", peb, 0x30, ctypes.addressof(heap))
    bridge = ScriptedBridge({"peb_read": {"address": hex(ctypes.addressof(peb))}})
    async with _attached_to_self(bridge):
        result = await bridge.patch_anti_debug(checks=["heap_flags"])
    assert result["success"] is True
    assert result["status"] == {"heap_flags": True}
    assert "errors" not in result
    assert struct.unpack_from("<QQQ", heap, 0x68) == (_ALL_ONES_64, 0, _ALL_ONES_64)


@pytest.mark.asyncio
async def test_reconstruct_imports_does_not_fall_back_on_plugin_unavailable() -> None:
    """An unavailable plugin is a transport failure; the script fallback would travel the same dead pipe."""
    bridge = X64DbgBridge()
    with pytest.raises(ToolError, match="x64dbg bridge plugin not available") as excinfo:
        await bridge.reconstruct_imports(0x401000, r"C:\out\fixed.exe")
    assert excinfo.value.details["x64dbg_error_code"] == "plugin_unavailable"


@pytest.mark.asyncio
@pytest.mark.parametrize("plugin_result", [None, "done", ["step"]])
async def test_reconstruct_imports_omits_details_for_non_dict_result(plugin_result: PipeCommandResult) -> None:
    """A reply that is not a dict contributes no ``details`` to the response.

    Args:
        plugin_result: Reply of the ``scylla_reconstruct`` RPC.
    """
    output = r"C:\out\fixed.exe"
    bridge = ScriptedBridge({"scylla_reconstruct": plugin_result})
    result = await bridge.reconstruct_imports(0x401000, output)
    assert result == {"success": True, "oep": "0x401000", "output_path": output}
    assert ("scylla_reconstruct", {"oep": "0x401000", "output_path": output}) in bridge.sent_rpcs


@pytest.mark.asyncio
async def test_adjust_privilege_enables_a_held_privilege_on_the_real_token() -> None:
    """Enabling a privilege every token holds succeeds and the token still lists it as enabled."""
    name = "SeChangeNotifyPrivilege"
    result = await X64DbgBridge.adjust_privilege(name, enable=True)
    assert result == {"success": True, "privilege": name, "enabled": True}
    privileges = {entry["name"]: entry for entry in await X64DbgBridge.get_privileges()}
    assert privileges[name]["enabled"] is True


def test_walk_resource_directory_ignores_a_truncated_header() -> None:
    """A resource blob shorter than one directory header yields no resources and no error."""
    bridge = X64DbgBridge()
    resources: list[dict[str, Any]] = []
    walk = cast("Callable[..., None]", getattr(bridge, "_walk_resource_directory"))
    walk(blob=b"\x00" * 15, module_base=0x10000000, dir_offset=0, depth=0, resources=resources, labels=_new_labels())
    assert resources == []


def test_walk_resource_directory_stops_at_truncated_entries() -> None:
    """A directory that announces more entries than the blob holds stops cleanly at the truncation.

    The first entry is a data leaf whose entry lies outside the blob, so it adds nothing; the
    second entry does not fit in the blob at all.
    """
    header = struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 2)
    first_entry = struct.pack("<II", 0x10, 0x100)
    blob = header + first_entry + b"\x00" * 4
    bridge = X64DbgBridge()
    resources: list[dict[str, Any]] = []
    walk = cast("Callable[..., None]", getattr(bridge, "_walk_resource_directory"))
    walk(blob=blob, module_base=0x10000000, dir_offset=0, depth=0, resources=resources, labels=_new_labels())
    assert resources == []


def test_walk_resource_entry_returns_minus_one_when_the_entry_is_truncated() -> None:
    """An entry that does not fit in the blob is signalled with ``-1`` so the caller aborts."""
    bridge = X64DbgBridge()
    walk_entry = cast("Callable[..., int]", getattr(bridge, "_walk_resource_entry"))
    cursor = walk_entry(
        blob=b"\x00" * 7,
        module_base=0,
        cursor=0,
        depth=0,
        resources=[],
        labels=_new_labels(),
    )
    assert cursor == -1


@pytest.mark.parametrize(("blob", "offset", "expected"), _NAME_STRING_CASES)
def test_read_resource_name_string_rejects_truncated_strings(blob: bytes, offset: int, expected: str | None) -> None:
    """A resource name is decoded from UTF-16-LE only when its length prefix and characters are present.

    Args:
        blob: Resource bytes holding the length-prefixed string.
        offset: Offset of the string inside the blob.
        expected: Decoded string, or ``None`` when the blob is truncated.
    """
    read = cast("Callable[[bytes, int], str | None]", getattr(X64DbgBridge, "_read_resource_name_string"))
    assert read(blob, offset) == expected


def test_read_resource_data_entry_rejects_a_truncated_entry() -> None:
    """A 16-byte ``IMAGE_RESOURCE_DATA_ENTRY`` is read in full or not at all."""
    read = cast(
        "Callable[[bytes, int, int], tuple[int, int, int] | None]",
        getattr(X64DbgBridge, "_read_resource_data_entry"),
    )
    assert read(b"\x00" * 15, 0x10000000, 0) is None
    assert read(struct.pack("<IIII", 0x3000, 0x44, 1252, 0), 0x10000000, 0) == (0x10003000, 0x44, 1252)


@pytest.mark.asyncio
async def test_create_thread_accepts_an_integer_result_and_verifies_it() -> None:
    """An integer ``$result`` is the new thread id and ``thread_detail`` confirms it."""
    bridge = ScriptedBridge({"reg_get": 4321, "thread_detail": [{"threadId": 4321}]})
    result = await bridge.create_thread(0x401000)
    assert result == {"success": True, "tid": 4321, "entry": "0x401000", "verified": True}
    assert bridge.sent_commands == ["createthread 0x401000, 0x0"]
    assert ("reg_get", {"name": "$result"}) in bridge.sent_rpcs


@pytest.mark.asyncio
@pytest.mark.parametrize("unusable", _UNUSABLE_THREAD_RESULTS)
async def test_create_thread_rejects_an_unusable_result(unusable: PipeCommandResult) -> None:
    """A ``$result`` that is not a non-zero thread id means no thread was created.

    Args:
        unusable: Value of ``$result`` that cannot be a thread id.
    """
    bridge = ScriptedBridge({"reg_get": unusable})
    with pytest.raises(ToolError, match=r"create_thread verification failed: \$result is .* after createthread at 0x401000") as excinfo:
        await bridge.create_thread(0x401000)
    assert excinfo.value.details == {"x64dbg_error_code": "remote_error", "entry": "0x401000"}


@pytest.mark.asyncio
async def test_create_thread_fails_when_thread_detail_never_lists_the_thread() -> None:
    """A thread id that never appears in ``thread_detail`` fails the verification."""
    bridge = ScriptedBridge({"reg_get": "0x1b58", "thread_detail": []})
    with pytest.raises(ToolError, match="thread_detail never listed new tid=7000") as excinfo:
        await bridge.create_thread(0x401000)
    assert excinfo.value.details == {"x64dbg_error_code": "timeout", "tid": 7000}


@pytest.mark.asyncio
async def test_kill_thread_without_tid_is_unverified() -> None:
    """Killing the main thread by omitting the id cannot be verified because no id is known."""
    bridge = ScriptedBridge({})
    assert await bridge.kill_thread() == {"success": True, "tid": None, "verified": False}
    assert bridge.sent_commands == ["killthread"]


@pytest.mark.asyncio
async def test_kill_thread_is_unverified_when_thread_detail_is_missing() -> None:
    """Without a ``thread_detail`` RPC a thread kill is sent but cannot be verified."""
    bridge = ScriptedBridge({"thread_detail": _unknown_command()})
    assert await bridge.kill_thread(77, 3) == {"success": True, "tid": 77, "verified": False}
    assert bridge.sent_commands == ["killthread 77, 3"]


@pytest.mark.asyncio
async def test_shutdown_reraises_runtime_error_after_finishing_cleanup() -> None:
    """A runtime failure while closing the pipe is re-raised as a ``RuntimeError`` after state is cleared."""
    bridge = X64DbgBridge()
    bridge.attached_pid = 4242
    config = PipeConfig(pipe_name=r"\\.\pipe\intellicrack_critcov_x64dbg03_unused")
    setattr(bridge, "_pipe_client", ExplodingCloseClient(config))
    with pytest.raises(RuntimeError, match="pipe teardown exploded") as excinfo:
        await bridge.shutdown()
    assert isinstance(excinfo.value.__cause__, RuntimeError)
    assert excinfo.value.__cause__ is not excinfo.value
    assert bridge.attached_pid is None
