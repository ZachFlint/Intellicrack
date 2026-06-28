# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Wave 5 RPC-command gates: pipe-based bridge operations.

Each test drives the real bridge method through a ``_FakePipeClient`` that
records every ``(command, params)`` pair sent and returns scripted responses.
No production code is patched or replaced — only the named-pipe transport
boundary is faked.

Findings closed:
    7   get_stack_trace — frame field mapping from raw plugin dicts
    8   get_labels — RPC framing and address-range filtering
    9   get_comments — RPC framing and address-range filtering
    10  set_exception_config — exact SetExceptionBPX command string
    11  find_references — exact ref_search framing and passthrough
    12  find_string_references — exact ref_search framing and passthrough
    13  get_function_cfg — exact cfg framing and dict passthrough
    14  clear_database — db_clear RPC path
    15  remove_watch — watch_remove RPC framing
    16  get_watches — watch_list RPC passthrough
    17  script_load — exec + eval round-trips and verified flag
    18  script_run — exec + eval round-trips and verified flag
    19  script_cmd — exec + eval round-trips and line passthrough
    20  script_abort — exec + eval round-trips and verified flag
    21  close_handle — exact handleclose command string
    22  break_on_tls_callbacks — breakpoints_set key and count
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Final

import pefile
import pytest

from intellicrack.bridges.base import StackFrame
from intellicrack.bridges.x64dbg import X64DbgBridge


_SCRIPT_PATH: Final[str] = "/scripts/analysis.x64dbg"
_SCRIPT_LINE: Final[str] = "msg eax"
_HANDLE_VAL: Final[int] = 0xDEAD
_NTDLL_PATH: Final[Path] = Path(r"C:\Windows\System32\ntdll.dll")


class _FakePipeClient:
    """In-process substitute for ``NamedPipeClient``.

    Records every ``(command, params)`` pair the bridge sends and returns
    canned responses from the caller-supplied responder callable.

    Attributes:
        sent: Ordered list of ``(command, params)`` pairs recorded on each
            ``send_command`` call.
    """

    def __init__(
        self,
        responder: Any,
    ) -> None:
        """Initialise with a scripted responder callable.

        Args:
            responder: Callable ``(command, params) -> dict`` returning canned
                responses.
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
    """Sentinel satisfying ``self._process is not None`` bridge guards."""

    pid: int = 0


def _install_fake_pipe(
    bridge: X64DbgBridge,
    responder: Any,
) -> _FakePipeClient:
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


def _success(result: Any = "") -> dict[str, Any]:
    """Return a generic success response dict.

    Args:
        result: Optional result payload.

    Returns:
        dict[str, Any]: ``{"success": True, "result": result}``.
    """
    return {"success": True, "result": result}


@pytest.mark.asyncio
class TestGetStackTrace:
    """Gate ``get_stack_trace`` — exact frame field mapping from plugin dicts."""

    async def test_return_address_and_frame_pointer_mapped_from_from_and_to(self) -> None:
        """``from`` maps to ``return_address`` and ``to`` to ``frame_pointer``.

        Oracle: x64dbg.py:4948 ``return_address=from_addr`` and
        x64dbg.py:4949 ``frame_pointer=to_addr``.  The comment field is split
        on the last ``"."`` to yield ``module_name`` and ``function_name``.
        Mutation caught: swapping ``from_addr`` / ``to_addr`` assignments or
        using ``find(".")`` instead of ``rfind(".")`` → field values change →
        assertion fails.
        """
        raw_frames = [
            {
                "index": 0,
                "address": 0x400500,
                "from": 0x401000,
                "to": 0x402000,
                "comment": "ntdll.RtlUserThreadStart",
            },
        ]

        def _responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "stack_trace":
                return _success(raw_frames)
            return _success()

        bridge = X64DbgBridge()
        _install_fake_pipe(bridge, _responder)
        frames: list[StackFrame] = await bridge.get_stack_trace()

        assert len(frames) == 1
        frame = frames[0]
        assert frame.return_address == 0x401000
        assert frame.frame_pointer == 0x402000
        assert frame.module_name == "ntdll"
        assert frame.function_name == "RtlUserThreadStart"

    async def test_sends_stack_trace_rpc_with_no_params(self) -> None:
        """``get_stack_trace`` sends ``("stack_trace", None)`` to the pipe.

        Oracle: x64dbg.py:4182 ``await self._send_pipe_command("stack_trace")``.
        Mutation caught: changing the RPC name to ``"stacktrace"`` → tuple
        not found in ``fake.sent`` → assertion fails.
        """

        def _responder(_cmd: str, _p: dict[str, Any] | None) -> dict[str, Any]:
            return _success([])

        bridge = X64DbgBridge()
        fake = _install_fake_pipe(bridge, _responder)
        await bridge.get_stack_trace()

        assert ("stack_trace", None) in fake.sent


@pytest.mark.asyncio
class TestGetLabels:
    """Gate ``get_labels`` — RPC framing and address-range filtering."""

    async def test_sends_lbl_list_with_integer_start_and_end(self) -> None:
        """``get_labels`` sends ``("lbl_list", {"start": N, "end": M})`` as ints.

        Oracle: x64dbg.py:6074 ``_send_pipe_command("lbl_list", {"start": start,
        "end": end})``.
        Mutation caught: sending hex strings instead of ints → tuple mismatch.
        """
        bridge = X64DbgBridge()
        fake = _install_fake_pipe(bridge, lambda _c, _p: _success([]))
        await bridge.get_labels(0x400000, 0x402000)
        assert ("lbl_list", {"start": 0x400000, "end": 0x402000}) in fake.sent

    async def test_out_of_range_entry_is_filtered(self) -> None:
        """Labels outside ``[start, end]`` are excluded from the returned list.

        Oracle: x64dbg.py:6093 ``if start <= addr <= end: labels.append(...)``.
        Mutation caught: removing the range filter → out-of-range label appears
        → ``len(labels) == 1`` assertion fails.
        """
        pipe_entries = [
            {"address": "0x401000", "text": "WinMain"},
            {"address": "0x501000", "text": "OutOfRange"},
        ]

        bridge = X64DbgBridge()
        _install_fake_pipe(bridge, lambda _c, _p: _success(pipe_entries))
        labels: list[dict[str, Any]] = await bridge.get_labels(0x400000, 0x402000)

        assert len(labels) == 1
        assert labels[0]["address"] == "0x401000"
        assert labels[0]["text"] == "WinMain"


@pytest.mark.asyncio
class TestGetComments:
    """Gate ``get_comments`` — RPC framing and address-range filtering."""

    async def test_sends_cmt_list_with_integer_start_and_end(self) -> None:
        """``get_comments`` sends ``("cmt_list", {"start": N, "end": M})`` as ints.

        Oracle: x64dbg.py:6152 ``_send_pipe_command("cmt_list", {"start": start,
        "end": end})``.
        Mutation caught: sending hex strings instead of ints → tuple mismatch.
        """
        bridge = X64DbgBridge()
        fake = _install_fake_pipe(bridge, lambda _c, _p: _success([]))
        await bridge.get_comments(0x400000, 0x402000)
        assert ("cmt_list", {"start": 0x400000, "end": 0x402000}) in fake.sent

    async def test_in_range_comment_is_included(self) -> None:
        """Comment inside ``[start, end]`` is returned with exact text.

        Oracle: x64dbg.py:6171 ``if start <= addr <= end: comments.append(...)``.
        Mutation caught: inverting the range guard → in-range comment excluded →
        empty list returned → assertion fails.
        """
        pipe_entries = [
            {"address": "0x401500", "text": "allocates heap buffer"},
        ]

        bridge = X64DbgBridge()
        _install_fake_pipe(bridge, lambda _c, _p: _success(pipe_entries))
        comments: list[dict[str, Any]] = await bridge.get_comments(0x401000, 0x402000)

        assert len(comments) == 1
        assert comments[0]["text"] == "allocates heap buffer"
        assert comments[0]["address"] == "0x401500"


@pytest.mark.asyncio
class TestSetExceptionConfig:
    """Gate ``set_exception_config`` — exact SetExceptionBPX command string."""

    async def test_ignore_maps_to_zero_in_command(self) -> None:
        """``handling='ignore'`` maps to code ``0`` in the sent command.

        Oracle: x64dbg.py:6765 ``handling_map = {"break": 1, "ignore": 0, "log": 2}``;
        x64dbg.py:6767 ``SetExceptionBPX {hex(code)}, {handling_code}``.
        Mutation caught: using ``handling_map.get(handling, 0)`` instead of
        ``get(handling, 1)`` (wrong default) or swapping break/ignore values →
        wrong integer suffix → assertion fails.
        """
        bridge = X64DbgBridge()
        fake = _install_fake_pipe(bridge, lambda _c, _p: _success())
        result: dict[str, Any] = await bridge.set_exception_config(0xC0000005, "ignore")

        assert ("exec", {"command": "SetExceptionBPX 0xc0000005, 0"}) in fake.sent
        assert result == {"success": True, "code": "0xc0000005", "handling": "ignore"}

    async def test_break_maps_to_one_in_command(self) -> None:
        """``handling='break'`` maps to code ``1`` in the sent command.

        Oracle: x64dbg.py:6765 ``"break": 1``.
        Mutation caught: using ``0`` for break → assertion fails.
        """
        bridge = X64DbgBridge()
        fake = _install_fake_pipe(bridge, lambda _c, _p: _success())
        await bridge.set_exception_config(0x80000003, "break")
        assert ("exec", {"command": "SetExceptionBPX 0x80000003, 1"}) in fake.sent


@pytest.mark.asyncio
class TestFindReferences:
    """Gate ``find_references`` — exact ref_search framing and passthrough."""

    async def test_sends_ref_search_with_hex_address_and_type_reference(self) -> None:
        """``find_references`` sends exact ``("ref_search", ...)`` params.

        Oracle: x64dbg.py:6928 ``_send_pipe_command("ref_search",
        {"address": hex(address), "type": "reference"})``.
        Mutation caught: using ``str(address)`` instead of ``hex(address)`` →
        address param differs → assertion fails.
        """
        canned_refs = [{"from": "0x401100", "type": "call"}]
        bridge = X64DbgBridge()
        fake = _install_fake_pipe(bridge, lambda _c, _p: _success(canned_refs))

        result: dict[str, Any] = await bridge.find_references(0x401000)

        assert ("ref_search", {"address": "0x401000", "type": "reference"}) in fake.sent
        assert result["success"] is True
        assert result["address"] == "0x401000"
        assert result["references"] == canned_refs


@pytest.mark.asyncio
class TestFindStringReferences:
    """Gate ``find_string_references`` — exact ref_search framing and passthrough."""

    async def test_sends_ref_search_with_module_and_type_string(self) -> None:
        """``find_string_references`` sends ``type: "string"`` in the params.

        Oracle: x64dbg.py:6946 ``_send_pipe_command("ref_search",
        {"module": module, "type": "string"})``.
        Mutation caught: using ``"reference"`` instead of ``"string"`` →
        type value differs → assertion fails.
        """
        canned_refs = [{"address": "0x402000", "string": "Hello, World!"}]
        bridge = X64DbgBridge()
        fake = _install_fake_pipe(bridge, lambda _c, _p: _success(canned_refs))

        result: dict[str, Any] = await bridge.find_string_references("kernel32.dll")

        assert ("ref_search", {"module": "kernel32.dll", "type": "string"}) in fake.sent
        assert result["success"] is True
        assert result["module"] == "kernel32.dll"
        assert result["references"] == canned_refs


@pytest.mark.asyncio
class TestGetFunctionCfg:
    """Gate ``get_function_cfg`` — exact cfg framing and dict passthrough."""

    async def test_sends_cfg_with_hex_address_and_max_blocks(self) -> None:
        """``get_function_cfg`` sends the exact ``("cfg", ...)`` params.

        Oracle: x64dbg.py:6982 ``_send_pipe_command("cfg",
        {"address": hex(address), "max_blocks": max_blocks})``.
        Mutation caught: omitting ``max_blocks`` → param dict differs →
        assertion fails.
        """
        canned_cfg = {
            "entry": "0x401000",
            "blocks": [{"start": "0x401000", "end": "0x401010"}],
            "edges": [],
        }
        bridge = X64DbgBridge()
        fake = _install_fake_pipe(bridge, lambda _c, _p: _success(canned_cfg))

        result: dict[str, Any] = await bridge.get_function_cfg(0x401000, max_blocks=100)

        assert ("cfg", {"address": "0x401000", "max_blocks": 100}) in fake.sent
        assert result["entry"] == "0x401000"
        assert result["blocks"] == [{"start": "0x401000", "end": "0x401010"}]


@pytest.mark.asyncio
class TestClearDatabase:
    """Gate ``clear_database`` — db_clear RPC path and success return."""

    async def test_sends_db_clear_and_returns_success(self) -> None:
        """``clear_database`` sends ``("db_clear", None)`` and returns success.

        Oracle: x64dbg.py:7040 ``await self._send_pipe_command("db_clear")``;
        x64dbg.py:7046 ``return {"success": True}``.
        Mutation caught: changing the RPC name to ``"cleardb"`` → tuple not
        found → assertion fails; removing the ``return {"success": True}`` →
        return value assertion fails.
        """
        bridge = X64DbgBridge()
        fake = _install_fake_pipe(bridge, lambda _c, _p: _success())

        result: dict[str, Any] = await bridge.clear_database()

        assert ("db_clear", None) in fake.sent
        assert result == {"success": True}


@pytest.mark.asyncio
class TestRemoveWatch:
    """Gate ``remove_watch`` — watch_remove RPC framing."""

    async def test_sends_watch_remove_with_exact_index(self) -> None:
        """``remove_watch(3)`` sends ``("watch_remove", {"index": 3})``.

        Oracle: x64dbg.py:7452 ``_send_pipe_command("watch_remove", {"index": index})``.
        Mutation caught: using ``"index": str(index)`` → dict type mismatch →
        assertion fails.
        """
        bridge = X64DbgBridge()
        fake = _install_fake_pipe(bridge, lambda _c, _p: _success())

        result: dict[str, Any] = await bridge.remove_watch(3)

        assert ("watch_remove", {"index": 3}) in fake.sent
        assert result == {"success": True, "index": 3}


@pytest.mark.asyncio
class TestGetWatches:
    """Gate ``get_watches`` — watch_list RPC passthrough."""

    async def test_returns_exact_watch_list_from_pipe(self) -> None:
        """``get_watches`` sends ``("watch_list", None)`` and returns the exact list.

        Oracle: x64dbg.py:7471 ``_send_pipe_command("watch_list")``;
        x64dbg.py:7478 ``return [dict(entry) ...]``.
        Mutation caught: renaming the RPC to ``"watches"`` → no response →
        empty list returned → length assertion fails; or returning the list
        unmodified (without ``dict(entry)``) → type annotation mismatch.
        """
        canned_watches = [
            {"index": 0, "expression": "eax", "type": "DWORD", "value": "0x12345678"},
            {"index": 1, "expression": "rip", "type": "QWORD", "value": "0x401000"},
        ]
        bridge = X64DbgBridge()
        fake = _install_fake_pipe(bridge, lambda _c, _p: _success(canned_watches))

        watches: list[dict[str, Any]] = await bridge.get_watches()

        assert ("watch_list", None) in fake.sent
        assert len(watches) == 2
        assert watches[0] == {"index": 0, "expression": "eax", "type": "DWORD", "value": "0x12345678"}
        assert watches[1]["expression"] == "rip"


@pytest.mark.asyncio
class TestScriptLoad:
    """Gate ``script_load`` — exec + eval round-trips and verified flag."""

    async def test_sends_scriptload_command_and_queries_script_iserror(self) -> None:
        """``script_load`` sends exec then eval RPC and returns ``verified=True``.

        Oracle: x64dbg.py:8020 ``await self._send_command(f'scriptload "{path}"')``;
        x64dbg.py:8021 ``error_flag = await self._query_script_error()``;
        x64dbg.py:8035 ``return {"success": True, "path": path, "verified": True}``.
        Mutation caught: omitting the eval query → ``("eval", ...)`` absent from
        ``fake.sent`` → assertion fails; or returning ``verified=False`` →
        assertion on result value fails.
        """

        def _responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "eval":
                return _success(0)
            return _success("")

        bridge = X64DbgBridge()
        fake = _install_fake_pipe(bridge, _responder)

        result: dict[str, Any] = await bridge.script_load(_SCRIPT_PATH)

        exec_tuple = ("exec", {"command": f'scriptload "{_SCRIPT_PATH}"'})
        eval_tuple = ("eval", {"expression": "script.iserror()"})
        assert exec_tuple in fake.sent
        assert eval_tuple in fake.sent
        assert result == {"success": True, "path": _SCRIPT_PATH, "verified": True}


@pytest.mark.asyncio
class TestScriptRun:
    """Gate ``script_run`` — exec + eval round-trips and verified flag."""

    async def test_sends_scriptrun_command_and_queries_script_iserror(self) -> None:
        """``script_run`` sends exec then eval RPC and returns ``verified=True``.

        Oracle: x64dbg.py:8057 ``await self._send_command("scriptrun")``;
        x64dbg.py:8058 ``error_flag = await self._query_script_error()``;
        x64dbg.py:8071 ``return {"success": True, "verified": True}``.
        Mutation caught: omitting the eval query → ``("eval", ...)`` absent →
        assertion fails.
        """

        def _responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "eval":
                return _success(0)
            return _success("")

        bridge = X64DbgBridge()
        fake = _install_fake_pipe(bridge, _responder)

        result: dict[str, Any] = await bridge.script_run()

        assert ("exec", {"command": "scriptrun"}) in fake.sent
        assert ("eval", {"expression": "script.iserror()"}) in fake.sent
        assert result == {"success": True, "verified": True}


@pytest.mark.asyncio
class TestScriptCmd:
    """Gate ``script_cmd`` — exec + eval round-trips and line passthrough."""

    async def test_sends_scriptcmd_with_line_and_queries_script_iserror(self) -> None:
        """``script_cmd`` sends exec with the quoted line and queries eval.

        Oracle: x64dbg.py:8096 ``await self._send_command(f'scriptcmd "{line}"')``;
        x64dbg.py:8111 ``return {"success": True, "line": line, "verified": True}``.
        Mutation caught: not quoting ``line`` → command string differs →
        exec assertion fails; not including ``line`` in return dict →
        result assertion fails.
        """

        def _responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "eval":
                return _success(0)
            return _success("")

        bridge = X64DbgBridge()
        fake = _install_fake_pipe(bridge, _responder)

        result: dict[str, Any] = await bridge.script_cmd(_SCRIPT_LINE)

        exec_cmd = f'scriptcmd "{_SCRIPT_LINE}"'
        assert ("exec", {"command": exec_cmd}) in fake.sent
        assert ("eval", {"expression": "script.iserror()"}) in fake.sent
        assert result == {"success": True, "line": _SCRIPT_LINE, "verified": True}


@pytest.mark.asyncio
class TestScriptAbort:
    """Gate ``script_abort`` — exec + eval round-trips and verified flag."""

    async def test_sends_scriptabort_command_and_queries_script_iserror(self) -> None:
        """``script_abort`` sends exec then eval RPC and returns ``verified=True``.

        Oracle: x64dbg.py:8134 ``await self._send_command("scriptabort")``;
        x64dbg.py:8135 ``error_flag = await self._query_script_error()``.
        Mutation caught: omitting the eval query → assertion fails.
        """

        def _responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "eval":
                return _success(0)
            return _success("")

        bridge = X64DbgBridge()
        fake = _install_fake_pipe(bridge, _responder)

        result: dict[str, Any] = await bridge.script_abort()

        assert ("exec", {"command": "scriptabort"}) in fake.sent
        assert ("eval", {"expression": "script.iserror()"}) in fake.sent
        assert result["success"] is True
        assert result["verified"] is True


@pytest.mark.asyncio
class TestCloseHandle:
    """Gate ``close_handle`` — exact handleclose command string."""

    async def test_sends_handleclose_with_hex_handle(self) -> None:
        """``close_handle(0xDEAD)`` sends ``handleclose 0xdead`` via exec.

        Oracle: x64dbg.py:8386 ``await self._send_command(f"handleclose {hex(handle)}")``.
        Mutation caught: using ``str(handle)`` (decimal) instead of ``hex(handle)``
        → command string differs → assertion fails.
        """
        bridge = X64DbgBridge()
        fake = _install_fake_pipe(bridge, lambda _c, _p: _success())

        result: dict[str, Any] = await bridge.close_handle(_HANDLE_VAL)

        expected_cmd = f"handleclose {hex(_HANDLE_VAL)}"
        assert ("exec", {"command": expected_cmd}) in fake.sent
        assert result == {"success": True, "handle": hex(_HANDLE_VAL)}


@pytest.mark.skipif(sys.platform != "win32", reason="Toolhelp and ReadProcessMemory are Windows-only")
@pytest.mark.skipif(not _NTDLL_PATH.exists(), reason="ntdll.dll not present at expected path")
@pytest.mark.asyncio
class TestBreakOnTlsCallbacks:
    """Gate ``break_on_tls_callbacks`` — breakpoints_set key and count oracle."""

    async def test_breakpoints_set_matches_pefile_tls_callback_count(self) -> None:
        """``break_on_tls_callbacks`` returns a count matching the on-disk PE count.

        The test attaches to the current process (``os.getpid()``) and asks
        the bridge to set breakpoints on ntdll.dll's TLS callbacks.  pefile
        parses the on-disk binary as the independent oracle for callback count.

        Oracle: ``pefile.PE(ntdll_path).DIRECTORY_ENTRY_TLS.callbacks``
        (count of VA entries in the TLS callback array); x64dbg.py:8723
        ``"breakpoints_set": len(callbacks)``.
        Mutation caught: changing the key name from ``"breakpoints_set"`` to
        ``"count"`` → ``result["breakpoints_set"]`` raises ``KeyError`` →
        assertion fails; or off-by-one in the count → value mismatch.
        """
        pe = pefile.PE(str(_NTDLL_PATH))
        pe.parse_data_directories()
        if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
            raw_cbs: list[Any] = getattr(pe.DIRECTORY_ENTRY_TLS, "callbacks", []) or []
            expected_count = len(raw_cbs)
        else:
            expected_count = 0
        pe.close()

        def _responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "bp_list":
                return {"success": False, "code": "unknown_command", "error": "unknown_command"}
            return {"success": True, "result": None}

        bridge = X64DbgBridge()
        setattr(bridge, "_attached_pid", os.getpid())
        _install_fake_pipe(bridge, _responder)

        result: dict[str, Any] = await bridge.break_on_tls_callbacks("ntdll.dll")

        assert result["success"] is True
        assert result["breakpoints_set"] == expected_count
