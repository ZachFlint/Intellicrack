# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Wave-2b test gates: X64DbgBridge register / process-structure read family.

Directly remediates:
  FG-1 — ``read_peb`` asserted only a docstring substring in the tool
    definition's ``returns`` field; no data-flow was tested.  Replaced
    with a full round-trip through a fake pipe client that asserts exact
    field values against independent oracle constants.
  FG-3 — ``get_registers`` only tested the no-plugin ``ToolError`` path.
    The value-population branches (hex string parsing, integer passthrough,
    legacy 32-bit alias fallback) were never exercised.  Replaced with
    gates that assert exact parsed ``RegisterState`` field values.

New real gates added (previously NO COVERAGE):
  set_register         — verifies exact RPC framing (param key is
                         ``"register"``, not ``"name"``) and that ``True``
                         is returned on success.
  read_teb             — verifies ``teb_read`` is sent with ``None`` params
                         when no tid is given, and with ``{"tid": …}`` when
                         one is supplied; asserts exact returned fields.
  get_seh_chain        — verifies entry-list parsing and that recoverable
                         ``unknown command`` errors return ``[]``.
  get_pe_directories   — verifies the ``"module"`` key is forwarded and
                         that the returned list carries exact index/rva/size
                         values from the canned response.
  get_tls_callbacks    — drives a full PE64 TLS directory scan through
                         monkeypatched ``_resolve_module_base``,
                         ``_read_pe_header``, and ``read_memory``; asserts
                         callback addresses against known oracle constants.
  get_handles          — verifies ``ToolError`` when not attached; verifies
                         ``_parse_handle_buffer`` PID-filter via a
                         ctypes-built synthetic buffer.
  get_privileges       — verifies list shape (name / enabled /
                         enabled_by_default keys) and that names begin with
                         ``Se``, on Windows live token.
"""

from __future__ import annotations

import asyncio
import ctypes
import struct
import sys
from typing import TYPE_CHECKING, Any, Final, cast

import pytest

from intellicrack.bridges.pe_format import (
    PE32PLUS_OPTIONAL_HEADER_SIZE,
    PE_DATA_DIRECTORY_ENTRY_SIZE,
    PE_OPTIONAL_HEADER_OFFSET,
)
from intellicrack.bridges.win32_types import SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.core.types import RegisterState, ToolError


if TYPE_CHECKING:
    from collections.abc import Callable


# ---------------------------------------------------------------------------
# Independent oracle constants
# ---------------------------------------------------------------------------

_RAX_VALUE: Final[int] = 0xDEAD_BEEF
_RBX_VALUE: Final[int] = 1
_RDX_VALUE: Final[int] = 0xFF
_RIP_VALUE: Final[int] = 0x0000_7FFF_1234_5678
_RFLAGS_VALUE: Final[int] = 0x246
_CS_VALUE: Final[int] = 0x33
_SS_VALUE: Final[int] = 0x2B

_EAX_ALIAS_VALUE: Final[int] = 0x1234_5678

_SET_REG_NAME: Final[str] = "rax"
_SET_REG_VALUE: Final[int] = 0xCAFE_BABE

_PEB_ADDRESS: Final[str] = "0x7FFE0000"
_PEB_BEING_DEBUGGED: Final[int] = 0
_PEB_NT_GLOBAL_FLAG: Final[int] = 0x70
_PEB_IMAGE_BASE: Final[str] = "0x140000000"
_PEB_PARAMS: Final[str] = "0x40000000"

_TEB_STACK_BASE: Final[str] = "0x7FFF0000"
_TEB_STACK_LIMIT: Final[str] = "0x7FF90000"
_TEB_THREAD_ID: Final[int] = 9988
_TEB_TID_ARG: Final[int] = 7777

_SEH_HANDLER_0: Final[str] = "0x401000"
_SEH_NEXT_0: Final[str] = "0xFFFFFFFF"
_SEH_HANDLER_1: Final[str] = "0x402000"
_SEH_NEXT_1: Final[str] = "0xFFFFE000"

_PE_MODULE: Final[str] = "target.dll"
_PE_DIR_EXPORT_RVA: Final[int] = 0x1000
_PE_DIR_EXPORT_SIZE: Final[int] = 0x200
_PE_DIR_IMPORT_RVA: Final[int] = 0x2000
_PE_DIR_IMPORT_SIZE: Final[int] = 0x100

_TLS_MODULE: Final[str] = "tls_target.dll"
_TLS_MODULE_BASE: Final[int] = 0x1_4000_0000
_TLS_RVA: Final[int] = 0x1000
_TLS_SIZE: Final[int] = 0x40
_TLS_CALLBACK_ARRAY_VA: Final[int] = 0x1_4000_2000
_TLS_CB0_VA: Final[int] = 0x1_4000_3000
_TLS_CB1_VA: Final[int] = 0x1_4000_4000

_HANDLE_TARGET_PID: Final[int] = 3737
_HANDLE_VALUE: Final[int] = 0x14
_HANDLE_OBJECT: Final[int] = 0x1234_5678_9ABC
_HANDLE_GRANTED_ACCESS: Final[int] = 0x001F_0001
_HANDLE_TYPE_INDEX: Final[int] = 0x25
_HANDLE_OTHER_PID: Final[int] = 9999

_PARSE_HANDLE_BUFFER_ATTR: Final[str] = "_parse_handle_buffer"


# ---------------------------------------------------------------------------
# Fake pipe-client (self-contained, no unittest.mock)
# ---------------------------------------------------------------------------


class _FakePipe2B:
    """In-process ``NamedPipeClient`` replacement for wave-2b tests.

    Records every ``(command, params)`` pair in ``sent`` and returns
    responses produced by a scripted ``_responder`` callable.
    """

    def __init__(
        self,
        responder: Callable[[str, dict[str, Any] | None], dict[str, Any]],
    ) -> None:
        """Initialise with a scripted responder.

        Args:
            responder: Callable mapping ``(command, params)`` to the
                response dict the named-pipe layer would have returned.
        """
        self._responder = responder
        self.sent: list[tuple[str, dict[str, Any] | None]] = []

    @property
    def is_connected(self) -> bool:
        """Report permanently connected.

        Returns:
            bool: Always ``True``.
        """
        return True

    async def send_command(
        self,
        command: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Record the call and return the scripted response.

        Args:
            command: RPC command name.
            params: Optional parameters dict.

        Returns:
            dict[str, Any]: Response produced by the responder.
        """
        self.sent.append((command, params))
        return self._responder(command, params)


class _StubProcess2B:
    """Sentinel satisfying ``self._process is not None`` guards in the bridge."""


def _install_fake_2b(
    bridge: X64DbgBridge,
    responder: Callable[[str, dict[str, Any] | None], dict[str, Any]],
) -> _FakePipe2B:
    """Attach a fake pipe client and mark the plugin deployed.

    Args:
        bridge: Bridge under test.
        responder: Per-command response generator.

    Returns:
        _FakePipe2B: The installed fake, useful for ``sent`` assertions.
    """
    fake = _FakePipe2B(responder)
    setattr(bridge, "_pipe_client", fake)
    setattr(bridge, "_plugin_deployed", True)
    setattr(bridge, "_process", _StubProcess2B())
    return fake


# ---------------------------------------------------------------------------
# Shared fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def bridge() -> X64DbgBridge:
    """Create a fresh, unattached bridge instance.

    Returns:
        X64DbgBridge: Bridge with no attached PID.
    """
    return X64DbgBridge()


# ---------------------------------------------------------------------------
# TestGetRegisters — FG-3: replace error-path-only gate with value assertions
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestGetRegisters:
    """FG-3 fix: ``get_registers`` round-trip asserts exact parsed register values.

    All previous coverage consisted of confirming that an undeployed
    plugin raises ``ToolError``.  These gates drive the real parsing
    branches (hex-string coercion, integer passthrough, 32-bit alias
    fallback) using a fake pipe that returns a known canned register dict.
    """

    async def test_parses_hex_string_and_int_values(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Canned response with mixed hex-string/int values populates all GPRs.

        The SUT cannot reproduce ``_RAX_VALUE`` / ``_CS_VALUE`` etc.
        without correctly dispatching ``reg_all`` and parsing the
        response, so these assertions are falsifiable by any parsing
        regression.

        Args:
            bridge: Fresh bridge fixture.
        """

        def responder(_cmd: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {
                "success": True,
                "result": {
                    "rax": hex(_RAX_VALUE),
                    "rbx": _RBX_VALUE,
                    "rcx": 0,
                    "rdx": _RDX_VALUE,
                    "rsi": 0,
                    "rdi": 0,
                    "rbp": 0,
                    "rsp": 0,
                    "rip": hex(_RIP_VALUE),
                    "r8": 0,
                    "r9": 0,
                    "r10": 0,
                    "r11": 0,
                    "r12": 0,
                    "r13": 0,
                    "r14": 0,
                    "r15": 0,
                    "rflags": hex(_RFLAGS_VALUE),
                    "cs": _CS_VALUE,
                    "ds": 0,
                    "es": 0,
                    "fs": 0,
                    "gs": 0,
                    "ss": _SS_VALUE,
                },
            }

        fake = _install_fake_2b(bridge, responder)
        state = await bridge.get_registers()

        assert isinstance(state, RegisterState)
        assert ("reg_all", None) in fake.sent, "bridge must dispatch 'reg_all' with no params"
        assert state.rax == _RAX_VALUE, f"rax: want {_RAX_VALUE:#x}, got {state.rax:#x}"
        assert state.rbx == _RBX_VALUE, f"rbx: want {_RBX_VALUE}, got {state.rbx}"
        assert state.rdx == _RDX_VALUE, f"rdx: want {_RDX_VALUE:#x}, got {state.rdx:#x}"
        assert state.rip == _RIP_VALUE, f"rip: want {_RIP_VALUE:#x}, got {state.rip:#x}"
        assert state.rflags == _RFLAGS_VALUE, f"rflags: want {_RFLAGS_VALUE:#x}, got {state.rflags:#x}"
        assert state.cs == _CS_VALUE, f"cs: want {_CS_VALUE:#x}, got {state.cs:#x}"
        assert state.ss == _SS_VALUE, f"ss: want {_SS_VALUE:#x}, got {state.ss:#x}"

    async def test_legacy_alias_eax_populates_rax(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """A response using the 32-bit alias ``eax`` still populates ``state.rax``.

        Mutation caught: removing the ``alt`` fallback in ``get_reg``
        would leave ``state.rax == 0`` even when the pipe returned
        a value under the ``"eax"`` key.

        Args:
            bridge: Fresh bridge fixture.
        """

        def responder(_cmd: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {
                "success": True,
                "result": {
                    "eax": _EAX_ALIAS_VALUE,
                    "ebx": 0,
                    "ecx": 0,
                    "edx": 0,
                    "esi": 0,
                    "edi": 0,
                    "ebp": 0,
                    "esp": 0,
                    "eip": 0,
                    "eflags": 0,
                },
            }

        _install_fake_2b(bridge, responder)
        state = await bridge.get_registers()
        assert state.rax == _EAX_ALIAS_VALUE, f"legacy alias 'eax' must populate state.rax; want {_EAX_ALIAS_VALUE:#x}, got {state.rax:#x}"

    async def test_non_dict_response_raises(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """A non-dict ``reg_all`` payload raises ``ToolError``.

        Args:
            bridge: Fresh bridge fixture.
        """

        def responder(_cmd: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {"success": True, "result": [1, 2, 3]}

        _install_fake_2b(bridge, responder)
        with pytest.raises(ToolError, match="Invalid register response"):
            await bridge.get_registers()


# ---------------------------------------------------------------------------
# TestSetRegister — new real gate: exact RPC framing
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestSetRegister:
    """Real gates for ``set_register``: command framing and return value."""

    async def test_emits_reg_set_with_register_key_not_name(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Bridge sends ``reg_set`` with ``"register"`` param key (not ``"name"``).

        Mutation caught: renaming the param key from ``"register"`` to
        ``"name"`` would break the RPC contract while the old ToolError-only
        gate still passed.

        Args:
            bridge: Fresh bridge fixture.
        """

        def responder(_cmd: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {"success": True, "result": None}

        fake = _install_fake_2b(bridge, responder)
        result = await bridge.set_register(_SET_REG_NAME, _SET_REG_VALUE)

        assert result is True, "set_register must return True on success"
        expected_params: dict[str, Any] = {"register": _SET_REG_NAME, "value": _SET_REG_VALUE}
        assert ("reg_set", expected_params) in fake.sent, f"bridge must emit ('reg_set', {expected_params!r}); got {fake.sent!r}"

    async def test_pipe_error_propagates(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """A pipe-disconnect error propagates from ``set_register``.

        ``set_register`` has no recoverable fallback: the error must
        surface so the caller knows the register write never reached the
        debugger.

        Args:
            bridge: Fresh bridge fixture.
        """

        def responder(_cmd: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {"success": False, "error": "Pipe not connected"}

        _install_fake_2b(bridge, responder)
        with pytest.raises(ToolError, match="Pipe not connected"):
            await bridge.set_register("rax", 0)


# ---------------------------------------------------------------------------
# TestReadPeb — FG-1 fix: replace docstring-substring gate with round-trip
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestReadPeb:
    """FG-1 fix: ``read_peb`` round-trip asserts exact field values.

    The previous gate only confirmed that the string ``"address"`` appeared
    in the tool-definition ``returns`` field — completely independent of
    the method's runtime behaviour.  Deleting the implementation body
    would have left that gate green.
    """

    async def test_returns_exact_peb_fields(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Canned PEB dict is returned verbatim with all known fields intact.

        Mutation caught: replacing ``return dict(result)`` with
        ``return {}`` causes every field assertion to fail.

        Args:
            bridge: Fresh bridge fixture.
        """

        def responder(_cmd: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {
                "success": True,
                "result": {
                    "address": _PEB_ADDRESS,
                    "beingDebugged": _PEB_BEING_DEBUGGED,
                    "ntGlobalFlag": _PEB_NT_GLOBAL_FLAG,
                    "imageBaseAddress": _PEB_IMAGE_BASE,
                    "processParameters": _PEB_PARAMS,
                },
            }

        fake = _install_fake_2b(bridge, responder)
        result = await bridge.read_peb()

        assert ("peb_read", None) in fake.sent, "bridge must dispatch 'peb_read' with no params"
        assert result["address"] == _PEB_ADDRESS
        assert result["beingDebugged"] == _PEB_BEING_DEBUGGED
        assert result["ntGlobalFlag"] == _PEB_NT_GLOBAL_FLAG
        assert result["imageBaseAddress"] == _PEB_IMAGE_BASE
        assert result["processParameters"] == _PEB_PARAMS

    async def test_pipe_disconnected_propagates(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """A non-recoverable pipe error propagates rather than silently returning ``{}``.

        Args:
            bridge: Fresh bridge fixture.
        """

        def responder(_cmd: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {"success": False, "error": "Pipe not connected"}

        _install_fake_2b(bridge, responder)
        with pytest.raises(ToolError, match="Pipe not connected"):
            await bridge.read_peb()

    async def test_unknown_command_returns_empty_dict(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """A recoverable ``unknown command`` error causes ``read_peb`` to return ``{}``.

        Args:
            bridge: Fresh bridge fixture.
        """

        def responder(_cmd: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {"success": False, "error": "Unknown command 'peb_read'"}

        _install_fake_2b(bridge, responder)
        result = await bridge.read_peb()
        assert result == {}, f"recoverable error must yield empty dict, got {result!r}"

    async def test_non_dict_result_returns_empty_dict(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """A non-dict plugin payload returns ``{}``.

        Args:
            bridge: Fresh bridge fixture.
        """

        def responder(_cmd: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {"success": True, "result": ["not", "a", "dict"]}

        _install_fake_2b(bridge, responder)
        result = await bridge.read_peb()
        assert result == {}


# ---------------------------------------------------------------------------
# TestReadTeb — new real gate (NO COVERAGE)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestReadTeb:
    """Real gates for ``read_teb``: command framing and field assertions."""

    async def test_no_tid_sends_null_params(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Calling without ``tid`` sends ``teb_read`` with ``None`` params.

        Mutation caught: removing the ``params or None`` guard would
        forward an empty dict instead of ``None``.

        Args:
            bridge: Fresh bridge fixture.
        """

        def responder(_cmd: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {
                "success": True,
                "result": {
                    "stackBase": _TEB_STACK_BASE,
                    "stackLimit": _TEB_STACK_LIMIT,
                    "threadId": _TEB_THREAD_ID,
                },
            }

        fake = _install_fake_2b(bridge, responder)
        result = await bridge.read_teb()

        assert ("teb_read", None) in fake.sent, "read_teb() with no tid must send ('teb_read', None)"
        assert result["stackBase"] == _TEB_STACK_BASE
        assert result["stackLimit"] == _TEB_STACK_LIMIT
        assert result["threadId"] == _TEB_THREAD_ID

    async def test_with_tid_forwards_tid_in_params(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Calling with ``tid`` forwards it in the params dict under key ``"tid"``.

        Mutation caught: dropping the ``if tid is not None: params["tid"] = tid``
        block would forward ``None`` params even when a tid is supplied.

        Args:
            bridge: Fresh bridge fixture.
        """

        def responder(_cmd: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {"success": True, "result": {"threadId": _TEB_TID_ARG}}

        fake = _install_fake_2b(bridge, responder)
        result = await bridge.read_teb(_TEB_TID_ARG)

        expected_params: dict[str, Any] = {"tid": _TEB_TID_ARG}
        assert ("teb_read", expected_params) in fake.sent, f"read_teb(tid={_TEB_TID_ARG}) must send {expected_params!r}; got {fake.sent!r}"
        assert result["threadId"] == _TEB_TID_ARG

    async def test_unknown_command_returns_empty_dict(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """A recoverable unknown-command error returns ``{}``.

        Args:
            bridge: Fresh bridge fixture.
        """

        def responder(_cmd: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {"success": False, "error": "Unknown command 'teb_read'"}

        _install_fake_2b(bridge, responder)
        assert await bridge.read_teb() == {}


# ---------------------------------------------------------------------------
# TestGetSehChain — new real gate (NO COVERAGE)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestGetSehChain:
    """Real gates for ``get_seh_chain``: entry parsing and recoverable fallback."""

    async def test_returns_parsed_entry_dicts(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Response list items are returned as dicts with exact field values.

        Mutation caught: replacing ``dict(entry)`` with ``{}`` would
        zero out every field assertion.

        Args:
            bridge: Fresh bridge fixture.
        """

        def responder(_cmd: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {
                "success": True,
                "result": [
                    {"handler": _SEH_HANDLER_0, "next": _SEH_NEXT_0},
                    {"handler": _SEH_HANDLER_1, "next": _SEH_NEXT_1},
                ],
            }

        fake = _install_fake_2b(bridge, responder)
        entries = await bridge.get_seh_chain()

        assert ("seh_chain", None) in fake.sent, "bridge must dispatch 'seh_chain' with no params"
        assert len(entries) == 2
        assert entries[0]["handler"] == _SEH_HANDLER_0
        assert entries[0]["next"] == _SEH_NEXT_0
        assert entries[1]["handler"] == _SEH_HANDLER_1
        assert entries[1]["next"] == _SEH_NEXT_1

    async def test_unknown_command_returns_empty_list(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """A recoverable unknown-command error returns ``[]``.

        Args:
            bridge: Fresh bridge fixture.
        """

        def responder(_cmd: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {"success": False, "error": "Unknown command 'seh_chain'"}

        _install_fake_2b(bridge, responder)
        assert await bridge.get_seh_chain() == []

    async def test_non_list_result_returns_empty_list(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """A non-list payload returns ``[]``.

        Args:
            bridge: Fresh bridge fixture.
        """

        def responder(_cmd: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {"success": True, "result": {"not": "a list"}}

        _install_fake_2b(bridge, responder)
        assert await bridge.get_seh_chain() == []


# ---------------------------------------------------------------------------
# TestGetPeDirectories — new real gate (NO COVERAGE)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestGetPeDirectories:
    """Real gates for ``get_pe_directories``: module param forwarding and parsing."""

    async def test_forwards_module_name_and_returns_entries(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Bridge sends ``pe_directories`` with ``"module"`` key equal to the arg.

        Mutation caught: swapping ``"module"`` for ``"module_name"`` in
        the params dict would send the wrong key to the plugin RPC.

        Args:
            bridge: Fresh bridge fixture.
        """

        def responder(_cmd: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {
                "success": True,
                "result": [
                    {
                        "index": 0,
                        "name": "export",
                        "rva": hex(_PE_DIR_EXPORT_RVA),
                        "size": _PE_DIR_EXPORT_SIZE,
                    },
                    {
                        "index": 1,
                        "name": "import",
                        "rva": hex(_PE_DIR_IMPORT_RVA),
                        "size": _PE_DIR_IMPORT_SIZE,
                    },
                ],
            }

        fake = _install_fake_2b(bridge, responder)
        dirs = await bridge.get_pe_directories(_PE_MODULE)

        expected_params: dict[str, Any] = {"module": _PE_MODULE}
        assert ("pe_directories", expected_params) in fake.sent, f"bridge must forward {expected_params!r}; got {fake.sent!r}"
        assert len(dirs) == 2
        assert dirs[0]["name"] == "export"
        assert dirs[0]["rva"] == hex(_PE_DIR_EXPORT_RVA)
        assert dirs[0]["size"] == _PE_DIR_EXPORT_SIZE
        assert dirs[1]["name"] == "import"
        assert dirs[1]["rva"] == hex(_PE_DIR_IMPORT_RVA)
        assert dirs[1]["size"] == _PE_DIR_IMPORT_SIZE

    async def test_unknown_command_returns_empty_list(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """A recoverable unknown-command error returns ``[]``.

        Args:
            bridge: Fresh bridge fixture.
        """

        def responder(_cmd: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {"success": False, "error": "Unknown command 'pe_directories'"}

        _install_fake_2b(bridge, responder)
        assert await bridge.get_pe_directories("any.dll") == []


# ---------------------------------------------------------------------------
# TestGetTlsCallbacks — new real gate (NO COVERAGE)
# ---------------------------------------------------------------------------


def _build_tls_pe64_header() -> bytes:
    """Build a minimal 512-byte PE64 NT-headers buffer with a TLS data-directory entry.

    The buffer starts at the NT-headers (no DOS stub).  Magic
    ``0x020B`` (PE32+) is written at ``PE_OPTIONAL_HEADER_OFFSET`` (24).
    The TLS data-directory entry (index 9) is written at the standard
    PE64 computed offset.

    Returns:
        bytes: 512-byte buffer readable by ``is_pe64_optional_header``
        and ``get_data_directory_offset`` / ``read_data_directory_entry``.
    """
    buf = bytearray(512)
    struct.pack_into("<H", buf, PE_OPTIONAL_HEADER_OFFSET, 0x020B)
    tls_entry_offset = PE_OPTIONAL_HEADER_OFFSET + PE32PLUS_OPTIONAL_HEADER_SIZE + 9 * PE_DATA_DIRECTORY_ENTRY_SIZE
    struct.pack_into("<II", buf, tls_entry_offset, _TLS_RVA, _TLS_SIZE)
    return bytes(buf)


def _build_tls_directory_pe64() -> bytes:
    """Build a 64-byte PE64 TLS directory with a known callback-array VA.

    The production code reads the callback-array VA as a QWORD at
    offset ``12 + ptr_size = 12 + 8 = 20`` for PE64.  The oracle VA
    ``_TLS_CALLBACK_ARRAY_VA`` is placed at that exact offset.

    Returns:
        bytes: 64-byte TLS directory buffer.
    """
    buf = bytearray(64)
    struct.pack_into("<Q", buf, 20, _TLS_CALLBACK_ARRAY_VA)
    return bytes(buf)


@pytest.mark.asyncio
class TestGetTlsCallbacks:
    """Real gates for ``get_tls_callbacks``: PE64 TLS enumeration end-to-end."""

    async def test_enumerates_two_callbacks_until_null_terminator(
        self,
        bridge: X64DbgBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Two non-zero callbacks followed by a null terminator yields two entries.

        The oracle addresses are ``_TLS_CB0_VA`` / ``_TLS_CB1_VA``.
        Mutation caught: reading the callback-array VA from offset 24
        instead of 20 inside the TLS directory would yield 0 for the
        VA (since those bytes are zero-filled), causing the function to
        return ``[]`` instead of the two entries.

        Args:
            bridge: Fresh bridge fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        pe_header = _build_tls_pe64_header()
        tls_dir = _build_tls_directory_pe64()
        ptr_size = 8

        callback_reads: dict[int, bytes] = {
            _TLS_CALLBACK_ARRAY_VA + 0 * ptr_size: struct.pack("<Q", _TLS_CB0_VA),
            _TLS_CALLBACK_ARRAY_VA + 1 * ptr_size: struct.pack("<Q", _TLS_CB1_VA),
            _TLS_CALLBACK_ARRAY_VA + 2 * ptr_size: struct.pack("<Q", 0),
        }

        async def fake_resolve(_name: str) -> int:
            await asyncio.sleep(0)
            return _TLS_MODULE_BASE

        async def fake_read_pe_header(
            _base: int,
            _module: str,
            size: int = 256,
        ) -> tuple[int, bytes]:
            await asyncio.sleep(0)
            return 0, pe_header[:size]

        async def fake_read_memory(address: int, size: int) -> bytes:
            await asyncio.sleep(0)
            tls_dir_addr = _TLS_MODULE_BASE + _TLS_RVA
            if address == tls_dir_addr:
                return tls_dir[:size]
            data = callback_reads.get(address)
            if data is not None:
                return data[:size]
            msg = f"unexpected read_memory at {hex(address)}"
            raise ToolError(msg)

        monkeypatch.setattr(bridge, "_resolve_module_base", fake_resolve)
        monkeypatch.setattr(bridge, "_read_pe_header", fake_read_pe_header)
        monkeypatch.setattr(bridge, "read_memory", fake_read_memory)

        result = await bridge.get_tls_callbacks(_TLS_MODULE)

        assert len(result) == 2, f"expected 2 callbacks, got {len(result)}: {result!r}"
        assert result[0]["index"] == 0
        assert result[0]["address"] == hex(_TLS_CB0_VA)
        assert result[1]["index"] == 1
        assert result[1]["address"] == hex(_TLS_CB1_VA)

    async def test_no_tls_directory_returns_empty_list(
        self,
        bridge: X64DbgBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A PE header with zero TLS RVA / size returns ``[]``.

        Args:
            bridge: Fresh bridge fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        buf = bytearray(512)
        struct.pack_into("<H", buf, PE_OPTIONAL_HEADER_OFFSET, 0x020B)

        async def fake_resolve(_name: str) -> int:
            await asyncio.sleep(0)
            return _TLS_MODULE_BASE

        async def fake_read_pe_header(
            _base: int,
            _module: str,
            size: int = 256,
        ) -> tuple[int, bytes]:
            await asyncio.sleep(0)
            return 0, bytes(buf)[:size]

        monkeypatch.setattr(bridge, "_resolve_module_base", fake_resolve)
        monkeypatch.setattr(bridge, "_read_pe_header", fake_read_pe_header)

        result = await bridge.get_tls_callbacks(_TLS_MODULE)
        assert result == []


# ---------------------------------------------------------------------------
# TestGetHandles — new real gate (NO COVERAGE)
# ---------------------------------------------------------------------------


def _build_synthetic_handle_buffer(
    target_pid: int,
    *,
    handle_value: int,
    object_addr: int,
    granted_access: int,
    type_index: int,
    other_pid: int,
) -> bytes:
    """Build a ``SystemExtendedHandleInformation`` buffer with two entries.

    The first entry belongs to ``target_pid``.  The second belongs to
    ``other_pid`` so that the PID filter in ``_parse_handle_buffer`` can
    be independently verified.

    Args:
        target_pid: PID that the target entry belongs to.
        handle_value: ``HandleValue`` to embed in the target entry.
        object_addr: ``Object`` pointer to embed in the target entry.
        granted_access: ``GrantedAccess`` field for the target entry.
        type_index: ``ObjectTypeIndex`` for the target entry.
        other_pid: PID for the second (non-matching) entry.

    Returns:
        bytes: Raw buffer parseable by
        ``X64DbgBridge._parse_handle_buffer``.
    """
    entry_size = ctypes.sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)
    entries_offset = ctypes.sizeof(ctypes.c_void_p) * 2
    ptr_width = ctypes.sizeof(ctypes.c_void_p)

    buf = bytearray(entries_offset + 2 * entry_size)
    buf[:ptr_width] = (2).to_bytes(ptr_width, "little")

    e0 = SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX()
    e0.Object = object_addr
    e0.UniqueProcessId = target_pid
    e0.HandleValue = handle_value
    e0.GrantedAccess = granted_access
    e0.CreatorBackTraceIndex = 0
    e0.ObjectTypeIndex = type_index
    e0.HandleAttributes = 0
    e0.Reserved = 0
    buf[entries_offset : entries_offset + entry_size] = bytes(e0)

    e1 = SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX()
    e1.Object = 0
    e1.UniqueProcessId = other_pid
    e1.HandleValue = 0x1C
    e1.GrantedAccess = 0x0002
    e1.CreatorBackTraceIndex = 0
    e1.ObjectTypeIndex = 0x07
    e1.HandleAttributes = 0
    e1.Reserved = 0
    buf[entries_offset + entry_size : entries_offset + 2 * entry_size] = bytes(e1)

    return bytes(buf)


class TestGetHandles:
    """Real gates for ``get_handles``: not-attached guard and buffer parsing."""

    @pytest.mark.asyncio
    async def test_raises_when_not_attached(self, bridge: X64DbgBridge) -> None:
        """``get_handles`` raises ``ToolError`` when no process is attached.

        Args:
            bridge: Fresh unattached bridge fixture.
        """
        with pytest.raises(ToolError, match="not attached"):
            await bridge.get_handles()

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    def test_parse_handle_buffer_filters_by_pid(self) -> None:
        """``_parse_handle_buffer`` returns only entries matching ``target_pid``.

        Mutation caught: removing the ``if owner_pid != target_pid: continue``
        filter would return both entries, causing the ``len == 1`` assertion
        to fail.
        """
        raw = _build_synthetic_handle_buffer(
            _HANDLE_TARGET_PID,
            handle_value=_HANDLE_VALUE,
            object_addr=_HANDLE_OBJECT,
            granted_access=_HANDLE_GRANTED_ACCESS,
            type_index=_HANDLE_TYPE_INDEX,
            other_pid=_HANDLE_OTHER_PID,
        )
        parse_fn = cast(
            "Callable[[bytes, int], list[dict[str, Any]]]",
            getattr(X64DbgBridge, _PARSE_HANDLE_BUFFER_ATTR),
        )
        result = parse_fn(raw, _HANDLE_TARGET_PID)
        assert len(result) == 1, f"expected 1 entry for pid {_HANDLE_TARGET_PID}, got {len(result)}: {result!r}"
        entry = result[0]
        assert entry["handle"] == hex(_HANDLE_VALUE), f"handle: want {hex(_HANDLE_VALUE)!r}, got {entry['handle']!r}"
        assert entry["granted_access"] == hex(_HANDLE_GRANTED_ACCESS), (
            f"granted_access: want {hex(_HANDLE_GRANTED_ACCESS)!r}, got {entry['granted_access']!r}"
        )
        assert entry["object_type_index"] == _HANDLE_TYPE_INDEX, (
            f"object_type_index: want {_HANDLE_TYPE_INDEX}, got {entry['object_type_index']!r}"
        )

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    def test_parse_handle_buffer_empty_when_no_pid_match(self) -> None:
        """``_parse_handle_buffer`` returns ``[]`` when no entry matches ``target_pid``.

        Mutation caught: removing the PID filter entirely would return
        non-empty results for any PID, causing this assertion to fail.
        """
        raw = _build_synthetic_handle_buffer(
            _HANDLE_TARGET_PID,
            handle_value=_HANDLE_VALUE,
            object_addr=_HANDLE_OBJECT,
            granted_access=_HANDLE_GRANTED_ACCESS,
            type_index=_HANDLE_TYPE_INDEX,
            other_pid=_HANDLE_OTHER_PID,
        )
        parse_fn = cast(
            "Callable[[bytes, int], list[dict[str, Any]]]",
            getattr(X64DbgBridge, _PARSE_HANDLE_BUFFER_ATTR),
        )
        result = parse_fn(raw, _HANDLE_OTHER_PID + 1)
        assert result == [], f"no entry must match pid {_HANDLE_OTHER_PID + 1}, got {result!r}"


# ---------------------------------------------------------------------------
# TestGetPrivileges — new real gate (NO COVERAGE)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestGetPrivileges:
    """Real gates for ``get_privileges``: returned dict shape on a live Windows token."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    async def test_returns_nonempty_list_with_required_keys(self) -> None:
        """Each privilege dict has ``name``, ``enabled``, and ``enabled_by_default`` keys.

        Mutation caught: omitting ``"enabled"`` from the dict literal in
        ``_append_token_privilege`` would cause the ``"enabled" in priv``
        assertion to fail.
        """
        privileges = await X64DbgBridge.get_privileges()
        assert isinstance(privileges, list)
        assert len(privileges) > 0, "at least one privilege must be returned on Windows"
        for priv in privileges:
            assert "name" in priv, f"missing 'name': {priv!r}"
            assert "enabled" in priv, f"missing 'enabled': {priv!r}"
            assert "enabled_by_default" in priv, f"missing 'enabled_by_default': {priv!r}"
            assert isinstance(priv["name"], str), f"'name' must be str: {priv!r}"
            assert isinstance(priv["enabled"], bool), f"'enabled' must be bool: {priv!r}"
            assert isinstance(priv["enabled_by_default"], bool), f"'enabled_by_default' must be bool: {priv!r}"

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    async def test_privilege_names_start_with_se(self) -> None:
        """All privilege names are non-empty strings beginning with ``Se``.

        Mutation caught: if ``LookupPrivilegeNameW`` is never called
        (e.g. the loop body is removed), names would be empty strings
        and the ``startswith("Se")`` assertion would fail.
        """
        privileges = await X64DbgBridge.get_privileges()
        for priv in privileges:
            name = priv.get("name", "")
            assert isinstance(name, str), f"privilege name must be a str, got {type(name).__name__}: {priv!r}"
            assert len(name) > 0, f"privilege name must be non-empty: {priv!r}"
            assert name.startswith("Se"), f"Windows privilege names start with 'Se', got {name!r}"
