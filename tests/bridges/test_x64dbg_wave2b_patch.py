# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Wave 2b patch/anti-debug/import gate tests for ``intellicrack.bridges.x64dbg``.

Covers the following operations with falsifiable assertions against
independent oracles:

- ``patch_instruction``: exact ``assemble`` framing, ``verified=True``
  when memory changes, ``ToolError`` when bytes are unchanged.
- ``nop_range``: exact ``fill`` command framing, ``verified=True`` when all
  NOP bytes, ``ToolError`` on non-NOP residual.
- ``get_patches``: ``patch_list`` command, exact parsed patch records.
- ``restore_patch``: ``patch_restore`` framing and success structure.
- ``export_patches``: ``savedata`` command framing via exec.
- ``detect_anti_debug``: PEB field parsing for ``beingDebugged`` and
  ``NtGlobalFlag``.
- ``read_peb``: real round-trip via fake pipe (replaces FG-1 docstring gate).
- ``get_registers``: ``reg_all`` parsing into ``RegisterState`` (replaces
  FG-3 ToolError-only gate).
- ``set_register``: ``reg_set`` framing (replaces FG-3 ToolError-only gate).
- ``reconstruct_imports``: ``scylla_reconstruct`` framing; script fallback.
- ``get_module_imports``: ``mod_imports`` framing and parsed import records.
- ``find_intermodular_calls``: ``ref_search`` ``type=intermodular`` framing.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, Final, cast

import pytest

from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.core.types import RegisterState, ToolError


if TYPE_CHECKING:
    from collections.abc import Callable


_PATCH_ADDR: Final[int] = 0x401500
_NOP_FILL_ADDR: Final[int] = 0x402000
_NOP_FILL_SIZE: Final[int] = 8
_TARGET_PID: Final[int] = 9999
_OEP: Final[int] = 0x401000
_OUTPUT_PATH: Final[str] = "C:\\dump\\target_fixed.exe"
_EXPORT_PATH: Final[str] = "C:\\patches\\export.txt"
_MODULE_NAME: Final[str] = "target.dll"
_PEB_ADDR_HEX: Final[str] = "0x7ffe0000"
_PEB_BEING_DEBUGGED: Final[int] = 1
_PEB_NT_GLOBAL_FLAG: Final[int] = 0x70
_REG_RAX: Final[int] = 0xDEAD_BEEF
_REG_RBX: Final[int] = 0x0000_0001
_REG_RIP: Final[int] = 0x0040_0000
_IMPORT_IAT_RVA: Final[str] = "0x1234"
_IMPORT_NAME: Final[str] = "CreateFileW"
_PATCH_OLD_BYTE: Final[str] = "0x55"
_PATCH_NEW_BYTE: Final[str] = "0x90"
_NOP_OPCODE: Final[int] = 0x90
_INT3_OPCODE: Final[int] = 0xCC


class _FakePipeClient:
    """In-process replacement for ``NamedPipeClient`` used by wave-2b tests.

    Records every ``(command, params)`` pair sent by the bridge and
    returns scripted responses via a caller-supplied ``responder``.
    """

    def __init__(
        self,
        responder: Callable[[str, dict[str, Any] | None], dict[str, Any]],
    ) -> None:
        """Initialize the fake pipe client with a responder callable.

        Args:
            responder: Callable mapping ``(command, params)`` to the
                full response dict (with ``success``, ``id``, ``result``).
        """
        self._responder = responder
        self.sent: list[tuple[str, dict[str, Any] | None]] = []

    @property
    def is_connected(self) -> bool:
        """Report that the fake client is always connected.

        Returns:
            bool: True unconditionally.
        """
        return True

    async def send_command(
        self,
        command: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Record the request and return the scripted response.

        Args:
            command: RPC command name.
            params: Optional parameters dict.

        Returns:
            dict[str, Any]: The full response dict produced by the responder.
        """
        self.sent.append((command, params))
        return self._responder(command, params)


class _PlaceholderProcess:
    """Sentinel that satisfies ``self._process is not None`` guard checks.

    The ``_send_command`` method requires ``self._process`` to be non-None
    before routing through the pipe.  This sentinel satisfies that check
    without spawning a real x64dbg process.
    """


def _install_fake_pipe(
    bridge: X64DbgBridge,
    responder: Callable[[str, dict[str, Any] | None], dict[str, Any]],
) -> _FakePipeClient:
    """Wire a fake pipe client to ``bridge`` and mark the plugin deployed.

    Sets the bridge's ``_process`` to a sentinel value so guards that
    reject commands when no process is running do not short-circuit, and
    sets ``_plugin_deployed=True`` so ``_send_pipe_command`` does not
    raise the ``plugin_unavailable`` error before reaching the fake client.

    Args:
        bridge: Bridge instance under test.
        responder: Per-command response generator callable.

    Returns:
        _FakePipeClient: The attached fake, for asserting ``sent`` entries.
    """
    fake = _FakePipeClient(responder)
    setattr(bridge, "_pipe_client", fake)
    setattr(bridge, "_plugin_deployed", True)
    setattr(bridge, "_process", _PlaceholderProcess())
    return fake


def _ok(result: object = None) -> dict[str, Any]:
    """Build a minimal successful pipe response with an optional result payload.

    Args:
        result: Optional payload to embed under the ``result`` key.

    Returns:
        dict[str, Any]: Response dict with ``id=1``, ``success=True``,
        and the supplied ``result``.
    """
    return {"id": 1, "success": True, "result": result}


def _unknown(command: str) -> dict[str, Any]:
    """Build a ``Unknown command`` error response for the given command name.

    Causes ``_is_recoverable_pipe_error`` to classify the error as
    recoverable, triggering the script-fallback path in methods that
    support it.

    Args:
        command: Command name to embed in the error text.

    Returns:
        dict[str, Any]: Failure response whose error text matches the
        ``"Unknown command"`` pattern.
    """
    return {"id": 1, "success": False, "error": f"Unknown command '{command}'"}


@pytest.fixture
def bridge() -> X64DbgBridge:
    """Provide a fresh, unattached bridge instance.

    Returns:
        X64DbgBridge: Bridge with no attached PID and no pipe client.
    """
    return X64DbgBridge()


@pytest.mark.asyncio
class TestPatchInstructionFraming:
    """Gate: ``patch_instruction`` emits ``assemble`` with exact address and instruction.

    Falsifiable mutation caught: if ``patch_instruction`` sent ``"patch"`` instead
    of ``"assemble"``, or omitted the ``instruction`` key from params, the framing
    assertion would fail while the existing not-attached gate would still pass.
    """

    async def test_assemble_command_framing_and_unverified_result(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Verify ``assemble`` params and ``verified=False`` when not attached.

        Without an attached PID the bridge cannot read memory back, so
        ``verified=False`` and ``patched_bytes=None`` must be reported.
        The oracle for the command params is the constant ``_PATCH_ADDR``
        and the literal ``"nop"`` string.

        Args:
            bridge: Unattached bridge fixture.
        """

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            del params
            if command == "assemble":
                return _ok()
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        result = await bridge.patch_instruction(_PATCH_ADDR, "nop")

        assert ("assemble", {"address": hex(_PATCH_ADDR), "instruction": "nop"}) in fake.sent
        assert result["success"] is True
        assert result["address"] == hex(_PATCH_ADDR)
        assert result["instruction"] == "nop"
        assert result["verified"] is False
        assert result["patched_bytes"] is None

    async def test_verified_true_when_bytes_change(
        self,
        bridge: X64DbgBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When memory reads differ before and after assemble, ``verified=True``.

        The oracle: ``patched_bytes`` must equal the hex of the second
        ``read_memory`` return value.  Mutating the result field to return
        the first read's bytes would change ``patched_bytes`` and falsify
        this assertion.

        Args:
            bridge: Unattached bridge fixture (PID will be set below).
            monkeypatch: Pytest monkeypatch fixture.
        """
        original_bytes = bytes([_INT3_OPCODE]) + bytes(15)
        patched_bytes = bytes([_NOP_OPCODE]) + bytes(15)
        call_count: list[int] = [0]

        async def fake_read_memory(address: int, size: int) -> bytes:
            del address
            await asyncio.sleep(0)
            call_count[0] += 1
            return original_bytes[:size] if call_count[0] == 1 else patched_bytes[:size]

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            del params
            if command == "assemble":
                return _ok()
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        bridge.attached_pid = _TARGET_PID
        fake = _install_fake_pipe(bridge, responder)
        monkeypatch.setattr(bridge, "read_memory", fake_read_memory)

        result = await bridge.patch_instruction(_PATCH_ADDR, "nop")

        assert result["success"] is True
        assert result["verified"] is True
        assert result["patched_bytes"] == patched_bytes.hex()
        assert ("assemble", {"address": hex(_PATCH_ADDR), "instruction": "nop"}) in fake.sent

    async def test_raises_when_bytes_unchanged(
        self,
        bridge: X64DbgBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``ToolError`` when both reads return identical bytes.

        The oracle: ``assemble`` claimed success but memory is unchanged,
        meaning the patch was silently dropped.  This gate catches a
        regression where ``patch_instruction`` swallowed the unchanged
        check and returned ``success=True`` anyway.

        Args:
            bridge: Unattached bridge fixture (PID will be set below).
            monkeypatch: Pytest monkeypatch fixture.
        """
        frozen_bytes = bytes([_INT3_OPCODE]) + bytes(15)

        async def fake_read_memory_frozen(address: int, size: int) -> bytes:
            del address
            await asyncio.sleep(0)
            return frozen_bytes[:size]

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            del params
            if command == "assemble":
                return _ok()
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        bridge.attached_pid = _TARGET_PID
        _install_fake_pipe(bridge, responder)
        monkeypatch.setattr(bridge, "read_memory", fake_read_memory_frozen)

        with pytest.raises(ToolError, match="patch_instruction verification failed"):
            await bridge.patch_instruction(_PATCH_ADDR, "nop")


@pytest.mark.asyncio
class TestNopRangeFraming:
    """Gate: ``nop_range`` emits ``fill <address>, <size>, 90`` via exec.

    Falsifiable mutation caught: if ``nop_range`` used ``"fill"`` as a
    direct RPC name instead of routing through ``_send_command``/``exec``,
    or if it used ``00`` instead of ``90``, the framing assertion fails.
    """

    async def test_fill_command_framing_not_attached(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Verify the exact ``exec`` command when not attached.

        Without an attached PID the verification read returns ``None``,
        so ``verified=False`` - but the ``fill`` command must still be
        sent with the right address, size, and opcode byte before that.

        Args:
            bridge: Unattached bridge fixture.
        """
        expected_cmd = f"fill {hex(_NOP_FILL_ADDR)}, {_NOP_FILL_SIZE}, 90"

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            del params
            if command == "exec":
                return _ok()
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        result = await bridge.nop_range(_NOP_FILL_ADDR, _NOP_FILL_SIZE)

        assert ("exec", {"command": expected_cmd}) in fake.sent
        assert result["success"] is True
        assert result["address"] == hex(_NOP_FILL_ADDR)
        assert result["size"] == _NOP_FILL_SIZE
        assert result["verified"] is False

    async def test_verified_true_when_all_nop_bytes(
        self,
        bridge: X64DbgBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        r"""When all read-back bytes are 0x90, ``verified=True`` and ``bytes_filled`` is set.

        The oracle: ``read_memory`` returning exactly ``b"\x90" * size``
        must produce ``verified=True`` and ``bytes_filled == size``.  If
        the bridge compared against the wrong opcode, this gate fails.

        Args:
            bridge: Unattached bridge fixture (PID will be set below).
            monkeypatch: Pytest monkeypatch fixture.
        """

        async def fake_read_memory_nop(address: int, size: int) -> bytes:
            del address
            await asyncio.sleep(0)
            return bytes([_NOP_OPCODE]) * size

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            del params
            if command == "exec":
                return _ok()
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        bridge.attached_pid = _TARGET_PID
        _install_fake_pipe(bridge, responder)
        monkeypatch.setattr(bridge, "read_memory", fake_read_memory_nop)

        result = await bridge.nop_range(_NOP_FILL_ADDR, _NOP_FILL_SIZE)

        assert result["success"] is True
        assert result["verified"] is True
        assert result["bytes_filled"] == _NOP_FILL_SIZE

    async def test_raises_when_non_nop_byte_present(
        self,
        bridge: X64DbgBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``ToolError`` when at least one byte in the fill range is not 0x90.

        The oracle: a trailing ``INT3`` (0xCC) byte at position 7 within
        an 8-byte fill means the fill command was silently partial or the
        write did not apply.

        Args:
            bridge: Unattached bridge fixture (PID will be set below).
            monkeypatch: Pytest monkeypatch fixture.
        """
        partial_fill = bytes([_NOP_OPCODE] * (_NOP_FILL_SIZE - 1)) + bytes([_INT3_OPCODE])

        async def fake_read_memory_partial(address: int, size: int) -> bytes:
            del address
            await asyncio.sleep(0)
            return partial_fill[:size]

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            del params
            if command == "exec":
                return _ok()
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        bridge.attached_pid = _TARGET_PID
        _install_fake_pipe(bridge, responder)
        monkeypatch.setattr(bridge, "read_memory", fake_read_memory_partial)

        with pytest.raises(ToolError, match="nop_range verification failed"):
            await bridge.nop_range(_NOP_FILL_ADDR, _NOP_FILL_SIZE)


@pytest.mark.asyncio
class TestGetPatches:
    """Gate: ``get_patches`` issues ``patch_list`` and parses each record.

    Falsifiable mutation caught: if ``get_patches`` read from a wrong RPC
    name (``"patches"`` vs ``"patch_list"``), the fake pipe would raise
    ``AssertionError`` for the unexpected command, catching the regression.
    If the parsing dropped the ``address`` key, the field assertion fails.
    """

    async def test_sends_patch_list_and_returns_parsed_records(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """``patch_list`` RPC is sent and each field is parsed into the result list.

        The oracle: canned ``address``, ``oldByte``, ``newByte`` values
        that the production code must have read from the RPC result, not
        computed itself.

        Args:
            bridge: Unattached bridge fixture.
        """
        canned_patches: list[dict[str, object]] = [
            {"address": hex(_PATCH_ADDR), "oldByte": _PATCH_OLD_BYTE, "newByte": _PATCH_NEW_BYTE},
        ]

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            del params
            if command == "patch_list":
                return _ok(canned_patches)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        patches = await bridge.get_patches()

        assert ("patch_list", None) in fake.sent
        assert len(patches) == 1
        entry = patches[0]
        assert entry["address"] == hex(_PATCH_ADDR)
        assert entry["oldByte"] == _PATCH_OLD_BYTE
        assert entry["newByte"] == _PATCH_NEW_BYTE

    async def test_returns_empty_list_when_no_patches(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Empty ``patch_list`` result produces an empty Python list.

        Args:
            bridge: Unattached bridge fixture.
        """

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            del params
            if command == "patch_list":
                return _ok([])
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        patches = await bridge.get_patches()

        assert patches == []

    async def test_returns_empty_list_when_result_is_not_list(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """A non-list ``patch_list`` result is normalised to an empty list.

        Falsifiable: if ``get_patches`` returned the raw dict instead of
        converting a non-list to ``[]``, ``patches == []`` would fail.

        Args:
            bridge: Unattached bridge fixture.
        """

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            del params
            if command == "patch_list":
                return _ok({"unexpected": "dict"})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        patches = await bridge.get_patches()

        assert patches == []


@pytest.mark.asyncio
class TestRestorePatch:
    """Gate: ``restore_patch`` issues ``patch_restore`` with the correct address.

    Falsifiable mutation caught: if ``restore_patch`` passed ``address``
    as a decimal string instead of ``hex(address)``, the params assertion
    fails while the existing no-coverage baseline left no gate at all.
    """

    async def test_sends_patch_restore_with_hex_address(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """``patch_restore`` is sent with ``{"address": hex(address)}``.

        The oracle: ``hex(_PATCH_ADDR)`` is the independent expected value;
        the production code must produce this exact string, not a decimal.

        Args:
            bridge: Unattached bridge fixture.
        """

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            del params
            if command == "patch_restore":
                return _ok()
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        result = await bridge.restore_patch(_PATCH_ADDR)

        assert ("patch_restore", {"address": hex(_PATCH_ADDR)}) in fake.sent
        assert result["success"] is True
        assert result["address"] == hex(_PATCH_ADDR)

    async def test_result_keys_include_success_and_address(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Return dict contains at least ``success`` and ``address`` keys.

        Args:
            bridge: Unattached bridge fixture.
        """

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            del params
            if command == "patch_restore":
                return _ok()
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.restore_patch(_PATCH_ADDR)

        assert "success" in result
        assert "address" in result
        assert result["success"] is True
        assert result["address"] == hex(_PATCH_ADDR)


@pytest.mark.asyncio
class TestExportPatches:
    """Gate: ``export_patches`` routes through ``exec`` with a quoted path.

    Falsifiable mutation caught: if ``export_patches`` sent ``savedata path``
    without quotes, or used a different command name, the exact-command
    assertion fails while the baseline had zero coverage.
    """

    async def test_sends_savedata_command_with_quoted_path(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """``exec`` is sent with ``savedata "<path>"`` including quotes.

        The oracle: the path string in ``_EXPORT_PATH`` wrapped in
        double-quotes is the expected command text.

        Args:
            bridge: Unattached bridge fixture.
        """
        expected_cmd = f'savedata "{_EXPORT_PATH}"'

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            del params
            if command == "exec":
                return _ok()
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        result = await bridge.export_patches(_EXPORT_PATH)

        assert ("exec", {"command": expected_cmd}) in fake.sent
        assert result["success"] is True
        assert result["path"] == _EXPORT_PATH

    async def test_result_path_matches_input(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """The returned ``path`` field echoes the caller-supplied path verbatim.

        Args:
            bridge: Unattached bridge fixture.
        """

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            del params
            if command == "exec":
                return _ok()
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.export_patches(_EXPORT_PATH)

        assert result["path"] == _EXPORT_PATH


@pytest.mark.asyncio
class TestReadPebRoundTrip:
    """Gate: ``read_peb`` issues ``peb_read`` and returns the result dict verbatim.

    Replaces the FG-1 gate that only checked a docstring substring for
    ``"address"`` without ever calling the method.  Falsifiable mutation
    caught: returning an empty dict instead of the parsed result, or
    reading from the wrong RPC name.
    """

    async def test_peb_read_rpc_sent_and_fields_returned(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """``peb_read`` is issued and all canned fields appear in the return dict.

        The oracle: each field value in ``canned_peb`` is derived from
        the independent test constants, not from re-running ``read_peb``.

        Args:
            bridge: Unattached bridge fixture.
        """
        canned_peb: dict[str, object] = {
            "address": _PEB_ADDR_HEX,
            "beingDebugged": _PEB_BEING_DEBUGGED,
            "ntGlobalFlag": _PEB_NT_GLOBAL_FLAG,
            "imageBaseAddress": "0x400000",
            "processParameters": "0x20000",
        }

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            del params
            if command == "peb_read":
                return _ok(canned_peb)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        result = await bridge.read_peb()

        assert ("peb_read", None) in fake.sent
        assert result["address"] == _PEB_ADDR_HEX
        assert result["beingDebugged"] == _PEB_BEING_DEBUGGED
        assert result["ntGlobalFlag"] == _PEB_NT_GLOBAL_FLAG
        assert result["imageBaseAddress"] == "0x400000"
        assert result["processParameters"] == "0x20000"

    async def test_returns_empty_dict_on_recoverable_error(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Recoverable ``peb_read`` errors surface as an empty dict, not raised.

        Args:
            bridge: Unattached bridge fixture.
        """

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            del params
            if command == "peb_read":
                return _unknown("peb_read")
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.read_peb()

        assert result == {}

    async def test_raises_on_non_recoverable_pipe_error(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Non-recoverable pipe errors propagate as ``ToolError``.

        Args:
            bridge: Unattached bridge fixture.
        """

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            del params
            if command == "peb_read":
                return {"id": 1, "success": False, "error": "Pipe not connected"}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        with pytest.raises(ToolError, match="Pipe not connected"):
            await bridge.read_peb()


@pytest.mark.asyncio
class TestDetectAntiDebug:
    """Gate: ``detect_anti_debug`` parses PEB fields into per-check boolean flags.

    Replaces the NO-COVERAGE baseline.  Falsifiable mutations caught:
    reading ``"being_debugged"`` instead of ``"beingDebugged"``, applying
    the wrong mask (``0xFF`` vs ``0x70``), or inverting the bool conversion.
    """

    async def test_being_debugged_flag_set(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """``beingDebugged=1`` produces ``peb_being_debugged=True``.

        The oracle: the integer ``1`` from the PEB must become the Python
        bool ``True`` via ``bool(being_debugged)``.

        Args:
            bridge: Unattached bridge fixture.
        """
        canned_peb: dict[str, object] = {
            "address": _PEB_ADDR_HEX,
            "beingDebugged": 1,
            "ntGlobalFlag": 0,
        }

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            del params
            if command == "peb_read":
                return _ok(canned_peb)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.detect_anti_debug()

        assert result["success"] is True
        assert result["checks"]["peb_being_debugged"] is True
        assert result["checks"].get("nt_global_flag_set") is False

    async def test_nt_global_flag_mask_detected(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """``ntGlobalFlag=0x70`` produces ``nt_global_flag_set=True`` (mask 0x70).

        The oracle: ``(0x70 & 0x70) != 0`` is ``True``.  If the mask
        were wrong (e.g. ``0xFF00``), ``0x70 & 0xFF00 == 0`` and the
        assertion would fail.

        Args:
            bridge: Unattached bridge fixture.
        """
        canned_peb: dict[str, object] = {
            "address": _PEB_ADDR_HEX,
            "beingDebugged": 0,
            "ntGlobalFlag": 0x70,
        }

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            del params
            if command == "peb_read":
                return _ok(canned_peb)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.detect_anti_debug()

        assert result["success"] is True
        assert result["checks"]["peb_being_debugged"] is False
        assert result["checks"]["nt_global_flag_set"] is True

    async def test_neither_flag_set_when_peb_clean(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Both flags are ``False`` when PEB fields are zero.

        Args:
            bridge: Unattached bridge fixture.
        """
        canned_peb: dict[str, object] = {
            "address": _PEB_ADDR_HEX,
            "beingDebugged": 0,
            "ntGlobalFlag": 0,
        }

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            del params
            if command == "peb_read":
                return _ok(canned_peb)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.detect_anti_debug()

        assert result["checks"]["peb_being_debugged"] is False
        assert result["checks"]["nt_global_flag_set"] is False

    async def test_peb_dict_returned_alongside_checks(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """The full PEB dict is embedded in the result under ``"peb"``.

        Args:
            bridge: Unattached bridge fixture.
        """
        canned_peb: dict[str, object] = {
            "address": _PEB_ADDR_HEX,
            "beingDebugged": 1,
            "ntGlobalFlag": 0x70,
        }

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            del params
            if command == "peb_read":
                return _ok(canned_peb)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.detect_anti_debug()

        assert "peb" in result
        assert result["peb"]["address"] == _PEB_ADDR_HEX


@pytest.mark.asyncio
class TestGetRegisters:
    """Gate: ``get_registers`` issues ``reg_all`` and parses into ``RegisterState``.

    Replaces the FG-3 gate that only tested the no-plugin ``ToolError`` path.
    Falsifiable mutations caught: reading from the wrong response key (e.g.
    ``"RAX"`` vs ``"rax"``), not falling back to 32-bit aliases, or
    collapsing all fields to ``0`` silently.
    """

    async def test_reg_all_parsed_into_register_state(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """``reg_all`` response is parsed into exact ``RegisterState`` field values.

        The oracle: ``_REG_RAX`` and ``_REG_RBX`` are test constants;
        the bridge must extract them from the ``"rax"`` / ``"rbx"`` keys,
        not recompute them.

        Args:
            bridge: Unattached bridge fixture.
        """
        canned_regs: dict[str, object] = {
            "rax": hex(_REG_RAX),
            "rbx": hex(_REG_RBX),
            "rcx": 0,
            "rdx": 0,
            "rsi": 0,
            "rdi": 0,
            "rbp": 0,
            "rsp": 0,
            "rip": hex(_REG_RIP),
            "r8": 0,
            "r9": 0,
            "r10": 0,
            "r11": 0,
            "r12": 0,
            "r13": 0,
            "r14": 0,
            "r15": 0,
            "rflags": 0,
            "cs": 0,
            "ds": 0,
            "es": 0,
            "fs": 0,
            "gs": 0,
            "ss": 0,
        }

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            del params
            if command == "reg_all":
                return _ok(canned_regs)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        state = await bridge.get_registers()

        assert ("reg_all", None) in fake.sent
        assert isinstance(state, RegisterState)
        assert state.rax == _REG_RAX
        assert state.rbx == _REG_RBX
        assert state.rip == _REG_RIP

    async def test_32bit_alias_eax_falls_back_when_rax_absent(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """When ``"rax"`` is absent, the bridge falls back to ``"eax"``.

        Falsifiable: removing the fallback logic in ``get_reg`` would
        make ``state.rax`` return ``0`` instead of ``_REG_RAX``.

        Args:
            bridge: Unattached bridge fixture.
        """
        canned_regs: dict[str, object] = {
            "eax": hex(_REG_RAX),
            "ebx": hex(_REG_RBX),
            "ecx": 0,
            "edx": 0,
            "esi": 0,
            "edi": 0,
            "ebp": 0,
            "esp": 0,
            "eip": hex(_REG_RIP),
            "eflags": 0,
            "cs": 0,
            "ds": 0,
            "es": 0,
            "fs": 0,
            "gs": 0,
            "ss": 0,
        }

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            del params
            if command == "reg_all":
                return _ok(canned_regs)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        state = await bridge.get_registers()

        assert state.rax == _REG_RAX
        assert state.rbx == _REG_RBX
        assert state.rip == _REG_RIP

    async def test_non_dict_response_raises_tool_error(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """A non-dict ``reg_all`` response raises ``ToolError``.

        Falsifiable: if ``get_registers`` silently returned a zeroed
        ``RegisterState`` instead of raising, this gate would fail.

        Args:
            bridge: Unattached bridge fixture.
        """

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            del params
            if command == "reg_all":
                return _ok(["not", "a", "dict"])
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        with pytest.raises(ToolError, match="Invalid register response"):
            await bridge.get_registers()


@pytest.mark.asyncio
class TestSetRegister:
    """Gate: ``set_register`` issues ``reg_set`` with exact params.

    Replaces the FG-3 gate that only tested the no-plugin ``ToolError`` path.
    Falsifiable mutations caught: sending the register name under the wrong
    key (``"name"`` vs ``"register"``), or omitting the ``value`` field.
    """

    async def test_reg_set_framing_and_returns_true(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """``reg_set`` is sent with ``register`` and ``value`` keys and returns ``True``.

        The oracle: the production code must use ``"register"`` as the
        parameter key (not ``"name"`` or ``"reg_name"``).

        Args:
            bridge: Unattached bridge fixture.
        """

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            del params
            if command == "reg_set":
                return _ok()
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        result = await bridge.set_register("rax", _REG_RAX)

        assert ("reg_set", {"register": "rax", "value": _REG_RAX}) in fake.sent
        assert result is True

    async def test_different_register_name_and_value(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """``reg_set`` framing is correct for a different register and value.

        Args:
            bridge: Unattached bridge fixture.
        """

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            del params
            if command == "reg_set":
                return _ok()
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        result = await bridge.set_register("rcx", 0)

        assert ("reg_set", {"register": "rcx", "value": 0}) in fake.sent
        assert result is True


@pytest.mark.asyncio
class TestReconstructImports:
    """Gate: ``reconstruct_imports`` issues ``scylla_reconstruct`` with OEP and path.

    Replaces the NO-COVERAGE baseline.  Falsifiable mutations caught: using
    a decimal OEP string instead of ``hex(oep)``, omitting ``output_path``
    from the RPC params, or never falling back to script commands when the
    RPC is unavailable.
    """

    async def test_scylla_reconstruct_rpc_framing(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """``scylla_reconstruct`` is sent with ``oep`` (hex) and ``output_path``.

        The oracle: ``hex(_OEP)`` is the expected OEP string.  A decimal
        string would falsify this assertion.

        Args:
            bridge: Unattached bridge fixture.
        """

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            del params
            if command == "scylla_reconstruct":
                return _ok({"iat_found": True, "imports_fixed": 42})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        result = await bridge.reconstruct_imports(_OEP, _OUTPUT_PATH)

        expected_params = {"oep": hex(_OEP), "output_path": _OUTPUT_PATH}
        assert ("scylla_reconstruct", expected_params) in fake.sent
        assert result["success"] is True
        assert result["oep"] == hex(_OEP)
        assert result["output_path"] == _OUTPUT_PATH

    async def test_rpc_result_dict_embedded_in_details(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """When the RPC returns extra data, it appears under ``"details"``.

        Args:
            bridge: Unattached bridge fixture.
        """
        extra: dict[str, object] = {"iat_found": True, "imports_fixed": 7}

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            del params
            if command == "scylla_reconstruct":
                return _ok(extra)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.reconstruct_imports(_OEP, _OUTPUT_PATH)

        assert "details" in result
        assert result["details"]["imports_fixed"] == 7

    async def test_fallback_sends_three_script_commands(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Unknown-RPC triggers the three stepwise ``scylla.*`` script commands.

        Falsifiable: removing one of the three fallback ``_send_command``
        calls means the corresponding ``exec`` entry is absent from ``sent``,
        failing the in-list assertion.

        Args:
            bridge: Unattached bridge fixture.
        """
        exec_commands: list[str] = []

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "scylla_reconstruct":
                return _unknown("scylla_reconstruct")
            if command == "exec":
                if params is not None:
                    cmd = cast("str", params.get("command", ""))
                    exec_commands.append(cmd)
                return _ok()
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.reconstruct_imports(_OEP, _OUTPUT_PATH)

        assert result["success"] is True
        assert result["oep"] == hex(_OEP)
        assert result["output_path"] == _OUTPUT_PATH
        assert any(f"scylla.searchIAT {hex(_OEP)}" in cmd for cmd in exec_commands)
        assert any("scylla.autoFix" in cmd for cmd in exec_commands)
        assert any(f'scylla.dump "{_OUTPUT_PATH}"' in cmd for cmd in exec_commands)


@pytest.mark.asyncio
class TestGetModuleImports:
    """Gate: ``get_module_imports`` issues ``mod_imports`` with the module name.

    Replaces the NO-COVERAGE baseline.  Falsifiable mutations caught: using
    a different param key (``"module"`` vs ``"name"``), or not parsing each
    import entry into a dict from the list.
    """

    async def test_sends_mod_imports_with_name_and_parses_result(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """``mod_imports`` is sent with ``{"name": module_name}`` and entries parsed.

        The oracle: ``_IMPORT_IAT_RVA`` and ``_IMPORT_NAME`` are test
        constants; the production code must copy them from the RPC
        result, not generate them.

        Args:
            bridge: Unattached bridge fixture.
        """
        canned_imports: list[dict[str, object]] = [
            {"iatRva": _IMPORT_IAT_RVA, "name": _IMPORT_NAME, "ordinal": 0},
        ]

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            del params
            if command == "mod_imports":
                return _ok(canned_imports)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        imports = await bridge.get_module_imports(_MODULE_NAME)

        assert ("mod_imports", {"name": _MODULE_NAME}) in fake.sent
        assert len(imports) == 1
        entry = imports[0]
        assert entry["iatRva"] == _IMPORT_IAT_RVA
        assert entry["name"] == _IMPORT_NAME
        assert entry["ordinal"] == 0

    async def test_returns_empty_list_when_result_is_not_list(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """A non-list ``mod_imports`` result is normalised to an empty list.

        Args:
            bridge: Unattached bridge fixture.
        """

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            del params
            if command == "mod_imports":
                return _ok()
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        imports = await bridge.get_module_imports(_MODULE_NAME)

        assert imports == []


@pytest.mark.asyncio
class TestFindIntermodularCalls:
    """Gate: ``find_intermodular_calls`` issues ``ref_search`` with ``type=intermodular``.

    Replaces the NO-COVERAGE baseline.  Falsifiable mutations caught: using
    ``"type": "cross_module"`` instead of ``"intermodular"``, or using the
    wrong param key for the module name.
    """

    async def test_ref_search_framing_and_references_returned(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """``ref_search`` is sent with ``module`` and ``type=intermodular``.

        The oracle: the canned reference dict must come from the RPC
        result, not from the production code.

        Args:
            bridge: Unattached bridge fixture.
        """
        canned_refs: list[dict[str, object]] = [
            {"from": hex(_PATCH_ADDR), "to": "0x70001234"},
        ]

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            del params
            if command == "ref_search":
                return _ok(canned_refs)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        result = await bridge.find_intermodular_calls(_MODULE_NAME)

        expected_params = {"module": _MODULE_NAME, "type": "intermodular"}
        assert ("ref_search", expected_params) in fake.sent
        assert result["success"] is True
        assert result["module"] == _MODULE_NAME
        assert len(result["references"]) == 1
        assert result["references"][0]["from"] == hex(_PATCH_ADDR)

    async def test_empty_references_when_none_found(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """An empty ``ref_search`` result produces an empty ``references`` list.

        Args:
            bridge: Unattached bridge fixture.
        """

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            del params
            if command == "ref_search":
                return _ok([])
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.find_intermodular_calls(_MODULE_NAME)

        assert result["references"] == []
        assert result["success"] is True

    async def test_non_list_result_normalised_to_empty(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """A non-list ``ref_search`` result is treated as no references found.

        Args:
            bridge: Unattached bridge fixture.
        """

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            del params
            if command == "ref_search":
                return _ok({"unexpected": "dict"})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.find_intermodular_calls(_MODULE_NAME)

        assert result["references"] == []
