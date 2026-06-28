# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real falsifiable test gates for the CutterBridge operations still open after wave-2a.

Covers the 9 CutterBridge operations identified as NOT_RESOLVED in
audit/verification/group-02-report.md (STILL OPEN § CutterBridge):

- decompile(address)           — pdc / pdg command dispatch + C-code content
- search_crypto_constants()    — /cj command + parsed result structure
- search_magic()               — /mj command + parsed result structure
- search_value(value, size)    — /vj{size} {value} size dispatch
- compare_bytes(hex_data, address) — c {hex} @ {addr} command + result text
- compare_disassembly(file_path, address) — cD + cCj two-command join
- get_segments()               — iSSj command + SegmentInfo field mapping
- hexdump_words(address, length)   — pxw command (distinct from px)
- disassemble_function(address)    — pdf @ {addr} command + mnemonic content

Every test drives the REAL bridge method through the _CommandRecorder fake
transport.  Each gate asserts BOTH the exact rizin command string the bridge
emits AND the exact parsed return value derived from an independently-specified
oracle response.  Mutating a command verb or a response parser causes the gate
to fail.
"""

from __future__ import annotations

import json
from typing import Final, cast

import pytest
import r2pipe

from intellicrack.bridges.cutter import CutterBridge
from intellicrack.core.types import SegmentInfo, ToolError


_ADDR: Final[int] = 0x1000
_ATTR_ANALYZED: Final[str] = "_analyzed"


class _CommandRecorder:
    """r2pipe stand-in that records issued commands and returns configurable responses.

    Attributes:
        commands: Ordered list of every command string passed to ``cmd()``.
        responses: Mapping of command prefix to the pre-configured string
            response returned when a command starts with that prefix.
    """

    commands: list[str]
    responses: dict[str, str]

    def __init__(self, responses: dict[str, str] | None = None) -> None:
        """Initialise the recorder with optional pre-configured responses.

        Args:
            responses: Mapping of command prefix to response string.  Falls
                back to an empty string when no configured prefix matches.
        """
        self.commands = []
        self.responses = responses or {}

    def cmd(self, command: str) -> str:
        """Record ``command`` and return the matching pre-configured response.

        Args:
            command: Rizin command string issued by the bridge.

        Returns:
            str: Pre-configured response for the longest matching prefix, or
            an empty string when no configured prefix matches.
        """
        self.commands.append(command)
        for prefix, response in self.responses.items():
            if command == prefix or command.startswith(prefix):
                return response
        return ""

    def quit(self) -> None:
        """No-op quit matching the r2pipe.open interface."""


def _as_r2pipe(recorder: _CommandRecorder) -> r2pipe.open:
    """Cast ``_CommandRecorder`` to ``r2pipe.open`` for the bridge's type-checked setter.

    Args:
        recorder: Fake r2pipe session implementing ``cmd`` and ``quit``.

    Returns:
        r2pipe.open: The same instance typed as ``r2pipe.open``.
    """
    return cast(r2pipe.open, recorder)


def _set_analyzed(bridge: CutterBridge) -> None:
    """Force the bridge into the post-analysis state without running a real analysis.

    Args:
        bridge: CutterBridge instance to mutate.
    """
    setattr(bridge, _ATTR_ANALYZED, True)


class TestDecompile:
    """Gate decompile: verify pdc command, C-code content, and pdg fallback."""

    @pytest.mark.asyncio
    async def test_pdc_command_issued_and_c_token_in_result(self) -> None:
        """Decompile must seek to address, issue pdc, and return the response text.

        Independent oracle: the recorder is pre-loaded to return a known C
        pseudocode snippet for the ``pdc`` command.  The bridge must:
        (a) emit ``s 0x1000`` to seek, (b) emit ``pdc`` to decompile, and
        (c) return the text unmodified so that ``"int main"`` is present.

        Mutation caught: swapping ``pdc`` for ``pdf`` in the decompile body
        would emit the wrong command and the ``pdc`` assertion would fail.
        """
        c_code: str = "int main(int argc, char **argv) {\n  return 0;\n}"
        rec = _CommandRecorder({f"s {_ADDR}": "", "pdc": c_code})
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        _set_analyzed(bridge)
        result = await bridge.decompile(_ADDR)
        assert f"s {_ADDR}" in rec.commands
        assert "pdc" in rec.commands
        assert "int main" in result
        assert "return 0" in result

    @pytest.mark.asyncio
    async def test_pdg_fallback_when_pdc_returns_cannot(self) -> None:
        """Decompile falls back to pdg when pdc returns a "Cannot" error.

        Oracle: recorder returns "Cannot decompile" for ``pdc`` and a known
        C snippet for ``pdg``.  The bridge must issue both commands and return
        the pdg result.

        Mutation caught: removing the fallback branch so pdg is never called
        would raise ToolError instead of returning the pdg text, failing the
        assertion on the result and on the presence of ``pdg`` in commands.
        """
        pdg_code: str = "void func_0x1000(void) {\n  local_8 = 0;\n}"
        rec = _CommandRecorder({f"s {_ADDR}": "", "pdc": "Cannot decompile", "pdg": pdg_code})
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        _set_analyzed(bridge)
        result = await bridge.decompile(_ADDR)
        assert "pdg" in rec.commands
        assert "void func_0x1000" in result

    @pytest.mark.asyncio
    async def test_raises_when_no_binary(self) -> None:
        """Decompile raises ToolError when no r2 session is open."""
        bridge = CutterBridge()
        with pytest.raises(ToolError, match="no binary"):
            await bridge.decompile(_ADDR)

    @pytest.mark.asyncio
    async def test_raises_when_not_analyzed(self) -> None:
        """Decompile raises ToolError when r2 is open but analysis has not run."""
        rec = _CommandRecorder()
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        with pytest.raises(ToolError, match="not analyzed"):
            await bridge.decompile(_ADDR)

    @pytest.mark.asyncio
    async def test_raises_when_both_commands_fail(self) -> None:
        """Decompile raises ToolError when both pdc and pdg return Cannot responses."""
        rec = _CommandRecorder({f"s {_ADDR}": "", "pdc": "Cannot decompile at 0x1000", "pdg": "Cannot find function"})
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        _set_analyzed(bridge)
        with pytest.raises(ToolError, match="decompilation not available"):
            await bridge.decompile(_ADDR)


class TestSearchCryptoConstants:
    """Gate search_crypto_constants: verify /cj command and parsed result structure."""

    @pytest.mark.asyncio
    async def test_cj_command_issued_and_result_parsed(self) -> None:
        """search_crypto_constants must issue "/cj" and return the parsed JSON list.

        Independent oracle: the recorder returns a JSON list containing one
        entry with known ``offset`` and ``name`` values.  The bridge must:
        (a) emit exactly ``/cj``, and (b) return a list whose first element
        has those exact field values.

        Mutation caught: emitting ``/c`` instead of ``/cj`` would return text
        rather than JSON and raise a parse error, failing the command assertion.
        """
        oracle_offset: int = 4096
        oracle_name: str = "AES_SBOX"
        payload: str = json.dumps([{"offset": oracle_offset, "name": oracle_name, "bits": 128}])
        rec = _CommandRecorder({"/cj": payload})
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.search_crypto_constants()
        assert "/cj" in rec.commands
        assert len(result) == 1
        assert result[0]["offset"] == oracle_offset
        assert result[0]["name"] == oracle_name

    @pytest.mark.asyncio
    async def test_empty_response_yields_empty_list(self) -> None:
        """search_crypto_constants returns [] when rizin finds no crypto constants."""
        rec = _CommandRecorder({"/cj": ""})
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.search_crypto_constants()
        assert result == []

    @pytest.mark.asyncio
    async def test_multiple_entries_all_returned(self) -> None:
        """search_crypto_constants returns all entries from the JSON array.

        Oracle: two distinct crypto-constant entries with different names.
        Mutation caught: returning only the first entry would fail len == 2.
        """
        entries: list[dict[str, object]] = [
            {"offset": 0x1000, "name": "AES_SBOX"},
            {"offset": 0x2000, "name": "SHA256_K"},
        ]
        rec = _CommandRecorder({"/cj": json.dumps(entries)})
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.search_crypto_constants()
        assert len(result) == 2
        assert result[1]["name"] == "SHA256_K"
        assert result[1]["offset"] == 0x2000

    @pytest.mark.asyncio
    async def test_raises_without_binary(self) -> None:
        """search_crypto_constants raises ToolError when no r2 session is open."""
        bridge = CutterBridge()
        with pytest.raises(ToolError, match="no binary"):
            await bridge.search_crypto_constants()


class TestSearchMagic:
    """Gate search_magic: verify /mj command and parsed magic match structure."""

    @pytest.mark.asyncio
    async def test_mj_command_issued_and_result_parsed(self) -> None:
        """search_magic must issue "/mj" and return the parsed JSON list.

        Independent oracle: the recorder returns a JSON list with one magic
        match containing known ``offset`` and ``magic`` values.  The bridge
        must emit exactly ``/mj`` and return the parsed list.

        Mutation caught: emitting ``/m`` instead of ``/mj`` changes the rizin
        output format from JSON to text, causing a parse error — the command
        assertion also fails directly.
        """
        oracle_offset: int = 0x0
        oracle_magic: str = "PE EXE"
        payload: str = json.dumps([{"offset": oracle_offset, "magic": oracle_magic}])
        rec = _CommandRecorder({"/mj": payload})
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.search_magic()
        assert "/mj" in rec.commands
        assert len(result) == 1
        assert result[0]["offset"] == oracle_offset
        assert result[0]["magic"] == oracle_magic

    @pytest.mark.asyncio
    async def test_empty_response_yields_empty_list(self) -> None:
        """search_magic returns [] when rizin finds no magic signatures."""
        rec = _CommandRecorder({"/mj": ""})
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.search_magic()
        assert result == []

    @pytest.mark.asyncio
    async def test_raises_without_binary(self) -> None:
        """search_magic raises ToolError when no r2 session is open."""
        bridge = CutterBridge()
        with pytest.raises(ToolError, match="no binary"):
            await bridge.search_magic()


class TestSearchValue:
    """Gate search_value: verify /vj{size} dispatch and address list parsing."""

    @pytest.mark.asyncio
    async def test_default_size4_command_exact_form(self) -> None:
        r"""search_value with size=4 must emit "/vj4 <value>" and parse address list.

        Independent oracle: the value 0xDEADBEEF searched at size 4 must
        produce the command ``/vj4 3735928559`` (decimal representation of the
        value).  The recorder returns a JSON list with one offset entry.

        Mutation caught: emitting ``/vj 3735928559`` (without size digit) would
        not be a valid size-specific search — the command assertion fails.
        """
        value: int = 0xDEADBEEF
        oracle_addr: int = 0x4000
        payload: str = json.dumps([{"offset": oracle_addr}])
        rec = _CommandRecorder({f"/vj4 {value}": payload})
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.search_value(value)
        assert f"/vj4 {value}" in rec.commands
        assert result == [oracle_addr]

    @pytest.mark.asyncio
    async def test_size1_command_uses_vj1(self) -> None:
        """search_value with size=1 must emit "/vj1 <value>".

        Mutation caught: always emitting ``/vj4`` regardless of ``size``
        would fail the ``/vj1`` command assertion.
        """
        value: int = 0xFF
        oracle_addr: int = 0x100
        payload: str = json.dumps([{"offset": oracle_addr}])
        rec = _CommandRecorder({f"/vj1 {value}": payload})
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.search_value(value, size=1)
        assert f"/vj1 {value}" in rec.commands
        assert result == [oracle_addr]

    @pytest.mark.asyncio
    async def test_size2_command_uses_vj2(self) -> None:
        """search_value with size=2 must emit "/vj2 <value>".

        Mutation caught: always emitting ``/vj4`` regardless of ``size``
        would fail the ``/vj2`` command assertion.
        """
        value: int = 0x1234
        oracle_addr: int = 0x200
        payload: str = json.dumps([{"offset": oracle_addr}])
        rec = _CommandRecorder({f"/vj2 {value}": payload})
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.search_value(value, size=2)
        assert f"/vj2 {value}" in rec.commands
        assert result == [oracle_addr]

    @pytest.mark.asyncio
    async def test_size8_command_uses_vj8(self) -> None:
        """search_value with size=8 must emit "/vj8 <value>".

        Mutation caught: always emitting ``/vj4`` regardless of ``size``
        would fail the ``/vj8`` command assertion.
        """
        value: int = 0x0102030405060708
        oracle_addr: int = 0x8000
        payload: str = json.dumps([{"offset": oracle_addr}])
        rec = _CommandRecorder({f"/vj8 {value}": payload})
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.search_value(value, size=8)
        assert f"/vj8 {value}" in rec.commands
        assert result == [oracle_addr]

    @pytest.mark.asyncio
    async def test_multiple_addresses_all_returned(self) -> None:
        """search_value returns all addresses from the JSON array.

        Oracle: two distinct offset entries.  Mutation caught: returning only
        the first would fail len == 2.
        """
        value: int = 0x90909090
        addrs: list[int] = [0x1000, 0x2000]
        payload: str = json.dumps([{"offset": a} for a in addrs])
        rec = _CommandRecorder({f"/vj4 {value}": payload})
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.search_value(value)
        assert result == addrs

    @pytest.mark.asyncio
    async def test_empty_response_yields_empty_list(self) -> None:
        """search_value returns [] when rizin finds no matches."""
        rec = _CommandRecorder({f"/vj4 {0x1234}": ""})
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.search_value(0x1234)
        assert result == []

    @pytest.mark.asyncio
    async def test_raises_without_binary(self) -> None:
        """search_value raises ToolError when no r2 session is open."""
        bridge = CutterBridge()
        with pytest.raises(ToolError, match="no binary"):
            await bridge.search_value(0xDEAD)


class TestCompareBytes:
    """Gate compare_bytes: verify "c {hex} @ {addr}" command and result text."""

    @pytest.mark.asyncio
    async def test_command_exact_form_and_result_text(self) -> None:
        """compare_bytes must emit "c {hex_data} @ {address}" and return the text.

        Independent oracle: the recorder is pre-loaded to return a known diff
        string for the ``c`` command.  The bridge must emit the command with the
        correct hex data and address operands, and return the result verbatim.

        Mutation caught: omitting ``@ {address}`` from the command string would
        produce a different command that does not match the recorder prefix,
        returning empty string and failing the text assertion.
        """
        hex_data: str = "deadbeef"
        address: int = 0x2000
        oracle_text: str = "0x00002000  de ad be ef                                 ...."
        rec = _CommandRecorder({f"c {hex_data} @ {address}": oracle_text})
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.compare_bytes(hex_data, address)
        assert f"c {hex_data} @ {address}" in rec.commands
        assert result == oracle_text

    @pytest.mark.asyncio
    async def test_empty_response_returned_as_empty_string(self) -> None:
        """compare_bytes returns an empty string when rizin produces no diff."""
        rec = _CommandRecorder({f"c aabb @ {_ADDR}": ""})
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.compare_bytes("aabb", _ADDR)
        assert not result

    @pytest.mark.asyncio
    async def test_raises_without_binary(self) -> None:
        """compare_bytes raises ToolError when no r2 session is open."""
        bridge = CutterBridge()
        with pytest.raises(ToolError, match="no binary"):
            await bridge.compare_bytes("deadbeef", _ADDR)


class TestCompareDisassembly:
    """Gate compare_disassembly: verify cD + cCj two-command join logic."""

    @pytest.mark.asyncio
    async def test_both_commands_issued_in_order_and_result_joined(self) -> None:
        """compare_disassembly must issue cD then cCj, and join non-empty outputs.

        Independent oracle: the recorder returns a known textual diff for
        ``cD`` and a known JSON diff for ``cCj``.  The bridge must:
        (a) emit both commands, (b) join the two non-empty responses with a
        newline, producing a result that contains both substrings.

        Mutation caught: issuing only ``cD`` and not ``cCj`` would produce a
        result with only the first section, failing the assertion on the JSON
        block being present.
        """
        file_path: str = r"C:\target\other.exe"
        address: int = 0x3000
        text_diff: str = "- push rbp\n+ push rbx"
        json_diff: str = '[{"addr":12288,"diff":"changed"}]'
        rec = _CommandRecorder(
            {
                f"cD {file_path} @ {address}": text_diff,
                f"cCj {file_path} @ {address}": json_diff,
            },
        )
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.compare_disassembly(file_path, address)
        assert f"cD {file_path} @ {address}" in rec.commands
        assert f"cCj {file_path} @ {address}" in rec.commands
        assert text_diff.rstrip() in result
        assert json_diff.rstrip() in result
        cd_index: int = rec.commands.index(f"cD {file_path} @ {address}")
        ccj_index: int = rec.commands.index(f"cCj {file_path} @ {address}")
        assert cd_index < ccj_index

    @pytest.mark.asyncio
    async def test_only_cd_result_included_when_ccj_empty(self) -> None:
        """compare_disassembly includes only the cD section when cCj returns empty.

        Mutation caught: joining an empty section anyway would insert a spurious
        newline or empty string, and the exact result assertion would fail.
        """
        file_path: str = r"C:\target\other.exe"
        address: int = 0x4000
        text_diff: str = "- mov eax, 1\n+ mov eax, 2"
        rec = _CommandRecorder(
            {
                f"cD {file_path} @ {address}": text_diff,
                f"cCj {file_path} @ {address}": "",
            },
        )
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.compare_disassembly(file_path, address)
        assert result == text_diff.rstrip()

    @pytest.mark.asyncio
    async def test_raises_without_binary(self) -> None:
        """compare_disassembly raises ToolError when no r2 session is open."""
        bridge = CutterBridge()
        with pytest.raises(ToolError, match="no binary"):
            await bridge.compare_disassembly(r"C:\other.exe", _ADDR)


class TestGetSegments:
    """Gate get_segments: verify iSSj command and SegmentInfo field mapping."""

    @pytest.mark.asyncio
    async def test_issj_command_issued_and_fields_mapped(self) -> None:
        """get_segments must issue "iSSj" and map all five SegmentInfo fields.

        Independent oracle: a single segment entry with known name, vaddr,
        vsize, perm, and type values.  The bridge must map ``vaddr`` →
        ``address``, ``vsize`` → ``size``, ``perm`` → ``permissions``,
        ``type`` → ``type``.

        Mutation caught: reading ``addr`` instead of ``vaddr`` for ``address``
        would produce ``address == 0`` rather than the oracle value.
        """
        segment_entry: dict[str, object] = {
            "name": ".text",
            "vaddr": 4096,
            "vsize": 8192,
            "perm": "r-x",
            "type": "LOAD",
        }
        rec = _CommandRecorder({"iSSj": json.dumps([segment_entry])})
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.get_segments()
        assert "iSSj" in rec.commands
        assert len(result) == 1
        seg: SegmentInfo = result[0]
        assert seg.name == ".text"
        assert seg.address == 4096
        assert seg.size == 8192
        assert seg.permissions == "r-x"
        assert seg.type == "LOAD"

    @pytest.mark.asyncio
    async def test_vsize_fallback_to_size_field(self) -> None:
        """get_segments falls back to "size" when "vsize" is absent.

        Oracle: segment entry with no ``vsize`` key but a known ``size`` value.
        Mutation caught: using only ``vsize`` and not the fallback would produce
        ``size == 0`` rather than the oracle value.
        """
        segment_entry: dict[str, object] = {
            "name": ".data",
            "vaddr": 8192,
            "size": 512,
            "perm": "rw-",
            "type": "LOAD",
        }
        rec = _CommandRecorder({"iSSj": json.dumps([segment_entry])})
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.get_segments()
        assert len(result) == 1
        assert result[0].size == 512

    @pytest.mark.asyncio
    async def test_multiple_segments_all_parsed(self) -> None:
        """get_segments returns one SegmentInfo per JSON entry.

        Mutation caught: returning only the first entry would fail len == 2.
        """
        entries: list[dict[str, object]] = [
            {"name": ".text", "vaddr": 0x1000, "vsize": 0x1000, "perm": "r-x", "type": "LOAD"},
            {"name": ".data", "vaddr": 0x2000, "vsize": 0x800, "perm": "rw-", "type": "LOAD"},
        ]
        rec = _CommandRecorder({"iSSj": json.dumps(entries)})
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.get_segments()
        assert len(result) == 2
        assert result[0].name == ".text"
        assert result[1].name == ".data"

    @pytest.mark.asyncio
    async def test_empty_response_yields_empty_list(self) -> None:
        """get_segments returns [] when rizin reports no segments."""
        rec = _CommandRecorder({"iSSj": ""})
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.get_segments()
        assert result == []

    @pytest.mark.asyncio
    async def test_raises_without_binary(self) -> None:
        """get_segments raises ToolError when no r2 session is open."""
        bridge = CutterBridge()
        with pytest.raises(ToolError, match="no binary"):
            await bridge.get_segments()


class TestHexdumpWords:
    """Gate hexdump_words: verify pxw command (distinct from px used by hexdump)."""

    @pytest.mark.asyncio
    async def test_pxw_command_exact_form_and_result(self) -> None:
        """hexdump_words must emit "pxw {length} @ {address}" and return the text.

        Independent oracle: the recorder returns a known word-dump string for
        the exact ``pxw`` command.  The bridge must emit ``pxw``, NOT ``px``.

        Mutation caught: emitting ``px`` instead of ``pxw`` would not match
        the recorder prefix for ``pxw``, returning empty string and failing
        the result assertion; the command assertion also fails directly.
        """
        address: int = 0x5000
        length: int = 64
        oracle_text: str = "0x00005000  deadbeef cafebabe  ...."
        rec = _CommandRecorder({f"pxw {length} @ {address}": oracle_text})
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.hexdump_words(address, length)
        assert f"pxw {length} @ {address}" in rec.commands
        assert result == oracle_text

    @pytest.mark.asyncio
    async def test_default_length_256_used_in_command(self) -> None:
        """hexdump_words uses 256 as the default length when none is specified.

        Oracle: the command must contain ``pxw 256 @`` when called with only
        an address argument.  Mutation caught: using a different default would
        fail the command assertion.
        """
        address: int = 0x6000
        rec = _CommandRecorder({f"pxw 256 @ {address}": "0x00006000  00000000  ...."})
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.hexdump_words(address)
        assert f"pxw 256 @ {address}" in rec.commands
        assert "0x00006000" in result

    @pytest.mark.asyncio
    async def test_pxw_not_px_in_command(self) -> None:
        """hexdump_words must not emit the bare "px" command that hexdump uses.

        This test specifically verifies the command distinguishes hexdump_words
        from hexdump.  Mutation caught: using ``px`` would produce a command
        that does NOT contain the ``pxw`` substring.
        """
        address: int = 0x7000
        length: int = 32
        rec = _CommandRecorder({f"pxw {length} @ {address}": "word dump output"})
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        await bridge.hexdump_words(address, length)
        pxw_commands: list[str] = [c for c in rec.commands if c.startswith("pxw")]
        px_only_commands: list[str] = [c for c in rec.commands if c.startswith("px ") or c == "px"]
        assert len(pxw_commands) == 1
        assert len(px_only_commands) == 0

    @pytest.mark.asyncio
    async def test_raises_without_binary(self) -> None:
        """hexdump_words raises ToolError when no r2 session is open."""
        bridge = CutterBridge()
        with pytest.raises(ToolError, match="no binary"):
            await bridge.hexdump_words(_ADDR)


class TestDisassembleFunction:
    """Gate disassemble_function: verify pdf @ {addr} command and mnemonic content."""

    @pytest.mark.asyncio
    async def test_pdf_command_exact_form_and_mnemonic_in_result(self) -> None:
        """disassemble_function must emit "pdf @ {address}" and return the text.

        Independent oracle: the recorder returns a known disassembly listing
        for the ``pdf`` command that contains ``push rbp`` as the first
        instruction.  The bridge must emit the exact command and return the
        text verbatim.

        Mutation caught: emitting ``pd @ {address}`` (without the ``f``
        suffix that means ``function``) would not match the recorder prefix,
        returning empty string and failing the mnemonic assertion.
        """
        address: int = 0x401000
        oracle_asm: str = (
            "/ (fcn) sym.main 42\n"
            "|   0x00401000      55             push rbp\n"
            "|   0x00401001      4889e5         mov rbp, rsp\n"
            "\\   0x00401003      c3             ret\n"
        )
        rec = _CommandRecorder({f"pdf @ {address}": oracle_asm})
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.disassemble_function(address)
        assert f"pdf @ {address}" in rec.commands
        assert "push rbp" in result
        assert "mov rbp, rsp" in result
        assert "ret" in result

    @pytest.mark.asyncio
    async def test_pdf_address_embedded_correctly(self) -> None:
        """disassemble_function embeds the exact address value in the command.

        Oracle: a different address (0x402000) must appear verbatim in the
        emitted command string.  Mutation caught: using a hardcoded address
        instead of the parameter would fail when the address differs from the
        hardcoded value.
        """
        address: int = 0x402000
        rec = _CommandRecorder({f"pdf @ {address}": "0x00402000  90  nop"})
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.disassemble_function(address)
        assert f"pdf @ {address}" in rec.commands
        assert "nop" in result

    @pytest.mark.asyncio
    async def test_raises_without_binary(self) -> None:
        """disassemble_function raises ToolError when no r2 session is open."""
        bridge = CutterBridge()
        with pytest.raises(ToolError, match="no binary"):
            await bridge.disassemble_function(_ADDR)
