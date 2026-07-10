# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Gates for CutterBridge project management and write-transform operations.

Covers the NONE-verdict operations identified in the section-02 test-coverage
audit under the CUTTER-PROJECT scope:

- Project management: save_project, open_project, list_projects
- Write transforms: write_xor, write_add, write_sub, write_from_file,
  write_to_file, write_value, write_string

Every test drives the REAL bridge method through the _CommandRecorder fake
transport: a known response string is pre-configured for a known command
prefix, the real method is invoked, and the test asserts BOTH the exact
command string the bridge emitted AND the exact parsed return value derived
from the known response.  Each gate documents the concrete one-line production
mutation it would catch.
"""

from __future__ import annotations

from typing import Final, cast

import pytest
import r2pipe

from intellicrack.bridges.cutter import CutterBridge
from intellicrack.core.types import ToolError


_ADDR: Final[int] = 0x1000


class _CommandRecorder:
    """Fake r2pipe session that records issued commands and returns configured responses.

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
        return next(
            (response for prefix, response in self.responses.items() if command.startswith(prefix)),
            "",
        )

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


class TestSaveProject:
    """Gate save_project: verify it issues exactly "Ps <name>" to rizin."""

    @pytest.mark.asyncio
    async def test_ps_command_exact_form(self) -> None:
        """save_project must emit exactly "Ps myproject" to rizin and return True.

        Mutation caught: changing ``Ps`` to ``Po`` in the save_project body
        would emit "Po myproject" instead, failing the command assertion.
        """
        rec = _CommandRecorder()
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.save_project("myproject")
        assert result is True
        assert "Ps myproject" in rec.commands

    @pytest.mark.asyncio
    async def test_raises_without_binary(self) -> None:
        """save_project raises ToolError when no r2 session is open."""
        bridge = CutterBridge()
        with pytest.raises(ToolError, match="no binary"):
            await bridge.save_project("myproject")


class TestOpenProject:
    """Gate open_project: verify it issues exactly "Po <name>" to rizin."""

    @pytest.mark.asyncio
    async def test_po_command_exact_form(self) -> None:
        """open_project must emit exactly "Po myproject" to rizin and return True.

        Mutation caught: swapping ``Po`` for ``Ps`` in open_project would emit
        "Ps myproject", failing the command assertion.
        """
        rec = _CommandRecorder()
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.open_project("myproject")
        assert result is True
        assert "Po myproject" in rec.commands

    @pytest.mark.asyncio
    async def test_raises_without_binary(self) -> None:
        """open_project raises ToolError when no r2 session is open."""
        bridge = CutterBridge()
        with pytest.raises(ToolError, match="no binary"):
            await bridge.open_project("myproject")


class TestListProjects:
    """Gate list_projects: verify it issues "Pl" and parses newline-delimited output."""

    @pytest.mark.asyncio
    async def test_pl_command_line_split_parsing(self) -> None:
        r"""list_projects must split "Pl" output on newlines and return stripped names.

        Independent oracle: the recorder returns "proj1\nproj2\n" for the "Pl"
        command.  The bridge must parse that into exactly ["proj1", "proj2"] by
        splitting on newlines and stripping each non-empty line.

        Mutation caught: returning the raw response string instead of a list,
        or failing to strip trailing whitespace, would produce a different value
        and fail the exact-list assertion.
        """
        rec = _CommandRecorder({"Pl": "proj1\nproj2\n"})
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.list_projects()
        assert result == ["proj1", "proj2"]
        assert "Pl" in rec.commands

    @pytest.mark.asyncio
    async def test_empty_response_yields_empty_list(self) -> None:
        """list_projects returns [] when rizin reports no projects.

        Mutation caught: returning a non-empty list for an empty response would
        fail the exact-list assertion.
        """
        rec = _CommandRecorder({"Pl": ""})
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.list_projects()
        assert result == []

    @pytest.mark.asyncio
    async def test_raises_without_binary(self) -> None:
        """list_projects raises ToolError when no r2 session is open."""
        bridge = CutterBridge()
        with pytest.raises(ToolError, match="no binary"):
            await bridge.list_projects()


class TestWriteXor:
    """Gate write_xor: verify it emits "wox <key> @ <addr> @!<length>"."""

    @pytest.mark.asyncio
    async def test_exact_command_with_block_suffix(self) -> None:
        """write_xor must emit exactly "wox 255 @ 4096 @!4" to rizin.

        The @!{length} suffix constrains the XOR to exactly the requested byte
        count rather than the full session block size; this invariant is the
        core correctness property of write_xor.

        Mutation caught: omitting the ``@!{length}`` suffix from the rizin
        command would expand the XOR to the full session block size; the exact
        command assertion would fail.
        """
        rec = _CommandRecorder()
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.write_xor(_ADDR, 4, 0xFF)
        assert result is True
        assert f"wox 255 @ {_ADDR} @!4" in rec.commands

    @pytest.mark.asyncio
    async def test_raises_without_binary(self) -> None:
        """write_xor raises ToolError when no r2 session is open."""
        bridge = CutterBridge()
        with pytest.raises(ToolError, match="no binary"):
            await bridge.write_xor(_ADDR, 4, 0xFF)


class TestWriteAdd:
    """Gate write_add: verify it emits "woa <value> @ <addr> @!<length>"."""

    @pytest.mark.asyncio
    async def test_exact_command_with_block_suffix(self) -> None:
        """write_add must emit exactly "woa 1 @ 4096 @!8" to rizin.

        Mutation caught: changing ``woa`` to ``wox`` in the write_add body
        would emit "wox 1 @ 4096 @!8", failing the command assertion.
        """
        rec = _CommandRecorder()
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.write_add(_ADDR, 8, 1)
        assert result is True
        assert f"woa 1 @ {_ADDR} @!8" in rec.commands

    @pytest.mark.asyncio
    async def test_raises_without_binary(self) -> None:
        """write_add raises ToolError when no r2 session is open."""
        bridge = CutterBridge()
        with pytest.raises(ToolError, match="no binary"):
            await bridge.write_add(_ADDR, 8, 1)


class TestWriteSub:
    """Gate write_sub: verify it emits "wos <value> @ <addr> @!<length>"."""

    @pytest.mark.asyncio
    async def test_exact_command_with_block_suffix(self) -> None:
        """write_sub must emit exactly "wos 5 @ 4096 @!16" to rizin.

        Mutation caught: changing ``wos`` to ``woa`` in the write_sub body
        would emit "woa 5 @ 4096 @!16", failing the command assertion.
        """
        rec = _CommandRecorder()
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.write_sub(_ADDR, 16, 5)
        assert result is True
        assert f"wos 5 @ {_ADDR} @!16" in rec.commands

    @pytest.mark.asyncio
    async def test_raises_without_binary(self) -> None:
        """write_sub raises ToolError when no r2 session is open."""
        bridge = CutterBridge()
        with pytest.raises(ToolError, match="no binary"):
            await bridge.write_sub(_ADDR, 16, 5)


class TestWriteFromFile:
    """Gate write_from_file: verify it emits "wf <path> @ <addr>"."""

    @pytest.mark.asyncio
    async def test_exact_command_form(self) -> None:
        """write_from_file must emit exactly "wf /data/patch.bin @ 4096" to rizin.

        Mutation caught: changing ``wf`` to ``wtf`` in the write_from_file body
        would emit "wtf /data/patch.bin @ 4096", failing the command assertion.
        """
        rec = _CommandRecorder()
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.write_from_file("/data/patch.bin", _ADDR)
        assert result is True
        assert f"wf /data/patch.bin @ {_ADDR}" in rec.commands

    @pytest.mark.asyncio
    async def test_raises_without_binary(self) -> None:
        """write_from_file raises ToolError when no r2 session is open."""
        bridge = CutterBridge()
        with pytest.raises(ToolError, match="no binary"):
            await bridge.write_from_file("/data/patch.bin", _ADDR)


class TestWriteToFile:
    """Gate write_to_file: verify it emits "wtf <path> <size> @ <addr>"."""

    @pytest.mark.asyncio
    async def test_exact_command_form(self) -> None:
        """write_to_file must emit exactly "wtf /out/dump.bin 64 @ 4096" to rizin.

        Mutation caught: omitting the size argument from the rizin command would
        emit "wtf /out/dump.bin @ 4096" without the size field, failing the
        exact command assertion.
        """
        rec = _CommandRecorder()
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.write_to_file("/out/dump.bin", 64, _ADDR)
        assert result is True
        assert f"wtf /out/dump.bin 64 @ {_ADDR}" in rec.commands

    @pytest.mark.asyncio
    async def test_raises_without_binary(self) -> None:
        """write_to_file raises ToolError when no r2 session is open."""
        bridge = CutterBridge()
        with pytest.raises(ToolError, match="no binary"):
            await bridge.write_to_file("/out/dump.bin", 64, _ADDR)


class TestWriteValue:
    """Gate write_value: verify size-variant dispatch emits "wv<size> <value> @ <addr>"."""

    @pytest.mark.asyncio
    async def test_size1_dispatch(self) -> None:
        """write_value with size=1 must emit "wv1 255 @ 4096" to rizin.

        Mutation caught: always emitting ``wv4`` regardless of the size argument
        would produce "wv4 255 @ 4096" for this call, failing the assertion.
        """
        rec = _CommandRecorder()
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.write_value(_ADDR, 255, 1)
        assert result is True
        assert f"wv1 255 @ {_ADDR}" in rec.commands

    @pytest.mark.asyncio
    async def test_size2_dispatch(self) -> None:
        """write_value with size=2 must emit "wv2 1000 @ 4096" to rizin.

        Mutation caught: always emitting ``wv4`` would produce "wv4 1000 @ 4096"
        for this call, failing the assertion.
        """
        rec = _CommandRecorder()
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.write_value(_ADDR, 1000, 2)
        assert result is True
        assert f"wv2 1000 @ {_ADDR}" in rec.commands

    @pytest.mark.asyncio
    async def test_size4_dispatch(self) -> None:
        """write_value with size=4 must emit "wv4 57005 @ 4096" to rizin.

        0xDEAD == 57005.  Mutation caught: emitting ``wv8`` for size=4 would
        produce "wv8 57005 @ 4096", failing the assertion.
        """
        rec = _CommandRecorder()
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.write_value(_ADDR, 0xDEAD, 4)
        assert result is True
        assert f"wv4 57005 @ {_ADDR}" in rec.commands

    @pytest.mark.asyncio
    async def test_size8_dispatch(self) -> None:
        """write_value with size=8 must emit "wv8 1234567890 @ 4096" to rizin.

        Mutation caught: always emitting ``wv4`` would produce
        "wv4 1234567890 @ 4096", failing the assertion.
        """
        rec = _CommandRecorder()
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.write_value(_ADDR, 1234567890, 8)
        assert result is True
        assert f"wv8 1234567890 @ {_ADDR}" in rec.commands

    @pytest.mark.asyncio
    async def test_raises_without_binary(self) -> None:
        """write_value raises ToolError when no r2 session is open."""
        bridge = CutterBridge()
        with pytest.raises(ToolError, match="no binary"):
            await bridge.write_value(_ADDR, 42, 4)


class TestWriteString:
    """Gate write_string: verify quote escaping and exact rizin command form."""

    @pytest.mark.asyncio
    async def test_plain_string_command_form(self) -> None:
        """write_string with a plain string must emit 'w "hello" @ 4096' to rizin.

        Mutation caught: using ``wx`` instead of ``w`` as the command prefix
        would emit 'wx "hello" @ 4096', failing the exact command assertion.
        """
        rec = _CommandRecorder()
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.write_string(_ADDR, "hello")
        assert result is True
        assert f'w "hello" @ {_ADDR}' in rec.commands

    @pytest.mark.asyncio
    async def test_embedded_quote_escaping(self) -> None:
        r"""write_string must escape embedded double-quotes to prevent command injection.

        The bridge must transform each literal " in the text to \" before
        interpolating it into the rizin command string so that rizin receives
        the quotes as string content rather than command delimiters.

        Independent oracle: passing 'say "hi"' must produce the command
        'w "say \\"hi\\"" @ 4096' (where \\" is a literal backslash + double-quote
        pair inside the outer double-quote delimiters).

        Mutation caught: omitting the replace('"', '\\"') step in write_string
        would emit 'w "say "hi"" @ 4096', which does NOT match the escaped form
        and fails the assertion.
        """
        rec = _CommandRecorder()
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(rec)
        result = await bridge.write_string(_ADDR, 'say "hi"')
        assert result is True
        expected = f'w "say \\"hi\\"" @ {_ADDR}'
        assert expected in rec.commands

    @pytest.mark.asyncio
    async def test_raises_without_binary(self) -> None:
        """write_string raises ToolError when no r2 session is open."""
        bridge = CutterBridge()
        with pytest.raises(ToolError, match="no binary"):
            await bridge.write_string(_ADDR, "hello")
