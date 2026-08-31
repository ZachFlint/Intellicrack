# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gates for the live 6F x64dbg re-drive findings.

Two defects surfaced when the never-exercised 6F items were driven against
a real x64dbg process and a real ``notepad.exe`` debuggee:

* **Annotation whitespace loss (F6-13).** ``set_label`` / ``set_comment``
  handed the annotation text to the ``lblset`` / ``cmtset`` console
  commands *unquoted*. x64dbg's command tokenizer strips internal
  whitespace from an unquoted argument, so ``"IC audit comment"`` was
  stored as ``ICauditcomment`` and the bridge's own read-back
  verification (correctly) raised. The live probe confirmed a *quoted*
  argument survives intact.

* **Patch verification race (F6-14).** ``patch_instruction`` read memory
  back exactly once, immediately after the ``assemble`` RPC returned. The
  RPC only queues an asynchronous ``DbgCmdExec("asm ...")``, so that
  single read raced the write: the live probe observed the pre-patch
  bytes on the first read and the ``mov eax, 1`` encoding present a poll
  later, at a real code address where the patch genuinely succeeded.

Both doubles below are *derived from that observed x64dbg behaviour* - the
tokenizer's space collapsing and the delayed reveal of the assembled
bytes - rather than restating the bridge's own logic, so each test fails
when its fix is reverted.
"""

from __future__ import annotations

from typing import Any

import pytest

from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.core.types import ToolError


_LABEL_ADDR = 0x7FF63AA4001A
_COMMENT_ADDR = 0x7FF63AA4000A
_PATCH_ADDR = 0x7FF63AA4000A
_MOV_EAX_1 = bytes.fromhex("b801000000")


def _x64dbg_tokenize_annotation(rest: str) -> str:
    """Model x64dbg's console tokenizer for a single annotation argument.

    Derived from the live 6F probe: an unquoted argument has *all* of its
    internal whitespace stripped by the command parser, while a
    double-quoted argument is preserved verbatim with the surrounding
    quotes removed.

    Args:
        rest: The raw argument text following ``lblset ADDR, `` /
            ``cmtset ADDR, `` in the queued console command.

    Returns:
        str: The text x64dbg would actually store for that argument.
    """
    rest = rest.strip()
    if len(rest) >= 2 and rest.startswith('"') and rest.endswith('"'):
        return rest[1:-1]
    return rest.replace(" ", "").replace("\t", "")


class _AnnotationTokenizerPipe:
    """Fake pipe that stores annotations the way x64dbg's parser would.

    ``exec`` commands carrying ``lblset`` / ``cmtset`` are parsed through
    :func:`_x64dbg_tokenize_annotation` and stored per address; the
    matching ``lbl_list`` / ``cmt_list`` read-backs return whatever was
    stored. A fix that quotes the text round-trips embedded spaces; the
    unquoted (pre-fix) command loses them and trips the bridge's own
    verification.
    """

    def __init__(self) -> None:
        """Initialize empty label and comment stores."""
        self.labels: dict[int, str] = {}
        self.comments: dict[int, str] = {}

    @property
    def is_connected(self) -> bool:
        """Report the fake pipe as permanently connected.

        Returns:
            bool: Always ``True``.
        """
        return True

    def _store(self, command: str) -> None:
        """Parse and store a ``lblset`` / ``cmtset`` console command.

        Args:
            command: The full console command string queued via ``exec``.
        """
        for verb, store in (("lblset ", self.labels), ("cmtset ", self.comments)):
            if command.startswith(verb):
                addr_str, _, rest = command[len(verb) :].partition(", ")
                store[int(addr_str, 0)] = _x64dbg_tokenize_annotation(rest)
                return

    async def send_command(self, command: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Dispatch a fake RPC, applying the tokenizer to annotation writes.

        Args:
            command: RPC command name.
            params: RPC parameters.

        Returns:
            dict[str, Any]: A scripted pipe response.

        Raises:
            AssertionError: If an unexpected RPC command is received.
        """
        if command == "exec":
            self._store(str((params or {}).get("command", "")))
            return {"id": 1, "success": True, "result": None}
        if command in {"lbl_list", "cmt_list"}:
            store = self.labels if command == "lbl_list" else self.comments
            addr = int((params or {}).get("start", 0))
            if addr in store:
                return {"id": 1, "success": True, "result": [{"address": hex(addr), "text": store[addr]}]}
            return {"id": 1, "success": True, "result": []}
        msg = f"unexpected command: {command}"
        raise AssertionError(msg)


class _AsyncAssemblePipe:
    """Fake pipe whose ``assemble`` write becomes visible only after a delay.

    Models x64dbg's asynchronous ``DbgCmdExec("asm ...")``: the RPC
    returns immediately, but the target bytes change only after
    ``reveal_after`` further memory reads. Paired with an override of
    ``_read_memory_for_verification`` it reproduces the live race where a
    single immediate read observed the pre-patch bytes.
    """

    def __init__(self, original: bytes, patched: bytes, reveal_after: int) -> None:
        """Initialize the async-assemble model.

        Args:
            original: Bytes resident at the patch address before assembly.
            patched: Bytes that become visible once the async write lands.
            reveal_after: Number of post-assemble reads that still observe
                ``original`` before ``patched`` is revealed.
        """
        self.original = original
        self.patched = patched
        self.reveal_after = reveal_after
        self.assembled = False
        self._post_reads = 0

    @property
    def is_connected(self) -> bool:
        """Report the fake pipe as permanently connected.

        Returns:
            bool: Always ``True``.
        """
        return True

    async def send_command(self, command: str, _params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Handle the ``assemble`` RPC by arming the delayed reveal.

        Args:
            command: RPC command name.
            _params: RPC parameters (unused; the model tracks a single address).

        Returns:
            dict[str, Any]: A scripted pipe response.

        Raises:
            AssertionError: If an unexpected RPC command is received.
        """
        if command == "assemble":
            self.assembled = True
            return {"id": 1, "success": True, "result": "true"}
        msg = f"unexpected command: {command}"
        raise AssertionError(msg)

    async def read_verification(self, _address: int, size: int) -> bytes:
        """Stand in for ``_read_memory_for_verification`` with delayed reveal.

        Args:
            _address: Ignored; the model tracks a single patch address.
            size: Number of bytes requested.

        Returns:
            bytes: ``original`` before the assemble and for the first
            ``reveal_after`` reads after it, ``patched`` thereafter.
        """
        if not self.assembled:
            return self.original[:size]
        self._post_reads += 1
        if self._post_reads <= self.reveal_after:
            return self.original[:size]
        return self.patched[:size]


class _PlaceholderProcess:
    """Sentinel satisfying ``self._process is not None`` guards."""


def _attach_pipe(bridge: X64DbgBridge, pipe: object) -> None:
    """Install a fake pipe client and mark the plugin/process ready.

    Args:
        bridge: Bridge under test.
        pipe: Fake pipe client exposing ``is_connected`` / ``send_command``.
    """
    setattr(bridge, "_pipe_client", pipe)
    setattr(bridge, "_plugin_deployed", True)
    setattr(bridge, "_process", _PlaceholderProcess())


@pytest.fixture
def bridge() -> X64DbgBridge:
    """Construct a fresh bridge instance.

    Returns:
        X64DbgBridge: A bridge with no attached PID.
    """
    return X64DbgBridge()


@pytest.mark.asyncio
class TestAnnotationWhitespaceSurvives:
    """F6-13: spaced labels/comments must survive x64dbg's tokenizer."""

    async def test_set_comment_preserves_internal_spaces(self, bridge: X64DbgBridge) -> None:
        """A spaced comment round-trips instead of collapsing to ``ICauditcomment``.

        Args:
            bridge: Fixture bridge instance.
        """
        pipe = _AnnotationTokenizerPipe()
        _attach_pipe(bridge, pipe)
        result = await bridge.set_comment(_COMMENT_ADDR, "IC audit comment")
        assert result["verified"] is True
        assert pipe.comments[_COMMENT_ADDR] == "IC audit comment"

    async def test_set_label_preserves_internal_spaces(self, bridge: X64DbgBridge) -> None:
        """A spaced label round-trips instead of collapsing to ``ICauditlabel``.

        Args:
            bridge: Fixture bridge instance.
        """
        pipe = _AnnotationTokenizerPipe()
        _attach_pipe(bridge, pipe)
        result = await bridge.set_label(_LABEL_ADDR, "IC audit label")
        assert result["verified"] is True
        assert pipe.labels[_LABEL_ADDR] == "IC audit label"

    async def test_tokenizer_double_would_strip_unquoted_spaces(self) -> None:
        """Guard that the derived tokenizer models the real space-stripping.

        Without this the whitespace tests could pass vacuously (a
        tokenizer that never strips spaces cannot detect the regression).
        """
        assert _x64dbg_tokenize_annotation("IC audit comment") == "ICauditcomment"
        assert _x64dbg_tokenize_annotation('"IC audit comment"') == "IC audit comment"


@pytest.mark.asyncio
class TestPatchInstructionRace:
    """F6-14: patch verification must not race the async assemble write."""

    async def test_patch_succeeds_when_write_lands_after_first_read(self, bridge: X64DbgBridge) -> None:
        """A patch visible only on a later poll is verified, not misreported.

        Args:
            bridge: Fixture bridge instance.
        """
        original = bytes(16)
        patched = _MOV_EAX_1 + bytes(11)
        pipe = _AsyncAssemblePipe(original=original, patched=patched, reveal_after=2)
        _attach_pipe(bridge, pipe)
        setattr(bridge, "_read_memory_for_verification", pipe.read_verification)

        result = await bridge.patch_instruction(_PATCH_ADDR, "mov eax, 1")

        assert result["success"] is True
        assert result["verified"] is True
        assert str(result["patched_bytes"]).lower().startswith("b801000000")

    async def test_patch_still_raises_when_memory_never_changes(self, bridge: X64DbgBridge) -> None:
        """A genuinely failed assemble (bytes never change) still raises.

        Args:
            bridge: Fixture bridge instance.
        """
        original = bytes(16)
        pipe = _AsyncAssemblePipe(original=original, patched=original, reveal_after=10_000)
        _attach_pipe(bridge, pipe)
        setattr(bridge, "_read_memory_for_verification", pipe.read_verification)
        bridge.VERIFY_TIMEOUT = 0.05
        bridge.VERIFY_POLL_INTERVAL = 0.005

        with pytest.raises(ToolError, match="unchanged after assemble"):
            await bridge.patch_instruction(_PATCH_ADDR, "mov eax, 1")
