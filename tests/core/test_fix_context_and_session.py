# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Multi-part tool results are priced, bounded, trimmed and persisted correctly.

Covers the context-window side of multi-part results (images priced by their
pixels, textual parts bounded, trimming never orphaning a tool result), the
session store's handling of multi-part history and of a failure inside its
save transaction, and the argument summary an MCP tool is advertised with.
"""

from __future__ import annotations

import base64
import os
import sqlite3
import struct
import zlib
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final

import pytest
from PyQt6.QtCore import QBuffer, QByteArray, QIODevice
from PyQt6.QtGui import QColor, QImage

from intellicrack.core.orchestrator import Orchestrator
from intellicrack.core.result_parts import IMAGE_MAX_TOKENS, bound_result_parts, estimate_image_tokens, image_dimensions
from intellicrack.core.session import Session, SessionStore
from intellicrack.core.types import (
    AudioResultPart,
    EmbeddedResourcePart,
    ImageResultPart,
    Message,
    ResourceLinkPart,
    StructuredResultPart,
    TextResultPart,
    ToolCall,
    ToolFunction,
    ToolResult,
    ToolResultPart,
    render_schema_parameters,
)


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


_MINIMAL_GIF: Final[bytes] = (
    b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00"
    b",\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
)
_BOUND: Final[int] = 8000


def _qt_encoded(width: int, height: int, fmt: str) -> str:
    """Encode a solid image of the given size through Qt's real encoder.

    Args:
        width: Image width.
        height: Image height.
        fmt: Qt image format name, such as ``"PNG"`` or ``"JPEG"``.

    Returns:
        str: The base64-encoded file.
    """
    image = QImage(width, height, QImage.Format.Format_RGB32)
    image.fill(QColor(90, 120, 200))
    data = QByteArray()
    buffer = QBuffer(data)
    assert buffer.open(QIODevice.OpenModeFlag.WriteOnly)
    assert image.save(buffer, fmt)
    buffer.close()
    return base64.b64encode(bytes(data.data())).decode("ascii")


def _noise_png(width: int, height: int) -> str:
    """Encode an incompressible greyscale PNG, so its base64 is large.

    Args:
        width: Image width.
        height: Image height.

    Returns:
        str: The base64-encoded PNG.
    """

    def chunk(kind: bytes, payload: bytes) -> bytes:
        """Frame one PNG chunk.

        Args:
            kind: Chunk type.
            payload: Chunk data.

        Returns:
            bytes: The framed chunk.
        """
        return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)

    rows = b"".join(b"\x00" + os.urandom(width) for _ in range(height))
    header = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)
    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b"")
    return base64.b64encode(png).decode("ascii")


def _tool_turn(result: ToolResult) -> list[Message]:
    """Build an assistant call followed by the tool message answering it.

    Args:
        result: The tool result to answer with.

    Returns:
        list[Message]: The two messages.
    """
    call = ToolCall(id=result.call_id, tool_name="mcp-srv", function_name="mcp-srv.shot", arguments={})
    return [
        Message(role="assistant", content="", tool_calls=[call]),
        Message(role="tool", content="", tool_results=[result]),
    ]


class TestImageDimensions:
    """Item 35: an image's size is read from the encoded file header."""

    @pytest.mark.parametrize("fmt", ["PNG", "JPEG", "WEBP"])
    def test_reads_dimensions_of_real_encoder_output(self, fmt: str) -> None:
        """PNG, JPEG and WebP written by Qt decode to their true size.

        Args:
            fmt: Image format to encode.
        """
        assert image_dimensions(_qt_encoded(333, 177, fmt)) == (333, 177)

    def test_reads_gif_dimensions(self) -> None:
        """A real GIF decodes to the size Qt reads from it."""
        reference = QImage.fromData(_MINIMAL_GIF)
        assert not reference.isNull()
        assert image_dimensions(base64.b64encode(_MINIMAL_GIF).decode()) == (reference.width(), reference.height())

    def test_unrecognised_payload_has_no_dimensions(self) -> None:
        """Data that is not an image yields no dimensions."""
        assert image_dimensions(base64.b64encode(b"not an image at all" * 10).decode()) is None
        assert image_dimensions("%%% not base64 %%%") is None


class TestImageTokens:
    """Item 35: an image is priced by its pixels, not its base64 length."""

    @pytest.mark.parametrize(
        ("width", "height", "expected"),
        [(200, 200, 64), (1000, 1000, 1296), (1920, 1080, 2691), (3840, 2160, 4784)],
    )
    def test_matches_the_published_visual_token_table(self, width: int, height: int, expected: int) -> None:
        """The estimate reproduces Anthropic's published high-resolution costs.

        Args:
            width: Image width.
            height: Image height.
            expected: Published visual-token cost.
        """
        part = ImageResultPart(
            data=_noise_png(width, height) if width * height < 250_000 else _header_only_png(width, height),
            mime_type="image/png",
        )
        assert estimate_image_tokens(part) == expected

    def test_unreadable_image_is_charged_the_ceiling(self) -> None:
        """An image whose size cannot be read is never counted as cheap."""
        part = ImageResultPart(data=base64.b64encode(b"garbage").decode(), mime_type="image/png")
        assert estimate_image_tokens(part) == IMAGE_MAX_TOKENS

    def test_history_with_a_screenshot_is_not_trimmed_away(self) -> None:
        """A 640x480 screenshot costs hundreds of tokens, not a hundred thousand.

        The PNG is random noise, so its base64 form is roughly 400 KB; counted
        as text it would dwarf a 20k-token window and trim the whole history.
        """
        image = ImageResultPart(data=_noise_png(640, 480), mime_type="image/png")
        assert len(image.data) > 300_000
        result = ToolResult(
            call_id="c1",
            success=True,
            result="caption",
            error=None,
            duration_ms=1.0,
            content=[TextResultPart("caption"), image],
        )
        messages = [Message(role="system", content="sys"), Message(role="user", content="look"), *_tool_turn(result)]
        trimmed = Orchestrator.trim_messages_to_context_window(list(messages), 20_000)
        assert [message.role for message in trimmed] == ["system", "user", "assistant", "tool"]


def _header_only_png(width: int, height: int) -> str:
    """Encode a PNG of a large declared size cheaply.

    Args:
        width: Declared width.
        height: Declared height.

    Returns:
        str: The base64-encoded PNG, with one compressed row per scanline.
    """
    rows = zlib.compress(b"".join(b"\x00" + b"\x00" * width for _ in range(height)), 9)
    header = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)

    def chunk(kind: bytes, payload: bytes) -> bytes:
        """Frame one PNG chunk.

        Args:
            kind: Chunk type.
            payload: Chunk data.

        Returns:
            bytes: The framed chunk.
        """
        return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)

    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", rows) + chunk(b"IEND", b"")
    return base64.b64encode(png).decode("ascii")


class TestBoundingContent:
    """Item 35: multi-part content shares the same bound as plain results."""

    def test_textual_parts_share_one_budget(self) -> None:
        """Text, resource text and JSON are cut at one shared budget; media is kept."""
        image = ImageResultPart(data=_noise_png(32, 32), mime_type="image/png")
        parts: list[ToolResultPart] = [
            TextResultPart("a" * 5000),
            image,
            EmbeddedResourcePart(uri="file:///x", text="b" * 5000, mime_type="text/plain"),
            StructuredResultPart(content={"rows": ["c" * 100] * 100}),
            ResourceLinkPart(uri="file:///y"),
            AudioResultPart(data="AAAA", mime_type="audio/wav"),
        ]
        bounded = bound_result_parts(parts, _BOUND)

        assert bounded[0] == parts[0]
        assert bounded[1] is image
        embedded = bounded[2]
        assert isinstance(embedded, EmbeddedResourcePart)
        assert embedded.text is not None
        assert embedded.text.startswith("b" * 3000)
        assert "truncated 2000 characters" in embedded.text
        assert isinstance(bounded[3], TextResultPart)
        assert "truncated" in bounded[3].text
        assert bounded[4] == parts[4]
        assert bounded[5] == parts[5]

    def test_small_content_is_untouched(self) -> None:
        """Content inside the budget comes back identical."""
        parts: list[ToolResultPart] = [TextResultPart("short"), StructuredResultPart(content={"ok": True})]
        assert bound_result_parts(parts, _BOUND) == parts


class TestTrimmingKeepsCallsAndResultsTogether:
    """Item 34: trimming never leaves a tool result without its call."""

    def test_results_go_with_the_call_they_answer(self) -> None:
        """Removing the assistant tool-call message removes its results too."""
        big_arguments = {"blob": "word " * 3000}
        call = ToolCall(id="c1", tool_name="mcp-srv", function_name="mcp-srv.put", arguments=big_arguments)
        result = ToolResult(call_id="c1", success=True, result="ok", error=None, duration_ms=1.0)
        messages = [
            Message(role="system", content="sys"),
            Message(role="assistant", content="", tool_calls=[call]),
            Message(role="tool", content="", tool_results=[result]),
            Message(role="assistant", content="stored"),
            Message(role="user", content="next question"),
        ]
        trimmed = Orchestrator.trim_messages_to_context_window(messages, 1000)

        assert "tool" not in [message.role for message in trimmed]
        assert [message.content for message in trimmed] == ["sys", "stored", "next question"]


def _session(messages: list[Message], created_at: datetime | None = None) -> Session:
    """Build a session carrying the given history.

    Args:
        messages: Conversation history.
        created_at: Creation timestamp, defaulting to now.

    Returns:
        Session: The session.
    """
    now = datetime.now(tz=UTC)
    return Session(
        id="s1",
        name="multipart",
        created_at=created_at or now,
        updated_at=now,
        provider="loopback",
        model="m",
        messages=messages,
    )


class _BrokenTimestamp(datetime):
    """A timestamp whose rendering fails after the transaction has begun."""

    def isoformat(self, sep: str = "T", timespec: str = "auto") -> str:
        """Fail on rendering.

        Args:
            sep: Ignored.
            timespec: Ignored.

        Raises:
            RuntimeError: Always.
        """
        message = f"timestamp source failed ({sep}, {timespec})"
        raise RuntimeError(message)


class TestSessionPersistence:
    """Blocker 2: multi-part history saves, loads and never wedges a save."""

    def test_multipart_error_result_round_trips(self, tmp_path: Path) -> None:
        """Every part kind and the error flag survive a save and a load.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        parts: list[ToolResultPart] = [
            TextResultPart("text"),
            ImageResultPart(data=_noise_png(8, 8), mime_type="image/png"),
            AudioResultPart(data="AAAA", mime_type="audio/wav"),
            ResourceLinkPart(uri="file:///a", name="a", mime_type="text/plain", description="d"),
            EmbeddedResourcePart(uri="file:///b", text="inline"),
            StructuredResultPart(content={"n": 1, "nested": {"k": [1, 2]}}),
        ]
        result = ToolResult(call_id="c1", success=True, result="text", error=None, duration_ms=2.0, content=parts, is_error=True)
        store = SessionStore(db_path=tmp_path / "s.db")
        store.save(_session(_tool_turn(result)))

        loaded = store.load("s1")
        assert loaded is not None
        restored = loaded.messages[1].tool_results
        assert restored is not None
        assert restored[0].content == parts
        assert restored[0].is_error is True
        assert restored[0].result == "text"

    def test_failure_inside_the_transaction_rolls_back(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A non-SQLite failure mid-transaction issues an explicit ROLLBACK.

        The store's connections are real; they are only instrumented with
        SQLite's own statement trace so the test can see what was executed.

        Args:
            tmp_path: Pytest-provided temporary directory.
            monkeypatch: Pytest monkeypatch fixture.
        """
        store = SessionStore(db_path=tmp_path / "s.db")
        statements: list[str] = []
        real_connect: Callable[..., sqlite3.Connection] = sqlite3.connect

        def traced_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
            """Open a real connection that records every statement it runs.

            Args:
                *args: Positional arguments for :func:`sqlite3.connect`.
                **kwargs: Keyword arguments for :func:`sqlite3.connect`.

            Returns:
                sqlite3.Connection: The traced connection.
            """
            connection = real_connect(*args, **kwargs)
            connection.set_trace_callback(statements.append)
            return connection

        monkeypatch.setattr(sqlite3, "connect", traced_connect)
        broken = _BrokenTimestamp(2026, 1, 1, tzinfo=UTC)
        with pytest.raises(RuntimeError, match="timestamp source failed"):
            store.save(_session([], created_at=broken))

        assert "BEGIN IMMEDIATE" in statements
        assert "ROLLBACK" in statements
        assert "COMMIT" not in statements
        monkeypatch.setattr(sqlite3, "connect", real_connect)
        store.save(_session([Message(role="user", content="after")]))
        loaded = store.load("s1")
        assert loaded is not None
        assert loaded.messages[0].content == "after"

    def test_unencodable_payload_fails_before_taking_the_lock(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A payload JSON cannot express is rejected before BEGIN IMMEDIATE.

        Args:
            tmp_path: Pytest-provided temporary directory.
            monkeypatch: Pytest monkeypatch fixture.
        """
        store = SessionStore(db_path=tmp_path / "s.db")
        statements: list[str] = []
        real_connect: Callable[..., sqlite3.Connection] = sqlite3.connect

        def traced_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
            """Open a real connection that records every statement it runs.

            Args:
                *args: Positional arguments for :func:`sqlite3.connect`.
                **kwargs: Keyword arguments for :func:`sqlite3.connect`.

            Returns:
                sqlite3.Connection: The traced connection.
            """
            connection = real_connect(*args, **kwargs)
            connection.set_trace_callback(statements.append)
            return connection

        result = ToolResult(call_id="c1", success=True, result={1, 2}, error=None, duration_ms=1.0)
        monkeypatch.setattr(sqlite3, "connect", traced_connect)
        with pytest.raises(TypeError):
            store.save(_session(_tool_turn(result)))
        assert "BEGIN IMMEDIATE" not in statements


class TestSchemaArgumentSummary:
    """Item 33: a raw input schema renders as a readable argument list."""

    def test_renders_types_optionality_and_combinators(self) -> None:
        """Required, optional, arrays, unions, enums and refs all render."""
        schema: dict[str, object] = {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "limit": {"type": ["integer", "null"]},
                "tags": {"type": "array", "items": {"type": "string"}},
                "mode": {"enum": ["fast", "slow"]},
                "target": {"$ref": "#/$defs/Target"},
                "either": {"anyOf": [{"type": "string"}, {"type": "number"}]},
                "free": {},
            },
            "required": ["path", "target"],
        }
        rendered = render_schema_parameters(schema)
        assert rendered == (
            'path: string, limit?: integer|null, tags?: array[string], mode?: "fast"|"slow", '
            "target: Target, either?: string|number, free?: any"
        )

    def test_signature_prefers_the_input_schema(self) -> None:
        """``signature`` reads ``input_schema`` when it is set."""
        function = ToolFunction(
            name="mcp-srv.read",
            description="d",
            parameters=[],
            returns="text",
            input_schema={"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
        )
        assert function.signature == "mcp-srv.read(path: string) -> text"
