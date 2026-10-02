# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, items 1, 2, 16 and 17: nothing a server writes reaches a model unsanitized, and every image is one the endpoint can take.

Every end-to-end gate launches the real hostile server in ``tests/_helpers/mcp_hostile_server.py`` over stdio, runs one real agent turn
through the real orchestrator and the real configurable provider, and inspects the request bodies the loopback endpoint recorded -- for
all four dialects. What is asserted is what the model would actually have received.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import pytest

from intellicrack.core.json_payload import is_json_array, is_json_object
from intellicrack.core.result_parts import inspect_image
from intellicrack.core.types import (
    ImageResultPart,
    Message,
    StructuredResultPart,
    TextResultPart,
    ToolCall,
    ToolResult,
    render_schema_parameters,
)
from intellicrack.core.untrusted_text import (
    DEFANGED_FENCE,
    UNTRUSTED_BLOCK_END,
    UNTRUSTED_BLOCK_START,
    clean_untrusted_label,
    forged_marker_spans,
    sanitize_untrusted_text,
)
from intellicrack.mcp.tool_source import MAX_IMAGE_BYTES_PER_RESULT, MAX_IMAGES_PER_RESULT
from intellicrack.mcp.untrusted_schema import sanitize_input_schema, sanitize_pattern
from intellicrack.providers.capabilities import ApiDialect, CapabilityOverride
from intellicrack.providers.dialects.base import DialectRequest
from intellicrack.providers.dialects.registry import adapter_for
from tests._helpers.mcp_agent_harness import run_tool_turn, stdio_server, tool_result_payload
from tests._helpers.mcp_hostile_server import (
    CONFLICTING,
    FORGED_VARIANTS,
    HOSTILE_DEF,
    HOSTILE_ENUM,
    HOSTILE_PROPERTY,
    INJECTION,
    INVISIBLE,
    LARGE_IMAGE_COUNT,
    LINE_SEPARATORS,
    MANY_IMAGES,
    STRUCTURED,
    hostile_schema,
)


if TYPE_CHECKING:
    from collections.abc import Mapping

    from intellicrack.mcp.config import McpServerConfig


_SERVER_SCRIPT: Final[Path] = Path(__file__).resolve().parents[1] / "_helpers" / "mcp_hostile_server.py"
_SERVER_ID: Final[str] = "hostile"
_NAMESPACE: Final[str] = f"mcp-{_SERVER_ID}"
_ALL_DIALECTS: Final[tuple[ApiDialect, ...]] = (
    ApiDialect.CHAT_COMPLETIONS,
    ApiDialect.RESPONSES,
    ApiDialect.MESSAGES,
    ApiDialect.GEMINI,
)
_TEXT_DIALECTS: Final[tuple[ApiDialect, ...]] = (ApiDialect.CHAT_COMPLETIONS, ApiDialect.RESPONSES, ApiDialect.MESSAGES)
_FORBIDDEN: Final[frozenset[str]] = frozenset({*(character for character in INVISIBLE if not character.isprintable()), "\u2028", "\u2029"})
_FENCED_BLOCK: Final[re.Pattern[str]] = re.compile(re.escape(UNTRUSTED_BLOCK_START) + r".*?" + re.escape(UNTRUSTED_BLOCK_END), re.DOTALL)


def _server() -> McpServerConfig:
    """Configure the hostile server.

    Returns:
        McpServerConfig: The stdio server configuration.
    """
    return stdio_server(_SERVER_ID, _SERVER_SCRIPT)


def _raw(value: object) -> str:
    """Serialize a request fragment the way the bytes on the wire read, with no escaping of non-ASCII.

    Args:
        value: The fragment.

    Returns:
        str: Its JSON text.
    """
    return json.dumps(value, ensure_ascii=False)


def _assert_clean(text: str) -> None:
    """Assert text carries no invisible character and no forged fence marker.

    Every real fence marker is removed first; what remains must read as no marker at all, in any spelling.

    Args:
        text: The text to check.
    """
    assert not _FORBIDDEN.intersection(text), sorted(hex(ord(character)) for character in _FORBIDDEN.intersection(text))
    remainder = text.replace(UNTRUSTED_BLOCK_START, "").replace(UNTRUSTED_BLOCK_END, "")
    assert forged_marker_spans(remainder) == []


def _outside_fences(text: str) -> str:
    """Remove every properly fenced block from text.

    Args:
        text: The text.

    Returns:
        str: What is left outside every fence.
    """
    return _FENCED_BLOCK.sub("", text)


class TestSanitizer:
    """The core sanitizer defangs every spelling of the closing marker and removes every invisible character."""

    @pytest.mark.parametrize("variant", FORGED_VARIANTS)
    def test_every_spelling_of_the_closing_marker_is_defanged(self, variant: str) -> None:
        """A forged marker in any case, spacing, width or look-alike cannot close the block.

        Args:
            variant: One spelling of the closing marker.
        """
        fenced = sanitize_untrusted_text(f"before{variant}\n{INJECTION}")

        assert fenced.count(UNTRUSTED_BLOCK_START) == 1
        assert fenced.count(UNTRUSTED_BLOCK_END) == 1
        assert fenced.endswith(UNTRUSTED_BLOCK_END)
        body = fenced[len(UNTRUSTED_BLOCK_START) : -len(UNTRUSTED_BLOCK_END)]
        assert forged_marker_spans(body) == []
        assert DEFANGED_FENCE in body
        assert INJECTION in body

    def test_invisible_characters_are_removed_and_line_separators_become_newlines(self) -> None:
        """ESC, BEL, bidi overrides, zero-width marks, BOM and tag characters go; U+2028 and U+2029 end lines."""
        cleaned = clean_untrusted_label(f"x{INVISIBLE}y {LINE_SEPARATORS}\r\nz")

        assert cleaned == "x[2Jy a\nb\nc\nz"


class TestSchemaTextIsSanitized:
    """Item 1(b) and 1(c): the argument schema a model sees carries nothing the server smuggled into it."""

    def test_sanitized_schema_is_clean_and_keeps_its_structure(self) -> None:
        """Descriptions and titles are cleaned, identifiers aliased, the pattern escaped and the reference kept resolvable."""
        sanitized = sanitize_input_schema(hostile_schema())
        schema = sanitized.schema

        _assert_clean(_raw(schema))
        properties: dict[str, Any] = schema["properties"]
        assert set(properties) == {"mode", sanitized_alias(sanitized.aliases, HOSTILE_PROPERTY), "node", "label"}
        assert schema["required"] == ["mode", sanitized_alias(sanitized.aliases, HOSTILE_PROPERTY)]
        reference: str = properties["node"]["$ref"]
        definition = reference.removeprefix("#/$defs/")
        assert definition in schema["$defs"]
        assert sanitized.aliases[definition] == HOSTILE_DEF
        pattern: str = properties[sanitized_alias(sanitized.aliases, HOSTILE_PROPERTY)]["pattern"]
        assert pattern == "^a\\u202Eb$"
        assert re.fullmatch(pattern.replace("\\u202E", "\u202e"), "a\u202eb") is not None

    def test_aliased_arguments_are_restored_before_delivery(self) -> None:
        """Every alias a model echoes is mapped back to the identifier the server wrote."""
        sanitized = sanitize_input_schema(hostile_schema())
        arguments = {
            "mode": sanitized_alias(sanitized.aliases, HOSTILE_ENUM),
            sanitized_alias(sanitized.aliases, HOSTILE_PROPERTY): "free text stays as it is",
        }

        restored = sanitized.restore_arguments(arguments)

        assert restored == {"mode": HOSTILE_ENUM, HOSTILE_PROPERTY: "free text stays as it is"}

    def test_pattern_escaping_does_not_change_what_matches(self) -> None:
        r"""An unsafe character written as an identity escape becomes the equivalent ``\uXXXX`` escape."""
        assert sanitize_pattern("^[a\\\u202e]+$") == "^[a\\u202E]+$"
        assert sanitize_pattern("^\\d{3}-plain$") == "^\\d{3}-plain$"

    def test_signature_renderer_cleans_names_references_and_values(self) -> None:
        """The prompt's one-line signature never writes a server's raw name, reference or value."""
        rendered = render_schema_parameters(hostile_schema())

        _assert_clean(rendered)
        assert "target[2J" in rendered


def sanitized_alias(aliases: Mapping[str, str], original: str) -> str:
    """Find the alias advertised for one original identifier.

    Args:
        aliases: Alias to original mapping.
        original: The identifier as the server wrote it.

    Returns:
        str: Its alias.
    """
    matches = [alias for alias, source in dict(aliases).items() if source == original]
    assert len(matches) == 1, f"expected one alias for {original!r}, found {matches}"
    return matches[0]


@pytest.mark.parametrize("dialect", _ALL_DIALECTS)
class TestEverythingTheModelReadsIsClean:
    """Item 1(a), (b) and (d) end to end, on every dialect."""

    def test_structured_output_is_sanitized_on_every_dialect(self, tmp_path: Path, dialect: ApiDialect) -> None:
        """Structured output carrying forged markers and invisible characters reaches the endpoint clean and isolated.

        Args:
            tmp_path: Per-test directory.
            dialect: The dialect under test.
        """
        results, bodies = run_tool_turn(tmp_path, dialect, _server(), f"{_NAMESPACE}.leak", {})

        assert len(bodies) == 2
        _assert_clean(_raw(bodies[0]))
        payload = tool_result_payload(dialect, bodies[1])
        text = _raw(payload)
        _assert_clean(text)
        assert results[0].success is True
        if dialect is ApiDialect.GEMINI:
            response: dict[str, Any] = payload[0]["function_response"]["response"]
            assert set(response) == {"output"}
            assert isinstance(response["output"], dict)
            assert response["output"]["count"] == STRUCTURED["count"]
        else:
            assert INJECTION in text
            assert INJECTION not in _outside_fences(json.loads(text)[0].get("content") or json.loads(text)[0].get("output") or "")

    def test_structured_output_without_a_restatement_is_sanitized(self, tmp_path: Path, dialect: ApiDialect) -> None:
        """Structured output sent as the only copy of its data reaches the endpoint clean, fenced on text dialects.

        Args:
            tmp_path: Per-test directory.
            dialect: The dialect under test.
        """
        results, bodies = run_tool_turn(tmp_path, dialect, _server(), f"{_NAMESPACE}.structured_only", {})

        assert not any(isinstance(part, TextResultPart) and part.mirrors_structured for part in results[0].content or ())
        payload = tool_result_payload(dialect, bodies[1])
        text = _raw(payload)
        _assert_clean(text)
        assert text.count(INJECTION) == 1
        if dialect is not ApiDialect.GEMINI:
            assert INJECTION not in _outside_fences(json.loads(text)[0].get("content") or json.loads(text)[0].get("output") or "")

    def test_schema_text_is_clean_and_the_call_reaches_the_server_verbatim(self, tmp_path: Path, dialect: ApiDialect) -> None:
        """The advertised schema carries nothing hostile, yet the server receives exactly the identifiers it published.

        Args:
            tmp_path: Per-test directory.
            dialect: The dialect under test.
        """
        aliases = dict(sanitize_input_schema(hostile_schema()).aliases)
        arguments = {"mode": sanitized_alias(aliases, HOSTILE_ENUM), sanitized_alias(aliases, HOSTILE_PROPERTY): "ab"}

        results, bodies = run_tool_turn(tmp_path, dialect, _server(), f"{_NAMESPACE}.schema", arguments)

        _assert_clean(_raw(bodies[0]))
        assert INJECTION in _raw(bodies[0])
        structured = next(part for part in results[0].content or () if isinstance(part, StructuredResultPart))
        expected = json.dumps({"mode": HOSTILE_ENUM, HOSTILE_PROPERTY: "ab"}, ensure_ascii=True, sort_keys=True)
        assert structured.content == {"received": expected}

    def test_a_protocol_error_message_is_fenced(self, tmp_path: Path, dialect: ApiDialect) -> None:
        """A server's error text reaches the model inside the fence, stripped of escapes.

        Args:
            tmp_path: Per-test directory.
            dialect: The dialect under test.
        """
        results, bodies = run_tool_turn(tmp_path, dialect, _server(), f"{_NAMESPACE}.boom", {})

        assert results[0].success is False
        assert results[0].error is not None
        assert INJECTION in results[0].error
        assert INJECTION not in _outside_fences(results[0].error)
        _assert_clean(_raw(tool_result_payload(dialect, bodies[1])))


class TestOneRepresentationIsSent:
    """Item 17: a text block that restates structured output is not sent alongside it."""

    @pytest.mark.parametrize("dialect", _TEXT_DIALECTS)
    def test_text_dialects_send_the_structured_data_once(self, tmp_path: Path, dialect: ApiDialect) -> None:
        """The data appears once, as the fenced text the server wrote, with no second structured rendering.

        Args:
            tmp_path: Per-test directory.
            dialect: The dialect under test.
        """
        results, bodies = run_tool_turn(tmp_path, dialect, _server(), f"{_NAMESPACE}.leak", {})

        mirrors = [part for part in results[0].content or () if isinstance(part, TextResultPart) and part.mirrors_structured]
        assert len(mirrors) == 1
        text = _raw(tool_result_payload(dialect, bodies[1]))
        assert text.count(INJECTION) == 1

    def test_gemini_sends_the_structured_object_alone(self, tmp_path: Path) -> None:
        """Gemini receives the object natively and not the text that restates it.

        Args:
            tmp_path: Per-test directory.
        """
        _, bodies = run_tool_turn(tmp_path, ApiDialect.GEMINI, _server(), f"{_NAMESPACE}.leak", {})

        response = tool_result_payload(ApiDialect.GEMINI, bodies[1])[0]["function_response"]["response"]
        assert _raw(response).count(INJECTION) == 1
        assert "text" not in response["output"]


class TestGeminiFieldsAreNotOverwritten:
    """Item 16: structured fields named ``content`` and ``error`` survive on Gemini."""

    def test_reserved_field_names_reach_gemini_intact(self, tmp_path: Path) -> None:
        """The tool's own ``content`` and ``error`` fields arrive under ``output``, and no error is reported.

        Args:
            tmp_path: Per-test directory.
        """
        _, bodies = run_tool_turn(tmp_path, ApiDialect.GEMINI, _server(), f"{_NAMESPACE}.conflicting", {})

        response = tool_result_payload(ApiDialect.GEMINI, bodies[1])[0]["function_response"]["response"]
        assert response == {"output": CONFLICTING}

    def test_a_failed_call_reports_its_error_beside_the_output(self) -> None:
        """A failure goes to ``error`` without replacing a structured field of that name."""
        adapter = adapter_for(ApiDialect.GEMINI)
        result = ToolResult(
            call_id="c",
            success=True,
            result=None,
            error=None,
            duration_ms=1.0,
            content=[StructuredResultPart(content=dict(CONFLICTING))],
            is_error=True,
        )

        [part] = adapter.render_tool_result(result, adapter.default_capabilities(), function_name="f")

        response = part["function_response"]["response"]
        assert response["output"] == CONFLICTING
        assert response["error"] == "tool reported an error"


def _image_parts(results: list[ToolResult]) -> list[ImageResultPart]:
    """Collect the image parts of the only tool result.

    Args:
        results: The turn's tool results.

    Returns:
        list[ImageResultPart]: Its images.
    """
    return [part for part in results[0].content or () if isinstance(part, ImageResultPart)]


def _texts(results: list[ToolResult]) -> list[str]:
    """Collect the text parts of the only tool result.

    Args:
        results: The turn's tool results.

    Returns:
        list[str]: Their text.
    """
    return [part.text for part in results[0].content or () if isinstance(part, TextResultPart)]


def _sent_images(dialect: ApiDialect, payload: list[Any]) -> list[tuple[str, str]]:
    """Read every image a request sends natively, as ``(mime type, base64)``.

    Args:
        dialect: The request's dialect.
        payload: The tool-result items of the request.

    Returns:
        list[tuple[str, str]]: The images, in order.
    """
    found: list[tuple[str, str]] = []
    for item in payload:
        if dialect is ApiDialect.MESSAGES:
            content: object = item.get("content")
            blocks: list[dict[str, Any]] = content if is_json_array(content) else []
            found.extend((block["source"]["media_type"], block["source"]["data"]) for block in blocks if block.get("type") == "image")
        elif dialect is ApiDialect.GEMINI:
            if "inline_data" in item:
                found.append((item["inline_data"]["mime_type"], item["inline_data"]["data"]))
        else:
            content = item.get("content")
            blocks = content if is_json_array(content) else []
            for block in blocks:
                url: object = block.get("image_url")
                if is_json_object(url):
                    url = url.get("url")
                if isinstance(url, str) and url.startswith("data:"):
                    header, _, data = url.partition(",")
                    found.append((header.removeprefix("data:").removesuffix(";base64"), data))
    return found


class TestImagesAreChecked:
    """Item 2: an image is validated, capped and sent only where the endpoint can take it."""

    def test_images_are_checked_where_the_server_hands_them_over(self, tmp_path: Path) -> None:
        """A mislabelled image is retyped by its bytes; one that is not base64 or not an image becomes a note.

        Args:
            tmp_path: Per-test directory.
        """
        results, _ = run_tool_turn(tmp_path, ApiDialect.MESSAGES, _server(), f"{_NAMESPACE}.images", {})

        images = _image_parts(results)
        assert [image.mime_type for image in images] == ["image/png", "image/jpeg", "image/bmp"]
        notes = [text for text in _texts(results) if text.startswith("[the server sent an image")]
        assert len(notes) == 2
        assert any("not valid base64" in note for note in notes)
        assert any("'text/plain' is not an image type" in note for note in notes)

    @pytest.mark.parametrize("dialect", _ALL_DIALECTS)
    def test_every_image_sent_is_one_the_endpoint_accepts(self, tmp_path: Path, dialect: ApiDialect) -> None:
        """Only PNG and JPEG go natively; the BMP is described with the reason it was not sent.

        Args:
            tmp_path: Per-test directory.
            dialect: The dialect under test.
        """
        _, bodies = run_tool_turn(tmp_path, dialect, _server(), f"{_NAMESPACE}.images", {})

        payload = tool_result_payload(dialect, bodies[1])
        sent = _sent_images(dialect, payload)
        assert [mime for mime, _ in sent] == ["image/png", "image/jpeg"]
        for mime, data in sent:
            inspection = inspect_image(data, mime)
            assert inspection.problem is None
            assert inspection.mime_type == mime
        assert "image/bmp" in _raw(payload)
        assert "not shown: this endpoint accepts only" in _raw(payload)

    def test_gif_is_described_on_gemini_and_sent_to_messages(self, tmp_path: Path) -> None:
        """Gemini takes no GIF, so it is described there; Anthropic takes it natively.

        Args:
            tmp_path: Per-test directory.
        """
        _, gemini = run_tool_turn(tmp_path / "g", ApiDialect.GEMINI, _server(), f"{_NAMESPACE}.gif", {})
        _, messages = run_tool_turn(tmp_path / "m", ApiDialect.MESSAGES, _server(), f"{_NAMESPACE}.gif", {})

        assert _sent_images(ApiDialect.GEMINI, tool_result_payload(ApiDialect.GEMINI, gemini[1])) == []
        assert "image/gif" in _raw(tool_result_payload(ApiDialect.GEMINI, gemini[1]))
        assert [mime for mime, _ in _sent_images(ApiDialect.MESSAGES, tool_result_payload(ApiDialect.MESSAGES, messages[1]))] == [
            "image/gif",
        ]

    def test_image_count_is_capped(self, tmp_path: Path) -> None:
        """Past the per-result cap, images are described rather than kept.

        Args:
            tmp_path: Per-test directory.
        """
        results, _ = run_tool_turn(tmp_path, ApiDialect.MESSAGES, _server(), f"{_NAMESPACE}.many_images", {})

        assert len(_image_parts(results)) == MAX_IMAGES_PER_RESULT
        described = [text for text in _texts(results) if f"at most {MAX_IMAGES_PER_RESULT} images" in text]
        assert len(described) == MANY_IMAGES - MAX_IMAGES_PER_RESULT

    def test_image_bytes_are_capped(self, tmp_path: Path) -> None:
        """Past the per-result byte budget, images are described rather than kept.

        Args:
            tmp_path: Per-test directory.
        """
        results, _ = run_tool_turn(tmp_path, ApiDialect.MESSAGES, _server(), f"{_NAMESPACE}.large_images", {})

        kept = _image_parts(results)
        assert 0 < len(kept) < LARGE_IMAGE_COUNT
        assert sum(len(base64.b64decode(image.data)) for image in kept) <= MAX_IMAGE_BYTES_PER_RESULT
        described = [text for text in _texts(results) if f"at most {MAX_IMAGE_BYTES_PER_RESULT} bytes of images" in text]
        assert len(described) == LARGE_IMAGE_COUNT - len(kept)


@pytest.mark.parametrize("dialect", _ALL_DIALECTS)
def test_a_bad_image_already_in_history_is_never_sent(dialect: ApiDialect) -> None:
    """An image recorded before the check existed is described, not sent, so it cannot break every later request.

    Args:
        dialect: The dialect under test.
    """
    adapter = adapter_for(dialect)
    vision = dataclasses.replace(adapter.default_capabilities(), supports_vision=True)
    history = [
        Message(role="user", content="look"),
        Message(role="assistant", content="", tool_calls=[ToolCall(id="c1", tool_name="mcp-x", function_name="mcp-x.shot", arguments={})]),
        Message(
            role="tool",
            content="",
            tool_results=[
                ToolResult(
                    call_id="c1",
                    success=True,
                    result=None,
                    error=None,
                    duration_ms=1.0,
                    content=[ImageResultPart(data="not-base64!!", mime_type="image/png")],
                ),
            ],
        ),
    ]
    body = adapter.build_request(DialectRequest(model="m", messages=history, capabilities=vision))

    text = _raw(body)
    assert "not-base64!!" not in text
    assert "not shown: the payload is not valid base64" in text


def test_capability_override_without_vision_describes_every_image(tmp_path: Path) -> None:
    """A model that takes no images gets a description saying so.

    Args:
        tmp_path: Per-test directory.
    """
    _, bodies = run_tool_turn(
        tmp_path,
        ApiDialect.MESSAGES,
        _server(),
        f"{_NAMESPACE}.images",
        {},
        overrides=CapabilityOverride(supports_vision=False, context_window=200_000),
    )

    payload = tool_result_payload(ApiDialect.MESSAGES, bodies[1])
    assert _sent_images(ApiDialect.MESSAGES, payload) == []
    assert "not shown: this model does not accept images" in _raw(payload)
