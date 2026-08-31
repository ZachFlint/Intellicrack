# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gates for S16-D10: Gemini 3.x ``thought_signature`` round-trip.

Gemini 3.x attaches an opaque ``thought_signature`` to the ``Part`` that
carries a ``function_call``.  When a multi-turn tool chain resumes (the
assistant's function-call turn is replayed back to the API alongside the
tool result), Gemini rejects the request with ``400 INVALID_ARGUMENT:
Function call is missing a thought_signature`` unless that signature is
echoed back verbatim on the replayed ``function_call`` part.

These gates use only real ``google.genai.types`` objects (the SDK's own
data model) as the oracle for the Gemini wire shape, and exercise
``GoogleProvider``'s own extraction (``_parse_response`` /
``_extract_function_calls``) and rebuild (``_convert_messages_to_provider_format``
via the public ``convert_messages_to_provider_format`` wrapper) code paths
directly. No network I/O and no mocking of the code under test.
"""

from __future__ import annotations

import base64
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any, cast

from google.genai.types import (
    Candidate,
    Content,
    FinishReason,
    FunctionCall,
    GenerateContentResponse,
    Part,
)

from intellicrack.core.types import Message, ToolCall
from intellicrack.providers.google import GoogleProvider


_parse_response: Any = getattr(GoogleProvider, "_parse_response")
_extract_function_calls: Any = getattr(GoogleProvider, "_extract_function_calls")

_RAW_SIGNATURE: bytes = b"\x00\x01opaque-gemini-3-thought-signature\xff\xfe\x02"


def _response_with_signed_function_call(function_name: str, args: dict[str, object]) -> GenerateContentResponse:
    """Build a real Gemini response whose function-call part carries a signature.

    Args:
        function_name: Name of the function the model "called".
        args: Arguments dict attached to the function call.

    Returns:
        GenerateContentResponse: A response with one candidate whose single
        part carries both ``function_call`` and ``thought_signature``.
    """
    fc = FunctionCall(name=function_name, args=args)
    part = Part(function_call=fc, thought_signature=_RAW_SIGNATURE)
    content_obj = Content(parts=[part], role="model")
    candidate = Candidate(content=content_obj, finish_reason=FinishReason.STOP)
    return GenerateContentResponse(candidates=[candidate])


class TestThoughtSignatureExtraction:
    """Gates on capturing ``thought_signature`` during response parsing."""

    def test_parse_response_captures_thought_signature(self) -> None:
        """``_parse_response`` stores the part's signature on the ``ToolCall``.

        Mutation caught: dropping the signature capture (reverting to the
        pre-fix implementation that only reads ``response.function_calls``)
        leaves ``ToolCall.thought_signature`` as ``None``; this assertion
        fails.
        """
        response = _response_with_signed_function_call("hex_editor.open_file", {"path": "/bin/target"})

        _content, tool_calls = _parse_response(response)

        assert len(tool_calls) == 1
        assert tool_calls[0].thought_signature == base64.b64encode(_RAW_SIGNATURE).decode("ascii")

    def test_extract_function_calls_captures_thought_signature(self) -> None:
        """``_extract_function_calls`` (streaming path) also stores the signature.

        Mutation caught: same as above but for the streaming-chunk helper,
        which has its own extraction path.
        """
        response = _response_with_signed_function_call("hex_editor.open_file", {"path": "/bin/target"})

        tool_calls = _extract_function_calls(response)

        assert len(tool_calls) == 1
        assert tool_calls[0].thought_signature == base64.b64encode(_RAW_SIGNATURE).decode("ascii")

    def test_function_call_without_signature_yields_none(self) -> None:
        """A function-call part with no signature leaves the field ``None``.

        Backward-compatibility gate: models/responses that never emit a
        signature (pre-Gemini-3.x) must not synthesize one.

        Mutation caught: unconditionally setting a signature (e.g. an empty
        string sentinel) instead of ``None`` would fail the ``is None`` check.
        """
        fc = FunctionCall(name="hex_editor.open_file", args={"path": "/bin/target"})
        part = Part(function_call=fc)
        content_obj = Content(parts=[part], role="model")
        candidate = Candidate(content=content_obj, finish_reason=FinishReason.STOP)
        response = GenerateContentResponse(candidates=[candidate])

        _content, tool_calls = _parse_response(response)

        assert len(tool_calls) == 1
        assert tool_calls[0].thought_signature is None


class TestThoughtSignatureRoundTrip:
    """Gates on the extract -> rebuild round trip that fixes the 400 error."""

    def test_signature_survives_extract_then_rebuild_for_continuation(self) -> None:
        """The signature captured on extraction reappears on the rebuilt part.

        This is the exact failure mode from S16-D10: approve
        ``hex_editor.open_file`` (turn 1, captured here via
        ``_parse_response``), then the orchestrator replays the assistant's
        function-call turn back to Gemini for the tool-result continuation
        (turn 2, built here via ``convert_messages_to_provider_format``).
        The rebuilt ``function_call`` part must carry the *same*
        ``thought_signature`` bytes Gemini originally attached, or Gemini
        rejects the continuation with ``400 INVALID_ARGUMENT: Function call
        is missing a thought_signature``.

        Mutation caught: dropping the re-attach step in
        ``_build_function_call_part`` (i.e. reverting to a bare
        ``{"function_call": {...}}`` dict) removes the ``thought_signature``
        key entirely; the ``"thought_signature" in fc_part`` assertion fails.
        """
        response = _response_with_signed_function_call("hex_editor.open_file", {"path": "/bin/target"})
        _content, tool_calls = _parse_response(response)
        assert tool_calls[0].thought_signature is not None

        assistant_msg = Message(
            role="assistant",
            content="",
            tool_calls=tool_calls,
            timestamp=datetime.now(tz=UTC),
        )

        provider = GoogleProvider()
        rebuilt = provider.convert_messages_to_provider_format([assistant_msg])

        assert len(rebuilt) == 1
        parts = cast("list[dict[str, object]]", rebuilt[0]["parts"])
        assert len(parts) == 1
        fc_part = parts[0]

        assert "thought_signature" in fc_part
        assert fc_part["thought_signature"] == _RAW_SIGNATURE

        fc_dict = cast("dict[str, object]", fc_part["function_call"])
        assert fc_dict["name"] == "hex_editor.open_file"
        assert fc_dict["args"] == {"path": "/bin/target"}

    def test_missing_signature_omits_key_on_rebuild(self) -> None:
        """A ``ToolCall`` with no signature rebuilds without the key at all.

        Backward-compatibility gate: models that never emitted a signature
        must not have a fabricated ``thought_signature`` key injected into
        the replayed request, which would itself be malformed.

        Mutation caught: unconditionally adding ``"thought_signature": None``
        (or ``b""``) to every rebuilt part regardless of source data would
        make this assertion (``"thought_signature" not in fc_part``) fail.
        """
        tc = ToolCall(
            id="call_0",
            tool_name="hex_editor",
            function_name="hex_editor.open_file",
            arguments={"path": "/bin/target"},
        )
        assistant_msg = Message(
            role="assistant",
            content="",
            tool_calls=[tc],
            timestamp=datetime.now(tz=UTC),
        )

        provider = GoogleProvider()
        rebuilt = provider.convert_messages_to_provider_format([assistant_msg])

        parts = cast("list[dict[str, object]]", rebuilt[0]["parts"])
        fc_part = parts[0]
        assert "thought_signature" not in fc_part


class TestToolCallDataclassPersistenceRoundTrip:
    """Gates proving ``thought_signature`` is a real, persisted dataclass field.

    ``core/session.py`` persists conversation history via
    ``asdict(message)`` / reconstructs it via ``ToolCall(**data)``.  These
    gates prove the signature is not merely an in-memory/same-instance
    artifact of ``GoogleProvider`` but survives that exact
    serialize-to-dict / reconstruct-from-dict cycle, which is what a real
    save-then-reload of a conversation session performs.
    """

    def test_thought_signature_survives_asdict_and_reconstruction(self) -> None:
        """``asdict`` -> ``ToolCall(**data)`` preserves the signature value.

        Mutation caught: if ``thought_signature`` were tracked out-of-band
        (e.g. a provider-instance-keyed cache) rather than as a real
        dataclass field, ``asdict`` would never see it and this
        reconstruction would silently lose it (or ``ToolCall(**data)``
        would not accept the key at all).
        """
        encoded_signature = base64.b64encode(_RAW_SIGNATURE).decode("ascii")
        original = ToolCall(
            id="call_0",
            tool_name="hex_editor",
            function_name="hex_editor.open_file",
            arguments={"path": "/bin/target"},
            thought_signature=encoded_signature,
        )

        persisted: dict[str, Any] = asdict(original)
        restored = ToolCall(**persisted)

        assert restored.thought_signature == encoded_signature
        assert restored == original

    def test_none_thought_signature_survives_asdict_and_reconstruction(self) -> None:
        """A ``None`` signature also survives the persistence round trip.

        Mutation caught: a reconstruction path that special-cased missing
        keys instead of accepting an explicit ``None`` would raise or
        silently coerce the value; both would break this assertion.
        """
        original = ToolCall(
            id="call_0",
            tool_name="hex_editor",
            function_name="hex_editor.open_file",
            arguments={"path": "/bin/target"},
        )
        assert original.thought_signature is None

        persisted: dict[str, Any] = asdict(original)
        restored = ToolCall(**persisted)

        assert restored.thought_signature is None
        assert restored == original
