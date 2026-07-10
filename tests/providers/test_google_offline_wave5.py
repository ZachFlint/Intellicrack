# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Wave-5 offline falsifiable gates for GoogleProvider (findings #28, #31-#37, #39).

All nine findings from the group-07 audit that were NOT_RESOLVED for the Google
provider are gated here.  Every test uses only offline transport seams, real
``google.genai`` SDK types as independent oracles, and known-constant expected
values.  No mock replaces the SUT or any of its decision dependencies.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from typing import Any, cast, override

import google.genai as _real_genai
import httpx
import pytest
from google.genai import Client as GenaiClient
from google.genai.types import (
    Candidate,
    Content,
    FinishReason,
    FunctionCall,
    FunctionCallingConfigMode,
    GenerateContentResponse,
    GenerateContentResponseUsageMetadata,
    HttpOptions,
    Part,
    Tool,
)

from intellicrack.core.types import (
    Message,
    ProviderCredentials,
    ProviderError,
    ThinkingConfig as IntelliThinkingConfig,
    ToolCall,
    ToolChoice,
    ToolChoiceMode,
    ToolResult,
)
from intellicrack.providers.base import UsageInfo
from intellicrack.providers.google import GoogleProvider


_OFFLINE_PROBE_ERR: str = "offline probe"


class _FakeModelsApi:
    """Fake genai models namespace whose ``list()`` raises ``OSError``.

    Injected by ``_FakeGenaiClient`` so ``_connect_impl`` triggers the
    ``except (... OSError ...)`` branch in ``connect()`` without any
    outbound network request.
    """

    def list(self) -> list[object]:
        """Raise ``OSError`` to simulate an offline probe failure.

        Returns:
            list[object]: Never returns; always raises before producing a value.

        Raises:
            OSError: Always, to exercise the ``connect()`` error path.
        """
        raise OSError(_OFFLINE_PROBE_ERR)


class _FakeGenaiClient:
    """Minimal ``genai.Client`` stand-in for the ``#28`` env-var gate.

    Replaced via ``monkeypatch`` so ``_connect_impl`` never opens a socket
    while the full ``except``/``finally`` logic in ``connect()`` still runs.
    """

    def __init__(self, **_kwargs: object) -> None:
        """Construct with a ``models`` attribute backed by ``_FakeModelsApi``.

        Args:
            **_kwargs: Keyword arguments forwarded from the real ``Client``
                call (e.g. ``api_key=``); accepted but not used by the stub.
        """
        self.models: _FakeModelsApi = _FakeModelsApi()


_SENTINEL_ENV_KEY: str = "test-sentinel-gemini-env-99"
_DUMMY_TOOLS: list[Tool] = [Tool(function_declarations=[])]

_parse_response: Any = getattr(GoogleProvider, "_parse_response")
_extract_function_calls: Any = getattr(GoogleProvider, "_extract_function_calls")
_extract_visible_chunk_text: Any = getattr(GoogleProvider, "_extract_visible_chunk_text")
_extract_thinking_text: Any = getattr(GoogleProvider, "_extract_thinking_text")
_create_config: Any = getattr(GoogleProvider, "_create_config")
_extract_usage: Any = getattr(GoogleProvider, "_extract_usage")


def _build_sse_body(chunks: list[dict[str, object]]) -> bytes:
    """Build an SSE-formatted byte body from a list of Gemini chunk dicts.

    Args:
        chunks: Raw Gemini streaming response chunk dictionaries.

    Returns:
        bytes: UTF-8 SSE body; each chunk is a ``data: <json>`` line.
    """
    return b"".join(b"data: " + json.dumps(c).encode() + b"\n\n" for c in chunks)


def _make_google_provider_with_async_transport(
    transport: httpx.AsyncBaseTransport,
) -> GoogleProvider:
    """Construct a pre-connected GoogleProvider backed by a stub async transport.

    The real ``google.genai.Client`` is initialised with an ``HttpOptions``
    that routes all outbound requests through ``transport``, so every SDK
    serialisation and deserialisation layer runs without substitution.

    Args:
        transport: Stub transport that intercepts all async HTTP requests.

    Returns:
        GoogleProvider: Provider with ``connected=True`` and the stub-backed
        genai client injected as ``provider.client``.
    """
    provider = GoogleProvider()
    provider.connected = True
    provider.client = GenaiClient(
        api_key="offline-test-key",
        http_options=HttpOptions(httpx_async_client=httpx.AsyncClient(transport=transport)),
    )
    return provider


def _user_message(text: str = "hello") -> Message:
    """Build a minimal user :class:`Message` for provider calls.

    Args:
        text: Message content string.

    Returns:
        Message: A user-role message with a fixed timestamp.
    """
    return Message(role="user", content=text, timestamp=datetime.now(tz=UTC))


# ---------------------------------------------------------------------------
# Finding #28 — connect: GEMINI_API_KEY env-var clearing and restoration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_connect_gemini_api_key_restored_after_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GEMINI_API_KEY is restored in ``os.environ`` after ``connect`` raises.

    ``connect()`` pops GEMINI_API_KEY before building the genai client (so
    the SDK cannot silently prefer an ambient env key over the credentials
    key).  ``_FakeGenaiClient.models.list()`` raises ``OSError("offline
    probe")``, which falls into the ``except (... OSError ...) as e`` clause
    at google.py line 137 and is re-raised as
    ``ProviderError(_MSG_CONNECTION_FAILED)``.  The ``finally`` block at
    google.py lines 145-147 then restores GEMINI_API_KEY regardless of the
    exception.

    Oracle: ``_FakeGenaiClient`` injects a deterministic ``OSError``; the
    sentinel ``"test-sentinel-gemini-env-99"`` is set before the call and
    verified equal after the exception exits the ``with pytest.raises`` block.

    Mutation caught: removing ``os.environ["GEMINI_API_KEY"] = saved_gemini_key``
    from the ``finally`` block leaves the env var absent after connect fails
    (popped but never restored), so
    ``os.environ.get("GEMINI_API_KEY") != _SENTINEL_ENV_KEY``.
    """
    monkeypatch.setenv("GEMINI_API_KEY", _SENTINEL_ENV_KEY)
    monkeypatch.setattr(_real_genai, "Client", _FakeGenaiClient)
    provider = GoogleProvider()
    creds = ProviderCredentials(api_key="fake-offline-key")
    with pytest.raises(ProviderError, match="Connection failed"):
        await provider.connect(creds)
    assert os.environ.get("GEMINI_API_KEY") == _SENTINEL_ENV_KEY


# ---------------------------------------------------------------------------
# Finding #31 — chat_stream: text chunk accumulation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_chat_stream_yields_text_chunks_in_order() -> None:
    """``chat_stream`` yields each visible text chunk in source order.

    A stub async transport returns two SSE frames: ``"Hello"`` then
    ``" world"``.  The full ``_iter_google_stream`` loop runs against the
    real genai SDK; only the HTTP boundary is faked.  The collected strings
    must equal the two expected fragments in order.

    Oracle: SSE ``data:`` frames constructed from independently-known text
    values; the genai SDK deserialises them into ``GenerateContentResponse``
    objects with the same text.

    Mutation caught: removing ``yield visible_text`` from the stream loop
    produces an empty ``collected`` list; ``collected[0] != "Hello"`` fails.
    """
    chunks: list[dict[str, object]] = [
        {
            "candidates": [
                {
                    "content": {"parts": [{"text": "Hello"}], "role": "model"},
                    "index": 0,
                },
            ],
        },
        {
            "candidates": [
                {
                    "content": {"parts": [{"text": " world"}], "role": "model"},
                    "finishReason": "STOP",
                    "index": 0,
                },
            ],
            "usageMetadata": {
                "promptTokenCount": 5,
                "candidatesTokenCount": 2,
                "totalTokenCount": 7,
            },
        },
    ]
    sse_body = _build_sse_body(chunks)

    class _SseTransport(httpx.AsyncBaseTransport):
        @override
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                content=sse_body,
                headers={"content-type": "text/event-stream"},
            )

    provider = _make_google_provider_with_async_transport(_SseTransport())
    collected: list[str] = [
        chunk
        async for chunk in provider.chat_stream(
            messages=[_user_message("hello")],
            model="gemini-2.0-flash",
            max_tokens=64,
        )
    ]

    assert collected == ["Hello", " world"]


# ---------------------------------------------------------------------------
# Finding #32 — _parse_response
# ---------------------------------------------------------------------------


class TestParseResponse:
    """Offline unit gates for ``GoogleProvider._parse_response``.

    Oracle: real ``google.genai.types.GenerateContentResponse`` objects with
    known text and function-call payloads fed through the static helper.
    """

    def test_text_only_response_returns_content_and_empty_tool_calls(self) -> None:
        """Pure text response maps to the content string with no tool calls.

        Mutation caught: zeroing ``content`` inside ``_parse_response``
        returns an empty string; ``content == "Hello from Gemini"`` fails.
        """
        content_obj = Content(
            parts=[Part(text="Hello from Gemini")],
            role="model",
        )
        candidate = Candidate(content=content_obj, finish_reason=FinishReason.STOP)
        response = GenerateContentResponse(candidates=[candidate])

        content, tool_calls = _parse_response(response)

        assert content == "Hello from Gemini"
        assert tool_calls == []

    def test_function_call_response_returns_correct_tool_call(self) -> None:
        """A single function-call candidate produces one ToolCall with exact fields.

        Oracle: ``FunctionCall(name="analyze_binary", args={"path": "/bin/ls"})``
        must map to ``ToolCall(id="call_0", tool_name="analyze_binary",
        function_name="analyze_binary", arguments={"path": "/bin/ls"})``.

        Mutation caught: using the wrong index for the ``call_`` id (e.g.
        starting at 1) causes ``tool_calls[0].id == "call_1"``; assertion fails.
        """
        fc = FunctionCall(name="analyze_binary", args={"path": "/bin/ls"})
        content_obj = Content(parts=[Part(function_call=fc)], role="model")
        candidate = Candidate(content=content_obj, finish_reason=FinishReason.STOP)
        response = GenerateContentResponse(candidates=[candidate])

        content, tool_calls = _parse_response(response)

        assert len(tool_calls) == 1
        assert tool_calls[0].id == "call_0"
        assert tool_calls[0].tool_name == "analyze_binary"
        assert tool_calls[0].function_name == "analyze_binary"
        assert tool_calls[0].arguments == {"path": "/bin/ls"}
        assert not content


# ---------------------------------------------------------------------------
# Finding #33 — _extract_function_calls
# ---------------------------------------------------------------------------


class TestExtractFunctionCalls:
    """Offline unit gates for ``GoogleProvider._extract_function_calls``.

    Oracle: ``google.genai.types.FunctionCall`` objects with independently-
    known names and argument dicts.
    """

    def test_single_function_call_mapped_correctly(self) -> None:
        """A single ``FunctionCall`` produces one ``ToolCall`` with exact fields.

        Mutation caught: using ``fc.name`` directly as ``tool_name`` without
        the dotted-prefix split causes ``tool_name == "tool.sub"`` instead of
        ``"tool"`` for dotted names — but for a plain name the mutation of
        returning an empty ``args`` dict causes ``arguments == {}``.
        """
        fc = FunctionCall(name="analyze_binary", args={"path": "/bin/ls", "depth": 3})
        content_obj = Content(parts=[Part(function_call=fc)], role="model")
        candidate = Candidate(content=content_obj, finish_reason=FinishReason.STOP)
        response = GenerateContentResponse(candidates=[candidate])

        tool_calls = _extract_function_calls(response)

        assert len(tool_calls) == 1
        assert tool_calls[0].id == "call_0"
        assert tool_calls[0].tool_name == "analyze_binary"
        assert tool_calls[0].function_name == "analyze_binary"
        assert tool_calls[0].arguments == {"path": "/bin/ls", "depth": 3}

    def test_dotted_function_name_splits_tool_name_from_prefix(self) -> None:
        """Dotted ``function_name`` uses the prefix as ``tool_name``.

        Oracle: the implementation splits on ``"."`` and takes ``[0]``;
        ``"ghidra.decompile"`` → ``tool_name="ghidra"``,
        ``function_name="ghidra.decompile"``.

        Mutation caught: removing the split keeps ``tool_name == "ghidra.decompile"``
        instead of ``"ghidra"``; assertion fails.
        """
        fc = FunctionCall(name="ghidra.decompile", args={"address": "0x1000"})
        content_obj = Content(parts=[Part(function_call=fc)], role="model")
        candidate = Candidate(content=content_obj, finish_reason=FinishReason.STOP)
        response = GenerateContentResponse(candidates=[candidate])

        tool_calls = _extract_function_calls(response)

        assert len(tool_calls) == 1
        assert tool_calls[0].tool_name == "ghidra"
        assert tool_calls[0].function_name == "ghidra.decompile"
        assert tool_calls[0].arguments == {"address": "0x1000"}

    def test_multiple_function_calls_assigned_sequential_ids(self) -> None:
        """Multiple calls receive ``call_0``, ``call_1``, … in source order.

        Mutation caught: always emitting ``"call_0"`` for every call produces
        duplicate ids; ``tool_calls[1].id == "call_0"`` instead of ``"call_1"``.
        """
        fc0 = FunctionCall(name="read_mem", args={"addr": "0x400000"})
        fc1 = FunctionCall(name="write_patch", args={"offset": 8, "value": 144})
        content_obj = Content(
            parts=[Part(function_call=fc0), Part(function_call=fc1)],
            role="model",
        )
        candidate = Candidate(content=content_obj, finish_reason=FinishReason.STOP)
        response = GenerateContentResponse(candidates=[candidate])

        tool_calls = _extract_function_calls(response)

        assert len(tool_calls) == 2
        assert tool_calls[0].id == "call_0"
        assert tool_calls[0].function_name == "read_mem"
        assert tool_calls[1].id == "call_1"
        assert tool_calls[1].function_name == "write_patch"

    def test_empty_function_calls_returns_empty_list(self) -> None:
        """A response without function calls returns an empty list.

        Mutation caught: always returning a non-empty list would fail the
        ``== []`` assertion for a pure-text candidate.
        """
        content_obj = Content(parts=[Part(text="No tool needed.")], role="model")
        candidate = Candidate(content=content_obj, finish_reason=FinishReason.STOP)
        response = GenerateContentResponse(candidates=[candidate])

        tool_calls = _extract_function_calls(response)

        assert tool_calls == []


# ---------------------------------------------------------------------------
# Finding #34 — _extract_visible_chunk_text
# ---------------------------------------------------------------------------


class TestExtractVisibleChunkText:
    """Offline unit gates for ``GoogleProvider._extract_visible_chunk_text``.

    Oracle: ``google.genai.types.Part`` objects with ``thought=True/False``
    and independently-known text values.
    """

    def test_thought_parts_are_filtered_out(self) -> None:
        """Only non-thought parts appear in the returned string.

        Candidate has four parts alternating thought/visible.  The result
        must contain only the two non-thought texts concatenated in order.

        Oracle: parts constructed with known ``text`` and ``thought`` values;
        expected output is their concatenation ``"Hello user! More text."``.

        Mutation caught: removing the ``if getattr(part, "thought", False): continue``
        guard returns all four texts, so the result contains "I am thinking..."
        and the assertion fails.
        """
        content_obj = Content(
            parts=[
                Part(text="I am thinking...", thought=True),
                Part(text="Hello user!", thought=False),
                Part(text="More thinking", thought=True),
                Part(text=" More text.", thought=False),
            ],
            role="model",
        )
        candidate = Candidate(content=content_obj, finish_reason=FinishReason.STOP)
        chunk = GenerateContentResponse(candidates=[candidate])

        visible = _extract_visible_chunk_text(chunk)

        assert visible == "Hello user! More text."

    def test_all_thought_parts_returns_empty_string(self) -> None:
        """When all parts are thoughts the visible text is empty.

        Mutation caught: returning the full concatenation instead of filtering
        produces non-empty output; ``visible == ""`` fails.
        """
        content_obj = Content(
            parts=[
                Part(text="First inner thought.", thought=True),
                Part(text="Second inner thought.", thought=True),
            ],
            role="model",
        )
        candidate = Candidate(content=content_obj, finish_reason=FinishReason.STOP)
        chunk = GenerateContentResponse(candidates=[candidate])

        visible = _extract_visible_chunk_text(chunk)

        assert not visible

    def test_no_thought_flag_parts_all_included(self) -> None:
        """Parts without the ``thought`` attribute are treated as visible.

        ``Part(text=...)`` without ``thought=True`` leaves the flag unset
        (``None``); ``getattr(part, "thought", False)`` returns the falsy
        sentinel so the part is included.

        Mutation caught: treating ``None`` thought flag as ``True`` would
        filter out valid text; the assertion on ``"alpha beta"`` fails.
        """
        content_obj = Content(
            parts=[Part(text="alpha"), Part(text=" beta")],
            role="model",
        )
        candidate = Candidate(content=content_obj, finish_reason=FinishReason.STOP)
        chunk = GenerateContentResponse(candidates=[candidate])

        visible = _extract_visible_chunk_text(chunk)

        assert visible == "alpha beta"


# ---------------------------------------------------------------------------
# Finding #35 — _extract_thinking_text
# ---------------------------------------------------------------------------


class TestExtractThinkingText:
    """Offline unit gates for ``GoogleProvider._extract_thinking_text``.

    Oracle: ``google.genai.types.Part`` objects with ``thought=True`` and
    independently-known text strings.
    """

    def test_thought_parts_concatenated_with_double_newline(self) -> None:
        r"""Consecutive thought parts are joined with a double-newline separator.

        Oracle: two thought parts with known text joined by the separator
        ``"\n\n"`` give ``"First thought.\n\nSecond thought."``.

        Mutation caught: using ``"\n"`` as separator produces a different
        string; the exact-equality assertion fails.
        """
        content_obj = Content(
            parts=[
                Part(text="First thought.", thought=True),
                Part(text="Visible text.", thought=False),
                Part(text="Second thought.", thought=True),
            ],
            role="model",
        )
        candidate = Candidate(content=content_obj, finish_reason=FinishReason.STOP)
        response = GenerateContentResponse(candidates=[candidate])

        thinking = _extract_thinking_text(response)

        assert thinking == "First thought.\n\nSecond thought."

    def test_no_thought_parts_returns_empty_string(self) -> None:
        """When no parts have ``thought=True`` the result is an empty string.

        Mutation caught: returning any non-empty string for a visible-only
        candidate fails ``== ""``.
        """
        content_obj = Content(
            parts=[Part(text="Only visible."), Part(text=" More visible.")],
            role="model",
        )
        candidate = Candidate(content=content_obj, finish_reason=FinishReason.STOP)
        response = GenerateContentResponse(candidates=[candidate])

        thinking = _extract_thinking_text(response)

        assert not thinking

    def test_single_thought_part_no_separator(self) -> None:
        r"""A single thought part is returned without any surrounding separator.

        Mutation caught: prepending or appending a double-newline would give
        ``"\n\nOnly thought."``; the exact assertion fails.
        """
        content_obj = Content(
            parts=[Part(text="Only thought.", thought=True)],
            role="model",
        )
        candidate = Candidate(content=content_obj, finish_reason=FinishReason.STOP)
        response = GenerateContentResponse(candidates=[candidate])

        thinking = _extract_thinking_text(response)

        assert thinking == "Only thought."


# ---------------------------------------------------------------------------
# Finding #36 — _create_config: ThinkingConfig and tool_config branches
# ---------------------------------------------------------------------------


class TestCreateConfig:
    """Offline unit gates for ``GoogleProvider._create_config``.

    Oracle: ``google.genai.types.FunctionCallingConfigMode`` enum values and
    the ``ThinkingConfig`` field layout documented in the genai SDK.
    """

    def test_thinking_config_budget_and_include_thoughts_set(self) -> None:
        """``ThinkingConfig`` attaches the budget and sets ``include_thoughts=True``.

        Oracle: ``IntelliThinkingConfig(enabled=True, budget_tokens=1000)``
        maps to ``types.ThinkingConfig(thinking_budget=1000, include_thoughts=True)``.

        Mutation caught: omitting ``include_thoughts=True`` from the constructed
        ``types.ThinkingConfig`` leaves it as ``None``; the equality assertion fails.
        """
        tc = IntelliThinkingConfig(enabled=True, budget_tokens=1000)
        config = _create_config(
            temperature=0.7,
            max_tokens=512,
            gemini_tools=None,
            system_instruction=None,
            tool_choice=None,
            thinking=tc,
        )

        assert config.thinking_config is not None
        assert config.thinking_config.thinking_budget == 1000
        assert config.thinking_config.include_thoughts is True

    def test_disabled_thinking_config_omitted(self) -> None:
        """``ThinkingConfig(enabled=False)`` must NOT set a ``thinking_config``.

        Mutation caught: always constructing a ``types.ThinkingConfig``
        regardless of ``enabled`` leaves a non-None config; ``is None`` fails.
        """
        tc = IntelliThinkingConfig(enabled=False, budget_tokens=1000)
        config = _create_config(
            temperature=0.7,
            max_tokens=512,
            gemini_tools=None,
            thinking=tc,
        )

        assert config.thinking_config is None

    def test_tool_choice_auto_sets_auto_mode(self) -> None:
        """``ToolChoiceMode.AUTO`` maps to ``FunctionCallingConfigMode.AUTO``.

        Oracle: ``FunctionCallingConfigMode.AUTO`` is the genai SDK constant
        for ``mode='AUTO'``; the config must carry it unchanged.

        Mutation caught: mapping AUTO→NONE swaps the enum; the exact comparison
        ``== FunctionCallingConfigMode.AUTO`` fails.
        """
        config = _create_config(
            temperature=0.7,
            max_tokens=512,
            gemini_tools=_DUMMY_TOOLS,
            tool_choice=ToolChoice(mode=ToolChoiceMode.AUTO),
            thinking=None,
        )

        assert config.tool_config is not None
        assert config.tool_config.function_calling_config is not None
        assert config.tool_config.function_calling_config.mode == FunctionCallingConfigMode.AUTO

    def test_tool_choice_none_sets_none_mode(self) -> None:
        """``ToolChoiceMode.NONE`` maps to ``FunctionCallingConfigMode.NONE``.

        Mutation caught: mapping NONE→AUTO causes the mode to be AUTO;
        ``== FunctionCallingConfigMode.NONE`` fails.
        """
        config = _create_config(
            temperature=0.7,
            max_tokens=512,
            gemini_tools=_DUMMY_TOOLS,
            tool_choice=ToolChoice(mode=ToolChoiceMode.NONE),
            thinking=None,
        )

        assert config.tool_config is not None
        assert config.tool_config.function_calling_config is not None
        assert config.tool_config.function_calling_config.mode == FunctionCallingConfigMode.NONE

    def test_tool_choice_required_sets_any_mode(self) -> None:
        """``ToolChoiceMode.REQUIRED`` maps to ``FunctionCallingConfigMode.ANY``.

        Oracle: the Google genai SDK uses ``ANY`` to force at least one tool
        invocation; the implementation maps ``REQUIRED`` → ``ANY``.

        Mutation caught: mapping REQUIRED→AUTO gives the wrong mode value.
        """
        config = _create_config(
            temperature=0.7,
            max_tokens=512,
            gemini_tools=_DUMMY_TOOLS,
            tool_choice=ToolChoice(mode=ToolChoiceMode.REQUIRED),
            thinking=None,
        )

        assert config.tool_config is not None
        assert config.tool_config.function_calling_config is not None
        assert config.tool_config.function_calling_config.mode == FunctionCallingConfigMode.ANY

    def test_no_tools_no_tool_config(self) -> None:
        """When ``gemini_tools`` is ``None`` no ``tool_config`` is created.

        Mutation caught: constructing ``tool_config`` even without tools
        would leave it non-None; ``is None`` fails.
        """
        config = _create_config(
            temperature=0.5,
            max_tokens=256,
            gemini_tools=None,
            tool_choice=ToolChoice(mode=ToolChoiceMode.AUTO),
            thinking=None,
        )

        assert config.tool_config is None


# ---------------------------------------------------------------------------
# Finding #37 — _extract_usage
# ---------------------------------------------------------------------------


class TestExtractUsage:
    """Offline unit gates for ``GoogleProvider._extract_usage``.

    Oracle: ``google.genai.types.GenerateContentResponseUsageMetadata`` with
    independently-known integer counts; the expected ``UsageInfo`` is computed
    from those same constants.
    """

    def test_known_token_counts_map_to_usage_info_fields(self) -> None:
        """Token counts from ``GenerateContentResponseUsageMetadata`` flow into ``UsageInfo``.

        Oracle: ``prompt_token_count=17``, ``candidates_token_count=5``,
        ``total_token_count=22`` → ``UsageInfo(prompt_tokens=17,
        completion_tokens=5, total_tokens=22)``.

        Mutation caught: reading ``response_token_count`` instead of
        ``candidates_token_count`` returns 0 for completion_tokens;
        ``completion_tokens == 5`` fails.
        """
        usage_meta = GenerateContentResponseUsageMetadata(
            prompt_token_count=17,
            candidates_token_count=5,
            total_token_count=22,
        )
        response = GenerateContentResponse(candidates=[], usage_metadata=usage_meta)

        result = _extract_usage(response)

        assert result is not None
        assert result.prompt_tokens == 17
        assert result.completion_tokens == 5
        assert result.total_tokens == 22

    def test_missing_total_defaults_to_sum(self) -> None:
        """When ``total_token_count`` is absent the sum is used as the total.

        Oracle: 11 + 4 = 15; no other computation applies.

        Mutation caught: returning ``total_tokens=0`` when total is absent
        (instead of summing) causes ``total_tokens == 15`` to fail.
        """
        usage_meta = GenerateContentResponseUsageMetadata(
            prompt_token_count=11,
            candidates_token_count=4,
        )
        response = GenerateContentResponse(candidates=[], usage_metadata=usage_meta)

        result = _extract_usage(response)

        assert result is not None
        assert result.prompt_tokens == 11
        assert result.completion_tokens == 4
        assert result.total_tokens == 15

    def test_all_zero_counts_returns_none(self) -> None:
        """Zero prompt and completion tokens produce ``None``, not a zero UsageInfo.

        The production guard ``if prompt_tokens == 0 and completion_tokens == 0
        and total_tokens == 0: return None`` prevents emitting empty usage.

        Mutation caught: removing the guard returns a ``UsageInfo(0, 0, 0)``;
        ``result is None`` fails.
        """
        usage_meta = GenerateContentResponseUsageMetadata(
            prompt_token_count=0,
            candidates_token_count=0,
            total_token_count=0,
        )
        response = GenerateContentResponse(candidates=[], usage_metadata=usage_meta)

        result = _extract_usage(response)

        assert result is None

    def test_no_usage_metadata_returns_none(self) -> None:
        """A response without ``usage_metadata`` returns ``None``.

        Mutation caught: always returning a default ``UsageInfo`` when
        metadata is absent causes ``result is None`` to fail.
        """
        response = GenerateContentResponse(candidates=[])

        result = _extract_usage(response)

        assert result is None

    def test_returned_type_is_usage_info(self) -> None:
        """The returned object is a ``UsageInfo`` dataclass instance.

        Confirms the exact type, not just that fields carry the right values.

        Mutation caught: returning a plain tuple ``(17, 5, 22)`` instead of
        a ``UsageInfo`` fails the ``isinstance`` check.
        """
        usage_meta = GenerateContentResponseUsageMetadata(
            prompt_token_count=17,
            candidates_token_count=5,
            total_token_count=22,
        )
        response = GenerateContentResponse(candidates=[], usage_metadata=usage_meta)

        result = _extract_usage(response)

        assert isinstance(result, UsageInfo)


# ---------------------------------------------------------------------------
# Finding #39 — _convert_messages_to_provider_format: tool_calls and tool_results
# ---------------------------------------------------------------------------


class TestConvertMessagesToProviderFormat:
    """Offline unit gates for the complex message-conversion cases in GoogleProvider.

    Finding #39: the simple user-text case was already gated via the F-0001
    HTTP body test.  These gates cover the ``function_call`` (assistant with
    tool_calls) and ``function_response`` (tool result) paths.

    Oracle: Gemini Content wire format spec — assistant tool calls map to
    ``function_call`` parts; tool results map to ``function_response`` parts
    with the function name resolved via the ``call_id→name`` mapping.
    """

    def test_assistant_message_with_tool_calls_produces_function_call_part(self) -> None:
        """An assistant ``Message`` with ``tool_calls`` maps to a ``function_call`` part.

        The assistant role becomes ``"model"`` in Gemini format; each
        ``ToolCall`` produces a ``{"function_call": {"name": ..., "args": ...}}``
        entry in ``parts``.

        Oracle: the Gemini ``generateContent`` request spec; ``function_call``
        in ``parts`` is the only valid way to represent a model tool invocation.

        Mutation caught: omitting the ``if msg.tool_calls`` branch produces
        only a text part (or an empty ``parts`` list); ``"function_call" in
        parts[0]`` fails.
        """
        tc = ToolCall(
            id="call_abc",
            tool_name="analyze",
            function_name="analyze_binary",
            arguments={"path": "/bin/ls"},
        )
        msg = Message(
            role="assistant",
            content="",
            tool_calls=[tc],
            timestamp=datetime.now(tz=UTC),
        )
        provider = GoogleProvider()
        result = provider.convert_messages_to_provider_format([msg])

        assert len(result) == 1
        assert result[0]["role"] == "model"
        parts = cast("list[dict[str, object]]", result[0]["parts"])
        assert len(parts) == 1
        fc_part = parts[0]
        assert "function_call" in fc_part
        fc_dict = cast("dict[str, object]", fc_part["function_call"])
        assert fc_dict["name"] == "analyze_binary"
        assert fc_dict["args"] == {"path": "/bin/ls"}

    def test_tool_result_message_produces_function_response_part(self) -> None:
        """A ``tool``-role ``Message`` maps to a ``function_response`` part in user role.

        The ``call_id→function_name`` mapping from the preceding assistant
        message resolves the function name so the ``function_response.name``
        carries the real function name, not the opaque call id.

        Oracle: Gemini API requires ``function_response.name`` to match the
        name used in the corresponding ``function_call``; using the call_id
        directly would be rejected by the API.

        Mutation caught: using ``tr.call_id`` as the response name instead of
        resolving via ``call_id_to_name`` produces ``name="call_abc"`` instead
        of ``"analyze_binary"``; ``fr_dict["name"] == "analyze_binary"`` fails.
        """
        tc = ToolCall(
            id="call_abc",
            tool_name="analyze",
            function_name="analyze_binary",
            arguments={"path": "/bin/ls"},
        )
        assistant_msg = Message(
            role="assistant",
            content="",
            tool_calls=[tc],
            timestamp=datetime.now(tz=UTC),
        )
        tr = ToolResult(
            call_id="call_abc",
            success=True,
            result="binary analysis result",
            error=None,
            duration_ms=100.0,
        )
        tool_msg = Message(
            role="tool",
            content="",
            tool_results=[tr],
            timestamp=datetime.now(tz=UTC),
        )
        provider = GoogleProvider()
        result = provider.convert_messages_to_provider_format([assistant_msg, tool_msg])

        assert len(result) == 2
        assert result[1]["role"] == "user"
        parts = cast("list[dict[str, object]]", result[1]["parts"])
        assert len(parts) == 1
        fr_part = parts[0]
        assert "function_response" in fr_part
        fr_dict = cast("dict[str, object]", fr_part["function_response"])
        assert fr_dict["name"] == "analyze_binary"
        response_dict = cast("dict[str, object]", fr_dict["response"])
        assert response_dict["result"] == "binary analysis result"

    def test_function_response_result_field_carries_tool_output(self) -> None:
        """The ``response.result`` field carries the tool's output string verbatim.

        Oracle: ``{"response": {"result": <tool_output>}}`` is the Gemini
        function response wire format; any other key name silently drops the
        output.

        Mutation caught: wrapping the result under ``{"output": ...}`` instead
        of ``{"result": ...}`` causes ``response_dict["result"] == ...`` to fail
        with a ``KeyError``.
        """
        tc = ToolCall(
            id="call_xyz",
            tool_name="hex_dump",
            function_name="hex_dump",
            arguments={"offset": 0, "length": 16},
        )
        assistant_msg = Message(
            role="assistant",
            content="",
            tool_calls=[tc],
            timestamp=datetime.now(tz=UTC),
        )
        tr = ToolResult(
            call_id="call_xyz",
            success=True,
            result="00 01 02 03 04 05 06 07",
            error=None,
            duration_ms=5.0,
        )
        tool_msg = Message(
            role="tool",
            content="",
            tool_results=[tr],
            timestamp=datetime.now(tz=UTC),
        )
        provider = GoogleProvider()
        result = provider.convert_messages_to_provider_format([assistant_msg, tool_msg])

        parts = cast("list[dict[str, object]]", result[1]["parts"])
        fr_dict = cast("dict[str, object]", parts[0]["function_response"])
        response_dict = cast("dict[str, object]", fr_dict["response"])
        assert response_dict["result"] == "00 01 02 03 04 05 06 07"
