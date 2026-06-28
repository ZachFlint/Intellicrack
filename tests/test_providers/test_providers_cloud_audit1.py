# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression tests for ``audit1.md`` providers-cloud findings.

Every audit finding has a paired red/green test in this module:

* F-0001 — ``enable_cache`` is wired into OpenAI/Grok/OpenRouter/Google.
* F-0002 — ``ThinkingConfig`` is wired into OpenAI o-series, Grok
  multi-agent, and Gemini 2.5 ``thinking_config``.
* F-0003 — ``cancel_request`` cancels in-flight non-streaming
  requests by populating ``self._current_task``.
* F-0004 — Grok / Google / OpenRouter route their non-streaming
  requests through ``LLMProviderBase._retry_with_backoff``.
* F-0005 — Anthropic ``enable_cache`` extends to tools and the last
  message turn, not only the system prompt.
* F-0006 — OpenAI ``chat_stream`` re-raises transport errors even when
  ``cancel_requested`` is True so the failure is never swallowed.
* F-0007 — ``_convert_tool_choice_to_openai_format`` raises
  :class:`ProviderError` instead of emitting an empty function name.
* F-0008 — Orchestrator drains ``get_pending_usage`` /
  ``get_pending_thinking`` after each LLM call.
* F-0009 — ``_convert_tools_to_openai_format`` is a single base
  helper shared by OpenAI / Grok / OpenRouter.
* F-0010 — Anthropic ``_fetch_all_models`` forwards a ``limit``
  through to every paginated request.

Live-network tests are gated by environment credentials at the test
level only — never source-level.
"""

from __future__ import annotations

import asyncio
import json
import os
from typing import TYPE_CHECKING, Any, cast, override
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import openai
import pytest
from google.genai import Client as GenaiClient
from google.genai.types import HttpOptions

from intellicrack.core.orchestrator import Orchestrator, OrchestratorConfig, OrchestratorStats
from intellicrack.core.types import (
    Message,
    ProviderCredentials,
    ProviderError,
    RateLimitError,
    ThinkingConfig,
    ToolChoice,
    ToolChoiceMode,
    ToolDefinition,
    ToolFunction,
    ToolName,
    ToolParameter,
)
from intellicrack.providers.anthropic import AnthropicProvider
from intellicrack.providers.base import LLMProviderBase, UsageInfo
from intellicrack.providers.google import GoogleProvider
from intellicrack.providers.grok import GrokProvider
from intellicrack.providers.openai import OpenAIProvider
from intellicrack.providers.openrouter import OpenRouterProvider


if TYPE_CHECKING:
    from anthropic.types import MessageParam


# Private-helper accessors --------------------------------------------------
#
# Tests reach into the provider internals via ``getattr`` so ruff's
# ``SLF001`` rule treats the access as a public attribute lookup.  This
# matches the pattern established in
# :mod:`tests.test_providers.test_openai_format_helpers`.

_CONVERT_TOOL_CHOICE_ATTR: str = "_convert_tool_choice_to_openai_format"
_CONVERT_TOOLS_OPENAI_ATTR: str = "_convert_tools_to_openai_format"
_CONVERT_TOOLS_PROVIDER_ATTR: str = "_convert_tools_to_provider_format"
_BUILD_API_KWARGS_ATTR: str = "_build_api_kwargs"
_FETCH_ALL_MODELS_ATTR: str = "_fetch_all_models"
_REASONING_EFFORT_ATTR: str = "_reasoning_effort_for"
_APPLY_CACHE_CONTROL_ATTR: str = "_apply_cache_control"
_RECORD_USAGE_ATTR: str = "_record_provider_usage"
_CURRENT_TASK_ATTR: str = "_current_task"
_CANCEL_REQUESTED_ATTR: str = "_cancel_requested"
_CLIENT_ATTR: str = "_client"
_STATS_ATTR: str = "_stats"
_CONFIG_ATTR: str = "_config"

_convert_tool_choice: Any = getattr(LLMProviderBase, _CONVERT_TOOL_CHOICE_ATTR)
_convert_tools_to_openai: Any = getattr(LLMProviderBase, _CONVERT_TOOLS_OPENAI_ATTR)
_anthropic_build_api_kwargs: Any = getattr(AnthropicProvider, _BUILD_API_KWARGS_ATTR)
_openrouter_apply_cache_control: Any = getattr(OpenRouterProvider, _APPLY_CACHE_CONTROL_ATTR)
_openrouter_reasoning_effort: Any = getattr(OpenRouterProvider, _REASONING_EFFORT_ATTR)


_KABOOM_MESSAGE: str = "kaboom"


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _build_text_tool() -> ToolDefinition:
    """Build a minimal :class:`ToolDefinition` with one function.

    Returns:
        ToolDefinition: A ``ToolDefinition`` named ``"audit"`` with a
        single function ``ping`` that takes one string parameter.
    """
    func = ToolFunction(
        name="ping",
        description="Return pong.",
        parameters=[
            ToolParameter(
                name="message",
                type="string",
                description="Echo payload.",
                required=True,
            ),
        ],
        returns="The literal string 'pong'.",
    )
    return ToolDefinition(tool_name=ToolName.PROCESS, description="Audit fixture tool.", functions=[func])


def _user_messages(text: str = "Hello, world.") -> list[Message]:
    """Build a single-user-message conversation.

    Args:
        text: Text payload for the user message.

    Returns:
        list[Message]: One-element list with a ``user`` role message.
    """
    return [Message(role="user", content=text)]


# ---------------------------------------------------------------------------
# F-0007 — empty function name raises ProviderError
# ---------------------------------------------------------------------------


def test_f0007_specific_tool_choice_without_function_name_raises() -> None:
    """ToolChoiceMode.SPECIFIC with no function name must raise.

    Sending ``{"type": "function", "function": {"name": ""}}`` to an
    OpenAI-compatible endpoint produces a 400 server-side; the bridge
    must surface the misuse as a typed :class:`ProviderError` instead.
    """
    bad_choice = ToolChoice(mode=ToolChoiceMode.SPECIFIC, function_name=None)
    with pytest.raises(ProviderError, match="non-empty function_name"):
        _convert_tool_choice(bad_choice)

    empty_choice = ToolChoice(mode=ToolChoiceMode.SPECIFIC, function_name="")
    with pytest.raises(ProviderError, match="non-empty function_name"):
        _convert_tool_choice(empty_choice)


def test_f0007_specific_tool_choice_with_function_name_returns_dict() -> None:
    """ToolChoiceMode.SPECIFIC with a function name yields the OpenAI dict.

    Confirms the happy path still returns the OpenAI-compatible dict
    shape ``{"type": "function", "function": {"name": <name>}}``.
    """
    choice = ToolChoice(mode=ToolChoiceMode.SPECIFIC, function_name="run_pipeline")
    result = _convert_tool_choice(choice)
    assert result == {"type": "function", "function": {"name": "run_pipeline"}}


def test_f0007_all_tool_choice_modes_map_to_openai_spec_constants() -> None:
    """Every ToolChoiceMode maps to the exact OpenAI ``tool_choice`` value.

    The expected values are fixed by the public OpenAI Chat Completions
    contract, independent of Intellicrack: ``AUTO`` -> ``"auto"``,
    ``NONE`` -> ``"none"``, ``REQUIRED`` -> ``"required"``, and ``SPECIFIC``
    -> the named-function dict. Pinning all four guards against any single
    branch silently emitting the wrong literal (which the server would
    reject), not just the SPECIFIC happy path.
    """
    assert _convert_tool_choice(ToolChoice(mode=ToolChoiceMode.AUTO)) == "auto"
    assert _convert_tool_choice(ToolChoice(mode=ToolChoiceMode.NONE)) == "none"
    assert _convert_tool_choice(ToolChoice(mode=ToolChoiceMode.REQUIRED)) == "required"
    assert _convert_tool_choice(ToolChoice(mode=ToolChoiceMode.SPECIFIC, function_name="ping")) == {
        "type": "function",
        "function": {"name": "ping"},
    }


@pytest.mark.skipif(
    not os.environ.get("OPENAI_API_KEY"),
    reason="OPENAI_API_KEY not set; live network test skipped",
)
@pytest.mark.asyncio
async def test_f0007_specific_tool_choice_forces_named_tool_on_live_openai() -> None:
    """Live: a SPECIFIC tool choice forces the OpenAI API to call that tool.

    Drives the converted ``{"type": "function", "function": {"name": "ping"}}``
    dict through a real OpenAI chat request and asserts the server actually
    selects the named function. This closes the gap the audit flagged on the
    unit test: the conversion is not merely the right shape, it is accepted by
    and honoured by the real endpoint. Gated on ``OPENAI_API_KEY``.
    """
    api_key = os.environ.get("OPENAI_API_KEY")
    assert api_key
    provider = OpenAIProvider()
    creds = ProviderCredentials(api_key=api_key)
    await provider.connect(creds)
    try:
        _response, tool_calls = await provider.chat(
            messages=_user_messages("Echo the word ready back to me."),
            model="gpt-4o-mini",
            max_tokens=64,
            tools=[_build_text_tool()],
            tool_choice=ToolChoice(mode=ToolChoiceMode.SPECIFIC, function_name="ping"),
        )
        assert tool_calls is not None, "Forced tool choice produced no tool call"
        assert len(tool_calls) == 1
        assert tool_calls[0].function_name == "ping"
    finally:
        await provider.disconnect()


# ---------------------------------------------------------------------------
# F-0009 — base helper de-duplicates the OpenAI tool conversion
# ---------------------------------------------------------------------------


def test_f0009_openai_tools_helper_shared_across_providers() -> None:
    """OpenAI/Grok/OpenRouter share the base ``_convert_tools_to_openai_format``.

    Checks that all three subclass overrides delegate to the base
    helper and produce byte-identical output.
    """
    tools = [_build_text_tool()]
    base_output: list[dict[str, object]] = _convert_tools_to_openai(tools)

    openai = OpenAIProvider()
    grok = GrokProvider()
    openrouter = OpenRouterProvider()

    assert openai.convert_tools_to_provider_format(tools) == base_output
    assert grok.convert_tools_to_provider_format(tools) == base_output
    assert openrouter.convert_tools_to_provider_format(tools) == base_output

    first_entry = base_output[0]
    assert first_entry["type"] == "function"
    function_block = first_entry["function"]
    assert isinstance(function_block, dict)
    assert function_block["name"] == "ping"


# ---------------------------------------------------------------------------
# F-0005 — Anthropic enable_cache extends to system, tools, and messages
# ---------------------------------------------------------------------------


def test_f0005_enable_cache_marks_system_tools_and_last_message() -> None:
    """``_build_api_kwargs`` attaches cache_control across the prefix.

    With ``enable_cache=True``, the helper must rewrite the system
    prompt into a structured block, place a cache breakpoint on the
    last tool entry, and place a cache breakpoint on the final block
    of the last message turn.  Each breakpoint is the literal
    ephemeral marker.
    """
    tools_payload: list[dict[str, object]] = [
        {"name": "tool_a", "description": "A", "input_schema": {"type": "object", "properties": {}, "required": []}},
        {"name": "tool_b", "description": "B", "input_schema": {"type": "object", "properties": {}, "required": []}},
    ]
    raw_messages: list[dict[str, object]] = [
        {"role": "user", "content": "First."},
        {"role": "assistant", "content": "Mid."},
        {"role": "user", "content": "Final question."},
    ]
    messages_payload = cast("list[MessageParam]", raw_messages)

    kwargs: dict[str, Any] = _anthropic_build_api_kwargs(
        model="claude-opus-4-7",
        max_tokens=4096,
        temperature=0.7,
        messages=messages_payload,
        system_prompt="You are an audit fixture.",
        tools=tools_payload,
        enable_cache=True,
    )

    system_blocks = kwargs["system"]
    assert isinstance(system_blocks, list)
    assert system_blocks[-1]["cache_control"] == {"type": "ephemeral"}

    cached_tools = kwargs["tools"]
    assert isinstance(cached_tools, list)
    assert cached_tools[-1]["name"] == "tool_b"
    assert cached_tools[-1]["cache_control"] == {"type": "ephemeral"}
    assert "cache_control" not in cached_tools[0]

    last_msg = kwargs["messages"][-1]
    assert isinstance(last_msg["content"], list)
    last_block = last_msg["content"][-1]
    assert last_block["cache_control"] == {"type": "ephemeral"}


def test_f0005_enable_cache_disabled_leaves_payload_untouched() -> None:
    """``enable_cache=False`` (default) must not introduce breakpoints.

    Confirms there's no silent caching when callers omit the flag.
    """
    raw_messages: list[dict[str, object]] = [{"role": "user", "content": "hi"}]
    messages_payload = cast("list[MessageParam]", raw_messages)
    kwargs: dict[str, Any] = _anthropic_build_api_kwargs(
        model="claude-opus-4-7",
        max_tokens=4096,
        temperature=0.7,
        messages=messages_payload,
        system_prompt="System.",
        tools=None,
        enable_cache=False,
    )
    assert kwargs["system"] == "System."
    first_msg = kwargs["messages"][0]
    assert first_msg["content"] == "hi"


# ---------------------------------------------------------------------------
# F-0010 — Anthropic _fetch_all_models forwards limit to pagination
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_f0010_fetch_all_models_forwards_limit() -> None:
    """``_fetch_all_models`` must pass ``limit`` to every page call.

    The method now accepts a keyword-only ``limit`` and the fake
    client's ``list`` is called with it on every iteration (not just
    the probe).
    """
    provider = AnthropicProvider()
    fake_client = MagicMock()

    page_one = MagicMock()
    page_one.data = [MagicMock(id="claude-opus-4-7", display_name="Opus 4.7")]
    page_one.has_more = True
    page_one.last_id = "claude-opus-4-7"

    page_two = MagicMock()
    page_two.data = [MagicMock(id="claude-sonnet-4-6", display_name="Sonnet 4.6")]
    page_two.has_more = False
    page_two.last_id = "claude-sonnet-4-6"

    list_calls: list[dict[str, object]] = []

    async def _list(**kwargs: object) -> object:
        list_calls.append(kwargs)
        page_index = len(list_calls)
        await asyncio.sleep(0)
        return page_one if page_index == 1 else page_two

    fake_client.models.list = _list
    setattr(provider, _CLIENT_ATTR, fake_client)

    fetch_all = getattr(provider, _FETCH_ALL_MODELS_ATTR)
    models = await fetch_all(limit=5)
    assert len(models) == 2
    assert all(call["limit"] == 5 for call in list_calls)
    assert "after_id" not in list_calls[0]
    assert list_calls[1]["after_id"] == "claude-opus-4-7"


# ---------------------------------------------------------------------------
# F-0001 / F-0002 — enable_cache + thinking signatures wired
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_f0001_openai_enable_cache_http_request_body() -> None:
    """OpenAI ``enable_cache=True`` sends the correct serialised chat request body.

    A real :class:`httpx.AsyncBaseTransport` recording seam is injected into
    the real :class:`openai.AsyncOpenAI` client so every SDK serialisation and
    JSON-encoding layer runs without substitution.  The captured HTTP request
    body is asserted against the OpenAI Chat Completions API request schema as
    the independent oracle: ``model``, ``messages``, and ``max_tokens`` must
    carry the literal values supplied to :meth:`OpenAIProvider.chat`.

    OpenAI auto-caches prompts above 1024 tokens server-side; no
    ``cache_control`` or ``prompt_caching`` field must appear in the client
    request body.  A matching call with ``enable_cache=False`` must produce a
    byte-identical body, confirming the flag does not corrupt the request
    either way.

    Mutation caught: replacing the API dispatch call with an early return when
    ``enable_cache=True`` leaves ``captured`` empty, failing the
    ``assert len(captured) == 2`` gate.
    """
    completion_body: dict[str, object] = {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "model": "gpt-4o",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
    }
    captured: list[dict[str, object]] = []

    class _Transport(httpx.AsyncBaseTransport):
        @override
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            captured.append(cast("dict[str, object]", json.loads(request.content)))
            return httpx.Response(
                200,
                content=json.dumps(completion_body).encode(),
                headers={"content-type": "application/json"},
            )

    sdk_client = openai.AsyncOpenAI(
        api_key="test-key",
        http_client=httpx.AsyncClient(transport=_Transport()),
    )
    provider = OpenAIProvider()
    provider.connected = True
    provider.client = sdk_client

    await provider.chat(
        messages=_user_messages("hello"),
        model="gpt-4o",
        max_tokens=64,
        enable_cache=True,
    )
    await provider.chat(
        messages=_user_messages("hello"),
        model="gpt-4o",
        max_tokens=64,
        enable_cache=False,
    )

    assert len(captured) == 2, "Provider must dispatch two HTTP requests (one per chat call)"
    body_true = captured[0]
    body_false = captured[1]

    assert body_true["model"] == "gpt-4o"
    assert body_true["messages"] == [{"role": "user", "content": "hello"}]
    assert body_true["max_tokens"] == 64
    assert "cache_control" not in body_true
    assert "prompt_caching" not in body_true
    assert body_false == body_true


@pytest.mark.asyncio
async def test_f0001_grok_enable_cache_http_request_body() -> None:
    """Grok ``enable_cache=True`` sends the correct serialised chat request body.

    A real :class:`httpx.AsyncBaseTransport` recording seam is injected into
    the real :class:`openai.AsyncOpenAI` client (with Grok's base URL) so
    every SDK serialisation and JSON-encoding layer runs without substitution.
    The captured HTTP request body is asserted against the OpenAI-compatible
    Chat Completions API request schema as the independent oracle: ``model``,
    ``messages``, and ``max_tokens`` must carry the literal values supplied to
    :meth:`GrokProvider.chat`.

    Grok auto-caches repeated prompt prefixes server-side; no ``cache_control``
    field must appear in the client request body.  A matching call with
    ``enable_cache=False`` must produce a byte-identical body.

    Mutation caught: replacing the Grok API dispatch call with an early return
    when ``enable_cache=True`` leaves ``captured`` empty, failing the
    ``assert len(captured) == 2`` gate.
    """
    completion_body: dict[str, object] = {
        "id": "chatcmpl-grok",
        "object": "chat.completion",
        "model": "grok-3",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "grok-ok"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
    }
    captured: list[dict[str, object]] = []

    class _Transport(httpx.AsyncBaseTransport):
        @override
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            captured.append(cast("dict[str, object]", json.loads(request.content)))
            return httpx.Response(
                200,
                content=json.dumps(completion_body).encode(),
                headers={"content-type": "application/json"},
            )

    sdk_client = openai.AsyncOpenAI(
        api_key="test-key",
        base_url=GrokProvider.BASE_URL,
        http_client=httpx.AsyncClient(transport=_Transport()),
    )
    provider = GrokProvider()
    provider.connected = True
    provider.client = sdk_client

    await provider.chat(
        messages=_user_messages("hello"),
        model="grok-3",
        max_tokens=64,
        enable_cache=True,
    )
    await provider.chat(
        messages=_user_messages("hello"),
        model="grok-3",
        max_tokens=64,
        enable_cache=False,
    )

    assert len(captured) == 2, "Provider must dispatch two HTTP requests (one per chat call)"
    body_true = captured[0]
    body_false = captured[1]

    assert body_true["model"] == "grok-3"
    assert body_true["messages"] == [{"role": "user", "content": "hello"}]
    assert body_true["max_tokens"] == 64
    assert "cache_control" not in body_true
    assert body_false == body_true


@pytest.mark.asyncio
async def test_f0001_google_enable_cache_http_request_body() -> None:
    """Google ``enable_cache=True`` sends the correct serialised generateContent body.

    A real :class:`httpx.AsyncBaseTransport` recording seam is injected into
    the real :class:`google.genai.Client` via :class:`HttpOptions` so every
    genai SDK serialisation and JSON-encoding layer runs without substitution.
    The captured HTTP request body is asserted against the Gemini
    ``generateContent`` API request schema as the independent oracle:
    ``contents`` must carry the Gemini-format user message and
    ``generationConfig.maxOutputTokens`` must equal the ``max_tokens`` value
    supplied to :meth:`GoogleProvider.chat`.

    Google's implicit caching operates server-side; no ``cachedContent`` or
    ``cacheContext`` field must appear in the client request body.  A matching
    call with ``enable_cache=False`` must produce a byte-identical body.

    Mutation caught: replacing the ``generate_content`` dispatch with an early
    return when ``enable_cache=True`` leaves ``captured`` empty, failing the
    ``assert len(captured) == 2`` gate.
    """
    gemini_response_body: dict[str, object] = {
        "candidates": [
            {
                "content": {"parts": [{"text": "google-ok"}], "role": "model"},
                "finishReason": "STOP",
                "index": 0,
            },
        ],
        "usageMetadata": {"promptTokenCount": 3, "candidatesTokenCount": 2, "totalTokenCount": 5},
    }
    captured: list[dict[str, object]] = []

    class _Transport(httpx.AsyncBaseTransport):
        @override
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            captured.append(cast("dict[str, object]", json.loads(request.content)))
            return httpx.Response(
                200,
                content=json.dumps(gemini_response_body).encode(),
                headers={"content-type": "application/json"},
            )

    provider = GoogleProvider()
    provider.connected = True
    provider.client = GenaiClient(
        api_key="test-key",
        http_options=HttpOptions(httpx_async_client=httpx.AsyncClient(transport=_Transport())),
    )

    await provider.chat(
        messages=_user_messages("hello"),
        model="gemini-2.0-flash",
        max_tokens=64,
        enable_cache=True,
    )
    await provider.chat(
        messages=_user_messages("hello"),
        model="gemini-2.0-flash",
        max_tokens=64,
        enable_cache=False,
    )

    assert len(captured) == 2, "Provider must dispatch two HTTP requests (one per chat call)"
    body_true = captured[0]
    body_false = captured[1]

    assert body_true["contents"] == [{"parts": [{"text": "hello"}], "role": "user"}]
    gen_cfg = cast("dict[str, object]", body_true["generationConfig"])
    assert gen_cfg["maxOutputTokens"] == 64
    assert "cachedContent" not in body_true
    assert "cacheContext" not in body_true
    assert body_false == body_true


def test_f0002_openai_thinking_maps_to_reasoning_effort() -> None:
    """Enabled thinking maps to ``reasoning_effort`` on o-series only.

    Non-reasoning models (gpt-4o family) must continue to omit the
    parameter — sending it would 400.  o3/o4 must receive it.
    """
    provider = OpenAIProvider()
    cfg_low = ThinkingConfig(enabled=True, budget_tokens=2000)
    cfg_high = ThinkingConfig(enabled=True, budget_tokens=32000)
    cfg_disabled = ThinkingConfig(enabled=False, budget_tokens=10000)

    resolver = getattr(provider, _REASONING_EFFORT_ATTR)
    assert resolver(model="gpt-4o", thinking=cfg_low) is None
    assert resolver(model="gpt-4o", thinking=None) is None
    assert resolver(model="gpt-4o", thinking=cfg_disabled) is None
    assert resolver(model="o3-mini", thinking=cfg_low) == "low"
    assert resolver(model="o4", thinking=cfg_high) == "high"


def test_f0002_grok_thinking_maps_to_reasoning_effort_for_multi_agent() -> None:
    """Grok-4 multi-agent receives ``reasoning_effort``; grok-4 fast does not.

    X.AI rejects ``reasoning_effort`` on grok-4 and grok-4-fast, so
    the helper must omit it for those families.
    """
    provider = GrokProvider()
    cfg = ThinkingConfig(enabled=True, budget_tokens=10000)
    resolver = getattr(provider, _REASONING_EFFORT_ATTR)
    assert resolver(model="grok-4-fast", thinking=cfg) is None
    assert resolver(model="grok-4-multi-agent", thinking=cfg) == "medium"


@pytest.mark.asyncio
async def test_f0002_openai_o_series_uses_max_completion_tokens_and_temp_1() -> None:
    """O-series chat uses ``max_completion_tokens`` and forces ``temperature=1.0``.

    OpenAI rejects o-series requests that send ``max_tokens`` (legacy field)
    or any temperature other than ``1.0``.  The bridge must dispatch
    ``max_completion_tokens`` and pin temperature when ``reasoning_effort``
    is active.
    """
    provider = OpenAIProvider()
    provider.connected = True
    fake_client = MagicMock()
    provider.client = fake_client

    captured_kwargs: list[dict[str, object]] = []

    async def _capture(**kwargs: object) -> object:
        await asyncio.sleep(0)
        captured_kwargs.append(dict(kwargs))
        completion = MagicMock()
        completion.choices = [MagicMock()]
        completion.choices[0].message = MagicMock(content="ok", tool_calls=None)
        completion.usage = MagicMock(prompt_tokens=10, completion_tokens=5, total_tokens=15)
        return completion

    fake_client.chat = MagicMock()
    fake_client.chat.completions = MagicMock()
    fake_client.chat.completions.create = _capture

    await provider.chat(
        messages=_user_messages("hello"),
        model="o4-mini",
        temperature=0.7,
        max_tokens=1024,
        thinking=ThinkingConfig(enabled=True, budget_tokens=10000),
    )

    assert captured_kwargs, "No API call was captured"
    kwargs = captured_kwargs[0]
    assert "max_completion_tokens" in kwargs, "o-series must use max_completion_tokens"
    assert "max_tokens" not in kwargs, "o-series must NOT use max_tokens"
    assert kwargs["max_completion_tokens"] == 1024
    assert abs(float(cast("float", kwargs["temperature"])) - 1.0) < 1e-9, "o-series must use temperature=1.0"


def test_f0002_openrouter_thinking_maps_to_reasoning_effort() -> None:
    """OpenRouter forwards ``reasoning.effort`` whenever thinking is enabled.

    Backends that ignore the field receive the request unchanged;
    backends that honour it (Anthropic, Gemini, OpenAI o-series) get
    the routed value.
    """
    cfg_low = ThinkingConfig(enabled=True, budget_tokens=1000)
    cfg_med = ThinkingConfig(enabled=True, budget_tokens=8000)
    cfg_high = ThinkingConfig(enabled=True, budget_tokens=40000)

    assert _openrouter_reasoning_effort(None) is None
    assert _openrouter_reasoning_effort(ThinkingConfig(enabled=False)) is None
    assert _openrouter_reasoning_effort(cfg_low) == "low"
    assert _openrouter_reasoning_effort(cfg_med) == "medium"
    assert _openrouter_reasoning_effort(cfg_high) == "high"


def test_f0001_openrouter_enable_cache_attaches_cache_control() -> None:
    """OpenRouter ``enable_cache`` adds ephemeral markers in place.

    The helper rewrites the last user and last system message into the
    structured-block form with ``cache_control: ephemeral`` so
    Anthropic / Gemini routes activate caching.  Mutates in place, so
    we verify the input list directly after the call.
    """
    messages: list[dict[str, object]] = [
        {"role": "system", "content": "System rules."},
        {"role": "user", "content": "First user."},
        {"role": "assistant", "content": "Mid reply."},
        {"role": "user", "content": "Final question."},
    ]
    _openrouter_apply_cache_control(messages)
    last_user_content = messages[-1]["content"]
    assert isinstance(last_user_content, list)
    last_user_blocks = cast("list[dict[str, object]]", last_user_content)
    assert last_user_blocks[-1]["cache_control"] == {"type": "ephemeral"}
    system_content = messages[0]["content"]
    assert isinstance(system_content, list)
    system_blocks_typed = cast("list[dict[str, object]]", system_content)
    assert system_blocks_typed[-1]["cache_control"] == {"type": "ephemeral"}


# ---------------------------------------------------------------------------
# F-0003 — cancel_request cancels non-streaming task
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_f0003_openai_chat_populates_current_task() -> None:
    """``chat`` registers the active task so ``cancel_request`` can cancel.

    Bug F-0003 was that ``self._current_task`` stayed ``None`` for the
    non-streaming path, so ``cancel_request`` was a no-op.  The fixed
    code wraps the API call in ``asyncio.create_task`` and assigns the
    handle for the duration of the request.
    """
    provider = OpenAIProvider()
    provider.connected = True
    fake_client = MagicMock()
    provider.client = fake_client

    captured: list[asyncio.Task[object] | None] = []

    async def _slow_call(**_: object) -> object:
        captured.append(getattr(provider, _CURRENT_TASK_ATTR))
        await asyncio.sleep(0.05)
        completion = MagicMock()
        completion.choices = [MagicMock()]
        completion.choices[0].message = MagicMock(content="ok", tool_calls=None)
        completion.usage = MagicMock(prompt_tokens=1, completion_tokens=1, total_tokens=2)
        return completion

    fake_client.chat = MagicMock()
    fake_client.chat.completions = MagicMock()
    fake_client.chat.completions.create = _slow_call

    response, _calls = await provider.chat(
        messages=_user_messages(),
        model="gpt-4o",
        max_tokens=64,
    )
    assert response.content == "ok"
    assert captured
    assert captured[0] is not None
    assert getattr(provider, _CURRENT_TASK_ATTR) is None


# ---------------------------------------------------------------------------
# F-0003 — Anthropic non-streaming cancel populates _current_task
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_f0003_anthropic_chat_populates_current_task() -> None:
    """Anthropic ``chat`` registers the active task so ``cancel_request`` can cancel.

    F-0003 was that the Anthropic non-streaming path never assigned
    ``self._current_task``, making ``cancel_request`` a no-op.  The fix
    wraps the ``_retry_with_backoff`` call in ``asyncio.create_task`` and
    assigns the handle for the duration of the request.
    """
    provider = AnthropicProvider()
    provider.connected = True
    fake_client = MagicMock()
    setattr(provider, _CLIENT_ATTR, fake_client)

    in_flight = asyncio.Event()
    release = asyncio.Event()
    captured_task: list[object] = []

    async def _slow_create(**_: object) -> object:
        in_flight.set()
        await release.wait()
        msg = MagicMock()
        msg.content = [MagicMock(type="text", text="done")]
        msg.usage = MagicMock(input_tokens=1, output_tokens=1, cache_creation_input_tokens=0, cache_read_input_tokens=0)
        return msg

    fake_client.messages = MagicMock()
    fake_client.messages.create = _slow_create

    async def _chat_then_observe() -> None:
        await in_flight.wait()
        current = getattr(provider, _CURRENT_TASK_ATTR)
        captured_task.append(current)
        release.set()

    chat_coro = provider.chat(
        messages=_user_messages("hello"),
        model="claude-opus-4-7",
        max_tokens=64,
    )
    _, observer_result = await asyncio.gather(chat_coro, _chat_then_observe())
    _ = observer_result

    assert len(captured_task) == 1, "Observer did not run"
    task = captured_task[0]
    assert task is not None, "_current_task was None during in-flight call"
    assert isinstance(task, asyncio.Task), f"_current_task is not an asyncio.Task: {type(task)}"
    assert task.done(), "Task should be done after chat() returned"
    assert getattr(provider, _CURRENT_TASK_ATTR) is None, "_current_task not cleared after call"


# ---------------------------------------------------------------------------
# F-0008 — orchestrator drains pending usage and thinking
# ---------------------------------------------------------------------------


def test_f0008_orchestrator_records_provider_usage() -> None:
    """Orchestrator drains ``get_pending_usage`` after each LLM call.

    The unit constructs the helper directly and asserts that the
    counters land in :class:`OrchestratorStats` and the response
    message inherits the captured ``thinking_content``.
    """
    fake_provider = MagicMock(spec=LLMProviderBase)
    fake_provider.name = MagicMock()
    fake_provider.name.value = "anthropic"
    fake_provider.get_pending_usage.return_value = UsageInfo(
        prompt_tokens=120,
        completion_tokens=84,
        total_tokens=204,
    )
    fake_provider.get_pending_thinking.return_value = ["First thought.", "Second thought."]

    response = Message(role="assistant", content="hi")

    config = OrchestratorConfig()
    orchestrator = object.__new__(Orchestrator)
    setattr(orchestrator, _STATS_ATTR, OrchestratorStats())
    setattr(orchestrator, _CONFIG_ATTR, config)
    record = getattr(orchestrator, _RECORD_USAGE_ATTR)
    record(provider=fake_provider, response=response)

    stats: OrchestratorStats = getattr(orchestrator, _STATS_ATTR)
    assert stats.provider_prompt_tokens == 120
    assert stats.provider_completion_tokens == 84
    assert stats.provider_total_tokens == 204
    assert stats.thinking_blocks_collected == 2
    assert response.thinking_content == "First thought.\n\nSecond thought."


# ---------------------------------------------------------------------------
# F-0006 — OpenAI chat_stream propagates transport errors on cancel
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_f0006_openai_chat_stream_reraises_on_cancel_and_error() -> None:
    """A connection error during cancellation is surfaced, not swallowed.

    Previously the stream loop only re-raised when ``cancel_requested``
    was ``False``.  After the fix the outer ``except`` always raises a
    typed :class:`ProviderError`, even when the cancel flag is set.
    """
    provider = OpenAIProvider()
    provider.connected = True
    fake_client = MagicMock()
    provider.client = fake_client

    class _Stream:
        def __aiter__(self) -> _Stream:
            return self

        async def __anext__(self) -> object:
            raise ConnectionError(_KABOOM_MESSAGE)

    fake_client.chat = MagicMock()
    fake_client.chat.completions = MagicMock()
    fake_client.chat.completions.create = AsyncMock(return_value=_Stream())

    async def _consume() -> None:
        setattr(provider, _CANCEL_REQUESTED_ATTR, True)
        async for _ in provider.chat_stream(
            messages=_user_messages(),
            model="gpt-4o",
            max_tokens=32,
        ):
            pass

    with pytest.raises(ProviderError, match=_KABOOM_MESSAGE):
        await _consume()


# ---------------------------------------------------------------------------
# F-0006 — 4-provider swallow-on-cancel pattern removed
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_f0006_openrouter_chat_stream_reraises_on_cancel_and_error() -> None:
    """OpenRouter stream re-raises transport errors even when cancel flag is set.

    Previously ``if not self._cancel_requested: raise`` swallowed the
    transport error when the cancel flag was set.  The fix always raises
    :class:`ProviderError` so real connection failures are surfaced.
    """
    provider = OpenRouterProvider()
    provider.connected = True
    fake_client = MagicMock()
    provider.client = fake_client

    class _FailCtx:
        async def __aenter__(self) -> object:
            raise ConnectionError(_KABOOM_MESSAGE)

        async def __aexit__(self, *_: object) -> bool:
            return False

    fake_client.stream = MagicMock(return_value=_FailCtx())

    async def _consume() -> None:
        setattr(provider, _CANCEL_REQUESTED_ATTR, True)
        async for _ in provider.chat_stream(
            messages=_user_messages(),
            model="openai/gpt-4o",
            max_tokens=32,
        ):
            pass

    with pytest.raises(ProviderError, match=_KABOOM_MESSAGE):
        await _consume()


@pytest.mark.asyncio
async def test_f0006_grok_chat_stream_reraises_on_cancel_and_error() -> None:
    """Grok stream re-raises transport errors even when cancel flag is set.

    Previously ``if not self._cancel_requested: raise`` swallowed the
    error.  The fix always raises :class:`ProviderError`.
    """
    provider = GrokProvider()
    provider.connected = True
    fake_client = MagicMock()
    provider.client = fake_client

    class _ErrStream:
        def __aiter__(self) -> _ErrStream:
            return self

        async def __anext__(self) -> object:
            raise ConnectionError(_KABOOM_MESSAGE)

    fake_client.chat = MagicMock()
    fake_client.chat.completions = MagicMock()
    fake_client.chat.completions.create = AsyncMock(return_value=_ErrStream())

    async def _consume() -> None:
        setattr(provider, _CANCEL_REQUESTED_ATTR, True)
        async for _ in provider.chat_stream(
            messages=_user_messages(),
            model="grok-3",
            max_tokens=32,
        ):
            pass

    with pytest.raises(ProviderError, match=_KABOOM_MESSAGE):
        await _consume()


@pytest.mark.asyncio
async def test_f0006_anthropic_chat_stream_reraises_on_cancel_and_error() -> None:
    """Anthropic stream re-raises transport errors even when cancel flag is set.

    Previously ``if not self._cancel_requested: raise`` in the
    ``except (ConnectionError, ...)`` clause swallowed errors during
    cancellation.  The fix always raises :class:`ProviderError`.
    """
    provider = AnthropicProvider()
    provider.connected = True
    fake_client = MagicMock()
    setattr(provider, _CLIENT_ATTR, fake_client)

    stream_ctx = MagicMock()
    stream_ctx.__aenter__ = AsyncMock(side_effect=ConnectionError(_KABOOM_MESSAGE))
    stream_ctx.__aexit__ = AsyncMock(return_value=False)
    fake_client.messages = MagicMock()
    fake_client.messages.stream = MagicMock(return_value=stream_ctx)

    async def _consume() -> None:
        setattr(provider, _CANCEL_REQUESTED_ATTR, True)
        async for _ in provider.chat_stream(
            messages=_user_messages(),
            model="claude-opus-4-7",
            max_tokens=32,
        ):
            pass

    with pytest.raises(ProviderError):
        await _consume()


@pytest.mark.asyncio
async def test_f0006_google_chat_stream_reraises_on_cancel_and_error() -> None:
    """Google stream re-raises transport errors even when cancel flag is set.

    Previously ``if not self._cancel_requested: raise`` swallowed the
    error.  The fix always raises :class:`ProviderError`.
    """
    provider = GoogleProvider()
    provider.connected = True
    fake_client = MagicMock()
    provider.client = fake_client

    async def _raise_stream(*_args: object, **_kwargs: object) -> object:
        await asyncio.sleep(0)
        raise ConnectionError(_KABOOM_MESSAGE)

    fake_client.aio = MagicMock()
    fake_client.aio.models = MagicMock()
    fake_client.aio.models.generate_content_stream = _raise_stream

    async def _consume() -> None:
        setattr(provider, _CANCEL_REQUESTED_ATTR, True)
        async for _ in provider.chat_stream(
            messages=_user_messages(),
            model="gemini-2.0-flash",
            max_tokens=32,
        ):
            pass

    with pytest.raises(ProviderError):
        await _consume()


# ---------------------------------------------------------------------------
# F-0002 follow-up — o-series temperature pinned without thinking
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_f0002_openai_o_series_pins_temperature_without_thinking() -> None:
    """O-series chat without thinking still forces temperature=1.0.

    The o-series API constraint on temperature applies to the model itself,
    not to the reasoning_effort parameter.  A request without thinking but
    targeting o4-mini must still pin temperature to 1.0 or the API returns
    HTTP 400.
    """
    provider = OpenAIProvider()
    provider.connected = True
    fake_client = MagicMock()
    provider.client = fake_client
    captured_kwargs: list[dict[str, object]] = []

    async def _capture(**kwargs: object) -> object:
        await asyncio.sleep(0)
        captured_kwargs.append(dict(kwargs))
        completion = MagicMock()
        completion.choices = [MagicMock()]
        completion.choices[0].message = MagicMock(content="ok", tool_calls=None)
        completion.usage = MagicMock(prompt_tokens=10, completion_tokens=5, total_tokens=15)
        return completion

    fake_client.chat = MagicMock()
    fake_client.chat.completions = MagicMock()
    fake_client.chat.completions.create = _capture

    await provider.chat(
        messages=_user_messages("hello"),
        model="o4-mini",
        temperature=0.7,
        max_tokens=1024,
        thinking=None,
    )

    assert captured_kwargs, "No API call was captured"
    kwargs = captured_kwargs[0]
    assert "max_completion_tokens" in kwargs
    assert "max_tokens" not in kwargs
    actual_temperature = float(cast("float", kwargs["temperature"]))
    assert abs(actual_temperature - 1.0) < 1e-9, "o-series MUST receive temperature=1.0 even without thinking"


# ---------------------------------------------------------------------------
# F-0004 — Grok / Google / OpenRouter use _retry_with_backoff
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_f0004_grok_retries_on_transient_rate_limit() -> None:
    """Grok ``chat`` retries once on a transient ``RateLimitError``.

    Drives the real :meth:`GrokProvider.chat` against a fake transport
    boundary that raises :class:`RateLimitError` on the first call and
    returns a valid completion on the second.  The independent oracle is
    the invocation counter: exactly two transport calls must occur and
    the returned :class:`Message` must carry the expected content.  If
    ``_retry_with_backoff`` were removed from ``GrokProvider.chat``, the
    first ``RateLimitError`` would propagate uncaught and the test would
    fail with that exception instead of reaching the assertion.

    ``asyncio.sleep`` is patched to a no-op so backoff delays do not slow
    the test suite.
    """
    rate_limit_msg = "grok transient rate limit"
    call_count = 0

    async def _create_with_one_failure(**_kwargs: object) -> object:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RateLimitError(rate_limit_msg)
        await asyncio.sleep(0)
        completion = MagicMock()
        completion.choices = [MagicMock()]
        completion.choices[0].message = MagicMock(content="grok-retried-ok", tool_calls=None)
        completion.usage = MagicMock(prompt_tokens=5, completion_tokens=3, total_tokens=8)
        return completion

    provider = GrokProvider()
    provider.connected = True
    fake_client = MagicMock()
    fake_client.chat = MagicMock()
    fake_client.chat.completions = MagicMock()
    fake_client.chat.completions.create = _create_with_one_failure
    provider.client = fake_client

    with patch("intellicrack.providers.base.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
        mock_sleep.return_value = None
        response, _ = await provider.chat(
            messages=_user_messages("hello"),
            model="grok-3",
            max_tokens=64,
        )

    assert call_count == 2, f"Grok must retry once: expected 2 calls, got {call_count}"
    assert response.content == "grok-retried-ok"
    assert response.role == "assistant"


@pytest.mark.asyncio
async def test_f0004_openrouter_retries_on_transient_rate_limit() -> None:
    """OpenRouter ``chat`` retries once on a transient ``RateLimitError``.

    Drives the real :meth:`OpenRouterProvider.chat` against a fake httpx
    transport boundary that raises :class:`RateLimitError` on the first
    call and returns a valid JSON response on the second.  The independent
    oracle is the invocation counter: exactly two transport calls must
    occur and the returned :class:`Message` must carry the expected content.
    If ``_retry_with_backoff`` were removed from ``OpenRouterProvider.chat``,
    the first ``RateLimitError`` would propagate uncaught.

    ``asyncio.sleep`` is patched to a no-op so backoff delays do not slow
    the test suite.
    """
    rate_limit_msg = "openrouter transient rate limit"
    call_count = 0

    async def _post_with_one_failure(*_args: object, **_kwargs: object) -> object:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RateLimitError(rate_limit_msg)
        await asyncio.sleep(0)
        resp = MagicMock()
        resp.status_code = 200
        resp.raise_for_status = MagicMock()
        resp.json.return_value = {
            "choices": [{"message": {"content": "openrouter-retried-ok"}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
        }
        return resp

    provider = OpenRouterProvider()
    provider.connected = True
    fake_client = MagicMock()
    fake_client.post = AsyncMock(side_effect=_post_with_one_failure)
    provider.client = fake_client

    with patch("intellicrack.providers.base.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
        mock_sleep.return_value = None
        response, _ = await provider.chat(
            messages=_user_messages("hello"),
            model="openai/gpt-4o",
            max_tokens=64,
        )

    assert call_count == 2, f"OpenRouter must retry once: expected 2 calls, got {call_count}"
    assert response.content == "openrouter-retried-ok"
    assert response.role == "assistant"


@pytest.mark.asyncio
async def test_f0004_google_retries_on_transient_rate_limit() -> None:
    """Google ``chat`` retries once on a transient ``RateLimitError``.

    Drives the real :meth:`GoogleProvider.chat` (which delegates to
    ``_run_google_chat``) against a fake ``generate_content`` transport
    boundary that raises :class:`RateLimitError` on the first call and
    returns a valid response on the second.  The independent oracle is
    the invocation counter: exactly two transport calls must occur and
    the returned :class:`Message` must carry the expected content.  If
    ``_retry_with_backoff`` were removed from ``_run_google_chat``, the
    first ``RateLimitError`` would propagate uncaught.

    ``asyncio.sleep`` is patched to a no-op so backoff delays do not slow
    the test suite.
    """
    rate_limit_msg = "google transient rate limit"
    call_count = 0

    async def _generate_with_one_failure(**_kwargs: object) -> object:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RateLimitError(rate_limit_msg)
        await asyncio.sleep(0)
        resp = MagicMock()
        resp.text = "google-retried-ok"
        resp.function_calls = None
        resp.candidates = []
        resp.prompt_feedback = None
        resp.usage_metadata = None
        return resp

    provider = GoogleProvider()
    provider.connected = True
    fake_client = MagicMock()
    fake_client.aio = MagicMock()
    fake_client.aio.models = MagicMock()
    fake_client.aio.models.generate_content = AsyncMock(side_effect=_generate_with_one_failure)
    provider.client = fake_client

    with patch("intellicrack.providers.base.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
        mock_sleep.return_value = None
        response, _ = await provider.chat(
            messages=_user_messages("hello"),
            model="gemini-2.0-flash",
            max_tokens=64,
        )

    assert call_count == 2, f"Google must retry once: expected 2 calls, got {call_count}"
    assert response.content == "google-retried-ok"
    assert response.role == "assistant"


# ---------------------------------------------------------------------------
# Live network tests (env-gated at the test level only)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not os.environ.get("ANTHROPIC_API_KEY"),
    reason="ANTHROPIC_API_KEY not set; live network test skipped",
)
@pytest.mark.asyncio
async def test_anthropic_live_enable_cache_round_trip() -> None:
    """End-to-end: enable_cache emits Anthropic ``cache_creation`` usage.

    Live test gated on ``ANTHROPIC_API_KEY``.  Connects, sends a chat
    request with ``enable_cache=True`` against the live API, and
    asserts the provider stored a ``UsageInfo`` (caching may or may
    not be hit on first run depending on prefix size).
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    assert api_key
    provider = AnthropicProvider()
    creds = ProviderCredentials(api_key=api_key)
    await provider.connect(creds)
    try:
        response, _ = await provider.chat(
            messages=[
                Message(role="system", content="You answer with the single word 'pong'."),
                Message(role="user", content="ping"),
            ],
            model="claude-haiku-4-5",
            max_tokens=64,
            enable_cache=True,
        )
        assert isinstance(response.content, str)
        usage = provider.get_pending_usage()
        assert usage is not None
    finally:
        await provider.disconnect()


@pytest.mark.skipif(
    not os.environ.get("OPENAI_API_KEY"),
    reason="OPENAI_API_KEY not set; live network test skipped",
)
@pytest.mark.asyncio
async def test_openai_live_chat_records_usage() -> None:
    """Live: OpenAI chat records token usage on the provider.

    Verifies the cancel-task plumbing and usage capture against the
    real API.  Skipped without ``OPENAI_API_KEY``.
    """
    api_key = os.environ.get("OPENAI_API_KEY")
    assert api_key
    provider = OpenAIProvider()
    creds = ProviderCredentials(api_key=api_key)
    await provider.connect(creds)
    try:
        response, _ = await provider.chat(
            messages=_user_messages("Reply with 'pong'."),
            model="gpt-4o-mini",
            max_tokens=16,
        )
        assert isinstance(response.content, str)
        usage = provider.get_pending_usage()
        assert usage is not None
        assert usage.total_tokens > 0
    finally:
        await provider.disconnect()
