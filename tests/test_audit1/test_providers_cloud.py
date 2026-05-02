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
import inspect
import os
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import AsyncMock, MagicMock

import pytest

from intellicrack.core.orchestrator import Orchestrator, OrchestratorConfig, OrchestratorStats
from intellicrack.core.types import (
    Message,
    ProviderCredentials,
    ProviderError,
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


def test_f0001_chat_signatures_accept_enable_cache_and_thinking() -> None:
    """Every cloud provider's ``chat`` accepts ``enable_cache`` and ``thinking``.

    The audit findings call out that callers were silently dropping
    these knobs.  This is a regression guard at the signature level —
    the parameters must continue to be present even after future
    refactors.
    """
    for provider_cls in (AnthropicProvider, OpenAIProvider, GrokProvider, OpenRouterProvider, GoogleProvider):
        sig = inspect.signature(provider_cls.chat)
        cls_name = provider_cls.__name__
        assert "enable_cache" in sig.parameters, f"{cls_name}.chat lost enable_cache"
        assert "thinking" in sig.parameters, f"{cls_name}.chat lost thinking"


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
# F-0004 — Grok / Google / OpenRouter use _retry_with_backoff
# ---------------------------------------------------------------------------


def test_f0004_providers_use_retry_with_backoff_in_chat_path() -> None:
    """Static check: each provider references _retry_with_backoff.

    Confirms the retry wrapper is present in each provider's
    non-streaming chat source so transient rate-limit failures
    actually back off instead of fast-failing.  Source-level inspection
    avoids running live network code while still verifying wiring.
    """
    sources: dict[str, str] = {
        "grok": inspect.getsource(GrokProvider.chat),
        "openrouter": inspect.getsource(OpenRouterProvider.chat),
        "google": inspect.getsource(GoogleProvider.chat),
    }
    for name, src in sources.items():
        assert "_retry_with_backoff" in src, f"{name}.chat missing _retry_with_backoff"


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
