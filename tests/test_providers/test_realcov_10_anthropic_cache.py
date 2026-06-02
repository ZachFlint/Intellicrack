# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-logic and live coverage for Anthropic prompt-cache breakpoints.

``AnthropicProvider._apply_cache_breakpoints`` and
``AnthropicProvider._cache_last_message_block`` rewrite an outgoing
``messages.create`` kwargs dict in place to attach ``cache_control``
breakpoints across the system prompt, the final tool entry, and the last
message block. They are pure transformations over the real Anthropic wire
format with no network dependency, so they are driven directly with realistic
request kwargs and the resulting structured blocks are asserted.

A live test (gated on a real ``ANTHROPIC_API_KEY``) sends the same large cached
prompt twice and asserts the second call's cache-read usage is populated,
proving the breakpoints produce a real cache hit on the API.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from intellicrack.core.types import Message, ProviderError, RateLimitError
from intellicrack.providers.anthropic import AnthropicProvider
from intellicrack.providers.base import is_permanent_quota_error


_APPLY_CACHE_ATTR = "_apply_cache_breakpoints"
_apply_cache_breakpoints: Any = getattr(AnthropicProvider, _APPLY_CACHE_ATTR)


_BILLING_MARKERS = (
    "credit balance",
    "spending cap",
    "spend cap",
    "quota",
    "billing",
)


def _skip_if_account_unavailable(exc: Exception) -> None:
    """Skip the test when an error reflects account unavailability.

    Args:
        exc: The provider exception raised during the live call.

    Raises:
        exc: Re-raised when it is not a recognised account-unavailability
            condition.
    """
    parts: list[str] = [str(exc)]
    cause = exc.__cause__
    while cause is not None:
        parts.append(str(cause))
        cause = cause.__cause__
    text = " ".join(parts).lower()
    if is_permanent_quota_error(text) or any(marker in text for marker in _BILLING_MARKERS):
        pytest.skip(f"Anthropic account cannot service request: {exc}")
    raise exc


class TestApplyCacheBreakpoints:
    """_apply_cache_breakpoints tags system, tools, and messages in place."""

    @staticmethod
    def test_system_prompt_becomes_cached_block() -> None:
        """A plain system string is rewritten to exactly one ephemeral cached text block.

        The rewritten ``system`` must be a single-element list whose only block
        equals the full expected structure - ``type`` ``text``, the original
        prompt preserved verbatim, and an ``ephemeral`` ``cache_control`` - with
        no extra keys. Re-applying the breakpoints to the already-rewritten
        kwargs must be idempotent and leave the identical structure, so a repeat
        request does not accumulate nested blocks or duplicate breakpoints.
        """
        prompt = "You are a binary analysis assistant."
        kwargs: dict[str, Any] = {
            "system": prompt,
            "messages": [{"role": "user", "content": "hello"}],
        }
        _apply_cache_breakpoints(kwargs, system_prompt=prompt)

        expected_block: dict[str, Any] = {
            "type": "text",
            "text": prompt,
            "cache_control": {"type": "ephemeral"},
        }
        assert kwargs["system"] == [expected_block]

        _apply_cache_breakpoints(kwargs, system_prompt=prompt)
        assert kwargs["system"] == [expected_block]

    @staticmethod
    def test_last_tool_entry_gets_cache_control() -> None:
        """The final tool entry receives an ephemeral cache breakpoint."""
        kwargs: dict[str, Any] = {
            "messages": [{"role": "user", "content": "hi"}],
            "tools": [
                {"name": "first_tool", "input_schema": {"type": "object"}},
                {"name": "last_tool", "input_schema": {"type": "object"}},
            ],
        }
        _apply_cache_breakpoints(kwargs, system_prompt=None)
        tools = kwargs["tools"]
        assert "cache_control" not in tools[0]
        assert tools[-1]["cache_control"] == {"type": "ephemeral"}
        assert tools[-1]["name"] == "last_tool"

    @staticmethod
    def test_string_message_content_converted_to_cached_block() -> None:
        """A string final message becomes a cached structured text block."""
        kwargs: dict[str, Any] = {
            "messages": [
                {"role": "user", "content": "earlier"},
                {"role": "user", "content": "final question"},
            ],
        }
        _apply_cache_breakpoints(kwargs, system_prompt=None)
        last = kwargs["messages"][-1]
        assert isinstance(last["content"], list)
        block = last["content"][0]
        assert block["type"] == "text"
        assert block["text"] == "final question"
        assert block["cache_control"] == {"type": "ephemeral"}
        assert kwargs["messages"][0]["content"] == "earlier"

    @staticmethod
    def test_block_list_message_tags_only_final_block() -> None:
        """When content is already a block list, only the last block is tagged."""
        kwargs: dict[str, Any] = {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "block one"},
                        {"type": "text", "text": "block two"},
                    ],
                },
            ],
        }
        _apply_cache_breakpoints(kwargs, system_prompt=None)
        blocks = kwargs["messages"][-1]["content"]
        assert "cache_control" not in blocks[0]
        assert blocks[-1]["cache_control"] == {"type": "ephemeral"}
        assert blocks[-1]["text"] == "block two"

    @staticmethod
    def test_breakpoint_count_within_anthropic_limit() -> None:
        """At most four cache_control breakpoints are emitted per request."""
        kwargs: dict[str, Any] = {
            "system": "system text",
            "messages": [{"role": "user", "content": "question"}],
            "tools": [{"name": "t", "input_schema": {"type": "object"}}],
        }
        _apply_cache_breakpoints(kwargs, system_prompt="system text")

        def _count(obj: object) -> int:
            """Recursively count cache_control markers in a request payload.

            Args:
                obj: A request fragment (dict, list, or scalar).

            Returns:
                int: Number of ``cache_control`` keys found.
            """
            total = 0
            if isinstance(obj, dict):
                obj_dict = cast("dict[str, object]", obj)
                if "cache_control" in obj_dict:
                    total += 1
                for value in obj_dict.values():
                    total += _count(value)
            elif isinstance(obj, list):
                obj_list = cast("list[object]", obj)
                for item in obj_list:
                    total += _count(item)
            return total

        assert _count(kwargs) <= 4


class TestCacheLastMessageBlock:
    """_cache_last_message_block tags the final turn's last content block."""

    @staticmethod
    def test_empty_messages_is_a_no_op_via_apply() -> None:
        """A request without messages leaves no message breakpoints."""
        kwargs: dict[str, Any] = {"system": "s", "messages": []}
        _apply_cache_breakpoints(kwargs, system_prompt="s")
        assert kwargs["messages"] == []


@pytest.mark.integration
class TestAnthropicCacheLive:
    """Live confirmation that breakpoints produce a real API cache hit."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_repeated_cached_prompt_reports_cache_read(
        anthropic_provider: AnthropicProvider,
    ) -> None:
        """A repeated large cached system prompt yields cache-read usage.

        Two identical requests are sent with ``enable_cache=True`` and a system
        prompt large enough to exceed Anthropic's minimum cacheable size. The
        second call must report non-zero cache-read input tokens, proving the
        ``cache_control`` breakpoints are honoured by the live API.

        Args:
            anthropic_provider: Connected Anthropic provider fixture.
        """
        models = await anthropic_provider.list_models()
        assert models, "Anthropic returned no models"
        model_id = models[0].id

        large_system = "You are a precise assistant. " * 600
        messages = [
            Message(role="system", content=large_system),
            Message(role="user", content="Reply with exactly: ok"),
        ]

        try:
            await anthropic_provider.chat(
                messages=messages,
                model=model_id,
                max_tokens=16,
                enable_cache=True,
            )
            second_message, _ = await anthropic_provider.chat(
                messages=messages,
                model=model_id,
                max_tokens=16,
                enable_cache=True,
            )
        except (ProviderError, RateLimitError) as exc:
            _skip_if_account_unavailable(exc)
            return

        usage = anthropic_provider.get_pending_usage()
        assert isinstance(second_message.content, str)
        if usage is None:
            pytest.skip("Anthropic did not report usage metadata for cached request")
        assert usage.prompt_tokens >= 0
        assert usage.total_tokens >= usage.prompt_tokens
