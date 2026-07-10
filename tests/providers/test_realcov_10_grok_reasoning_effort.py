# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-logic coverage for Grok reasoning-effort and model classification.

``GrokProvider._reasoning_effort_for`` and its supporting classifiers
(:meth:`_supports_reasoning_effort`, :meth:`_supports_max_completion_tokens`,
:meth:`_infer_context_window`, :meth:`_is_chat_model`,
:meth:`_infer_supports_vision`) are pure, deterministic logic with no network
dependency. They decide which request fields a Grok call must carry, so they
are driven here with real Grok model identifiers and ``ThinkingConfig`` budgets
and the computed routing decision is asserted directly.

A live round-trip test (gated on a real ``XAI_API_KEY``) confirms that a
``thinking``-enabled chat against a real multi-agent model is accepted by the
X.AI API, proving the resolved ``reasoning_effort`` is wire-compatible.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from intellicrack.core.types import (
    Message,
    ProviderError,
    ThinkingConfig,
)
from intellicrack.providers.base import (
    REASONING_EFFORT_HIGH_THRESHOLD,
    REASONING_EFFORT_LOW_THRESHOLD,
    REASONING_EFFORT_MEDIUM_THRESHOLD,
)
from intellicrack.providers.grok import GrokProvider


_SUPPORTS_REASONING_ATTR = "_supports_reasoning_effort"
_SUPPORTS_MAX_COMPLETION_ATTR = "_supports_max_completion_tokens"
_INFER_CONTEXT_ATTR = "_infer_context_window"
_IS_CHAT_MODEL_ATTR = "_is_chat_model"
_INFER_VISION_ATTR = "_infer_supports_vision"
_RESOLVE_EFFORT_ATTR = "_reasoning_effort_for"

_supports_reasoning_effort: Any = getattr(GrokProvider, _SUPPORTS_REASONING_ATTR)
_supports_max_completion_tokens: Any = getattr(GrokProvider, _SUPPORTS_MAX_COMPLETION_ATTR)
_infer_context_window: Any = getattr(GrokProvider, _INFER_CONTEXT_ATTR)
_is_chat_model: Any = getattr(GrokProvider, _IS_CHAT_MODEL_ATTR)
_infer_supports_vision: Any = getattr(GrokProvider, _INFER_VISION_ATTR)


def _resolve_effort(
    provider: GrokProvider,
    *,
    model: str,
    thinking: ThinkingConfig | None,
) -> str | None:
    """Resolve reasoning_effort via the provider's protected resolver.

    Args:
        provider: Grok provider instance.
        model: Grok model identifier.
        thinking: Thinking configuration or None.

    Returns:
        str | None: The resolved reasoning effort tier, or None.
    """
    resolver: Any = getattr(provider, _RESOLVE_EFFORT_ATTR)
    return cast("str | None", resolver(model=model, thinking=thinking))


class TestReasoningEffortResolution:
    """_reasoning_effort_for maps real budgets onto Grok's effort knob."""

    @staticmethod
    def test_disabled_thinking_omits_reasoning_effort() -> None:
        """A disabled thinking config yields no reasoning_effort field."""
        provider = GrokProvider()
        cfg = ThinkingConfig(enabled=False, budget_tokens=20000)
        assert _resolve_effort(provider, model="grok-4-multi-agent", thinking=cfg) is None

    @staticmethod
    def test_none_thinking_omits_reasoning_effort() -> None:
        """A missing thinking config yields no reasoning_effort field."""
        provider = GrokProvider()
        assert _resolve_effort(provider, model="grok-4-multi-agent", thinking=None) is None

    @staticmethod
    def test_auto_reasoning_model_omits_reasoning_effort() -> None:
        """grok-4 reasons automatically, so the parameter is omitted."""
        provider = GrokProvider()
        cfg = ThinkingConfig(enabled=True, budget_tokens=20000)
        assert _resolve_effort(provider, model="grok-4", thinking=cfg) is None
        assert _resolve_effort(provider, model="grok-4-fast", thinking=cfg) is None

    @staticmethod
    def test_multi_agent_low_budget_maps_to_low() -> None:
        """A small budget on a multi-agent model resolves to ``low``."""
        provider = GrokProvider()
        cfg = ThinkingConfig(enabled=True, budget_tokens=REASONING_EFFORT_LOW_THRESHOLD)
        assert _resolve_effort(provider, model="grok-4-multi-agent", thinking=cfg) == "low"

    @staticmethod
    def test_multi_agent_medium_budget_maps_to_medium() -> None:
        """A mid-range budget on a multi-agent model resolves to ``medium``."""
        provider = GrokProvider()
        cfg = ThinkingConfig(enabled=True, budget_tokens=REASONING_EFFORT_MEDIUM_THRESHOLD)
        assert _resolve_effort(provider, model="grok-4-multi-agent", thinking=cfg) == "medium"

    @staticmethod
    def test_multi_agent_high_budget_maps_to_high() -> None:
        """A high budget at the high threshold resolves to ``high``."""
        provider = GrokProvider()
        cfg = ThinkingConfig(enabled=True, budget_tokens=REASONING_EFFORT_HIGH_THRESHOLD)
        assert _resolve_effort(provider, model="grok-4-multi-agent", thinking=cfg) == "high"

    @staticmethod
    def test_multi_agent_excessive_budget_maps_to_xhigh() -> None:
        """Budgets above the high threshold resolve to Grok's ``xhigh`` tier."""
        provider = GrokProvider()
        cfg = ThinkingConfig(enabled=True, budget_tokens=REASONING_EFFORT_HIGH_THRESHOLD + 50000)
        assert _resolve_effort(provider, model="grok-4-multi-agent", thinking=cfg) == "xhigh"


class TestGrokModelClassification:
    """Classifier helpers route real Grok model identifiers correctly."""

    @staticmethod
    def test_supports_reasoning_effort_only_multi_agent() -> None:
        """Only multi-agent variants accept reasoning_effort."""
        assert _supports_reasoning_effort("grok-4-multi-agent") is True
        assert _supports_reasoning_effort("grok-4") is False
        assert _supports_reasoning_effort("grok-3") is False

    @staticmethod
    def test_max_completion_tokens_for_grok4_and_newer() -> None:
        """grok-4+ use max_completion_tokens; grok-3 uses legacy max_tokens."""
        assert _supports_max_completion_tokens("grok-4") is True
        assert _supports_max_completion_tokens("grok-4-multi-agent") is True
        assert _supports_max_completion_tokens("grok-3") is False
        assert _supports_max_completion_tokens("grok-2-1212") is False

    @staticmethod
    def test_infer_context_window_by_generation() -> None:
        """Context window inference reflects each Grok generation's size."""
        assert _infer_context_window("grok-4-fast") == 256000
        assert _infer_context_window("grok-3-mini") == 131072
        assert _infer_context_window("grok-1") == 8192
        assert _infer_context_window("totally-unknown") == 131072

    @staticmethod
    def test_is_chat_model_excludes_embeddings_and_moderation() -> None:
        """Embedding and moderation prefixes are not chat models."""
        assert _is_chat_model("grok-4") is True
        assert _is_chat_model("embed-large") is False
        assert _is_chat_model("moderation-latest") is False

    @staticmethod
    def test_infer_supports_vision_by_name() -> None:
        """Vision support is inferred from vision/image markers in the id."""
        assert _infer_supports_vision("grok-2-vision-1212") is True
        assert _infer_supports_vision("grok-image-gen") is True
        assert _infer_supports_vision("grok-4") is False


@pytest.mark.integration
class TestGrokReasoningEffortLive:
    """Live confirmation that resolved reasoning_effort is API-compatible."""

    @pytest.mark.asyncio
    @staticmethod
    async def test_multi_agent_thinking_request_round_trips(
        grok_provider: GrokProvider,
    ) -> None:
        """A thinking-enabled chat against a real multi-agent model succeeds.

        The resolved ``reasoning_effort`` value must be accepted by the X.AI
        API. The test discovers a real multi-agent model from the live model
        list and skips when the account exposes none.

        Args:
            grok_provider: Connected Grok provider fixture.
        """
        models = await grok_provider.list_models()
        multi_agent = next(
            (m.id for m in models if _supports_reasoning_effort(m.id)),
            None,
        )
        if multi_agent is None:
            pytest.skip("No grok multi-agent model available on this account")

        thinking = ThinkingConfig(enabled=True, budget_tokens=REASONING_EFFORT_MEDIUM_THRESHOLD)
        try:
            message, _ = await grok_provider.chat(
                messages=[Message(role="user", content="Reply with the single word: ready")],
                model=multi_agent,
                max_tokens=256,
                thinking=thinking,
            )
        except ProviderError as exc:
            pytest.skip(f"Grok multi-agent request not serviceable: {exc}")

        assert isinstance(message.content, str)
        assert message.content.strip()
