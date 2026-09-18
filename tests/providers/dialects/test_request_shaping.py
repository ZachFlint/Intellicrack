# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates on the request body each dialect adapter renders.

Routing between OpenAI's two APIs, the name of the token-limit field, whether
``temperature`` is sent at all and whether the endpoint may retain the request
are no longer decided by string-matching a model id. They read from a resolved
:class:`~intellicrack.providers.capabilities.ModelCapabilities` record, which
means a wrong record is now a wrong request body rather than a wrong branch.

These gates resolve capabilities the way the running provider does -- through
the real presets -- and assert on what the adapter actually renders. Each one
fails if the resolution or the rendering regresses.
"""

from __future__ import annotations

from typing import Any

import pytest

from intellicrack.core.json_payload import is_json_array, is_json_object
from intellicrack.core.types import Message
from intellicrack.providers.capabilities import ApiDialect, ModelCapabilities, TokenLimitField, merge_capabilities
from intellicrack.providers.dialects.base import DialectRequest
from intellicrack.providers.dialects.registry import adapter_for
from intellicrack.providers.presets import preset_for


_OPENAI_PRESET_ID = "openai"

_RESPONSES_MODELS = ("gpt-5.4", "o3-mini")
"""OpenAI models whose resolved dialect must be the Responses API."""

_CHAT_COMPLETIONS_MODELS = ("gpt-4o", "gpt-4-turbo", "gpt-3.5-turbo")
"""OpenAI models whose resolved dialect must stay on Chat Completions."""


def _capabilities(model: str) -> ModelCapabilities:
    """Resolve one OpenAI model's capabilities through the real preset table.

    Args:
        model: The model id to resolve.

    Returns:
        ModelCapabilities: The record the provider would use for this model.
    """
    preset = preset_for(_OPENAI_PRESET_ID)
    assert preset is not None, "the shipped OpenAI preset is missing"
    resolved = merge_capabilities(ModelCapabilities(), preset.capabilities_for(model))
    assert resolved.dialect is not None, f"{model} resolved to no dialect"
    return resolved


def _request(model: str, capabilities: ModelCapabilities, *, store: bool | None = None) -> dict[str, Any]:
    """Render a minimal request body for one model through its own adapter.

    Args:
        model: The model id to render for.
        capabilities: The resolved capability record.
        store: Explicit server-side retention choice, or ``None`` to leave the
            decision to the adapter.

    Returns:
        dict[str, Any]: The rendered request body.
    """
    assert capabilities.dialect is not None
    adapter = adapter_for(capabilities.dialect)
    return adapter.build_request(
        DialectRequest(
            model=model,
            messages=[Message(role="user", content="disassemble the entry point")],
            capabilities=capabilities,
            max_tokens=2048,
            store=store,
        ),
    )


@pytest.mark.parametrize("model", _RESPONSES_MODELS)
def test_reasoning_family_posts_to_responses(model: str) -> None:
    """A reasoning-family OpenAI model must render a Responses body.

    ``max_output_tokens`` rather than ``max_tokens``, no ``temperature`` at
    all, and ``store`` false so binary-analysis context is not retained
    server-side.

    Args:
        model: The model id under test.
    """
    capabilities = _capabilities(model)
    assert capabilities.dialect is ApiDialect.RESPONSES
    assert capabilities.token_limit_field is TokenLimitField.MAX_OUTPUT_TOKENS
    assert capabilities.supports_temperature is False

    body = _request(model, capabilities)
    assert body["max_output_tokens"] == 2048
    assert "max_tokens" not in body
    assert "temperature" not in body
    assert body["store"] is False


@pytest.mark.parametrize("model", _CHAT_COMPLETIONS_MODELS)
def test_legacy_family_posts_to_chat_completions(model: str) -> None:
    """A pre-reasoning OpenAI model must stay on Chat Completions.

    Args:
        model: The model id under test.
    """
    capabilities = _capabilities(model)
    assert capabilities.dialect is ApiDialect.CHAT_COMPLETIONS
    assert capabilities.token_limit_field is TokenLimitField.MAX_TOKENS
    assert capabilities.supports_temperature is True

    body = _request(model, capabilities)
    assert body["max_tokens"] == 2048
    assert "max_output_tokens" not in body
    assert body["temperature"] == pytest.approx(0.7)
    assert "store" not in body


def test_store_defaults_to_false_and_honours_an_explicit_opt_in() -> None:
    """Responses must not retain by default, but must obey an explicit choice.

    A default that silently flipped to ``True`` would retain reverse-
    engineering context on OpenAI's servers, so the default is asserted
    separately from the opt-in.
    """
    capabilities = _capabilities("gpt-5.4")

    assert _request("gpt-5.4", capabilities)["store"] is False
    assert _request("gpt-5.4", capabilities, store=False)["store"] is False
    assert _request("gpt-5.4", capabilities, store=True)["store"] is True
    assert _request("gpt-5.4", capabilities, store=None)["store"] is False


def test_not_storing_requests_encrypted_reasoning() -> None:
    """A stateless Responses request must ask for reasoning it can replay.

    With ``store: false`` the endpoint keeps nothing, so a multi-turn
    reasoning chain survives only if the response carries
    ``reasoning.encrypted_content``. Omitting the include silently breaks
    reasoning replay on every tool-use turn.
    """
    capabilities = _capabilities("gpt-5.4")
    assert capabilities.reasoning.encrypted_content is True

    body = _request("gpt-5.4", capabilities)
    assert body["store"] is False
    assert any("encrypted_content" in str(entry) for entry in body.get("include", []))


def _find_key(node: object, key: str) -> list[object]:
    """Collect every value stored under ``key`` anywhere in a request body.

    A dialect is free to nest its token limit -- Gemini puts it inside
    ``generationConfig`` -- so the search is by name rather than by a fixed
    path.

    Args:
        node: The body, or any subtree of it.
        key: The field name to look for.

    Returns:
        list[object]: Every value found under that name, in traversal order.
    """
    if is_json_object(node):
        found: list[object] = [] if key not in node else [node[key]]
        for value in node.values():
            found.extend(_find_key(value, key))
        return found
    if is_json_array(node):
        return [hit for item in node for hit in _find_key(item, key)]
    return []


def test_every_dialect_names_its_own_token_limit_field() -> None:
    """Each adapter must render the token limit under the field it declares.

    A dialect that renders the wrong field name, or omits the limit entirely,
    has the endpoint fall back to its own default. That is silent until a
    response comes back truncated, so it is asserted on the rendered body
    rather than on the declaration alone.
    """
    for dialect in ApiDialect:
        adapter = adapter_for(dialect)
        capabilities = adapter.default_capabilities()
        field_name = adapter.token_limit_field(capabilities)
        body = adapter.build_request(
            DialectRequest(
                model="probe-model",
                messages=[Message(role="user", content="hello")],
                capabilities=capabilities,
                max_tokens=1234,
            ),
        )
        rendered = _find_key(body, field_name)
        assert rendered == [1234], f"{dialect.name}: {field_name} rendered {rendered!r}, body={body!r}"
