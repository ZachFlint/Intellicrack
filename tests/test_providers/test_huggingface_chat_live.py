# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Live end-to-end tests for ``HuggingFaceProvider`` (Group C unit 4).

These tests hit the live HuggingFace Inference API via
``huggingface_hub.AsyncInferenceClient``.  The HuggingFace token is resolved
through the shared ``credential_loader`` fixture which reads ``.env`` or the
equivalent ``HUGGINGFACE_API_TOKEN``/``HUGGINGFACE_TOKEN`` environment
variable.  Tests are skipped when no valid token is available so CI runs
without the secret remain green.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from intellicrack.core.types import Message, ProviderName
from intellicrack.providers.huggingface import HuggingFaceProvider, UsageInfo


if TYPE_CHECKING:
    from intellicrack.credentials.env_loader import CredentialLoader


_LIVE_MODEL = "meta-llama/Meta-Llama-3-8B-Instruct"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_live_chat_returns_content_and_usage(
    credential_loader: CredentialLoader,
    *,
    has_huggingface_key: bool,
) -> None:
    """Live ``chat()`` call returns non-empty content and captures usage.

    Args:
        credential_loader: Loader providing the HuggingFace credentials.
        has_huggingface_key: True when a valid HuggingFace token is present.
    """
    if not has_huggingface_key:
        pytest.skip("HUGGINGFACE_API_TOKEN / HUGGINGFACE_TOKEN not configured")

    credentials = credential_loader.get_credentials(ProviderName.HUGGINGFACE)
    assert credentials is not None, "Expected credentials after validation"

    provider = HuggingFaceProvider()
    await provider.connect(credentials)
    try:
        assert provider.is_connected is True

        messages = [
            Message(role="user", content="Respond with the single word: pong"),
        ]
        response, tool_calls = await provider.chat(
            messages=messages,
            model=_LIVE_MODEL,
            temperature=0.0,
            max_tokens=32,
        )

        assert response.role == "assistant"
        assert response.content, "Expected non-empty assistant content"
        assert tool_calls is None

        usage = provider.get_pending_usage()
        assert isinstance(usage, UsageInfo)
        assert usage.prompt_tokens > 0
        assert usage.completion_tokens > 0
        assert usage.total_tokens >= usage.prompt_tokens
    finally:
        await provider.disconnect()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_live_chat_stream_yields_and_captures_usage(
    credential_loader: CredentialLoader,
    *,
    has_huggingface_key: bool,
) -> None:
    """Live ``chat_stream()`` call yields text chunks and captures usage.

    Args:
        credential_loader: Loader providing the HuggingFace credentials.
        has_huggingface_key: True when a valid HuggingFace token is present.
    """
    if not has_huggingface_key:
        pytest.skip("HUGGINGFACE_API_TOKEN / HUGGINGFACE_TOKEN not configured")

    credentials = credential_loader.get_credentials(ProviderName.HUGGINGFACE)
    assert credentials is not None, "Expected credentials after validation"

    provider = HuggingFaceProvider()
    await provider.connect(credentials)
    try:
        assert provider.is_connected is True

        messages = [
            Message(
                role="user",
                content="Count the tokens: one two three four five.",
            ),
        ]
        chunks: list[str] = [
            chunk
            async for chunk in provider.chat_stream(
                messages=messages,
                model=_LIVE_MODEL,
                temperature=0.0,
                max_tokens=64,
            )
        ]

        full_text = "".join(chunks)
        assert full_text.strip(), "Expected non-empty streamed text"
        assert any(chunks), "Stream produced no chunks"

        usage = provider.get_pending_usage()
        if usage is not None:
            assert isinstance(usage, UsageInfo)
            assert usage.prompt_tokens > 0
            assert usage.total_tokens >= usage.prompt_tokens
    finally:
        await provider.disconnect()
