# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Exhaustive dispatch from an API dialect to the adapter implementing it.

This is where the exhaustiveness guarantee lives. Provider identity became an
open string, so basedpyright can no longer prove every provider is handled;
instead :func:`adapter_for` dispatches over the closed
:class:`~intellicrack.providers.capabilities.ApiDialect` and ends in
``_assert_never``, which makes an unhandled member a type error.

It is a module of its own rather than package ``__init__`` content because the
dispatch has to import every concrete adapter, and those adapters import the
dialect base in turn.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Never

from intellicrack.core.logging import get_logger
from intellicrack.providers.capabilities import ApiDialect
from intellicrack.providers.dialects.chat_completions import ChatCompletionsAdapter
from intellicrack.providers.dialects.gemini import GeminiAdapter
from intellicrack.providers.dialects.messages import MessagesAdapter
from intellicrack.providers.dialects.responses import ResponsesAdapter


if TYPE_CHECKING:
    from intellicrack.providers.capabilities import ModelCapabilities
    from intellicrack.providers.dialects.base import DialectAdapter


_logger = get_logger(__name__)


def _assert_never(value: Never) -> Never:
    """Assert that a dialect dispatch branch is unreachable.

    Args:
        value: A value of type ``Never``; reaching this function at runtime
            means a dialect member exists that no branch handles.

    Returns:
        Never: This function never returns; it always raises.

    Raises:
        AssertionError: Always.
    """
    message = f"Unhandled API dialect: {value!r}"
    _logger.error("dialect_assert_never_triggered", unexpected_value=repr(value))
    raise AssertionError(message)


def adapter_for(dialect: ApiDialect) -> DialectAdapter:
    """Construct the adapter implementing one API dialect.

    A fresh instance is returned on every call because an adapter may hold
    per-stream state -- the Messages adapter accumulates thinking blocks until
    their signature arrives -- and sharing one across concurrent streams would
    interleave that state.

    Args:
        dialect: The wire format to build an adapter for.

    Returns:
        DialectAdapter: The adapter implementing ``dialect``.
    """
    if dialect is ApiDialect.CHAT_COMPLETIONS:
        return ChatCompletionsAdapter()
    if dialect is ApiDialect.RESPONSES:
        return ResponsesAdapter()
    if dialect is ApiDialect.MESSAGES:
        return MessagesAdapter()
    if dialect is ApiDialect.GEMINI:
        return GeminiAdapter()
    _assert_never(dialect)


def default_capabilities_for(dialect: ApiDialect) -> ModelCapabilities:
    """Return a dialect's baseline capability record.

    Args:
        dialect: The wire format whose defaults are wanted.

    Returns:
        ModelCapabilities: The dialect's baseline record.
    """
    return adapter_for(dialect).default_capabilities()
