# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""One adapter per API dialect, and the exhaustive dispatch that selects them.

Provider identity is an open string, so the exhaustiveness guarantee that the
closed provider enum used to give basedpyright lives here instead:
:func:`adapter_for` dispatches over the closed
:class:`~intellicrack.providers.capabilities.ApiDialect` and ends in
``_assert_never``. Removing a branch is a type error, not a runtime surprise.

``local_transformers`` is deliberately outside this package. It is not an HTTP
provider at all -- it runs ``AutoModelForCausalLM.from_pretrained`` and
``model.generate()`` in-process -- so it implements ``LLMProviderBase``
directly and has no dialect. Code that maps a provider to a dialect must
tolerate ``None``.
"""

from __future__ import annotations

from intellicrack.providers.capabilities import ApiDialect
from intellicrack.providers.dialects.base import (
    API_KEY_PLACEHOLDER,
    AUTH_HEADER_NAMES,
    PROTOCOL_HEADER_NAMES,
    DialectAdapter,
    DialectRequest,
    DialectResponse,
    StreamDelta,
    ToolCallFragment,
    ToolNameStyle,
    UsageInfo,
    describe_tool_result_part,
    headers_receiving_api_key,
    image_parts,
    interpolate_headers,
    merge_auth_headers,
    parse_tool_call,
    render_parts_as_text,
    serialize_tool_result,
    structured_parts,
    tool_result_text,
    wire_function_name,
)
from intellicrack.providers.dialects.chat_completions import ChatCompletionsAdapter
from intellicrack.providers.dialects.gemini import GeminiAdapter
from intellicrack.providers.dialects.messages import MessagesAdapter
from intellicrack.providers.dialects.registry import adapter_for, default_capabilities_for
from intellicrack.providers.dialects.responses import ResponsesAdapter


__all__ = [
    "API_KEY_PLACEHOLDER",
    "AUTH_HEADER_NAMES",
    "PROTOCOL_HEADER_NAMES",
    "ApiDialect",
    "ChatCompletionsAdapter",
    "DialectAdapter",
    "DialectRequest",
    "DialectResponse",
    "GeminiAdapter",
    "MessagesAdapter",
    "ResponsesAdapter",
    "StreamDelta",
    "ToolCallFragment",
    "ToolNameStyle",
    "UsageInfo",
    "adapter_for",
    "default_capabilities_for",
    "describe_tool_result_part",
    "headers_receiving_api_key",
    "image_parts",
    "interpolate_headers",
    "merge_auth_headers",
    "parse_tool_call",
    "render_parts_as_text",
    "serialize_tool_result",
    "structured_parts",
    "tool_result_text",
    "wire_function_name",
]
