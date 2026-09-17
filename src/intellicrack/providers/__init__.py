# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""LLM Provider implementations for Intellicrack.

This module contains provider implementations for various LLM APIs including Anthropic Claude, OpenAI GPT, Google Gemini, Ollama,
OpenRouter, and local Transformers with Intel XPU acceleration.
"""

from __future__ import annotations

from intellicrack.providers.anthropic import AnthropicProvider
from intellicrack.providers.base import (
    LLMProvider,
    LLMProviderBase,
    ToolCallBufferManager,
    create_anthropic_tool_schema,
    create_google_tool_schema,
    create_openai_tool_schema,
)
from intellicrack.providers.capabilities import (
    ApiDialect,
    CapabilityOverride,
    ModelCapabilities,
    ReasoningSupport,
    TokenLimitField,
    ToolSearchSupport,
    merge_capabilities,
)
from intellicrack.providers.configurable import ConfigurableProvider
from intellicrack.providers.dialects import (
    ChatCompletionsAdapter,
    DialectAdapter,
    DialectRequest,
    DialectResponse,
    GeminiAdapter,
    MessagesAdapter,
    ResponsesAdapter,
    StreamDelta,
    ToolNameStyle,
    adapter_for,
)
from intellicrack.providers.discovery import DiscoveryCache, DiscoveryFilter, ModelDiscovery
from intellicrack.providers.google import GoogleProvider
from intellicrack.providers.grok import GrokProvider
from intellicrack.providers.huggingface import HuggingFaceProvider
from intellicrack.providers.instances import ProviderInstance, TransportRisk, classify_transport
from intellicrack.providers.local_transformers import LocalTransformersProvider
from intellicrack.providers.model_loader import (
    LoadedModel,
    ModelCache,
    clear_global_cache,
    estimate_model_memory,
    get_global_model_cache,
    load_model_for_cpu,
    load_model_for_xpu,
    set_global_cache_size,
)
from intellicrack.providers.model_metadata import IngestedModel, ModelFetcherRegistry, ingest_models
from intellicrack.providers.ollama import OllamaProvider
from intellicrack.providers.openai import OpenAIProvider
from intellicrack.providers.openrouter import OpenRouterProvider
from intellicrack.providers.presets import BUILTIN_PRESETS, COMPATIBLE_PRESETS, ProviderPreset, preset_for
from intellicrack.providers.registry import (
    CredentialLoaderProtocol,
    ProviderRegistry,
    get_provider_registry,
    reset_provider_registry,
)
from intellicrack.providers.xpu_utils import (
    XPUDeviceInfo,
    check_windows_requirements,
    clear_xpu_cache,
    get_optimal_dtype_for_xpu,
    get_xpu_device_count,
    get_xpu_device_info,
    get_xpu_memory_info,
    initialize_xpu,
    is_arc_b580,
    is_xpu_available,
)


__all__: list[str] = [
    "BUILTIN_PRESETS",
    "COMPATIBLE_PRESETS",
    "AnthropicProvider",
    "ApiDialect",
    "CapabilityOverride",
    "ChatCompletionsAdapter",
    "ConfigurableProvider",
    "CredentialLoaderProtocol",
    "DialectAdapter",
    "DialectRequest",
    "DialectResponse",
    "DiscoveryCache",
    "DiscoveryFilter",
    "GeminiAdapter",
    "GoogleProvider",
    "GrokProvider",
    "HuggingFaceProvider",
    "IngestedModel",
    "LLMProvider",
    "LLMProviderBase",
    "LoadedModel",
    "LocalTransformersProvider",
    "MessagesAdapter",
    "ModelCache",
    "ModelCapabilities",
    "ModelDiscovery",
    "ModelFetcherRegistry",
    "OllamaProvider",
    "OpenAIProvider",
    "OpenRouterProvider",
    "ProviderInstance",
    "ProviderPreset",
    "ProviderRegistry",
    "ReasoningSupport",
    "ResponsesAdapter",
    "StreamDelta",
    "TokenLimitField",
    "ToolCallBufferManager",
    "ToolNameStyle",
    "ToolSearchSupport",
    "TransportRisk",
    "XPUDeviceInfo",
    "adapter_for",
    "check_windows_requirements",
    "classify_transport",
    "clear_global_cache",
    "clear_xpu_cache",
    "create_anthropic_tool_schema",
    "create_google_tool_schema",
    "create_openai_tool_schema",
    "estimate_model_memory",
    "get_global_model_cache",
    "get_optimal_dtype_for_xpu",
    "get_provider_registry",
    "get_xpu_device_count",
    "get_xpu_device_info",
    "get_xpu_memory_info",
    "ingest_models",
    "initialize_xpu",
    "is_arc_b580",
    "is_xpu_available",
    "load_model_for_cpu",
    "load_model_for_xpu",
    "merge_capabilities",
    "preset_for",
    "reset_provider_registry",
    "set_global_cache_size",
]
