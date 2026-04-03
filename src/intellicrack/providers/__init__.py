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
    AnthropicToolSchema,
    GoogleFunctionDeclaration,
    JSONSchemaParameters,
    JSONSchemaProperty,
    LLMProvider,
    LLMProviderBase,
    OpenAIFunctionSchema,
    OpenAIToolSchema,
    ToolCallBufferManager,
    create_anthropic_tool_schema,
    create_google_tool_schema,
    create_openai_tool_schema,
)
from intellicrack.providers.discovery import DiscoveryCache, DiscoveryEvent, DiscoveryFilter, ModelDiscovery
from intellicrack.providers.google import GoogleProvider
from intellicrack.providers.grok import GrokProvider
from intellicrack.providers.huggingface import HuggingFaceProvider
from intellicrack.providers.local_transformers import LocalTransformersProvider
from intellicrack.providers.model_loader import (
    DtypeOption,
    LoadedModel,
    ModelCache,
    ModelConfig,
    clear_global_cache,
    estimate_model_memory,
    get_global_model_cache,
    load_model_for_cpu,
    load_model_for_xpu,
    set_global_cache_size,
)
from intellicrack.providers.ollama import OllamaProvider
from intellicrack.providers.openai import OpenAIProvider
from intellicrack.providers.openrouter import OpenRouterProvider
from intellicrack.providers.registry import ProviderRegistry
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
    "AnthropicProvider",
    "AnthropicToolSchema",
    "DiscoveryCache",
    "DiscoveryEvent",
    "DiscoveryFilter",
    "DtypeOption",
    "GoogleFunctionDeclaration",
    "GoogleProvider",
    "GrokProvider",
    "HuggingFaceProvider",
    "JSONSchemaParameters",
    "JSONSchemaProperty",
    "LLMProvider",
    "LLMProviderBase",
    "LoadedModel",
    "LocalTransformersProvider",
    "ModelCache",
    "ModelConfig",
    "ModelDiscovery",
    "OllamaProvider",
    "OpenAIFunctionSchema",
    "OpenAIProvider",
    "OpenAIToolSchema",
    "OpenRouterProvider",
    "ProviderRegistry",
    "ToolCallBufferManager",
    "XPUDeviceInfo",
    "check_windows_requirements",
    "clear_global_cache",
    "clear_xpu_cache",
    "create_anthropic_tool_schema",
    "create_google_tool_schema",
    "create_openai_tool_schema",
    "estimate_model_memory",
    "get_global_model_cache",
    "get_optimal_dtype_for_xpu",
    "get_xpu_device_count",
    "get_xpu_device_info",
    "get_xpu_memory_info",
    "initialize_xpu",
    "is_arc_b580",
    "is_xpu_available",
    "load_model_for_cpu",
    "load_model_for_xpu",
    "set_global_cache_size",
]
