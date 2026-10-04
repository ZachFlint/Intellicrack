# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Exports of :mod:`intellicrack.providers`, each resolved on first use.

``intellicrack.core.config`` imports the providers package for the provider
ids alone, so every bridge and the whole of :mod:`intellicrack.core` import
it. When the package imported its submodules eagerly, that loaded every
provider SDK and, through the local Transformers provider, PyTorch and
Transformers: a fresh interpreter spent several seconds on a workstation, and
more than a minute on a loaded CI runner, before it could import a single
bridge or print the application's version.

The package still exports every name it did. It resolves each one here the
first time it is asked for, so a process pays only for the providers it uses.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Final


if TYPE_CHECKING:
    from collections.abc import Mapping


_PACKAGE: Final[str] = "intellicrack.providers"

LAZY_EXPORTS: Final[Mapping[str, str]] = {
    "AnthropicProvider": f"{_PACKAGE}.anthropic",
    "LLMProvider": f"{_PACKAGE}.base",
    "LLMProviderBase": f"{_PACKAGE}.base",
    "ToolCallBufferManager": f"{_PACKAGE}.base",
    "create_anthropic_tool_schema": f"{_PACKAGE}.base",
    "create_google_tool_schema": f"{_PACKAGE}.base",
    "create_openai_tool_schema": f"{_PACKAGE}.base",
    "ApiDialect": f"{_PACKAGE}.capabilities",
    "CapabilityOverride": f"{_PACKAGE}.capabilities",
    "ModelCapabilities": f"{_PACKAGE}.capabilities",
    "ReasoningSupport": f"{_PACKAGE}.capabilities",
    "TokenLimitField": f"{_PACKAGE}.capabilities",
    "ToolSearchSupport": f"{_PACKAGE}.capabilities",
    "merge_capabilities": f"{_PACKAGE}.capabilities",
    "ConfigurableProvider": f"{_PACKAGE}.configurable",
    "ChatCompletionsAdapter": f"{_PACKAGE}.dialects",
    "DialectAdapter": f"{_PACKAGE}.dialects",
    "DialectRequest": f"{_PACKAGE}.dialects",
    "DialectResponse": f"{_PACKAGE}.dialects",
    "GeminiAdapter": f"{_PACKAGE}.dialects",
    "MessagesAdapter": f"{_PACKAGE}.dialects",
    "ResponsesAdapter": f"{_PACKAGE}.dialects",
    "StreamDelta": f"{_PACKAGE}.dialects",
    "ToolNameStyle": f"{_PACKAGE}.dialects",
    "adapter_for": f"{_PACKAGE}.dialects",
    "DiscoveryCache": f"{_PACKAGE}.discovery",
    "DiscoveryFilter": f"{_PACKAGE}.discovery",
    "ModelDiscovery": f"{_PACKAGE}.discovery",
    "GoogleProvider": f"{_PACKAGE}.google",
    "GrokProvider": f"{_PACKAGE}.grok",
    "HuggingFaceProvider": f"{_PACKAGE}.huggingface",
    "ProviderInstance": f"{_PACKAGE}.instances",
    "TransportRisk": f"{_PACKAGE}.instances",
    "classify_transport": f"{_PACKAGE}.instances",
    "LocalTransformersProvider": f"{_PACKAGE}.local_transformers",
    "LoadedModel": f"{_PACKAGE}.model_loader",
    "ModelCache": f"{_PACKAGE}.model_loader",
    "clear_global_cache": f"{_PACKAGE}.model_loader",
    "estimate_model_memory": f"{_PACKAGE}.model_loader",
    "get_global_model_cache": f"{_PACKAGE}.model_loader",
    "load_model_for_cpu": f"{_PACKAGE}.model_loader",
    "load_model_for_xpu": f"{_PACKAGE}.model_loader",
    "set_global_cache_size": f"{_PACKAGE}.model_loader",
    "IngestedModel": f"{_PACKAGE}.model_metadata",
    "ModelFetcherRegistry": f"{_PACKAGE}.model_metadata",
    "ingest_models": f"{_PACKAGE}.model_metadata",
    "OllamaProvider": f"{_PACKAGE}.ollama",
    "OpenAIProvider": f"{_PACKAGE}.openai",
    "OpenRouterProvider": f"{_PACKAGE}.openrouter",
    "BUILTIN_PRESETS": f"{_PACKAGE}.presets",
    "COMPATIBLE_PRESETS": f"{_PACKAGE}.presets",
    "ProviderPreset": f"{_PACKAGE}.presets",
    "preset_for": f"{_PACKAGE}.presets",
    "CredentialLoaderProtocol": f"{_PACKAGE}.registry",
    "ProviderRegistry": f"{_PACKAGE}.registry",
    "get_provider_registry": f"{_PACKAGE}.registry",
    "reset_provider_registry": f"{_PACKAGE}.registry",
    "XPUDeviceInfo": f"{_PACKAGE}.xpu_utils",
    "check_windows_requirements": f"{_PACKAGE}.xpu_utils",
    "clear_xpu_cache": f"{_PACKAGE}.xpu_utils",
    "get_optimal_dtype_for_xpu": f"{_PACKAGE}.xpu_utils",
    "get_xpu_device_count": f"{_PACKAGE}.xpu_utils",
    "get_xpu_device_info": f"{_PACKAGE}.xpu_utils",
    "get_xpu_memory_info": f"{_PACKAGE}.xpu_utils",
    "initialize_xpu": f"{_PACKAGE}.xpu_utils",
    "is_arc_b580": f"{_PACKAGE}.xpu_utils",
    "is_xpu_available": f"{_PACKAGE}.xpu_utils",
}
"""Each export of the package, and the submodule that defines it."""


def resolve_lazy_export(name: str) -> object:
    """Import the submodule that defines a lazily resolved export and return the export.

    Args:
        name: Attribute name requested from :mod:`intellicrack.providers`.

    Returns:
        object: The export, taken from the submodule that defines it.

    Raises:
        AttributeError: If ``name`` is not a lazily resolved export.
    """
    module_name = LAZY_EXPORTS.get(name)
    if module_name is None:
        msg = f"module {_PACKAGE!r} has no attribute {name!r}"
        raise AttributeError(msg)
    value: object = getattr(importlib.import_module(module_name), name)
    return value
