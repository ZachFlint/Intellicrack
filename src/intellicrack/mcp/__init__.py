# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Model Context Protocol client for Intellicrack.

Third-party MCP servers appear inside Intellicrack as ordinary tools: they are configured in ``mcp.json``, connected over stdio or
Streamable HTTP, and registered into the same tool registry the built-in bridges use, so the orchestrator, the confirmation dialog and the
chat transcript treat them exactly as they treat Ghidra or Frida.

What is deliberately different is trust. A bridge ships with the application; a server does not. Nothing local is launched without the
operator seeing the exact command first, a server's claims about its own tools count for nothing until the operator marks it trusted, and
every piece of text a server sends is bounded and fenced before it reaches the model.

This package imports no Qt and is importable headless. The dialogs that ask the operator anything live under :mod:`intellicrack.ui`, and
reach this package through the callables it accepts.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

from intellicrack.mcp.catalog import (
    McpToolCatalog,
    McpToolEntry,
    compute_generation,
    fetch_catalog,
)
from intellicrack.mcp.config import (
    MCP_CONFIG_FILENAME,
    NAMESPACE_PREFIX,
    SERVER_ID_PATTERN,
    HttpServerSpec,
    McpConfigDocument,
    McpConfigStore,
    McpInputSpec,
    McpSandboxSpec,
    McpServerConfig,
    McpTransportKind,
    StdioServerSpec,
    from_canonical_name,
    is_mcp_namespace,
    to_canonical_name,
)
from intellicrack.mcp.consent import (
    ApprovalRecord,
    ApprovalScope,
    ApprovalStore,
    ConsentAnswer,
    DangerousPattern,
    McpConsentGate,
    TrustState,
    TrustStore,
    deny_all_launches,
    describe_launch,
    scan_command_for_dangerous_patterns,
    server_identity,
)
from intellicrack.mcp.errors import (
    McpAuthError,
    McpConfigError,
    McpConnectionError,
    McpConsentDeniedError,
    McpError,
    McpProtocolError,
)
from intellicrack.mcp.policy import ToolCost, enabled_entries, estimate_tool_cost
from intellicrack.mcp.sandbox_launch import (
    ENVIRONMENT_ALLOWLIST,
    JobLimits,
    SandboxedJob,
    SandboxedLaunch,
    apply_job_limits,
    build_sandboxed_startup,
    sandbox_supported,
)
from intellicrack.mcp.secrets import MCP_SECRET_NAMESPACE, McpSecretResolver
from intellicrack.mcp.tool_source import (
    UNTRUSTED_BLOCK_END,
    UNTRUSTED_BLOCK_START,
    McpToolSource,
    map_result,
    map_tool_to_function,
    sanitize_untrusted_text,
    source_label,
    validate_structured_content,
)
from intellicrack.mcp.validation import SchemaViolation, validate_against_schema


if TYPE_CHECKING:
    from intellicrack.mcp.auth import (
        KeyringTokenStorage,
        build_oauth_provider,
        has_stored_credentials,
        issuer_for,
        resolve_client_identity,
        sign_out,
    )
    from intellicrack.mcp.connection import (
        McpConnection,
        McpConnectionManager,
        McpHealth,
        McpServerStatus,
    )
    from intellicrack.mcp.resources import (
        PromptSummary,
        ResourceSummary,
        get_prompt,
        list_prompts,
        list_resources,
        read_resource,
    )


def __getattr__(name: str) -> object:
    """Resolve an SDK-backed export the first time it is used.

    Everything else in this package is plain Python, so configuration, consent, naming and validation stay importable when the ``mcp``
    SDK is missing. Loading the modules that talk to servers only when one of their names is asked for is what lets a missing SDK disable
    MCP instead of breaking every module that merely checks whether a tool name belongs to it. The resolved object is cached on the package
    globals so later look-ups bypass this hook.

    Args:
        name: The attribute being looked up.

    Returns:
        object: The exported object.

    Raises:
        AttributeError: If ``name`` is not an export of this package.
    """
    sdk_exports: dict[str, str] = {
        "KeyringTokenStorage": "intellicrack.mcp.auth",
        "build_oauth_provider": "intellicrack.mcp.auth",
        "has_stored_credentials": "intellicrack.mcp.auth",
        "issuer_for": "intellicrack.mcp.auth",
        "resolve_client_identity": "intellicrack.mcp.auth",
        "sign_out": "intellicrack.mcp.auth",
        "McpConnection": "intellicrack.mcp.connection",
        "McpConnectionManager": "intellicrack.mcp.connection",
        "McpHealth": "intellicrack.mcp.connection",
        "McpServerStatus": "intellicrack.mcp.connection",
        "PromptSummary": "intellicrack.mcp.resources",
        "ResourceSummary": "intellicrack.mcp.resources",
        "get_prompt": "intellicrack.mcp.resources",
        "list_prompts": "intellicrack.mcp.resources",
        "list_resources": "intellicrack.mcp.resources",
        "read_resource": "intellicrack.mcp.resources",
    }
    module_name = sdk_exports.get(name)
    if module_name is None:
        message = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(message)
    value: object = getattr(importlib.import_module(module_name), name)
    globals()[name] = value
    return value


__all__ = [
    "ENVIRONMENT_ALLOWLIST",
    "MCP_CONFIG_FILENAME",
    "MCP_SECRET_NAMESPACE",
    "NAMESPACE_PREFIX",
    "SERVER_ID_PATTERN",
    "UNTRUSTED_BLOCK_END",
    "UNTRUSTED_BLOCK_START",
    "ApprovalRecord",
    "ApprovalScope",
    "ApprovalStore",
    "ConsentAnswer",
    "DangerousPattern",
    "HttpServerSpec",
    "JobLimits",
    "KeyringTokenStorage",
    "McpAuthError",
    "McpConfigDocument",
    "McpConfigError",
    "McpConfigStore",
    "McpConnection",
    "McpConnectionError",
    "McpConnectionManager",
    "McpConsentDeniedError",
    "McpConsentGate",
    "McpError",
    "McpHealth",
    "McpInputSpec",
    "McpProtocolError",
    "McpSandboxSpec",
    "McpSecretResolver",
    "McpServerConfig",
    "McpServerStatus",
    "McpToolCatalog",
    "McpToolEntry",
    "McpToolSource",
    "McpTransportKind",
    "PromptSummary",
    "ResourceSummary",
    "SandboxedJob",
    "SandboxedLaunch",
    "SchemaViolation",
    "StdioServerSpec",
    "ToolCost",
    "TrustState",
    "TrustStore",
    "apply_job_limits",
    "build_oauth_provider",
    "build_sandboxed_startup",
    "compute_generation",
    "deny_all_launches",
    "describe_launch",
    "enabled_entries",
    "estimate_tool_cost",
    "fetch_catalog",
    "from_canonical_name",
    "get_prompt",
    "has_stored_credentials",
    "is_mcp_namespace",
    "issuer_for",
    "list_prompts",
    "list_resources",
    "map_result",
    "map_tool_to_function",
    "read_resource",
    "resolve_client_identity",
    "sandbox_supported",
    "sanitize_untrusted_text",
    "scan_command_for_dangerous_patterns",
    "server_identity",
    "sign_out",
    "source_label",
    "to_canonical_name",
    "validate_against_schema",
    "validate_structured_content",
]
