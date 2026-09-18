# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Model Context Protocol client for Intellicrack.

Third-party MCP servers appear inside Intellicrack as ordinary tools: they are
configured in ``mcp.json``, connected over stdio or Streamable HTTP, and
registered into the same tool registry the built-in bridges use, so the
orchestrator, the confirmation dialog and the chat transcript treat them
exactly as they treat Ghidra or Frida.

What is deliberately different is trust. A bridge ships with the application;
a server does not. Nothing local is launched without the operator seeing the
exact command first, a server's claims about its own tools count for nothing
until the operator marks it trusted, and every piece of text a server sends is
bounded and fenced before it reaches the model.

This package imports no Qt and is importable headless. The dialogs that ask
the operator anything live under :mod:`intellicrack.ui`, and reach this
package through the callables it accepts.
"""

from __future__ import annotations

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
from intellicrack.mcp.connection import (
    McpConnection,
    McpConnectionManager,
    McpHealth,
    McpServerStatus,
)
from intellicrack.mcp.consent import (
    ApprovalScope,
    ApprovalStore,
    DangerousPattern,
    McpConsentGate,
    TrustState,
    TrustStore,
    describe_launch,
    scan_command_for_dangerous_patterns,
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


__all__ = [
    "MCP_CONFIG_FILENAME",
    "MCP_SECRET_NAMESPACE",
    "NAMESPACE_PREFIX",
    "SERVER_ID_PATTERN",
    "UNTRUSTED_BLOCK_END",
    "UNTRUSTED_BLOCK_START",
    "ApprovalScope",
    "ApprovalStore",
    "DangerousPattern",
    "HttpServerSpec",
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
    "StdioServerSpec",
    "ToolCost",
    "TrustState",
    "TrustStore",
    "compute_generation",
    "describe_launch",
    "enabled_entries",
    "estimate_tool_cost",
    "fetch_catalog",
    "from_canonical_name",
    "is_mcp_namespace",
    "map_result",
    "map_tool_to_function",
    "sanitize_untrusted_text",
    "scan_command_for_dangerous_patterns",
    "source_label",
    "to_canonical_name",
    "validate_structured_content",
]
