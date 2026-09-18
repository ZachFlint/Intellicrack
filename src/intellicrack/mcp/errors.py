# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Error hierarchy for the Model Context Protocol client.

Every failure raised by :mod:`intellicrack.mcp` derives from
:class:`McpError`, which itself derives from
:class:`~intellicrack.core.types.IntellicrackError`, so a caller that already
handles Intellicrack errors keeps working unchanged while a caller that cares
about MCP specifically can narrow to one branch of the tree.
"""

from __future__ import annotations

from intellicrack.core.types import IntellicrackError


class McpError(IntellicrackError):
    """Base class for every Model Context Protocol failure."""


class McpConfigError(McpError):
    """A server configuration is malformed, unsafe, or unresolvable.

    Raised for a bad ``serverId``, a literal secret written into
    ``mcp.json``, an unresolvable ``${input:id}`` reference, and shell
    metacharacters in a launch command.
    """


class McpConnectionError(McpError):
    """A server could not be reached, or an established connection dropped."""


class McpConsentDeniedError(McpError):
    """The operator refused consent for an action that requires it.

    Raised before a local server process is spawned when the consent gate
    reports refusal, so nothing is launched.
    """


class McpProtocolError(McpError):
    """A server violated the protocol contract it advertised.

    Raised when a tool result fails the ``outputSchema`` the server itself
    published, and for a tool listing that cannot be interpreted.
    """


class McpAuthError(McpError):
    """Authorization against an HTTP server failed or is unavailable.

    Raised when the keyring backing per-server tokens is unusable, when an
    issuer check rejects stored credentials, and when an interactive sign-in
    cannot be completed.
    """
