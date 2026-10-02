# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Progress a server reports on a request that is still running.

A client asks for progress by giving a request a ``progressToken`` in its ``_meta``; the server answers with
``notifications/progress`` carrying the token, how far it has got, optionally the total, and optionally a message. Intellicrack asks for
it on every tool call, resource read and prompt fetch, on both protocol generations, and hands each notice on as an :class:`McpProgress`.

The message is the server's own text, so it is cleaned of hidden characters and forged fence markers and bounded before anything shows
it. Whether a notice counts as progress for the request's deadline is decided by the connection: only a value above the last one does,
as the protocol requires progress to increase.
"""

from __future__ import annotations

import enum
import math
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from intellicrack.core.untrusted_text import clean_untrusted_label


PROGRESS_MESSAGE_LIMIT: Final[int] = 300
"""The most characters of a server's progress message that are kept."""


class ProgressKind(enum.StrEnum):
    """Which kind of request the progress is for.

    Attributes:
        TOOL: A ``tools/call``.
        RESOURCE: A ``resources/read``.
        PROMPT: A ``prompts/get``.
    """

    TOOL = "tool"
    RESOURCE = "resource"
    PROMPT = "prompt"


@dataclass(frozen=True, slots=True)
class McpProgress:
    """One progress notice from a server.

    Attributes:
        server_id: The server reporting.
        kind: The kind of request.
        subject: The tool's name, the resource's URI or the prompt's name.
        progress: How far the server has got.
        total: The total it is working towards, or ``None`` when unknown.
        message: What the server said about it, cleaned, or ``None``.
    """

    server_id: str
    kind: ProgressKind
    subject: str
    progress: float
    total: float | None = None
    message: str | None = None

    @classmethod
    def from_wire(
        cls,
        server_id: str,
        kind: ProgressKind,
        subject: str,
        *,
        progress: float,
        total: float | None,
        message: str | None,
    ) -> McpProgress:
        """Build a notice from what the server sent, cleaning its text.

        Args:
            server_id: The server reporting.
            kind: The kind of request.
            subject: What the request is for.
            progress: How far the server has got.
            total: Its total, or ``None``.
            message: Its message, or ``None``.

        Returns:
            McpProgress: The notice, its message cleaned and bounded and a
            total that is not a positive finite number dropped.
        """
        cleaned = clean_untrusted_label(message, limit=PROGRESS_MESSAGE_LIMIT) if message else None
        usable_total = total if total is not None and math.isfinite(total) and total > 0 else None
        return cls(
            server_id=server_id,
            kind=kind,
            subject=clean_untrusted_label(subject),
            progress=progress,
            total=usable_total,
            message=cleaned or None,
        )

    @property
    def fraction(self) -> float | None:
        """How much of the total is done.

        Returns:
            float | None: A value from 0 to 1, or ``None`` when the total is
            unknown.
        """
        if self.total is None:
            return None
        return min(1.0, max(0.0, self.progress / self.total))

    def describe(self) -> str:
        """Render the notice for the operator.

        Returns:
            str: How far the server has got, out of what total, and what it
            said, such as ``3/10: indexing sections``.
        """
        amount = f"{self.progress:g}/{self.total:g}" if self.total is not None else f"{self.progress:g}"
        return f"{amount}: {self.message}" if self.message else amount


type ProgressFn = Callable[[McpProgress], None]
"""Receives each progress notice for one request."""
