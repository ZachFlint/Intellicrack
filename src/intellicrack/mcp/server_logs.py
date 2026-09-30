# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Log messages MCP servers send, routed into Intellicrack's own logging.

A server may send ``notifications/message`` log records: on a 2025-11-25 connection at or above the level ``logging/setLevel`` asked
for, and on a 2026-07-28 connection only for requests that opt in with a ``logLevel`` in their ``_meta``. Every record is the server's
own text, so it is cleaned of invisible characters and forged fence markers and bounded before it is logged. Each record goes to the
structlog pipeline -- and so to the log files and the log viewer -- with the server it came from, its level mapped onto structlog's, and
is kept in a bounded per-server buffer the MCP settings show. A server that floods is rate limited per server; what it sends over the
limit is counted, not logged, and the count is reported once the limit allows.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Final

from intellicrack.core.logging import get_logger
from intellicrack.core.untrusted_text import clean_untrusted_label


if TYPE_CHECKING:
    from collections.abc import Callable

    from mcp.client.session import LoggingFnT
    from mcp_types import LoggingMessageNotificationParams


_logger = get_logger(__name__)
_server_logger = get_logger("intellicrack.mcp.server")

LOG_RECORD_TEXT_LIMIT: Final[int] = 4000
"""Longest record text kept, in characters."""

DEFAULT_BUFFER_RECORDS: Final[int] = 500
"""Records kept per server for the settings view."""

DEFAULT_RATE_PER_S: Final[float] = 20.0
"""Records per second a server may log once its burst is spent."""

DEFAULT_BURST: Final[int] = 100
"""Records a server may log at once before the rate applies."""

_STRUCTLOG_METHODS: Final[dict[str, str]] = {
    "debug": "debug",
    "info": "info",
    "notice": "info",
    "warning": "warning",
    "error": "error",
    "critical": "critical",
    "alert": "critical",
    "emergency": "critical",
}
"""structlog method each protocol level is logged with; an unknown level logs as ``warning``."""


@dataclass(frozen=True, slots=True)
class McpLogRecord:
    """One log message a server sent, cleaned for display.

    Attributes:
        received_at: When it arrived.
        server_id: The server that sent it.
        level: Its protocol level, such as ``warning``.
        logger: The server-side logger name it gave, if any.
        text: Its data, rendered as text and cleaned.
    """

    received_at: datetime
    server_id: str
    level: str
    logger: str | None
    text: str

    def render(self) -> str:
        """Render the record as one line of the settings view.

        Returns:
            str: ``time level [logger] text``.
        """
        source = f" [{self.logger}]" if self.logger else ""
        return f"{self.received_at.astimezone().strftime('%H:%M:%S')} {self.level.upper()}{source} {self.text}"


@dataclass(slots=True)
class _Bucket:
    """One server's rate-limit state.

    Attributes:
        tokens: Records it may log right now.
        refilled_at: Monotonic time the tokens were last topped up.
        suppressed: Records dropped since the last one logged.
    """

    tokens: float
    refilled_at: float
    suppressed: int = 0


@dataclass(slots=True)
class _ServerLog:
    """One server's buffer and rate-limit state.

    Attributes:
        records: The most recent records, oldest first.
        bucket: The rate limit.
    """

    records: deque[McpLogRecord]
    bucket: _Bucket = field(default_factory=lambda: _Bucket(tokens=float(DEFAULT_BURST), refilled_at=time.monotonic()))


def render_log_data(data: object) -> str:
    """Render a record's ``data``, which may be any JSON value, as text.

    Args:
        data: The record's data.

    Returns:
        str: A string as it is, anything else as compact JSON.
    """
    if isinstance(data, str):
        return data
    try:
        return json.dumps(data, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    except (TypeError, ValueError):
        return repr(data)


class McpServerLogBook:
    """Receives every server's log messages and keeps each server's recent ones.

    Callbacks are invoked on the MCP event loop and listeners are called there too; a GUI listener must hand the record to its own
    thread.
    """

    def __init__(
        self,
        *,
        capacity: int = DEFAULT_BUFFER_RECORDS,
        rate_per_s: float = DEFAULT_RATE_PER_S,
        burst: int = DEFAULT_BURST,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Create an empty log book.

        Args:
            capacity: Records kept per server.
            rate_per_s: Records per second a server may log after its burst.
            burst: Records a server may log at once.
            clock: Monotonic clock the rate limit reads.
        """
        self._capacity = capacity
        self._rate_per_s = rate_per_s
        self._burst = burst
        self._clock = clock
        self._lock = threading.Lock()
        self._servers: dict[str, _ServerLog] = {}
        self._listeners: list[Callable[[McpLogRecord], None]] = []

    def callback_for(self, server_id: str) -> LoggingFnT:
        """Build the SDK logging callback for one server.

        Args:
            server_id: The server the callback receives messages from.

        Returns:
            LoggingFnT: The callback.
        """

        async def on_message(params: LoggingMessageNotificationParams) -> None:
            """Take one log message from the server, then let the loop run, so a flood of them cannot starve it.

            Args:
                params: The notification's parameters.
            """
            _ = self.receive(server_id, params.level, params.logger, params.data)
            await asyncio.sleep(0)

        return on_message

    def receive(self, server_id: str, level: str, logger: str | None, data: object) -> McpLogRecord | None:
        """Log, keep and announce one message, unless the server is over its rate.

        Args:
            server_id: The server that sent it.
            level: Its protocol level.
            logger: Its logger name, if any.
            data: Its data.

        Returns:
            McpLogRecord | None: The record, or ``None`` when it was rate limited.
        """
        record = McpLogRecord(
            received_at=datetime.now(tz=UTC),
            server_id=server_id,
            level=level,
            logger=clean_untrusted_label(logger) if logger else None,
            text=clean_untrusted_label(render_log_data(data), limit=LOG_RECORD_TEXT_LIMIT),
        )
        with self._lock:
            entry = self._servers.setdefault(server_id, _ServerLog(records=deque(maxlen=self._capacity)))
            suppressed = self._take_token(entry.bucket)
            if suppressed is None:
                entry.bucket.suppressed += 1
                return None
            entry.records.append(record)
            listeners = list(self._listeners)
        if suppressed:
            _server_logger.warning("mcp_server_log_suppressed", mcp_server=server_id, suppressed=suppressed)
        method = getattr(_server_logger, _STRUCTLOG_METHODS.get(level, "warning"))
        method("mcp_server_log", mcp_server=server_id, mcp_level=level, mcp_logger=record.logger, message=record.text)
        for listener in listeners:
            try:
                listener(record)
            except (RuntimeError, ValueError, TypeError, AttributeError) as exc:
                _logger.warning("mcp_server_log_listener_failed", server_id=server_id, error=str(exc))
        return record

    def _take_token(self, bucket: _Bucket) -> int | None:
        """Spend one of a server's tokens, topping them up for the time passed.

        The caller holds ``self._lock``.

        Args:
            bucket: The server's rate-limit state.

        Returns:
            int | None: How many records were suppressed before this one,
            which the caller reports; ``None`` when there is no token and
            this record is suppressed too.
        """
        now = self._clock()
        bucket.tokens = min(float(self._burst), bucket.tokens + (now - bucket.refilled_at) * self._rate_per_s)
        bucket.refilled_at = now
        if bucket.tokens < 1.0:
            return None
        bucket.tokens -= 1.0
        suppressed, bucket.suppressed = bucket.suppressed, 0
        return suppressed

    def records(self, server_id: str) -> list[McpLogRecord]:
        """Return a server's recent records.

        Args:
            server_id: The server.

        Returns:
            list[McpLogRecord]: Its records, oldest first.
        """
        with self._lock:
            entry = self._servers.get(server_id)
            return list(entry.records) if entry is not None else []

    def suppressed(self, server_id: str) -> int:
        """Report how many of a server's records are being held back by its rate limit.

        Args:
            server_id: The server.

        Returns:
            int: Records dropped since its last logged one.
        """
        with self._lock:
            entry = self._servers.get(server_id)
            return entry.bucket.suppressed if entry is not None else 0

    def add_listener(self, listener: Callable[[McpLogRecord], None]) -> None:
        """Call a function for every record kept from now on.

        Args:
            listener: Receives each record, on the MCP event loop.
        """
        with self._lock:
            self._listeners.append(listener)

    def remove_listener(self, listener: Callable[[McpLogRecord], None]) -> None:
        """Stop calling a listener.

        Args:
            listener: A listener added earlier.
        """
        with self._lock:
            if listener in self._listeners:
                self._listeners.remove(listener)
