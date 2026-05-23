# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Error-logging helpers for typed-exception passthrough patterns.

These helpers exist so every ``except ... : raise`` site emits a structured log event before re-raising, satisfying the project rule that every except
clause must log even when re-raising. Centralizing the pattern keeps call sites terse and consistent across providers, bridges, and core modules.
"""

from __future__ import annotations

from typing import TYPE_CHECKING


if TYPE_CHECKING:
    import structlog


def log_passthrough(
    logger: structlog.stdlib.BoundLogger,
    event: str,
    exc: BaseException,
    **context: object,
) -> None:
    """Emit a structured warning event describing an exception about to be re-raised.

    Callers are expected to follow the call with a bare ``raise`` (inside an
    ``except ... as exc:`` block) so the original traceback is preserved. The
    helper does not raise itself, which keeps the ``raise`` statement visible
    to static analysers (pydoclint, basedpyright) that infer documented
    ``Raises:`` clauses from the function body.

    Args:
        logger: BoundLogger to emit the event on.
        event: Stable snake_case event name
            (e.g. ``"ollama_list_tags_passthrough"``).
        exc: Exception being re-raised; only its ``str()`` and class name are
            recorded.
        **context: Additional structured kwargs (provider, model, op, etc.).
    """
    logger.warning(
        event,
        error=str(exc),
        error_type=type(exc).__name__,
        **context,
    )
