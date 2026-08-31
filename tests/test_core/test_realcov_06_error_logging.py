# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-data coverage for :mod:`intellicrack.core.error_logging`.

These tests exercise the genuine ``log_passthrough`` helper against a real
structlog ``BoundLogger`` and capture the real event the helper emits. No
behaviour is mocked: ``structlog.testing.capture_logs`` records the exact
event dict that travels through the configured processor chain, so the
assertions validate the helper's true output rather than that a call merely
occurred.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from structlog.testing import capture_logs

from intellicrack.core.error_logging import log_passthrough
from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence


def _find_passthrough_event(
    captured: Sequence[Mapping[str, object]],
) -> Mapping[str, object]:
    """Return the single ``passthrough_exception`` event from captured logs.

    Args:
        captured: The list of captured event dictionaries produced by
            :func:`structlog.testing.capture_logs`.

    Returns:
        Mapping[str, object]: The captured event whose ``event`` key equals
        ``"passthrough_exception"``.
    """
    matches = [entry for entry in captured if entry.get("event") == "passthrough_exception"]
    assert len(matches) == 1, f"expected exactly one passthrough event, found {len(matches)}"
    return matches[0]


def test_log_passthrough_emits_real_warning_event() -> None:
    """``log_passthrough`` emits a real warning event with the exception details."""
    logger = get_logger("tests.error_logging")
    original = ValueError("disk offset out of range")

    with capture_logs() as captured:
        result = log_passthrough(
            logger,
            "ollama_list_tags_passthrough",
            original,
            provider="ollama",
            model="llama3",
        )

    assert result is None
    event = _find_passthrough_event(captured)
    assert event["log_level"] == "warning"
    assert event["op_event"] == "ollama_list_tags_passthrough"
    assert event["error"] == "disk offset out of range"
    assert event["error_type"] == "ValueError"
    assert event["provider"] == "ollama"
    assert event["model"] == "llama3"


def _passthrough_then_reraise(captured_out: list[Mapping[str, object]]) -> None:
    """Reproduce the real ``except ... : log_passthrough(...); raise`` site.

    Logs the in-flight exception with :func:`log_passthrough` and then issues
    a bare ``raise`` so the original ``KeyError`` propagates to the caller,
    exactly as production call sites do.

    Args:
        captured_out: Mutable list that receives the captured event dicts so
            the test can assert on them after the exception propagates.

    Raises:
        KeyError: Always re-raised to prove the passthrough pattern preserves
            the original exception and traceback.
    """
    logger = get_logger("tests.error_logging")
    sessions: dict[str, object] = {}
    try:
        _ = sessions["session-token"]
    except KeyError as exc:
        with capture_logs() as captured:
            log_passthrough(logger, "session_lookup_passthrough", exc, session="abc-123")
        captured_out.extend(captured)
        raise


def test_log_passthrough_preserves_re_raise_pattern() -> None:
    """``log_passthrough`` does not raise, so a following bare ``raise`` runs.

    Mirrors the real call-site contract: the helper logs inside an
    ``except`` block and the caller's subsequent bare ``raise`` must still
    propagate the original exception with its traceback intact.
    """
    captured: list[Mapping[str, object]] = []
    with pytest.raises(KeyError, match="session-token"):
        _passthrough_then_reraise(captured)

    raised_event = _find_passthrough_event(captured)
    assert raised_event["error_type"] == "KeyError"
    assert raised_event["session"] == "abc-123"


def test_log_passthrough_records_exception_subclass_name() -> None:
    """The ``error_type`` field reflects the concrete exception subclass name."""
    logger = get_logger("tests.error_logging")

    class _CustomFailureError(RuntimeError):
        """Local exception subclass used to assert real class-name capture."""

    with capture_logs() as captured:
        log_passthrough(logger, "custom_passthrough", _CustomFailureError("boom"))

    event = _find_passthrough_event(captured)
    assert event["error_type"] == "_CustomFailureError"
    assert event["error"] == "boom"
