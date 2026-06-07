# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for F11 error-handling blocks in :class:`GhidraBridge`.

These tests exercise the real exception-to-:class:`ToolError` translation
that ``define_structure`` and ``create_function`` perform when the attached
``ghidra_bridge`` RPC client raises. No logger is mocked: the structured
warning emitted on the failure path is captured with
:func:`structlog.testing.capture_logs` and asserted field-by-field, so the
test fails if the bridge stops catching, stops logging, or stops re-raising
as a :class:`ToolError`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, NoReturn

import pytest
import structlog

from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from structlog.typing import EventDict


_REMOTE_ERR: str = "simulated_remote_error"
_FUNC_ADDR: int = 0x401000


class _FailingBridgeClient:
    """A ``ghidra_bridge`` RPC double whose ``remote_exec`` always raises.

    This is not a mock of the operation under test: it stands in for the
    upstream ``jfx_bridge`` client and faithfully reproduces the contract
    (``remote_exec`` / ``remote_eval``). The bridge's own error handling is
    what is being validated.
    """

    def remote_exec(self, _code: str) -> NoReturn:
        """Reject every script with a :class:`RuntimeError`.

        Args:
            _code: Jython source the bridge tried to dispatch.

        Raises:
            RuntimeError: Always, to drive the bridge's failure path.
        """
        raise RuntimeError(_REMOTE_ERR)

    def remote_eval(self, _expr: str) -> NoReturn:
        """Reject every expression with a :class:`RuntimeError`.

        Args:
            _expr: Jython expression the bridge tried to evaluate.

        Raises:
            RuntimeError: Always, to drive the bridge's failure path.
        """
        raise RuntimeError(_REMOTE_ERR)


@pytest.fixture
def bridge_with_failing_fake() -> GhidraBridge:
    """Wire a :class:`GhidraBridge` to a failing RPC client.

    Returns:
        GhidraBridge: A bridge whose attached client raises on every call.
    """
    bridge = GhidraBridge()
    bridge.attach_remote_bridge(_FailingBridgeClient())
    return bridge


def _single_event(captured: list[EventDict], event: str) -> EventDict:
    """Return the one captured record whose ``event`` equals ``event``.

    Args:
        captured: Records collected by :func:`structlog.testing.capture_logs`.
        event: The structlog event name to isolate.

    Returns:
        EventDict: The single matching record.
    """
    matches = [rec for rec in captured if rec.get("event") == event]
    assert len(matches) == 1, f"expected exactly one {event!r}, captured: {captured}"
    return matches[0]


@pytest.mark.asyncio
async def test_f11_define_structure_translates_and_logs_remote_failure(
    bridge_with_failing_fake: GhidraBridge,
) -> None:
    """Verify ``define_structure`` catches, logs, and re-raises remote failures.

    Args:
        bridge_with_failing_fake: Bridge wired to a failing RPC client.
    """
    fields: list[dict[str, Any]] = [{"name": "field1", "type": "int", "size": 4}]

    with structlog.testing.capture_logs() as captured, pytest.raises(ToolError) as exc_info:
        await bridge_with_failing_fake.define_structure("MyStruct", fields)

    assert str(exc_info.value) == f"Define structure failed: Remote execution failed: {_REMOTE_ERR}"
    cause = exc_info.value.__cause__
    assert isinstance(cause, ToolError)
    assert str(cause) == f"Remote execution failed: {_REMOTE_ERR}"
    root = cause.__cause__
    assert isinstance(root, RuntimeError)
    assert str(root) == _REMOTE_ERR

    record = _single_event(captured, "ghidra_define_structure_failed")
    assert record["log_level"] == "warning"
    assert record["struct_name"] == "MyStruct"
    assert record["error"] == f"Remote execution failed: {_REMOTE_ERR}"


@pytest.mark.asyncio
async def test_f11_create_function_translates_and_logs_remote_failure(
    bridge_with_failing_fake: GhidraBridge,
) -> None:
    """Verify ``create_function`` catches, logs, and re-raises remote failures.

    Args:
        bridge_with_failing_fake: Bridge wired to a failing RPC client.
    """
    with structlog.testing.capture_logs() as captured, pytest.raises(ToolError) as exc_info:
        await bridge_with_failing_fake.create_function(_FUNC_ADDR, "func1")

    assert str(exc_info.value) == f"Create function failed: Remote execution failed: {_REMOTE_ERR}"
    cause = exc_info.value.__cause__
    assert isinstance(cause, ToolError)
    root = cause.__cause__
    assert isinstance(root, RuntimeError)
    assert str(root) == _REMOTE_ERR

    record = _single_event(captured, "ghidra_create_function_failed")
    assert record["log_level"] == "warning"
    assert record["address"] == hex(_FUNC_ADDR)
    assert record["error"] == f"Remote execution failed: {_REMOTE_ERR}"


@pytest.mark.asyncio
async def test_f11_define_structure_not_connected_raises_before_dispatch() -> None:
    """Verify ``define_structure`` rejects an unconnected bridge with a clear error."""
    bridge = GhidraBridge()
    fields: list[dict[str, Any]] = [{"name": "f", "type": "byte", "size": 1}]

    with structlog.testing.capture_logs() as captured, pytest.raises(ToolError, match="Ghidra not connected"):
        await bridge.define_structure("S", fields)

    record = _single_event(captured, "ghidra_not_connected")
    assert record["log_level"] == "error"


@pytest.mark.asyncio
async def test_f11_create_function_not_connected_raises_before_dispatch() -> None:
    """Verify ``create_function`` rejects an unconnected bridge with a clear error."""
    bridge = GhidraBridge()

    with structlog.testing.capture_logs() as captured, pytest.raises(ToolError, match="Ghidra not connected"):
        await bridge.create_function(_FUNC_ADDR, "func1")

    record = _single_event(captured, "ghidra_not_connected")
    assert record["log_level"] == "error"
    assert record["address"] == hex(_FUNC_ADDR)
