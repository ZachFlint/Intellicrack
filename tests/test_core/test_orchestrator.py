# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for core.orchestrator module - AI agent orchestration."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.core.orchestrator import (
    Orchestrator,
    OrchestratorConfig,
    OrchestratorStats,
)
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ConfirmationLevel, ToolCall
from intellicrack.providers.registry import ProviderRegistry


if TYPE_CHECKING:
    from pathlib import Path


_MAX_ITER: Final[int] = 20
_TIMEOUT: Final[int] = 120
_MAX_TOKENS: Final[int] = 4096
_RESPONSE_TIME_A: Final[float] = 100.0
_RESPONSE_TIME_B: Final[float] = 200.0
_EXPECTED_AVG: Final[float] = 150.0
_STATS_KEYS: Final[int] = 10
_DESTRUCTIVE_COUNT: Final[int] = 12
_CUSTOM_MAX_ITER: Final[int] = 5
_FLOAT_TOLERANCE: Final[float] = 1e-9


def _make_orchestrator(tmp_path: Path) -> Orchestrator:
    """Create an Orchestrator with tmp_path dependencies.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        Orchestrator: Orchestrator instance.
    """
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    db_path = tmp_path / "sessions.db"
    return Orchestrator(
        provider_registry=ProviderRegistry(),
        tool_registry=ToolRegistry(tools_dir=tools_dir),
        session_manager=SessionManager(store=SessionStore(db_path=db_path)),
    )


def test_orchestrator_config_defaults() -> None:
    """Verify OrchestratorConfig defaults."""
    config = OrchestratorConfig()
    assert config.confirmation_level == ConfirmationLevel.DESTRUCTIVE
    assert config.max_iterations == _MAX_ITER
    assert config.timeout_seconds == _TIMEOUT
    assert config.max_tokens == _MAX_TOKENS
    assert config.stream_responses is True
    assert config.stream_mode == "auto"


def test_orchestrator_config_custom() -> None:
    """Verify OrchestratorConfig with custom values."""
    config = OrchestratorConfig(
        confirmation_level=ConfirmationLevel.NONE,
        max_iterations=_CUSTOM_MAX_ITER,
        stream_mode="never",
    )
    assert config.confirmation_level == ConfirmationLevel.NONE
    assert config.max_iterations == _CUSTOM_MAX_ITER
    assert config.stream_mode == "never"


def test_stats_defaults() -> None:
    """Verify OrchestratorStats defaults."""
    stats = OrchestratorStats()
    assert stats.total_requests == 0
    assert stats.total_tool_calls == 0
    assert stats.successful_tool_calls == 0
    assert stats.failed_tool_calls == 0
    assert stats.total_tokens_used == 0


def test_stats_record_response_time() -> None:
    """Verify record_response_time updates rolling average."""
    stats = OrchestratorStats()
    stats.record_response_time(_RESPONSE_TIME_A)
    assert abs(stats.average_response_time_ms - _RESPONSE_TIME_A) < _FLOAT_TOLERANCE
    stats.record_response_time(_RESPONSE_TIME_B)
    assert abs(stats.average_response_time_ms - _EXPECTED_AVG) < _FLOAT_TOLERANCE


def test_stats_to_dict() -> None:
    """Verify to_dict serializes all fields with correct values.

    Records one response time and then checks every serialised value against
    the independent oracle computed from the known inputs and initial-state
    defaults, so a field-swap, stale-value, or wrong-average regression fails.
    """
    stats = OrchestratorStats()
    stats.record_response_time(_RESPONSE_TIME_A)
    d = stats.to_dict()

    assert len(d) == _STATS_KEYS

    assert d["total_requests"] == 0
    assert d["total_tool_calls"] == 0
    assert d["successful_tool_calls"] == 0
    assert d["failed_tool_calls"] == 0
    assert d["total_tokens_used"] == 0
    assert d["provider_prompt_tokens"] == 0
    assert d["provider_completion_tokens"] == 0
    assert d["provider_total_tokens"] == 0
    assert d["thinking_blocks_collected"] == 0
    assert abs(d["average_response_time_ms"] - _RESPONSE_TIME_A) < _FLOAT_TOLERANCE


def test_orchestrator_initial_state(tmp_path: Path) -> None:
    """Verify orchestrator starts in idle state.

    Args:
        tmp_path: Pytest temporary directory.
    """
    orch = _make_orchestrator(tmp_path)
    assert orch.state == "idle"
    assert orch.current_session is None
    assert orch.stats.total_requests == 0


def test_orchestrator_provider_registry(tmp_path: Path) -> None:
    """Verify provider_registry property returns the exact injected registry instance.

    Constructs a dedicated ``ProviderRegistry`` and passes it as the
    ``provider_registry`` argument.  The property must return the *same object*
    (identity, not just the same type) and the returned reference must be usable
    for registry operations such as ``list_registered()``, whose oracle is the
    empty list produced by a freshly constructed registry.

    Args:
        tmp_path: Pytest temporary directory.
    """
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    db_path = tmp_path / "sessions.db"
    registry = ProviderRegistry()
    orch = Orchestrator(
        provider_registry=registry,
        tool_registry=ToolRegistry(tools_dir=tools_dir),
        session_manager=SessionManager(store=SessionStore(db_path=db_path)),
    )
    assert orch.provider_registry is registry
    assert orch.provider_registry.list_registered() == []


def test_destructive_patterns_class_attribute() -> None:
    """Verify DESTRUCTIVE_PATTERNS contains expected patterns."""
    patterns = Orchestrator.DESTRUCTIVE_PATTERNS
    assert "write" in patterns
    assert "patch" in patterns
    assert "hook" in patterns
    assert "inject" in patterns
    assert "delete" in patterns
    assert len(patterns) == _DESTRUCTIVE_COUNT


@pytest.mark.asyncio
async def test_start_session_no_provider(tmp_path: Path) -> None:
    """Verify start_session raises when no provider is connected.

    Args:
        tmp_path: Pytest temporary directory.
    """
    orch = _make_orchestrator(tmp_path)
    with pytest.raises(ValueError, match="not available"):
        await orch.start_session("anthropic", "test-model")


@pytest.mark.asyncio
async def test_cancel_resolves_in_flight_confirmation(tmp_path: Path) -> None:
    """Verify cancel actually cancels an outstanding confirmation future.

    Drives a real destructive tool call through ``request_confirmation`` so a
    confirmation future is genuinely pending, then asserts ``cancel()`` marshals
    it: the awaiting coroutine resolves to ``False`` and the underlying future
    is cancelled rather than left dangling.

    Args:
        tmp_path: Pytest temporary directory.
    """
    orch = _make_orchestrator(tmp_path)
    loop = asyncio.get_running_loop()
    awaited_future: asyncio.Future[bool] = loop.create_future()

    def _callback(_call: ToolCall) -> asyncio.Future[bool]:
        return awaited_future

    orch.set_async_confirmation_callback(_callback)
    call = ToolCall(id="cancel-1", tool_name="frida", function_name="frida.write_memory", arguments={})
    confirm_task = asyncio.create_task(orch.request_confirmation(call))
    await asyncio.sleep(0)
    assert orch.pending_confirmation is not None

    await orch.cancel()

    result = await asyncio.wait_for(confirm_task, timeout=1.0)
    assert result is False
    assert awaited_future.cancelled()
    assert orch.pending_confirmation is None


def test_orchestrator_custom_config(tmp_path: Path) -> None:
    """Verify custom OrchestratorConfig fields are stored and readable via public API.

    Constructs an orchestrator with ``ConfirmationLevel.NONE`` and
    ``max_iterations=5``, then verifies both fields are active by:

    1. Using ``set_confirmation_level`` (which writes to the stored config)
       to cycle through a sentinel level and back; the write propagates to the
       original ``config`` object proving the orchestrator holds the same
       reference rather than a copy.
    2. Asserting that the injected ``config.confirmation_level`` differs from
       the ``OrchestratorConfig()`` default, so the test is not a tautology.
    3. Asserting ``config.max_iterations == _CUSTOM_MAX_ITER`` which is
       distinct from the default ``_MAX_ITER`` (20), so a regression that
       ignores the ``max_iterations`` kwarg and stores the default fails.

    Args:
        tmp_path: Pytest temporary directory.
    """
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    db_path = tmp_path / "sessions.db"
    config = OrchestratorConfig(
        confirmation_level=ConfirmationLevel.NONE,
        max_iterations=_CUSTOM_MAX_ITER,
    )
    orch = Orchestrator(
        provider_registry=ProviderRegistry(),
        tool_registry=ToolRegistry(tools_dir=tools_dir),
        session_manager=SessionManager(store=SessionStore(db_path=db_path)),
        config=config,
    )
    orch.set_confirmation_level(ConfirmationLevel.ALL)
    assert config.confirmation_level == ConfirmationLevel.ALL
    orch.set_confirmation_level(ConfirmationLevel.NONE)
    assert config.confirmation_level == ConfirmationLevel.NONE

    default_config = OrchestratorConfig()
    assert default_config.confirmation_level == ConfirmationLevel.DESTRUCTIVE
    assert config.confirmation_level != default_config.confirmation_level

    assert config.max_iterations == _CUSTOM_MAX_ITER
    assert config.max_iterations != _MAX_ITER
