# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for core.orchestrator module - AI agent orchestration."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.core.orchestrator import (
    Orchestrator,
    OrchestratorConfig,
    OrchestratorStats,
)
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ConfirmationLevel
from intellicrack.providers.registry import ProviderRegistry


if TYPE_CHECKING:
    from pathlib import Path


_MAX_ITER: Final[int] = 20
_TIMEOUT: Final[int] = 120
_MAX_TOKENS: Final[int] = 4096
_RESPONSE_TIME_A: Final[float] = 100.0
_RESPONSE_TIME_B: Final[float] = 200.0
_EXPECTED_AVG: Final[float] = 150.0
_STATS_KEYS: Final[int] = 6
_DESTRUCTIVE_COUNT: Final[int] = 12
_CUSTOM_MAX_ITER: Final[int] = 5


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
    assert stats.average_response_time_ms == pytest.approx(_RESPONSE_TIME_A)
    stats.record_response_time(_RESPONSE_TIME_B)
    assert stats.average_response_time_ms == pytest.approx(_EXPECTED_AVG)


def test_stats_to_dict() -> None:
    """Verify to_dict returns all expected keys."""
    stats = OrchestratorStats()
    stats.record_response_time(_RESPONSE_TIME_A)
    d = stats.to_dict()
    assert len(d) == _STATS_KEYS
    assert "total_requests" in d
    assert "average_response_time_ms" in d


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
    """Verify provider_registry property returns the registry.

    Args:
        tmp_path: Pytest temporary directory.
    """
    orch = _make_orchestrator(tmp_path)
    assert isinstance(orch.provider_registry, ProviderRegistry)


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
async def test_cancel(tmp_path: Path) -> None:
    """Verify cancel executes without error.

    Args:
        tmp_path: Pytest temporary directory.
    """
    orch = _make_orchestrator(tmp_path)
    await orch.cancel()


def test_orchestrator_custom_config(tmp_path: Path) -> None:
    """Verify orchestrator accepts custom config.

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
    assert orch.state == "idle"
