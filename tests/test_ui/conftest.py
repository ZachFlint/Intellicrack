# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Pytest configuration and fixtures for UI tests.

Provides shared fixtures including QApplication instance
required for Qt widget testing, signal recording utilities,
and real Config/Orchestrator instances.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from PyQt6.QtWidgets import QApplication

from intellicrack.core.config import Config
from intellicrack.core.orchestrator import Orchestrator
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.providers.registry import ProviderRegistry


if TYPE_CHECKING:
    from collections.abc import Callable, Generator
    from pathlib import Path


class SignalRecorder:
    """Records signal emissions for assertion without unittest.mock.

    Construction takes no arguments and initialises an empty call history.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[Any, ...]] = []

    def __call__(self, *args: object) -> None:
        """Record a call with its arguments.

        Args:
            *args: Arguments passed to the signal slot.
        """
        self.calls.append(args)

    def verify_single_call(self, *expected: object) -> None:
        """Assert exactly one call with expected arguments.

        Args:
            *expected: Expected arguments.
        """
        assert len(self.calls) == 1, f"Expected 1 call, got {len(self.calls)}"
        assert self.calls[0] == expected, f"Expected {expected}, got {self.calls[0]}"

    def verify_any_call(self, *expected: object) -> None:
        """Assert at least one call with expected arguments.

        Args:
            *expected: Expected arguments to find.
        """
        assert expected in list(self.calls), f"{expected} not found in {self.calls}"

    @property
    def times_called(self) -> int:
        """Return the number of recorded calls.

        Returns:
            int: Number of times this recorder was called.
        """
        return len(self.calls)


class DialogRecorder:
    """Records dialog invocations for assertion without unittest.mock.

    Construction takes no arguments and initialises an empty call history.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[Any, ...]] = []

    def __call__(self, *args: object, **_kwargs: object) -> None:
        """Record a dialog invocation.

        Args:
            *args: Positional arguments.
            **_kwargs: Keyword arguments (accepted but not stored).
        """
        self.calls.append(args)


class NoOpSandboxManager:
    """No-op replacement for SandboxManager in tests.

    Accepts any constructor arguments and returns no-op callables
    for any attribute access.

    Args:
        *args: Ignored positional arguments.
        **kwargs: Ignored keyword arguments.
    """

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs

    def __getattr__(self, name: str) -> Callable[..., None]:
        """Return a no-op callable for any attribute.

        Args:
            name: Attribute name.

        Returns:
            Callable[..., None]: A callable that does nothing and returns None.
        """
        return lambda *_args, **_kwargs: None


class CallRecorder:
    """Records arbitrary function calls for assertion.

    Args:
        result: Value returned by each invocation of this recorder.
    """

    def __init__(self, result: object = None) -> None:
        self.calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
        self.result: object = result

    def __call__(self, *args: object, **kwargs: object) -> object:
        """Record a call and return the configured value.

        Args:
            *args: Positional arguments.
            **kwargs: Keyword arguments.

        Returns:
            object: The configured result value.
        """
        self.calls.append((args, kwargs))
        return self.result

    @property
    def times_called(self) -> int:
        """Return the number of recorded calls.

        Returns:
            int: Number of times this recorder was called.
        """
        return len(self.calls)


@pytest.fixture(scope="session")
def qapp() -> Generator[QApplication]:
    """Provide a QApplication instance for the test session.

    Qt requires exactly one QApplication instance per process.
    This fixture creates one for the entire test session and
    cleans it up afterward.

    Yields:
        Generator[QApplication]: QApplication instance for widget testing.
    """
    existing = QApplication.instance()
    if existing is not None and isinstance(existing, QApplication):
        yield existing
        return

    yield QApplication([])


@pytest.fixture
def real_config(tmp_path: Path) -> Config:
    """Create a real Config instance with tmp_path directories.

    Args:
        tmp_path: Pytest temporary directory fixture.

    Returns:
        Config: Config instance using temporary directories.
    """
    return Config(
        tools_directory=tmp_path / "tools",
        logs_directory=tmp_path / "logs",
        data_directory=tmp_path / "data",
    )


@pytest.fixture
def real_orchestrator(tmp_path: Path) -> Orchestrator:
    """Create a real Orchestrator with empty registries.

    Args:
        tmp_path: Pytest temporary directory fixture.

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
