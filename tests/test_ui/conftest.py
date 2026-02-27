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
    from collections.abc import Generator
    from pathlib import Path


class SignalRecorder:
    """Records signal emissions for assertion without unittest.mock.

    Attributes:
        calls: List of argument tuples from each call.
    """

    def __init__(self) -> None:
        """Initialize with empty call list."""
        self.calls: list[tuple[Any, ...]] = []

    def __call__(self, *args: Any) -> None:
        """Record a call with its arguments.

        Args:
            args: Arguments passed to the signal slot.
        """
        self.calls.append(args)

    def verify_single_call(self, *expected: Any) -> None:
        """Assert exactly one call with expected arguments.

        Args:
            expected: Expected arguments.

        Raises:
            AssertionError: If not called exactly once with expected args.
        """
        assert len(self.calls) == 1, f"Expected 1 call, got {len(self.calls)}"
        assert self.calls[0] == expected, f"Expected {expected}, got {self.calls[0]}"

    def verify_any_call(self, *expected: Any) -> None:
        """Assert at least one call with expected arguments.

        Args:
            expected: Expected arguments to find.

        Raises:
            AssertionError: If no matching call found.
        """
        assert expected in list(self.calls), f"{expected} not found in {self.calls}"

    @property
    def times_called(self) -> int:
        """Return the number of recorded calls.

        Returns:
            Number of times this recorder was called.
        """
        return len(self.calls)


class DialogRecorder:
    """Records dialog invocations for assertion without unittest.mock.

    Attributes:
        calls: List of argument tuples from each invocation.
    """

    def __init__(self) -> None:
        """Initialize with empty call list."""
        self.calls: list[tuple[Any, ...]] = []

    def __call__(self, *args: Any, **_kwargs: Any) -> None:
        """Record a dialog invocation.

        Args:
            args: Positional arguments.
            _kwargs: Keyword arguments (accepted but not stored).
        """
        self.calls.append(args)


class NoOpSandboxManager:
    """No-op replacement for SandboxManager in tests.

    Accepts any constructor arguments and returns no-op callables
    for any attribute access.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Accept any arguments silently.

        Args:
            args: Ignored positional arguments.
            kwargs: Ignored keyword arguments.
        """

    def __getattr__(self, name: str) -> Any:
        """Return a no-op callable for any attribute.

        Args:
            name: Attribute name.

        Returns:
            A callable that does nothing and returns None.
        """
        return lambda *_args, **_kwargs: None


class CallRecorder:
    """Records arbitrary function calls for assertion.

    Attributes:
        calls: List of (args, kwargs) tuples.
        result: Value to return on each call.
    """

    def __init__(self, result: Any = None) -> None:
        """Initialize with optional return value.

        Args:
            result: Value returned by each call.
        """
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        self.result: Any = result

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Record a call and return the configured value.

        Args:
            args: Positional arguments.
            kwargs: Keyword arguments.

        Returns:
            The configured result value.
        """
        self.calls.append((args, kwargs))
        return self.result

    @property
    def times_called(self) -> int:
        """Return the number of recorded calls.

        Returns:
            Number of times this recorder was called.
        """
        return len(self.calls)


@pytest.fixture(scope="session")
def qapp() -> Generator[QApplication]:
    """Provide a QApplication instance for the test session.

    Qt requires exactly one QApplication instance per process.
    This fixture creates one for the entire test session and
    cleans it up afterward.

    Yields:
        QApplication instance for widget testing.
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
        Config instance using temporary directories.
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
        Orchestrator instance.
    """
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    db_path = tmp_path / "sessions.db"
    return Orchestrator(
        provider_registry=ProviderRegistry(),
        tool_registry=ToolRegistry(tools_dir=tools_dir),
        session_manager=SessionManager(store=SessionStore(db_path=db_path)),
    )
