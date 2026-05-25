# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for audit7 F-0021: ``wire_sandbox_backend`` injection path.

The original defect: :meth:`ToolOutputPanel.wire_sandbox_backend` was fully
implemented but had no production caller, leaving the plugin / CLI sandbox
injection surface dead. The fix added :meth:`MainWindow.wire_sandbox_backend`
as the public injection entry point and a startup helper
:func:`intellicrack.main._wire_preregistered_sandbox` that walks the
orchestrator's tool registry on construction.

These tests exercise both the public ``MainWindow.wire_sandbox_backend``
method (the plugin-facing surface) and the startup helper (the CLI/bootstrap
surface) against a real ``MainWindow`` constructed against real
``Config``/``Orchestrator`` instances, with a real ``SandboxBase`` subclass
driving the wiring. No mocks are used; only ``QMessageBox`` UI surfaces are
monkey-patched away to keep the run headless.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, cast

import pytest

from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.core.config import Config
from intellicrack.core.orchestrator import Orchestrator
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ToolName
from intellicrack.providers.registry import ProviderRegistry
from intellicrack.sandbox.base import SandboxBase, SandboxConfig
from intellicrack.sandbox.manager import SandboxManager
from intellicrack.ui.app import MainWindow


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication


_wire_preregistered_sandbox = cast(
    "Callable[[MainWindow, Orchestrator], None]",
    importlib.import_module("intellicrack.main")._wire_preregistered_sandbox,
)
"""Production startup helper resolved through :func:`importlib.import_module`.

Imported via the module object rather than ``from intellicrack.main import X``
because ``intellicrack.__init__`` ships a lazy ``__getattr__`` that aliases
``intellicrack.main`` to the ``main()`` function during collection-time
``from``-imports, hiding the underscored helpers.
"""


class _InProcessSandbox(SandboxBase):
    """Real ``SandboxBase`` subclass used to drive the wiring tests.

    The class is a concrete (not mocked) ``SandboxBase`` so the type checks
    inside ``ToolOutputPanel.wire_sandbox_backend`` accept it. It performs
    no subprocess, network, or filesystem work because the wiring path only
    needs an identity-stable ``SandboxBase`` instance for registration.
    """

    def __init__(self) -> None:
        """Initialize the in-process sandbox with default ``SandboxConfig``."""
        super().__init__(SandboxConfig())


def _orchestrator_tool_registry(orchestrator: Orchestrator) -> ToolRegistry:
    """Return the orchestrator's tool registry without dunder access in tests.

    The orchestrator stores its registry on ``_tools`` (a leading-underscore
    attribute). Tests need to insert bridges before the helper under test
    runs, so we route that access through :func:`getattr` to keep the
    private name out of the test source. The accompanying ``assert``
    narrows the lookup result for ``basedpyright`` and is stripped under
    ``python -O`` rather than functioning as a documented exception.

    Args:
        orchestrator: Orchestrator whose registry the test wants to mutate.

    Returns:
        ToolRegistry: The orchestrator-owned tool registry.
    """
    registry = getattr(orchestrator, "_tools", None)
    assert isinstance(registry, ToolRegistry), "orchestrator must expose a ToolRegistry"
    return registry


@pytest.fixture
def real_config(tmp_path: Path) -> Config:
    """Build a real :class:`Config` rooted under ``tmp_path``.

    Args:
        tmp_path: Pytest temporary directory fixture.

    Returns:
        Config: Configuration whose tools/logs/data directories live in
        ``tmp_path`` so no host directory is touched.
    """
    return Config(
        tools_directory=tmp_path / "tools",
        logs_directory=tmp_path / "logs",
        data_directory=tmp_path / "data",
    )


@pytest.fixture
def real_orchestrator(tmp_path: Path) -> Orchestrator:
    """Build a real :class:`Orchestrator` with empty registries.

    Args:
        tmp_path: Pytest temporary directory fixture.

    Returns:
        Orchestrator: Orchestrator with an empty tool registry that tests
        can populate via :meth:`ToolRegistry.register_bridge`.
    """
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    db_path = tmp_path / "sessions.db"
    return Orchestrator(
        provider_registry=ProviderRegistry(),
        tool_registry=ToolRegistry(tools_dir=tools_dir),
        session_manager=SessionManager(store=SessionStore(db_path=db_path)),
    )


@pytest.fixture
def main_window(
    qapp: QApplication,
    real_config: Config,
    real_orchestrator: Orchestrator,
) -> Iterator[MainWindow]:
    """Construct a real :class:`MainWindow` and clean it up after each test.

    Args:
        qapp: QApplication fixture (session-scoped).
        real_config: Real Config instance from the local fixture.
        real_orchestrator: Real Orchestrator instance from the local fixture.

    Yields:
        MainWindow: Live main window ready to receive backend injections.
    """
    del qapp
    window = MainWindow(real_config, real_orchestrator)
    try:
        yield window
    finally:
        window.close()
        window.deleteLater()


class TestMainWindowWireSandboxBackend:
    """:meth:`MainWindow.wire_sandbox_backend` exposes the panel wiring."""

    @staticmethod
    def test_public_method_forwards_to_tool_panel(main_window: MainWindow) -> None:
        """Public injection method must forward to the tool panel and expose the bridge.

        Args:
            main_window: Real main window fixture.
        """
        sandbox = _InProcessSandbox()

        main_window.wire_sandbox_backend(sandbox)

        bridge = main_window.tool_panel.get_sandbox_bridge()
        assert isinstance(bridge, SandboxBridge), "tool_panel must expose the wired bridge"
        manager = bridge.manager
        assert manager is not None, "wired bridge must own a manager"
        assert any(inst.sandbox is sandbox for inst in manager.instances), "the injected sandbox must be reachable through the wired bridge"

    @staticmethod
    def test_supplied_manager_replaces_window_attribute(main_window: MainWindow) -> None:
        """A supplied manager is installed on the window and reused on the bridge.

        Args:
            main_window: Real main window fixture.
        """
        sandbox = _InProcessSandbox()
        manager = SandboxManager()

        main_window.wire_sandbox_backend(sandbox, manager)

        assert main_window.sandbox_manager is manager
        bridge = main_window.tool_panel.get_sandbox_bridge()
        assert isinstance(bridge, SandboxBridge)
        assert bridge.manager is manager

    @staticmethod
    def test_call_count_matches_forwarded_invocation(
        main_window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Each ``MainWindow.wire_sandbox_backend`` call invokes the panel exactly once.

        Args:
            main_window: Real main window fixture.
            monkeypatch: Pytest monkeypatch for recording panel invocations.
        """
        calls: list[tuple[object, object]] = []
        original = main_window.tool_panel.wire_sandbox_backend

        def recording_wire(sandbox: object, manager: object | None = None) -> None:
            calls.append((sandbox, manager))
            original(sandbox, manager)

        monkeypatch.setattr(main_window.tool_panel, "wire_sandbox_backend", recording_wire)

        sandbox = _InProcessSandbox()
        main_window.wire_sandbox_backend(sandbox)

        assert len(calls) == 1, "wire_sandbox_backend must be invoked exactly once"
        assert calls[0][0] is sandbox

    @staticmethod
    def test_rejects_non_sandbox_input(main_window: MainWindow) -> None:
        """The tool panel's type check propagates through the MainWindow surface.

        Args:
            main_window: Real main window fixture.
        """
        not_a_sandbox = cast("SandboxBase", object())
        with pytest.raises(TypeError, match="SandboxBase"):
            main_window.wire_sandbox_backend(not_a_sandbox)


class TestPreRegisteredSandboxStartupWiring:
    """Startup helper forwards pre-registered sandbox instances to MainWindow."""

    @staticmethod
    def test_startup_helper_wires_existing_bridge(
        qapp: QApplication,
        real_config: Config,
        tmp_path: Path,
    ) -> None:
        """Pre-registering a SandboxBridge in the tool registry must drive ``wire_sandbox_backend``.

        Simulates the CLI/plugin bootstrap path where an external caller
        registers a fully populated ``SandboxBridge`` on the orchestrator's
        tool registry before the GUI is constructed. The startup helper
        :func:`_wire_preregistered_sandbox` must detect the registered
        bridge, pull the sandbox out of its manager, and forward it to
        :meth:`MainWindow.wire_sandbox_backend`.

        Args:
            qapp: QApplication fixture (session-scoped).
            real_config: Real Config instance.
            tmp_path: Pytest temporary directory fixture.
        """
        del qapp
        tools_dir = tmp_path / "tools"
        tools_dir.mkdir(parents=True, exist_ok=True)
        db_path = tmp_path / "sessions.db"
        tool_registry = ToolRegistry(tools_dir=tools_dir)

        sandbox = _InProcessSandbox()
        manager = SandboxManager()
        bridge = SandboxBridge()
        bridge.attach_manager(manager)
        bridge.register_existing_sandbox(sandbox, "windows")
        tool_registry.register_bridge(ToolName.SANDBOX, bridge)

        orchestrator = Orchestrator(
            provider_registry=ProviderRegistry(),
            tool_registry=tool_registry,
            session_manager=SessionManager(store=SessionStore(db_path=db_path)),
        )
        window = MainWindow(real_config, orchestrator)
        try:
            TestPreRegisteredSandboxStartupWiring._assert_preregistered_sandbox_wired(
                window,
                orchestrator,
                manager,
                sandbox,
            )
        finally:
            window.close()
            window.deleteLater()

    @staticmethod
    def _assert_preregistered_sandbox_wired(
        window: MainWindow,
        orchestrator: Orchestrator,
        manager: SandboxManager,
        sandbox: object,
    ) -> None:
        """Run the startup wiring helper and verify the sandbox bridge state.

        Args:
            window: The MainWindow instance under test.
            orchestrator: Orchestrator instance bound to ``window``.
            manager: SandboxManager expected to be retained by the bridge.
            sandbox: Pre-registered sandbox instance expected to be present.
        """
        _wire_preregistered_sandbox(window, orchestrator)

        wired_bridge = window.tool_panel.get_sandbox_bridge()
        assert isinstance(wired_bridge, SandboxBridge)
        assert wired_bridge.manager is manager
        assert any(inst.sandbox is sandbox for inst in manager.instances)
        assert window.sandbox_manager is manager

    @staticmethod
    def test_startup_helper_is_noop_without_preregistration(
        main_window: MainWindow,
        real_orchestrator: Orchestrator,
    ) -> None:
        """When no sandbox bridge is pre-registered the helper must be a silent no-op.

        Args:
            main_window: Real main window fixture (already constructed with
                an empty tool registry).
            real_orchestrator: Real Orchestrator with an empty tool registry.
        """
        assert main_window.tool_panel.get_sandbox_bridge() is None

        _wire_preregistered_sandbox(main_window, real_orchestrator)

        assert main_window.tool_panel.get_sandbox_bridge() is None

    @staticmethod
    def test_startup_helper_skips_bridge_without_instances(
        main_window: MainWindow,
        real_orchestrator: Orchestrator,
    ) -> None:
        """A bridge without any registered sandbox instance must not trigger wiring.

        Args:
            main_window: Real main window fixture.
            real_orchestrator: Real Orchestrator the test will populate.
        """
        empty_bridge = SandboxBridge()
        registry = _orchestrator_tool_registry(real_orchestrator)
        registry.register_bridge(ToolName.SANDBOX, empty_bridge)

        _wire_preregistered_sandbox(main_window, real_orchestrator)

        assert main_window.tool_panel.get_sandbox_bridge() is None
