# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for audit3 U13 - HxDPanel wired through panels package and MainWindow.

Validates that:

* ``HxDPanel`` is importable from the ``intellicrack.ui.panels`` public surface
  and listed in ``__all__``.
* ``MainWindow`` registers ``HxDPanel`` as a docked tab in the tool panel when
  the HxD executable is reachable.
* ``MainWindow`` skips registration silently (no exception, no widget attached)
  when the HxD executable cannot be located.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

import intellicrack.ui.app as app_mod
import intellicrack.ui.panels as panels_pkg
from intellicrack.ui.app import MainWindow
from intellicrack.ui.panels import HxDPanel
from intellicrack.ui.panels.hxd_panel import HxDPanel as HxDPanelDirect
from tests.test_ui.conftest import NoOpSandboxManager


if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication

    from intellicrack.core.config import Config
    from intellicrack.core.orchestrator import Orchestrator


_HXD_TAB_LABEL: str = "HxD"


class TestPanelsPackageSurface:
    """Validate that ``HxDPanel`` is exposed through the panels package."""

    @staticmethod
    def test_hxd_panel_importable_from_package() -> None:
        """Importing ``HxDPanel`` from ``intellicrack.ui.panels`` succeeds."""
        assert HxDPanel is HxDPanelDirect

    @staticmethod
    def test_hxd_panel_in_dunder_all() -> None:
        """``HxDPanel`` appears in ``intellicrack.ui.panels.__all__``."""
        exported: list[str] = list(panels_pkg.__all__)
        assert "HxDPanel" in exported

    @staticmethod
    def test_hxd_panel_attribute_on_module() -> None:
        """``HxDPanel`` is reachable as an attribute on the package module."""
        assert getattr(panels_pkg, "HxDPanel", None) is HxDPanelDirect


@pytest.fixture
def window_with_hxd_available(
    qapp: QApplication,
    real_config: Config,
    real_orchestrator: Orchestrator,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> Generator[MainWindow]:
    """Provide a ``MainWindow`` constructed with HxD detection forced on.

    Uses a temporary stub ``HxD.exe`` file written under ``tmp_path`` so the
    finder returns a real, existing ``Path``.

    Args:
        qapp: QApplication instance required by Qt widgets.
        real_config: Real ``Config`` instance from the test fixtures.
        real_orchestrator: Real ``Orchestrator`` instance from the test fixtures.
        monkeypatch: Pytest monkeypatch fixture.
        tmp_path: Pytest temporary directory fixture.

    Yields:
        Generator[MainWindow]: Window constructed with HxD detection patched to a stub.
    """
    _ = qapp
    stub_exe = tmp_path / "HxD.exe"
    stub_exe.write_bytes(b"\x4d\x5a")

    monkeypatch.setattr("intellicrack.ui.app.find_hxd_executable", lambda: stub_exe)
    monkeypatch.setattr("intellicrack.ui.app.SandboxManager", NoOpSandboxManager)

    window = MainWindow(real_config, real_orchestrator)
    yield window
    window.close()


@pytest.fixture
def window_without_hxd(
    qapp: QApplication,
    real_config: Config,
    real_orchestrator: Orchestrator,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[MainWindow]:
    """Provide a ``MainWindow`` constructed with HxD detection forced off.

    Args:
        qapp: QApplication instance required by Qt widgets.
        real_config: Real ``Config`` instance from the test fixtures.
        real_orchestrator: Real ``Orchestrator`` instance from the test fixtures.
        monkeypatch: Pytest monkeypatch fixture.

    Yields:
        Generator[MainWindow]: Window constructed with HxD detection patched to ``None``.
    """
    _ = qapp
    monkeypatch.setattr("intellicrack.ui.app.find_hxd_executable", lambda: None)
    monkeypatch.setattr("intellicrack.ui.app.SandboxManager", NoOpSandboxManager)

    window = MainWindow(real_config, real_orchestrator)
    yield window
    window.close()


class TestHxDPanelRegistrationWhenAvailable:
    """``MainWindow`` attaches ``HxDPanel`` when HxD is reachable."""

    @staticmethod
    def test_hxd_panel_attribute_set(window_with_hxd_available: MainWindow) -> None:
        """``MainWindow.hxd_panel`` references an ``HxDPanel`` instance.

        Args:
            window_with_hxd_available: Window with HxD detection forced on.
        """
        assert window_with_hxd_available.hxd_panel is not None
        assert isinstance(window_with_hxd_available.hxd_panel, HxDPanel)

    @staticmethod
    def test_hxd_tab_attached_to_tool_panel(
        window_with_hxd_available: MainWindow,
    ) -> None:
        """The tool panel ``QTabWidget`` exposes the HxD tab.

        Args:
            window_with_hxd_available: Window with HxD detection forced on.
        """
        tab_widget = window_with_hxd_available.tool_panel.tab_widget
        labels: list[str] = [tab_widget.tabText(i) for i in range(tab_widget.count())]
        assert _HXD_TAB_LABEL in labels

    @staticmethod
    def test_hxd_tab_widget_is_panel_instance(
        window_with_hxd_available: MainWindow,
    ) -> None:
        """The tab labelled ``HxD`` holds the registered ``HxDPanel`` widget.

        Args:
            window_with_hxd_available: Window with HxD detection forced on.
        """
        tab_widget = window_with_hxd_available.tool_panel.tab_widget
        panel = window_with_hxd_available.hxd_panel
        assert panel is not None
        idx = tab_widget.indexOf(panel)
        assert idx >= 0
        assert tab_widget.tabText(idx) == _HXD_TAB_LABEL

    @staticmethod
    def test_hxd_tab_present_in_embedded_tools(
        window_with_hxd_available: MainWindow,
    ) -> None:
        """The HxD panel is recorded in ``tool_panel.embedded_tools``.

        Args:
            window_with_hxd_available: Window with HxD detection forced on.
        """
        embedded = window_with_hxd_available.tool_panel.embedded_tools
        assert "hxd" in embedded
        assert embedded["hxd"] is window_with_hxd_available.hxd_panel


class TestHxDPanelRegistrationWhenUnavailable:
    """``MainWindow`` is silent and stable when HxD is not reachable."""

    @staticmethod
    def test_no_hxd_panel_attribute(window_without_hxd: MainWindow) -> None:
        """``_hxd_panel`` stays ``None`` when HxD cannot be located.

        Args:
            window_without_hxd: Window with HxD detection forced off.
        """
        assert window_without_hxd.hxd_panel is None

    @staticmethod
    def test_no_hxd_tab_attached(window_without_hxd: MainWindow) -> None:
        """The tool panel ``QTabWidget`` does not expose the HxD tab.

        Args:
            window_without_hxd: Window with HxD detection forced off.
        """
        tab_widget = window_without_hxd.tool_panel.tab_widget
        labels: list[str] = [tab_widget.tabText(i) for i in range(tab_widget.count())]
        assert _HXD_TAB_LABEL not in labels

    @staticmethod
    def test_no_embedded_tools_entry(window_without_hxd: MainWindow) -> None:
        """No ``hxd`` key is recorded in ``tool_panel.embedded_tools``.

        Args:
            window_without_hxd: Window with HxD detection forced off.
        """
        assert "hxd" not in window_without_hxd.tool_panel.embedded_tools

    @staticmethod
    def test_main_window_constructs_without_exception(
        qapp: QApplication,
        real_config: Config,
        real_orchestrator: Orchestrator,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``MainWindow`` construction succeeds even when HxD lookup returns ``None``.

        Args:
            qapp: QApplication instance required by Qt widgets.
            real_config: Real ``Config`` instance.
            real_orchestrator: Real ``Orchestrator`` instance.
            monkeypatch: Pytest monkeypatch fixture.
        """
        _ = qapp
        monkeypatch.setattr("intellicrack.ui.app.find_hxd_executable", lambda: None)
        monkeypatch.setattr("intellicrack.ui.app.SandboxManager", NoOpSandboxManager)

        window = MainWindow(real_config, real_orchestrator)
        try:
            assert window.hxd_panel is None
        finally:
            window.close()


class TestPathStubBranch:
    """Drive the available branch by stubbing ``find_hxd_executable``."""

    @staticmethod
    def test_path_stub_drives_available_branch(
        qapp: QApplication,
        real_config: Config,
        real_orchestrator: Orchestrator,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """A stub executable on disk drives the panel registration branch.

        Validates that, given a real ``HxD.exe`` path returned from the finder,
        ``MainWindow`` attaches the ``HxDPanel`` as a docked tab.

        Args:
            qapp: QApplication instance required by Qt widgets.
            real_config: Real ``Config`` instance.
            real_orchestrator: Real ``Orchestrator`` instance.
            monkeypatch: Pytest monkeypatch fixture.
            tmp_path: Pytest temporary directory fixture.
        """
        _ = qapp

        stub_dir = tmp_path / "stub_path"
        stub_dir.mkdir()
        stub_exe = stub_dir / "HxD.exe"
        stub_exe.write_bytes(b"\x4d\x5a")

        monkeypatch.setattr("intellicrack.ui.app.SandboxManager", NoOpSandboxManager)
        monkeypatch.setattr(
            app_mod,
            "find_hxd_executable",
            lambda: stub_exe,
        )

        window = MainWindow(real_config, real_orchestrator)
        try:
            assert window.hxd_panel is not None
            tab_widget = window.tool_panel.tab_widget
            labels: list[str] = [tab_widget.tabText(i) for i in range(tab_widget.count())]
            assert _HXD_TAB_LABEL in labels
        finally:
            window.close()
