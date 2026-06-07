# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for audit3 U13 - HxDPanel wired through panels package and MainWindow.

Validates that:

* ``HxDPanel`` is importable from the ``intellicrack.ui.panels`` public surface
  and listed in ``__all__``.
* The real ``find_hxd_executable`` detection logic resolves a genuine
  ``HxD.exe`` placed on ``PATH`` and rejects non-matching entries, exercised
  end to end without patching the function under test.
* ``MainWindow`` registers ``HxDPanel`` as a docked tab in the tool panel when
  the real finder locates an HxD executable (driven by real ``PATH``
  environment control, not by stubbing the finder).
* ``MainWindow`` skips registration silently (no exception, no widget attached)
  when the real finder cannot locate an HxD executable.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest

import intellicrack.ui.panels as panels_pkg
from intellicrack.ui.app import MainWindow
from intellicrack.ui.panels import HxDPanel
from intellicrack.ui.panels.hxd_panel import (
    HxDPanel as HxDPanelDirect,
    find_hxd_executable,
)
from tests.test_ui.conftest import NoOpSandboxManager


if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication

    from intellicrack.core.config import Config
    from intellicrack.core.orchestrator import Orchestrator


_HXD_TAB_LABEL: str = "HxD"
_HXD_EXE_NAME: str = "HxD.exe"

# Minimal but real PE/MZ header bytes. ``find_hxd_executable`` only requires the
# candidate to exist as a regular file named ``HxD.exe``; a real on-disk file
# (not an empty path or a hand-built answer dict) drives the detection logic.
_MZ_STUB: bytes = b"MZ" + b"\x00" * 62


def _host_has_registry_or_common_hxd() -> bool:
    """Probe the real host-level HxD sources the finder consults besides ``PATH``.

    ``find_hxd_executable`` checks Windows registry entries and hard-coded
    common install directories before falling back to ``PATH``. Those sources
    are absolute and cannot be redirected by the test environment, so the
    unavailable-branch tests must assert this precondition explicitly rather
    than masking a genuine local install with a silent skip. Probing is done by
    running the real finder with ``PATH`` temporarily cleared: any non-``None``
    result then originates from registry or common-directory detection.

    Returns:
        bool: ``True`` when the host has a registry-registered or common-dir
        HxD install that the finder would resolve regardless of ``PATH``.
    """
    saved_path = os.environ.get("PATH")
    os.environ["PATH"] = ""
    try:
        return find_hxd_executable() is not None
    finally:
        if saved_path is None:
            os.environ.pop("PATH", None)
        else:
            os.environ["PATH"] = saved_path


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


class TestFindHxDExecutableRealDetection:
    """Exercise the real ``find_hxd_executable`` detection logic via ``PATH``.

    These tests drive the production detection function end to end by placing a
    genuine ``HxD.exe`` file on a controlled ``PATH`` (real environment control,
    never a stub of the function under test) and asserting the exact ``Path`` it
    resolves. They are the gate for the detection logic itself: corrupting the
    ``PATH`` scan, the ``is_file`` guard, or the name match turns them red.
    """

    @staticmethod
    def test_real_exe_on_path_resolves_to_exact_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """A real ``HxD.exe`` on ``PATH`` resolves to that exact file path.

        Args:
            monkeypatch: Pytest monkeypatch fixture used only for ``PATH`` env control.
            tmp_path: Pytest temporary directory fixture.
        """
        if _host_has_registry_or_common_hxd():
            pytest.fail("Host has a registry/common-dir HxD install; isolate the test host so PATH detection is authoritative.")

        install_dir = tmp_path / "hxd_install"
        install_dir.mkdir()
        exe = install_dir / _HXD_EXE_NAME
        exe.write_bytes(_MZ_STUB)

        monkeypatch.setenv("PATH", str(install_dir))

        resolved = find_hxd_executable()
        assert resolved == exe
        assert resolved is not None
        assert resolved.is_file()
        assert resolved.read_bytes() == _MZ_STUB

    @staticmethod
    def test_empty_path_with_no_install_resolves_to_none(monkeypatch: pytest.MonkeyPatch) -> None:
        """With no registry/common install and an empty ``PATH``, detection yields ``None``.

        Args:
            monkeypatch: Pytest monkeypatch fixture used only for ``PATH`` env control.
        """
        if _host_has_registry_or_common_hxd():
            pytest.fail("Host has a registry/common-dir HxD install; cannot validate the unavailable branch on this host.")

        monkeypatch.setenv("PATH", "")
        assert find_hxd_executable() is None

    @staticmethod
    def test_directory_named_like_exe_is_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """A directory named ``HxD.exe`` on ``PATH`` must not satisfy the file check.

        Args:
            monkeypatch: Pytest monkeypatch fixture used only for ``PATH`` env control.
            tmp_path: Pytest temporary directory fixture.
        """
        if _host_has_registry_or_common_hxd():
            pytest.fail("Host has a registry/common-dir HxD install; cannot validate the rejection branch on this host.")

        decoy_dir = tmp_path / "decoy"
        decoy_dir.mkdir()
        (decoy_dir / _HXD_EXE_NAME).mkdir()

        monkeypatch.setenv("PATH", str(decoy_dir))
        assert find_hxd_executable() is None

    @staticmethod
    def test_path_scan_skips_empty_dir_and_finds_later_entry(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """The ``PATH`` scan skips a dir without the exe and resolves a later real entry.

        Args:
            monkeypatch: Pytest monkeypatch fixture used only for ``PATH`` env control.
            tmp_path: Pytest temporary directory fixture.
        """
        if _host_has_registry_or_common_hxd():
            pytest.fail("Host has a registry/common-dir HxD install; cannot validate PATH ordering on this host.")

        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        real_dir = tmp_path / "real"
        real_dir.mkdir()
        exe = real_dir / _HXD_EXE_NAME
        exe.write_bytes(_MZ_STUB)

        monkeypatch.setenv("PATH", os.pathsep.join([str(empty_dir), str(real_dir)]))
        assert find_hxd_executable() == exe


@pytest.fixture
def window_with_hxd_available(
    qapp: QApplication,
    real_config: Config,
    real_orchestrator: Orchestrator,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> Generator[MainWindow]:
    """Provide a ``MainWindow`` whose real finder locates a genuine ``HxD.exe``.

    A real ``HxD.exe`` file is written to disk and its directory is placed on
    ``PATH`` via environment control. The production ``find_hxd_executable``
    runs unmodified during ``MainWindow`` construction and genuinely resolves
    the executable, so the registration branch is driven by real detection,
    not by stubbing the function under test. The heavyweight ``SandboxManager``
    is replaced with a no-op stand-in purely to isolate the unrelated sandbox
    subsystem; it is not the operation under test here.

    Args:
        qapp: QApplication instance required by Qt widgets.
        real_config: Real ``Config`` instance from the test fixtures.
        real_orchestrator: Real ``Orchestrator`` instance from the test fixtures.
        monkeypatch: Pytest monkeypatch fixture used for ``PATH`` env control and sandbox isolation.
        tmp_path: Pytest temporary directory fixture.

    Yields:
        Generator[MainWindow]: Window whose real finder located the HxD stub on ``PATH``.
    """
    _ = qapp
    if _host_has_registry_or_common_hxd():
        pytest.fail("Host has a registry/common-dir HxD install; isolate the test host so PATH detection is authoritative.")

    install_dir = tmp_path / "hxd_install"
    install_dir.mkdir()
    exe = install_dir / _HXD_EXE_NAME
    exe.write_bytes(_MZ_STUB)

    monkeypatch.setenv("PATH", str(install_dir))
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
    """Provide a ``MainWindow`` whose real finder locates no ``HxD.exe``.

    ``PATH`` is emptied via environment control and the host is asserted to
    have no registry/common-dir install, so the production
    ``find_hxd_executable`` genuinely returns ``None`` during construction. The
    finder itself is never stubbed; only the unrelated sandbox subsystem is
    isolated.

    Args:
        qapp: QApplication instance required by Qt widgets.
        real_config: Real ``Config`` instance from the test fixtures.
        real_orchestrator: Real ``Orchestrator`` instance from the test fixtures.
        monkeypatch: Pytest monkeypatch fixture used for ``PATH`` env control and sandbox isolation.

    Yields:
        Generator[MainWindow]: Window whose real finder found no HxD executable.
    """
    _ = qapp
    if _host_has_registry_or_common_hxd():
        pytest.fail("Host has a registry/common-dir HxD install; cannot validate the unavailable branch on this host.")

    monkeypatch.setenv("PATH", "")
    monkeypatch.setattr("intellicrack.ui.app.SandboxManager", NoOpSandboxManager)

    window = MainWindow(real_config, real_orchestrator)
    yield window
    window.close()


class TestHxDPanelRegistrationWhenAvailable:
    """``MainWindow`` attaches ``HxDPanel`` when the real finder locates HxD."""

    @staticmethod
    def test_hxd_panel_attribute_set(window_with_hxd_available: MainWindow) -> None:
        """``MainWindow.hxd_panel`` references an ``HxDPanel`` instance.

        Args:
            window_with_hxd_available: Window whose real finder located HxD on ``PATH``.
        """
        panel = window_with_hxd_available.hxd_panel
        assert panel is not None
        assert isinstance(panel, HxDPanel)

    @staticmethod
    def test_registered_panel_resolved_real_exe(window_with_hxd_available: MainWindow, tmp_path: Path) -> None:
        """The registered panel's ``hxd_exe`` is the real file resolved from ``PATH``.

        The panel's ``__init__`` independently re-runs the real detection, so
        its ``hxd_exe`` value confirms the whole detection path executed for
        real rather than being injected.

        Args:
            window_with_hxd_available: Window whose real finder located HxD on ``PATH``.
            tmp_path: Pytest temporary directory fixture (the install dir lives under it).
        """
        panel = window_with_hxd_available.hxd_panel
        assert panel is not None
        assert panel.hxd_exe is not None
        assert panel.hxd_exe.name == _HXD_EXE_NAME
        assert panel.hxd_exe.is_file()
        assert panel.hxd_exe.read_bytes() == _MZ_STUB
        assert tmp_path in panel.hxd_exe.parents

    @staticmethod
    def test_hxd_tab_attached_to_tool_panel(
        window_with_hxd_available: MainWindow,
    ) -> None:
        """The tool panel ``QTabWidget`` exposes the HxD tab.

        Args:
            window_with_hxd_available: Window whose real finder located HxD on ``PATH``.
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
            window_with_hxd_available: Window whose real finder located HxD on ``PATH``.
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
            window_with_hxd_available: Window whose real finder located HxD on ``PATH``.
        """
        embedded = window_with_hxd_available.tool_panel.embedded_tools
        assert "hxd" in embedded
        assert embedded["hxd"] is window_with_hxd_available.hxd_panel


class TestHxDPanelRegistrationWhenUnavailable:
    """``MainWindow`` is silent and stable when the real finder locates no HxD."""

    @staticmethod
    def test_no_hxd_panel_attribute(window_without_hxd: MainWindow) -> None:
        """``hxd_panel`` stays ``None`` when the real finder locates no HxD.

        Args:
            window_without_hxd: Window whose real finder found no HxD executable.
        """
        assert window_without_hxd.hxd_panel is None

    @staticmethod
    def test_no_hxd_tab_attached(window_without_hxd: MainWindow) -> None:
        """The tool panel ``QTabWidget`` does not expose the HxD tab.

        Args:
            window_without_hxd: Window whose real finder found no HxD executable.
        """
        tab_widget = window_without_hxd.tool_panel.tab_widget
        labels: list[str] = [tab_widget.tabText(i) for i in range(tab_widget.count())]
        assert _HXD_TAB_LABEL not in labels

    @staticmethod
    def test_no_embedded_tools_entry(window_without_hxd: MainWindow) -> None:
        """No ``hxd`` key is recorded in ``tool_panel.embedded_tools``.

        Args:
            window_without_hxd: Window whose real finder found no HxD executable.
        """
        assert "hxd" not in window_without_hxd.tool_panel.embedded_tools

    @staticmethod
    def test_main_window_constructs_without_exception(
        qapp: QApplication,
        real_config: Config,
        real_orchestrator: Orchestrator,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``MainWindow`` construction succeeds when the real finder locates no HxD.

        Args:
            qapp: QApplication instance required by Qt widgets.
            real_config: Real ``Config`` instance.
            real_orchestrator: Real ``Orchestrator`` instance.
            monkeypatch: Pytest monkeypatch fixture used for ``PATH`` env control and sandbox isolation.
        """
        _ = qapp
        if _host_has_registry_or_common_hxd():
            pytest.fail("Host has a registry/common-dir HxD install; cannot validate the unavailable branch on this host.")

        monkeypatch.setenv("PATH", "")
        monkeypatch.setattr("intellicrack.ui.app.SandboxManager", NoOpSandboxManager)

        window = MainWindow(real_config, real_orchestrator)
        try:
            assert window.hxd_panel is None
            tab_widget = window.tool_panel.tab_widget
            labels: list[str] = [tab_widget.tabText(i) for i in range(tab_widget.count())]
            assert _HXD_TAB_LABEL not in labels
        finally:
            window.close()


class TestHxDRegistrationTogglesWithRealDetection:
    """The same ``MainWindow`` code registers or skips purely on real detection.

    A single test drives both outcomes through the unmodified production finder
    by toggling only ``PATH`` between two constructions. This proves the
    registration decision is governed by real detection, not by any stub: the
    presence of the tab flips with the genuine on-disk/``PATH`` state.
    """

    @staticmethod
    def test_registration_flips_with_path_state(
        qapp: QApplication,
        real_config: Config,
        real_orchestrator: Orchestrator,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """Tab appears when a real exe is on ``PATH`` and disappears when it is not.

        Args:
            qapp: QApplication instance required by Qt widgets.
            real_config: Real ``Config`` instance.
            real_orchestrator: Real ``Orchestrator`` instance.
            monkeypatch: Pytest monkeypatch fixture used for ``PATH`` env control and sandbox isolation.
            tmp_path: Pytest temporary directory fixture.
        """
        _ = qapp
        if _host_has_registry_or_common_hxd():
            pytest.fail("Host has a registry/common-dir HxD install; cannot validate detection toggling on this host.")

        monkeypatch.setattr("intellicrack.ui.app.SandboxManager", NoOpSandboxManager)

        install_dir = tmp_path / "hxd_install"
        install_dir.mkdir()
        exe = install_dir / _HXD_EXE_NAME
        exe.write_bytes(_MZ_STUB)

        monkeypatch.setenv("PATH", str(install_dir))
        present_window = MainWindow(real_config, real_orchestrator)
        try:
            present_tabs = present_window.tool_panel.tab_widget
            present_labels = [present_tabs.tabText(i) for i in range(present_tabs.count())]
            assert _HXD_TAB_LABEL in present_labels
            assert present_window.hxd_panel is not None
        finally:
            present_window.close()

        monkeypatch.setenv("PATH", "")
        absent_window = MainWindow(real_config, real_orchestrator)
        try:
            absent_tabs = absent_window.tool_panel.tab_widget
            absent_labels = [absent_tabs.tabText(i) for i in range(absent_tabs.count())]
            assert _HXD_TAB_LABEL not in absent_labels
            assert absent_window.hxd_panel is None
        finally:
            absent_window.close()
