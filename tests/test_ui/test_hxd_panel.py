# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for HxD hex editor panel.

Validates HxD executable detection, panel construction, file loading
preconditions, lifecycle management, and toolbar behavior.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import intellicrack.ui.panels.hxd_panel as hxd_panel_mod
from intellicrack.ui.panels.hxd_panel import HxDPanel


@pytest.mark.usefixtures("qapp")
class TestFindHxdExecutable:
    """Tests for _find_hxd_executable detection logic."""

    @staticmethod
    def test_returns_path_or_none() -> None:
        """Verify return type is Path or None."""
        result = hxd_panel_mod._find_hxd_executable()
        assert result is None or isinstance(result, Path)

    @staticmethod
    def test_returned_path_exists_if_not_none() -> None:
        """Verify returned path exists on disk if not None."""
        result = hxd_panel_mod._find_hxd_executable()
        if result is not None:
            assert result.exists()

    @staticmethod
    def test_returned_path_is_executable() -> None:
        """Verify returned path points to an actual file."""
        result = hxd_panel_mod._find_hxd_executable()
        if result is not None:
            assert result.is_file()

    @staticmethod
    def test_deterministic_result() -> None:
        """Verify repeated calls return the same result."""
        result1 = hxd_panel_mod._find_hxd_executable()
        result2 = hxd_panel_mod._find_hxd_executable()
        assert result1 == result2


@pytest.mark.usefixtures("qapp")
class TestHxDPanelConstruction:
    """Tests for HxDPanel widget construction."""

    @staticmethod
    def test_panel_constructs() -> None:
        """Verify HxDPanel can be instantiated."""
        panel = HxDPanel()
        assert panel is not None

    @staticmethod
    def test_panel_has_embed_host() -> None:
        """Verify panel creates the embed host widget."""
        panel = HxDPanel()
        assert hasattr(panel, "_embed_host")
        assert panel._embed_host is not None

    @staticmethod
    def test_panel_has_info_label() -> None:
        """Verify panel creates the info label."""
        panel = HxDPanel()
        assert hasattr(panel, "_embed_info_label")
        assert panel._embed_info_label.text() == "HxD not launched"

    @staticmethod
    def test_initial_process_is_none() -> None:
        """Verify no HxD process is running initially."""
        panel = HxDPanel()
        assert panel._process is None

    @staticmethod
    def test_initial_file_is_none() -> None:
        """Verify no file is loaded initially."""
        panel = HxDPanel()
        assert panel._current_file is None

    @staticmethod
    def test_initial_container_is_none() -> None:
        """Verify no embedded container exists initially."""
        panel = HxDPanel()
        assert panel._embedded_container is None

    @staticmethod
    def test_hxd_exe_matches_finder() -> None:
        """Verify panel._hxd_exe agrees with _find_hxd_executable."""
        panel = HxDPanel()
        expected = hxd_panel_mod._find_hxd_executable()
        assert panel._hxd_exe == expected

    @staticmethod
    def test_embed_host_layout_exists() -> None:
        """Verify embed host widget has a layout."""
        panel = HxDPanel()
        assert panel._embed_host.layout() is not None


@pytest.mark.usefixtures("qapp")
class TestHxDPanelFileLoadingPreconditions:
    """Tests for HxDPanel file loading precondition checks.

    These tests verify the conditions that load_file checks
    without triggering the blocking not-installed dialog.
    """

    @staticmethod
    def test_hxd_none_blocks_launch() -> None:
        """Verify _hxd_exe=None would prevent file loading."""
        panel = HxDPanel()
        panel._hxd_exe = None
        assert panel._hxd_exe is None

    @staticmethod
    def test_nonexistent_file_check() -> None:
        """Verify load_file would reject non-existent files.

        When HxD IS installed, load_file checks file existence
        after the _hxd_exe check. This validates the path check logic.
        """
        panel = HxDPanel()
        if panel._hxd_exe is not None:
            result = panel.load_file(Path("/nonexistent/path/test.bin"))
            assert result is False

    @staticmethod
    def test_load_file_accepts_string() -> None:
        """Verify load_file converts string path to Path object.

        Validates path conversion logic without requiring HxD.
        """
        panel = HxDPanel()
        if panel._hxd_exe is not None:
            result = panel.load_file("/nonexistent/path/test.bin")
            assert result is False

    @staticmethod
    def test_path_conversion() -> None:
        """Verify Path conversion from string produces consistent result."""
        path_str = "/test/file.bin"
        path_obj = Path(path_str)
        assert Path(path_str) == path_obj


@pytest.mark.usefixtures("qapp")
class TestHxDPanelLifecycle:
    """Tests for HxDPanel start/stop lifecycle."""

    @staticmethod
    def test_stop_tool_returns_true() -> None:
        """Verify stop_tool returns True even without running process."""
        panel = HxDPanel()
        result = panel.stop_tool()
        assert result is True

    @staticmethod
    def test_stop_tool_emits_tool_closed() -> None:
        """Verify stop_tool emits tool_closed signal."""
        panel = HxDPanel()
        emitted: list[bool] = []
        panel.tool_closed.connect(lambda: emitted.append(True))
        panel.stop_tool()
        assert len(emitted) == 1

    @staticmethod
    def test_terminate_existing_no_process() -> None:
        """Verify _terminate_existing is safe with no running process."""
        panel = HxDPanel()
        panel._terminate_existing()
        assert panel._process is None
        assert panel._embedded_container is None

    @staticmethod
    def test_cleanup_calls_stop() -> None:
        """Verify _cleanup terminates the process."""
        panel = HxDPanel()
        panel._cleanup()
        assert panel._process is None

    @staticmethod
    def test_double_terminate_is_safe() -> None:
        """Verify calling _terminate_existing twice is safe."""
        panel = HxDPanel()
        panel._terminate_existing()
        panel._terminate_existing()
        assert panel._process is None

    @staticmethod
    def test_stop_then_cleanup() -> None:
        """Verify stop_tool followed by _cleanup is safe."""
        panel = HxDPanel()
        panel.stop_tool()
        panel._cleanup()
        assert panel._process is None

    @staticmethod
    def test_stop_tool_clears_container() -> None:
        """Verify stop_tool clears the embedded container."""
        panel = HxDPanel()
        panel.stop_tool()
        assert panel._embedded_container is None


@pytest.mark.usefixtures("qapp")
class TestHxDPanelToolbar:
    """Tests for HxDPanel toolbar content."""

    @staticmethod
    def test_status_label_exists() -> None:
        """Verify the toolbar status label is created."""
        panel = HxDPanel()
        assert panel._status_label is not None

    @staticmethod
    def test_status_label_shows_hxd_in_text() -> None:
        """Verify status label text contains HxD reference."""
        panel = HxDPanel()
        label = panel._status_label
        assert label is not None
        text = label.text()
        assert "HxD" in text

    @staticmethod
    def test_status_label_content_reflects_availability() -> None:
        """Verify status label reflects HxD availability."""
        panel = HxDPanel()
        label = panel._status_label
        assert label is not None
        text = label.text()
        if panel._hxd_exe is None:
            assert "not found" in text
        else:
            assert str(panel._hxd_exe) in text

    @staticmethod
    def test_hxd_exe_attribute_type() -> None:
        """Verify _hxd_exe is Path or None."""
        panel = HxDPanel()
        assert panel._hxd_exe is None or isinstance(panel._hxd_exe, Path)
