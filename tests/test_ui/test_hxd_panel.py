# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for the HxD hex editor panel bridge.

These tests exercise the real panel logic end to end. Because HxD itself is
an external Windows GUI tool that is not guaranteed to be installed in CI,
the editor binary is substituted with a *real* long-lived OS process (the
test interpreter running a sleeping script). The panel treats its editor as
"a program launched with the target file as its argument", so driving a real
QProcess through ``load_file`` / ``stop_tool`` / ``terminate_existing``
genuinely validates the bridge's launch, lifecycle, and teardown logic
without any mocks. The executable-detection logic is validated against a real
``HxD.exe`` file planted on ``PATH``.
"""

from __future__ import annotations

import shutil
import sys
import textwrap
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import QProcess

import intellicrack.ui.panels.hxd_panel as hxd_panel_mod
from intellicrack.ui.panels.hxd_panel import HxDPanel, find_hxd_executable


if TYPE_CHECKING:
    from collections.abc import Callable, Generator


_WAIT_FOR_STARTED_MS: int = 5_000


def _make_sleeper_script(tmp_path: Path) -> Path:
    """Write a real Python script that blocks so a spawned process stays alive.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        Path: Path to the on-disk script the panel will "open".
    """
    script = tmp_path / "target_payload.py"
    script.write_text(
        textwrap.dedent(
            """
            import time

            time.sleep(120)
            """,
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    return script


@pytest.fixture
def make_launchable_panel() -> Generator[Callable[[], HxDPanel]]:
    """Provide a factory for panels wired to a real launchable interpreter.

    The panel launches ``<editor> <file>``; pointing the editor at the test
    Python interpreter and opening a real ``.py`` script yields a genuine,
    controllable child process that exercises the full QProcess lifecycle.
    Every panel produced is terminated on teardown so no orphan process or
    embedded container survives the test.

    Yields:
        Generator[Callable[[], HxDPanel]]: Factory returning a launch-ready panel.
    """
    panels: list[HxDPanel] = []

    def _factory() -> HxDPanel:
        panel = HxDPanel()
        panel.hxd_exe = Path(sys.executable)
        panels.append(panel)
        return panel

    yield _factory

    for panel in panels:
        panel.terminate_existing()


@pytest.mark.usefixtures("qapp")
class TestFindHxdExecutable:
    """Tests for HxD executable detection against real on-disk binaries."""

    @staticmethod
    def test_detects_real_exe_on_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """The finder returns the real ``HxD.exe`` planted on ``PATH``.

        Args:
            tmp_path: Pytest temporary directory.
            monkeypatch: Pytest monkeypatch used only to control ``PATH``.
        """
        if sys.platform != "win32":
            pytest.skip("HxD detection is Windows-only")
        bin_dir = tmp_path / "hxd_install"
        bin_dir.mkdir()
        planted = bin_dir / "HxD.exe"
        shutil.copy(sys.executable, planted)

        monkeypatch.setenv("PATH", str(bin_dir))
        result = find_hxd_executable()

        assert result == planted
        assert result is not None
        assert result.is_file()
        assert result.read_bytes() == planted.read_bytes()

    @staticmethod
    def test_returns_none_when_absent_everywhere(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """The finder returns ``None`` when no ``HxD.exe`` exists on ``PATH``.

        Args:
            tmp_path: Pytest temporary directory.
            monkeypatch: Pytest monkeypatch used only to control ``PATH``.
        """
        if sys.platform != "win32":
            pytest.skip("HxD detection is Windows-only")
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        monkeypatch.setenv("PATH", str(empty_dir))

        assert find_hxd_executable() is None

    @staticmethod
    def test_ignores_directory_named_like_exe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A directory named ``HxD.exe`` is rejected because it is not a file.

        Args:
            tmp_path: Pytest temporary directory.
            monkeypatch: Pytest monkeypatch used only to control ``PATH``.
        """
        if sys.platform != "win32":
            pytest.skip("HxD detection is Windows-only")
        bin_dir = tmp_path / "trap"
        (bin_dir / "HxD.exe").mkdir(parents=True)
        monkeypatch.setenv("PATH", str(bin_dir))

        assert find_hxd_executable() is None

    @staticmethod
    def test_returns_none_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
        """Non-Windows platforms short-circuit to ``None`` before any probe.

        Args:
            monkeypatch: Pytest monkeypatch used to simulate the platform.
        """
        monkeypatch.setattr(hxd_panel_mod.sys, "platform", "linux")
        assert find_hxd_executable() is None


@pytest.mark.usefixtures("qapp")
class TestHxDPanelConstruction:
    """Tests for HxDPanel widget construction and initial wiring."""

    @staticmethod
    def test_initial_state_is_idle() -> None:
        """A fresh panel has no process, file, or embedded container."""
        panel = HxDPanel()
        assert panel.process is None
        assert panel.current_file is None
        assert panel.embedded_container is None
        assert panel.embed_info_label.text() == "HxD not launched"

    @staticmethod
    def test_status_label_reflects_real_detection() -> None:
        """The status label text matches the actual detection result.

        The independent oracle here is :func:`find_hxd_executable` invoked
        separately from the panel; the label must render exactly the
        "not found" sentinel or the discovered path, never a stale default.
        """
        panel = HxDPanel()
        detected = find_hxd_executable()
        text = panel.status_label.text()
        if detected is None:
            assert text == "HxD: not found"
        else:
            assert text == f"HxD: {detected}"

    @staticmethod
    def test_status_label_renders_planted_path() -> None:
        """Setting a real exe and refreshing renders that exact path.

        Drives :meth:`HxDPanel._update_status_label` with a concrete,
        independently-known path and asserts the exact rendered string.
        """
        panel = HxDPanel()
        editor = Path(sys.executable)
        panel.hxd_exe = editor
        panel._update_status_label()
        assert panel.status_label.text() == f"HxD: {editor}"

    @staticmethod
    def test_status_label_renders_not_found() -> None:
        """Clearing the exe and refreshing renders the not-found sentinel."""
        panel = HxDPanel()
        panel.hxd_exe = None
        panel._update_status_label()
        assert panel.status_label.text() == "HxD: not found"


@pytest.mark.usefixtures("qapp")
class TestHxDPanelFileLoading:
    """Tests for HxDPanel file loading against a real spawned process."""

    @staticmethod
    def test_load_file_rejects_missing_editor(tmp_path: Path) -> None:
        """``load_file`` returns ``False`` and spawns nothing without an editor.

        Args:
            tmp_path: Pytest temporary directory.
        """
        target = _make_sleeper_script(tmp_path)
        panel = HxDPanel()
        panel.hxd_exe = None

        assert panel.load_file(target) is False
        assert panel.process is None

    @staticmethod
    def test_load_file_rejects_nonexistent_target(
        tmp_path: Path,
        make_launchable_panel: Callable[[], HxDPanel],
    ) -> None:
        """A real editor still refuses to launch for a non-existent file.

        Args:
            tmp_path: Pytest temporary directory.
            make_launchable_panel: Factory producing launch-ready panels.
        """
        panel = make_launchable_panel()
        missing = tmp_path / "does_not_exist.bin"

        assert panel.load_file(missing) is False
        assert panel.process is None
        assert panel.current_file != missing

    @staticmethod
    def test_load_file_spawns_real_process(
        tmp_path: Path,
        make_launchable_panel: Callable[[], HxDPanel],
    ) -> None:
        """``load_file`` launches a real running process for an existing file.

        Args:
            tmp_path: Pytest temporary directory.
            make_launchable_panel: Factory producing launch-ready panels.
        """
        target = _make_sleeper_script(tmp_path)
        panel = make_launchable_panel()

        assert panel.load_file(target) is True

        process = panel.process
        assert process is not None
        assert process.state() == QProcess.ProcessState.Running
        assert process.processId() > 0
        assert panel.current_file == target
        assert panel.embed_info_label.text() == f"HxD: {target.name}"

    @staticmethod
    def test_load_file_accepts_string_path(
        tmp_path: Path,
        make_launchable_panel: Callable[[], HxDPanel],
    ) -> None:
        """A string path is coerced to ``Path`` and launches identically.

        Args:
            tmp_path: Pytest temporary directory.
            make_launchable_panel: Factory producing launch-ready panels.
        """
        target = _make_sleeper_script(tmp_path)
        panel = make_launchable_panel()

        assert panel.load_file(str(target)) is True

        assert panel.current_file == target
        assert isinstance(panel.current_file, Path)
        process = panel.process
        assert process is not None
        assert process.state() == QProcess.ProcessState.Running

    @staticmethod
    def test_tool_started_emitted_once_on_load(
        tmp_path: Path,
        make_launchable_panel: Callable[[], HxDPanel],
    ) -> None:
        """A successful load emits ``tool_started`` exactly once.

        Args:
            tmp_path: Pytest temporary directory.
            make_launchable_panel: Factory producing launch-ready panels.
        """
        target = _make_sleeper_script(tmp_path)
        panel = make_launchable_panel()
        started: list[bool] = []
        panel.tool_started.connect(lambda: started.append(True))

        assert panel.load_file(target) is True
        assert started == [True]

    @staticmethod
    def test_reload_replaces_running_process(
        tmp_path: Path,
        make_launchable_panel: Callable[[], HxDPanel],
    ) -> None:
        """Loading a second file terminates the first process and starts anew.

        Args:
            tmp_path: Pytest temporary directory.
            make_launchable_panel: Factory producing launch-ready panels.
        """
        first = _make_sleeper_script(tmp_path)
        second = tmp_path / "second_payload.py"
        second.write_text(first.read_text(encoding="utf-8"), encoding="utf-8")
        panel = make_launchable_panel()

        assert panel.load_file(first) is True
        first_process = panel.process
        assert first_process is not None
        first_pid = first_process.processId()

        assert panel.load_file(second) is True
        second_process = panel.process
        assert second_process is not None
        assert second_process.state() == QProcess.ProcessState.Running
        assert second_process.processId() != first_pid
        assert second_process is not first_process
        assert panel.current_file == second


@pytest.mark.usefixtures("qapp")
class TestHxDPanelLifecycle:
    """Tests for HxDPanel start/stop lifecycle against real processes."""

    @staticmethod
    def test_terminate_existing_kills_running_process(
        tmp_path: Path,
        make_launchable_panel: Callable[[], HxDPanel],
    ) -> None:
        """``terminate_existing`` actually stops a running child process.

        Args:
            tmp_path: Pytest temporary directory.
            make_launchable_panel: Factory producing launch-ready panels.
        """
        target = _make_sleeper_script(tmp_path)
        panel = make_launchable_panel()
        assert panel.load_file(target) is True
        process = panel.process
        assert process is not None
        assert process.waitForStarted(_WAIT_FOR_STARTED_MS)
        assert process.state() == QProcess.ProcessState.Running

        panel.terminate_existing()

        assert panel.process is None
        assert panel.embedded_container is None
        assert process.state() == QProcess.ProcessState.NotRunning

    @staticmethod
    def test_stop_tool_terminates_and_resets(
        tmp_path: Path,
        make_launchable_panel: Callable[[], HxDPanel],
    ) -> None:
        """``stop_tool`` returns ``True``, kills the process, and resets state.

        Args:
            tmp_path: Pytest temporary directory.
            make_launchable_panel: Factory producing launch-ready panels.
        """
        target = _make_sleeper_script(tmp_path)
        panel = make_launchable_panel()
        assert panel.load_file(target) is True
        process = panel.process
        assert process is not None

        assert panel.stop_tool() is True

        assert panel.process is None
        assert panel.embedded_container is None
        assert panel.embed_info_label.text() == "HxD not launched"
        assert process.state() == QProcess.ProcessState.NotRunning

    @staticmethod
    def test_stop_tool_emits_tool_closed_once(
        tmp_path: Path,
        make_launchable_panel: Callable[[], HxDPanel],
    ) -> None:
        """``stop_tool`` emits ``tool_closed`` exactly once with state cleared.

        Args:
            tmp_path: Pytest temporary directory.
            make_launchable_panel: Factory producing launch-ready panels.
        """
        target = _make_sleeper_script(tmp_path)
        panel = make_launchable_panel()
        assert panel.load_file(target) is True
        closed: list[bool] = []
        panel.tool_closed.connect(lambda: closed.append(True))

        panel.stop_tool()

        assert closed == [True]
        assert panel.process is None

    @staticmethod
    def test_terminate_without_process_is_noop() -> None:
        """``terminate_existing`` on an idle panel leaves state untouched."""
        panel = HxDPanel()
        panel.terminate_existing()
        assert panel.process is None
        assert panel.embedded_container is None

    @staticmethod
    def test_double_terminate_after_load_is_safe(
        tmp_path: Path,
        make_launchable_panel: Callable[[], HxDPanel],
    ) -> None:
        """Terminating twice after a real load remains safe and idempotent.

        Args:
            tmp_path: Pytest temporary directory.
            make_launchable_panel: Factory producing launch-ready panels.
        """
        target = _make_sleeper_script(tmp_path)
        panel = make_launchable_panel()
        assert panel.load_file(target) is True
        process = panel.process
        assert process is not None

        panel.terminate_existing()
        panel.terminate_existing()

        assert panel.process is None
        assert process.state() == QProcess.ProcessState.NotRunning

    @staticmethod
    def test_cleanup_terminates_running_process(
        tmp_path: Path,
        make_launchable_panel: Callable[[], HxDPanel],
    ) -> None:
        """``cleanup`` tears down a running process and nulls the reference.

        Args:
            tmp_path: Pytest temporary directory.
            make_launchable_panel: Factory producing launch-ready panels.
        """
        target = _make_sleeper_script(tmp_path)
        panel = make_launchable_panel()
        assert panel.load_file(target) is True
        process = panel.process
        assert process is not None

        panel.cleanup()

        assert panel.process is None
        assert process.state() == QProcess.ProcessState.NotRunning


@pytest.mark.usefixtures("qapp")
class TestHxDPanelToolbar:
    """Tests for HxDPanel toolbar status label content transitions."""

    @staticmethod
    def test_label_tracks_loaded_filename(
        tmp_path: Path,
        make_launchable_panel: Callable[[], HxDPanel],
    ) -> None:
        """Loading a file updates the embed info label to the file name.

        Args:
            tmp_path: Pytest temporary directory.
            make_launchable_panel: Factory producing launch-ready panels.
        """
        target = _make_sleeper_script(tmp_path)
        panel = make_launchable_panel()

        assert panel.embed_info_label.text() == "HxD not launched"
        assert panel.load_file(target) is True
        assert panel.embed_info_label.text() == f"HxD: {target.name}"

    @staticmethod
    def test_label_resets_after_stop(
        tmp_path: Path,
        make_launchable_panel: Callable[[], HxDPanel],
    ) -> None:
        """Stopping the tool restores the not-launched label sentinel.

        Args:
            tmp_path: Pytest temporary directory.
            make_launchable_panel: Factory producing launch-ready panels.
        """
        target = _make_sleeper_script(tmp_path)
        panel = make_launchable_panel()
        assert panel.load_file(target) is True
        assert panel.embed_info_label.text() == f"HxD: {target.name}"

        panel.stop_tool()

        assert panel.embed_info_label.text() == "HxD not launched"
