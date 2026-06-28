# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Wave-5 real-gate tests for UI shell and panel findings.

Closes group-08 section-14 findings 54-60 and group-02 section-15 findings
47 and 49 (StackViewer rendered rows and async_bridge
cancel_pending_main_loop_tasks). Finding 48 (SandboxMixin bridge routing) is
already gated by tests/test_audit4/c12_hex_sandbox_route/test_sandbox_route.py,
which asserts the exact ``copy_to(instance_id, source, dest)`` triple, so it is
not duplicated here.
"""

from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import sys
import threading
import time
from typing import TYPE_CHECKING, Any

import pytest
from PyQt6.QtWidgets import (
    QApplication,
    QMessageBox,
    QPushButton,
    QWidget,
)

import intellicrack.__main__ as _intellicrack_main_module
import intellicrack.ui.panels.async_bridge as _async_bridge_mod
import intellicrack.ui.xpu_status as _xpu_status_mod
from intellicrack.core.config import Config, LogConfig, SessionConfig, UIConfig
from intellicrack.core.logging import setup_logging
from intellicrack.main import _CLIOptions, _parse_args
from intellicrack.providers.xpu_utils import XPUDeviceInfo
from intellicrack.ui import dialogs_helpers
from intellicrack.ui.dialogs_helpers import show_info
from intellicrack.ui.panels.async_bridge import cancel_pending_main_loop_tasks
from intellicrack.ui.panels.stack_viewer import StackFrame, StackFrameTable
from intellicrack.ui.preferences import AppearanceSettingsWidget, SessionSettingsWidget
from intellicrack.ui.session_manager import _FlowLayout
from intellicrack.ui.xpu_status import XPUStatusDialog


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from PyQt6.QtCore import QThread


pytestmark = pytest.mark.usefixtures("qapp")


def _thread_finished(worker: QThread) -> bool:
    """Report whether a retained worker QThread has finished or been deleted.

    Args:
        worker: The retained ``QThread`` to inspect.

    Returns:
        bool: True if the worker has finished or its C++ object was already
        destroyed (``deleteLater`` processed); False while it is still running.
    """
    try:
        return worker.isFinished()
    except RuntimeError:
        return True


@pytest.fixture(autouse=True)
def _drain_bridge_workers() -> Iterator[None]:
    """Join and release async-bridge worker QThreads after every test.

    The SandboxMixin save path dispatches ``copy_to`` onto a retained
    :class:`BridgeCallWorker` QThread. Without pumping the Qt event loop the
    finished worker's ``deleteLater`` is never delivered, so the worker stays
    pinned in ``_WorkerRegistry`` and its QThread keeps the interpreter from
    exiting, hanging the whole test session. Pumping events plus joining each
    worker, then shutting the persistent loop down, lets the process exit.

    Yields:
        None: Control returns to the test; cleanup runs on teardown.
    """
    yield
    app = QApplication.instance()
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if app is not None:
            app.processEvents()
        with _async_bridge_mod._WorkerRegistry.lock:
            pending = [w for w in _async_bridge_mod._WorkerRegistry.workers if not _thread_finished(w)]
        if not pending:
            break
        for worker in pending:
            worker.wait(100)
    if app is not None:
        app.processEvents()
    _async_bridge_mod.shutdown_bridge_loop()


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _configure_logging(log_dir: Path) -> Path:
    """Wire real structlog JSON-Lines logging into ``log_dir``.

    Args:
        log_dir: Directory to receive ``intellicrack.log``.

    Returns:
        Path: The active log file path.
    """
    log_dir.mkdir(parents=True, exist_ok=True)
    setup_logging(
        LogConfig(
            level="DEBUG",
            file_enabled=True,
            console_enabled=False,
            json_file=True,
            max_file_size_mb=10,
            backup_count=1,
            retention_days=1,
        ),
        log_dir=log_dir,
    )
    return log_dir / "intellicrack.log"


def _read_log_records(log_file: Path) -> list[dict[str, object]]:
    """Flush handlers and parse JSON-Lines records from ``log_file``.

    Args:
        log_file: Path to the JSON-Lines log file produced by structlog.

    Returns:
        list[dict[str, object]]: All successfully parsed log records.
    """
    for handler in logging.getLogger().handlers:
        handler.flush()
    records: list[dict[str, object]] = []
    for line in log_file.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            records.append(json.loads(stripped))
        except json.JSONDecodeError:
            continue
    return records


# ---------------------------------------------------------------------------
# Finding 54: show_info() structured log (dialogs_helpers.py:28)
# ---------------------------------------------------------------------------


class TestShowInfoStructuredLog:
    """Gate for the missing show_info log assertion (finding 54).

    The existing test_realcov_15_dialog_helpers_logging.py covers show_error
    and show_warning only. Deleting ``_logger.info(...)`` inside show_info
    leaves all prior tests green.
    """

    @staticmethod
    def test_show_info_emits_dialog_info_at_info_level(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``show_info`` logs ``dialog_info`` at INFO level with exact title.

        Args:
            tmp_path: Pytest temporary directory.
            monkeypatch: Pytest monkeypatch fixture (isolates the OS modal).
        """
        log_file = _configure_logging(tmp_path / "logs")
        monkeypatch.setattr(
            dialogs_helpers.QMessageBox,
            "information",
            staticmethod(lambda *_a, **_k: QMessageBox.StandardButton.Ok),
        )

        show_info(None, "Deploy Complete", "Binary transferred successfully.")

        records = _read_log_records(log_file)
        matching = [r for r in records if r.get("event") == "dialog_info"]
        assert matching, "show_info did not emit a dialog_info log record"
        record = matching[-1]
        assert str(record.get("level", "")).upper() == "INFO", f"expected INFO level, got {record.get('level')!r}"
        assert record.get("title") == "Deploy Complete", f"title mismatch: {record.get('title')!r}"


# ---------------------------------------------------------------------------
# Finding 55: AppearanceSettingsWidget.get_settings() (preferences.py:278)
# ---------------------------------------------------------------------------


class TestAppearanceSettingsGetSettings:
    """Gate for AppearanceSettingsWidget.get_settings (finding 55).

    Deleting the method or returning ``{}`` breaks nothing in the existing
    suite; returning the wrong font_size or theme goes undetected.
    """

    @staticmethod
    def test_get_settings_reflects_explicit_font_size_and_theme(
        tmp_path: Path,
    ) -> None:
        """Configured font_size=14 and theme='light' appear in get_settings output.

        Args:
            tmp_path: Pytest temporary directory (satisfies type constraints
                for Config path fields).
        """
        config = Config(
            tools_directory=tmp_path / "tools",
            logs_directory=tmp_path / "logs",
            data_directory=tmp_path / "data",
        )
        widget = AppearanceSettingsWidget(config)

        widget._font_size.setValue(14)
        light_idx = widget._theme_combo.findData("light")
        assert light_idx >= 0, "theme combo lacks 'light' data entry"
        widget._theme_combo.setCurrentIndex(light_idx)

        settings: dict[str, Any] = widget.get_settings()
        ui_cfg = settings["ui"]
        assert isinstance(ui_cfg, UIConfig), f"expected UIConfig, got {type(ui_cfg)}"
        assert ui_cfg.font_size == 14, f"font_size: expected 14, got {ui_cfg.font_size}"
        assert ui_cfg.theme == "light", f"theme: expected 'light', got {ui_cfg.theme!r}"


# ---------------------------------------------------------------------------
# Finding 56: SessionSettingsWidget.get_settings() (preferences.py:349)
# ---------------------------------------------------------------------------


class TestSessionSettingsGetSettings:
    """Gate for SessionSettingsWidget.get_settings (finding 56).

    Neither method deletion nor wrong field values are caught by the
    existing suite.
    """

    @staticmethod
    def test_get_settings_auto_save_false_and_exact_interval_retention(
        tmp_path: Path,
    ) -> None:
        """auto_save=False, interval=120, retention=7 round-trip through get_settings.

        Args:
            tmp_path: Pytest temporary directory for Config path fields.
        """
        config = Config(
            tools_directory=tmp_path / "tools",
            logs_directory=tmp_path / "logs",
            data_directory=tmp_path / "data",
        )
        widget = SessionSettingsWidget(config)

        widget._autosave_enabled.setChecked(False)
        widget._autosave_interval.setValue(120)
        widget._retention_days.setValue(7)

        settings: dict[str, Any] = widget.get_settings()
        sess_cfg = settings["session"]
        assert isinstance(sess_cfg, SessionConfig), f"expected SessionConfig, got {type(sess_cfg)}"
        assert sess_cfg.auto_save is False, f"auto_save should be False, got {sess_cfg.auto_save!r}"
        assert sess_cfg.save_interval_seconds == 120, f"interval: expected 120, got {sess_cfg.save_interval_seconds}"
        assert sess_cfg.retention_days == 7, f"retention: expected 7, got {sess_cfg.retention_days}"


# ---------------------------------------------------------------------------
# Finding 57: _FlowLayout tag-chip flow wrapping (session_manager.py:64)
# ---------------------------------------------------------------------------


class TestFlowLayoutWrapping:
    """Gate for _FlowLayout.heightForWidth wrapping behavior (finding 57).

    With no test covering _FlowLayout, removing the wrap-on-overflow branch
    in _do_layout would leave all buttons on a single row regardless of
    available width, causing heightForWidth to return the same value for
    any width.
    """

    @staticmethod
    def test_height_for_width_increases_in_narrow_container() -> None:
        """Three chips in a 1-pixel-wide container require more height than in 10000 px.

        The independent oracle is the geometric wrapping specification:
        items that cannot fit on one row must occupy additional rows, each
        adding ``item_height + vertical_spacing`` to the total.  Any
        non-zero button height makes the narrow case strictly taller.
        """
        container = QWidget()
        flow = _FlowLayout(container, margin=0, horizontal_spacing=4, vertical_spacing=4)

        for i in range(3):
            btn = QPushButton(f"chip-{i}", container)
            flow.addWidget(btn)

        single_row_height = flow.heightForWidth(10_000)
        assert single_row_height > 0, "buttons must have positive height in offscreen Qt"
        wrapped_height = flow.heightForWidth(1)
        assert wrapped_height > single_row_height, (
            f"wrapped height ({wrapped_height}) should exceed single-row height ({single_row_height}); wrap logic may be broken"
        )

    @staticmethod
    def test_height_for_width_reports_via_has_height_for_width() -> None:
        """_FlowLayout advertises height-for-width dependency via hasHeightForWidth.

        Mutation: returning ``False`` from ``hasHeightForWidth`` → assertion
        fails; layout callers would skip ``heightForWidth`` entirely.
        """
        flow = _FlowLayout()
        assert flow.hasHeightForWidth() is True


# ---------------------------------------------------------------------------
# Finding 58: XPUStatusDialog label text after _refresh_device_info()
# ---------------------------------------------------------------------------


class TestXPUStatusDialogRefreshDeviceInfo:
    """Gate for XPUStatusDialog._refresh_device_info label text (finding 58).

    The nine existing tests only check widget existence and types; they pass
    even if _refresh_device_info silently sets wrong text or is deleted.
    """

    @staticmethod
    def test_no_xpu_available_sets_cpu_only_status_label(
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When is_xpu_available() returns False the status label reads 'CPU Only'.

        Args:
            monkeypatch: Pytest monkeypatch fixture.
        """
        monkeypatch.setattr(_xpu_status_mod, "is_xpu_available", lambda: False)
        monkeypatch.setattr(_xpu_status_mod, "get_xpu_memory_info", lambda _idx: None)
        monkeypatch.setattr(
            _xpu_status_mod,
            "check_windows_requirements",
            lambda: (True, []),
        )
        monkeypatch.setattr(_xpu_status_mod, "get_global_model_cache", None)

        dialog = XPUStatusDialog()
        dialog.refresh_timer.stop()

        worker = getattr(dialog, "_requirements_worker", None)
        if worker is not None:
            worker.wait(3_000)

        assert dialog.status_label.text() == "CPU Only", f"expected 'CPU Only', got {dialog.status_label.text()!r}"
        assert dialog.device_name_label.text() == "No XPU device detected", f"device label: {dialog.device_name_label.text()!r}"
        dialog.close()

    @staticmethod
    def test_known_device_info_sets_exact_device_driver_and_caps_labels(
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A known XPUDeviceInfo produces exact device, driver, and caps label text.

        The oracle is the XPUDeviceInfo fields themselves: device_name,
        driver_version, and the capability flags that map to "FP16 / BF16 / INT8".

        Args:
            monkeypatch: Pytest monkeypatch fixture.
        """
        device_info = XPUDeviceInfo(
            device_index=0,
            device_name="Intel Arc B580",
            total_memory_bytes=12 * 1024 * 1024 * 1024,
            driver_version="31.0.101.5522",
            device_id="0xe20b",
            is_arc_b580=True,
            supports_fp16=True,
            supports_bf16=True,
            supports_int8=True,
        )

        monkeypatch.setattr(_xpu_status_mod, "is_xpu_available", lambda: True)
        monkeypatch.setattr(
            _xpu_status_mod,
            "get_xpu_device_info",
            lambda _idx: device_info,
        )
        monkeypatch.setattr(
            _xpu_status_mod,
            "get_optimal_dtype_for_xpu",
            lambda: "float16",
        )
        monkeypatch.setattr(
            _xpu_status_mod,
            "get_xpu_memory_info",
            lambda _idx: (2 * 1024 * 1024 * 1024, 12 * 1024 * 1024 * 1024),
        )
        monkeypatch.setattr(
            _xpu_status_mod,
            "check_windows_requirements",
            lambda: (True, []),
        )
        monkeypatch.setattr(_xpu_status_mod, "get_global_model_cache", None)

        dialog = XPUStatusDialog()
        dialog.refresh_timer.stop()

        worker = getattr(dialog, "_requirements_worker", None)
        if worker is not None:
            worker.wait(3_000)

        assert dialog.device_name_label.text() == "Intel Arc B580", f"device: {dialog.device_name_label.text()!r}"
        assert dialog.driver_label.text() == "31.0.101.5522", f"driver: {dialog.driver_label.text()!r}"
        assert dialog.caps_label.text() == "FP16 / BF16 / INT8", f"caps: {dialog.caps_label.text()!r}"
        dialog.close()


# ---------------------------------------------------------------------------
# Finding 59: main.py arg parsing (no --log-dir; test what exists)
# ---------------------------------------------------------------------------


class TestMainArgParsing:
    """Gate for _parse_args in main.py (finding 59).

    No test_main.py existed. The audit spec mentioned ``--log-dir`` which
    does NOT exist in the parser; that flag is an audit artifact.  Tests
    below cover the flags that ARE present: --log-level, --verbose, --quiet,
    --config. Each assertion is falsified by returning the wrong field value.
    """

    @staticmethod
    def test_log_level_flag_sets_exact_string(
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``--log-level DEBUG`` produces _CLIOptions.log_level == 'DEBUG'.

        Args:
            monkeypatch: Pytest monkeypatch for sys.argv isolation.
        """
        monkeypatch.setattr(sys, "argv", ["intellicrack", "--log-level", "DEBUG"])
        opts: _CLIOptions
        opts, _ = _parse_args()
        assert opts.log_level == "DEBUG", f"expected 'DEBUG', got {opts.log_level!r}"

    @staticmethod
    def test_verbose_flag_resolves_to_debug_level(
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``-v`` / ``--verbose`` produces log_level == 'DEBUG'.

        Args:
            monkeypatch: Pytest monkeypatch for sys.argv isolation.
        """
        monkeypatch.setattr(sys, "argv", ["intellicrack", "--verbose"])
        opts: _CLIOptions
        opts, _ = _parse_args()
        assert opts.log_level == "DEBUG", f"expected 'DEBUG' from --verbose, got {opts.log_level!r}"

    @staticmethod
    def test_quiet_flag_resolves_to_warning_level(
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``-q`` / ``--quiet`` produces log_level == 'WARNING'.

        Args:
            monkeypatch: Pytest monkeypatch for sys.argv isolation.
        """
        monkeypatch.setattr(sys, "argv", ["intellicrack", "--quiet"])
        opts: _CLIOptions
        opts, _ = _parse_args()
        assert opts.log_level == "WARNING", f"expected 'WARNING' from --quiet, got {opts.log_level!r}"

    @staticmethod
    def test_config_flag_produces_exact_path(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``--config <path>`` produces config_path == Path(path).expanduser().

        Args:
            tmp_path: Pytest temporary directory used as config file location.
            monkeypatch: Pytest monkeypatch for sys.argv isolation.
        """
        cfg_path = tmp_path / "custom.toml"
        monkeypatch.setattr(sys, "argv", ["intellicrack", "--config", str(cfg_path)])
        opts: _CLIOptions
        opts, _ = _parse_args()
        assert opts.config_path == cfg_path.expanduser(), f"config_path: expected {cfg_path.expanduser()!r}, got {opts.config_path!r}"


# ---------------------------------------------------------------------------
# Finding 60: __main__.py entry point
# ---------------------------------------------------------------------------


class TestMainEntryPoint:
    """Gate for the __main__.py entry point (finding 60).

    No test existed. The module must export ``run`` as a callable, and
    invoking ``python -m intellicrack --version`` must exit with code 0
    and emit version text. ``--version`` triggers sys.exit(0) inside
    argparse before Qt is initialised, so no display is needed.
    """

    @staticmethod
    def test_run_is_callable_in_main_module() -> None:
        """``intellicrack.__main__.run`` is a callable object.

        Mutation: renaming ``run`` to ``_run`` in __main__.py → AttributeError
        on ``getattr`` → assertion fails.
        """
        run_fn = getattr(_intellicrack_main_module, "run", None)
        assert callable(run_fn), "__main__.run must be a callable; missing or renamed entry point"

    @staticmethod
    def test_version_flag_exits_zero_and_emits_version_string() -> None:
        """``python -m intellicrack --version`` exits 0 and prints 'Intellicrack'.

        Mutation: changing the version argparse action to exit(1) → returncode
        != 0 → assertion fails.
        """
        result = subprocess.run(
            [sys.executable, "-m", "intellicrack", "--version"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, f"expected exit 0, got {result.returncode}; stderr: {result.stderr[:200]!r}"
        combined = result.stdout + result.stderr
        assert "Intellicrack" in combined, f"version output should contain 'Intellicrack'; got: {combined[:200]!r}"


# ---------------------------------------------------------------------------
# Finding 47 (group-02): stack_viewer.py — StackFrameTable.set_frames
# ---------------------------------------------------------------------------


class TestStackFrameTableSetFrames:
    """Gate for StackFrameTable.set_frames rendered rows (group-02 finding 47).

    No test file for stack_viewer existed. Deleting set_frames or returning
    wrong text in any cell is undetected.
    """

    @staticmethod
    def test_rendered_row_count_matches_frame_list_length() -> None:
        """set_frames with 2 frames produces rowCount() == 2.

        Mutation: hardcoding ``setRowCount(0)`` → rowCount() == 0 → fails.
        """
        table = StackFrameTable()
        frames = [
            StackFrame(
                index=0,
                return_address=0x00007FFE_12345678,
                function_name="main",
                module_name="target.exe",
            ),
            StackFrame(
                index=1,
                return_address=0x00007FFE_AABB_CCDD,
                function_name="unknown",
                module_name="ntdll.dll",
            ),
        ]
        table.set_frames(frames)
        assert table.rowCount() == 2, f"expected 2 rows for 2 frames, got {table.rowCount()}"

    @staticmethod
    def test_first_row_address_formatted_as_16_uppercase_hex_digits() -> None:
        """Column 1 of row 0 contains the address in 0x{addr:016X} format.

        Oracle: ``f"0x{0x00007FFE12345678:016X}"`` == ``"0x00007FFE12345678"``,
        independently computed from the documented format string.

        Mutation: using ``:08X`` padding → ``"0x12345678"`` ≠ expected →
        assertion fails.
        """
        table = StackFrameTable()
        frame = StackFrame(
            index=0,
            return_address=0x00007FFE_12345678,
            function_name="main",
            module_name="target.exe",
        )
        table.set_frames([frame])

        expected_addr = f"0x{0x00007FFE12345678:016X}"
        addr_item = table.item(0, 1)
        assert addr_item is not None, "address cell (row 0, col 1) is None"
        assert addr_item.text() == expected_addr, f"address: expected {expected_addr!r}, got {addr_item.text()!r}"

    @staticmethod
    def test_first_row_function_name_and_module_name_exact() -> None:
        """Columns 2 and 3 of row 0 hold the exact function and module names.

        Args: none (static; uses fixed frame data as independent oracle).

        Mutation: populating column 2 with module_name and column 3 with
        function_name (swapped) → function assertion fails.
        """
        table = StackFrameTable()
        frame = StackFrame(
            index=0,
            return_address=0x0000_0000_0040_1000,
            function_name="WinMain",
            module_name="crackme.exe",
        )
        table.set_frames([frame])

        func_item = table.item(0, 2)
        mod_item = table.item(0, 3)
        assert func_item is not None, "function cell (row 0, col 2) is None"
        assert mod_item is not None, "module cell (row 0, col 3) is None"
        assert func_item.text() == "WinMain", f"function: expected 'WinMain', got {func_item.text()!r}"
        assert mod_item.text() == "crackme.exe", f"module: expected 'crackme.exe', got {mod_item.text()!r}"

    @staticmethod
    def test_index_column_contains_string_representation_of_index() -> None:
        """Column 0 holds the frame index as a decimal string.

        Mutation: hardcoding column 0 to ``"#"`` → ``"0"`` ≠ ``"#"`` → fails.
        """
        table = StackFrameTable()
        frame = StackFrame(
            index=0,
            return_address=0x400000,
            function_name="entry",
            module_name="mod.exe",
        )
        table.set_frames([frame])

        idx_item = table.item(0, 0)
        assert idx_item is not None, "index cell (row 0, col 0) is None"
        assert idx_item.text() == "0", f"index column: expected '0', got {idx_item.text()!r}"


# ---------------------------------------------------------------------------
# Finding 49 (group-02): async_bridge.cancel_pending_main_loop_tasks
# ---------------------------------------------------------------------------


class TestCancelPendingMainLoopTasks:
    """Gate for cancel_pending_main_loop_tasks (group-02 finding 49).

    The existing idempotency test never schedules a real task, so calling
    cancel_pending_main_loop_tasks on an empty registry always returns 0.
    Removing the cancel loop or the task.cancel() call is not detected.
    """

    @staticmethod
    def test_cancels_tracked_task_and_reports_count() -> None:
        """A task in _pending.tasks is cancelled; function returns 1.

        Steps:
        1. Acquire the persistent bridge loop.
        2. Schedule asyncio.sleep(3600) as a task and add it to _pending.tasks.
        3. Call cancel_pending_main_loop_tasks().
        4. Pump the loop to deliver CancelledError to the sleeping coroutine.
        5. Assert task.cancelled() is True and the return value was 1.

        Mutation: removing ``task.cancel()`` inside the function → task stays
        pending → task.cancelled() is False → assertion fails.
        """
        loop: asyncio.AbstractEventLoop = _async_bridge_mod._ensure_loop()

        task_holder: list[asyncio.Task[object]] = []
        ready_event = threading.Event()

        def _create() -> None:
            t: asyncio.Task[object] = loop.create_task(asyncio.sleep(3_600))
            task_holder.append(t)
            ready_event.set()

        loop.call_soon_threadsafe(_create)
        assert ready_event.wait(timeout=5.0), "task creation on bridge loop timed out"

        task = task_holder[0]
        with _async_bridge_mod._pending.lock:
            _async_bridge_mod._pending.tasks.add(task)

        try:
            cancelled_count = cancel_pending_main_loop_tasks()
            assert cancelled_count >= 1, f"expected at least 1 cancellation, got {cancelled_count}"

            asyncio.run_coroutine_threadsafe(asyncio.sleep(0.1), loop).result(
                timeout=5.0,
            )

            assert task.done(), "task must be done after cancel + loop pump"
            assert task.cancelled(), "task.cancelled() must be True; cancel_pending_main_loop_tasks may have failed to call task.cancel()"
        finally:
            with _async_bridge_mod._pending.lock:
                _async_bridge_mod._pending.tasks.discard(task)
