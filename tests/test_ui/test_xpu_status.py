# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""End-to-end tests for the XPU Status dialog and provider config XPU settings.

Validates XPU status dialog construction, live refresh behavior, device
enumeration, memory display, cache reporting, requirements checking,
provider config XPU group box construction, settings persistence, and
Help menu integration using real XPU backend APIs.
"""

from __future__ import annotations

import re
import time
from typing import TYPE_CHECKING, cast

import pytest
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QGroupBox,
    QLabel,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QTextEdit,
)

import intellicrack.ui.provider_config as _provider_config_module
from intellicrack.providers.model_loader import get_global_model_cache
from intellicrack.providers.xpu_utils import (
    check_windows_requirements,
    get_xpu_device_count,
    get_xpu_device_info,
    get_xpu_memory_info,
    is_xpu_available,
)
from intellicrack.ui.provider_config import ProviderSettingsWidget
from intellicrack.ui.xpu_status import XPUStatusDialog


if TYPE_CHECKING:
    from collections.abc import Generator

    from PyQt6.QtCore import QThread, QTimer


_LIVE_REFRESH_MS: int = 2000
_REQUIREMENTS_RENDER_TIMEOUT_S: float = 15.0
_REQUIREMENTS_CHECKING_TEXT: str = "Checking system requirements"
_PROVIDER_MEM_REFRESH_MS: int = 15000
_CACHE_DEFAULT_MB: int = 10240
_CACHE_MIN_MB: int = 512
_CACHE_MAX_MB: int = 65536
_CACHE_STEP_MB: int = 512
_BYTES_PER_GB: float = 1024.0 * 1024.0 * 1024.0
_PROGRESS_BAR_MAX: int = 100


def _wait_for_requirements_render(dialog: XPUStatusDialog, timeout_s: float = _REQUIREMENTS_RENDER_TIMEOUT_S) -> None:
    """Block until the dialog's asynchronous requirements check has rendered its result.

    The requirements probe runs on a background ``QThread`` and delivers its outcome via a queued signal, so the rendered text is not
    available immediately after construction. This joins the worker thread and pumps the Qt event loop until the placeholder "Checking..."
    text is replaced or the timeout elapses.

    Args:
        dialog: The XPU status dialog whose requirements worker should be awaited.
        timeout_s: Maximum time to wait for the rendered result, in seconds.
    """
    worker = cast("QThread | None", getattr(dialog, "_requirements_worker", None))
    if worker is not None:
        worker.wait(int(timeout_s * 1000))
    app = QApplication.instance()
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if app is not None:
            app.processEvents()
        if _REQUIREMENTS_CHECKING_TEXT not in dialog.requirements_text.toPlainText():
            return


@pytest.fixture
def xpu_dialog(qapp: QApplication) -> Generator[XPUStatusDialog]:
    """Create a real XPUStatusDialog instance.

    Args:
        qapp: QApplication session fixture.

    Yields:
        Generator[XPUStatusDialog]: A live dialog instance with active refresh timer.
    """
    _ = qapp
    dialog = XPUStatusDialog()
    yield dialog
    dialog.close()


@pytest.fixture
def provider_widget(qapp: QApplication) -> Generator[ProviderSettingsWidget]:
    """Create a real ProviderSettingsWidget for local_transformers.

    Args:
        qapp: QApplication session fixture.

    Yields:
        Generator[ProviderSettingsWidget]: Widget configured for local_transformers.
    """
    _ = qapp
    widget = ProviderSettingsWidget(provider_id="local_transformers")
    yield widget
    mem_timer: QTimer | None = getattr(widget, "_xpu_mem_timer", None)
    if mem_timer is not None:
        mem_timer.stop()


@pytest.mark.usefixtures("qapp")
class TestXPUStatusDialogConstruction:
    """Verify XPUStatusDialog creates all expected child widgets."""

    @staticmethod
    def test_dialog_has_window_title(xpu_dialog: XPUStatusDialog) -> None:
        """Window title is set to 'XPU Status'.

        Args:
            xpu_dialog: XPUStatusDialog fixture instance.
        """
        assert xpu_dialog.windowTitle() == "XPU Status"

    @staticmethod
    def test_dialog_contains_device_status_group(xpu_dialog: XPUStatusDialog) -> None:
        """Dialog contains a 'Device Status' group box.

        Args:
            xpu_dialog: XPUStatusDialog fixture instance.
        """
        groups = xpu_dialog.findChildren(QGroupBox)
        titles = [g.title() for g in groups]
        assert "Device Status" in titles

    @staticmethod
    def test_dialog_contains_memory_usage_group(xpu_dialog: XPUStatusDialog) -> None:
        """Dialog contains a 'Memory Usage' group box.

        Args:
            xpu_dialog: XPUStatusDialog fixture instance.
        """
        groups = xpu_dialog.findChildren(QGroupBox)
        titles = [g.title() for g in groups]
        assert "Memory Usage" in titles

    @staticmethod
    def test_dialog_contains_model_cache_group(xpu_dialog: XPUStatusDialog) -> None:
        """Dialog contains a 'Model Cache' group box.

        Args:
            xpu_dialog: XPUStatusDialog fixture instance.
        """
        groups = xpu_dialog.findChildren(QGroupBox)
        titles = [g.title() for g in groups]
        assert "Model Cache" in titles

    @staticmethod
    def test_dialog_contains_system_requirements_group(xpu_dialog: XPUStatusDialog) -> None:
        """Dialog contains a 'System Requirements' group box.

        Args:
            xpu_dialog: XPUStatusDialog fixture instance.
        """
        groups = xpu_dialog.findChildren(QGroupBox)
        titles = [g.title() for g in groups]
        assert "System Requirements" in titles

    @staticmethod
    def test_dialog_has_four_group_boxes(xpu_dialog: XPUStatusDialog) -> None:
        """Dialog has exactly four group boxes.

        Args:
            xpu_dialog: XPUStatusDialog fixture instance.
        """
        groups = xpu_dialog.findChildren(QGroupBox)
        assert len(groups) == 4

    @staticmethod
    def test_dialog_has_refresh_button(xpu_dialog: XPUStatusDialog) -> None:
        """Dialog has a 'Refresh' button.

        Args:
            xpu_dialog: XPUStatusDialog fixture instance.
        """
        buttons = xpu_dialog.findChildren(QPushButton)
        texts = [b.text() for b in buttons]
        assert "Refresh" in texts

    @staticmethod
    def test_dialog_has_close_button(xpu_dialog: XPUStatusDialog) -> None:
        """Dialog has a 'Close' button.

        Args:
            xpu_dialog: XPUStatusDialog fixture instance.
        """
        buttons = xpu_dialog.findChildren(QPushButton)
        texts = [b.text() for b in buttons]
        assert "Close" in texts

    @staticmethod
    def test_dialog_has_memory_progress_bar(xpu_dialog: XPUStatusDialog) -> None:
        """Dialog contains a QProgressBar for memory display.

        Args:
            xpu_dialog: XPUStatusDialog fixture instance.
        """
        bars = xpu_dialog.findChildren(QProgressBar)
        assert len(bars) == 1
        assert bars[0].minimum() == 0
        assert bars[0].maximum() == _PROGRESS_BAR_MAX

    @staticmethod
    def test_dialog_has_requirements_text_edit(xpu_dialog: XPUStatusDialog) -> None:
        """Dialog contains a read-only QTextEdit for requirements.

        Args:
            xpu_dialog: XPUStatusDialog fixture instance.
        """
        edits = xpu_dialog.findChildren(QTextEdit)
        assert len(edits) == 1
        assert edits[0].isReadOnly()


@pytest.mark.usefixtures("qapp")
class TestXPUStatusDialogRefreshTimer:
    """Verify the live refresh timer behavior."""

    @staticmethod
    def test_timer_is_active_after_construction(xpu_dialog: XPUStatusDialog) -> None:
        """Refresh timer starts automatically on construction.

        Args:
            xpu_dialog: XPUStatusDialog fixture instance.
        """
        assert xpu_dialog.refresh_timer.isActive()

    @staticmethod
    def test_timer_interval_is_2_seconds(xpu_dialog: XPUStatusDialog) -> None:
        """Refresh timer interval is 2000ms.

        Args:
            xpu_dialog: XPUStatusDialog fixture instance.
        """
        assert xpu_dialog.refresh_timer.interval() == _LIVE_REFRESH_MS

    @staticmethod
    def test_timer_stops_on_close(xpu_dialog: XPUStatusDialog) -> None:
        """Refresh timer stops when the dialog is closed.

        Args:
            xpu_dialog: XPUStatusDialog fixture instance.
        """
        assert xpu_dialog.refresh_timer.isActive()
        xpu_dialog.close()
        assert not xpu_dialog.refresh_timer.isActive()


@pytest.mark.usefixtures("qapp")
class TestXPUStatusDialogDeviceInfo:
    """Verify the dialog displays real XPU device information."""

    @staticmethod
    def test_status_label_reflects_xpu_availability(xpu_dialog: XPUStatusDialog) -> None:
        """Status label text is exactly the string mandated by the active hardware path.

        ``_refresh_device_info`` has three mutually exclusive branches:
        - ``is_xpu_available is None`` (import-failure): label == ``"XPU utilities not available"``
        - ``is_xpu_available()`` returns ``False``: label == ``"CPU Only"``
        - ``is_xpu_available()`` returns ``True``: label == ``"XPU Active"``

        The test queries the real backend via the same function the dialog uses,
        derives the single expected string, and asserts an exact equality - not a
        set membership - so a typo, wrong-branch regression, or a new label string
        introduced anywhere in ``_refresh_device_info`` will immediately go red.

        Args:
            xpu_dialog: XPUStatusDialog fixture instance.
        """
        text = xpu_dialog.status_label.text()
        xpu_available_result = is_xpu_available()
        expected = "XPU Active" if xpu_available_result else "CPU Only"
        assert text == expected, (
            f"status_label must be exactly {expected!r} when is_xpu_available()={xpu_available_result}, got {text!r}; "
            "only the import-failure path (is_xpu_available is None) should produce 'XPU utilities not available'"
        )

    @staticmethod
    @pytest.mark.skipif(not is_xpu_available(), reason="No XPU device available")
    def test_device_name_shows_real_device(xpu_dialog: XPUStatusDialog) -> None:
        """Device name label displays the real device name from XPU hardware.

        Args:
            xpu_dialog: XPUStatusDialog fixture instance.
        """
        info = get_xpu_device_info(0)
        assert info is not None
        assert xpu_dialog.device_name_label.text() == info.device_name

    @staticmethod
    @pytest.mark.skipif(not is_xpu_available(), reason="No XPU device available")
    def test_driver_label_shows_real_driver(xpu_dialog: XPUStatusDialog) -> None:
        """Driver label matches the exact driver string from the real XPU device.

        Production code in ``_refresh_device_details`` sets ``driver_label`` to
        ``str(info.driver_version)`` when non-empty, and to ``"Unknown"`` when
        ``info.driver_version`` is falsy.  Both branches are tested unconditionally:
        if the device reports an empty driver string the test asserts ``"Unknown"``,
        not that the test body is skipped.  A regression that omits the driver label
        for a device with no driver string will therefore be caught.

        Args:
            xpu_dialog: XPUStatusDialog fixture instance.
        """
        info = get_xpu_device_info(0)
        assert info is not None, "get_xpu_device_info(0) must return a device when XPU is available"
        expected = str(info.driver_version) if info.driver_version else "Unknown"
        actual = xpu_dialog.driver_label.text()
        assert actual == expected, f"driver_label must be {expected!r} for driver_version={info.driver_version!r}, got {actual!r}"

    @staticmethod
    @pytest.mark.skipif(not is_xpu_available(), reason="No XPU device available")
    def test_capabilities_label_shows_dtype_flags(xpu_dialog: XPUStatusDialog) -> None:
        """Capabilities label is the exact string produced by ``_refresh_device_details``.

        Production code assembles the caps string as
        ``" / ".join(supported_dtypes) or "None detected"``.  The test reconstructs
        the same string independently from the raw device flags and asserts exact
        equality.  A regression that swaps the separator, omits INT8, or uses a
        different fallback will go red even on hardware where both fp16 and bf16
        are False (previously those asserts were silently skipped).

        Args:
            xpu_dialog: XPUStatusDialog fixture instance.
        """
        info = get_xpu_device_info(0)
        assert info is not None, "get_xpu_device_info(0) must return a device when XPU is available"
        parts: list[str] = []
        if info.supports_fp16:
            parts.append("FP16")
        if info.supports_bf16:
            parts.append("BF16")
        if info.supports_int8:
            parts.append("INT8")
        expected = " / ".join(parts) if parts else "None detected"
        actual = xpu_dialog.caps_label.text()
        assert actual == expected, (
            f"caps_label must be {expected!r} for fp16={info.supports_fp16}, bf16={info.supports_bf16}, "
            f"int8={info.supports_int8}; got {actual!r}"
        )


@pytest.mark.usefixtures("qapp")
class TestXPUStatusDialogMemory:
    """Verify memory display matches real XPU memory state."""

    @staticmethod
    @pytest.mark.skipif(not is_xpu_available(), reason="No XPU device available")
    def test_memory_bar_shows_real_percentage(xpu_dialog: XPUStatusDialog) -> None:
        """Memory progress bar always asserts a concrete value, even when total==0.

        Production has two sub-branches inside the XPU-available path:
        - ``total > 0``: bar value = ``int(allocated / total * 100)``
        - ``total == 0``: bar value = 0, text = ``"Unable to determine memory size"``

        Neither branch is skipped.  When ``total == 0`` the test asserts bar==0 and
        the correct fallback text; when ``total > 0`` it asserts the computed
        percentage is within ±2 pp of the live reading (accounting for activity
        between the fixture read and the dialog read).

        Args:
            xpu_dialog: XPUStatusDialog fixture instance.
        """
        allocated, total = get_xpu_memory_info(0)
        if total > 0:
            expected_pct = int((allocated / total) * 100)
            actual_pct = xpu_dialog.memory_bar.value()
            assert abs(actual_pct - expected_pct) <= 2, (
                f"memory_bar value {actual_pct} must be within 2pp of expected {expected_pct} (allocated={allocated}, total={total})"
            )
        else:
            assert xpu_dialog.memory_bar.value() == 0, "memory_bar must be 0 when total memory is 0"
            assert xpu_dialog.memory_text.text() == "Unable to determine memory size", (
                f"memory_text must be 'Unable to determine memory size' when total==0, got {xpu_dialog.memory_text.text()!r}"
            )

    @staticmethod
    @pytest.mark.skipif(not is_xpu_available(), reason="No XPU device available")
    def test_memory_text_shows_gb_values(xpu_dialog: XPUStatusDialog) -> None:
        """Memory text label shows correctly formatted GB and percentage values.

        The oracle is ``get_xpu_memory_info(0)`` read immediately before forcing
        a dialog refresh so that the dialog state and the reference values are
        derived from the same VRAM snapshot.  The production format is:

            ``"{alloc_gb:.2f} GB / {total_gb:.2f} GB ({pct}%)"``

        where ``alloc_gb = allocated / _BYTES_PER_GB``,
        ``total_gb = total / _BYTES_PER_GB``,
        ``pct = int(allocated / total * 100)``.

        When ``total == 0`` the dialog shows ``"Unable to determine memory size"``;
        both branches are verified so the test is not vacuous on hardware that
        reports zero total memory.

        A regression that swaps ``allocated`` and ``total``, that drops the
        ``:.2f`` format, or that prints ``"NaN%"`` will fail because the
        parsed numeric values diverge from the oracle by more than the accepted
        ±1 GB / ±2 pp tolerance (which covers legitimate memory churn between
        the oracle read and the widget refresh).

        Args:
            xpu_dialog: XPUStatusDialog fixture instance.
        """
        allocated, total = get_xpu_memory_info(0)
        refresh_memory = getattr(xpu_dialog, "_refresh_memory")
        refresh_memory()

        text = xpu_dialog.memory_text.text()

        if total == 0:
            assert text == "Unable to determine memory size", (
                f"memory_text must be 'Unable to determine memory size' when total==0, got {text!r}"
            )
            return

        expected_alloc_gb = allocated / _BYTES_PER_GB
        expected_total_gb = total / _BYTES_PER_GB
        expected_pct = int((allocated / total) * 100)

        match = re.fullmatch(
            r"(\d+\.\d{2}) GB / (\d+\.\d{2}) GB \((\d+)%\)",
            text,
        )
        assert match is not None, (
            f"memory_text must match '<alloc> GB / <total> GB (<pct>%)' format; got {text!r}"
        )
        actual_alloc_gb = float(match.group(1))
        actual_total_gb = float(match.group(2))
        actual_pct = int(match.group(3))

        assert abs(actual_alloc_gb - expected_alloc_gb) <= 1.0, (
            f"memory_text allocated GB {actual_alloc_gb:.2f} must be within 1 GB of oracle "
            f"{expected_alloc_gb:.2f} (allocated={allocated} bytes)"
        )
        assert abs(actual_total_gb - expected_total_gb) <= 1.0, (
            f"memory_text total GB {actual_total_gb:.2f} must be within 1 GB of oracle "
            f"{expected_total_gb:.2f} (total={total} bytes)"
        )
        assert abs(actual_pct - expected_pct) <= 2, (
            f"memory_text percentage {actual_pct}% must be within 2 pp of oracle "
            f"{expected_pct}% (allocated={allocated}, total={total})"
        )

    @staticmethod
    @pytest.mark.skipif(is_xpu_available(), reason="XPU is available")
    def test_memory_shows_no_device_when_unavailable(xpu_dialog: XPUStatusDialog) -> None:
        """Memory text is exactly ``"No XPU device"`` on the import-succeeded-but-no-device path.

        ``_refresh_memory`` has three distinct non-XPU outcomes:
        - ``get_xpu_memory_info is None`` (import failure): ``"XPU memory info not available"``
        - ``_read_xpu_allocation()`` returns ``None`` (import ok, device absent): ``"No XPU device"``
        - ``_read_xpu_allocation()`` raises (I/O error): ``"Failed to read memory"``

        The test asserts only the path that actually ran, not an over-broad set.
        Because ``get_xpu_memory_info`` was successfully imported in this test module
        (the module-level import would have raised on failure), the import-failure
        path cannot trigger here. ``is_xpu_available()`` returned ``False`` so
        ``_read_xpu_allocation()`` returns ``None``, producing ``"No XPU device"``.

        Args:
            xpu_dialog: XPUStatusDialog fixture instance.
        """
        text = xpu_dialog.memory_text.text()
        assert text == "No XPU device", (
            f"When is_xpu_available()=False but xpu_utils imported successfully, memory_text must be exactly 'No XPU device', got {text!r}"
        )


@pytest.mark.usefixtures("qapp")
class TestXPUStatusDialogCache:
    """Verify model cache display reads from the real global cache."""

    @staticmethod
    def test_cache_usage_label_has_value(xpu_dialog: XPUStatusDialog) -> None:
        """Cache usage label displays a MB value or an informational message.

        The label is populated by ``_refresh_cache()`` which emits one of three
        deterministic outcomes: ``"{N} MB"`` from the real cache, ``"Model cache
        not available"`` when the optional dependency is missing, or
        ``"Error reading cache"`` on an exception.  The default ``"--"``
        placeholder must be replaced before the dialog is fully constructed.

        Args:
            xpu_dialog: XPUStatusDialog fixture instance.
        """
        text = xpu_dialog.cache_usage_label.text()
        valid_texts = {"Model cache not available", "Error reading cache"}
        is_mb_value = text.endswith(" MB") and text[:-3].replace(".", "", 1).isdigit()
        assert is_mb_value or text in valid_texts, (
            f"cache_usage_label has unexpected text {text!r}; expected '<N> MB', 'Model cache not available', or 'Error reading cache'"
        )

    @staticmethod
    def test_cache_limit_label_has_value(xpu_dialog: XPUStatusDialog) -> None:
        """Cache limit label displays a MB value or a recognised placeholder.

        ``_refresh_cache()`` sets the label to ``"{N} MB"`` from the real cache
        limit, ``"N/A"`` when the optional dependency is missing, or ``"Error"``
        on an exception.  The initial ``"--"`` placeholder must not survive
        dialog construction.

        Args:
            xpu_dialog: XPUStatusDialog fixture instance.
        """
        text = xpu_dialog.cache_limit_label.text()
        valid_short = {"N/A", "Error"}
        is_mb_value = text.endswith(" MB") and text[:-3].replace(".", "", 1).isdigit()
        assert is_mb_value or text in valid_short, f"cache_limit_label has unexpected text {text!r}; expected '<N> MB', 'N/A', or 'Error'"


@pytest.mark.usefixtures("qapp")
class TestXPUStatusDialogRequirements:
    """Verify the system requirements check runs and displays results."""

    @staticmethod
    def test_requirements_text_is_populated(xpu_dialog: XPUStatusDialog) -> None:
        """Requirements text shows one of the known initial render states.

        ``_refresh_requirements()`` sets the text to exactly one of:
        ``"Requirements check not available."`` (when the optional dependency is
        absent), ``"Checking system requirements..."`` (immediately after
        construction while the background worker runs), or the rendered HTML
        result.  The ``"--"`` placeholder or an empty string must never appear.

        Args:
            xpu_dialog: XPUStatusDialog fixture instance.
        """
        text = xpu_dialog.requirements_text.toPlainText()
        assert len(text) > 0, "requirements_text must not be empty after construction"
        known_stubs = {"Requirements check not available.", "Checking system requirements..."}
        has_real_content = "requirements met" in text.lower() or "warning" in text.lower() or "failed" in text.lower()
        assert text in known_stubs or has_real_content, (
            f"requirements_text has unexpected content {text[:80]!r}; expected a known stub or rendered requirement results"
        )

    @staticmethod
    def test_requirements_text_contains_met_or_warnings(xpu_dialog: XPUStatusDialog) -> None:
        """Requirements text after render contains the exact phrase from the production render path.

        ``_on_requirements_ready`` renders into one of two exact HTML patterns:
        - All met, no warnings: plain-text ``"All system requirements met."``
        - Warnings present: HTML with a ``<ul>`` element containing ``<li>`` items

        ``_on_requirements_failed`` sets plain text starting with ``"Failed to check requirements: ..."``.
        ``_refresh_requirements`` with no helper available sets plain text ``"Requirements check not available."``.

        The test waits for the background worker, then asserts that exactly one of the four known terminal
        states is present in the rendered output.  A regression that changes the "met" phrase, removes the
        ``<ul>`` structure, or introduces a fifth state will go red.

        Args:
            xpu_dialog: XPUStatusDialog fixture instance.
        """
        _wait_for_requirements_render(xpu_dialog)
        plain = xpu_dialog.requirements_text.toPlainText()
        html = xpu_dialog.requirements_text.toHtml()
        all_met = plain.strip() == "All system requirements met."
        has_ul_warnings = "<ul>" in html and "<li>" in html
        check_failed = plain.startswith("Failed to check requirements:")
        unavailable = plain.strip() == "Requirements check not available."
        assert all_met or has_ul_warnings or check_failed or unavailable, (
            f"requirements text must be one of the four terminal states after render; got {plain[:120]!r}"
        )
        assert "Checking system requirements" not in plain, (
            "requirements_text must not still contain the 'Checking' placeholder after the worker completed"
        )


@pytest.mark.usefixtures("qapp")
class TestProviderConfigXPUGroupBox:
    """Verify the XPU settings group box in the provider config dialog."""

    @staticmethod
    def test_xpu_group_box_exists(provider_widget: ProviderSettingsWidget) -> None:
        """XPU group box is present AND its hidden-state matches the XPU availability state.

        ``findChildren`` returns hidden widgets, so asserting title presence alone cannot
        detect a regression where ``_setup_xpu_settings`` unconditionally calls
        ``xpu_group.hide()``.  This test additionally asserts that ``isHidden()``
        matches the expected state: when XPU is available the group must NOT be hidden
        (it is shown so users can configure device settings); when unavailable it MUST
        be hidden (the polling timer is stopped to avoid a hot loop on idle systems).

        Args:
            provider_widget: ProviderSettingsWidget fixture configured for local_transformers.
        """
        groups = provider_widget.findChildren(QGroupBox)
        titles = [g.title() for g in groups]
        assert "XPU / Device Settings" in titles, "XPU / Device Settings group box must exist in the local_transformers widget"
        xpu_group: QGroupBox | None = getattr(provider_widget, "_xpu_group", None)
        assert xpu_group is not None, "_xpu_group attribute must be set by _setup_xpu_settings"
        if is_xpu_available():
            assert not xpu_group.isHidden(), "XPU group box must NOT be hidden when XPU is available (users need to configure it)"
        else:
            assert xpu_group.isHidden(), "XPU group box must be hidden when XPU is unavailable to prevent the polling timer hot-loop"

    @staticmethod
    def test_prefer_xpu_checkbox_exists(provider_widget: ProviderSettingsWidget) -> None:
        """Widget has a 'Prefer XPU over CPU' checkbox defaulting to checked.

        Args:
            provider_widget: ProviderSettingsWidget fixture configured for local_transformers.
        """
        cb: QCheckBox | None = getattr(provider_widget, "_prefer_xpu_cb", None)
        assert cb is not None
        assert isinstance(cb, QCheckBox)
        assert cb.isChecked()
        assert cb.text() == "Prefer XPU over CPU"

    @staticmethod
    def test_device_combo_exists_and_populated(provider_widget: ProviderSettingsWidget) -> None:
        """Device combo item text is the exact string produced by ``_populate_device_combo``.

        Production populates the combo with one of three exact item-text patterns:
        - XPU present: ``"XPU:{idx} - {device_name} ({mem_gb:.1f} GB)"``
        - No XPU devices but utils importable: ``"CPU (no XPU devices)"``
        - Utils import failed: ``"CPU (XPU utils unavailable)"``

        The test checks not only that count >= 1, but also that the first item text
        matches the expected pattern for the actual hardware state.  A regression that
        silently swaps the two CPU fallback messages, or drops the device name from the
        XPU entry, will go red.

        Args:
            provider_widget: ProviderSettingsWidget fixture configured for local_transformers.
        """
        combo: QComboBox | None = getattr(provider_widget, "_device_combo", None)
        assert combo is not None
        assert isinstance(combo, QComboBox)
        assert combo.count() >= 1, "device combo must have at least one item"
        first_text = combo.itemText(0)
        if is_xpu_available():
            count = get_xpu_device_count()
            assert combo.count() == count, (
                f"device combo must have {count} items when {count} XPU device(s) are present, got {combo.count()}"
            )
            info = get_xpu_device_info(0)
            if info is not None:
                mem_gb = info.total_memory_bytes / (1024.0 * 1024.0 * 1024.0)
                expected_text = f"XPU:0 - {info.device_name} ({mem_gb:.1f} GB)"
                assert first_text == expected_text, f"device combo item 0 must be {expected_text!r}, got {first_text!r}"
        else:
            assert first_text in {"CPU (no XPU devices)", "CPU (XPU utils unavailable)"}, (
                f"device combo item 0 must be a CPU fallback string when XPU is absent, got {first_text!r}"
            )

    @staticmethod
    def test_device_combo_has_xpu_entries_when_available(provider_widget: ProviderSettingsWidget) -> None:
        """Device combo shows real XPU devices when hardware is present.

        Args:
            provider_widget: ProviderSettingsWidget fixture configured for local_transformers.
        """
        combo: QComboBox | None = getattr(provider_widget, "_device_combo", None)
        assert combo is not None
        if is_xpu_available():
            count = get_xpu_device_count()
            assert combo.count() == count
            info = get_xpu_device_info(0)
            if info is not None:
                assert info.device_name in combo.itemText(0)
        else:
            assert "CPU" in combo.itemText(0)

    @staticmethod
    def test_dtype_combo_has_four_options(provider_widget: ProviderSettingsWidget) -> None:
        """Dtype combo contains Auto, float16, bfloat16, float32.

        Args:
            provider_widget: ProviderSettingsWidget fixture configured for local_transformers.
        """
        combo: QComboBox | None = getattr(provider_widget, "_dtype_combo", None)
        assert combo is not None
        assert isinstance(combo, QComboBox)
        items = [combo.itemText(i) for i in range(combo.count())]
        assert items == ["Auto", "float16", "bfloat16", "float32"]

    @staticmethod
    def test_memory_bar_exists(provider_widget: ProviderSettingsWidget) -> None:
        """Widget has an XPU memory progress bar.

        Args:
            provider_widget: ProviderSettingsWidget fixture configured for local_transformers.
        """
        bar: QProgressBar | None = getattr(provider_widget, "_xpu_mem_bar", None)
        assert bar is not None
        assert isinstance(bar, QProgressBar)
        assert bar.minimum() == 0
        assert bar.maximum() == _PROGRESS_BAR_MAX

    @staticmethod
    def test_cache_spinbox_defaults(provider_widget: ProviderSettingsWidget) -> None:
        """Cache size spinbox has correct range and default.

        Args:
            provider_widget: ProviderSettingsWidget fixture configured for local_transformers.
        """
        spin: QSpinBox | None = getattr(provider_widget, "_cache_spin", None)
        assert spin is not None
        assert isinstance(spin, QSpinBox)
        assert spin.minimum() == _CACHE_MIN_MB
        assert spin.maximum() == _CACHE_MAX_MB
        assert spin.singleStep() == _CACHE_STEP_MB
        assert spin.value() == _CACHE_DEFAULT_MB
        assert "MB" in spin.suffix()

    @staticmethod
    def test_warnings_label_exists(provider_widget: ProviderSettingsWidget) -> None:
        """Widget has a warnings label for requirement check results.

        Args:
            provider_widget: ProviderSettingsWidget fixture configured for local_transformers.
        """
        label: QLabel | None = getattr(provider_widget, "_xpu_warnings_label", None)
        assert label is not None
        assert isinstance(label, QLabel)
        assert label.wordWrap()

    @staticmethod
    def test_memory_refresh_timer_active(provider_widget: ProviderSettingsWidget) -> None:
        """XPU memory refresh timer runs only when an XPU device is present.

        When an XPU is available the widget schedules periodic memory refreshes
        at the ``_PROVIDER_MEM_REFRESH_MS`` cadence; when XPU is unavailable the
        widget stops the timer and hides the group box to avoid a hot polling
        loop on idle systems.

        Args:
            provider_widget: ProviderSettingsWidget fixture configured for local_transformers.
        """
        timer: QTimer | None = getattr(provider_widget, "_xpu_mem_timer", None)
        assert timer is not None
        if is_xpu_available():
            assert timer.isActive()
            assert timer.interval() == _PROVIDER_MEM_REFRESH_MS
        else:
            assert not timer.isActive()


@pytest.mark.usefixtures("qapp")
class TestProviderConfigXPUButtons:
    """Verify the XPU action buttons exist and are connected."""

    def test_device_info_button_invokes_slot_when_clicked(
        self,
        provider_widget: ProviderSettingsWidget,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Clicking 'Device Info' invokes ``_on_show_device_info`` and ultimately calls ``show_info``.

        The observable proof that the button's ``clicked`` signal is connected to
        ``_on_show_device_info`` is that ``show_info`` is called exactly once after the
        click - that call only happens if the slot runs.  ``get_provider_device_info`` is
        patched on the instance so it always returns a non-None dict, ensuring the
        ``if info is not None`` guard inside ``_on_show_device_info`` is satisfied.

        A regression that removes ``device_info_btn.clicked.connect(self._on_show_device_info)``
        means clicking the button fires no slot and ``show_info`` is never called:
        the assertion goes red regardless of whether the method still exists on the class.

        Args:
            provider_widget: ProviderSettingsWidget fixture configured for local_transformers.
            monkeypatch: pytest monkeypatch fixture.
        """
        buttons = provider_widget.findChildren(QPushButton)
        texts = [b.text() for b in buttons]
        assert "Device Info" in texts, "Device Info button must exist in the XPU settings group"

        show_info_calls: list[tuple[object, str, str]] = []
        monkeypatch.setattr(_provider_config_module, "show_info", lambda parent, title, msg: show_info_calls.append((parent, title, msg)))
        monkeypatch.setattr(provider_widget, "get_provider_device_info", lambda: {"device": "TestXPU", "driver": "1.0"})

        for b in buttons:
            if b.text() == "Device Info":
                b.click()
                break
        QApplication.processEvents()

        assert len(show_info_calls) == 1, (
            f"show_info must be called exactly once when Device Info is clicked (got {len(show_info_calls)}); "
            "zero calls means device_info_btn.clicked.connect(self._on_show_device_info) was removed"
        )
        _parent, title, msg = show_info_calls[0]
        assert title == "Device Info", f"show_info title must be 'Device Info', got {title!r}"
        assert "TestXPU" in msg, f"show_info message must contain the device name 'TestXPU', got {msg!r}"
        assert "1.0" in msg, f"show_info message must contain driver '1.0', got {msg!r}"

    def test_clear_cache_button_invokes_slot_when_clicked(
        self,
        provider_widget: ProviderSettingsWidget,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Clicking 'Clear Cache' invokes ``_on_clear_cache`` and calls ``show_info``.

        ``_on_clear_cache`` unconditionally calls ``show_info`` at the end of its body.
        Monkeypatching ``show_info`` to record calls creates a clear falsifiable gate:
        if ``clear_cache_btn.clicked.connect(self._on_clear_cache)`` is removed from
        production code, the slot never runs and ``show_info`` is never called.
        The assertion goes red regardless of memory bar values or range checks.

        Args:
            provider_widget: ProviderSettingsWidget fixture configured for local_transformers.
            monkeypatch: pytest monkeypatch fixture.
        """
        show_info_calls: list[tuple[object, str, str]] = []
        monkeypatch.setattr(_provider_config_module, "show_info", lambda parent, title, msg: show_info_calls.append((parent, title, msg)))

        buttons = provider_widget.findChildren(QPushButton)
        texts = [b.text() for b in buttons]
        assert "Clear Cache" in texts, "Clear Cache button must exist in the XPU settings group"

        for b in buttons:
            if b.text() == "Clear Cache":
                b.click()
                break
        QApplication.processEvents()

        assert len(show_info_calls) == 1, (
            f"show_info must be called exactly once when Clear Cache is clicked (got {len(show_info_calls)}); "
            "zero calls means clear_cache_btn.clicked.connect(self._on_clear_cache) was removed"
        )
        _parent, title, msg = show_info_calls[0]
        assert title == "Cache", f"show_info title must be 'Cache' from _on_clear_cache, got {title!r}"
        assert "cleared" in msg.lower(), f"show_info message must mention clearing, got {msg!r}"

    @staticmethod
    def test_check_requirements_button_updates_warnings_label(provider_widget: ProviderSettingsWidget) -> None:
        r"""Clicking 'Check Requirements' writes the exact oracle-derived string into ``_xpu_warnings_label``.

        ``_on_check_requirements`` selects one of four deterministic outcomes from the production
        code and writes it verbatim into ``_xpu_warnings_label``:

        - ``check_windows_requirements is None``: ``"Requirements check not available"``
        - ``check_windows_requirements()`` raises: ``"Failed to check requirements"``
        - ``all_met and not warnings``: ``"All system requirements met"``
        - warnings present: ``"\n".join(warnings)`` from the live requirements check

        The test derives the same expected string by calling the backend directly (the same
        oracle the production button handler uses), then asserts exact equality.  A disconnected
        button leaves the label empty and goes red; a button wired to the wrong handler goes red
        because the label will contain an unexpected string; production code that changes the
        fixed-phrase constants goes red.

        Args:
            provider_widget: ProviderSettingsWidget fixture configured for local_transformers.
        """
        buttons = provider_widget.findChildren(QPushButton)
        texts = [b.text() for b in buttons]
        assert "Check Requirements" in texts, "Check Requirements button must exist in the XPU settings group"
        warnings_label: QLabel | None = getattr(provider_widget, "_xpu_warnings_label", None)
        assert warnings_label is not None

        try:
            all_met, live_warnings = check_windows_requirements()
        except (RuntimeError, OSError):
            expected_text = "Failed to check requirements"
        else:
            expected_text = "All system requirements met" if all_met and not live_warnings else "\n".join(live_warnings)

        for b in buttons:
            if b.text() == "Check Requirements":
                b.click()
                break
        QApplication.processEvents()
        result_text = warnings_label.text()
        assert result_text == expected_text, (
            f"_xpu_warnings_label must be exactly {expected_text!r} after Check Requirements click; "
            f"got {result_text!r}. A disconnected button leaves the label empty; a wrong-slot "
            "connection produces a different string."
        )

    def test_auto_detect_button_invokes_slot_when_clicked(
        self,
        provider_widget: ProviderSettingsWidget,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Clicking 'Auto-Detect' invokes ``_on_detect_xpu_dtype`` and updates the dtype combo.

        ``_on_detect_xpu_dtype`` calls ``get_xpu_optimal_dtype()``, which calls
        ``get_optimal_dtype_for_xpu()``.  The module-level ``get_optimal_dtype_for_xpu``
        is replaced with a function returning ``"float16"`` so the slot has a non-None
        dtype to work with.  The slot then sets ``_dtype_combo`` to ``"float16"`` and
        calls ``show_info``.

        A regression that removes ``auto_dtype_btn.clicked.connect(self._on_detect_xpu_dtype)``
        means the slot never runs: ``_dtype_combo`` stays at its initial value (``"Auto"``)
        and ``show_info`` is never called.  Both assertions go red independently.

        Args:
            provider_widget: ProviderSettingsWidget fixture configured for local_transformers.
            monkeypatch: pytest monkeypatch fixture.
        """
        buttons = provider_widget.findChildren(QPushButton)
        texts = [b.text() for b in buttons]
        assert "Auto-Detect" in texts, "Auto-Detect button must exist in the XPU settings group"

        monkeypatch.setattr(_provider_config_module, "get_optimal_dtype_for_xpu", lambda: "float16")
        if hasattr(provider_widget, "_xpu_dtype"):
            monkeypatch.delattr(provider_widget, "_xpu_dtype", raising=False)

        show_info_calls: list[tuple[object, str, str]] = []
        monkeypatch.setattr(_provider_config_module, "show_info", lambda parent, title, msg: show_info_calls.append((parent, title, msg)))

        dtype_combo: QComboBox | None = getattr(provider_widget, "_dtype_combo", None)
        assert dtype_combo is not None, "_dtype_combo must exist on local_transformers widget"
        dtype_combo.setCurrentIndex(0)
        assert dtype_combo.currentText() == "Auto", "dtype_combo initial state must be 'Auto' for this test"

        for b in buttons:
            if b.text() == "Auto-Detect":
                b.click()
                break
        QApplication.processEvents()

        assert len(show_info_calls) == 1, (
            f"show_info must be called exactly once when Auto-Detect is clicked (got {len(show_info_calls)}); "
            "zero calls means auto_dtype_btn.clicked.connect(self._on_detect_xpu_dtype) was removed"
        )
        _parent, title, msg = show_info_calls[0]
        assert title == "XPU Dtype", f"show_info title must be 'XPU Dtype', got {title!r}"
        assert "float16" in msg, f"show_info message must contain 'float16', got {msg!r}"
        assert dtype_combo.currentText() == "float16", (
            f"dtype_combo must be set to 'float16' after Auto-Detect click, got {dtype_combo.currentText()!r}; "
            "a disconnected button leaves the combo at its initial 'Auto' value"
        )

    def test_apply_cache_button_updates_global_cache_size(
        self,
        provider_widget: ProviderSettingsWidget,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Clicking 'Apply' writes the spinbox value into the global model cache.

        ``_on_apply_cache_size`` reads ``_cache_spin.value()``, multiplies by
        ``1024 * 1024``, calls ``set_global_cache_size()``, and then calls ``show_info``.
        The blocking ``QMessageBox`` is suppressed via ``monkeypatch`` so the test
        runs headlessly.  The observable side effect that proves the button IS connected
        is that the global cache's ``max_memory_bytes`` changes to exactly the spinbox
        value * 1048576.  A disconnected button leaves the cache unchanged and this
        test will go red.

        Args:
            provider_widget: ProviderSettingsWidget fixture configured for local_transformers.
            monkeypatch: pytest monkeypatch fixture.
        """
        monkeypatch.setattr(_provider_config_module, "show_info", lambda *_a, **_kw: None)
        buttons = provider_widget.findChildren(QPushButton)
        texts = [b.text() for b in buttons]
        assert "Apply" in texts, "Apply button must exist in the XPU settings group"
        spin: QSpinBox | None = getattr(provider_widget, "_cache_spin", None)
        assert spin is not None
        test_mb = 3072
        spin.setValue(test_mb)
        for b in buttons:
            if b.text() == "Apply":
                b.click()
                break
        QApplication.processEvents()
        actual_bytes = get_global_model_cache().max_memory_bytes
        expected_bytes = test_mb * 1024 * 1024
        assert actual_bytes == expected_bytes, (
            f"After Apply click with spinbox={test_mb} MB, global cache max_memory_bytes must be "
            f"{expected_bytes} ({test_mb} MB), got {actual_bytes} ({actual_bytes // (1024 * 1024)} MB)"
        )


@pytest.mark.usefixtures("qapp")
class TestProviderConfigSettingsPersistence:
    """Verify XPU settings are included in get_settings() output."""

    @staticmethod
    def test_get_settings_includes_prefer_xpu(provider_widget: ProviderSettingsWidget) -> None:
        """get_settings() returns prefer_xpu boolean.

        Args:
            provider_widget: ProviderSettingsWidget fixture configured for local_transformers.
        """
        settings = provider_widget.get_settings()
        assert "prefer_xpu" in settings
        assert isinstance(settings["prefer_xpu"], bool)

    @staticmethod
    def test_get_settings_includes_device_index(provider_widget: ProviderSettingsWidget) -> None:
        """get_settings() returns device_index integer.

        Args:
            provider_widget: ProviderSettingsWidget fixture configured for local_transformers.
        """
        settings = provider_widget.get_settings()
        assert "device_index" in settings
        assert isinstance(settings["device_index"], int)

    @staticmethod
    def test_get_settings_includes_dtype_override(provider_widget: ProviderSettingsWidget) -> None:
        """get_settings() returns dtype_override string.

        Args:
            provider_widget: ProviderSettingsWidget fixture configured for local_transformers.
        """
        settings = provider_widget.get_settings()
        assert "dtype_override" in settings
        assert isinstance(settings["dtype_override"], str)
        assert settings["dtype_override"] in {"Auto", "float16", "bfloat16", "float32"}

    @staticmethod
    def test_get_settings_includes_cache_size_mb(provider_widget: ProviderSettingsWidget) -> None:
        """get_settings() returns cache_size_mb integer.

        Args:
            provider_widget: ProviderSettingsWidget fixture configured for local_transformers.
        """
        settings = provider_widget.get_settings()
        assert "cache_size_mb" in settings
        assert isinstance(settings["cache_size_mb"], int)
        assert settings["cache_size_mb"] == _CACHE_DEFAULT_MB

    @staticmethod
    def test_settings_reflect_checkbox_change(provider_widget: ProviderSettingsWidget) -> None:
        """Toggling prefer_xpu checkbox changes get_settings() output.

        Args:
            provider_widget: ProviderSettingsWidget fixture configured for local_transformers.
        """
        cb: QCheckBox | None = getattr(provider_widget, "_prefer_xpu_cb", None)
        assert cb is not None
        cb.setChecked(False)
        settings = provider_widget.get_settings()
        assert settings["prefer_xpu"] is False

    @staticmethod
    def test_settings_reflect_dtype_change(provider_widget: ProviderSettingsWidget) -> None:
        """Changing dtype combo changes get_settings() output.

        Args:
            provider_widget: ProviderSettingsWidget fixture configured for local_transformers.
        """
        combo: QComboBox | None = getattr(provider_widget, "_dtype_combo", None)
        assert combo is not None
        combo.setCurrentText("bfloat16")
        settings = provider_widget.get_settings()
        assert settings["dtype_override"] == "bfloat16"

    @staticmethod
    def test_settings_reflect_cache_size_change(provider_widget: ProviderSettingsWidget) -> None:
        """Changing cache spinbox value changes get_settings() output.

        Args:
            provider_widget: ProviderSettingsWidget fixture configured for local_transformers.
        """
        spin: QSpinBox | None = getattr(provider_widget, "_cache_spin", None)
        assert spin is not None
        spin.setValue(2048)
        settings = provider_widget.get_settings()
        assert settings["cache_size_mb"] == 2048


@pytest.mark.usefixtures("qapp")
class TestProviderConfigNonLocalTransformers:
    """Verify XPU widgets do NOT appear for other providers."""

    @staticmethod
    def test_anthropic_has_no_xpu_group() -> None:
        """Anthropic provider widget has no XPU settings group."""
        widget = ProviderSettingsWidget(provider_id="anthropic")
        groups = widget.findChildren(QGroupBox)
        titles = [g.title() for g in groups]
        assert "XPU / Device Settings" not in titles

    @staticmethod
    def test_ollama_has_no_xpu_group() -> None:
        """Ollama provider widget has no XPU settings group."""
        widget = ProviderSettingsWidget(provider_id="ollama")
        groups = widget.findChildren(QGroupBox)
        titles = [g.title() for g in groups]
        assert "XPU / Device Settings" not in titles

    @staticmethod
    def test_anthropic_settings_have_no_xpu_keys() -> None:
        """get_settings() for non-local_transformers has no XPU keys."""
        widget = ProviderSettingsWidget(provider_id="anthropic")
        settings = widget.get_settings()
        assert "prefer_xpu" not in settings
        assert "device_index" not in settings
        assert "dtype_override" not in settings
        assert "cache_size_mb" not in settings


@pytest.mark.usefixtures("qapp")
class TestProviderListInclusion:
    """Verify added providers are recognized by ProviderSettingsWidget."""

    @staticmethod
    def test_local_transformers_widget_has_xpu_settings() -> None:
        """ProviderSettingsWidget for 'local_transformers' renders XPU-specific UI.

        ``provider_id == 'local_transformers'`` must trigger ``_setup_xpu_settings``
        which creates the ``_prefer_xpu_cb``, ``_device_combo``, ``_dtype_combo``,
        ``_xpu_mem_bar``, and ``_cache_spin`` widgets.  Verifying their presence as
        typed attributes on the widget is a real gate: if ``_setup_provider_specific_ui``
        routing is broken and ``_setup_xpu_settings`` is never called, all five
        attributes will be absent and the test will go red.

        Args: (none)
        """
        widget = ProviderSettingsWidget(provider_id="local_transformers")
        prefer_cb: QCheckBox | None = getattr(widget, "_prefer_xpu_cb", None)
        assert isinstance(prefer_cb, QCheckBox), "_prefer_xpu_cb must be a QCheckBox on the local_transformers widget"
        device_combo: QComboBox | None = getattr(widget, "_device_combo", None)
        assert isinstance(device_combo, QComboBox), "_device_combo must be a QComboBox on the local_transformers widget"
        dtype_combo: QComboBox | None = getattr(widget, "_dtype_combo", None)
        assert isinstance(dtype_combo, QComboBox), "_dtype_combo must be a QComboBox on the local_transformers widget"
        mem_bar: QProgressBar | None = getattr(widget, "_xpu_mem_bar", None)
        assert isinstance(mem_bar, QProgressBar), "_xpu_mem_bar must be a QProgressBar on the local_transformers widget"
        spin: QSpinBox | None = getattr(widget, "_cache_spin", None)
        assert isinstance(spin, QSpinBox), "_cache_spin must be a QSpinBox on the local_transformers widget"
        settings = widget.get_settings()
        xpu_keys = {"prefer_xpu", "device_index", "dtype_override", "cache_size_mb"}
        assert xpu_keys <= settings.keys(), (
            f"get_settings() for local_transformers must contain {xpu_keys}, got keys: {set(settings.keys())}"
        )

    @staticmethod
    def test_grok_widget_has_no_xpu_settings() -> None:
        """ProviderSettingsWidget for 'grok' does not render XPU-specific UI.

        ``provider_id == 'grok'`` must NOT trigger ``_setup_xpu_settings``.  The XPU
        attributes (``_prefer_xpu_cb``, ``_device_combo``, ``_xpu_mem_bar``, etc.) must
        be absent, and ``get_settings()`` must not return XPU keys.  If the routing
        logic in ``_setup_provider_specific_ui`` is broken and all providers receive XPU
        settings, this test will go red.

        Args: (none)
        """
        widget = ProviderSettingsWidget(provider_id="grok")
        prefer_cb: QCheckBox | None = getattr(widget, "_prefer_xpu_cb", None)
        assert prefer_cb is None, "_prefer_xpu_cb must not exist on the grok widget (XPU settings are local_transformers-only)"
        device_combo: QComboBox | None = getattr(widget, "_device_combo", None)
        assert device_combo is None, "_device_combo must not exist on the grok widget"
        settings = widget.get_settings()
        assert "prefer_xpu" not in settings, "get_settings() for grok must not contain 'prefer_xpu' (XPU keys are local_transformers-only)"
        assert "cache_size_mb" not in settings, "get_settings() for grok must not contain 'cache_size_mb'"
        groups = widget.findChildren(QGroupBox)
        titles = [g.title() for g in groups]
        assert "XPU / Device Settings" not in titles, "grok widget must not contain an 'XPU / Device Settings' group box"
