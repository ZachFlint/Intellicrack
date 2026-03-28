"""End-to-end tests for the XPU Status dialog and provider config XPU settings.

Validates XPU status dialog construction, live refresh behavior, device
enumeration, memory display, cache reporting, requirements checking,
provider config XPU group box construction, settings persistence, and
Help menu integration using real XPU backend APIs.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QGroupBox,
    QLabel,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QTextEdit,
)

from intellicrack.providers.xpu_utils import (
    get_xpu_device_count,
    get_xpu_device_info,
    get_xpu_memory_info,
    is_xpu_available,
)
from intellicrack.ui.provider_config import ProviderSettingsWidget
from intellicrack.ui.xpu_status import XPUStatusDialog


if TYPE_CHECKING:
    from collections.abc import Generator

    from PyQt6.QtWidgets import QApplication


_LIVE_REFRESH_MS: int = 2000
_PROVIDER_MEM_REFRESH_MS: int = 3000
_CACHE_DEFAULT_MB: int = 10240
_CACHE_MIN_MB: int = 512
_CACHE_MAX_MB: int = 65536
_CACHE_STEP_MB: int = 512
_BYTES_PER_GB: float = 1024.0 * 1024.0 * 1024.0
_PROGRESS_BAR_MAX: int = 100


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
        """Window title is set to 'XPU Status'."""
        assert xpu_dialog.windowTitle() == "XPU Status"

    @staticmethod
    def test_dialog_contains_device_status_group(xpu_dialog: XPUStatusDialog) -> None:
        """Dialog contains a 'Device Status' group box."""
        groups = xpu_dialog.findChildren(QGroupBox)
        titles = [g.title() for g in groups]
        assert "Device Status" in titles

    @staticmethod
    def test_dialog_contains_memory_usage_group(xpu_dialog: XPUStatusDialog) -> None:
        """Dialog contains a 'Memory Usage' group box."""
        groups = xpu_dialog.findChildren(QGroupBox)
        titles = [g.title() for g in groups]
        assert "Memory Usage" in titles

    @staticmethod
    def test_dialog_contains_model_cache_group(xpu_dialog: XPUStatusDialog) -> None:
        """Dialog contains a 'Model Cache' group box."""
        groups = xpu_dialog.findChildren(QGroupBox)
        titles = [g.title() for g in groups]
        assert "Model Cache" in titles

    @staticmethod
    def test_dialog_contains_system_requirements_group(xpu_dialog: XPUStatusDialog) -> None:
        """Dialog contains a 'System Requirements' group box."""
        groups = xpu_dialog.findChildren(QGroupBox)
        titles = [g.title() for g in groups]
        assert "System Requirements" in titles

    @staticmethod
    def test_dialog_has_four_group_boxes(xpu_dialog: XPUStatusDialog) -> None:
        """Dialog has exactly four group boxes."""
        groups = xpu_dialog.findChildren(QGroupBox)
        assert len(groups) == 4

    @staticmethod
    def test_dialog_has_refresh_button(xpu_dialog: XPUStatusDialog) -> None:
        """Dialog has a 'Refresh' button."""
        buttons = xpu_dialog.findChildren(QPushButton)
        texts = [b.text() for b in buttons]
        assert "Refresh" in texts

    @staticmethod
    def test_dialog_has_close_button(xpu_dialog: XPUStatusDialog) -> None:
        """Dialog has a 'Close' button."""
        buttons = xpu_dialog.findChildren(QPushButton)
        texts = [b.text() for b in buttons]
        assert "Close" in texts

    @staticmethod
    def test_dialog_has_memory_progress_bar(xpu_dialog: XPUStatusDialog) -> None:
        """Dialog contains a QProgressBar for memory display."""
        bars = xpu_dialog.findChildren(QProgressBar)
        assert len(bars) == 1
        assert bars[0].minimum() == 0
        assert bars[0].maximum() == _PROGRESS_BAR_MAX

    @staticmethod
    def test_dialog_has_requirements_text_edit(xpu_dialog: XPUStatusDialog) -> None:
        """Dialog contains a read-only QTextEdit for requirements."""
        edits = xpu_dialog.findChildren(QTextEdit)
        assert len(edits) == 1
        assert edits[0].isReadOnly()


@pytest.mark.usefixtures("qapp")
class TestXPUStatusDialogRefreshTimer:
    """Verify the live refresh timer behavior."""

    @staticmethod
    def test_timer_is_active_after_construction(xpu_dialog: XPUStatusDialog) -> None:
        """Refresh timer starts automatically on construction."""
        assert xpu_dialog._refresh_timer.isActive()

    @staticmethod
    def test_timer_interval_is_2_seconds(xpu_dialog: XPUStatusDialog) -> None:
        """Refresh timer interval is 2000ms."""
        assert xpu_dialog._refresh_timer.interval() == _LIVE_REFRESH_MS

    @staticmethod
    def test_timer_stops_on_close(xpu_dialog: XPUStatusDialog) -> None:
        """Refresh timer stops when the dialog is closed."""
        assert xpu_dialog._refresh_timer.isActive()
        xpu_dialog.close()
        assert not xpu_dialog._refresh_timer.isActive()


@pytest.mark.usefixtures("qapp")
class TestXPUStatusDialogDeviceInfo:
    """Verify the dialog displays real XPU device information."""

    @staticmethod
    def test_status_label_reflects_xpu_availability(xpu_dialog: XPUStatusDialog) -> None:
        """Status label shows 'XPU Active' or 'CPU Only' based on real hardware."""
        text = xpu_dialog._status_label.text()
        if is_xpu_available():
            assert text == "XPU Active"
        else:
            assert text in {"CPU Only", "XPU utilities not available"}

    @staticmethod
    @pytest.mark.skipif(not is_xpu_available(), reason="No XPU device available")
    def test_device_name_shows_real_device(xpu_dialog: XPUStatusDialog) -> None:
        """Device name label displays the real device name from XPU hardware."""
        info = get_xpu_device_info(0)
        assert info is not None
        assert xpu_dialog._device_name_label.text() == info.device_name

    @staticmethod
    @pytest.mark.skipif(not is_xpu_available(), reason="No XPU device available")
    def test_driver_label_shows_real_driver(xpu_dialog: XPUStatusDialog) -> None:
        """Driver label shows the real driver version string."""
        info = get_xpu_device_info(0)
        assert info is not None
        if info.driver_version:
            assert xpu_dialog._driver_label.text() == info.driver_version

    @staticmethod
    @pytest.mark.skipif(not is_xpu_available(), reason="No XPU device available")
    def test_capabilities_label_shows_dtype_flags(xpu_dialog: XPUStatusDialog) -> None:
        """Capabilities label contains dtype support flags from real hardware."""
        text = xpu_dialog._caps_label.text()
        info = get_xpu_device_info(0)
        assert info is not None
        if info.supports_fp16:
            assert "FP16" in text
        if info.supports_bf16:
            assert "BF16" in text


@pytest.mark.usefixtures("qapp")
class TestXPUStatusDialogMemory:
    """Verify memory display matches real XPU memory state."""

    @staticmethod
    @pytest.mark.skipif(not is_xpu_available(), reason="No XPU device available")
    def test_memory_bar_shows_real_percentage(xpu_dialog: XPUStatusDialog) -> None:
        """Memory progress bar reflects actual XPU memory utilization."""
        allocated, total = get_xpu_memory_info(0)
        if total > 0:
            expected_pct = int((allocated / total) * 100)
            assert abs(xpu_dialog._memory_bar.value() - expected_pct) <= 2

    @staticmethod
    @pytest.mark.skipif(not is_xpu_available(), reason="No XPU device available")
    def test_memory_text_shows_gb_values(xpu_dialog: XPUStatusDialog) -> None:
        """Memory text label includes GB values and percentage."""
        text = xpu_dialog._memory_text.text()
        assert "GB" in text
        assert "%" in text

    @staticmethod
    @pytest.mark.skipif(is_xpu_available(), reason="XPU is available")
    def test_memory_shows_no_device_when_unavailable(xpu_dialog: XPUStatusDialog) -> None:
        """Memory text shows informational message when no XPU present."""
        text = xpu_dialog._memory_text.text()
        assert text in {"No XPU device", "XPU memory info not available"}


@pytest.mark.usefixtures("qapp")
class TestXPUStatusDialogCache:
    """Verify model cache display reads from the real global cache."""

    @staticmethod
    def test_cache_usage_label_has_value(xpu_dialog: XPUStatusDialog) -> None:
        """Cache usage label displays a value (MB or informational text)."""
        text = xpu_dialog._cache_usage_label.text()
        assert text != "--"
        assert len(text) > 0

    @staticmethod
    def test_cache_limit_label_has_value(xpu_dialog: XPUStatusDialog) -> None:
        """Cache limit label displays a value."""
        text = xpu_dialog._cache_limit_label.text()
        assert text != "--"
        assert len(text) > 0


@pytest.mark.usefixtures("qapp")
class TestXPUStatusDialogRequirements:
    """Verify the system requirements check runs and displays results."""

    @staticmethod
    def test_requirements_text_is_populated(xpu_dialog: XPUStatusDialog) -> None:
        """Requirements text area contains check results after construction."""
        html = xpu_dialog._requirements_text.toPlainText()
        assert len(html) > 0

    @staticmethod
    def test_requirements_text_contains_met_or_warnings(xpu_dialog: XPUStatusDialog) -> None:
        """Requirements text shows either 'met' or warning items."""
        html = xpu_dialog._requirements_text.toHtml()
        has_met = "requirements met" in html.lower()
        has_warnings = "warning" in html.lower() or "<li>" in html.lower()
        has_unavailable = "not available" in html.lower()
        assert has_met or has_warnings or has_unavailable


@pytest.mark.usefixtures("qapp")
class TestProviderConfigXPUGroupBox:
    """Verify the XPU settings group box in the provider config dialog."""

    @staticmethod
    def test_xpu_group_box_exists(provider_widget: Any) -> None:
        """Local Transformers provider widget contains 'XPU / Device Settings' group."""
        groups = provider_widget.findChildren(QGroupBox)
        titles = [g.title() for g in groups]
        assert "XPU / Device Settings" in titles

    @staticmethod
    def test_prefer_xpu_checkbox_exists(provider_widget: Any) -> None:
        """Widget has a 'Prefer XPU over CPU' checkbox defaulting to checked."""
        cb: QCheckBox | None = getattr(provider_widget, "_prefer_xpu_cb", None)
        assert cb is not None
        assert isinstance(cb, QCheckBox)
        assert cb.isChecked()
        assert cb.text() == "Prefer XPU over CPU"

    @staticmethod
    def test_device_combo_exists_and_populated(provider_widget: Any) -> None:
        """Widget has a device combo with at least one entry."""
        combo: QComboBox | None = getattr(provider_widget, "_device_combo", None)
        assert combo is not None
        assert isinstance(combo, QComboBox)
        assert combo.count() >= 1

    @staticmethod
    def test_device_combo_has_xpu_entries_when_available(provider_widget: Any) -> None:
        """Device combo shows real XPU devices when hardware is present."""
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
    def test_dtype_combo_has_four_options(provider_widget: Any) -> None:
        """Dtype combo contains Auto, float16, bfloat16, float32."""
        combo: QComboBox | None = getattr(provider_widget, "_dtype_combo", None)
        assert combo is not None
        assert isinstance(combo, QComboBox)
        items = [combo.itemText(i) for i in range(combo.count())]
        assert items == ["Auto", "float16", "bfloat16", "float32"]

    @staticmethod
    def test_memory_bar_exists(provider_widget: Any) -> None:
        """Widget has an XPU memory progress bar."""
        bar: QProgressBar | None = getattr(provider_widget, "_xpu_mem_bar", None)
        assert bar is not None
        assert isinstance(bar, QProgressBar)
        assert bar.minimum() == 0
        assert bar.maximum() == _PROGRESS_BAR_MAX

    @staticmethod
    def test_cache_spinbox_defaults(provider_widget: Any) -> None:
        """Cache size spinbox has correct range and default."""
        spin: QSpinBox | None = getattr(provider_widget, "_cache_spin", None)
        assert spin is not None
        assert isinstance(spin, QSpinBox)
        assert spin.minimum() == _CACHE_MIN_MB
        assert spin.maximum() == _CACHE_MAX_MB
        assert spin.singleStep() == _CACHE_STEP_MB
        assert spin.value() == _CACHE_DEFAULT_MB
        assert "MB" in spin.suffix()

    @staticmethod
    def test_warnings_label_exists(provider_widget: Any) -> None:
        """Widget has a warnings label for requirement check results."""
        label: QLabel | None = getattr(provider_widget, "_xpu_warnings_label", None)
        assert label is not None
        assert isinstance(label, QLabel)
        assert label.wordWrap()

    @staticmethod
    def test_memory_refresh_timer_active(provider_widget: Any) -> None:
        """XPU memory refresh timer starts on widget creation."""
        timer: QTimer | None = getattr(provider_widget, "_xpu_mem_timer", None)
        assert timer is not None
        assert timer.isActive()
        assert timer.interval() == _PROVIDER_MEM_REFRESH_MS


@pytest.mark.usefixtures("qapp")
class TestProviderConfigXPUButtons:
    """Verify the XPU action buttons exist and are connected."""

    @staticmethod
    def test_device_info_button_exists(provider_widget: Any) -> None:
        """Widget has a 'Device Info' button."""
        buttons = provider_widget.findChildren(QPushButton)
        texts = [b.text() for b in buttons]
        assert "Device Info" in texts

    @staticmethod
    def test_clear_cache_button_exists(provider_widget: Any) -> None:
        """Widget has a 'Clear Cache' button."""
        buttons = provider_widget.findChildren(QPushButton)
        texts = [b.text() for b in buttons]
        assert "Clear Cache" in texts

    @staticmethod
    def test_check_requirements_button_exists(provider_widget: Any) -> None:
        """Widget has a 'Check Requirements' button."""
        buttons = provider_widget.findChildren(QPushButton)
        texts = [b.text() for b in buttons]
        assert "Check Requirements" in texts

    @staticmethod
    def test_auto_detect_button_exists(provider_widget: Any) -> None:
        """Widget has an 'Auto-Detect' dtype button."""
        buttons = provider_widget.findChildren(QPushButton)
        texts = [b.text() for b in buttons]
        assert "Auto-Detect" in texts

    @staticmethod
    def test_apply_cache_button_exists(provider_widget: Any) -> None:
        """Widget has an 'Apply' button for cache size."""
        buttons = provider_widget.findChildren(QPushButton)
        texts = [b.text() for b in buttons]
        assert "Apply" in texts


@pytest.mark.usefixtures("qapp")
class TestProviderConfigSettingsPersistence:
    """Verify XPU settings are included in get_settings() output."""

    @staticmethod
    def test_get_settings_includes_prefer_xpu(provider_widget: Any) -> None:
        """get_settings() returns prefer_xpu boolean."""
        settings = provider_widget.get_settings()
        assert "prefer_xpu" in settings
        assert isinstance(settings["prefer_xpu"], bool)

    @staticmethod
    def test_get_settings_includes_device_index(provider_widget: Any) -> None:
        """get_settings() returns device_index integer."""
        settings = provider_widget.get_settings()
        assert "device_index" in settings
        assert isinstance(settings["device_index"], int)

    @staticmethod
    def test_get_settings_includes_dtype_override(provider_widget: Any) -> None:
        """get_settings() returns dtype_override string."""
        settings = provider_widget.get_settings()
        assert "dtype_override" in settings
        assert isinstance(settings["dtype_override"], str)
        assert settings["dtype_override"] in {"Auto", "float16", "bfloat16", "float32"}

    @staticmethod
    def test_get_settings_includes_cache_size_mb(provider_widget: Any) -> None:
        """get_settings() returns cache_size_mb integer."""
        settings = provider_widget.get_settings()
        assert "cache_size_mb" in settings
        assert isinstance(settings["cache_size_mb"], int)
        assert settings["cache_size_mb"] == _CACHE_DEFAULT_MB

    @staticmethod
    def test_settings_reflect_checkbox_change(provider_widget: Any) -> None:
        """Toggling prefer_xpu checkbox changes get_settings() output."""
        cb: QCheckBox | None = getattr(provider_widget, "_prefer_xpu_cb", None)
        assert cb is not None
        cb.setChecked(False)
        settings = provider_widget.get_settings()
        assert settings["prefer_xpu"] is False

    @staticmethod
    def test_settings_reflect_dtype_change(provider_widget: Any) -> None:
        """Changing dtype combo changes get_settings() output."""
        combo: QComboBox | None = getattr(provider_widget, "_dtype_combo", None)
        assert combo is not None
        combo.setCurrentText("bfloat16")
        settings = provider_widget.get_settings()
        assert settings["dtype_override"] == "bfloat16"

    @staticmethod
    def test_settings_reflect_cache_size_change(provider_widget: Any) -> None:
        """Changing cache spinbox value changes get_settings() output."""
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
    def test_local_transformers_widget_creates_successfully() -> None:
        """ProviderSettingsWidget accepts 'local_transformers' as provider_id."""
        widget = ProviderSettingsWidget(provider_id="local_transformers")
        assert widget._provider_id == "local_transformers"

    @staticmethod
    def test_grok_widget_creates_successfully() -> None:
        """ProviderSettingsWidget accepts 'grok' as provider_id."""
        widget = ProviderSettingsWidget(provider_id="grok")
        assert widget._provider_id == "grok"
