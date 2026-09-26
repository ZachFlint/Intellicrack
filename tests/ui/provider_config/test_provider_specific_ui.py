# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression tests for audit5 U7 ui-providerconfig fix (F-0022).

Verifies that ``ProviderSettingsWidget._setup_provider_specific_ui`` wires
provider-specific UI for every supported provider, not just the original
three (Ollama, Local Transformers, OpenRouter). Each cloud provider that
previously had no provider-specific section now exposes a "Resources"
group with deep links that route through ``QDesktopServices.openUrl``.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, cast

import pytest
from PyQt6.QtCore import QUrl
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import QApplication, QGroupBox, QMessageBox, QPushButton, QWidget

from intellicrack.ui import provider_config
from intellicrack.ui.provider_config import ProviderSettingsWidget


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


_RESOURCE_LINKS_ATTR = "_PROVIDER_RESOURCE_LINKS"


class _BrowserLaunchRecorder:
    """Stand in for the OS browser launcher, recording every URL it is asked to open."""

    def __init__(self, *, succeeds: bool) -> None:
        """Create a recorder that reports a fixed launch outcome.

        Args:
            succeeds: Value returned for every launch, as ``QDesktopServices.openUrl`` would.
        """
        self.succeeds = succeeds
        self.urls: list[QUrl] = []

    def open_url(self, url: QUrl) -> bool:
        """Record one launch request instead of spawning a browser.

        Args:
            url: The URL the handler asked the OS to open.

        Returns:
            bool: The configured launch outcome.
        """
        self.urls.append(url)
        return self.succeeds


class _WarningRecorder:
    """Stand in for ``show_warning``, recording each dialog instead of showing it."""

    def __init__(self) -> None:
        """Create a recorder with no warnings recorded yet."""
        self.calls: list[tuple[QWidget | None, str, str]] = []

    def show_warning(
        self,
        parent: QWidget | None,
        title: str,
        message: str,
        *,
        exc: BaseException | None = None,
    ) -> QMessageBox.StandardButton:
        """Record one warning dialog request.

        Args:
            parent: Widget that would own the dialog.
            title: Dialog title.
            message: Dialog body.
            exc: Optional exception attached to the warning.

        Returns:
            QMessageBox.StandardButton: ``Ok``, as a dismissed warning would return.
        """
        del exc
        self.calls.append((parent, title, message))
        return QMessageBox.StandardButton.Ok


def _resource_links() -> dict[str, tuple[tuple[str, str, str], ...]]:
    """Return the module-level ``_PROVIDER_RESOURCE_LINKS`` table.

    The table is module-private; routing through ``getattr`` with a string
    constant keeps tests free of ``reportPrivateUsage`` diagnostics while
    still asserting on the structure of the data table.

    Returns:
        dict[str, tuple[tuple[str, str, str], ...]]: The full table.
    """
    raw: object = getattr(provider_config, _RESOURCE_LINKS_ATTR)
    return cast("dict[str, tuple[tuple[str, str, str], ...]]", raw)


_PREVIOUSLY_WIRED_PROVIDERS: tuple[str, ...] = ("ollama", "local_transformers", "openrouter")
_PREVIOUSLY_UNWIRED_PROVIDERS: tuple[str, ...] = (
    "anthropic",
    "openai",
    "google",
    "huggingface",
    "grok",
)


@pytest.fixture(scope="module")
def qapp() -> Iterator[QApplication]:
    """Provide a process-wide ``QApplication`` for Qt widget construction.

    Yields:
        QApplication: The active Qt application for the test process.
    """
    existing = QApplication.instance()
    if isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


def _make_widget(tmp_path: Path, provider_id: str) -> ProviderSettingsWidget:
    """Construct a ``ProviderSettingsWidget`` with an isolated config path.

    Args:
        tmp_path: Per-test temporary directory.
        provider_id: Provider id to instantiate.

    Returns:
        ProviderSettingsWidget: A live widget rooted at the temp directory.
    """
    config_path = tmp_path / f"{provider_id}_providers.json"
    return ProviderSettingsWidget(provider_id, config_path=config_path)


def _find_group(widget: ProviderSettingsWidget, title: str) -> QGroupBox | None:
    """Locate the first child ``QGroupBox`` whose title matches ``title``.

    Args:
        widget: Provider settings widget to scan.
        title: Group box title to search for.

    Returns:
        QGroupBox | None: The matching group box, or ``None`` if absent.
    """
    return next(
        (child for child in widget.findChildren(QGroupBox) if child.title() == title),
        None,
    )


@pytest.mark.parametrize("provider_id", _PREVIOUSLY_UNWIRED_PROVIDERS)
def test_resources_group_present_for_previously_unwired_providers(
    qapp: QApplication,
    tmp_path: Path,
    provider_id: str,
) -> None:
    """Cloud providers without bespoke groups now expose a Resources group.

    Before F-0022 the function silently returned for these providers, leaving
    the dialog with no provider-specific UI. The fix registers a Resources
    group with deep links so each supported provider has at least one
    provider-specific affordance.

    Args:
        qapp: Module-scoped Qt application.
        tmp_path: Per-test temporary directory.
        provider_id: Provider id under test.
    """
    del qapp
    widget = _make_widget(tmp_path, provider_id)
    group = _find_group(widget, "Resources")
    assert group is not None, f"Resources group missing for provider '{provider_id}'"

    expected_links = _resource_links()[provider_id]
    expected_labels = {label for label, _, _ in expected_links}

    buttons = group.findChildren(QPushButton)
    actual_labels = {btn.text() for btn in buttons}
    assert expected_labels <= actual_labels, f"Provider '{provider_id}' missing buttons. expected {expected_labels}, got {actual_labels}"


def test_resource_links_table_covers_all_cloud_providers() -> None:
    """``_PROVIDER_RESOURCE_LINKS`` must define entries for every cloud provider.

    The static table is the source of truth for which providers receive a
    Resources group. If a new provider is added to the dialog without a
    corresponding entry here, the dialog will silently skip it.
    """
    cloud_providers = {"anthropic", "openai", "google", "huggingface", "grok", "openrouter"}
    table = _resource_links()
    assert cloud_providers <= table.keys()

    for provider_id, entries in table.items():
        assert entries, f"Provider '{provider_id}' has no resource entries"
        for entry in entries:
            assert len(entry) == 3, f"Malformed entry for '{provider_id}': {entry!r}"
            label, url, tooltip = entry
            assert label, f"Empty label in '{provider_id}'"
            assert url.startswith("https://"), f"Provider '{provider_id}' link must be HTTPS: {url!r}"
            assert tooltip, f"Empty tooltip for '{provider_id}' link {label!r}"


@pytest.mark.parametrize("provider_id", _PREVIOUSLY_UNWIRED_PROVIDERS)
def test_resource_button_click_routes_exact_url_once_to_browser(
    qapp: QApplication,
    tmp_path: Path,
    provider_id: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each Resources button is wired 1:1 to its own URL via the system browser hook.

    Clicking the *real* button (driving the genuine ``clicked`` signal/slot
    connection) must invoke ``QDesktopServices.openUrl`` exactly once with a
    ``QUrl`` whose text equals the configured link for that exact label. Asserting
    the call count is exactly one proves the connection is neither missing (zero
    calls) nor double-wired (two calls); asserting the URL string proves the
    ``partial(self._open_resource_url, QUrl(url), label)`` binding carried the
    correct per-button URL rather than, say, every button sharing the first link.
    ``QDesktopServices.openUrl`` is the OS browser launcher, not the unit under
    test, so replacing it with a recorder keeps the test from spawning a real
    browser while still exercising the full button -> handler -> openUrl path.

    Args:
        qapp: Module-scoped Qt application.
        tmp_path: Per-test temporary directory.
        provider_id: Provider id under test.
        monkeypatch: Pytest fixture used to swap in the browser launch recorder.
    """
    del qapp
    widget = _make_widget(tmp_path, provider_id)
    buttons = getattr(widget, "_resource_buttons", None)
    assert buttons is not None, f"Provider '{provider_id}' did not register buttons"

    expected_links = {label: url for label, url, _ in _resource_links()[provider_id]}
    assert set(buttons.keys()) == set(expected_links.keys()), (
        f"Provider '{provider_id}' button labels must match the resource table exactly"
    )

    launcher = _BrowserLaunchRecorder(succeeds=True)
    monkeypatch.setattr(QDesktopServices, "openUrl", launcher.open_url)
    for label, btn in buttons.items():
        btn.click()
        assert len(launcher.urls) == 1, f"button '{label}' must trigger exactly one openUrl, got {len(launcher.urls)}"
        called_url = launcher.urls[0]
        assert isinstance(called_url, QUrl)
        assert called_url.toString() == expected_links[label]
        launcher.urls.clear()


@pytest.mark.parametrize("provider_id", _PREVIOUSLY_WIRED_PROVIDERS)
def test_previously_wired_providers_retain_their_groups(
    qapp: QApplication,
    tmp_path: Path,
    provider_id: str,
) -> None:
    """Existing provider-specific groups remain wired after the fix.

    Args:
        qapp: Module-scoped Qt application.
        tmp_path: Per-test temporary directory.
        provider_id: Provider id under test.
    """
    del qapp
    widget = _make_widget(tmp_path, provider_id)

    expected_titles = {
        "ollama": "Model Download",
        "openrouter": "Cost Tracking",
        "local_transformers": "XPU / Device Settings",
    }
    title = expected_titles[provider_id]
    group = _find_group(widget, title)
    assert group is not None, f"Provider '{provider_id}' lost its '{title}' group after the fix"


def test_openrouter_gets_both_cost_and_resources_groups(
    qapp: QApplication,
    tmp_path: Path,
) -> None:
    """OpenRouter exposes both its bespoke cost-tracking group and a Resources group.

    Args:
        qapp: Module-scoped Qt application.
        tmp_path: Per-test temporary directory.
    """
    del qapp
    widget = _make_widget(tmp_path, "openrouter")
    assert _find_group(widget, "Cost Tracking") is not None
    assert _find_group(widget, "Resources") is not None


def test_open_resource_url_surfaces_exact_failure_dialog(
    qapp: QApplication,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed browser launch surfaces a warning naming the exact label and URL.

    When ``QDesktopServices.openUrl`` returns ``False`` (the OS could not open the
    browser), the handler must escalate to the user via ``show_warning`` with the
    title "Open Link Failed" and a body that interpolates the failing link's label
    and URL exactly as ``f"Could not open {label} ({url})."``. This proves the
    real button is wired to a handler that genuinely inspects the return value and
    surfaces failure rather than swallowing it. The expected message is built from
    the resource table (an independent source of truth), not from the handler's
    own output.

    Args:
        qapp: Module-scoped Qt application.
        tmp_path: Per-test temporary directory.
        monkeypatch: Pytest fixture used to swap in the launch and warning recorders.
    """
    del qapp
    widget = _make_widget(tmp_path, "anthropic")
    buttons = getattr(widget, "_resource_buttons", None)
    assert buttons is not None
    label, btn = next(iter(buttons.items()))
    assert label

    expected_url = {link_label: url for link_label, url, _ in _resource_links()["anthropic"]}[label]
    expected_message = f"Could not open {label} ({expected_url})."

    launcher = _BrowserLaunchRecorder(succeeds=False)
    warnings = _WarningRecorder()
    monkeypatch.setattr(QDesktopServices, "openUrl", launcher.open_url)
    monkeypatch.setattr(provider_config, "show_warning", warnings.show_warning)
    btn.click()

    assert len(warnings.calls) == 1, "exactly one warning must be shown when the browser launch fails"
    warn_args = warnings.calls[0]
    assert warn_args[0] is widget, "warning must be parented to the settings widget"
    assert warn_args[1] == "Open Link Failed"
    assert warn_args[2] == expected_message
