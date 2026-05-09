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
from unittest.mock import patch

import pytest
from PyQt6.QtCore import QUrl
from PyQt6.QtWidgets import QApplication, QGroupBox, QPushButton

from intellicrack.ui import provider_config
from intellicrack.ui.provider_config import ProviderSettingsWidget


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


_RESOURCE_LINKS_ATTR = "_PROVIDER_RESOURCE_LINKS"


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
    for child in widget.findChildren(QGroupBox):
        if child.title() == title:
            return child
    return None


@pytest.mark.parametrize("provider_id", _PREVIOUSLY_UNWIRED_PROVIDERS)
def test_resources_group_present_for_previously_unwired_providers(
    qapp: QApplication,  # noqa: ARG001
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
def test_resource_button_invokes_qdesktopservices(
    qapp: QApplication,  # noqa: ARG001
    tmp_path: Path,
    provider_id: str,
) -> None:
    """Clicking a Resources button routes the configured URL to ``QDesktopServices``.

    Args:
        qapp: Module-scoped Qt application.
        tmp_path: Per-test temporary directory.
        provider_id: Provider id under test.
    """
    widget = _make_widget(tmp_path, provider_id)
    buttons = getattr(widget, "_resource_buttons", None)
    assert buttons is not None, f"Provider '{provider_id}' did not register buttons"

    expected_links = {label: url for label, url, _ in _resource_links()[provider_id]}

    with patch(
        "intellicrack.ui.provider_config.QDesktopServices.openUrl",
        return_value=True,
    ) as mock_open:
        for label, btn in buttons.items():
            btn.click()
            assert mock_open.called, f"openUrl not invoked for '{provider_id}' / '{label}'"
            (called_url,), _ = mock_open.call_args
            assert isinstance(called_url, QUrl)
            assert called_url.toString() == expected_links[label]
            mock_open.reset_mock()


@pytest.mark.parametrize("provider_id", _PREVIOUSLY_WIRED_PROVIDERS)
def test_previously_wired_providers_retain_their_groups(
    qapp: QApplication,  # noqa: ARG001
    tmp_path: Path,
    provider_id: str,
) -> None:
    """Existing provider-specific groups remain wired after the fix.

    Args:
        qapp: Module-scoped Qt application.
        tmp_path: Per-test temporary directory.
        provider_id: Provider id under test.
    """
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
    qapp: QApplication,  # noqa: ARG001
    tmp_path: Path,
) -> None:
    """OpenRouter exposes both its bespoke cost-tracking group and a Resources group.

    Args:
        qapp: Module-scoped Qt application.
        tmp_path: Per-test temporary directory.
    """
    widget = _make_widget(tmp_path, "openrouter")
    assert _find_group(widget, "Cost Tracking") is not None
    assert _find_group(widget, "Resources") is not None


def test_open_resource_url_warns_when_qdesktopservices_fails(
    qapp: QApplication,  # noqa: ARG001
    tmp_path: Path,
) -> None:
    """A failed ``QDesktopServices.openUrl`` surfaces a warning dialog.

    Args:
        qapp: Module-scoped Qt application.
        tmp_path: Per-test temporary directory.
    """
    widget = _make_widget(tmp_path, "anthropic")
    buttons = getattr(widget, "_resource_buttons", None)
    assert buttons is not None
    label, btn = next(iter(buttons.items()))
    assert label

    with (
        patch(
            "intellicrack.ui.provider_config.QDesktopServices.openUrl",
            return_value=False,
        ),
        patch("intellicrack.ui.provider_config.show_warning") as mock_warn,
    ):
        btn.click()
        assert mock_warn.called, "show_warning must run when openUrl returns False"
