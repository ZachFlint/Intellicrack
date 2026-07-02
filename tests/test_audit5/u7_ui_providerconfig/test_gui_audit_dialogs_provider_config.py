# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for GUI audit findings in provider_config.

Covers two fixes:

* Discovery status label object name. ``ModelSelectionDialog`` set
  ``setObjectName("discovery_status_label")`` and then immediately overwrote it
  with ``setObjectName("hint_label")``, so any QSS targeting
  ``#discovery_status_label`` could never apply. The fix removes the erroneous
  second call so the intended object name survives.
* Worker guards. The manual ``_test_connection`` and ``_refresh_models``
  triggers reassigned their worker attribute without checking whether the
  previous worker was still running, orphaning a live ``QThread``. The fix
  returns early while a worker is running, mirroring the auto-refresh path.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast, override

import pytest

from intellicrack.ui.provider_config import (
    ConnectionTestWorker,
    ModelRefreshWorker,
    ModelSelectionDialog,
    ProviderSettingsWidget,
)


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication, QLabel

    from intellicrack.core.types import ModelInfo


def _invoke(widget: ProviderSettingsWidget, name: str) -> None:
    """Invoke a no-argument private method without tripping private-usage checks.

    Args:
        widget: The ProviderSettingsWidget under test.
        name: The private method name to invoke.
    """
    method: object = getattr(widget, name)
    cast("Callable[[], None]", method)()


def _status_text(widget: ProviderSettingsWidget) -> str:
    """Return the current status label text without tripping private-usage checks.

    Args:
        widget: The ProviderSettingsWidget under test.

    Returns:
        str: The status label text.
    """
    label: object = getattr(widget, "_status_label")
    return cast("QLabel", label).text()


class _RunningTestWorker(ConnectionTestWorker):
    """A ConnectionTestWorker that reports itself as perpetually running."""

    @override
    def isRunning(self) -> bool:
        """Report the worker as running.

        Returns:
            bool: Always ``True``.
        """
        return True


class _RunningRefreshWorker(ModelRefreshWorker):
    """A ModelRefreshWorker that reports itself as perpetually running."""

    @override
    def isRunning(self) -> bool:
        """Report the worker as running.

        Returns:
            bool: Always ``True``.
        """
        return True


@pytest.fixture
def provider_widget(qapp: QApplication, tmp_path: Path) -> Iterator[ProviderSettingsWidget]:
    """Create a ProviderSettingsWidget for the ``openai`` provider.

    Args:
        qapp: Session-scoped Qt application fixture.
        tmp_path: Per-test temporary directory.

    Yields:
        ProviderSettingsWidget: A live widget rooted at an isolated config path.
    """
    del qapp
    widget = ProviderSettingsWidget("openai", config_path=tmp_path / "providers.json")
    yield widget
    widget.deleteLater()


class TestDiscoveryStatusLabelObjectName:
    """The discovery status label must keep its intended object name."""

    def test_object_name_is_discovery_status_label(self, qapp: QApplication) -> None:
        """The label's objectName must be ``discovery_status_label``, not overwritten.

        Args:
            qapp: Session-scoped Qt application fixture.
        """
        del qapp
        empty_models: list[ModelInfo] = []
        dialog = ModelSelectionDialog(empty_models)
        try:
            label: object = getattr(dialog, "_discovery_status_label")
            assert cast("QLabel", label).objectName() == "discovery_status_label", (
                "the discovery status label must retain its intended object name; "
                "the erroneous second setObjectName('hint_label') must be removed"
            )
        finally:
            dialog.deleteLater()


class TestProviderWorkerRunningGuards:
    """Manual triggers must not orphan a still-running worker QThread."""

    def test_test_connection_does_not_replace_running_worker(self, provider_widget: ProviderSettingsWidget) -> None:
        """Triggering a connection test while one runs is a no-op, not a replacement.

        Args:
            provider_widget: ProviderSettingsWidget fixture.
        """
        running = _RunningTestWorker("openai", "sk-test", None, provider_widget)
        setattr(provider_widget, "_test_worker", running)

        _invoke(provider_widget, "_test_connection")

        worker_after: object = getattr(provider_widget, "_test_worker")
        assert worker_after is running, "the connection-test trigger must not replace a running worker, which would orphan its QThread"
        assert _status_text(provider_widget) != "Testing connection...", (
            "the guard must return before mutating status UI when a test is already running"
        )

    def test_refresh_models_does_not_replace_running_worker(self, provider_widget: ProviderSettingsWidget) -> None:
        """Triggering a model refresh while one runs is a no-op, not a replacement.

        Args:
            provider_widget: ProviderSettingsWidget fixture.
        """
        running = _RunningRefreshWorker("openai", "sk-test", None, None, provider_widget)
        setattr(provider_widget, "_refresh_worker", running)

        _invoke(provider_widget, "_refresh_models")

        worker_after: object = getattr(provider_widget, "_refresh_worker")
        assert worker_after is running, "the model-refresh trigger must not replace a running worker, which would orphan its QThread"
        assert _status_text(provider_widget) != "Refreshing models...", (
            "the guard must return before mutating status UI when a refresh is already running"
        )
