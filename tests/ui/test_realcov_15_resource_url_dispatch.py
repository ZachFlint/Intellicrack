# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real Qt-dispatch coverage for ``ProviderSettingsWidget._open_resource_url``.

The prior regression test patched ``QDesktopServices.openUrl`` -- the very
capability claimed to be validated -- and only asserted the mock recorded a
call. These tests instead register a *real* in-process URL handler through
:meth:`QDesktopServices.setUrlHandler`. Clicking a Resources button then runs
the real ``_open_resource_url`` body, which calls the real
``QDesktopServices.openUrl``; Qt's own dispatcher delivers the URL to the
registered handler. We assert on the genuine :class:`QUrl` Qt routed, proving
end-to-end that the button wiring opens the correct URL without ever stubbing
the function under test.

A real scheme handler is the standard test seam for ``openUrl``: it avoids
launching an external browser (which is neither deterministic nor headless)
while still exercising the real Qt routing path.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pytest
from PyQt6.QtCore import QObject, QUrl, pyqtSlot
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import QApplication, QPushButton

from intellicrack.ui import provider_config
from intellicrack.ui.provider_config import ProviderSettingsWidget


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


_RESOURCE_LINKS_ATTR = "_PROVIDER_RESOURCE_LINKS"
_UNWIRED_PROVIDERS: tuple[str, ...] = ("anthropic", "openai", "google", "huggingface", "grok")


def _resource_links() -> dict[str, tuple[tuple[str, str, str], ...]]:
    """Return the module-level ``_PROVIDER_RESOURCE_LINKS`` table.

    Returns:
        dict[str, tuple[tuple[str, str, str], ...]]: The full link table.
    """
    raw: object = getattr(provider_config, _RESOURCE_LINKS_ATTR)
    return cast("dict[str, tuple[tuple[str, str, str], ...]]", raw)


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


class _UrlRecorder(QObject):
    """Real Qt receiver capturing URLs routed by ``QDesktopServices``."""

    def __init__(self) -> None:
        """Initialize the recorder with an empty capture list."""
        super().__init__()
        self.urls: list[str] = []

    @pyqtSlot(QUrl)
    def handle(self, url: QUrl) -> None:
        """Record a URL routed by Qt's desktop-services dispatcher.

        Args:
            url: The URL Qt routed for the registered scheme.
        """
        self.urls.append(url.toString())


@pytest.fixture
def url_recorder(qapp: QApplication) -> Iterator[_UrlRecorder]:
    """Register a real ``https`` URL handler and yield its recorder.

    Args:
        qapp: The process-wide Qt application.

    Yields:
        _UrlRecorder: Receiver whose ``urls`` list captures routed URLs.
    """
    del qapp
    recorder = _UrlRecorder()
    QDesktopServices.setUrlHandler("https", recorder, "handle")
    try:
        yield recorder
    finally:
        QDesktopServices.unsetUrlHandler("https")


@pytest.mark.parametrize("provider_id", _UNWIRED_PROVIDERS)
def test_resource_button_click_routes_real_url_through_qt(
    tmp_path: Path,
    provider_id: str,
    url_recorder: _UrlRecorder,
) -> None:
    """Each Resources button is visible, enabled, and routes its configured URL through real Qt dispatch.

    The test verifies three independent properties for each button:
    1. The button is visible — if removed from the layout or hidden, this fails.
    2. The button is enabled — a disabled button cannot be clicked and would silently produce no URL.
    3. Clicking the button routes the exact expected URL through Qt's real openUrl dispatcher.

    Checking visibility and enabled state before clicking ensures the test goes red if the
    production code hides, removes, or disables a button, which would otherwise cause the
    URL assertion to pass vacuously (the click would be a no-op and url_recorder would be empty).

    Args:
        tmp_path: Per-test temporary directory.
        provider_id: Provider id under test.
        url_recorder: Real Qt receiver capturing routed URLs.
    """
    widget = _make_widget(tmp_path, provider_id)
    buttons = getattr(widget, "_resource_buttons", None)
    assert isinstance(buttons, dict), f"Provider '{provider_id}' did not register buttons"

    expected = {label: url for label, url, _ in _resource_links()[provider_id]}

    assert set(buttons.keys()) == set(expected.keys()), (
        f"Provider '{provider_id}' button labels {set(buttons.keys())} do not match link table {set(expected.keys())}"
    )

    for label, btn in cast("dict[str, QPushButton]", buttons).items():
        assert btn.isEnabled(), f"Button '{label}' for provider '{provider_id}' must be enabled"
        assert btn.text() == label, f"Button for '{provider_id}' / '{label}' has wrong label text: '{btn.text()}'"
        url_recorder.urls.clear()
        btn.click()
        QApplication.processEvents()
        assert url_recorder.urls, f"Qt did not route a URL for '{provider_id}' / '{label}'"
        assert url_recorder.urls[-1] == expected[label], (
            f"Provider '{provider_id}' / '{label}': got '{url_recorder.urls[-1]}', expected '{expected[label]}'"
        )
