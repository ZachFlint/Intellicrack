# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates proving a malformed URL from a server is refused, never raised on."""

from __future__ import annotations

import webbrowser

import pytest

from intellicrack.mcp.transport import is_web_url, open_web_url


_MALFORMED = ("http://[::1", "https://[fe80::1%25eth0/path", "http://[not-an-address]/")


class _RecordingBrowser:
    """Stands in for the platform browser so nothing is launched on the test machine.

    Attributes:
        opened: Every URL handed to the browser.
    """

    def __init__(self) -> None:
        """Start with nothing opened."""
        self.opened: list[str] = []

    def open(self, url: str, *_options: object) -> bool:
        """Record a URL the module asked to open.

        Args:
            url: The URL.
            *_options: Window placement and raise flags, ignored.

        Returns:
            bool: Always ``True``.
        """
        self.opened.append(url)
        return True


@pytest.fixture
def browser(monkeypatch: pytest.MonkeyPatch) -> _RecordingBrowser:
    """Route ``webbrowser.open`` to a recorder.

    Args:
        monkeypatch: Pytest fixture used to replace the browser launcher.

    Returns:
        _RecordingBrowser: The installed recorder.
    """
    recorder = _RecordingBrowser()
    monkeypatch.setattr(webbrowser, "open", recorder.open)
    return recorder


class TestMalformedUrls:
    """A URL ``urlsplit`` cannot parse is refused quietly."""

    @pytest.mark.parametrize("url", _MALFORMED)
    def test_is_not_a_web_url(self, url: str) -> None:
        """The guard reports a malformed URL as not a web URL.

        Args:
            url: The malformed URL.
        """
        assert not is_web_url(url)

    @pytest.mark.parametrize("url", _MALFORMED)
    def test_open_refuses_without_raising(self, url: str, browser: _RecordingBrowser) -> None:
        """Opening a malformed URL returns ``False`` and opens nothing.

        Args:
            url: The malformed URL.
            browser: The recording browser.
        """
        assert open_web_url(url) is False
        assert browser.opened == []

    def test_well_formed_url_still_opens(self, browser: _RecordingBrowser) -> None:
        """A good ``https`` URL still reaches the browser.

        Args:
            browser: The recording browser.
        """
        assert open_web_url("https://example.org/authorize?x=1") is True
        assert browser.opened == ["https://example.org/authorize?x=1"]
