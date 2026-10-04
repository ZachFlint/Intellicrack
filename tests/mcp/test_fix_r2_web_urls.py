# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, item 21: only the URL rebuilt from its parts reaches the platform's URL handler.

``urlsplit`` drops leading control characters and spaces and takes whatever sits between ``//`` and the path as the host, so the string a
server sent could pass the scheme check and still reach ``ShellExecute`` with a NUL in front or a UNC path for a host. The gates hand
``open_web_url`` and the OAuth sign-in path such strings and read what the browser launcher was given: the rebuilt URL, or nothing.
"""

from __future__ import annotations

import asyncio
import webbrowser

import pytest

from intellicrack.mcp.auth import open_authorization_page
from intellicrack.mcp.errors import McpAuthError
from intellicrack.mcp.transport import is_web_url, open_web_url


class _RecordingBrowser:
    """Stands in for the platform browser so nothing is launched on the test machine.

    Attributes:
        opened: Every URL handed to the browser.
    """

    opened: list[str]

    def __init__(self) -> None:
        """Start with nothing opened."""
        self.opened = []

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
        monkeypatch: Replaces the browser launcher.

    Returns:
        _RecordingBrowser: The installed recorder.
    """
    recorder = _RecordingBrowser()
    monkeypatch.setattr(webbrowser, "open", recorder.open)
    return recorder


@pytest.mark.parametrize(
    ("sent", "launched"),
    [
        ("\x00http://a", "http://a"),
        (" http://x", "http://x"),
        ("\thttps://auth.example/authorize?client_id=abc&state=x y", "https://auth.example/authorize?client_id=abc&state=x%20y"),
        ('HTTPS://Auth.Example:8443/a b?q="<x>"#f g', "https://auth.example:8443/a%20b?q=%22%3Cx%3E%22#f%20g"),
        ("https://auth.example/p?x=%zz", "https://auth.example/p?x=%25zz"),
        ("http://[::1]:8080/cb", "http://[::1]:8080/cb"),
        (f"https://b{chr(252)}cher.example/", "https://xn--bcher-kva.example/"),
        ("http://host_name.example./ok", "http://host_name.example./ok"),
    ],
    ids=["leading-nul", "leading-space", "tab-and-space", "case-quotes-angles", "stray-percent", "ipv6", "unicode-host", "underscore-host"],
)
def test_browser_gets_the_rebuilt_url(browser: _RecordingBrowser, sent: str, launched: str) -> None:
    """A URL the parser accepts is launched as rebuilt from its parts, never as the string the server sent.

    Args:
        browser: The recording browser.
        sent: The URL the server sent.
        launched: What the browser must be handed.
    """
    assert open_web_url(sent) is True
    assert browser.opened == [launched]


@pytest.mark.parametrize(
    "sent",
    ["http://\\\\evil\\share", "http://evil\\share/x", "http://a b/", "http://-bad-.example/", "https://h:99999/", "file:///C:/x.exe"],
    ids=["unc-host", "backslash-host", "space-in-host", "hyphen-edged-label", "bad-port", "file-scheme"],
)
def test_url_without_a_valid_host_is_refused(browser: _RecordingBrowser, sent: str) -> None:
    """A URL whose host is not an IP literal or a name of valid labels opens nothing.

    Args:
        browser: The recording browser.
        sent: The URL the server sent.
    """
    assert not is_web_url(sent)
    assert open_web_url(sent) is False
    assert browser.opened == []


def test_sign_in_opens_the_rebuilt_url(browser: _RecordingBrowser) -> None:
    """The OAuth sign-in page is opened as rebuilt, and a UNC host is refused before anything opens.

    Args:
        browser: The recording browser.
    """
    asyncio.run(open_authorization_page("\x00 https://auth.example/authorize?response_type=code&state=a b"))
    assert browser.opened == ["https://auth.example/authorize?response_type=code&state=a%20b"]
    with pytest.raises(McpAuthError, match="not a web address"):
        asyncio.run(open_authorization_page("https://\\\\evil\\share\\payload.exe"))
    assert len(browser.opened) == 1
