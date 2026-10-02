# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, item 20: encoding downloads leave no staging files, bound the name lookup, and stay bounded with tiktoken's cache turned off.

The gates run the real downloader and loader against real loopback servers. A staging file that cannot be moved into place is removed;
a name lookup that never answers is given up on within the connect timeout; a looked-up address is what gets connected to; and with
``TIKTOKEN_CACHE_DIR`` set to an empty string the files are still fetched under the download bounds, the encoding is built from them, and
the temporary copies are removed.
"""

from __future__ import annotations

import hashlib
import tempfile
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest
import tiktoken

from intellicrack.core.token_encoding import (
    DEFAULT_ENCODING_NAME,
    TIKTOKEN_SOURCES,
    EncodingDownloadError,
    EncodingSource,
    TokenEncodingLoader,
    cache_path_for,
    fetch_encoding_source,
    tiktoken_cache_dir,
)
from tests._helpers.stalling_http import ScriptedHttpServer, StallingServer


if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence


_O200K: Final[EncodingSource] = TIKTOKEN_SOURCES[DEFAULT_ENCODING_NAME][0]
_CONNECT_TIMEOUT_S: Final[float] = 1.0
_READ_TIMEOUT_S: Final[float] = 0.5
_DEADLINE_S: Final[float] = 1.5
_SCHEDULING_SLACK_S: Final[float] = 3.0
"""Allowance for thread start-up on a loaded machine; the regression waits for the whole stalled lookup."""
_STALLED_LOOKUP_S: Final[float] = 15.0
_LOOKUP_HOST: Final[str] = "encodings.test"
_PAYLOAD: Final[bytes] = b"token-table-" * 100
_SAMPLE: Final[str] = "Disassemble the entry point and list every import."


def _source(fetch_url: str, *, name: str = "demo") -> EncodingSource:
    """Describe a file whose content is :data:`_PAYLOAD`.

    Args:
        fetch_url: Where it is downloaded from.
        name: Distinguishes its cache key.

    Returns:
        EncodingSource: The source.
    """
    return EncodingSource(
        cache_url=f"https://example.invalid/encodings/{name}.tiktoken",
        sha256=hashlib.sha256(_PAYLOAD).hexdigest(),
        fetch_url=fetch_url,
    )


class _StalledResolver:
    """A name lookup that does not answer until it is released, as a resolver behind a dead DNS server does not.

    Attributes:
        asked: The hosts it was asked for.
    """

    asked: list[str]

    def __init__(self) -> None:
        """Start stalled."""
        self.asked = []
        self._released = threading.Event()

    def __call__(self, host: str, port: int) -> Sequence[str]:
        """Wait to be released, then fail as a timed-out lookup does.

        Args:
            host: The host asked for.
            port: The port.

        Returns:
            Sequence[str]: Never returns.

        Raises:
            OSError: Once released, as the resolver finally gives up.
        """
        self.asked.append(f"{host}:{port}")
        _ = self._released.wait(_STALLED_LOOKUP_S)
        message = f"lookup of {host} timed out"
        raise OSError(message)

    def release(self) -> None:
        """Let any waiting lookup finish."""
        self._released.set()


@pytest.fixture
def stalled_resolver() -> Iterator[_StalledResolver]:
    """Provide a stalled resolver, released after the test.

    Yields:
        _StalledResolver: The resolver.
    """
    resolver = _StalledResolver()
    try:
        yield resolver
    finally:
        resolver.release()


@pytest.fixture
def direct_to_lookup_host(monkeypatch: pytest.MonkeyPatch) -> None:
    """Configure proxies from the environment only, with the lookup host bypassing them.

    Args:
        monkeypatch: Environment patcher.
    """
    for name in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.setenv(name, f"{_LOOKUP_HOST},127.0.0.1,localhost")


def test_staging_file_is_removed_when_it_cannot_be_moved_into_place(tmp_path: Path) -> None:
    """A verified download whose cache entry cannot be replaced leaves no ``.tmp`` file behind.

    Args:
        tmp_path: Per-test directory.
    """
    cache_dir = tmp_path / "cache"
    with ScriptedHttpServer(status=200, body=_PAYLOAD) as server:
        source = _source(server.url)
        blocking = cache_path_for(source, cache_dir)
        blocking.mkdir(parents=True)
        (blocking / "occupant").write_bytes(b"x")
        with pytest.raises(OSError, match=r".") as raised:
            _ = fetch_encoding_source(source, cache_dir, connect_timeout_s=_CONNECT_TIMEOUT_S, read_timeout_s=_READ_TIMEOUT_S)
    assert not isinstance(raised.value, EncodingDownloadError)
    assert sorted(item.name for item in cache_dir.iterdir()) == [blocking.name]


def test_name_lookup_counts_against_the_connect_timeout(stalled_resolver: _StalledResolver, direct_to_lookup_host: None) -> None:
    """A lookup that never answers ends the download within the connect timeout.

    Args:
        stalled_resolver: A resolver that does not answer.
        direct_to_lookup_host: No proxy stands between the download and the lookup host.
    """
    del direct_to_lookup_host
    started = time.perf_counter()
    with pytest.raises(EncodingDownloadError, match="took longer than"):
        _ = fetch_encoding_source(
            _source(f"http://{_LOOKUP_HOST}:8080/demo.tiktoken"),
            Path(tempfile.gettempdir()) / "never-written",
            connect_timeout_s=_CONNECT_TIMEOUT_S,
            read_timeout_s=_READ_TIMEOUT_S,
            resolve=stalled_resolver,
        )
    assert time.perf_counter() - started < _CONNECT_TIMEOUT_S + _SCHEDULING_SLACK_S
    assert stalled_resolver.asked == [f"{_LOOKUP_HOST}:8080"]


def test_looked_up_address_is_the_one_connected_to(tmp_path: Path, direct_to_lookup_host: None) -> None:
    """The download connects to the address the resolver gave for the host.

    Args:
        tmp_path: Per-test directory.
        direct_to_lookup_host: No proxy stands between the download and the lookup host.
    """
    del direct_to_lookup_host
    asked: list[str] = []

    def loopback(host: str, port: int) -> list[str]:
        """Resolve every host to loopback, noting what was asked.

        Args:
            host: The host.
            port: The port.

        Returns:
            list[str]: The loopback address.
        """
        asked.append(host)
        del port
        return ["127.0.0.1"]

    with ScriptedHttpServer(status=200, body=_PAYLOAD) as server:
        port = server.url.rsplit(":", 1)[1].split("/", 1)[0]
        path = fetch_encoding_source(_source(f"http://{_LOOKUP_HOST}:{port}/demo.tiktoken"), tmp_path, resolve=loopback)
        assert server.requests == 1
    assert path.read_bytes() == _PAYLOAD
    assert asked == [_LOOKUP_HOST]


def _turn_cache_off(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Turn ``tiktoken``'s cache off and give temporary files a directory of their own.

    Args:
        tmp_path: Per-test directory.
        monkeypatch: Environment patcher.

    Returns:
        Path: The directory temporary files go to.
    """
    scratch = tmp_path / "tmp"
    scratch.mkdir()
    monkeypatch.setenv("TIKTOKEN_CACHE_DIR", "")
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    return scratch


@pytest.fixture
def cache_off(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Turn ``tiktoken``'s cache off and give temporary files a directory of their own.

    Args:
        tmp_path: Per-test directory.
        monkeypatch: Environment patcher.

    Returns:
        Path: The directory temporary files go to.
    """
    return _turn_cache_off(tmp_path, monkeypatch)


def test_disabled_cache_still_downloads_under_the_bounds(cache_off: Path) -> None:
    """With the cache off, a stalled server is given up on within the bounds instead of left to ``tiktoken``'s unbounded download.

    Args:
        cache_off: Where temporary files go.
    """
    with StallingServer() as server:
        source = EncodingSource(cache_url=_O200K.cache_url, sha256=_O200K.sha256, fetch_url=f"{server.url}/o200k_base.tiktoken")
        loader = TokenEncodingLoader(
            sources={DEFAULT_ENCODING_NAME: (source,)},
            connect_timeout_s=_CONNECT_TIMEOUT_S,
            read_timeout_s=_READ_TIMEOUT_S,
            deadline_s=_DEADLINE_S,
        )
        started = time.perf_counter()
        assert loader.get(None, timeout=_CONNECT_TIMEOUT_S + _READ_TIMEOUT_S + _SCHEDULING_SLACK_S) is None
        assert time.perf_counter() - started < _CONNECT_TIMEOUT_S + _READ_TIMEOUT_S + _SCHEDULING_SLACK_S
        assert loader.is_backing_off(None)
        assert server.connections == 1
    assert list(cache_off.iterdir()) == []


def _real_o200k(tmp_path: Path) -> bytes:
    """Read the real ``o200k_base`` file from this machine's cache, downloading it under the bounds when it is not there.

    Args:
        tmp_path: Where to download it to when it is not cached.

    Returns:
        bytes: The verified file.
    """
    cache_dir = tiktoken_cache_dir()
    cached = cache_path_for(_O200K, cache_dir) if cache_dir is not None else None
    path = cached if cached is not None and cached.is_file() else fetch_encoding_source(_O200K, tmp_path / "download")
    data = path.read_bytes()
    assert hashlib.sha256(data).hexdigest() == _O200K.sha256
    return data


def test_disabled_cache_builds_the_encoding_and_removes_the_copies(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """With the cache off, the encoding is built from the bounded download, counts as ``tiktoken``'s does, and leaves no files.

    Args:
        tmp_path: Per-test directory.
        monkeypatch: Environment patcher.
    """
    data = _real_o200k(tmp_path)
    reference = tmp_path / "reference"
    reference.mkdir()
    _ = cache_path_for(_O200K, reference).write_bytes(data)
    monkeypatch.setenv("TIKTOKEN_CACHE_DIR", str(reference))
    expected = tiktoken.get_encoding(DEFAULT_ENCODING_NAME).encode(_SAMPLE)
    scratch = _turn_cache_off(tmp_path, monkeypatch)
    with ScriptedHttpServer(status=200, body=data) as server:
        source = EncodingSource(cache_url=_O200K.cache_url, sha256=_O200K.sha256, fetch_url=server.url)
        loader = TokenEncodingLoader(sources={DEFAULT_ENCODING_NAME: (source,)}, connect_timeout_s=_CONNECT_TIMEOUT_S)
        encoder = loader.get(None, timeout=60.0)
        assert server.requests == 1
    assert encoder is not None
    assert encoder.name == DEFAULT_ENCODING_NAME
    assert encoder.encode(_SAMPLE) == expected
    assert encoder.decode(encoder.encode(_SAMPLE)) == _SAMPLE
    assert list(scratch.iterdir()) == []
