# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Loading ``tiktoken`` encodings without letting the network hold up a caller.

``tiktoken.get_encoding`` downloads an encoding's BPE file the first time it is used on a machine, through ``requests.get`` with no timeout,
while holding ``tiktoken``'s process-wide registry lock. A stalled connection therefore blocks the caller, and every other caller of
``get_encoding``, for as long as the socket stays open, and a failed download is retried from scratch on the very next call.

This module puts three bounds around that. The BPE files of the encodings ``tiktoken`` ships are fetched here first, with connect, read
and overall deadlines and a size cap, and written into the cache directory ``tiktoken`` itself reads, under the key it computes, so the
subsequent ``get_encoding`` is a local file read. Loading runs on a daemon worker thread, one per encoding, so a caller waits only as long
as it chooses -- the GUI thread does not wait at all. And a failed load is remembered for :data:`RETRY_AFTER_S` before it is attempted
again, so an offline machine pays for the failure once rather than on every count.

A caller that gets no encoder back counts with :func:`estimate_tokens_without_encoder`, a deliberate overestimate.
"""

from __future__ import annotations

import hashlib
import math
import os
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

import httpx
import tiktoken

from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from collections.abc import Mapping


_logger = get_logger(__name__)


DEFAULT_ENCODING_NAME: Final[str] = "o200k_base"
"""Encoding used when a caller names none, or names one ``tiktoken`` does not know."""

CONNECT_TIMEOUT_S: Final[float] = 10.0
"""Longest a BPE download may take to connect."""

READ_TIMEOUT_S: Final[float] = 15.0
"""Longest a BPE download may go without receiving data."""

DOWNLOAD_DEADLINE_S: Final[float] = 120.0
"""Longest one BPE file download may take in total, however steadily it trickles."""

MAX_ENCODING_BYTES: Final[int] = 64 * 1024 * 1024
"""Largest BPE file accepted; the biggest ``tiktoken`` ships is under 4 MiB."""

RETRY_AFTER_S: Final[float] = 300.0
"""How long a failed load is remembered before it is attempted again."""

OFF_GUI_THREAD_WAIT_S: Final[float] = 2.0
"""How long a caller that is not the GUI thread waits for a first load.

A cached encoding loads well within this; a download that has not finished by then carries on in the background while the caller
estimates.
"""

ESTIMATE_BYTES_PER_TOKEN: Final[int] = 1
"""UTF-8 bytes per token assumed when no encoder is available.

Every byte-level BPE token covers at least one byte, so this is a true upper bound whatever the text: prose averages three to four bytes
per token, but addresses, hex dumps and indentation-heavy code come close to one. A context-window check made without the encoder
therefore errs toward trimming, never toward overflowing.
"""

_OPENAI_PUBLIC: Final[str] = "https://openaipublic.blob.core.windows.net"


@dataclass(frozen=True, slots=True)
class EncodingSource:
    """One file an encoding is built from.

    Attributes:
        cache_url: The URL ``tiktoken`` itself loads the file from, which is
            also the key of its cache entry.
        sha256: The file's expected SHA-256 digest, as ``tiktoken`` checks it.
        fetch_url: Where to download the file from instead, such as an
            internal mirror; ``None`` downloads from ``cache_url``.
    """

    cache_url: str
    sha256: str
    fetch_url: str | None = None

    @property
    def download_url(self) -> str:
        """The URL the file is actually downloaded from.

        Returns:
            str: ``fetch_url`` when set, otherwise ``cache_url``.
        """
        return self.fetch_url or self.cache_url


_R50K: Final[EncodingSource] = EncodingSource(
    f"{_OPENAI_PUBLIC}/encodings/r50k_base.tiktoken",
    "306cd27f03c1a714eca7108e03d66b7dc042abe8c258b44c199a7ed9838dd930",
)
_P50K: Final[EncodingSource] = EncodingSource(
    f"{_OPENAI_PUBLIC}/encodings/p50k_base.tiktoken",
    "94b5ca7dff4d00767bc256fdd1b27e5b17361d7b8a5f968547f9f23eb70d2069",
)
_CL100K: Final[EncodingSource] = EncodingSource(
    f"{_OPENAI_PUBLIC}/encodings/cl100k_base.tiktoken",
    "223921b76ee99bde995b7ff738513eef100fb51d18c93597a113bcffe865b2a7",
)
_O200K: Final[EncodingSource] = EncodingSource(
    f"{_OPENAI_PUBLIC}/encodings/o200k_base.tiktoken",
    "446a9538cb6c348e3516120d7c08b09f57c36495e2acfffe59a5bf8b0cfb1a2d",
)

TIKTOKEN_SOURCES: Final[Mapping[str, tuple[EncodingSource, ...]]] = MappingProxyType({
    "gpt2": (
        EncodingSource(
            f"{_OPENAI_PUBLIC}/gpt-2/encodings/main/vocab.bpe",
            "1ce1664773c50f3e0cc8842619a93edc4624525b728b188a9e0be33b7726adc5",
        ),
        EncodingSource(
            f"{_OPENAI_PUBLIC}/gpt-2/encodings/main/encoder.json",
            "196139668be63f3b5d6574427317ae82f612a97c5d1cdaf36ed2256dbf636783",
        ),
    ),
    "r50k_base": (_R50K,),
    "p50k_base": (_P50K,),
    "p50k_edit": (_P50K,),
    "cl100k_base": (_CL100K,),
    "o200k_base": (_O200K,),
    "o200k_harmony": (_O200K,),
})
"""The files each encoding bundled with ``tiktoken`` is built from, as ``tiktoken_ext.openai_public`` names them."""


class EncodingDownloadError(OSError):
    """A BPE file could not be downloaded within its bounds, or did not verify."""


def tiktoken_cache_dir() -> Path | None:
    """Locate the directory ``tiktoken`` caches downloaded files in.

    This follows ``tiktoken.load.read_file_cached`` exactly, so a file
    written here is the file ``tiktoken`` reads.

    Returns:
        Path | None: The cache directory, or ``None`` when caching is
        disabled by setting ``TIKTOKEN_CACHE_DIR`` to an empty string.
    """
    if "TIKTOKEN_CACHE_DIR" in os.environ:
        configured = os.environ["TIKTOKEN_CACHE_DIR"]
    elif "DATA_GYM_CACHE_DIR" in os.environ:
        configured = os.environ["DATA_GYM_CACHE_DIR"]
    else:
        configured = str(Path(tempfile.gettempdir()) / "data-gym-cache")
    return Path(configured) if configured else None


def cache_path_for(source: EncodingSource, cache_dir: Path) -> Path:
    """Name the cache file ``tiktoken`` reads one source from.

    Args:
        source: The encoding file.
        cache_dir: The ``tiktoken`` cache directory.

    Returns:
        Path: The cache entry, keyed by the SHA-1 of ``source.cache_url``.
    """
    return cache_dir / hashlib.sha1(source.cache_url.encode(), usedforsecurity=False).hexdigest()


def _is_verified(path: Path, sha256: str) -> bool:
    """Check whether a cached file exists and carries the expected digest.

    Args:
        path: The cache entry.
        sha256: The expected SHA-256 digest.

    Returns:
        bool: ``True`` when the file is present and intact.
    """
    try:
        data = path.read_bytes()
    except OSError:
        return False
    return hashlib.sha256(data).hexdigest() == sha256


def _download(url: str, timeout: httpx.Timeout, deadline_s: float, max_bytes: int) -> bytes:
    """Stream one file into memory under a deadline and a size cap.

    Args:
        url: The file to download.
        timeout: Connect and per-read timeouts.
        deadline_s: Longest the whole download may take.
        max_bytes: Largest file accepted.

    Returns:
        bytes: The file's content.

    Raises:
        EncodingDownloadError: When the file passes ``max_bytes`` or the
            download passes ``deadline_s``.
    """
    started = time.monotonic()
    chunks: list[bytes] = []
    received = 0
    with httpx.Client(timeout=timeout, follow_redirects=True) as client, client.stream("GET", url) as response:
        _ = response.raise_for_status()
        for chunk in response.iter_bytes():
            received += len(chunk)
            if received > max_bytes:
                message = f"{url} exceeded {max_bytes} bytes"
                raise EncodingDownloadError(message)
            if time.monotonic() - started > deadline_s:
                message = f"{url} did not finish within {deadline_s:g}s"
                raise EncodingDownloadError(message)
            chunks.append(chunk)
    return b"".join(chunks)


def fetch_encoding_source(
    source: EncodingSource,
    cache_dir: Path,
    *,
    connect_timeout_s: float = CONNECT_TIMEOUT_S,
    read_timeout_s: float = READ_TIMEOUT_S,
    deadline_s: float = DOWNLOAD_DEADLINE_S,
    max_bytes: int = MAX_ENCODING_BYTES,
) -> Path:
    """Place one verified encoding file in the ``tiktoken`` cache.

    A cache entry that is already present and intact is used as-is. Otherwise
    the file is streamed with bounded connect and read timeouts, an overall
    deadline and a size cap, verified against its digest, and written
    atomically.

    Args:
        source: The encoding file.
        cache_dir: The ``tiktoken`` cache directory.
        connect_timeout_s: Longest the connection may take.
        read_timeout_s: Longest the download may go without data.
        deadline_s: Longest the whole download may take.
        max_bytes: Largest file accepted.

    Returns:
        Path: The verified cache entry.

    Raises:
        EncodingDownloadError: When the download fails, stalls, overruns its
            deadline or size cap, or does not match its digest.
    """
    path = cache_path_for(source, cache_dir)
    if _is_verified(path, source.sha256):
        return path

    timeout = httpx.Timeout(read_timeout_s, connect=connect_timeout_s)
    try:
        data = _download(source.download_url, timeout, deadline_s, max_bytes)
    except httpx.HTTPError as exc:
        message = f"{source.download_url} could not be downloaded: {exc}"
        raise EncodingDownloadError(message) from exc

    if hashlib.sha256(data).hexdigest() != source.sha256:
        message = f"{source.download_url} does not match its expected SHA-256 digest"
        raise EncodingDownloadError(message)

    cache_dir.mkdir(parents=True, exist_ok=True)
    staging = path.with_name(f"{path.name}.{uuid.uuid4().hex}.tmp")
    _ = staging.write_bytes(data)
    _ = staging.replace(path)
    return path


def estimate_tokens_without_encoder(text: str) -> int:
    """Estimate a token count when no encoder is available.

    Args:
        text: The text to count.

    Returns:
        int: ``0`` for empty text, otherwise an overestimate of at least one.
    """
    if not text:
        return 0
    return max(1, math.ceil(len(text.encode("utf-8", errors="surrogatepass")) / ESTIMATE_BYTES_PER_TOKEN))


class TokenEncodingLoader:
    """Loads ``tiktoken`` encodings in the background and caches the outcome.

    Every load runs on its own daemon thread, at most one per encoding at a
    time. :meth:`get` returns the encoder as soon as it is loaded and ``None``
    until then, waiting only as long as the caller allows. A load that fails
    is not attempted again for ``retry_after_s``.
    """

    def __init__(
        self,
        *,
        default_name: str = DEFAULT_ENCODING_NAME,
        sources: Mapping[str, tuple[EncodingSource, ...]] = TIKTOKEN_SOURCES,
        connect_timeout_s: float = CONNECT_TIMEOUT_S,
        read_timeout_s: float = READ_TIMEOUT_S,
        deadline_s: float = DOWNLOAD_DEADLINE_S,
        retry_after_s: float = RETRY_AFTER_S,
    ) -> None:
        """Configure a loader.

        Args:
            default_name: Encoding substituted for a name ``tiktoken`` does
                not know.
            sources: The files each encoding needs, fetched under the
                download bounds before ``tiktoken`` loads the encoding.
            connect_timeout_s: Longest a download may take to connect.
            read_timeout_s: Longest a download may go without data.
            deadline_s: Longest one file download may take in total.
            retry_after_s: How long a failed load is remembered.
        """
        self._default_name = default_name
        self._sources = sources
        self._connect_timeout_s = connect_timeout_s
        self._read_timeout_s = read_timeout_s
        self._deadline_s = deadline_s
        self._retry_after_s = retry_after_s
        self._lock = threading.Lock()
        self._encoders: dict[str, tiktoken.Encoding] = {}
        self._aliases: dict[str, str] = {}
        self._failed_at: dict[str, float] = {}
        self._pending: dict[str, threading.Event] = {}

    def get(self, name: str | None, timeout: float = 0.0) -> tiktoken.Encoding | None:
        """Return an encoder, starting its load if needed.

        Args:
            name: The encoding name, or ``None`` for the default.
            timeout: Longest to wait for a load in progress; ``0`` never
                waits, which is what the GUI thread must pass.

        Returns:
            tiktoken.Encoding | None: The encoder, or ``None`` while it is
            still loading, or for :data:`RETRY_AFTER_S` after a load failed.
        """
        requested = name or self._default_name
        with self._lock:
            event = self._start_locked(requested)
        if event is not None and timeout > 0:
            _ = event.wait(timeout)
        with self._lock:
            return self._encoders.get(self._aliases.get(requested, requested))

    def is_backing_off(self, name: str | None) -> bool:
        """Report whether a failed load of an encoding is being remembered.

        Args:
            name: The encoding name, or ``None`` for the default.

        Returns:
            bool: ``True`` while the loader will not attempt the load again.
        """
        requested = name or self._default_name
        with self._lock:
            failed = self._failed_at.get(self._aliases.get(requested, requested))
        return failed is not None and time.monotonic() - failed < self._retry_after_s

    def _start_locked(self, requested: str) -> threading.Event | None:
        """Start loading an encoding unless it is loaded, loading or backing off.

        The caller holds ``self._lock``.

        Args:
            requested: The encoding name as the caller gave it.

        Returns:
            threading.Event | None: An event set when the load finishes, or
            ``None`` when there is nothing to wait for.
        """
        resolved = self._aliases.get(requested, requested)
        if resolved in self._encoders:
            return None
        failed = self._failed_at.get(resolved)
        if failed is not None and time.monotonic() - failed < self._retry_after_s:
            return None
        pending = self._pending.get(resolved)
        if pending is not None:
            return pending
        event = threading.Event()
        self._pending[resolved] = event
        worker = threading.Thread(target=self._load, args=(resolved, event), name=f"tiktoken-load-{resolved}", daemon=True)
        worker.start()
        return event

    def _load(self, name: str, event: threading.Event) -> None:
        """Load one encoding on a worker thread and record the outcome.

        Args:
            name: The encoding to load.
            event: Set once the outcome is recorded.
        """
        try:
            if name not in tiktoken.list_encoding_names():
                self._alias_to_default(name)
                return
            encoder = self._load_encoding(name)
        except (OSError, ValueError, KeyError) as exc:
            with self._lock:
                self._failed_at[name] = time.monotonic()
            _logger.warning("token_encoding_unavailable", encoding=name, error=str(exc), retry_after_s=self._retry_after_s)
        else:
            with self._lock:
                self._encoders[name] = encoder
                _ = self._failed_at.pop(name, None)
        finally:
            with self._lock:
                _ = self._pending.pop(name, None)
            event.set()

    def _alias_to_default(self, name: str) -> None:
        """Serve an encoding ``tiktoken`` does not know with the default one.

        Args:
            name: The unknown encoding name.
        """
        _logger.warning("token_encoding_unknown", tokenizer=name, fallback=self._default_name)
        with self._lock:
            self._aliases[name] = self._default_name
            inner = self._start_locked(self._default_name)
        if inner is not None:
            _ = inner.wait(self._deadline_s + self._read_timeout_s + self._connect_timeout_s)

    def _load_encoding(self, name: str) -> tiktoken.Encoding:
        """Fetch an encoding's files under the download bounds, then load it.

        Args:
            name: An encoding ``tiktoken`` knows.

        Returns:
            tiktoken.Encoding: The loaded encoding.
        """
        sources = self._sources.get(name, ())
        cache_dir = tiktoken_cache_dir()
        if sources and cache_dir is None:
            _logger.warning("token_encoding_cache_disabled", encoding=name)
        elif cache_dir is not None:
            for source in sources:
                _ = fetch_encoding_source(
                    source,
                    cache_dir,
                    connect_timeout_s=self._connect_timeout_s,
                    read_timeout_s=self._read_timeout_s,
                    deadline_s=self._deadline_s,
                )
        return tiktoken.get_encoding(name)


_shared_loader: TokenEncodingLoader = TokenEncodingLoader()


def shared_encoding_loader() -> TokenEncodingLoader:
    """Return the process-wide loader every token counter shares.

    Returns:
        TokenEncodingLoader: The shared loader.
    """
    return _shared_loader


def get_token_encoder(name: str | None, timeout: float = 0.0) -> tiktoken.Encoding | None:
    """Return an encoder from the shared loader.

    Args:
        name: The encoding name, or ``None`` for the default.
        timeout: Longest to wait for a load in progress; ``0``, the default,
            never waits.

    Returns:
        tiktoken.Encoding | None: The encoder, or ``None`` when it is not
        available yet.
    """
    return _shared_loader.get(name, timeout)


def count_tokens(text: str, name: str | None, timeout: float = 0.0) -> int:
    """Count tokens with an encoding, estimating while it is unavailable.

    Args:
        text: The text to count.
        name: The encoding name, or ``None`` for the default.
        timeout: Longest to wait for a load in progress.

    Returns:
        int: The exact count, or :func:`estimate_tokens_without_encoder`'s
        overestimate when the encoder is not available.
    """
    if not text:
        return 0
    encoder = get_token_encoder(name, timeout)
    if encoder is None:
        return estimate_tokens_without_encoder(text)
    return len(encoder.encode(text, disallowed_special=()))
