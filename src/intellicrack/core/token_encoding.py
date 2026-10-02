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
subsequent ``get_encoding`` is a local file read. Resolving the server's name counts against the connect deadline too, since the system
resolver takes no timeout of its own. When ``TIKTOKEN_CACHE_DIR`` is set to an empty string, which turns ``tiktoken``'s cache off, the
files are fetched the same way into a temporary directory that is removed once the encoding is built from it. Loading runs on a daemon worker thread, one per encoding, so a caller waits only as long
as it chooses -- the GUI thread does not wait at all. And a failed load is remembered for :data:`RETRY_AFTER_S` before it is attempted
again, so an offline machine pays for the failure once rather than on every count.

A caller that gets no encoder back counts with :func:`estimate_tokens_without_encoder`, a deliberate overestimate.
"""

from __future__ import annotations

import hashlib
import importlib
import ipaddress
import math
import os
import socket
import tempfile
import threading
import time
import types
import urllib.request
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final, cast, override
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpcore
import httpx
import tiktoken
import tiktoken.load

from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    import ssl
    from collections.abc import Iterable, Mapping

    from httpcore import NetworkStream
    from httpcore._backends.base import SOCKET_OPTION


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

MAX_REDIRECTS: Final[int] = 5
"""Most redirects one BPE download follows."""

_REDIRECT_STATUSES: Final[frozenset[int]] = frozenset({301, 302, 303, 307, 308})
_SUCCESS_STATUSES: Final[range] = range(200, 300)
_CONSTRUCTOR_MODULE: Final[str] = "tiktoken_ext.openai_public"

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


type AddressResolver = Callable[[str, int], Sequence[str]]
"""Resolves a host and port to the addresses to try, in order."""


def resolve_addresses(host: str, port: int) -> list[str]:
    """Resolve a host through the system resolver.

    Args:
        host: The host name.
        port: The port to connect to.

    Returns:
        list[str]: The distinct addresses, in the resolver's order.
    """
    found = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(str(entry[4][0]) for entry in found))


def _resolve_within(resolve: AddressResolver, host: str, port: int, timeout: float | None) -> Sequence[str]:
    """Resolve a host, giving up once the connect timeout has passed.

    The system resolver cannot be interrupted, so a lookup that outlives the
    timeout is left to finish on its daemon thread and its answer dropped.

    Args:
        resolve: The resolver.
        host: The host name or address literal.
        port: The port to connect to.
        timeout: Longest the lookup may take; ``None`` waits for it.

    Returns:
        Sequence[str]: The addresses to try.

    Raises:
        httpcore.ConnectTimeout: When the lookup takes longer than ``timeout``.
        httpcore.ConnectError: When the lookup fails or finds nothing.
    """
    try:
        return [str(ipaddress.ip_address(host.strip("[]")))]
    except ValueError:
        pass
    found: list[str] = []
    failures: list[OSError] = []
    done = threading.Event()

    def lookup() -> None:
        """Run the lookup and record what it found."""
        try:
            found.extend(resolve(host, port))
        except OSError as exc:
            failures.append(exc)
        finally:
            done.set()

    threading.Thread(target=lookup, name=f"resolve-{host}", daemon=True).start()
    if not done.wait(timeout) and timeout is not None:
        message = f"resolving {host} took longer than {timeout:g}s"
        raise httpcore.ConnectTimeout(message)
    if failures or not found:
        message = f"could not resolve {host}: {failures[0] if failures else 'no addresses'}"
        raise httpcore.ConnectError(message)
    return found


class _BoundedResolutionBackend(httpcore.SyncBackend):
    """Opens connections whose name lookup counts against the connect timeout."""

    def __init__(self, resolve: AddressResolver) -> None:
        """Use a resolver.

        Args:
            resolve: Resolves each host before it is connected to.
        """
        super().__init__()
        self._resolve = resolve

    @override
    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[SOCKET_OPTION] | None = None,
    ) -> NetworkStream:
        """Resolve a host within the timeout, then connect to the first address that answers.

        Args:
            host: The host to connect to.
            port: The port.
            timeout: Longest the lookup and connection may take together.
            local_address: Address to bind locally, if any.
            socket_options: Options to set on the socket.

        Returns:
            NetworkStream: The connected stream.

        Raises:
            httpcore.ConnectTimeout: When the timeout passes first.
            httpcore.ConnectError: When no address can be connected to.
        """
        started = time.monotonic()
        errors: list[str] = []
        for address in _resolve_within(self._resolve, host, port, timeout):
            remaining: float | None = None
            if timeout is not None:
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0:
                    message = f"connecting to {host}:{port} took longer than {timeout:g}s"
                    raise httpcore.ConnectTimeout(message)
            try:
                return super().connect_tcp(address, port, remaining, local_address, socket_options)
            except httpcore.ConnectError as exc:
                errors.append(f"{address}: {exc}")
        message = f"could not connect to {host}:{port}: {'; '.join(errors)}"
        raise httpcore.ConnectError(message)


def _proxy_for(url: str) -> str | None:
    """Pick the proxy a URL is fetched through, as ``httpx`` and ``urllib`` read the environment and system settings.

    Args:
        url: The URL to fetch.

    Returns:
        str | None: The proxy URL, or ``None`` to connect directly.
    """
    parts = urlsplit(url)
    proxies = urllib.request.getproxies()
    proxy = proxies.get(parts.scheme) or proxies.get("all")
    if not proxy or urllib.request.proxy_bypass(parts.hostname or ""):
        return None
    return proxy if "://" in proxy else f"http://{proxy}"


def _connection_pool(
    url: str,
    ssl_context: ssl.SSLContext,
    backend: httpcore.SyncBackend,
) -> httpcore.ConnectionPool:
    """Build the connection pool one request goes through, direct or by its proxy.

    Args:
        url: The URL to fetch.
        ssl_context: TLS settings for the server.
        backend: Opens the connections.

    Returns:
        httpcore.ConnectionPool: The pool.
    """
    proxy = _proxy_for(url)
    if proxy is None:
        return httpcore.ConnectionPool(ssl_context=ssl_context, network_backend=backend)
    parts = urlsplit(proxy)
    auth = (parts.username or "", parts.password or "") if parts.username is not None else None
    bare = urlunsplit((parts.scheme, parts.netloc.rpartition("@")[2], parts.path, parts.query, parts.fragment))
    if parts.scheme.startswith("socks"):
        return httpcore.SOCKSProxy(proxy_url=bare, proxy_auth=auth, ssl_context=ssl_context, network_backend=backend)
    return httpcore.HTTPProxy(proxy_url=bare, proxy_auth=auth, ssl_context=ssl_context, network_backend=backend)


@dataclass(frozen=True, slots=True)
class _DownloadBounds:
    """The limits one download runs under.

    Attributes:
        connect_timeout_s: Longest resolving and connecting may take.
        read_timeout_s: Longest the download may go without data.
        deadline_s: Longest the whole download may take.
        max_bytes: Largest file accepted.
    """

    connect_timeout_s: float
    read_timeout_s: float
    deadline_s: float
    max_bytes: int


def _download(url: str, bounds: _DownloadBounds, resolve: AddressResolver) -> bytes:
    """Stream one file into memory under a deadline and a size cap, following redirects.

    Args:
        url: The file to download.
        bounds: The limits the download runs under.
        resolve: Resolves each host connected to, within the connect timeout.

    Returns:
        bytes: The file's content.

    Raises:
        EncodingDownloadError: When the server refuses the file, redirects
            too often, or the file passes ``max_bytes`` or the download
            passes ``deadline_s``.
    """
    started = time.monotonic()
    backend = _BoundedResolutionBackend(resolve)
    ssl_context = httpx.create_ssl_context()
    extensions = {
        "timeout": {
            "connect": bounds.connect_timeout_s,
            "read": bounds.read_timeout_s,
            "write": bounds.read_timeout_s,
            "pool": bounds.read_timeout_s,
        },
    }
    target = url
    for _hop in range(MAX_REDIRECTS + 1):
        with _connection_pool(target, ssl_context, backend) as pool, pool.stream("GET", target, extensions=extensions) as response:
            if response.status in _REDIRECT_STATUSES:
                location = {key.lower(): value for key, value in response.headers}.get(b"location")
                if location is None:
                    message = f"{target} redirected without a location"
                    raise EncodingDownloadError(message)
                target = urljoin(target, location.decode("latin-1"))
                continue
            if response.status not in _SUCCESS_STATUSES:
                message = f"{target} answered HTTP {response.status}"
                raise EncodingDownloadError(message)
            chunks: list[bytes] = []
            received = 0
            for chunk in response.iter_stream():
                received += len(chunk)
                if received > bounds.max_bytes:
                    message = f"{url} exceeded {bounds.max_bytes} bytes"
                    raise EncodingDownloadError(message)
                if time.monotonic() - started > bounds.deadline_s:
                    message = f"{url} did not finish within {bounds.deadline_s:g}s"
                    raise EncodingDownloadError(message)
                chunks.append(chunk)
            return b"".join(chunks)
    message = f"{url} redirected more than {MAX_REDIRECTS} times"
    raise EncodingDownloadError(message)


_TRANSFER_ERRORS: Final[tuple[type[Exception], ...]] = (
    httpcore.TimeoutException,
    httpcore.NetworkError,
    httpcore.ProtocolError,
    httpcore.ProxyError,
    httpcore.UnsupportedProtocol,
)


def fetch_encoding_source(
    source: EncodingSource,
    cache_dir: Path,
    *,
    connect_timeout_s: float = CONNECT_TIMEOUT_S,
    read_timeout_s: float = READ_TIMEOUT_S,
    deadline_s: float = DOWNLOAD_DEADLINE_S,
    max_bytes: int = MAX_ENCODING_BYTES,
    resolve: AddressResolver = resolve_addresses,
) -> Path:
    """Place one verified encoding file in the ``tiktoken`` cache.

    A cache entry that is already present and intact is used as-is. Otherwise
    the file is streamed with bounded connect and read timeouts, an overall
    deadline and a size cap, verified against its digest, and written
    atomically; a staging file that could not be moved into place is
    removed.

    Args:
        source: The encoding file.
        cache_dir: The ``tiktoken`` cache directory.
        connect_timeout_s: Longest resolving the server and connecting may
            take.
        read_timeout_s: Longest the download may go without data.
        deadline_s: Longest the whole download may take.
        max_bytes: Largest file accepted.
        resolve: Resolves each host connected to, within the connect
            timeout.

    Returns:
        Path: The verified cache entry.

    Raises:
        EncodingDownloadError: When the download fails, stalls, overruns its
            deadline or size cap, or does not match its digest.
    """
    path = cache_path_for(source, cache_dir)
    if _is_verified(path, source.sha256):
        return path

    bounds = _DownloadBounds(connect_timeout_s, read_timeout_s, deadline_s, max_bytes)
    try:
        data = _download(source.download_url, bounds, resolve)
    except _TRANSFER_ERRORS as exc:
        message = f"{source.download_url} could not be downloaded: {exc}"
        raise EncodingDownloadError(message) from exc

    if hashlib.sha256(data).hexdigest() != source.sha256:
        message = f"{source.download_url} does not match its expected SHA-256 digest"
        raise EncodingDownloadError(message)

    cache_dir.mkdir(parents=True, exist_ok=True)
    staging = path.with_name(f"{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        _ = staging.write_bytes(data)
        _ = staging.replace(path)
    finally:
        staging.unlink(missing_ok=True)
    return path


def _staged_constructor(name: str, staged: Mapping[str, Path]) -> Callable[[], dict[str, Any]]:
    """Rebuild ``tiktoken``'s constructor for an encoding so it reads local copies of its files.

    ``tiktoken_ext.openai_public`` names each file by URL and looks its two
    loaders up as module globals when a constructor runs. The copy returned
    here runs the same code over a copy of those globals whose loaders read
    the file downloaded for each URL instead, so the encoding's pattern and
    special tokens still come from ``tiktoken`` itself.

    Args:
        name: An encoding ``tiktoken_ext.openai_public`` constructs.
        staged: The local copy of each file, by the URL ``tiktoken`` names it by.

    Returns:
        Callable[[], dict[str, Any]]: The constructor, returning the
        keyword arguments of :class:`tiktoken.Encoding`.
    """

    def local(value: object) -> object:
        """Swap a staged URL for its local copy.

        Args:
            value: An argument a constructor passes to a loader.

        Returns:
            object: The local path, or the argument unchanged.
        """
        return str(staged[value]) if isinstance(value, str) and value in staged else value

    def redirected(loader: Callable[..., dict[bytes, int]]) -> Callable[..., dict[bytes, int]]:
        """Wrap a loader so it reads the local copies.

        Args:
            loader: The ``tiktoken.load`` function.

        Returns:
            Callable[..., dict[bytes, int]]: The wrapped loader.
        """

        def call(*args: object, **kwargs: object) -> dict[bytes, int]:
            """Call the loader with each staged URL swapped for its local copy.

            Args:
                *args: Positional arguments.
                **kwargs: Keyword arguments.

            Returns:
                dict[bytes, int]: The mergeable ranks.
            """
            return loader(*(local(arg) for arg in args), **{key: local(arg) for key, arg in kwargs.items()})

        return call

    module = importlib.import_module(_CONSTRUCTOR_MODULE)
    constructors = cast("Mapping[str, types.FunctionType]", vars(module)["ENCODING_CONSTRUCTORS"])
    namespace: dict[str, object] = dict(vars(module))
    namespace["load_tiktoken_bpe"] = redirected(tiktoken.load.load_tiktoken_bpe)
    namespace["data_gym_to_mergeable_bpe_ranks"] = redirected(tiktoken.load.data_gym_to_mergeable_bpe_ranks)
    for key, value in vars(module).items():
        if isinstance(value, types.FunctionType) and value.__module__ == module.__name__:
            namespace[key] = types.FunctionType(value.__code__, namespace, value.__name__, value.__defaults__, value.__closure__)
    return cast("Callable[[], dict[str, Any]]", namespace[constructors[name].__name__])


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
        resolve: AddressResolver = resolve_addresses,
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
            resolve: Resolves each download server, within the connect
                timeout.
        """
        self._default_name = default_name
        self._sources = sources
        self._connect_timeout_s = connect_timeout_s
        self._read_timeout_s = read_timeout_s
        self._deadline_s = deadline_s
        self._retry_after_s = retry_after_s
        self._resolve = resolve
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
            with tempfile.TemporaryDirectory(prefix="intellicrack-tiktoken-") as staging:
                staged = {source.cache_url: self._fetch(source, Path(staging)) for source in sources}
                return tiktoken.Encoding(**_staged_constructor(name, staged)())
        if cache_dir is not None:
            for source in sources:
                _ = self._fetch(source, cache_dir)
        return tiktoken.get_encoding(name)

    def _fetch(self, source: EncodingSource, directory: Path) -> Path:
        """Fetch one encoding file under this loader's download bounds.

        Args:
            source: The file.
            directory: Where to place it.

        Returns:
            Path: The verified file.
        """
        return fetch_encoding_source(
            source,
            directory,
            connect_timeout_s=self._connect_timeout_s,
            read_timeout_s=self._read_timeout_s,
            deadline_s=self._deadline_s,
            resolve=self._resolve,
        )


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
