# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates on loading ``tiktoken`` encodings with bounded downloads and remembered failures.

``tiktoken.get_encoding`` downloads its BPE file with ``requests.get`` and no
timeout, so a stalled network blocks whoever asked -- the GUI thread, when the
MCP settings dialog priced a server's tools -- and a failed download was
retried on every single call. These gates drive the real loader against real
loopback servers that stall, fail, trickle or send the wrong bytes, and drive
the real callers in child interpreters behind a proxy that never answers.
"""

from __future__ import annotations

import hashlib
import importlib.util
import re
import time
from pathlib import Path
from typing import Final

import pytest
import tiktoken

from intellicrack.core.token_encoding import (
    DEFAULT_ENCODING_NAME,
    OFF_GUI_THREAD_WAIT_S,
    TIKTOKEN_SOURCES,
    EncodingDownloadError,
    EncodingSource,
    TokenEncodingLoader,
    cache_path_for,
    estimate_tokens_without_encoder,
    fetch_encoding_source,
    tiktoken_cache_dir,
)
from tests._helpers.child_python import run_child_json
from tests._helpers.stalling_http import ScriptedHttpServer, StallingServer


_O200K: Final[EncodingSource] = TIKTOKEN_SOURCES[DEFAULT_ENCODING_NAME][0]
_READ_TIMEOUT_S: Final[float] = 0.5
_CONNECT_TIMEOUT_S: Final[float] = 1.0
_DEADLINE_S: Final[float] = 1.5
_CHILD_TIMEOUT_S: Final[float] = 240.0
_SCHEDULING_SLACK_S: Final[float] = 6.0
"""Allowance for thread start-up and scheduling on a heavily loaded machine; the regression waits forever."""


def _loader(fetch_url: str, *, retry_after_s: float = 600.0, deadline_s: float = _DEADLINE_S) -> TokenEncodingLoader:
    """Build a loader that downloads the default encoding from a loopback URL.

    Args:
        fetch_url: Where to download the default encoding's BPE file from.
        retry_after_s: How long a failure is remembered.
        deadline_s: Overall download deadline.

    Returns:
        TokenEncodingLoader: The loader.
    """
    source = EncodingSource(cache_url=_O200K.cache_url, sha256=_O200K.sha256, fetch_url=fetch_url)
    return TokenEncodingLoader(
        sources={DEFAULT_ENCODING_NAME: (source,)},
        connect_timeout_s=_CONNECT_TIMEOUT_S,
        read_timeout_s=_READ_TIMEOUT_S,
        deadline_s=deadline_s,
        retry_after_s=retry_after_s,
    )


@pytest.fixture
def empty_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point ``tiktoken``'s cache at an empty directory.

    Args:
        tmp_path: Per-test directory.
        monkeypatch: Environment patcher.

    Returns:
        Path: The empty cache directory.
    """
    cache = tmp_path / "tiktoken-cache"
    monkeypatch.setenv("TIKTOKEN_CACHE_DIR", str(cache))
    return cache


@pytest.fixture(scope="module")
def o200k_bytes() -> bytes:
    """Read the real ``o200k_base`` BPE file from this machine's ``tiktoken`` cache.

    Returns:
        bytes: The verified file.
    """
    cache_dir = tiktoken_cache_dir()
    if cache_dir is None or not cache_path_for(_O200K, cache_dir).is_file():
        pytest.skip("the real o200k_base BPE file is not in this machine's tiktoken cache")
    data = cache_path_for(_O200K, cache_dir).read_bytes()
    assert hashlib.sha256(data).hexdigest() == _O200K.sha256
    return data


def test_stalled_download_never_holds_the_caller_and_is_not_retried(empty_cache: Path) -> None:
    """A server that never answers costs a non-waiting caller nothing and is tried once.

    Args:
        empty_cache: The empty ``tiktoken`` cache.
    """
    with StallingServer() as server:
        loader = _loader(f"{server.url}/o200k_base.tiktoken")

        started = time.perf_counter()
        assert loader.get(None) is None
        assert time.perf_counter() - started < 0.2

        started = time.perf_counter()
        assert loader.get(None, timeout=_CONNECT_TIMEOUT_S + _READ_TIMEOUT_S + 3.0) is None
        assert time.perf_counter() - started < _CONNECT_TIMEOUT_S + _READ_TIMEOUT_S + 2.0
        assert loader.is_backing_off(None)
        assert server.connections == 1

        started = time.perf_counter()
        assert loader.get(None, timeout=2.0) is None
        assert time.perf_counter() - started < 0.2
        assert server.connections == 1
    assert not any(empty_cache.glob("*"))


def test_failed_download_is_remembered_then_retried_after_the_backoff(empty_cache: Path) -> None:
    """An HTTP error is cached as a failure, and the load is attempted again only once the backoff lapses.

    Args:
        empty_cache: The empty ``tiktoken`` cache.
    """
    with ScriptedHttpServer(status=503, body=b"unavailable") as server:
        loader = _loader(server.url, retry_after_s=0.5)

        assert loader.get(None, timeout=5.0) is None
        assert server.requests == 1
        for _ in range(20):
            assert loader.get(None) is None
        assert server.requests == 1

        time.sleep(0.6)
        assert loader.get(None, timeout=5.0) is None
        assert server.requests == 2
    assert not any(empty_cache.glob("*"))


def test_trickling_download_is_cut_off_at_the_deadline(empty_cache: Path) -> None:
    """A server that sends one byte at a time, never pausing past the read timeout, still hits the overall deadline.

    Args:
        empty_cache: The empty ``tiktoken`` cache.
    """
    with ScriptedHttpServer(status=200, body=b"x" * 400, chunk_size=1, chunk_delay_s=0.05) as server:
        loader = _loader(server.url, deadline_s=0.5)

        started = time.perf_counter()
        assert loader.get(None, timeout=10.0) is None
        assert time.perf_counter() - started < 3.0
        assert loader.is_backing_off(None)
    assert not any(empty_cache.glob("*"))


def test_fetch_verifies_digest_caps_size_and_writes_tiktokens_own_cache_key(tmp_path: Path) -> None:
    """The helper writes only a verified file, under the key ``tiktoken`` reads, and reuses it.

    Args:
        tmp_path: Per-test directory.
    """
    payload = b"token-table-" * 100
    cache_dir = tmp_path / "cache"
    with ScriptedHttpServer(status=200, body=payload) as server:
        good = EncodingSource(
            cache_url="https://example.invalid/encodings/demo.tiktoken",
            sha256=hashlib.sha256(payload).hexdigest(),
            fetch_url=server.url,
        )
        path = fetch_encoding_source(good, cache_dir, read_timeout_s=_READ_TIMEOUT_S, connect_timeout_s=_CONNECT_TIMEOUT_S)
        assert path == cache_dir / hashlib.sha1(good.cache_url.encode(), usedforsecurity=False).hexdigest()
        assert path.read_bytes() == payload
        assert fetch_encoding_source(good, cache_dir) == path
        assert server.requests == 1

        wrong = EncodingSource(cache_url="https://example.invalid/other", sha256="0" * 64, fetch_url=server.url)
        with pytest.raises(EncodingDownloadError, match="SHA-256"):
            _ = fetch_encoding_source(wrong, cache_dir)
        assert not cache_path_for(wrong, cache_dir).exists()

        with pytest.raises(EncodingDownloadError, match="exceeded"):
            _ = fetch_encoding_source(
                EncodingSource(cache_url="https://example.invalid/big", sha256=good.sha256, fetch_url=server.url),
                cache_dir,
                max_bytes=len(payload) // 2,
            )
    assert sorted(item.name for item in cache_dir.iterdir()) == [path.name]


def test_successful_load_serves_later_loaders_from_the_cache(empty_cache: Path, o200k_bytes: bytes) -> None:
    """A good download is verified, cached where ``tiktoken`` looks, and never fetched again.

    Args:
        empty_cache: The empty ``tiktoken`` cache.
        o200k_bytes: The real BPE file.
    """
    with ScriptedHttpServer(status=200, body=o200k_bytes) as server:
        encoder = _loader(server.url).get(None, timeout=60.0)
        assert encoder is not None
        assert encoder.name == DEFAULT_ENCODING_NAME
        assert encoder.encode("hello world") == [24912, 2375]
        assert cache_path_for(_O200K, empty_cache).read_bytes() == o200k_bytes
        assert server.requests == 1

        assert _loader(server.url).get(None, timeout=60.0) is not None
        assert server.requests == 1


def test_unknown_encoding_name_is_served_by_the_default(empty_cache: Path, o200k_bytes: bytes) -> None:
    """A tokenizer name ``tiktoken`` does not know costs accuracy, not availability.

    Args:
        empty_cache: The empty ``tiktoken`` cache.
        o200k_bytes: The real BPE file.
    """
    with ScriptedHttpServer(status=200, body=o200k_bytes) as server:
        encoder = _loader(server.url).get("vendor_private_tokenizer_v9", timeout=60.0)
    assert encoder is not None
    assert encoder.name == DEFAULT_ENCODING_NAME
    assert any(empty_cache.glob("*"))


def test_source_table_matches_the_installed_tiktoken() -> None:
    """Every URL and digest ``tiktoken`` ships is in the table, and nothing else is."""
    spec = importlib.util.find_spec("tiktoken_ext.openai_public")
    assert spec is not None
    assert spec.origin is not None
    text = Path(spec.origin).read_text(encoding="utf-8")
    shipped_urls = set(re.findall(r'"(https://[^"]+)"', text))
    shipped_hashes = set(re.findall(r'"([0-9a-f]{64})"', text))

    table_urls = {source.cache_url for sources in TIKTOKEN_SOURCES.values() for source in sources}
    table_hashes = {source.sha256 for sources in TIKTOKEN_SOURCES.values() for source in sources}

    assert table_urls == shipped_urls
    assert table_hashes == shipped_hashes
    assert set(TIKTOKEN_SOURCES) == set(tiktoken.list_encoding_names())


def test_estimate_overcounts_rather_than_undercounts(empty_cache: Path, o200k_bytes: bytes) -> None:
    """The fallback estimate is never below the real count, on prose, code or CJK text.

    Args:
        empty_cache: The empty ``tiktoken`` cache.
        o200k_bytes: The real BPE file.
    """
    with ScriptedHttpServer(status=200, body=o200k_bytes) as server:
        encoder = _loader(server.url).get(None, timeout=60.0)
    assert encoder is not None
    samples = [
        "a",
        "Disassemble the entry point and list every import.",
        "def f(x):\n    return x * 2\n" * 20,
        "        if (ptr != NULL) {\n            free(ptr);\n        }\n" * 10,
        "漢字とかな",
        "0x401000 0x401004 0x401008 " * 30,
    ]

    assert estimate_tokens_without_encoder("") == 0
    for sample in samples:
        assert estimate_tokens_without_encoder(sample) >= len(encoder.encode(sample))
    assert any(empty_cache.glob("*"))


def _stalled_network_env(proxy: StallingServer, cache: Path) -> dict[str, str]:
    """Build a child environment whose every HTTPS request goes to a proxy that never answers.

    Args:
        proxy: The stalling proxy.
        cache: An empty ``tiktoken`` cache directory.

    Returns:
        dict[str, str]: The environment to add.
    """
    return {"HTTPS_PROXY": proxy.url, "HTTP_PROXY": proxy.url, "NO_PROXY": "", "TIKTOKEN_CACHE_DIR": str(cache)}


def test_mcp_tool_pricing_never_waits_on_the_network(tmp_path: Path) -> None:
    """Pricing tools, as the settings dialog does on the GUI thread, returns at once on a stalled network.

    Args:
        tmp_path: Per-test directory.
    """
    code = """
        import json, time
        from intellicrack.core.types import ToolFunction
        from intellicrack.mcp.policy import estimate_tool_cost, total_cost
        function = ToolFunction(
            name="mcp-demo.search",
            description="Search the indexed binaries for a symbol.",
            parameters=[],
            returns="matches",
            input_schema={"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]},
        )
        started = time.perf_counter()
        costs = [estimate_tool_cost(function) for _ in range(50)]
        print(json.dumps({"elapsed": time.perf_counter() - started, "total": total_cost(costs)}))
    """
    with StallingServer() as proxy:
        result = run_child_json(code, timeout_s=_CHILD_TIMEOUT_S, extra_env=_stalled_network_env(proxy, tmp_path / "cache"))

    assert result["elapsed"] < 1.0
    assert result["total"] > 0


def test_orchestrator_token_count_is_bounded_on_a_stalled_network(tmp_path: Path) -> None:
    """The orchestrator waits a bounded time for a first load, then estimates.

    Args:
        tmp_path: Per-test directory.
    """
    code = """
        import json, time
        from intellicrack.core.orchestrator import Orchestrator
        from intellicrack.core.token_encoding import estimate_tokens_without_encoder
        text = "Disassemble the entry point and list every import it resolves."
        started = time.perf_counter()
        first = Orchestrator.estimate_tokens(text, "o200k_base")
        first_elapsed = time.perf_counter() - started
        started = time.perf_counter()
        second = Orchestrator.estimate_tokens(text, None)
        print(json.dumps({
            "first": first,
            "second": second,
            "first_elapsed": first_elapsed,
            "second_elapsed": time.perf_counter() - started,
            "estimate": estimate_tokens_without_encoder(text),
        }))
    """
    with StallingServer() as proxy:
        result = run_child_json(code, timeout_s=_CHILD_TIMEOUT_S, extra_env=_stalled_network_env(proxy, tmp_path / "cache"))

    assert result["first"] == result["estimate"]
    assert result["second"] == result["estimate"]
    assert result["first_elapsed"] < OFF_GUI_THREAD_WAIT_S + _SCHEDULING_SLACK_S
    assert result["second_elapsed"] < OFF_GUI_THREAD_WAIT_S + _SCHEDULING_SLACK_S
