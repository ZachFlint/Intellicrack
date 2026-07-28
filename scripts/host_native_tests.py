# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
"""Run the host-native pytest pass outside the Docker sandbox.

The Intellicrack test suite executes inside a hardware-less, network-isolated,
elevated Windows Docker container. A subset of tests can only pass on a real
host because they depend on capabilities the container cannot expose: an Intel
XPU (``torch.xpu``), a running local Ollama daemon, Microsoft debug symbols,
raw physical disks, loopback TCP capture, and the invoking shell's actual
elevation. Those tests are marked ``@pytest.mark.host_native`` and are
deselected inside the container by :func:`tests.conftest._deselect_host_native`.

This module is the companion runner. It provisions the host environment
(starting Ollama and pulling a small model, configuring the symbol server,
enabling host process tests) and then invokes pytest natively with
``-m host_native`` so the marked tests run against real hardware. It is wired
into ``just test`` so the host-native pass runs on every full suite invocation.

Cloud-provider tests that require paid API keys are intentionally excluded:
they are never marked ``host_native``.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import cast

import httpx

from intellicrack.core.elevation import is_elevated
from intellicrack.core.logging import get_logger
from intellicrack.providers.xpu_utils import is_xpu_available


_LOGGER = get_logger("scripts.host_native")

_REPO_ROOT: Path = Path(__file__).resolve().parent.parent

_DEFAULT_OLLAMA_PORT: str = "11434"
_LOOPBACK_HOST: str = "127.0.0.1"
_IPV4_OCTET_COUNT: int = 4


def _is_wildcard_host(host: str) -> bool:
    """Return whether ``host`` is a bind-all address unusable as a client target.

    A server bound to a wildcard address (all-zeros IPv4, ``::``/``[::]`` IPv6,
    or an empty host) must be reached over loopback by a client, so the caller
    rewrites these to :data:`_LOOPBACK_HOST`.

    Args:
        host: The host portion parsed from an Ollama address.

    Returns:
        bool: ``True`` when ``host`` is a wildcard/empty bind address.
    """
    if host in {"", "*", "::", "[::]"}:
        return True
    octets = host.split(".")
    return len(octets) == _IPV4_OCTET_COUNT and all(octet == "0" for octet in octets)


def _split_host_port(authority: str) -> tuple[str, str]:
    """Split a ``host:port`` authority into host and port, IPv6-aware.

    Bracketed IPv6 literals (``[::]:11434``) are unbracketed to their inner host
    so a naive colon split does not fracture the address. A bare all-digit value
    is treated as a port with an empty host.

    Args:
        authority: The authority portion of an Ollama address, without scheme.

    Returns:
        tuple[str, str]: The ``(host, port)`` pair; ``port`` is empty when absent.
    """
    if authority.startswith("["):
        close = authority.find("]")
        if close != -1:
            host = authority[1:close]
            rest = authority[close + 1 :]
            port = rest[1:] if rest.startswith(":") else ""
            return host, port
    host, sep, port = authority.partition(":")
    if not sep and host.isdigit():
        return "", host
    return host, port


def resolve_ollama_base_url() -> str:
    """Resolve the base URL of the local Ollama server from the environment.

    Honours an explicit ``OLLAMA_HOST_URL`` override first, then the standard
    ``OLLAMA_HOST`` variable Ollama itself uses (accepting ``host:port``,
    ``http://host:port``, a bare ``host`` or a bare ``port``). A wildcard bind
    address is rewritten to loopback for the client connection, and the loopback
    name is pinned to ``127.0.0.1`` rather than ``localhost`` to avoid Windows
    resolving it to IPv6 ``::1`` when the server only listens on IPv4.

    Returns:
        str: The Ollama base URL, for example ``http://127.0.0.1:11434``.
    """
    explicit = os.environ.get("OLLAMA_HOST_URL", "").strip()
    if explicit:
        return explicit.rstrip("/")
    raw = os.environ.get("OLLAMA_HOST", "").strip()
    if not raw:
        return f"http://{_LOOPBACK_HOST}:{_DEFAULT_OLLAMA_PORT}"
    scheme = "http"
    if "://" in raw:
        scheme, raw = raw.split("://", 1)
    raw = raw.rstrip("/")
    host, port = _split_host_port(raw)
    if _is_wildcard_host(host):
        host = _LOOPBACK_HOST
    elif ":" in host:
        host = f"[{host}]"
    return f"{scheme}://{host}:{port or _DEFAULT_OLLAMA_PORT}"


_OLLAMA_HOST: str = resolve_ollama_base_url()
_OLLAMA_TAGS_URL: str = f"{_OLLAMA_HOST}/api/tags"
_OLLAMA_MODEL_ENV: str = "INTELLICRACK_HOST_NATIVE_OLLAMA_MODEL"
_DEFAULT_OLLAMA_MODEL: str = "qwen2.5:0.5b"
# Ollama tags cloud-run models with this suffix (e.g. ``gpt-oss:120b-cloud``);
# such entries need an ollama.com subscription and cannot back local chat tests.
_CLOUD_MODEL_SUFFIX: str = "-cloud"

_SYMBOL_SERVER: str = "https://msdl.microsoft.com/download/symbols"
_SYMBOL_CACHE_DIRNAME: str = ".symbols"

_HTTP_OK: int = 200
_OLLAMA_SERVE_TIMEOUT_S: float = 45.0
_OLLAMA_POLL_INTERVAL_S: float = 1.0
_OLLAMA_PULL_TIMEOUT_S: float = 900.0
_PYTEST_TIMEOUT_S: float = 3600.0

_SANDBOX_ENV_VAR: str = "INTELLICRACK_SANDBOXED"
_ALLOW_HOST_PROCESS_TESTS_ENV: str = "INTELLICRACK_ALLOW_HOST_PROCESS_TESTS"
# Kept in sync with tests._helpers.process_cleanup.HOST_NATIVE_ONLY_ENV; setting
# it makes the conftest collection hook keep only host_native tests. Combined
# with the ``-m host_native`` filter as belt-and-suspenders selection.
_HOST_NATIVE_ONLY_ENV: str = "INTELLICRACK_HOST_NATIVE_ONLY"


def build_symbol_path(repo_root: Path) -> str:
    """Build a ``_NT_SYMBOL_PATH`` value backed by a local cache.

    The value resolves system-DLL symbols (needed by the dbghelp-based process
    bridge tests) from the Microsoft symbol server, caching downloaded PDBs
    under ``<repo_root>/.symbols`` so repeat runs are offline-fast.

    Args:
        repo_root: Repository root under which the symbol cache lives.

    Returns:
        str: A ``srv*<cache>*<server>`` symbol path string.
    """
    cache = repo_root / _SYMBOL_CACHE_DIRNAME
    return f"srv*{cache}*{_SYMBOL_SERVER}"


def _ollama_reachable() -> bool:
    """Return whether the local Ollama daemon answers its tags endpoint.

    Returns:
        bool: ``True`` when ``GET /api/tags`` returns HTTP 200.
    """
    try:
        response = httpx.get(_OLLAMA_TAGS_URL, timeout=5.0)
    except (OSError, httpx.HTTPError):
        return False
    return response.status_code == _HTTP_OK


def _installed_ollama_models() -> list[str]:
    """List the model names currently installed in the local Ollama daemon.

    Returns:
        list[str]: Model names reported by ``GET /api/tags``; empty when the
            daemon is unreachable or has no models.
    """
    try:
        response = httpx.get(_OLLAMA_TAGS_URL, timeout=10.0)
    except (OSError, httpx.HTTPError):
        return []
    if response.status_code != _HTTP_OK:
        return []
    raw: object = response.json()
    if not isinstance(raw, dict):
        return []
    payload = cast("dict[str, object]", raw)
    models_obj = payload.get("models")
    if not isinstance(models_obj, list):
        return []
    names: list[str] = []
    for entry in cast("list[object]", models_obj):
        if isinstance(entry, dict):
            name = cast("dict[str, object]", entry).get("name")
            if isinstance(name, str):
                names.append(name)
    return names


def _is_local_model_name(name: str) -> bool:
    """Return whether an Ollama tag names a genuinely-local, runnable model.

    Ollama surfaces cloud-run models with a ``-cloud`` tag suffix; those require
    an ollama.com subscription and cannot back a local chat test, so they are
    not counted as a local model.

    Args:
        name: A model tag as reported by ``GET /api/tags`` (for example
            ``qwen2.5:0.5b`` or ``gpt-oss:120b-cloud``).

    Returns:
        bool: ``True`` when ``name`` is a non-empty, non-cloud model tag.
    """
    return bool(name) and not name.endswith(_CLOUD_MODEL_SUFFIX)


def _has_local_ollama_model() -> bool:
    """Return whether at least one genuinely-local model is installed.

    Cloud-only listings (every entry ``-cloud`` suffixed) count as *no* local
    model, so the caller pulls a small default to give the local chat tests a
    real target.

    Returns:
        bool: ``True`` when a non-cloud model is installed locally.
    """
    return any(_is_local_model_name(name) for name in _installed_ollama_models())


def _start_ollama_daemon(ollama_path: str) -> subprocess.Popen[bytes] | None:
    """Start ``ollama serve`` and wait until it answers, if not already up.

    Args:
        ollama_path: Absolute path to the ``ollama`` executable.

    Returns:
        subprocess.Popen[bytes] | None: The spawned server process when this
            call started it, or ``None`` when the daemon was already running.
    """
    if _ollama_reachable():
        _LOGGER.info("ollama_already_running", url=_OLLAMA_HOST)
        return None
    _LOGGER.info("ollama_starting", path=ollama_path)
    proc = subprocess.Popen(
        [ollama_path, "serve"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + _OLLAMA_SERVE_TIMEOUT_S
    while time.monotonic() < deadline:
        if _ollama_reachable():
            _LOGGER.info("ollama_ready", url=_OLLAMA_HOST)
            return proc
        if proc.poll() is not None:
            _LOGGER.warning("ollama_serve_exited", returncode=proc.returncode)
            return None
        time.sleep(_OLLAMA_POLL_INTERVAL_S)
    _LOGGER.warning("ollama_serve_timeout", seconds=_OLLAMA_SERVE_TIMEOUT_S)
    return proc


def _pull_ollama_model(ollama_path: str, model: str) -> bool:
    """Pull an Ollama model so model-dependent tests have data to exercise.

    Args:
        ollama_path: Absolute path to the ``ollama`` executable.
        model: Model tag to pull (for example ``qwen2.5:0.5b``).

    Returns:
        bool: ``True`` when the pull completed successfully.
    """
    _LOGGER.info("ollama_pull_start", model=model)
    try:
        result = subprocess.run(
            [ollama_path, "pull", model],
            check=False,
            timeout=_OLLAMA_PULL_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        _LOGGER.warning("ollama_pull_timeout", model=model, seconds=_OLLAMA_PULL_TIMEOUT_S)
        return False
    if result.returncode != 0:
        _LOGGER.warning("ollama_pull_failed", model=model, returncode=result.returncode)
        return False
    _LOGGER.info("ollama_pull_complete", model=model)
    return True


def _provision_ollama() -> subprocess.Popen[bytes] | None:
    """Ensure a local Ollama daemon is running with at least one local model.

    Locates the ``ollama`` binary, starts the daemon when needed, and pulls a
    small default model when no *genuinely-local* model is installed. A signed-in
    account may list subscription-only cloud models (``-cloud`` suffixed), which
    do not count: the local chat tests need a model that runs locally, so the
    default is pulled even when only cloud models are present. Failures are
    logged and tolerated so the remaining host-native tests still run; the Ollama
    tests self-skip with a precise reason when provisioning is impossible.

    Returns:
        subprocess.Popen[bytes] | None: The server process this call started
            (to be terminated on exit), or ``None`` when nothing was started.
    """
    ollama_path = shutil.which("ollama")
    if ollama_path is None:
        _LOGGER.warning("ollama_binary_missing", detail="ollama not on PATH; Ollama tests will skip")
        return None

    started = _start_ollama_daemon(ollama_path)
    if not _ollama_reachable():
        _LOGGER.warning("ollama_unreachable_after_start")
        return started

    if not _has_local_ollama_model():
        model = os.environ.get(_OLLAMA_MODEL_ENV, _DEFAULT_OLLAMA_MODEL)
        _ = _pull_ollama_model(ollama_path, model)
    return started


def _configure_environment(env: dict[str, str], repo_root: Path) -> None:
    """Mutate ``env`` so the host-native pass runs against real capabilities.

    Clears the sandbox marker, enables host process tests (so
    ``spawns_process`` tests are not auto-skipped by the conftest host guard),
    requests the host-native-only collection filter, and points
    ``_NT_SYMBOL_PATH`` at a cached Microsoft symbol server unless the operator
    already configured one.

    Args:
        env: Environment mapping to mutate in place (a copy of ``os.environ``).
        repo_root: Repository root used to locate the symbol cache.
    """
    env.pop(_SANDBOX_ENV_VAR, None)
    env[_ALLOW_HOST_PROCESS_TESTS_ENV] = "1"
    env[_HOST_NATIVE_ONLY_ENV] = "1"
    if not env.get("_NT_SYMBOL_PATH"):
        cache = repo_root / _SYMBOL_CACHE_DIRNAME
        cache.mkdir(parents=True, exist_ok=True)
        env["_NT_SYMBOL_PATH"] = build_symbol_path(repo_root)


def build_pytest_argv(repo_root: Path) -> list[str]:
    """Build the pytest argument vector for the host-native pass.

    Args:
        repo_root: Repository root; the JUnit report is written under
            ``reports/tests`` beneath it.

    Returns:
        list[str]: Arguments passed to ``python -m pytest`` (excluding the
            interpreter and ``-m pytest`` prefix).
    """
    junit = repo_root / "reports" / "tests" / "junit_host_native.xml"
    return [
        "tests/",
        "-m",
        "host_native",
        "-v",
        "-p",
        "no:randomly",
        "-ra",
        "--strict-markers",
        f"--junitxml={junit}",
    ]


def elevation_skip_notice(*, elevated: bool) -> str:
    """Build the startup notice naming which tests elevation will skip.

    The host-native pass cannot satisfy both elevation states at once: admin-only
    tests (raw physical disk, ETW realtime tracing) need an elevated token, while
    the privilege-failure monitor tests need a non-elevated one. This notice
    tells the operator up front which subset the current shell will skip.

    Args:
        elevated: Whether the invoking shell holds an elevated token.

    Returns:
        str: A single-line, human-readable notice for the console.
    """
    if elevated:
        return (
            "[host-native] Elevated shell: raw-disk and ETW tests will run; "
            "tests that require a non-elevated token (privilege-failure monitors) "
            "will be SKIPPED."
        )
    return (
        "[host-native] Not elevated: admin-only tests (raw physical disk, ETW "
        "realtime tracing) will be SKIPPED. Run from an elevated shell to include them."
    )


def _log_capabilities() -> None:
    """Log which host capabilities are present, so skips are explainable."""
    installed = _installed_ollama_models()
    _LOGGER.info(
        "host_native_capabilities",
        platform=sys.platform,
        elevated=is_elevated(),
        xpu=is_xpu_available(),
        ollama=_ollama_reachable(),
        ollama_models=len(installed),
        ollama_local_models=sum(1 for name in installed if _is_local_model_name(name)),
    )


def run(repo_root: Path, extra_args: list[str] | None = None) -> int:
    """Provision the host and execute the host-native pytest pass.

    Args:
        repo_root: Repository root to run pytest from.
        extra_args: Additional pytest arguments appended to the built vector.

    Returns:
        int: The pytest process exit code (non-zero on any failure).
    """
    print(elevation_skip_notice(elevated=is_elevated()), file=sys.stderr, flush=True)
    env = dict(os.environ)
    _configure_environment(env, repo_root)
    server = _provision_ollama()
    _log_capabilities()
    argv = [sys.executable, "-m", "pytest", *build_pytest_argv(repo_root), *(extra_args or [])]
    _LOGGER.info("host_native_pytest_start", argv=argv[2:])
    try:
        result = subprocess.run(
            argv,
            cwd=repo_root,
            env=env,
            check=False,
            timeout=_PYTEST_TIMEOUT_S,
        )
        exit_code = result.returncode
    except subprocess.TimeoutExpired:
        _LOGGER.exception("host_native_pytest_timeout", seconds=_PYTEST_TIMEOUT_S)
        exit_code = 1
    finally:
        if server is not None and server.poll() is None:
            server.terminate()
            try:
                _ = server.wait(timeout=10.0)
            except subprocess.TimeoutExpired:
                server.kill()
    _LOGGER.info("host_native_pytest_done", exit_code=exit_code)
    return exit_code


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for the host-native test pass.

    Args:
        argv: Optional argument list (defaults to ``sys.argv[1:]``); any values
            are forwarded to pytest.

    Returns:
        int: Process exit code.
    """
    parser = argparse.ArgumentParser(description="Run the Intellicrack host-native pytest pass.")
    _ = parser.add_argument("pytest_args", nargs="*", help="Extra arguments forwarded to pytest.")
    args = parser.parse_args(argv)
    extra: list[str] = list(args.pytest_args)
    return run(_REPO_ROOT, extra)


if __name__ == "__main__":
    raise SystemExit(main())
