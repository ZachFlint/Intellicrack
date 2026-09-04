# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
"""Falsifiable gates for the host-native pass runner (scripts.host_native_tests).

These exercise the runner's deterministic pieces against real values: the
symbol-path builder, the pytest argument vector, and the environment
configuration that flips the process out of sandbox mode and into a host-native
collection. The capability probes are checked to return real booleans without
raising in the container (where the daemon/hardware are genuinely absent).
"""

from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest

from scripts import host_native_tests
from scripts.host_native_tests import (
    build_pytest_argv,
    build_symbol_path,
    elevation_skip_notice,
    resolve_ollama_base_url,
)


if TYPE_CHECKING:
    from collections.abc import Callable


def test_build_symbol_path_targets_repo_cache_and_ms_server() -> None:
    """The symbol path is a ``srv*<repo-cache>*<ms-server>`` triple."""
    repo = Path("D:/example-repo")
    result = build_symbol_path(repo)
    assert result.startswith("srv*")
    assert str(repo / ".symbols") in result
    assert result.endswith("https://msdl.microsoft.com/download/symbols")


def test_build_pytest_argv_selects_host_native_and_writes_junit() -> None:
    """The argv restricts to host_native and writes the host-native JUnit file."""
    repo = Path("D:/example-repo")
    argv = build_pytest_argv(repo)
    assert "tests/" in argv
    assert argv[argv.index("-m") + 1] == "host_native"
    junit_args = [arg for arg in argv if arg.startswith("--junitxml=")]
    assert junit_args == [f"--junitxml={repo / 'reports' / 'tests' / 'junit_host_native.xml'}"]


def test_build_pytest_argv_pins_unique_basetemp_off_the_shared_user_base() -> None:
    """The argv pins a per-run ``--basetemp`` so a poisoned shared base cannot fail teardown.

    Without an explicit basetemp, pytest walks the shared ``pytest-of-<user>`` base
    at session finish; a SYSTEM-owned directory or ``pytest-current`` symlink left by
    a prior elevated run makes ``pytest_sessionfinish`` raise ``PermissionError`` and
    the whole pass exit non-zero even when every test passed. Dropping the
    ``--basetemp`` argument, aiming it at the shared base, or using a constant
    (non-unique) path each reddens an assertion here.
    """
    repo = Path("D:/example-repo")
    basetemp_args = [arg for arg in build_pytest_argv(repo) if arg.startswith("--basetemp=")]
    assert len(basetemp_args) == 1, "host-native argv must pin exactly one --basetemp"
    basetemp = Path(basetemp_args[0].split("=", 1)[1])
    assert basetemp.parent.name == "intellicrack-host-native"
    assert str(basetemp).startswith(str(Path(tempfile.gettempdir())))
    assert "pytest-of-" not in str(basetemp).replace("\\", "/")
    second = next(arg for arg in build_pytest_argv(repo) if arg.startswith("--basetemp="))
    assert second != basetemp_args[0], "each run must receive a distinct basetemp"


def test_prepare_host_native_tmp_parent_prunes_aged_runs_but_keeps_recent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Aged prior-run trees are removed while a recent tree and the parent survive.

    The parent must exist for pytest to create its per-run directory, and old runs
    must be pruned so the parent does not grow without bound. This drives the real
    function against real directories: an aged tree is removed, a recent one is kept,
    and the parent is created. A no-op prune (aged tree survives) or an
    age-blind prune (recent tree deleted) reddens an assertion here.

    Args:
        tmp_path: Pytest-provided directory used as the basetemp parent root.
        monkeypatch: Fixture used to point the runner at the temporary parent.
    """
    parent = tmp_path / "intellicrack-host-native"
    monkeypatch.setattr(host_native_tests, "_HOST_NATIVE_TMP_PARENT", parent)
    monkeypatch.setattr(host_native_tests, "_HOST_NATIVE_TMP_MAX_AGE_S", 3600.0)
    aged = parent / "run-1-1"
    fresh = parent / "run-2-2"
    parent.mkdir()
    aged.mkdir()
    (aged / "leftover.txt").write_text("x", encoding="utf-8")
    fresh.mkdir()
    stale = time.time() - 7200.0
    os.utime(aged, (stale, stale))

    host_native_tests.prepare_host_native_tmp_parent()

    assert not aged.exists(), "a run tree older than the max age must be pruned"
    assert fresh.exists(), "a recent run tree must be kept"
    assert parent.is_dir(), "the basetemp parent must exist after preparation"


def test_configure_environment_flips_sandbox_to_host_native(tmp_path: Path) -> None:
    """Environment configuration leaves the process in host-native mode.

    Args:
        tmp_path: Temporary directory used as the repository root.
    """
    configure = cast(
        "Callable[[dict[str, str], Path], None]",
        getattr(host_native_tests, "_configure_environment"),
    )
    env: dict[str, str] = {"INTELLICRACK_SANDBOXED": "1"}
    configure(env, tmp_path)
    assert "INTELLICRACK_SANDBOXED" not in env
    assert env["INTELLICRACK_ALLOW_HOST_PROCESS_TESTS"] == "1"
    assert env["INTELLICRACK_HOST_NATIVE_ONLY"] == "1"
    assert env["_NT_SYMBOL_PATH"].startswith("srv*")
    assert (tmp_path / ".symbols").is_dir()


def test_configure_environment_preserves_existing_symbol_path(tmp_path: Path) -> None:
    """An operator-provided ``_NT_SYMBOL_PATH`` is not overwritten.

    Args:
        tmp_path: Temporary directory used as the repository root.
    """
    configure = cast(
        "Callable[[dict[str, str], Path], None]",
        getattr(host_native_tests, "_configure_environment"),
    )
    env: dict[str, str] = {"_NT_SYMBOL_PATH": r"C:\custom\symbols"}
    configure(env, tmp_path)
    assert env["_NT_SYMBOL_PATH"] == r"C:\custom\symbols"


def test_ollama_reachable_returns_bool_without_raising() -> None:
    """The Ollama probe returns a real boolean and never raises.

    In the network-isolated container there is no daemon, so this must return
    ``False`` rather than propagate a connection error.
    """
    reachable = cast(
        "Callable[[], bool]",
        getattr(host_native_tests, "_ollama_reachable"),
    )
    result = reachable()
    assert isinstance(result, bool)


def test_installed_ollama_models_returns_list_without_raising() -> None:
    """The installed-models probe returns a real list and never raises."""
    models = cast(
        "Callable[[], list[str]]",
        getattr(host_native_tests, "_installed_ollama_models"),
    )
    result = models()
    assert isinstance(result, list)


@pytest.mark.parametrize(
    ("model_name", "expected_local"),
    [
        ("qwen2.5:0.5b", True),
        ("llama3.2:1b", True),
        ("gpt-oss:120b-cloud", False),
        ("deepseek-v3.1:671b-cloud", False),
        ("", False),
    ],
)
def test_is_local_model_name_excludes_cloud_suffix(model_name: str, *, expected_local: bool) -> None:
    """Only non-empty, non ``-cloud`` tags count as genuinely-local models.

    Args:
        model_name: The Ollama tag to classify.
        expected_local: Whether the tag should be treated as local.
    """
    classify = cast(
        "Callable[[str], bool]",
        getattr(host_native_tests, "_is_local_model_name"),
    )
    assert classify(model_name) is expected_local


def test_has_local_ollama_model_returns_bool_without_raising() -> None:
    """The local-model probe returns a real boolean and never raises.

    In the network-isolated container there is no daemon, so this must return
    ``False`` rather than propagate a connection error.
    """
    has_local = cast(
        "Callable[[], bool]",
        getattr(host_native_tests, "_has_local_ollama_model"),
    )
    result = has_local()
    assert isinstance(result, bool)


def test_elevation_skip_notice_names_admin_tests_when_not_elevated() -> None:
    """Without elevation, the notice states admin-only tests are skipped."""
    notice = elevation_skip_notice(elevated=False)
    assert "Not elevated" in notice
    assert "SKIPPED" in notice
    assert "raw physical disk" in notice


def test_elevation_skip_notice_names_nonelevated_tests_when_elevated() -> None:
    """With elevation, the notice states non-elevated tests are skipped."""
    notice = elevation_skip_notice(elevated=True)
    assert "Elevated shell" in notice
    assert "SKIPPED" in notice
    assert "non-elevated token" in notice


def test_elevation_skip_notice_differs_by_elevation() -> None:
    """The elevated and non-elevated notices are distinct messages."""
    assert elevation_skip_notice(elevated=True) != elevation_skip_notice(elevated=False)


@pytest.mark.parametrize(
    ("ollama_host", "expected"),
    [
        ("0.0.0.0:11434", "http://127.0.0.1:11434"),
        ("127.0.0.1:11500", "http://127.0.0.1:11500"),
        ("http://localhost:1234", "http://localhost:1234"),
        ("11888", "http://127.0.0.1:11888"),
        ("[::]:11434", "http://127.0.0.1:11434"),
        ("[::1]:11500", "http://[::1]:11500"),
    ],
)
def test_resolve_ollama_base_url_from_ollama_host(
    monkeypatch: pytest.MonkeyPatch,
    ollama_host: str,
    expected: str,
) -> None:
    """OLLAMA_HOST is parsed and wildcard/loopback-normalised to a client URL.

    Args:
        monkeypatch: Pytest environment patcher.
        ollama_host: The ``OLLAMA_HOST`` value to resolve.
        expected: The expected client base URL.
    """
    monkeypatch.delenv("OLLAMA_HOST_URL", raising=False)
    monkeypatch.setenv("OLLAMA_HOST", ollama_host)
    assert resolve_ollama_base_url() == expected


def test_resolve_ollama_base_url_defaults_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """With no Ollama env set, the loopback default URL is used.

    Args:
        monkeypatch: Pytest environment patcher.
    """
    monkeypatch.delenv("OLLAMA_HOST_URL", raising=False)
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    assert resolve_ollama_base_url() == "http://127.0.0.1:11434"


def test_resolve_ollama_base_url_explicit_override_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    """OLLAMA_HOST_URL takes precedence over OLLAMA_HOST.

    Args:
        monkeypatch: Pytest environment patcher.
    """
    monkeypatch.setenv("OLLAMA_HOST_URL", "http://example.internal:9000")
    monkeypatch.setenv("OLLAMA_HOST", "0.0.0.0:11434")
    assert resolve_ollama_base_url() == "http://example.internal:9000"
