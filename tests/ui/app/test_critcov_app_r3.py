# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Third-pass coverage for the main window's optional-package fallbacks.

``intellicrack.ui.app`` imports the model loader and the ``intellicrack_hexcore`` extension inside ``try``/``except ImportError`` blocks and
degrades when either is missing. These tests start one real child interpreter per missing package, make the package unimportable with the
import system's own switch (``sys.modules[name] = None``), import the real module, build a real ``MainWindow`` over a real ``Orchestrator`` and
report the resulting state as JSON. The parent asserts on that state against expectations taken from the documented contract of each fallback.
Nothing in the pytest process is reloaded or altered.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from tests._helpers.provider_state import provider_environment_variables


pytestmark = pytest.mark.spawns_process


_REPO_ROOT: Path = Path(__file__).resolve().parents[3]
_SRC_DIR: Path = _REPO_ROOT / "src"
_CHILD_TIMEOUT_S: float = 900.0
_ATTACHED_PID: int = 4242
_STALE_TEXT: str = "stale"
_CACHE_BYTES: int = 1048576
_RESULT_PREFIX: str = "RESULT "

_CHILD_SOURCE: str = r"""
import json
import sys
import traceback
from pathlib import Path

block = sys.argv[1]
base = Path(sys.argv[2])
if block == "model_loader":
    sys.modules["intellicrack.providers.model_loader"] = None
elif block == "hexcore":
    sys.modules["intellicrack_hexcore"] = None

out = {}
state = {}


def measure(key, fn):
    try:
        out[key] = fn()
    except BaseException as exc:
        out[key] = "ERROR " + type(exc).__name__ + ": " + str(exc)[:300]


def traced(fn):
    from structlog.testing import capture_logs

    with capture_logs() as captured:
        fn()
    return [[entry.get("event"), entry.get("pid")] for entry in captured]


try:
    from PyQt6.QtCore import QSettings
    from PyQt6.QtWidgets import QApplication

    app = QApplication([])
    QSettings.setDefaultFormat(QSettings.Format.IniFormat)
    QSettings.setPath(QSettings.Format.IniFormat, QSettings.Scope.UserScope, str(base / "qs"))
    import intellicrack.ui.app as appmod

    out["import_ok"] = True
except BaseException:
    out["import_ok"] = False
    out["import_traceback"] = traceback.format_exc()[-2500:]
    print("RESULT " + json.dumps(out))
    sys.exit(0)

out["get_cache_is_none"] = appmod.get_global_model_cache is None
out["set_cache_is_none"] = appmod.set_global_cache_size is None
out["hexcore_is_none"] = appmod._hexcore is None
measure("static_label_text", lambda: appmod.MainWindow._compute_memory_label_text())

try:
    from intellicrack.core.config import Config, UIConfig
    from intellicrack.core.orchestrator import Orchestrator
    from intellicrack.core.session import SessionManager, SessionStore
    from intellicrack.core.tools import ToolRegistry
    from intellicrack.providers.registry import ProviderRegistry
    from intellicrack.ui.panels.async_bridge import drain_bridge_workers, shutdown_bridge_loop

    tools_dir = base / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    config = Config(
        tools_directory=tools_dir,
        logs_directory=base / "logs",
        data_directory=base / "data",
        ui=UIConfig(restore_layout=False),
    )
    setattr(config, "max_model_cache_bytes", int(sys.argv[3]))
    orchestrator = Orchestrator(
        provider_registry=ProviderRegistry(),
        tool_registry=ToolRegistry(tools_dir=tools_dir),
        session_manager=SessionManager(store=SessionStore(db_path=base / "sessions.db"), auto_save=False),
    )

    def build():
        state["window"] = appmod.MainWindow(config, orchestrator)

    measure("build_events", lambda: traced(build))
    window = state.get("window")
    out["window_built"] = window is not None
    if window is not None:
        measure("label_after_build", lambda: window._memory_label.text())

        def refresh():
            window._memory_label.setText(sys.argv[4])
            window._memory_label.setToolTip(sys.argv[4])
            window._refresh_memory_status()

        measure("refresh_events", lambda: traced(refresh))
        measure("label_after_refresh", lambda: window._memory_label.text())
        measure("tooltip_after_refresh", lambda: window._memory_label.toolTip())
        measure("init_cache_events", lambda: traced(window._initialize_model_cache))
        out["regions_worker_before"] = repr(window._process_regions_worker)
        measure("attach_events", lambda: traced(lambda: window._on_process_attached(int(sys.argv[5]))))
        out["regions_worker_after"] = repr(window._process_regions_worker)
except BaseException:
    out["window_error"] = traceback.format_exc()[-2500:]
finally:
    try:
        if state.get("window") is not None:
            state["window"].close()
        drain_bridge_workers()
        shutdown_bridge_loop()
    except BaseException:
        out["teardown_error"] = traceback.format_exc()[-800:]

print("RESULT " + json.dumps(out))
"""


def _child_environment(base: Path) -> dict[str, str]:
    """Build the environment of a child interpreter that must not touch user state.

    Args:
        base: A directory private to the child, holding the redirected state root.

    Returns:
        dict[str, str]: The inherited environment without provider variables, with the state root, Qt platform and import path redirected.
    """
    env = dict(os.environ)
    for name in provider_environment_variables():
        _ = env.pop(name, None)
    local_app_data = base / "LocalAppData"
    state_dir = local_app_data / "Intellicrack"
    state_dir.mkdir(parents=True, exist_ok=True)
    env["LOCALAPPDATA"] = str(local_app_data)
    env["INTELLICRACK_STATE_DIR"] = str(state_dir)
    env["QT_QPA_PLATFORM"] = "offscreen"
    env["PYTHONIOENCODING"] = "utf-8"
    inherited = env.get("PYTHONPATH")
    paths = [str(_SRC_DIR), str(_REPO_ROOT)]
    env["PYTHONPATH"] = os.pathsep.join([*paths, inherited] if inherited else paths)
    return env


def _run_child(block: str, base: Path) -> dict[str, Any]:
    """Run the driver in a fresh interpreter with one package made unimportable.

    Args:
        block: ``"model_loader"`` or ``"hexcore"``, the package the child makes unimportable.
        base: A directory private to the child.

    Returns:
        dict[str, Any]: The JSON object the child printed last.
    """
    base.mkdir(parents=True, exist_ok=True)
    arguments = [block, str(base), str(_CACHE_BYTES), _STALE_TEXT, str(_ATTACHED_PID)]
    completed = subprocess.run(
        [sys.executable, "-c", _CHILD_SOURCE, *arguments],
        capture_output=True,
        text=True,
        timeout=_CHILD_TIMEOUT_S,
        env=_child_environment(base),
        cwd=base,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr[-4000:]
    lines = [line for line in completed.stdout.splitlines() if line.startswith(_RESULT_PREFIX)]
    assert lines, f"child printed no result line:\n{completed.stdout[-3000:]}\n{completed.stderr[-3000:]}"
    decoded: dict[str, Any] = json.loads(lines[-1][len(_RESULT_PREFIX) :])
    return decoded


@pytest.fixture(scope="module")
def without_model_loader(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """Report the state of the main window module imported with the model loader unimportable.

    Args:
        tmp_path_factory: Session temporary directory factory.

    Returns:
        dict[str, Any]: The state the child reported.
    """
    return _run_child("model_loader", tmp_path_factory.mktemp("no_model_loader"))


@pytest.fixture(scope="module")
def without_hexcore(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """Report the state of the main window module imported with ``intellicrack_hexcore`` unimportable.

    Args:
        tmp_path_factory: Session temporary directory factory.

    Returns:
        dict[str, Any]: The state the child reported.
    """
    return _run_child("hexcore", tmp_path_factory.mktemp("no_hexcore"))


def test_the_module_still_imports_without_the_model_loader_and_unsets_only_its_hooks(without_model_loader: dict[str, Any]) -> None:
    """A missing model loader leaves both cache hooks unset and the hexcore binding intact.

    Args:
        without_model_loader: The child's reported state.
    """
    assert without_model_loader["import_ok"] is True, without_model_loader.get("import_traceback")
    assert without_model_loader["get_cache_is_none"] is True
    assert without_model_loader["set_cache_is_none"] is True
    assert without_model_loader["hexcore_is_none"] is False


def test_the_memory_label_text_is_empty_without_the_model_loader(without_model_loader: dict[str, Any]) -> None:
    """Without a model cache there is no usage to show, so the computed label text is the empty string.

    Args:
        without_model_loader: The child's reported state.
    """
    text = without_model_loader["static_label_text"]
    assert isinstance(text, str)
    assert not text


def test_a_window_builds_and_ignores_the_configured_cache_size_without_the_model_loader(without_model_loader: dict[str, Any]) -> None:
    """A window built with a cache size configured skips the resize silently, during startup and when asked again.

    A resize attempted through the missing hook would fail and be logged as ``model_cache_init_skipped``.

    Args:
        without_model_loader: The child's reported state.
    """
    assert without_model_loader.get("window_error") is None
    assert without_model_loader["window_built"] is True
    assert [name for name, _pid in without_model_loader["build_events"]].count("model_cache_init_skipped") == 0
    assert without_model_loader["init_cache_events"] == []


def test_the_memory_status_is_cleared_without_the_model_loader(without_model_loader: dict[str, Any]) -> None:
    """Refreshing the memory status empties a label that held text and its tooltip when no cache exists.

    Args:
        without_model_loader: The child's reported state.
    """
    shown = [
        without_model_loader["label_after_build"],
        without_model_loader["label_after_refresh"],
        without_model_loader["tooltip_after_refresh"],
    ]
    assert all(isinstance(value, str) for value in shown)
    assert not any(shown)
    assert without_model_loader["refresh_events"] == []


def test_the_module_still_imports_without_hexcore_and_unsets_only_its_binding(without_hexcore: dict[str, Any]) -> None:
    """A missing hexcore extension leaves the module-level binding unset and the model loader hooks intact.

    Args:
        without_hexcore: The child's reported state.
    """
    assert without_hexcore["import_ok"] is True, without_hexcore.get("import_traceback")
    assert without_hexcore["hexcore_is_none"] is True
    assert without_hexcore["get_cache_is_none"] is False
    assert without_hexcore["set_cache_is_none"] is False


def test_a_process_attach_without_hexcore_is_logged_and_starts_no_region_listing(without_hexcore: dict[str, Any]) -> None:
    """Attaching a process logs that hexcore is unavailable for that pid and starts no region-listing worker.

    Args:
        without_hexcore: The child's reported state.
    """
    assert without_hexcore.get("window_error") is None
    assert without_hexcore["window_built"] is True
    assert without_hexcore["regions_worker_before"] == "None"
    assert without_hexcore["attach_events"] == [["hexcore_unavailable_for_process_memory", _ATTACHED_PID]]
    assert without_hexcore["regions_worker_after"] == "None"
