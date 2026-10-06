# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Coverage for the application entry point paths the existing suites leave unexecuted.

Everything that can run inside the pytest process runs there against real objects:
configuration, structlog capture, the real provider, session, orchestrator and
discovery classes, and the real Qt application of the ``qapp`` fixture. Three things
cannot, because they would start the real GUI event loop or need a process without a
``QApplication``: the early splash construction, the whole ``main()`` launch and the
``python -m intellicrack.main`` exit code. Those run in a child interpreter whose
environment is redirected into ``tmp_path`` and stripped of provider credentials, and
the GUI launch is ended by a watcher thread that asks the application to quit once
its event loop is running.

Paths that cannot be driven honestly are left out: the UAC relaunch branch, the early
splash failure branches (Qt aborts the process instead of raising), the defensive
guards around modules that always import, and the stage timeouts that would need a
tracked process stalled for ten seconds.
"""

from __future__ import annotations

import asyncio
import contextlib
import ctypes
import gc
import importlib
import json
import logging
import os
import signal
import subprocess
import sys
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, cast, override

import pytest
from PyQt6 import sip
from PyQt6.QtGui import QGuiApplication, QPixmap
from PyQt6.QtWidgets import QApplication, QMainWindow, QSplashScreen
from structlog.testing import capture_logs

from intellicrack._metadata import __version__
from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.core.config import Config, get_config_dir, get_config_file, get_env_file
from intellicrack.core.logging import get_logger, get_stdlib_root_logger
from intellicrack.core.orchestrator import Orchestrator, OrchestratorConfig
from intellicrack.core.process_manager import ProcessManager
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.template_manager import TemplateManager
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ModelInfo, ProviderCredentials, ToolName
from intellicrack.credentials.env_loader import CredentialLoader, unregister_instance_mapping
from intellicrack.main import init_model_discovery, init_template_manager
from intellicrack.providers.capabilities import CapabilityOverride
from intellicrack.providers.configurable import ConfigurableProvider
from intellicrack.providers.discovery import ModelDiscovery
from intellicrack.providers.instances import ProviderInstance
from intellicrack.providers.openai import OpenAIProvider
from intellicrack.providers.registry import ProviderRegistry, get_provider_registry
from intellicrack.sandbox.manager import SandboxManager
from intellicrack.ui.dialogs import SplashScreen
from intellicrack.ui.log_viewer import get_qt_log_handler, install_qt_log_handler, uninstall_qt_log_handler
from intellicrack.ui.panels.async_bridge import drain_bridge_workers, ensure_loop, run_bridge_coroutine, shutdown_bridge_loop
from intellicrack.ui.resources import IconManager
from intellicrack.ui.resources.theme_manager import ThemeManager
from tests._helpers.child_python import REPO_ROOT
from tests._helpers.provider_state import isolate_provider_environment, provider_environment_variables, redirected_state_root


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Generator, Mapping, Sequence

    from structlog.stdlib import BoundLogger

    from intellicrack.credentials.provider_settings import ProviderConnectPolicy
    from intellicrack.providers.base import LLMProviderBase
    from intellicrack.ui.app import MainWindow


_main_module = importlib.import_module("intellicrack.main")

_CLIOptions = cast("Callable[..., object]", getattr(_main_module, "_CLIOptions"))
_apply_cli_overrides = cast("Callable[[Config, object], None]", getattr(_main_module, "_apply_cli_overrides"))
_log_import_time = cast("Callable[[BoundLogger, str, float], None]", getattr(_main_module, "_log_import_time"))
_compute_early_dpi_scale = cast("Callable[[QApplication], float]", getattr(_main_module, "_compute_early_dpi_scale"))
_build_early_splash_pixmap = cast("Callable[[Path, int, int], QPixmap]", getattr(_main_module, "_build_early_splash_pixmap"))
_ensure_per_monitor_dpi_awareness = cast("Callable[[], None]", getattr(_main_module, "_ensure_per_monitor_dpi_awareness"))
_upgrade_to_full_splash = cast(
    "Callable[[QApplication, QSplashScreen, BoundLogger, str], SplashScreen | None]",
    getattr(_main_module, "_upgrade_to_full_splash"),
)
_apply_saved_capability_overrides = cast(
    "Callable[[LLMProviderBase, str, BoundLogger], None]",
    getattr(_main_module, "_apply_saved_capability_overrides"),
)
_connect_provider_at_startup = cast(
    "Callable[[LLMProviderBase, str, CredentialLoader, ProviderConnectPolicy | None, BoundLogger], Coroutine[object, object, None]]",
    getattr(_main_module, "_connect_provider_at_startup"),
)
_saved_provider_instances = cast("Callable[[BoundLogger], list[object]]", getattr(_main_module, "_saved_provider_instances"))
_resolve_config_path = cast("Callable[[object, Callable[[], Path]], Path | None]", getattr(_main_module, "_resolve_config_path"))
_finalize_shutdown = cast(
    "Callable[[asyncio.AbstractEventLoop, ProcessManager, BoundLogger], None]",
    getattr(_main_module, "_finalize_shutdown"),
)
_load_startup_config = cast(
    "Callable[[object], tuple[Config, BoundLogger, ProcessManager] | None]",
    getattr(_main_module, "_load_startup_config"),
)
_clear_model_cache = cast("Callable[[BoundLogger], None]", getattr(_main_module, "_clear_model_cache"))
_wire_preregistered_sandbox = cast("Callable[[MainWindow, Orchestrator], None]", getattr(_main_module, "_wire_preregistered_sandbox"))
_detach_qt_log_handler = cast("Callable[[BoundLogger], None]", getattr(_main_module, "_detach_qt_log_handler"))
_cancel_pending_bridge_tasks = cast(
    "Callable[[BoundLogger], Coroutine[object, object, None]]",
    getattr(_main_module, "_cancel_pending_bridge_tasks"),
)
_drain_and_stop_bridge_loop = cast("Callable[[BoundLogger], None]", getattr(_main_module, "_drain_and_stop_bridge_loop"))
_shutdown_application = cast("Callable[..., Coroutine[object, object, None]]", getattr(_main_module, "_shutdown_application"))
_get_provider_registry = cast("Callable[[], ProviderRegistry]", getattr(_main_module, "_get_provider_registry"))

_BACKGROUND: Final[tuple[int, int, int]] = (30, 30, 46)
_EARLY_SPLASH_SIZE: Final[tuple[int, int]] = (600, 400)
_DPI_CONTEXT_PER_MONITOR_AWARE_V2: Final[int] = -4
_DPI_REJECTED_EVENT: Final[str] = "per_monitor_dpi_awareness_rejected"
_PROVIDER_STARTUP_TIMEOUT_S: Final[float] = 10.0
_INSTANCE_IDS: Final[tuple[str, ...]] = ("gw-valid", "gw-bad", "stall-gw", "shut-gw")
_NOISY_LOGGERS: Final[tuple[str, ...]] = ("httpx", "httpcore", "openai._base_client", "anthropic._base_client")
_OFFLINE_SECTIONS: Final[dict[str, dict[str, object]]] = {
    "ollama": {"enabled": False, "schema_version": 3},
    "local_transformers": {"enabled": False, "schema_version": 3},
}
_GUI_STAGES: Final[tuple[str, ...]] = (
    "app_starting",
    "splash_screen_shown",
    "provider_initialization_started",
    "provider_initialization_complete",
    "script_engine_initialized",
    "model_discovery_initialized",
    "ui_started",
    "shutdown_started",
    "shutdown_complete",
)

_IMPORTER_NAMES: Final[tuple[str, ...]] = (
    "_import_config_module",
    "_import_logging_funcs",
    "_import_process_manager",
    "_import_qt_app",
    "_import_splash_screen",
    "_import_theme_icon_managers",
    "_import_orchestrator",
    "_import_orchestrator_config",
    "_import_session_classes",
    "_import_tool_registry",
    "_import_credential_loader",
    "_import_main_window",
)

_GUI_DRIVER: Final[str] = """
import importlib
import json
import sys
import threading

from PyQt6.QtCore import QMetaObject, Qt
from PyQt6.QtWidgets import QApplication

main_module = importlib.import_module('intellicrack.main')
finished = threading.Event()


def quit_when_the_event_loop_runs():
    while not finished.wait(0.2):
        app = QApplication.instance()
        if app is not None:
            QMetaObject.invokeMethod(app, 'quit', Qt.ConnectionType.QueuedConnection)


watcher = threading.Thread(target=quit_when_the_event_loop_runs, daemon=True)
watcher.start()
exit_code = main_module.main()
finished.set()
watcher.join()
sys.stdout.write(json.dumps({'exit_code': exit_code}) + '\\n')
sys.stdout.flush()
"""

_EARLY_SPLASH_DRIVER: Final[str] = """
import importlib
import json
import sys

import structlog
from PyQt6 import sip
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication, QSplashScreen
from structlog.testing import capture_logs

main_module = importlib.import_module('intellicrack.main')
facts = {'app_before': QApplication.instance() is None}
app, early = main_module._show_early_splash()
pixmap = early.pixmap()
facts['app_is_instance'] = app is QApplication.instance()
facts['application_name'] = QApplication.applicationName()
facts['application_version'] = QApplication.applicationVersion()
facts['style_name'] = app.style().objectName().lower()
facts['screen_ratio'] = app.primaryScreen().devicePixelRatio()
facts['pixmap_size'] = [pixmap.width(), pixmap.height()]
facts['pixmap_ratio'] = pixmap.devicePixelRatio()
facts['frameless'] = bool(early.windowFlags() & Qt.WindowType.FramelessWindowHint)
facts['early_visible'] = early.isVisible()

logger = structlog.get_logger('driver')
with capture_logs() as upgraded_logs:
    splash = main_module._upgrade_to_full_splash(app, early, logger, 'dark')
facts['splash_class'] = type(splash).__name__
facts['early_visible_after'] = early.isVisible()
facts['splash_visible'] = splash.isVisible()
facts['import_timings'] = [entry['imported_module'] for entry in upgraded_logs if entry['event'] == 'import_timing']
splash.close()

broken = QSplashScreen()
sip.delete(broken)
with capture_logs() as failed_logs:
    failed = main_module._upgrade_to_full_splash(app, broken, logger, 'dark')
facts['failed_result_is_none'] = failed is None
facts['failure_events'] = [
    [entry['event'], entry['log_level']] for entry in failed_logs if entry['event'] == 'full_splash_upgrade_failed'
]
sys.stdout.write(json.dumps(facts) + '\\n')
sys.stdout.flush()
"""


class _NeverConnectingProvider(ConfigurableProvider):
    """A real configurable provider whose connection attempt never completes."""

    @override
    async def connect(self, credentials: ProviderCredentials) -> None:
        """Wait forever instead of connecting.

        Args:
            credentials: Ignored.
        """
        _ = credentials
        await asyncio.Event().wait()


class _StalledProvider(ConfigurableProvider):
    """A real configurable provider whose disconnect never completes."""

    @override
    async def disconnect(self) -> None:
        """Wait forever instead of disconnecting."""
        await asyncio.Event().wait()


class _StalledOrchestrator(Orchestrator):
    """A real orchestrator whose shutdown never completes."""

    @override
    async def shutdown(self) -> None:
        """Wait forever instead of shutting down."""
        await asyncio.Event().wait()


class _StalledSessionManager(SessionManager):
    """A real session manager whose close never completes."""

    @override
    async def close(self) -> None:
        """Wait forever instead of closing."""
        await asyncio.Event().wait()


def _events(captured: Sequence[Mapping[str, object]], name: str) -> list[Mapping[str, object]]:
    """Select the captured log records with the given event name.

    Args:
        captured: The list a ``capture_logs`` context fills in.
        name: The event name to select.

    Returns:
        list[Mapping[str, object]]: The matching records in emission order.
    """
    return [entry for entry in captured if entry.get("event") == name]


def _marked_events(captured: Sequence[Mapping[str, object]], origin: str, names: Sequence[str]) -> list[str]:
    """List, in emission order, the named events that one marked logger emitted.

    Args:
        captured: The list a ``capture_logs`` context fills in.
        origin: The marker the logger under test was bound with.
        names: The event names to keep.

    Returns:
        list[str]: The kept event names in emission order.
    """
    return [str(entry["event"]) for entry in captured if entry.get("origin") == origin and entry.get("event") in names]


def _marked_logger(origin: str) -> BoundLogger:
    """Create a logger whose records carry a marker no other logger sets.

    Args:
        origin: The marker value.

    Returns:
        BoundLogger: A logger bound with ``origin``.
    """
    return get_logger("critcov.main").bind(origin=origin)


def _write_json(path: Path, payload: Mapping[str, object]) -> None:
    """Write a JSON file, creating its directory.

    Args:
        path: The file to write.
        payload: The JSON object to store.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _write_config(path: Path, base: Path, *, theme: str, console_enabled: bool) -> None:
    """Write a TOML configuration whose directories all live under ``base``.

    Args:
        path: The configuration file to write.
        base: The directory the tools, logs and data directories go under.
        theme: The UI theme the file selects.
        console_enabled: Whether the file leaves the console log sink on.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    text = (
        "[general]\n"
        f'tools_directory = "{(base / "tools").as_posix()}"\n'
        f'logs_directory = "{(base / "logs").as_posix()}"\n'
        f'data_directory = "{(base / "data").as_posix()}"\n'
        "\n"
        "[ui]\n"
        f'theme = "{theme}"\n'
        "\n"
        "[log]\n"
        'level = "INFO"\n'
        f"console_enabled = {str(console_enabled).lower()}\n"
    )
    _ = path.write_text(text, encoding="utf-8")


def _orchestrator(tmp_path: Path, *, registry: ToolRegistry | None = None) -> Orchestrator:
    """Build a real orchestrator over empty registries.

    Args:
        tmp_path: A directory private to the test.
        registry: The tool registry to use, or None for a fresh one.

    Returns:
        Orchestrator: The orchestrator.
    """
    return Orchestrator(
        provider_registry=ProviderRegistry(),
        tool_registry=registry if registry is not None else ToolRegistry(tmp_path / "tools"),
        session_manager=SessionManager(SessionStore(tmp_path / "sessions.db")),
    )


def _model(provider: str, model_id: str) -> ModelInfo:
    """Build a model record.

    Args:
        provider: The provider id the model belongs to.
        model_id: The model id.

    Returns:
        ModelInfo: The record.
    """
    return ModelInfo(
        id=model_id,
        name=f"Model {model_id}",
        provider=provider,
        context_window=4096,
        supports_tools=True,
        supports_vision=False,
        supports_streaming=True,
        input_cost_per_1m_tokens=None,
        output_cost_per_1m_tokens=None,
    )


def _finalize_and_collect(loop: asyncio.AbstractEventLoop, manager: ProcessManager, logger: BoundLogger) -> None:
    """Run the final cleanup and then collect garbage so abandoned coroutines report themselves.

    Args:
        loop: The event loop to hand to the cleanup.
        manager: The process manager to hand to the cleanup.
        logger: The logger to hand to the cleanup.
    """
    _finalize_shutdown(loop, manager, logger)
    _ = gc.collect()


def _plain_window() -> MainWindow:
    """Create a real top-level window that stands in where the code under test never touches it.

    Returns:
        MainWindow: A ``QMainWindow`` presented under the main window's type.
    """
    return cast("MainWindow", QMainWindow())


def _child_environment(base: Path) -> dict[str, str]:
    """Build the environment of a child interpreter that must not touch user state.

    Args:
        base: A directory private to the test, holding the redirected state root.

    Returns:
        dict[str, str]: The inherited environment without provider variables, with
        the state root, Qt platform and import path redirected.
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
    paths = [str(REPO_ROOT / "src"), str(REPO_ROOT)]
    env["PYTHONPATH"] = os.pathsep.join([*paths, inherited] if inherited else paths)
    return env


def _last_json_line(stdout: str) -> dict[str, Any]:
    """Decode the last JSON object a child printed.

    Args:
        stdout: The child's standard output.

    Returns:
        dict[str, Any]: The decoded object.

    Raises:
        AssertionError: If the output holds no JSON object line.
    """
    for line in reversed(stdout.splitlines()):
        if line.startswith("{"):
            decoded: dict[str, Any] = json.loads(line)
            return decoded
    message = f"child printed no JSON line:\n{stdout[-3000:]}"
    raise AssertionError(message)


def _thread_dpi_context(user32: ctypes.WinDLL) -> int:
    """Read the DPI awareness context of the calling thread.

    Args:
        user32: The loaded ``user32`` library.

    Returns:
        int: The context handle value.
    """
    get_context = user32.GetThreadDpiAwarenessContext
    get_context.restype = ctypes.c_void_p
    get_context.argtypes = []
    return int(get_context() or 0)


def _same_dpi_context(user32: ctypes.WinDLL, first: int, second: int) -> bool:
    """Ask Windows whether two DPI awareness contexts are the same.

    Args:
        user32: The loaded ``user32`` library.
        first: The first context handle value.
        second: The second context handle value.

    Returns:
        bool: Whether Windows considers the contexts equal.
    """
    are_equal = user32.AreDpiAwarenessContextsEqual
    are_equal.restype = ctypes.c_int
    are_equal.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    return bool(are_equal(ctypes.c_void_p(first), ctypes.c_void_p(second)))


@contextlib.contextmanager
def _preserved_process_state() -> Generator[None]:
    """Put logging, signal handlers and the logger state back as they were found.

    ``setup_logging`` clears the root logger's handlers and records its directory
    in module state; the process manager replaces the interrupt handlers.

    Yields:
        None: Control passes to the code that changes that state.
    """
    watched = [get_stdlib_root_logger(), logging.getLogger("intellicrack"), *(logging.getLogger(name) for name in _NOISY_LOGGERS)]
    saved = [(item, item.level, list(item.handlers), item.propagate) for item in watched]
    logging_module = importlib.import_module("intellicrack.core.logging")
    state = getattr(logging_module, "_logger_state")
    saved_app_logger = getattr(state, "app_logger")
    saved_log_dir = getattr(state, "configured_log_dir")
    saved_interrupt = signal.getsignal(signal.SIGINT)
    saved_break = signal.getsignal(signal.SIGBREAK)
    try:
        yield
    finally:
        for item, level, handlers, propagate in saved:
            for handler in list(item.handlers):
                if handler not in handlers:
                    item.removeHandler(handler)
                    handler.close()
            for handler in handlers:
                if handler not in item.handlers:
                    item.addHandler(handler)
            item.setLevel(level)
            item.propagate = propagate
        setattr(state, "app_logger", saved_app_logger)
        setattr(state, "configured_log_dir", saved_log_dir)
        if saved_interrupt is not None:
            _ = signal.signal(signal.SIGINT, saved_interrupt)
        if saved_break is not None:
            _ = signal.signal(signal.SIGBREAK, saved_break)


@pytest.fixture
def state_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[Path]:
    """Redirect the per-user state root into the test directory with no provider variables set.

    Args:
        tmp_path: Per-test temporary directory.
        monkeypatch: Pytest monkeypatch fixture.

    Yields:
        Path: The redirected state root.
    """
    isolate_provider_environment(monkeypatch)
    with redirected_state_root(monkeypatch, tmp_path) as root:
        yield root
    for instance_id in _INSTANCE_IDS:
        unregister_instance_mapping(instance_id)


@pytest.fixture
def process_manager() -> Generator[ProcessManager]:
    """Provide a fresh ProcessManager singleton and discard it afterwards.

    Yields:
        ProcessManager: A freshly created singleton with an empty registry.
    """
    ProcessManager.reset_instance()
    manager = ProcessManager.get_instance()
    yield manager
    manager.uninstall_handlers()
    ProcessManager.reset_instance()


@pytest.fixture
def restored_application_look(qapp: QApplication) -> Generator[None]:
    """Put the application stylesheet, window icon and theme manager back after a test.

    Args:
        qapp: The Qt application.

    Yields:
        None: Control passes to the test.
    """
    previous_sheet = qapp.styleSheet()
    previous_icon = QApplication.windowIcon()
    yield
    qapp.setStyleSheet(previous_sheet)
    QApplication.setWindowIcon(previous_icon)
    ThemeManager.reset_instance()


def test_cli_log_level_replaces_the_configured_level() -> None:
    """An explicit log level wins over the configured one and leaves both sinks on.

    Falsifiable: replacing ``cli.log_level`` with ``"INFO"`` on main.py line 232
    leaves the configured level in place.
    """
    config = Config.default()
    assert config.log.level == "INFO"

    with capture_logs() as logs:
        _apply_cli_overrides(config, _CLIOptions(log_level="DEBUG"))

    assert config.log.level == "DEBUG"
    assert config.log.console_enabled is True
    assert config.log.file_enabled is True
    assert _events(logs, "all_log_output_disabled") == []


@pytest.mark.parametrize(
    ("disable_console", "disable_file", "console_on", "file_on", "warned"),
    [
        (False, False, True, True, False),
        (True, False, False, True, False),
        (False, True, True, False, False),
        (True, True, False, False, True),
    ],
)
def test_cli_flags_switch_off_exactly_the_sinks_they_name(
    *,
    disable_console: bool,
    disable_file: bool,
    console_on: bool,
    file_on: bool,
    warned: bool,
) -> None:
    """Each disable flag turns off its own sink only, and a warning marks the case with no sink left.

    Falsifiable: assigning ``False`` to ``config.log.file_enabled`` on main.py line
    234 (the console branch) turns the file sink off for ``--no-console-log``.

    Args:
        disable_console: Whether ``--no-console-log`` is given.
        disable_file: Whether ``--no-file-log`` is given.
        console_on: Whether the console sink must remain on.
        file_on: Whether the file sink must remain on.
        warned: Whether the all-sinks-off warning must be logged.
    """
    config = Config.default()

    with capture_logs() as logs:
        _apply_cli_overrides(config, _CLIOptions(disable_console_log=disable_console, disable_file_log=disable_file))

    assert config.log.console_enabled is console_on
    assert config.log.file_enabled is file_on
    assert config.log.level == "INFO"
    warnings = _events(logs, "all_log_output_disabled")
    assert len(warnings) == int(warned)
    assert all(entry["log_level"] == "warning" for entry in warnings)


def test_configured_sinks_that_are_already_off_still_warn() -> None:
    """A configuration that turns both sinks off warns even when no flag is given.

    Falsifiable: changing ``and`` to ``or`` on main.py line 237 stops the warning
    unless both sinks are off, and ``not`` removal on either operand changes the
    case this test sets up.
    """
    config = Config.default()
    config.log.console_enabled = False
    config.log.file_enabled = False

    with capture_logs() as logs:
        _apply_cli_overrides(config, _CLIOptions())

    assert len(_events(logs, "all_log_output_disabled")) == 1


@pytest.mark.parametrize("name", _IMPORTER_NAMES)
def test_each_lazy_importer_returns_the_real_class(name: str) -> None:
    """Every lazy import helper resolves to the class or function defined in its own module.

    Falsifiable: returning ``mod.OrchestratorConfig`` instead of ``mod.Orchestrator``
    on main.py line 318 breaks the orchestrator case; the other helpers fail the same
    way when their attribute is swapped.

    Args:
        name: The helper to call.
    """
    logging_module = importlib.import_module("intellicrack.core.logging")
    dialogs = importlib.import_module("intellicrack.ui.dialogs")
    resources = importlib.import_module("intellicrack.ui.resources")
    app_module = importlib.import_module("intellicrack.ui.app")
    expectations: dict[str, tuple[object, ...]] = {
        "_import_config_module": (Config, get_config_dir),
        "_import_logging_funcs": (logging_module.get_logger, logging_module.setup_logging),
        "_import_process_manager": (ProcessManager,),
        "_import_qt_app": (QApplication,),
        "_import_splash_screen": (dialogs.SplashScreen,),
        "_import_theme_icon_managers": (resources.ThemeManager, resources.IconManager),
        "_import_orchestrator": (Orchestrator,),
        "_import_orchestrator_config": (OrchestratorConfig,),
        "_import_session_classes": (SessionManager, SessionStore),
        "_import_tool_registry": (ToolRegistry,),
        "_import_credential_loader": (CredentialLoader,),
        "_import_main_window": (app_module.MainWindow,),
    }

    result = cast("object", getattr(_main_module, name)())

    actual: tuple[object, ...] = cast("tuple[object, ...]", result) if isinstance(result, tuple) else (result,)
    assert actual == expectations[name]


def test_the_provider_registry_helper_returns_the_process_wide_singleton() -> None:
    """The registry helper hands out the same registry every other caller sees.

    Falsifiable: returning ``ProviderRegistry()`` instead of ``get_registry()`` on
    main.py line 389 returns a registry nobody else shares.
    """
    registry = _get_provider_registry()

    assert isinstance(registry, ProviderRegistry)
    assert registry is get_provider_registry()
    assert _get_provider_registry() is registry


def test_import_timing_is_logged_at_debug_with_milliseconds_rounded() -> None:
    """The import timing record names the module and carries the elapsed time to three decimals.

    Falsifiable: rounding to two decimals on main.py line 410 logs 1.23.
    """
    logger = get_logger("critcov.timing")

    with capture_logs() as logs:
        _log_import_time(logger, "intellicrack.ui.resources", 1.23449)

    records = _events(logs, "import_timing")
    assert len(records) == 1
    assert records[0]["imported_module"] == "intellicrack.ui.resources"
    assert records[0]["elapsed_s"] == pytest.approx(1.234)
    assert records[0]["log_level"] == "debug"


def test_early_dpi_scale_is_the_primary_screens_device_pixel_ratio(qapp: QApplication) -> None:
    """The early splash scale is the primary screen's device pixel ratio as a float.

    Falsifiable: reading ``screen.logicalDotsPerInch()`` instead of
    ``screen.devicePixelRatio()`` on main.py line 424 returns 96.0 or similar.

    Args:
        qapp: The Qt application.
    """
    screen = QGuiApplication.primaryScreen()
    assert screen is not None

    scale = _compute_early_dpi_scale(qapp)

    assert isinstance(scale, float)
    assert scale == pytest.approx(float(screen.devicePixelRatio()))
    assert scale > 0


@pytest.mark.parametrize("kind", ["missing", "undecodable"])
def test_a_missing_or_undecodable_splash_asset_leaves_the_flat_background(qapp: QApplication, tmp_path: Path, kind: str) -> None:
    """With no usable splash image the pixmap is still the requested size, filled with the background colour.

    Falsifiable: returning ``QPixmap()`` instead of ``pixmap`` on main.py line 449
    (missing) or line 453 (undecodable) returns a null pixmap.

    Args:
        qapp: The Qt application.
        tmp_path: Per-test temporary directory.
        kind: Whether the asset is absent or a file that is not an image.
    """
    _ = qapp
    asset = tmp_path / "splash.png"
    if kind == "undecodable":
        _ = asset.write_text("this is text, not a PNG image", encoding="utf-8")
    width, height = 64, 36

    pixmap = _build_early_splash_pixmap(asset, width, height)

    assert (pixmap.width(), pixmap.height()) == (width, height)
    image = pixmap.toImage()
    for x, y in ((0, 0), (width - 1, height - 1), (width // 2, height // 2)):
        color = image.pixelColor(x, y)
        assert (color.red(), color.green(), color.blue()) == _BACKGROUND


def test_per_monitor_awareness_is_requested_or_already_in_force() -> None:
    """Asking for per-monitor-v2 awareness either takes effect or is refused because one is already set.

    The process-wide setting cannot be undone, so the assertion reads what Windows
    reports before and after: a refusal must leave the context unchanged, and no
    refusal must leave the thread in the per-monitor-v2 context.

    Falsifiable: passing ``-3`` instead of ``-4`` as the context on main.py line 501
    leaves the thread in the version-one context when the request is not refused.
    """
    user32 = ctypes.WinDLL("user32")
    before = _thread_dpi_context(user32)

    with capture_logs() as logs:
        _ensure_per_monitor_dpi_awareness()

    after = _thread_dpi_context(user32)
    events = {str(entry["event"]) for entry in logs if str(entry["event"]).startswith("per_monitor_dpi_awareness")}
    assert events <= {_DPI_REJECTED_EVENT}
    if _DPI_REJECTED_EVENT in events:
        assert _same_dpi_context(user32, after, before)
    else:
        assert _same_dpi_context(user32, after, _DPI_CONTEXT_PER_MONITOR_AWARE_V2)


@pytest.mark.usefixtures("restored_application_look")
def test_full_splash_replaces_the_early_splash_and_applies_the_theme(qapp: QApplication) -> None:
    """The upgrade closes the early splash, themes the application and shows the animated splash.

    Falsifiable: deleting ``early_splash.close()`` on main.py line 606 leaves the
    early splash visible; deleting ``theme_manager.apply_theme(theme)`` on line 600
    leaves the requested theme unchanged.

    Args:
        qapp: The Qt application.
    """
    early = QSplashScreen(QPixmap(8, 8))
    early.show()
    assert early.isVisible()
    splash: SplashScreen | None = None
    try:
        with capture_logs() as logs:
            splash = _upgrade_to_full_splash(qapp, early, get_logger("critcov.splash"), "dark")

        assert isinstance(splash, SplashScreen)
        assert splash.isVisible()
        assert not early.isVisible()
        assert ThemeManager.get_instance().requested_theme == "dark"
        assert QApplication.windowIcon().cacheKey() == IconManager.get_instance().get_app_icon().cacheKey()
        timed = [entry["imported_module"] for entry in _events(logs, "import_timing")]
        assert timed == ["intellicrack.ui.resources", "intellicrack.ui.dialogs"]
    finally:
        if splash is not None:
            splash.close()
            splash.deleteLater()
        early.deleteLater()


@pytest.mark.usefixtures("restored_application_look")
def test_full_splash_upgrade_reports_a_destroyed_early_splash_and_returns_none(qapp: QApplication) -> None:
    """A construction failure is logged as a warning and the upgrade gives up instead of raising.

    The early splash's C++ object is destroyed first, so closing it raises the
    ``RuntimeError`` that Qt raises for a deleted wrapper.

    Falsifiable: removing ``RuntimeError`` from the ``except`` tuple on main.py line
    637 lets the error escape.

    Args:
        qapp: The Qt application.
    """
    broken = QSplashScreen()
    sip.delete(broken)

    with capture_logs() as logs:
        result = _upgrade_to_full_splash(qapp, broken, get_logger("critcov.splash"), "dark")

    assert result is None
    failures = _events(logs, "full_splash_upgrade_failed")
    assert len(failures) == 1
    assert failures[0]["log_level"] == "warning"
    assert "deleted" in str(failures[0]["error"])


@pytest.mark.spawns_process
def test_early_splash_builds_the_application_and_the_upgrade_runs_in_a_fresh_process(tmp_path: Path) -> None:
    """In a process with no Qt application the early splash creates it, sized and styled as documented.

    The child then upgrades to the full splash and repeats the upgrade with a
    destroyed early splash, which must come back as ``None`` with a warning.

    Falsifiable: calling ``app.setStyle("Fusion")`` with another style on main.py
    line 533 changes the reported style, and changing ``_EARLY_SPLASH_WIDTH`` changes
    the pixmap size.

    Args:
        tmp_path: Per-test temporary directory.
    """
    completed = subprocess.run(
        [sys.executable, "-c", _EARLY_SPLASH_DRIVER],
        capture_output=True,
        text=True,
        timeout=180,
        env=_child_environment(tmp_path),
        cwd=tmp_path,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr[-4000:]
    facts = _last_json_line(completed.stdout)
    ratio = float(facts["screen_ratio"])
    assert facts["app_before"] is True
    assert facts["app_is_instance"] is True
    assert facts["application_name"] == "Intellicrack"
    assert facts["application_version"] == __version__
    assert facts["style_name"] == "fusion"
    assert facts["pixmap_size"] == [max(1, int(_EARLY_SPLASH_SIZE[0] * ratio)), max(1, int(_EARLY_SPLASH_SIZE[1] * ratio))]
    assert facts["pixmap_ratio"] == ratio
    assert facts["frameless"] is True
    assert facts["early_visible"] is True
    assert facts["splash_class"] == "SplashScreen"
    assert facts["early_visible_after"] is False
    assert facts["splash_visible"] is True
    assert facts["import_timings"] == ["intellicrack.ui.resources", "intellicrack.ui.dialogs"]
    assert facts["failed_result_is_none"] is True
    assert facts["failure_events"] == [["full_splash_upgrade_failed", "warning"]]


@pytest.mark.usefixtures("state_root")
def test_saved_capability_overrides_and_summary_mode_are_applied_to_the_provider() -> None:
    """Per-model overrides and the reasoning-summary mode saved for a provider reach the provider.

    Falsifiable: deleting the ``set_capability_override`` call on main.py line 720
    leaves the provider with no overrides.
    """
    _write_json(
        get_config_file("providers.json"),
        {
            "openai": {
                "schema_version": 3,
                "reasoning_summaries": "off",
                "model_overrides": {"gpt-test": {"supports_vision": True, "context_window": 54321}},
            },
        },
    )
    provider = OpenAIProvider()

    with capture_logs() as logs:
        _apply_saved_capability_overrides(provider, "openai", get_logger("critcov.overrides"))

    assert provider.capability_overrides() == {"gpt-test": CapabilityOverride(supports_vision=True, context_window=54321)}
    assert provider.reasoning_summary_mode.value == "off"
    loaded = _events(logs, "provider_capability_overrides_loaded")
    assert len(loaded) == 1
    assert loaded[0]["provider"] == "openai"
    assert loaded[0]["model_count"] == 1


@pytest.mark.asyncio
@pytest.mark.slow
@pytest.mark.usefixtures("state_root")
async def test_a_provider_connect_that_never_completes_is_abandoned_after_the_startup_timeout() -> None:
    """Startup stops waiting for a hung connect after its timeout and logs a warning.

    The provider stays unconnected and the call returns normally, so the caller can
    still register it for a later reconnect.

    Falsifiable: passing ``timeout=0`` to ``asyncio.wait_for`` on main.py line 793
    makes the call return at once, which the elapsed-time assertion rejects.
    """
    _ = get_env_file().write_text("", encoding="utf-8")
    instance = ProviderInstance(instance_id="stall-gw", api_base="http://127.0.0.1:9", requires_api_key=False)
    provider = _NeverConnectingProvider(instance)
    credentials = CredentialLoader(get_env_file())
    started = time.monotonic()

    with capture_logs() as logs:
        await _connect_provider_at_startup(provider, "stall-gw", credentials, None, get_logger("critcov.connect"))

    elapsed = time.monotonic() - started
    assert provider.is_connected is False
    assert elapsed >= _PROVIDER_STARTUP_TIMEOUT_S - 0.5
    timeouts = _events(logs, "provider_connect_timeout")
    assert len(timeouts) == 1
    assert timeouts[0]["provider"] == "stall-gw"
    assert timeouts[0]["timeout"] == _PROVIDER_STARTUP_TIMEOUT_S
    assert timeouts[0]["log_level"] == "warning"
    assert _events(logs, "provider_connected") == []


@pytest.mark.usefixtures("state_root")
def test_a_saved_instance_record_without_an_id_is_skipped_with_a_warning() -> None:
    """A stored record that names no instance id is dropped and the valid ones are still loaded.

    Falsifiable: replacing ``continue`` with ``pass`` on main.py line 936 appends a
    ``None`` instance to the result.
    """
    valid = ProviderInstance(instance_id="gw-valid", api_base="http://127.0.0.1:9", requires_api_key=False)
    _write_json(
        get_config_file("providers.json"),
        {
            "instances": {
                "gw-bad": {"api_base": "http://127.0.0.1:9"},
                "gw-valid": valid.to_mapping() | {"instance_id": "gw-valid"},
            },
        },
    )

    with capture_logs() as logs:
        loaded = _saved_provider_instances(get_logger("critcov.instances"))

    assert [getattr(instance, "instance_id") for instance in loaded] == ["gw-valid"]
    invalid = _events(logs, "provider_instance_record_invalid")
    assert len(invalid) == 1
    assert invalid[0]["instance_id"] == "gw-bad"
    assert invalid[0]["log_level"] == "warning"


@pytest.mark.usefixtures("state_root")
def test_an_explicit_config_path_that_does_not_exist_is_refused_and_logged() -> None:
    """A missing ``--config`` file resolves to nothing and is reported as an error.

    Falsifiable: returning ``config_path`` instead of ``None`` on main.py line 1025
    hands the missing path to the loader.
    """
    missing = get_config_dir() / "absent" / "config.toml"

    with capture_logs() as logs:
        resolved = _resolve_config_path(_CLIOptions(config_path=missing), get_config_dir)

    assert resolved is None
    records = _events(logs, "config_path_missing")
    assert len(records) == 1
    assert records[0]["config_path"] == str(missing)
    assert records[0]["log_level"] == "error"


@pytest.mark.usefixtures("state_root")
def test_an_existing_explicit_config_path_is_used_as_given(tmp_path: Path) -> None:
    """An explicit ``--config`` file that exists is the file used, whatever the default directory holds.

    Falsifiable: returning ``get_config_dir() / "config.toml"`` on main.py line 1026
    regardless of the option returns the default location.

    Args:
        tmp_path: Per-test temporary directory.
    """
    chosen = tmp_path / "chosen.toml"
    _ = chosen.write_text("", encoding="utf-8")

    assert _resolve_config_path(_CLIOptions(config_path=chosen), get_config_dir) == chosen


@pytest.mark.usefixtures("state_root")
def test_without_an_option_the_config_path_is_the_state_root_default() -> None:
    """With no explicit path the configuration file is ``config.toml`` in the state root's config directory.

    Falsifiable: using ``"settings.toml"`` as the file name on main.py line 1022
    changes the resolved name.
    """
    resolved = _resolve_config_path(_CLIOptions(), get_config_dir)

    assert resolved == get_config_dir() / "config.toml"


@pytest.mark.usefixtures("state_root")
def test_startup_with_a_missing_explicit_config_returns_none_and_installs_nothing(
    tmp_path: Path,
    process_manager: ProcessManager,
) -> None:
    """A bad ``--config`` ends startup before logging is set up or any handler is installed.

    Falsifiable: removing the ``if config_path is None: return None`` check on main.py
    lines 1067-1068 makes the next line load the missing file and raise.

    Args:
        tmp_path: Per-test temporary directory.
        process_manager: A fresh process manager singleton.
    """
    with _preserved_process_state():
        before = list(get_stdlib_root_logger().handlers)

        result = _load_startup_config(_CLIOptions(config_path=tmp_path / "nowhere.toml"))

        assert result is None
        assert list(get_stdlib_root_logger().handlers) == before
        assert process_manager.atexit_registered is False


@pytest.mark.parametrize("explicit", [True, False])
@pytest.mark.usefixtures("state_root")
def test_startup_loads_the_config_applies_overrides_and_starts_logging_and_the_process_manager(
    tmp_path: Path,
    process_manager: ProcessManager,
    *,
    explicit: bool,
) -> None:
    """Startup returns the loaded configuration with flag overrides applied, and file logging running.

    The file comes either from ``--config`` or from the state root's config
    directory. The configured directories are created, the root logger takes the
    overridden level and one rotating file handler in the configured log directory,
    and the process manager singleton has its handlers installed.

    Falsifiable: dropping the ``_apply_cli_overrides(config, cli_options)`` call on
    main.py line 1070 leaves the level at the file's ``INFO`` and the console sink on.

    Args:
        tmp_path: Per-test temporary directory.
        process_manager: A fresh process manager singleton.
        explicit: Whether the file is named by ``--config`` or found by default.
    """
    base = tmp_path / "startup"
    config_file = tmp_path / "chosen.toml" if explicit else get_config_dir() / "config.toml"
    _write_config(config_file, base, theme="light", console_enabled=True)
    cli = _CLIOptions(config_path=config_file if explicit else None, log_level="DEBUG", disable_console_log=True)
    root = get_stdlib_root_logger()

    with _preserved_process_state():
        before = list(root.handlers)

        result = _load_startup_config(cli)

        assert result is not None
        config, logger, manager = result
        assert config.ui.theme == "light"
        assert config.log.level == "DEBUG"
        assert config.log.console_enabled is False
        assert config.tools_directory == base / "tools"
        assert all((base / name).is_dir() for name in ("tools", "logs", "data"))
        assert manager is process_manager
        assert process_manager.atexit_registered is True
        assert logger is getattr(_main_module, "_logger")
        added = [handler for handler in root.handlers if handler not in before]
        assert [type(handler) for handler in added] == [RotatingFileHandler]
        assert Path(cast("RotatingFileHandler", added[0]).baseFilename) == base / "logs" / "intellicrack.log"
        assert root.level == logging.DEBUG
        lines = (base / "logs" / "intellicrack.log").read_text(encoding="utf-8").splitlines()
        started = [record for record in (json.loads(line) for line in lines if line.startswith("{")) if record["event"] == "app_starting"]
        assert len(started) == 1
        assert started[0]["version"] == __version__
        assert started[0]["log_level"] == "DEBUG"


def test_final_cleanup_runs_the_process_manager_cleanup_and_closes_the_loop(process_manager: ProcessManager) -> None:
    """The final cleanup awaits the process manager's cleanup on the loop and then closes the loop.

    Falsifiable: deleting the ``loop.run_until_complete`` call on main.py lines
    1038-1043 skips the cleanup, so the ``async_cleanup_started`` record never appears.

    Args:
        process_manager: A fresh process manager singleton.
    """
    loop = asyncio.new_event_loop()
    try:
        with capture_logs() as logs:
            _finalize_shutdown(loop, process_manager, get_logger("critcov.finalize"))

        assert loop.is_closed()
        assert len(_events(logs, "async_cleanup_started")) == 1
        assert len(_events(logs, "handlers_uninstalled")) == 1
        assert _events(logs, "final_process_cleanup_failed") == []
    finally:
        loop.close()


def test_final_cleanup_survives_a_loop_that_is_already_closed(process_manager: ProcessManager) -> None:
    """A loop that cannot run the cleanup is logged at debug level and the teardown still completes.

    Running anything on a closed loop raises ``RuntimeError``; the two coroutines
    built for the call are then never awaited, which Python reports as warnings.

    Falsifiable: removing ``RuntimeError`` from the ``except (OSError, RuntimeError)``
    tuple on main.py line 1046 lets the error escape.

    Args:
        process_manager: A fresh process manager singleton.
    """
    loop = asyncio.new_event_loop()
    loop.close()

    with capture_logs() as logs, pytest.warns(RuntimeWarning, match="never awaited"):
        _finalize_and_collect(loop, process_manager, get_logger("critcov.finalize"))

    failures = _events(logs, "final_process_cleanup_failed")
    assert len(failures) == 1
    assert failures[0]["log_level"] == "debug"
    assert len(_events(logs, "handlers_uninstalled")) == 1
    assert loop.is_closed()


@pytest.mark.usefixtures("state_root")
def test_a_failing_template_export_is_logged_as_a_partial_bootstrap() -> None:
    """When one built-in template cannot be written, startup logs the failure and returns the manager.

    A directory is created where the first built-in template's JSON file would be
    written, so exporting it fails while the others succeed.

    Falsifiable: replacing ``bootstrap_error_cls`` with ``ValueError`` on main.py line
    1238 lets the bootstrap error escape instead of being logged.
    """
    hexcore = importlib.import_module("intellicrack_hexcore")
    open_bytes = cast("Callable[[bytes], object]", hexcore.HexDocument.open_bytes)
    document = open_bytes(b"")
    list_templates = cast("Callable[[], list[tuple[str, str, str, int]]]", getattr(document, "list_templates_detailed"))
    entries = list_templates()
    assert len(entries) > 1
    blocked_name = entries[0][0]
    template_manager = TemplateManager(get_config_dir())
    template_manager.ensure_directories()
    builtin_root = get_config_dir() / "templates" / "builtin"
    for category_dir in (path for path in builtin_root.iterdir() if path.is_dir()):
        (category_dir / f"{blocked_name}.json").mkdir()

    with capture_logs() as logs:
        manager = init_template_manager(get_logger("critcov.templates"))

    assert isinstance(manager, TemplateManager)
    partial = _events(logs, "template_bootstrap_partial")
    assert len(partial) == 1
    assert partial[0]["failed_count"] == 1
    failed_paths = cast("list[str]", partial[0]["failed_paths"])
    assert len(failed_paths) == 1
    assert Path(failed_paths[0]).name == f"{blocked_name}.json"
    assert Path(failed_paths[0]).is_dir()
    startup_successes = [entry for entry in _events(logs, "template_manager_initialized") if entry["log_level"] == "info"]
    assert startup_successes == []


@pytest.mark.asyncio
async def test_model_discovery_startup_loads_the_saved_cache(tmp_path: Path) -> None:
    """An existing discovery cache file is loaded into the new discovery object.

    The cache is written by a first discovery object through its own save call and
    read back by the startup helper, which also reports the cache path.

    Falsifiable: deleting the ``await load_cache(discovery_cache)`` on main.py line
    1272 leaves the new object's cache empty.

    Args:
        tmp_path: Per-test temporary directory.
    """
    config = Config(tools_directory=tmp_path / "tools", logs_directory=tmp_path / "logs", data_directory=tmp_path / "data")
    cache_path = config.data_directory / "model_discovery_cache.json"
    seeded = ModelDiscovery(ProviderRegistry())
    seeded.cache.set("gw-test", [_model("gw-test", "m-1"), _model("gw-test", "m-2")])
    await seeded.save_cache(cache_path)
    assert cache_path.exists()

    discovery, reported_path = await init_model_discovery(ProviderRegistry(), config, get_logger("critcov.discovery"))

    assert reported_path == cache_path
    assert isinstance(discovery, ModelDiscovery)
    cached = discovery.cache.get("gw-test")
    assert cached is not None
    assert [model.id for model in cached] == ["m-1", "m-2"]


def test_clearing_the_model_cache_empties_the_global_cache() -> None:
    """The shutdown helper empties the process-wide model cache and says so.

    Falsifiable: deleting the ``clear_fn()`` call on main.py line 1342 leaves the
    cached model in place.
    """
    torch = importlib.import_module("torch")
    model_loader = importlib.import_module("intellicrack.providers.model_loader")
    cache = model_loader.get_global_model_cache()
    cache.clear()
    loaded_model = model_loader.LoadedModel(
        model=cast("Any", object()),
        tokenizer=cast("Any", object()),
        device=torch.device("cpu"),
        dtype="float32",
        memory_usage_bytes=4096,
        model_id="clear-test",
        load_time_seconds=0.0,
    )
    try:
        cache.put(loaded_model)
        assert cache.get("clear-test", "float32", "cpu") is loaded_model
        assert cache.get_memory_usage() == 4096

        with capture_logs() as logs:
            _clear_model_cache(_marked_logger("clear-cache"))

        assert cache.get("clear-test", "float32", "cpu") is None
        assert cache.get_memory_usage() == 0
        assert _marked_events(logs, "clear-cache", ["model_cache_cleared"]) == ["model_cache_cleared"]
    finally:
        cache.clear()


@pytest.mark.parametrize("registry_kind", ["none", "plain_object"])
def test_an_orchestrator_without_a_sandbox_accessor_wires_nothing(qapp: QApplication, tmp_path: Path, registry_kind: str) -> None:
    """Startup wiring is a silent no-op when the orchestrator has no tool registry or one without a sandbox accessor.

    Falsifiable: replacing ``return`` with ``pass`` on main.py line 1405 makes the next
    line call ``None`` and raise ``TypeError``.

    Args:
        qapp: The Qt application.
        tmp_path: Per-test temporary directory.
        registry_kind: Whether the orchestrator's registry is ``None`` or a bare object.
    """
    _ = qapp
    orchestrator = _orchestrator(tmp_path)
    replacement: object | None = None if registry_kind == "none" else object()
    setattr(orchestrator, "_tools", replacement)
    window = _plain_window()
    try:
        with capture_logs() as logs:
            _wire_preregistered_sandbox(window, orchestrator)

        assert _events(logs, "preregistered_sandbox_wired_into_main_window") == []
        assert _events(logs, "preregistered_sandbox_bridge_lookup_failed") == []
    finally:
        window.close()
        window.deleteLater()


def test_a_registered_bridge_with_no_sandbox_instances_wires_nothing(qapp: QApplication, tmp_path: Path) -> None:
    """A sandbox bridge whose manager holds no instance leaves the window alone.

    Falsifiable: deleting the ``if not instances: return`` guard on main.py lines
    1416-1417 makes the next line index an empty list and raise ``IndexError``.

    Args:
        qapp: The Qt application.
        tmp_path: Per-test temporary directory.
    """
    _ = qapp
    registry = ToolRegistry(tmp_path / "tools")
    bridge = SandboxBridge()
    bridge.attach_manager(SandboxManager())
    registry.register_bridge(ToolName.SANDBOX, bridge)
    orchestrator = _orchestrator(tmp_path, registry=registry)
    window = _plain_window()
    try:
        with capture_logs() as logs:
            _wire_preregistered_sandbox(window, orchestrator)

        assert _events(logs, "preregistered_sandbox_wired_into_main_window") == []
    finally:
        window.close()
        window.deleteLater()


def test_detaching_the_qt_log_handler_removes_it_from_the_root_logger(qapp: QApplication) -> None:
    """Shutdown detaches the Qt-signalling log handler and forgets it.

    Falsifiable: deleting the ``uninstall()`` call on main.py line 1452 leaves the
    handler installed.

    Args:
        qapp: The Qt application.
    """
    _ = qapp
    handler = install_qt_log_handler()
    root = get_stdlib_root_logger()
    try:
        assert handler in root.handlers
        assert get_qt_log_handler() is handler

        _detach_qt_log_handler(_marked_logger("detach"))

        assert get_qt_log_handler() is None
        assert handler not in root.handlers
    finally:
        uninstall_qt_log_handler()


@pytest.mark.asyncio
async def test_cancelling_bridge_tasks_lets_them_finish_their_cancellation() -> None:
    """Pending bridge coroutines are cancelled and given one loop turn to run their cleanup.

    Falsifiable: deleting the ``await asyncio.sleep(0)`` on main.py line 1488 leaves
    the coroutine's cancellation handler unrun when the helper returns.
    """
    flags: list[str] = []

    async def sleeper() -> None:
        """Wait until cancelled and record the cancellation.

        Raises:
            asyncio.CancelledError: Always, after recording, as asyncio requires.
        """
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            flags.append("cancelled")
            raise

    assert run_bridge_coroutine(sleeper()) is None
    await asyncio.sleep(0)
    assert flags == []

    with capture_logs() as logs:
        await _cancel_pending_bridge_tasks(_marked_logger("cancel-normal"))

    assert flags == ["cancelled"]
    cancelled = [entry for entry in logs if entry.get("origin") == "cancel-normal" and entry["event"] == "pending_bridge_tasks_cancelled"]
    assert len(cancelled) == 1
    assert cancelled[0]["count"] == 1


@pytest.mark.asyncio
async def test_an_interrupted_cancellation_drain_is_logged_and_does_not_raise() -> None:
    """If the drain itself is cancelled, the helper logs a warning and returns normally.

    The helper runs as a task that is cancelled while it waits for its one loop turn.

    Falsifiable: changing ``except asyncio.CancelledError`` to ``except ValueError`` on
    main.py line 1489 lets the cancellation escape and ``await task`` raise.
    """
    flags: list[str] = []

    async def sleeper() -> None:
        """Wait until cancelled and record the cancellation.

        Raises:
            asyncio.CancelledError: Always, after recording, as asyncio requires.
        """
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            flags.append("cancelled")
            raise

    assert run_bridge_coroutine(sleeper()) is None
    await asyncio.sleep(0)

    with capture_logs() as logs:
        task = asyncio.create_task(_cancel_pending_bridge_tasks(_marked_logger("cancel-interrupted")))
        await asyncio.sleep(0)
        _ = task.cancel()
        await task
        await asyncio.sleep(0)

    assert task.done()
    assert not task.cancelled()
    interrupted = [entry for entry in logs if entry.get("origin") == "cancel-interrupted" and entry["event"] == "cancel_drain_interrupted"]
    assert len(interrupted) == 1
    assert interrupted[0]["log_level"] == "warning"
    assert flags == ["cancelled"]


def test_the_bridge_loop_is_stopped_and_drained_workers_are_logged_only_when_there_were_some() -> None:
    """Stopping the bridge loop reports a drained-worker count only when workers were retained.

    The expected count is read from the public drain function just before the call,
    so the test holds whether or not earlier tests left finished workers retained.

    Falsifiable: logging ``bridge_workers_drained`` unconditionally on main.py line
    1509 logs it when no worker was retained.
    """
    loop = ensure_loop()
    assert loop.is_running()
    expected = drain_bridge_workers()
    try:
        with capture_logs() as logs:
            _drain_and_stop_bridge_loop(_marked_logger("drain"))

        assert not loop.is_running()
        drained = [entry for entry in logs if entry.get("origin") == "drain" and entry["event"] == "bridge_workers_drained"]
        if expected:
            assert [entry["count"] for entry in drained] == [expected]
        else:
            assert drained == []
    finally:
        shutdown_bridge_loop()


@pytest.mark.asyncio
async def test_shutdown_runs_every_stage_and_leaves_the_application_torn_down(
    tmp_path: Path,
    qapp: QApplication,
    process_manager: ProcessManager,
) -> None:
    """The shutdown sequence disconnects providers, saves the discovery cache and stops every service.

    Everything is a real object: a connected provider, a discovery object with one
    cached model, an orchestrator, a session manager, the process manager, the Qt log
    handler and the bridge loop.

    Falsifiable: deleting the ``await cast("Awaitable[None]", save_cache(discovery_cache))``
    statement on main.py line 1545 leaves no cache file, and deleting
    ``_drain_and_stop_bridge_loop(logger)`` on line 1576 leaves the bridge loop running.

    Args:
        tmp_path: Per-test temporary directory.
        qapp: The Qt application.
        process_manager: A fresh process manager singleton.
    """
    _ = qapp
    cache_path = tmp_path / "discovery.json"
    registry = ProviderRegistry()
    provider = ConfigurableProvider(ProviderInstance(instance_id="shut-gw", api_base="http://127.0.0.1:9", requires_api_key=False))
    await provider.connect(ProviderCredentials(api_base="http://127.0.0.1:9"))
    registry.register(provider)
    assert provider.is_connected
    discovery = ModelDiscovery(registry)
    discovery.cache.set("shut-gw", [_model("shut-gw", "m-1")])
    session_manager = SessionManager(SessionStore(tmp_path / "sessions.db"))
    orchestrator = Orchestrator(provider_registry=registry, tool_registry=ToolRegistry(tmp_path / "tools"), session_manager=session_manager)
    handler = install_qt_log_handler()
    loop = ensure_loop()
    assert loop.is_running()
    try:
        with capture_logs() as logs:
            await _shutdown_application(
                logger=_marked_logger("shutdown"),
                provider_registry=registry,
                orchestrator=orchestrator,
                session_manager=session_manager,
                process_manager=process_manager,
                model_discovery=discovery,
                discovery_cache=cache_path,
            )

        stages = ["shutdown_started", "model_cache_cleared", "shutdown_complete"]
        assert _marked_events(logs, "shutdown", stages) == stages
        assert provider.is_connected is False
        assert get_qt_log_handler() is None
        assert handler not in get_stdlib_root_logger().handlers
        assert not loop.is_running()
        assert len(_events(logs, "orchestrator_shutdown_completed")) == 1
        assert len(_events(logs, "async_cleanup_started")) == 1
        saved = json.loads(cache_path.read_text(encoding="utf-8"))
        assert [model["id"] for model in saved["entries"]["shut-gw"]["models"]] == ["m-1"]
    finally:
        shutdown_bridge_loop()
        uninstall_qt_log_handler()
        await session_manager.close()


@pytest.mark.asyncio
@pytest.mark.slow
async def test_a_stalled_stage_is_abandoned_after_its_timeout_and_shutdown_carries_on(
    tmp_path: Path,
    process_manager: ProcessManager,
) -> None:
    """Each stage that never finishes costs its timeout, is reported, and the later stages still run.

    A provider whose disconnect never completes, an orchestrator whose shutdown never
    completes and a session manager whose close never completes are shut down in turn.

    Falsifiable: removing ``TimeoutError`` from the ``except`` clause on main.py line
    1559 lets the stalled orchestrator's timeout escape and skips the session stage.

    Args:
        tmp_path: Per-test temporary directory.
        process_manager: A fresh process manager singleton.
    """
    registry = ProviderRegistry()
    provider = _StalledProvider(ProviderInstance(instance_id="shut-gw", api_base="http://127.0.0.1:9", requires_api_key=False))
    provider.connected = True
    registry.register(provider)
    session_manager = _StalledSessionManager(SessionStore(tmp_path / "sessions.db"))
    orchestrator = _StalledOrchestrator(
        provider_registry=registry,
        tool_registry=ToolRegistry(tmp_path / "tools"),
        session_manager=session_manager,
    )
    started = time.monotonic()

    with capture_logs() as logs:
        await _shutdown_application(
            logger=_marked_logger("stalled"),
            provider_registry=registry,
            orchestrator=orchestrator,
            session_manager=session_manager,
            process_manager=process_manager,
            model_discovery=ModelDiscovery(registry),
            discovery_cache=tmp_path / "discovery.json",
        )

    elapsed = time.monotonic() - started
    stages = [
        "shutdown_started",
        "provider_disconnect_timeout",
        "model_cache_cleared",
        "orchestrator_shutdown_timeout",
        "session_close_timeout",
        "shutdown_complete",
    ]
    assert _marked_events(logs, "stalled", stages) == stages
    assert elapsed >= 5.0 + 5.0 + 3.0 - 0.5
    assert provider.is_connected is True


@pytest.mark.spawns_process
@pytest.mark.slow
def test_a_whole_launch_starts_the_interface_and_shuts_down_cleanly(tmp_path: Path) -> None:
    """``main()`` walks every startup stage, enters the event loop and shuts down with status zero.

    A child interpreter runs ``main()`` against a redirected state root with the local
    providers disabled; a watcher thread asks the application to quit once its event
    loop is running. The stage records are read back from the child's JSON log file.

    Falsifiable: returning ``1`` instead of ``exit_code`` on main.py line 1694 changes
    the child's reported status, and deleting ``logger.info("ui_started")`` on line
    1674 drops a stage from the log.

    Args:
        tmp_path: Per-test temporary directory.
    """
    env = _child_environment(tmp_path)
    state_dir = Path(env["INTELLICRACK_STATE_DIR"])
    _write_json(state_dir / ".intellicrack" / "providers.json", _OFFLINE_SECTIONS)
    _ = (state_dir / ".env").write_text("", encoding="utf-8")
    config_file = tmp_path / "launch.toml"
    _write_config(config_file, tmp_path / "launch", theme="dark", console_enabled=False)

    completed = subprocess.run(
        [sys.executable, "-c", _GUI_DRIVER, "--no-elevate", "--config", str(config_file)],
        capture_output=True,
        text=True,
        timeout=420,
        env=env,
        cwd=tmp_path,
        check=False,
    )

    log_file = tmp_path / "launch" / "logs" / "intellicrack.log"
    log_text = log_file.read_text(encoding="utf-8") if log_file.exists() else ""
    tail = f"stdout:\n{completed.stdout[-2000:]}\nstderr:\n{completed.stderr[-2000:]}\nlog:\n{log_text[-3000:]}"
    reported = _last_json_line(completed.stdout)
    assert reported["exit_code"] == 0, tail
    records = [json.loads(line) for line in log_text.splitlines() if line.startswith("{")]
    names = [str(record["event"]) for record in records]
    positions = [names.index(stage) for stage in _GUI_STAGES if stage in names]
    assert len(positions) == len(_GUI_STAGES), tail
    assert positions == sorted(positions), tail
    assert "application_failed" not in names
    assert "shutdown_failed" not in names


@pytest.mark.spawns_process
def test_the_entry_point_exits_with_status_one_for_a_missing_config_file(tmp_path: Path) -> None:
    """``python -m intellicrack.main --config <missing file>`` reports the file and exits with status 1.

    Falsifiable: returning ``0`` instead of ``1`` on main.py line 1108 changes the exit
    status.

    Args:
        tmp_path: Per-test temporary directory.
    """
    completed = subprocess.run(
        [sys.executable, "-m", "intellicrack.main", "--no-elevate", "--config", str(tmp_path / "absent.toml")],
        capture_output=True,
        text=True,
        timeout=240,
        env=_child_environment(tmp_path),
        cwd=tmp_path,
        check=False,
    )

    assert completed.returncode == 1, completed.stderr[-4000:]
    assert "config_path_missing" in completed.stdout + completed.stderr
