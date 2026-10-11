# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Third-pass coverage for the application entry point, built from facts measured in the test container.

Saved provider instances run in the pytest process against a redirected state root. Everything that
needs a process of its own runs in a child interpreter this module starts: a second Qt application
(Qt allows one per process), the missing native hex backend (the import system is told the package is
absent), a real main window built without a template manager, and a child that strips its own debug
privilege and rewrites the access list of a grandchild so the operating system refuses to end it.

Measured in the container and relied on here: a second ``QApplication`` is constructed without error
whether the first application is a ``QApplication`` or a ``QCoreApplication``; ``httpx.InvalidURL``
derives straight from ``Exception``; ``httpx`` rejects a non-ASCII header with ``UnicodeEncodeError``
(a ``ValueError``); and a process whose access list denies ``PROCESS_TERMINATE`` stays running while
``psutil`` raises ``AccessDenied`` for it.
"""

from __future__ import annotations

import importlib
import json
import os
import subprocess
import sys
from typing import TYPE_CHECKING, Any, Final, cast

import pytest
from structlog.testing import capture_logs

from intellicrack._metadata import __version__
from intellicrack.core.config import get_config_file, get_env_file
from intellicrack.core.logging import get_logger
from intellicrack.credentials.env_loader import CredentialLoader, unregister_instance_mapping
from intellicrack.providers.registry import ProviderRegistry
from tests._helpers.child_python import REPO_ROOT
from tests._helpers.provider_state import isolate_provider_environment, provider_environment_variables, redirected_state_root


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Generator, Mapping, Sequence
    from pathlib import Path

    from structlog.stdlib import BoundLogger

    from intellicrack.credentials.provider_settings import ProviderConnectPolicy


pytestmark = pytest.mark.spawns_process

_INSTANCE_IDS: Final[tuple[str, ...]] = ("gw-hdr", "gw-url")

_main_module = importlib.import_module("intellicrack.main")
_initialize_saved_instances = cast(
    "Callable[[ProviderRegistry, CredentialLoader, BoundLogger, ProviderConnectPolicy | None], Coroutine[object, object, None]]",
    getattr(_main_module, "_initialize_saved_instances"),
)

_SECOND_APP_DRIVER: Final[str] = r"""
import importlib
import json
import sys

from PyQt6.QtCore import QCoreApplication
from PyQt6.QtWidgets import QApplication
from structlog.testing import capture_logs

kind = sys.argv[1]
first = {'qapp': QApplication, 'qcore': QCoreApplication}[kind](['driver'])
main_module = importlib.import_module('intellicrack.main')
with capture_logs() as logs:
    app, splash = main_module._show_early_splash_impl()
facts = {
    'first_type': type(first).__name__,
    'app_type': type(app).__name__,
    'app_is_first': app is first,
    'instance_is_app': QApplication.instance() is app,
    'splash_type': type(splash).__name__,
    'application_name': QApplication.applicationName(),
    'application_version': QApplication.applicationVersion(),
    'dpi_events': [entry['event'] for entry in logs if entry['event'].startswith('per_monitor_dpi_awareness')],
}
splash.close()
sys.stdout.write(json.dumps(facts) + '\n')
sys.stdout.flush()
"""

_NO_HEXCORE_DRIVER: Final[str] = r"""
import importlib
import json
import sys

from structlog.testing import capture_logs

from intellicrack.core.config import get_config_dir
from intellicrack.core.logging import get_logger

sys.modules['intellicrack_hexcore'] = None
main_module = importlib.import_module('intellicrack.main')
with capture_logs() as logs:
    template_manager = main_module._init_template_manager(get_logger('critcov.no_hexcore'))
templates = get_config_dir() / 'templates'
facts = {
    'blocked': sys.modules['intellicrack_hexcore'] is None,
    'result_type': type(template_manager).__name__,
    'failed_templates': [str(path) for path, _ in template_manager.failed_templates],
    'builtin_dir_created': (templates / 'builtin').is_dir(),
    'user_dir_created': (templates / 'user').is_dir(),
    'template_files': sorted(str(path) for path in templates.rglob('*.json')),
    'events': [[entry['event'], entry['log_level'], entry.get('reason')] for entry in logs],
}
sys.stdout.write(json.dumps(facts) + '\n')
sys.stdout.flush()
"""

_WINDOW_DRIVER: Final[str] = r"""
import asyncio
import importlib
import json
import sys
from pathlib import Path

from PyQt6.QtCore import QSettings
from PyQt6.QtWidgets import QApplication
from structlog.testing import capture_logs

from intellicrack.core.config import Config
from intellicrack.core.logging import get_logger
from intellicrack.core.orchestrator import Orchestrator
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.providers.discovery import ModelDiscovery
from intellicrack.providers.registry import ProviderRegistry

base = Path(sys.argv[1])
QSettings.setDefaultFormat(QSettings.Format.IniFormat)
QSettings.setPath(QSettings.Format.IniFormat, QSettings.Scope.UserScope, str(base / 'settings'))
main_module = importlib.import_module('intellicrack.main')
app = QApplication(['driver'])
tools = base / 'tools'
tools.mkdir(parents=True, exist_ok=True)
config = Config(tools_directory=tools, logs_directory=base / 'logs', data_directory=base / 'data')
config.ensure_directories()
registry = ProviderRegistry()
session_manager = SessionManager(SessionStore(base / 'sessions.db'))
orchestrator = Orchestrator(provider_registry=registry, tool_registry=ToolRegistry(tools), session_manager=session_manager)
script_manager, script_validator, script_generator = main_module._init_script_engine(config, get_logger('critcov.window'))
discovery = ModelDiscovery(registry)
window = None
facts = {}
try:
    with capture_logs() as logs:
        window = main_module._create_main_window(
            config=config,
            orchestrator=orchestrator,
            script_manager=script_manager,
            script_validator=script_validator,
            script_generator=script_generator,
            template_manager=None,
            model_discovery=discovery,
        )
    facts = {
        'window_type': type(window).__name__,
        'template_manager_is_none': window.template_manager is None,
        'model_discovery_is_passed': window.model_discovery is discovery,
        'events': [entry['event'] for entry in logs],
    }
finally:
    if window is not None:
        window.close()
    app.processEvents()
    asyncio.run(session_manager.close())
sys.stdout.write(json.dumps(facts) + '\n')
sys.stdout.flush()
"""

_SYNC_DENIED_DRIVER: Final[str] = r"""
import ctypes
import json
import subprocess
import sys
from ctypes import wintypes

from intellicrack.bridges.win32_types import LUID, TOKEN_PRIVILEGES
from intellicrack.core.process_manager import ProcessManager

TERMINATE = 0x1
SYNCHRONIZE = 0x00100000
READ_CONTROL = 0x00020000
WRITE_DAC = 0x00040000
SPECIFIC_RIGHTS = 0xFFFF
TOKEN_QUERY = 0x8
TOKEN_ADJUST_PRIVILEGES = 0x20
SE_PRIVILEGE_REMOVED = 0x4
DACL_SECURITY_INFORMATION = 0x4
SDDL_REVISION_1 = 1
ERROR_ACCESS_DENIED = 5
ALLOWED = SYNCHRONIZE | READ_CONTROL | WRITE_DAC | SPECIFIC_RIGHTS

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
kernel32.GetCurrentProcess.restype = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.LocalFree.argtypes = [ctypes.c_void_p]
kernel32.OpenProcess.restype = ctypes.c_void_p
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
advapi32.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p]
advapi32.AdjustTokenPrivileges.argtypes = [
    wintypes.HANDLE, wintypes.BOOL, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p,
]
advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
]
advapi32.SetKernelObjectSecurity.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p]

token = wintypes.HANDLE()
assert advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, ctypes.byref(token))
luid = LUID()
assert advapi32.LookupPrivilegeValueW(None, 'SeDebugPrivilege', ctypes.byref(luid))
request = TOKEN_PRIVILEGES()
request.PrivilegeCount = 1
request.Privileges[0].Luid = luid
request.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED
advapi32.AdjustTokenPrivileges(token, 0, ctypes.byref(request), ctypes.sizeof(request), None, None)
kernel32.CloseHandle(token)

SCRIPT = 'import sys\nprint("ready", flush=True)\nsys.stdin.read()\n'


def spawn():
    child = subprocess.Popen(
        [sys.executable, '-c', SCRIPT], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    assert child.stdout.readline().strip() == b'ready'
    return child


def reap(child):
    if child.poll() is None:
        child.kill()
    child.wait(timeout=15)
    child.stdin.close()
    child.stdout.close()


denied = spawn()
ordinary = spawn()
manager = ProcessManager.get_instance()
facts = {}
try:
    manager.register_external_pid(denied.pid, name='denied-target')
    manager.register_external_pid(ordinary.pid, name='ordinary-target')
    sddl = 'D:(D;;0x%x;;;WD)(A;;0x%x;;;WD)' % (TERMINATE, ALLOWED)
    descriptor = ctypes.c_void_p()
    assert advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, SDDL_REVISION_1, ctypes.byref(descriptor), None,
    )
    assert advapi32.SetKernelObjectSecurity(int(denied._handle), DACL_SECURITY_INFORMATION, descriptor)
    kernel32.LocalFree(descriptor)
    handle = kernel32.OpenProcess(TERMINATE, 0, denied.pid)
    facts['terminate_refused'] = (not handle) and ctypes.get_last_error() == ERROR_ACCESS_DENIED
    if handle:
        kernel32.CloseHandle(handle)
    manager.DEFAULT_GRACEFUL_TIMEOUT = 0.5
    manager.DEFAULT_FORCE_TIMEOUT = 0.5
    raised = None
    try:
        manager._sync_cleanup()
    except Exception as exc:
        raised = type(exc).__name__
    facts['raised'] = raised
    facts['denied_running'] = denied.poll() is None
    facts['ordinary_running'] = ordinary.poll() is None
    facts['cleanup_in_progress'] = manager._cleanup_in_progress
finally:
    manager._cleanup_in_progress = False
    reap(denied)
    reap(ordinary)
sys.stdout.write(json.dumps(facts) + '\n')
sys.stdout.flush()
"""


def _events(captured: Sequence[Mapping[str, object]], name: str) -> list[Mapping[str, object]]:
    """Select the captured log records with the given event name.

    Args:
        captured: The list a ``capture_logs`` context fills in.
        name: The event name to select.

    Returns:
        list[Mapping[str, object]]: The matching records in emission order.
    """
    return [entry for entry in captured if entry.get("event") == name]


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


def _run_driver(code: str, arguments: Sequence[str], base: Path, *, timeout_s: float) -> dict[str, Any]:
    """Run a driver script in a fresh interpreter and decode the JSON it prints last.

    Args:
        code: The driver source.
        arguments: The arguments the driver receives.
        base: A directory private to the test, used as the working directory.
        timeout_s: Hard bound on the whole run.

    Returns:
        dict[str, Any]: The decoded object.
    """
    completed = subprocess.run(
        [sys.executable, "-c", code, *arguments],
        capture_output=True,
        text=True,
        timeout=timeout_s,
        env=_child_environment(base),
        cwd=base,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr[-4000:]
    return _last_json_line(completed.stdout)


def _write_instance(instance_id: str, **fields: object) -> None:
    """Write one user-defined provider instance into the redirected ``providers.json``.

    Args:
        instance_id: The instance's id.
        **fields: Record fields that override the defaults (a local endpoint that needs no key).
    """
    record: dict[str, object] = {"instance_id": instance_id, "api_base": "http://127.0.0.1:9", "requires_api_key": False}
    record.update(fields)
    path = get_config_file("providers.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_text(json.dumps({"instances": {instance_id: record}}), encoding="utf-8")
    _ = get_env_file().write_text("", encoding="utf-8")


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


@pytest.mark.asyncio
@pytest.mark.usefixtures("state_root")
async def test_a_saved_instance_with_a_non_ascii_header_is_logged_and_still_registered() -> None:
    """A saved instance whose header cannot be encoded is reported at startup and kept for a later reconnect.

    ``httpx`` refuses a non-ASCII header value with ``UnicodeEncodeError``, which is a
    ``ValueError``, while the connect builds its client. The startup records the failure
    and carries on; the instance is registered anyway so Provider Settings can fix it.

    Falsifiable: removing ``ValueError`` from the ``except`` tuple on main.py line 999
    lets the encoding error escape ``_initialize_saved_instances``.
    """
    _write_instance("gw-hdr", headers={"X-Probe": "é"})
    registry = ProviderRegistry()
    loader = CredentialLoader(get_env_file())

    with capture_logs() as logs:
        await _initialize_saved_instances(registry, loader, get_logger("critcov.r3.headers"), None)

    failed = _events(logs, "provider_instance_init_failed")
    assert len(failed) == 1
    assert failed[0]["instance_id"] == "gw-hdr"
    assert failed[0]["error_type"] == "UnicodeEncodeError"
    assert failed[0]["log_level"] == "warning"
    assert "'ascii' codec can't encode character" in str(failed[0]["error"])
    assert registry.list_registered() == ["gw-hdr"]
    assert len(_events(logs, "provider_instances_initialized")) == 1


@pytest.mark.asyncio
@pytest.mark.usefixtures("state_root")
@pytest.mark.parametrize(
    "api_base",
    ["http://[::1", "http://127.0.0.1:abc", "http://127.0.0.1:9/\u0000x"],
    ids=["unclosed-bracket", "port-not-a-number", "control-character"],
)
async def test_a_saved_instance_with_a_malformed_base_url_does_not_abort_startup(api_base: str) -> None:
    """A hand-edited ``api_base`` that ``httpx`` rejects must not stop the other providers from starting.

    ``httpx.InvalidURL`` derives directly from ``Exception``, so the six-type handler in
    ``_init_instance`` does not catch it and it propagates out of ``asyncio.gather`` into
    the application's startup. The correct behavior is the same as for any other bad
    saved instance: log the failure, register the instance, finish initializing.

    Falsifiable: this test is red while main.py line 999 omits the ``httpx`` error;
    catching it there turns it green.

    Args:
        api_base: A base URL ``httpx.AsyncClient`` refuses to build.
    """
    _write_instance("gw-url", api_base=api_base)
    registry = ProviderRegistry()
    loader = CredentialLoader(get_env_file())

    with capture_logs() as logs:
        await _initialize_saved_instances(registry, loader, get_logger("critcov.r3.url"), None)

    assert registry.list_registered() == ["gw-url"]
    assert len(_events(logs, "provider_instances_initialized")) == 1


@pytest.mark.parametrize("first_kind", ["qapp", "qcore"])
def test_an_early_splash_joins_a_process_that_already_has_a_qt_application(tmp_path: Path, first_kind: str) -> None:
    """With an application already present the early splash skips the DPI declaration and still builds its own.

    The child creates the first application, then calls the real splash construction. The
    guard around the DPI awareness call exists because that call is only meaningful before
    the first application; in this container the call is always refused, so a run that
    reaches it logs ``per_monitor_dpi_awareness_rejected`` and one that skips it logs nothing.

    Falsifiable: deleting the ``if QApplication.instance() is None:`` guard on main.py line
    525 makes the construction call the DPI function again, which the empty event list rejects.

    Args:
        tmp_path: Per-test temporary directory.
        first_kind: Which Qt application class the child creates first.
    """
    facts = _run_driver(_SECOND_APP_DRIVER, [first_kind], tmp_path, timeout_s=180)

    assert facts["first_type"] == {"qapp": "QApplication", "qcore": "QCoreApplication"}[first_kind]
    assert facts["app_type"] == "QApplication"
    assert facts["app_is_first"] is False
    assert facts["instance_is_app"] is True
    assert facts["splash_type"] == "QSplashScreen"
    assert facts["application_name"] == "Intellicrack"
    assert facts["application_version"] == __version__
    assert facts["dpi_events"] == []


def test_the_template_manager_is_returned_without_templates_when_the_hex_backend_is_missing(tmp_path: Path) -> None:
    """A missing native hex backend leaves a usable template manager and logs why the built-ins were skipped.

    The child tells the import system that ``intellicrack_hexcore`` is absent, which makes
    ``import_module`` raise ``ImportError``, then calls the real initializer. The manager is
    constructed and its directories are created before the import is attempted (two debug
    events from ``TemplateManager``), then the skip is logged as a warning; no template file
    is written and no bootstrap failure is recorded.

    Falsifiable: deleting the ``except ImportError`` clause on main.py line 1212 lets the
    import error escape the initializer.

    Args:
        tmp_path: Per-test temporary directory.
    """
    facts = _run_driver(_NO_HEXCORE_DRIVER, [], tmp_path, timeout_s=180)

    assert facts["blocked"] is True
    assert facts["result_type"] == "TemplateManager"
    assert facts["events"] == [
        ["template_manager_initialized", "debug", None],
        ["template_directories_ensured", "debug", None],
        ["template_manager_skipped_no_hexcore", "warning", "intellicrack_hexcore module not available"],
    ]
    assert facts["builtin_dir_created"] is True
    assert facts["user_dir_created"] is True
    assert facts["template_files"] == []
    assert facts["failed_templates"] == []


@pytest.mark.slow
def test_a_main_window_is_built_without_a_template_manager_when_none_was_bootstrapped(tmp_path: Path) -> None:
    """The window wiring leaves the template manager unset and still hands over the model discovery.

    The child builds a real main window against a redirected settings store and calls the
    real wiring function with ``template_manager=None``.

    Falsifiable: deleting the ``if template_manager is not None:`` guard on main.py line 1376
    makes the wiring call ``set_template_manager`` anyway, which logs ``template_manager_set``.

    Args:
        tmp_path: Per-test temporary directory.
    """
    facts = _run_driver(_WINDOW_DRIVER, [str(tmp_path / "window")], tmp_path, timeout_s=360)

    assert facts["window_type"] == "MainWindow"
    assert facts["template_manager_is_none"] is True
    assert facts["model_discovery_is_passed"] is True
    assert "model_discovery_set" in facts["events"]
    assert "template_manager_set" not in facts["events"]


def test_a_synchronous_cleanup_survives_a_process_the_system_refuses_to_end(tmp_path: Path) -> None:
    """The exit-time cleanup logs a process it may not terminate and still ends the others.

    The child strips its own debug privilege and rewrites the access list of a grandchild
    so that ``PROCESS_TERMINATE`` is refused (the child asserts that refusal itself before
    calling the cleanup), registers it first and an ordinary process second, then runs the
    real synchronous cleanup. The asynchronous and tree paths already log this refusal and
    carry on; the synchronous one is expected to do the same and must not leave the manager
    flagged as cleaning up, because the exit and signal handlers return early while it is.

    Falsifiable: this test is red while ``_sync_cleanup`` (process_manager.py line 563 to 568)
    catches only ``psutil.NoSuchProcess``; catching ``psutil.AccessDenied`` there turns it green.

    Args:
        tmp_path: Per-test temporary directory.
    """
    facts = _run_driver(_SYNC_DENIED_DRIVER, [], tmp_path, timeout_s=180)

    assert facts["terminate_refused"] is True
    assert facts["denied_running"] is True
    assert facts["raised"] is None
    assert facts["ordinary_running"] is False
    assert facts["cleanup_in_progress"] is False
