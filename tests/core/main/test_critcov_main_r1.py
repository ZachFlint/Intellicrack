# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Second-pass coverage for the application entry point and the process manager.

Everything here targets lines the first pass could not reach. Stalled shutdown
stages are reproduced with a real child process whose cleanup callback never
returns. Paths that would terminate the pytest process, strip a privilege from it
or need the operating system to refuse access run in a child interpreter that
this module starts and that owns the processes it touches: the child spares its
own PID, and a grandchild it spawned has its access list rewritten so that
terminating or waiting on it is refused. The failing launch runs ``main()`` in a
child interpreter against a redirected state root.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, cast

import pytest
from structlog.testing import capture_logs

from intellicrack.core.logging import get_logger
from intellicrack.core.orchestrator import Orchestrator
from intellicrack.core.process_manager import ProcessManager
from intellicrack.core.session import SessionManager, SessionStore
from intellicrack.core.subprocess_compat import DEVNULL, PIPE, Popen
from intellicrack.core.tools import ToolRegistry
from intellicrack.providers.discovery import ModelDiscovery
from intellicrack.providers.registry import ProviderRegistry
from tests._helpers.child_python import REPO_ROOT
from tests._helpers.provider_state import provider_environment_variables


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Generator, Mapping, Sequence

    from structlog.stdlib import BoundLogger


pytestmark = pytest.mark.spawns_process

_WAIT_S: Final[float] = 15.0
_READY_MARKER: Final[bytes] = b"ready"
_BLOCKING_CHILD_SCRIPT: Final[str] = "import sys\nprint('ready', flush=True)\nsys.stdin.read()\n"
_PROCESS_TIMEOUT_S: Final[float] = 10.0
_OFFLINE_SECTIONS: Final[dict[str, dict[str, object]]] = {
    "ollama": {"enabled": False, "schema_version": 3},
    "local_transformers": {"enabled": False, "schema_version": 3},
}

_main_module = importlib.import_module("intellicrack.main")
_finalize_shutdown = cast(
    "Callable[[asyncio.AbstractEventLoop, ProcessManager, BoundLogger], None]",
    getattr(_main_module, "_finalize_shutdown"),
)
_shutdown_application = cast("Callable[..., Coroutine[object, object, None]]", getattr(_main_module, "_shutdown_application"))

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

_LINEAGE_DRIVER: Final[str] = """
import json
import os
import sys

from structlog.testing import capture_logs

from intellicrack.core.process_manager import ProcessManager

mode = sys.argv[1]
own = os.getpid()
manager = ProcessManager.get_instance()
with capture_logs() as logs:
    if mode == 'sync':
        manager.register_external_pid(own, name='self')
        manager._sync_cleanup()
        event = 'sync_cleanup_spared_own_lineage'
    else:
        ProcessManager.terminate_tree(own, graceful_timeout=0.1, force_timeout=0.1)
        event = 'terminate_tree_spared_own_lineage'
spared = [entry['pid'] for entry in logs if entry['event'] == event]
sys.stdout.write(json.dumps({'own': own, 'spared': spared}) + '\\n')
sys.stdout.flush()
"""

_DENIED_DRIVER: Final[str] = """
import ctypes
import json
import subprocess
import sys
from ctypes import wintypes

from structlog.testing import capture_logs

from intellicrack.bridges.win32_types import LUID, TOKEN_PRIVILEGES
from intellicrack.core.process_manager import ProcessManager, pid_is_running

TERMINATE = 0x1
QUERY_LIMITED = 0x1000
SYNCHRONIZE = 0x00100000
READ_CONTROL = 0x00020000
WRITE_DAC = 0x00040000
SPECIFIC_RIGHTS = 0xFFFF
TOKEN_QUERY = 0x8
TOKEN_ADJUST_PRIVILEGES = 0x20
SE_PRIVILEGE_REMOVED = 0x4
DACL_SECURITY_INFORMATION = 0x4
SDDL_REVISION_1 = 1
DENIED = {'terminate': TERMINATE, 'terminate_wait': TERMINATE | SYNCHRONIZE, 'query': QUERY_LIMITED}
ALLOWED = SYNCHRONIZE | READ_CONTROL | WRITE_DAC | SPECIFIC_RIGHTS

mode = sys.argv[1]
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
kernel32.GetCurrentProcess.restype = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.LocalFree.argtypes = [ctypes.c_void_p]
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

target = subprocess.Popen(
    [sys.executable, '-c', 'import sys\\nprint("ready", flush=True)\\nsys.stdin.read()\\n'],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
)
manager = ProcessManager.get_instance()
result = {}
try:
    assert target.stdout.readline().strip() == b'ready'
    manager.register_external_pid(target.pid, name='denied-target')
    sddl = 'D:(D;;0x%x;;;WD)(A;;0x%x;;;WD)' % (DENIED[mode], ALLOWED)
    descriptor = ctypes.c_void_p()
    assert advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, SDDL_REVISION_1, ctypes.byref(descriptor), None,
    )
    assert advapi32.SetKernelObjectSecurity(int(target._handle), DACL_SECURITY_INFORMATION, descriptor)
    kernel32.LocalFree(descriptor)
    with capture_logs() as logs:
        if mode == 'query':
            result['running'] = pid_is_running(target.pid)
        elif mode == 'terminate':
            ProcessManager.terminate_tree(target.pid, graceful_timeout=0.2, force_timeout=0.2)
        else:
            result['returned'] = manager.terminate_external_pid(target.pid, force=True)
    result['pid'] = target.pid
    result['events'] = [[entry['event'], entry.get('pid')] for entry in logs]
    result['alive'] = target.poll() is None
    result['still_registered'] = target.pid in manager._external_pids
finally:
    if target.poll() is None:
        target.kill()
    target.wait(timeout=15)
    target.stdin.close()
    target.stdout.close()
sys.stdout.write(json.dumps(result) + '\\n')
sys.stdout.flush()
"""


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


def _reap(child: Popen[bytes]) -> None:
    """Kill the child if it is still running, wait for it and close its pipes.

    Args:
        child: A process this module started.
    """
    if child.poll() is None:
        child.kill()
    _ = child.wait(timeout=_WAIT_S)
    for stream in (child.stdin, child.stdout):
        if stream is not None:
            stream.close()


def _spawn_blocking_child() -> Popen[bytes]:
    """Start a child that prints a ready marker and then blocks on stdin.

    Returns:
        Popen[bytes]: The running child, already past its ready marker.
    """
    child = Popen([sys.executable, "-c", _BLOCKING_CHILD_SCRIPT], stdin=PIPE, stdout=PIPE, stderr=DEVNULL)
    marker = child.stdout.readline().strip() if child.stdout is not None else b""
    if marker != _READY_MARKER:
        _reap(child)
        pytest.fail(f"child printed {marker!r} instead of {_READY_MARKER!r}")
    return child


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
    return get_logger("critcov.main_r1").bind(origin=origin)


def _external_registry(manager: ProcessManager) -> dict[int, object]:
    """Return the manager's external PID registry.

    Args:
        manager: The manager to inspect.

    Returns:
        dict[int, object]: The live registry mapping.
    """
    return cast("dict[int, object]", getattr(manager, "_external_pids"))


def _cleanup_in_progress(manager: ProcessManager) -> bool:
    """Read the manager's cleanup-in-progress flag.

    Args:
        manager: The manager to inspect.

    Returns:
        bool: The flag's current value.
    """
    return cast("bool", getattr(manager, "_cleanup_in_progress"))


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
        base: A directory private to the test.
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


def _real_services(tmp_path: Path) -> tuple[ProviderRegistry, Orchestrator, SessionManager]:
    """Build a provider registry, an orchestrator and a session manager of the real classes.

    Args:
        tmp_path: A directory private to the test.

    Returns:
        tuple[ProviderRegistry, Orchestrator, SessionManager]: The three services.
    """
    registry = ProviderRegistry()
    session_manager = SessionManager(SessionStore(tmp_path / "sessions.db"))
    orchestrator = Orchestrator(
        provider_registry=registry,
        tool_registry=ToolRegistry(tmp_path / "tools"),
        session_manager=session_manager,
    )
    return registry, orchestrator, session_manager


async def _hang() -> None:
    """Wait forever, as a bridge's shutdown request does when its connection is wedged."""
    await asyncio.Event().wait()


def test_cleanup_all_async_logs_an_external_pid_when_the_executor_refuses_work(process_manager: ProcessManager) -> None:
    """A termination that cannot be scheduled is logged, leaves the process alone and clears the registry.

    The loop's default executor is shut down first, so handing the termination to
    a worker thread raises ``RuntimeError('Executor shutdown has been called')``
    (``asyncio/base_events.py`` ``_check_default_executor``).

    Falsifiable: removing ``RuntimeError`` from the ``except`` tuple on
    process_manager.py line 993 lets the error escape ``cleanup_all_async``.

    Args:
        process_manager: The singleton the child is registered with.
    """
    child = _spawn_blocking_child()
    loop = asyncio.new_event_loop()
    try:
        process_manager.register_external_pid(child.pid, name="refused")
        loop.run_until_complete(loop.shutdown_default_executor())

        with capture_logs() as captured:
            loop.run_until_complete(process_manager.cleanup_all_async())

        failures = _events(captured, "external_pid_terminate_failed")
        assert [entry.get("pid") for entry in failures] == [child.pid]
        assert [entry.get("error") for entry in failures] == ["Executor shutdown has been called"]
        assert child.poll() is None
        assert _external_registry(process_manager) == {}
        assert _cleanup_in_progress(process_manager) is False
    finally:
        loop.close()
        _reap(child)


@pytest.mark.slow
def test_final_cleanup_gives_up_on_a_process_cleanup_that_never_finishes(process_manager: ProcessManager) -> None:
    """The final cleanup stops waiting after its timeout, warns, and still uninstalls handlers and closes the loop.

    A tracked child whose cleanup callback never returns stalls the real cleanup.

    Falsifiable: removing the ``except TimeoutError`` clause on main.py line 1044
    lets the timeout escape ``_finalize_shutdown``.

    Args:
        process_manager: The singleton the child is tracked by.
    """
    child = _spawn_blocking_child()
    loop = asyncio.new_event_loop()
    try:
        _ = process_manager.register(child, name="never-cleans-up", cleanup_callback=_hang)
        started = time.monotonic()

        with capture_logs() as captured:
            _finalize_shutdown(loop, process_manager, _marked_logger("finalize-timeout"))

        elapsed = time.monotonic() - started
        assert elapsed >= _PROCESS_TIMEOUT_S - 0.5
        assert _marked_events(captured, "finalize-timeout", ["final_process_cleanup_timeout"]) == ["final_process_cleanup_timeout"]
        assert len(_events(captured, "handlers_uninstalled")) == 1
        assert loop.is_closed()
        assert child.poll() is None
    finally:
        loop.close()
        _reap(child)


@pytest.mark.asyncio
async def test_shutdown_tolerates_a_model_discovery_without_a_cache_writer(tmp_path: Path, process_manager: ProcessManager) -> None:
    """A model discovery object that offers no ``save_cache`` is skipped and every later stage still runs.

    The parameter is declared as a plain ``object`` and documents that the cache
    is saved only if the object exposes ``save_cache``.

    Falsifiable: deleting the ``if callable(save_cache):`` guard on main.py line 1544
    makes the shutdown call ``None`` and raise ``TypeError``.

    Args:
        tmp_path: Per-test temporary directory.
        process_manager: A fresh process manager singleton.
    """
    registry, orchestrator, session_manager = _real_services(tmp_path)
    cache_path = tmp_path / "discovery.json"
    try:
        with capture_logs() as logs:
            await _shutdown_application(
                logger=_marked_logger("no-save-cache"),
                provider_registry=registry,
                orchestrator=orchestrator,
                session_manager=session_manager,
                process_manager=process_manager,
                model_discovery=object(),
                discovery_cache=cache_path,
            )

        stages = ["shutdown_started", "model_cache_cleared", "shutdown_complete"]
        assert _marked_events(logs, "no-save-cache", stages) == stages
        assert not cache_path.exists()
    finally:
        await session_manager.close()


@pytest.mark.asyncio
@pytest.mark.slow
async def test_shutdown_abandons_a_process_cleanup_that_never_finishes(tmp_path: Path, process_manager: ProcessManager) -> None:
    """A stalled process cleanup costs its timeout, is reported, and the bridge loop is still stopped.

    Falsifiable: removing the ``except TimeoutError`` clause on main.py line 1572
    lets the timeout escape ``_shutdown_application``.

    Args:
        tmp_path: Per-test temporary directory.
        process_manager: A fresh process manager singleton.
    """
    registry, orchestrator, session_manager = _real_services(tmp_path)
    child = _spawn_blocking_child()
    try:
        _ = process_manager.register(child, name="never-cleans-up", cleanup_callback=_hang)
        started = time.monotonic()

        with capture_logs() as logs:
            await _shutdown_application(
                logger=_marked_logger("stalled-process"),
                provider_registry=registry,
                orchestrator=orchestrator,
                session_manager=session_manager,
                process_manager=process_manager,
                model_discovery=ModelDiscovery(registry),
                discovery_cache=tmp_path / "discovery.json",
            )

        elapsed = time.monotonic() - started
        stages = ["shutdown_started", "model_cache_cleared", "process_cleanup_timeout", "shutdown_complete"]
        assert _marked_events(logs, "stalled-process", stages) == stages
        assert elapsed >= _PROCESS_TIMEOUT_S - 0.5
        assert child.poll() is None
    finally:
        _reap(child)
        await session_manager.close()


@pytest.mark.parametrize("mode", ["sync", "tree"])
def test_a_process_never_terminates_itself_through_either_cleanup_path(tmp_path: Path, mode: str) -> None:
    """A registry entry or tree root naming the running process itself is spared and logged.

    The interpreter that runs the driver is a child of this test and is the only
    process named; if the guard were missing it would end itself, which fails the
    run instead of touching the pytest process.

    Falsifiable: deleting the ``if pid in spared`` branch on process_manager.py
    line 546 (``sync``) or the ``if pid in _own_lineage()`` branch on line 658
    (``tree``) makes the driver terminate itself.

    Args:
        tmp_path: Per-test temporary directory.
        mode: Which cleanup path the driver exercises.
    """
    facts = _run_driver(_LINEAGE_DRIVER, [mode], tmp_path, timeout_s=180)

    assert facts["spared"] == [facts["own"]]


@pytest.mark.parametrize(
    ("mode", "expected_events"),
    [
        ("terminate", ["terminate_tree_access_denied", "kill_tree_access_denied"]),
        ("terminate_wait", ["terminate_tree_access_denied", "external_pid_terminate_error"]),
    ],
)
def test_a_process_that_refuses_termination_is_reported_and_left_running(
    tmp_path: Path,
    mode: str,
    expected_events: list[str],
) -> None:
    """When the operating system refuses to end a process, the manager logs the refusal and does not raise.

    The driver removes its own debug privilege, then rewrites the access list of a
    grandchild it started: ``terminate`` denies only the terminate right, so both
    the graceful and the forced attempt are refused; ``terminate_wait`` also denies
    the wait right, so psutil's wait raises and ``terminate_external_pid`` reports
    the error and returns False, leaving the PID registered.

    Falsifiable: removing the ``except psutil.AccessDenied`` clause on
    process_manager.py line 686 (or 697) lets the refusal escape, and removing
    ``psutil.Error`` from the tuple on line 1368 does the same for the wait refusal.

    Args:
        tmp_path: Per-test temporary directory.
        mode: Which rights the driver denies.
        expected_events: The refusal events expected, in order.
    """
    facts = _run_driver(_DENIED_DRIVER, [mode], tmp_path, timeout_s=180)

    pid = facts["pid"]
    refusals = [event for event in facts["events"] if event[0] in expected_events]
    assert [event[0] for event in refusals] == expected_events
    assert {event[1] for event in refusals} == {pid}
    assert facts["alive"] is True
    if mode == "terminate_wait":
        assert facts["returned"] is False
        assert facts["still_registered"] is True


def test_a_process_whose_query_right_is_denied_still_counts_as_running(tmp_path: Path) -> None:
    """A live process that the system refuses to open for querying is reported as existing.

    Falsifiable: returning ``False`` instead of ``True`` on process_manager.py line
    163 reports the live process as gone.

    Args:
        tmp_path: Per-test temporary directory.
    """
    facts = _run_driver(_DENIED_DRIVER, ["query"], tmp_path, timeout_s=180)

    assert facts["alive"] is True
    assert facts["running"] is True


@pytest.mark.slow
def test_a_launch_whose_startup_fails_reports_the_failure_and_exits_with_status_one(tmp_path: Path) -> None:
    """``main()`` logs ``application_failed`` and returns 1 when a startup stage raises an ``OSError``.

    The scripts directory the script engine needs is occupied by a regular file, so
    creating it raises ``FileExistsError`` after the providers and the tool
    registry have started and before any window exists.

    Falsifiable: removing ``OSError`` from the ``except`` tuple on main.py line 1127
    lets the error escape ``main()`` and the child dies without reporting a status.

    Args:
        tmp_path: Per-test temporary directory.
    """
    env = _child_environment(tmp_path)
    state_dir = Path(env["INTELLICRACK_STATE_DIR"])
    providers_file = state_dir / ".intellicrack" / "providers.json"
    providers_file.parent.mkdir(parents=True, exist_ok=True)
    _ = providers_file.write_text(json.dumps(_OFFLINE_SECTIONS), encoding="utf-8")
    _ = (state_dir / ".env").write_text("", encoding="utf-8")
    base = tmp_path / "launch"
    (base / "data").mkdir(parents=True)
    _ = (base / "data" / "scripts").write_text("not a directory", encoding="utf-8")
    config_file = tmp_path / "launch.toml"
    text = (
        "[general]\n"
        f'tools_directory = "{(base / "tools").as_posix()}"\n'
        f'logs_directory = "{(base / "logs").as_posix()}"\n'
        f'data_directory = "{(base / "data").as_posix()}"\n'
        "\n"
        "[ui]\n"
        'theme = "dark"\n'
        "\n"
        "[log]\n"
        'level = "INFO"\n'
        "console_enabled = false\n"
    )
    _ = config_file.write_text(text, encoding="utf-8")

    completed = subprocess.run(
        [sys.executable, "-c", _GUI_DRIVER, "--no-elevate", "--config", str(config_file)],
        capture_output=True,
        text=True,
        timeout=420,
        env=env,
        cwd=tmp_path,
        check=False,
    )

    log_file = base / "logs" / "intellicrack.log"
    log_text = log_file.read_text(encoding="utf-8") if log_file.exists() else ""
    tail = f"stdout:\n{completed.stdout[-2000:]}\nstderr:\n{completed.stderr[-2000:]}\nlog:\n{log_text[-3000:]}"
    reported = _last_json_line(completed.stdout)
    assert reported["exit_code"] == 1, tail
    records = [json.loads(line) for line in log_text.splitlines() if line.startswith("{")]
    failures = [record for record in records if record["event"] == "application_failed"]
    assert len(failures) == 1, tail
    assert failures[0]["error_type"] == "FileExistsError"
    names = {str(record["event"]) for record in records}
    assert "script_engine_initialized" not in names
    assert "ui_started" not in names
