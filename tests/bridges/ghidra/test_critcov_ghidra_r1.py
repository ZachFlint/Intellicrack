# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Second-pass real-process coverage for the Ghidra bridge launch and shutdown paths.

Three tests drive the product's own launch code (``start_headless``,
``run_headless_batch``) and its ``shutdown`` against a real child process, the
interpreter running ``pyghidra.ghidra_launch``, pointed at an install directory
that is deliberately not a Ghidra installation (it has the ``support`` launcher
file the bridge looks for, but no ``Ghidra/application.properties``). PyGhidra's
launcher rejects such a directory with a ``ValueError`` before any JVM starts,
so the child exits with code 1 within a couple of seconds and no Ghidra session
is ever opened. With ``JAVA_HOME`` removed from the environment and no bundled
``jdk-*`` in that directory, JDK discovery finds nothing, which is the case the
first-pass files could not produce.

The shutdown test additionally saturates the event loop's single-worker default
executor so that the product's ten-second wait for the terminated process
expires, exercising the kill fallback. No stand-in launcher, mock or patched
product code is involved: the product starts its real launch command and handles
the real outcome.
"""

from __future__ import annotations

import asyncio
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Final, cast

import pytest
from structlog.testing import capture_logs

from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.core.process_manager import ProcessManager
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    import subprocess
    from collections.abc import Callable
    from pathlib import Path

    from structlog.typing import EventDict, Processor, WrappedLogger


pytestmark = pytest.mark.spawns_process

_STEP_TIMEOUT_SECONDS: Final[float] = 180.0
_TERMINATE_TIMEOUT_EVENT: Final[str] = "ghidra_process_terminate_timeout"
_PROPERTIES_FILE_NAME: Final[str] = "application.properties"


def _attr(obj: object, name: str) -> object:
    """Read a (possibly private) data attribute by name.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name to read.

    Returns:
        object: The attribute value.
    """
    return getattr(obj, name)


def _method(obj: object, name: str) -> Callable[..., object]:
    """Resolve a (possibly private) synchronous method or static method by name.

    Args:
        obj: Instance or class that owns the attribute.
        name: Attribute name to look up.

    Returns:
        Callable[..., object]: The bound callable.
    """
    return cast("Callable[..., object]", getattr(obj, name))


def _reserve_free_port() -> int:
    """Reserve an ephemeral loopback TCP port and release it immediately.

    Returns:
        int: A port that nothing listens on at the moment of the call.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def _releasing_processor(release: threading.Event) -> Processor:
    """Build a structlog processor that sets an event when the kill fallback logs.

    Args:
        release: Event to set when the terminate-timeout warning is emitted.

    Returns:
        Processor: A processor that passes every event through unchanged.
    """

    def process(_logger: WrappedLogger, _method_name: str, event_dict: EventDict) -> EventDict:
        """Set the event when the terminate-timeout warning passes through.

        Args:
            _logger: Wrapped logger supplied by structlog; unused.
            _method_name: Log method name supplied by structlog; unused.
            event_dict: The event being logged.

        Returns:
            EventDict: The same event dictionary.
        """
        if event_dict.get("event") == _TERMINATE_TIMEOUT_EVENT:
            release.set()
        return event_dict

    return process


async def _start_expecting_failure(bridge: GhidraBridge, project_dir: Path) -> ToolError:
    """Run ``start_headless`` against the fake install and return the error it raises.

    The bridge is shut down afterwards whatever the outcome.

    Args:
        bridge: Bridge whose Ghidra path is the fake installation.
        project_dir: Directory the product creates for the Ghidra project.

    Returns:
        ToolError: The error raised by ``start_headless``.
    """
    try:
        await asyncio.wait_for(bridge.start_headless(project_dir, "critcov_ghidra_r1"), timeout=_STEP_TIMEOUT_SECONDS)
    except ToolError as exc:
        return exc
    finally:
        await bridge.shutdown()
    pytest.fail("start_headless connected although the install directory is not a Ghidra installation", pytrace=False)


async def _run_batch_expecting_failure(bridge: GhidraBridge, project_dir: Path, target: Path) -> ToolError:
    """Run ``run_headless_batch`` against the fake install and return the error it raises.

    Args:
        bridge: Bridge whose Ghidra path is the fake installation.
        project_dir: Directory for the batch project.
        target: File passed as the import target.

    Returns:
        ToolError: The error raised by ``run_headless_batch``.
    """
    try:
        await asyncio.wait_for(
            bridge.run_headless_batch(project_dir, [str(target)], "critcov_ghidra_r1_batch"),
            timeout=_STEP_TIMEOUT_SECONDS,
        )
    except ToolError as exc:
        return exc
    pytest.fail("run_headless_batch succeeded although the install directory is not a Ghidra installation", pytrace=False)


async def _shutdown_with_saturated_executor(
    bridge: GhidraBridge,
    project_dir: Path,
    executor: ThreadPoolExecutor,
    release: threading.Event,
) -> tuple[ToolError, subprocess.Popen[bytes], list[EventDict]]:
    """Fail a launch, then shut down while the only executor worker is busy.

    The default executor of the running loop is replaced by ``executor`` (one
    worker). After the failed launch a task occupying that worker is queued, so
    the ``to_thread`` wait the product issues for the terminated process cannot
    start until ``release`` is set. The warning the product logs when its
    ten-second wait expires sets ``release`` through a structlog processor.

    Args:
        bridge: Bridge whose Ghidra path is the fake installation.
        project_dir: Directory the product creates for the Ghidra project.
        executor: Single-worker executor installed as the loop default.
        release: Event the occupying task waits on.

    Returns:
        tuple[ToolError, subprocess.Popen[bytes], list[EventDict]]: The launch
        error, the product's child process object, and the events logged while
        ``shutdown`` ran.
    """
    loop = asyncio.get_running_loop()
    loop.set_default_executor(executor)
    try:
        try:
            await asyncio.wait_for(bridge.start_headless(project_dir, "critcov_ghidra_r1_shutdown"), timeout=_STEP_TIMEOUT_SECONDS)
        except ToolError as exc:
            start_error = exc
        else:
            pytest.fail("start_headless connected although the install directory is not a Ghidra installation", pytrace=False)
        process = cast("subprocess.Popen[bytes]", _attr(bridge, "_process"))
        occupier = loop.run_in_executor(None, release.wait)
        with capture_logs(processors=[_releasing_processor(release)]) as events:
            await asyncio.wait_for(bridge.shutdown(), timeout=_STEP_TIMEOUT_SECONDS)
        await occupier
        return start_error, process, events
    finally:
        release.set()


@pytest.fixture
def fake_ghidra_install(tmp_path: Path) -> Path:
    """Build a directory that looks like a Ghidra install to the bridge but is not one.

    It holds ``support/analyzeHeadless.bat``, the file the bridge requires on
    Windows, and nothing else, so PyGhidra's launcher refuses it.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        Path: Root of the fake installation.
    """
    root = tmp_path / "not_a_ghidra_install"
    support = root / "support"
    support.mkdir(parents=True)
    (support / "analyzeHeadless.bat").write_text("", encoding="utf-8")
    return root


def test_start_headless_without_a_discoverable_jdk_reports_the_launcher_exit(
    fake_ghidra_install: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With no JDK to hand to the launcher, a launcher that dies is reported by exit code.

    Args:
        fake_ghidra_install: Directory with no Ghidra files and no bundled JDK.
        tmp_path: Pytest temporary directory for the project.
        monkeypatch: Pytest fixture used to remove ``JAVA_HOME``.
    """
    monkeypatch.delenv("JAVA_HOME", raising=False)
    assert _method(GhidraBridge, "_discover_jdk")(fake_ghidra_install) is None
    bridge = GhidraBridge()
    bridge.set_port(_reserve_free_port())
    bridge.ghidra_path = fake_ghidra_install

    error = asyncio.run(_start_expecting_failure(bridge, tmp_path / "project"))

    assert str(error).startswith("Ghidra process exited prematurely with code 1")
    assert _attr(bridge, "_process") is None
    assert _attr(bridge, "_job_object_handle") is None


def test_run_headless_batch_without_a_discoverable_jdk_reports_the_launcher_failure(
    fake_ghidra_install: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A batch whose launcher dies reports exit code 1 and PyGhidra's own complaint.

    Args:
        fake_ghidra_install: Directory with no Ghidra files and no bundled JDK.
        tmp_path: Pytest temporary directory for the project and the import target.
        monkeypatch: Pytest fixture used to remove ``JAVA_HOME``.
    """
    monkeypatch.delenv("JAVA_HOME", raising=False)
    target = tmp_path / "sample.bin"
    target.write_bytes(b"MZ")
    bridge = GhidraBridge()
    bridge.ghidra_path = fake_ghidra_install

    error = asyncio.run(_run_batch_expecting_failure(bridge, tmp_path / "batch_project", target))

    message = str(error)
    assert message.startswith("Headless batch failed with exit code 1")
    assert "stderr tail:" in message
    assert _PROPERTIES_FILE_NAME in message


def test_shutdown_kills_a_process_that_outlives_the_terminate_wait(
    fake_ghidra_install: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the ten-second wait for the terminated process expires, shutdown kills and still finishes.

    Args:
        fake_ghidra_install: Directory with no Ghidra files and no bundled JDK.
        tmp_path: Pytest temporary directory for the project.
        monkeypatch: Pytest fixture used to remove ``JAVA_HOME``.
    """
    monkeypatch.delenv("JAVA_HOME", raising=False)
    bridge = GhidraBridge()
    bridge.set_port(_reserve_free_port())
    bridge.ghidra_path = fake_ghidra_install
    release = threading.Event()
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="critcov-ghidra-r1")
    try:
        start_error, process, events = asyncio.run(
            _shutdown_with_saturated_executor(bridge, tmp_path / "project", executor, release),
        )
    finally:
        release.set()
        executor.shutdown(wait=True)

    assert str(start_error).startswith("Ghidra process exited prematurely with code 1")
    timeouts = [event for event in events if event.get("event") == _TERMINATE_TIMEOUT_EVENT]
    assert len(timeouts) == 1
    assert timeouts[0]["pid"] == process.pid
    assert process.returncode is not None
    assert _attr(bridge, "_process") is None
    assert _attr(bridge, "_job_object_handle") is None
    assert ProcessManager.get_instance().get_tracked(process.pid) is None
