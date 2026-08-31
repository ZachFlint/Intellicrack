# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""The container harness must not start a container while an HCS VM is running.

Windows containers, WHPX virtual machines and Windows Sandbox sessions all run
on the Host Compute Service, and interleaving them bugchecked this host on
2026-08-02. ``tests/sandbox/qemu/windows_boot_probe.py`` already refuses to
start a VM while a container is running, but until this gate existed the
harness had no mirror of that check: a container started while a VM was live
was the same collision approached from the other side, and nothing stopped it.

The processes here are real. A copy of ``cmd.exe`` under a QEMU process name is
a genuine running process that the production enumerator sees exactly as it
sees a real ``qemu-system-x86_64.exe``, because the enumerator matches on the
process name and nothing else. Nothing is patched, and the interlock under test
is the one ``DockerSandbox.ensure_image`` calls.
"""

from __future__ import annotations

import ast
import inspect
import os
import shutil
import sys
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest

from intellicrack.core.subprocess_compat import DEVNULL, PIPE, Popen
from scripts.sandbox.docker_sandbox import (
    DockerSandbox,
    SandboxError,
    ensure_no_hcs_vm_running,
    running_hcs_vm_processes,
)


if TYPE_CHECKING:
    from collections.abc import Iterator


_VM_PROCESS_NAME: Final[str] = "qemu-system-x86_64.exe"
_REFUSAL_BUDGET_SEC: Final[float] = 8.0
_CLEARANCE_BUDGET_SEC: Final[float] = 120.0
_VM_LIFETIME_SEC: Final[float] = 8.0
_MIN_OBSERVED_WAIT_SEC: Final[float] = 5.0
_CLEAR_HOST_RETURN_SEC: Final[float] = 1.0
_PROCESS_KILL_GRACE_SEC: Final[float] = 5.0


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="the Host Compute Service interlock protects Windows hosts only",
)


def _stand_in_binary(directory: Path) -> Path:
    """Place a real executable under a QEMU process name.

    ``cmd.exe`` is copied because it is self-contained: a lone copy of the
    Python interpreter cannot start away from its own DLLs, so it would exit
    before the enumerator could ever see it.

    Args:
        directory: Directory to place the executable in.

    Returns:
        Path: The copied executable, named so the production enumerator
        classifies it as a virtual machine.
    """
    source = Path(os.environ["SYSTEMROOT"]) / "System32" / "cmd.exe"
    assert source.is_file(), f"cmd.exe not found at {source}"
    target = directory / _VM_PROCESS_NAME
    shutil.copy2(source, target)
    return target


def _start_vm_named_process(executable: Path) -> Popen[bytes]:
    """Start a long-lived process carrying a virtual machine's name.

    The process is a shell reading a pipe nobody writes to, so it stays alive
    until the test kills it and needs no timer, sleep helper or console.

    Args:
        executable: The stand-in executable to run.

    Returns:
        Popen[bytes]: The running process.
    """
    return Popen([str(executable)], stdin=PIPE, stdout=DEVNULL, stderr=DEVNULL)


def _terminate(process: Popen[bytes]) -> None:
    """Kill a stand-in process and wait for it to leave the process table.

    Args:
        process: The process to kill.
    """
    if process.poll() is None:
        process.kill()
    process.wait(timeout=_PROCESS_KILL_GRACE_SEC)


@pytest.fixture
def running_vm_process(tmp_path: Path) -> Iterator[Popen[bytes]]:
    """Yield a live process named like a QEMU virtual machine.

    Args:
        tmp_path: Pytest-provided temp directory holding the executable.

    Yields:
        Popen[bytes]: The running stand-in process.
    """
    process = _start_vm_named_process(_stand_in_binary(tmp_path))
    try:
        yield process
    finally:
        _terminate(process)


def test_a_running_vm_is_visible_to_the_harness(running_vm_process: Popen[bytes]) -> None:
    """The enumerator must report a live VM-named process by pid and name.

    Args:
        running_vm_process: A live process named ``qemu-system-x86_64.exe``.
    """
    found = running_hcs_vm_processes()
    pids = {pid for pid, _ in found}
    assert running_vm_process.pid in pids, (
        f"the harness cannot see a running {_VM_PROCESS_NAME} (pid {running_vm_process.pid}); found={found!r}"
    )
    names = {name for pid, name in found if pid == running_vm_process.pid}
    assert names == {_VM_PROCESS_NAME}, f"process reported under an unexpected name; names={names!r}"


def test_a_container_run_will_not_start_while_a_vm_is_running(running_vm_process: Popen[bytes]) -> None:
    """The interlock must fail, naming the process, rather than start a container.

    This is the check whose absence left the interlock one-directional: the
    WHPX boot gates refuse to start a VM while a container runs, and nothing
    refused the reverse.

    Args:
        running_vm_process: A live process named ``qemu-system-x86_64.exe``.
    """
    with pytest.raises(SandboxError, match=rf"pid {running_vm_process.pid}\b") as raised:
        ensure_no_hcs_vm_running(timeout=_REFUSAL_BUDGET_SEC)

    assert _VM_PROCESS_NAME in str(raised.value), f"the refusal must name the process holding the host; message={raised.value!s}"


def test_the_interlock_waits_for_the_vm_rather_than_failing_outright(tmp_path: Path) -> None:
    """A container run must proceed once the virtual machine has exited.

    Refusing immediately would make every sibling session's VM gate a hard
    failure here; the interlock waits, so this asserts both halves - that it
    really waited (it returned no earlier than a poll interval, while the VM
    was still alive) and that it returned once the VM was gone.

    Args:
        tmp_path: Pytest-provided temp directory holding the executable.
    """
    process = _start_vm_named_process(_stand_in_binary(tmp_path))
    killer = threading.Timer(_VM_LIFETIME_SEC, process.kill)
    killer.start()
    started = time.monotonic()
    try:
        ensure_no_hcs_vm_running(timeout=_CLEARANCE_BUDGET_SEC)
    finally:
        killer.cancel()
        _terminate(process)
    elapsed = time.monotonic() - started

    assert elapsed >= _MIN_OBSERVED_WAIT_SEC, f"the interlock returned in {elapsed:.1f}s while the VM was still running; it did not wait"
    assert elapsed < _CLEARANCE_BUDGET_SEC, (
        f"the interlock consumed its whole budget ({elapsed:.1f}s) instead of returning when the VM exited"
    )
    assert process.poll() is not None, "the stand-in process outlived the wait that was supposed to observe its exit"


def test_the_container_launch_path_consults_the_interlock_first() -> None:
    """``DockerSandbox.ensure_image`` must call the interlock before Docker.

    The tests above prove the interlock works; this one proves the launch path
    uses it, which is the half no runtime test can reach - exercising
    ``ensure_image`` for real needs a Docker engine, and these tests run inside
    a container that has none. The call order is read out of the production
    module's own syntax tree rather than matched as text, so reformatting the
    function cannot fake a pass and deleting the call cannot hide behind a
    comment that still mentions it.

    Ordering matters as much as presence: Docker Desktop starts its own utility
    VM, so waking it is already a Host Compute Service operation and must not
    happen while a virtual machine holds the host.
    """
    source = Path(inspect.getfile(DockerSandbox)).read_text(encoding="utf-8")
    module = ast.parse(source)
    functions = [
        node for node in ast.walk(module) if isinstance(node, ast.FunctionDef) and node.name == DockerSandbox.ensure_image.__name__
    ]
    assert len(functions) == 1, f"expected exactly one ensure_image definition; found {len(functions)}"

    called = [node.func.id for node in ast.walk(functions[0]) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
    interlock = ensure_no_hcs_vm_running.__name__
    docker = "ensure_docker_running"
    assert interlock in called, (
        f"ensure_image never calls {interlock}, so a container run can still start while a virtual "
        f"machine holds the Host Compute Service; calls={called!r}"
    )
    assert docker in called, f"ensure_image no longer calls {docker}; calls={called!r}"
    assert called.index(interlock) < called.index(docker), (
        f"{interlock} must run before {docker}, because starting Docker Desktop itself starts a VM; calls={called!r}"
    )


def test_a_clear_host_is_not_made_to_wait() -> None:
    """With no virtual machine running the interlock must return at once.

    The control for the two tests above: an implementation that always slept,
    or always raised, would satisfy them and fail here.
    """
    running = running_hcs_vm_processes()
    if running:
        pytest.skip(f"a real Host Compute Service VM is running on this host: {running!r}")

    started = time.monotonic()
    ensure_no_hcs_vm_running(timeout=_CLEARANCE_BUDGET_SEC)
    elapsed = time.monotonic() - started

    assert elapsed < _CLEAR_HOST_RETURN_SEC, f"the interlock waited {elapsed:.1f}s on a host with no virtual machine running"
