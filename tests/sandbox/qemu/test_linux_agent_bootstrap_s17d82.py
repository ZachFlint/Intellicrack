# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Gates for S17-D82: a Linux guest must actually reach a listening agent.

Booting ``debian13-intellicrack.qcow2`` through the production bridge failed
with ``guest agent failed to connect within 300.0s``, and that message was the
only thing the failure ever produced. Driving the same start phases against a
live guest on 2026-08-09, and then asking the guest itself, found two separate
faults.

**The agent could not start on a guest that had never run it.**
:meth:`QEMUSandbox._create_guest_agent_script` generates an ``agent.py`` that
configures logging at module scope::

    logging.basicConfig(handlers=[logging.FileHandler(LOG_DIR / "agent.log"), ...])

``FileHandler`` opens its file as it is constructed, and module scope runs on
import - long before ``main()``, which is where the directory used to be
created. The guest had no work root at all (``ls /var/lib/intellicrack`` exited
2, "No such file or directory"), so every run died at import::

    File "/mnt/shared/monitor/agent.py", line 88, in <module>
        logging.FileHandler(LOG_DIR / "agent.log"),
    FileNotFoundError: [Errno 2] No such file or directory:
        '/var/lib/intellicrack/logs/agent.log'

Nothing ever bound port 4445, so the host waited out the whole connect budget.

**Nothing could tell that it had died.** The launcher was
``python3 /mnt/shared/monitor/agent.py &``: the shell backgrounded the agent and
exited 0 whatever became of it, so ``guest_agent_bootstrap_launched`` recorded a
pid - 573, measured - that belonged to a shell which had already succeeded,
while the agent was gone. Its traceback went to a discarded stream. That is why
a defect at the agent's very first statement could only be seen as a timeout
minutes later.

The gates below run the generated agent as a real process on a work root that
does not exist, which is the guest's state on a first run, and check the
launcher's own ordering. The live gate boots the real Debian image through
``SandboxBridge`` - the reported repro exactly - and is the only one that
exercises the guest-side ``mkdir``, the ``exec`` and the liveness check
together.
"""

from __future__ import annotations

import asyncio
import re
import socket
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import pytest
import pytest_asyncio

from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.sandbox import qemu as qemu_module
from intellicrack.sandbox.base import SandboxConfig, SandboxError
from intellicrack.sandbox.qemu import GuestOS, QEMUConfig, QEMUSandbox
from tests.sandbox.qemu.guest_agent_server import GuestAgentProtocolServer, GuestCommandResult, QmpProtocolServer


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Sequence


_MONITOR_DIRECTORY: Final[str] = "monitor"
_LINUX_AGENT_NAME: Final[str] = "agent.py"
_LINUX_LAUNCHER_NAME: Final[str] = "start_agent.sh"
_AGENT_LOG_NAME: Final[str] = "agent.log"
_LOGS_DIRECTORY: Final[str] = "logs"

# The work root the agent is repointed at for the offline gate. It must not
# exist when the agent starts - that absence is the whole precondition - so it
# is named under the test's own temporary directory and never created.
_ABSENT_WORK_ROOT: Final[str] = "guest-work-root"

_WORK_ROOT_CONSTANT: Final[str] = "WORK_ROOT"
_PORT_CONSTANT: Final[str] = "PORT"

_LISTEN_BUDGET_S: Final[float] = 30.0
_LISTEN_POLL_S: Final[float] = 0.25
_CONNECT_TIMEOUT_S: Final[float] = 2.0
_AGENT_STOP_TIMEOUT_S: Final[float] = 10.0

_ERR_NO_CONSTANT: Final[str] = "the generated Linux agent has no single module-level {name} assignment (found {count})"

_GUEST_IMAGE: Final[Path] = Path("D:/Intellicrack/tools/qemu/images/debian13-intellicrack.qcow2")
_BOOT_BUDGET_S: Final[float] = 300.0
_COMMAND_LIMIT_S: Final[int] = 60
_GUEST_MEMORY_MB: Final[int] = 2048
_GUEST_CORES: Final[int] = 2

# What the live guest is asked once it is up. Any command would do; this one is
# on every Debian system and its answer cannot be produced by anything but a
# real agent running in the guest.
_LIVE_PROBE_COMMAND: Final[str] = "uname -s"
_LIVE_PROBE_ANSWER: Final[str] = "Linux"

# What the modelled agent dies of, and what it leaves behind on its way out.
# The text is the traceback the live Debian guest really produced.
_AGENT_FAILURE_EXIT: Final[int] = 1
_AGENT_TRACEBACK: Final[str] = (
    'Traceback (most recent call last):\n  File "/mnt/shared/monitor/agent.py", line 88, in <module>\n'
    "FileNotFoundError: [Errno 2] No such file or directory: '/var/lib/intellicrack/logs/agent.log'\n"
)
_REDIRECT_FAILED_EXIT: Final[int] = 1
_NO_AGENT_LINE_EXIT: Final[int] = 127
_TAIL_MISSING_EXIT: Final[int] = 1

# The connect budget the modelled host is given, and how long the failure may
# take. They are far apart on purpose: a host that only ever learns the budget
# ran out cannot come in under the second one.
_DEAD_AGENT_BUDGET_S: Final[float] = 20.0
_PROMPT_FAILURE_S: Final[float] = 8.0

_QUOTED_OPERAND = re.compile(r"'([^']+)'")
_REDIRECT_TARGET = re.compile(r">>\s*'([^']+)'")


class _LinuxAgentSandbox(QEMUSandbox):
    """``QEMUSandbox`` exposing the Linux start steps to test code.

    Every wrapped method is the real production implementation.
    """

    async def attach_agents(self) -> None:
        """Drive the real :meth:`QEMUSandbox._attach_qemu_agents`."""
        await self._attach_qemu_agents()

    async def close_clients(self) -> None:
        """Disconnect every protocol client the sandbox opened."""
        if self._qga is not None:
            await self._qga.disconnect()
            self._qga = None
        if self._qmp is not None:
            await self._qmp.disconnect()
            self._qmp = None
        if self._agent is not None:
            await self._agent.disconnect()
            self._agent = None

    async def generate_linux_scripts(self, share: Path) -> Path:
        """Write the production Linux agent and launcher into a shared folder.

        The directory is returned rather than the file contents so a caller can
        read the bytes as the guest receives them, which is the only way to see
        the line endings the writer chose.

        Args:
            share: Host directory standing in for the guest's shared folder.

        Returns:
            Path: The ``monitor`` directory the guest scripts were written to.
        """
        self._shared_folder = share
        await asyncio.to_thread((share / _MONITOR_DIRECTORY).mkdir, parents=True, exist_ok=True)
        await self._create_guest_agent_script()
        return share / _MONITOR_DIRECTORY


async def _generate(tmp_path: Path) -> Path:
    """Generate the production Linux guest scripts under a temporary root.

    Args:
        tmp_path: Directory the shared folder is created under.

    Returns:
        Path: The ``monitor`` directory the guest scripts were written to.
    """
    return await _LinuxAgentSandbox(qemu_config=_linux_config()).generate_linux_scripts(tmp_path / "share")


def _linux_config() -> QEMUConfig:
    """Build the configuration that selects the Linux guest scripts.

    Returns:
        QEMUConfig: Configuration naming a Linux guest.
    """
    return QEMUConfig(guest_os=GuestOS.LINUX)


def _rebind_constant(source: str, name: str, literal: str) -> str:
    """Repoint one module-level constant of the generated agent.

    The assignment is located rather than reproduced, and the annotation is
    kept, so a constant that was renamed or removed fails here loudly instead of
    leaving a test that silently measures the production value.

    Args:
        source: Full source of the generated ``agent.py``.
        name: Name of the constant to repoint.
        literal: Replacement expression, written as Python source.

    Returns:
        str: The agent source with that one assignment rewritten.

    Raises:
        AssertionError: If the source does not carry exactly one such
            annotated module-level assignment.
    """
    pattern = re.compile(rf"^({re.escape(name)}\s*:\s*[^=]+=\s*).*$", re.MULTILINE)
    rewritten, count = pattern.subn(lambda match: match.group(1) + literal, source)
    if count != 1:
        raise AssertionError(_ERR_NO_CONSTANT.format(name=name, count=count))
    return rewritten


def _free_port() -> int:
    """Reserve a TCP port the agent under test can bind.

    Returns:
        int: A port that was free on loopback a moment ago.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


async def _port_accepts(port: int) -> bool:
    """Report whether anything is accepting connections on a loopback port.

    Args:
        port: Port to try.

    Returns:
        bool: True when a connection was established and closed.
    """
    try:
        connection = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", port),
            timeout=_CONNECT_TIMEOUT_S,
        )
    except (OSError, TimeoutError):
        return False
    connection[1].close()
    return True


async def _await_listening(process: asyncio.subprocess.Process, port: int) -> bool:
    """Wait for the agent to start accepting, or for it to die trying.

    Args:
        process: The running agent process.
        port: Port the agent was repointed at.

    Returns:
        bool: True when the port accepted a connection within the budget.
    """
    deadline = asyncio.get_running_loop().time() + _LISTEN_BUDGET_S
    while asyncio.get_running_loop().time() < deadline:
        if await _port_accepts(port):
            return True
        if process.returncode is not None:
            return False
        await asyncio.sleep(_LISTEN_POLL_S)
    return False


async def _stop(process: asyncio.subprocess.Process) -> str:
    """Terminate the agent process and return whatever it complained about.

    Args:
        process: The running agent process.

    Returns:
        str: The agent's standard error, decoded.
    """
    if process.returncode is None:
        process.kill()
    try:
        _, stderr = await asyncio.wait_for(process.communicate(), timeout=_AGENT_STOP_TIMEOUT_S)
    except TimeoutError:
        return ""
    return stderr.decode(errors="replace").strip()


class TestTheGeneratedAgentStartsOnAGuestThatNeverRanIt:
    """The agent has to survive its own import before it can serve anything."""

    @pytest.mark.asyncio
    async def test_the_agent_listens_when_its_work_root_is_absent(self, tmp_path: Path) -> None:
        """The generated agent must reach its accept loop with no work root.

        A freshly provisioned guest has never run the agent, so the directory
        its log handler opens a file in does not exist. The agent is repointed
        at such a directory here - named, never created - and then run as a real
        process, because the fault is in what import time does and only running
        it can show that.

        Args:
            tmp_path: Directory the agent's work root is named under.
        """
        monitor = await _generate(tmp_path)
        agent_source = (monitor / _LINUX_AGENT_NAME).read_text(encoding="utf-8")

        work_root = tmp_path / _ABSENT_WORK_ROOT
        assert not work_root.exists(), (
            f"{work_root} already exists, so this run could not tell an agent that creates its work root "
            f"from one that depends on it already being there"
        )

        port = _free_port()
        relocated = _rebind_constant(agent_source, _WORK_ROOT_CONSTANT, f'Path("{work_root.as_posix()}")')
        relocated = _rebind_constant(relocated, _PORT_CONSTANT, str(port))
        agent_path = tmp_path / _LINUX_AGENT_NAME
        agent_path.write_text(relocated, encoding="utf-8")

        process = await asyncio.create_subprocess_exec(
            sys.executable,
            str(agent_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            listening = await _await_listening(process, port)
            diagnostics = "" if listening else await _stop(process)
        finally:
            if process.returncode is None:
                await _stop(process)

        assert listening, (
            f"the generated agent never accepted a connection on port {port} with its work root absent, "
            f"so a freshly provisioned guest can only fail the agent-connect wait; it said: {diagnostics}"
        )
        assert (work_root / _LOGS_DIRECTORY / _AGENT_LOG_NAME).is_file(), (
            f"the agent is listening but wrote no {_AGENT_LOG_NAME} under {work_root}, so it is not the log directory that this run proved"
        )


class TestTheLauncherProvesTheAgentItStarted:
    """A launcher that always succeeds hides every guest-side failure."""

    async def _launcher(self, tmp_path: Path) -> str:
        """Generate the production Linux launcher.

        Args:
            tmp_path: Directory the shared folder is created under.

        Returns:
            str: Full text of the generated ``start_agent.sh``.
        """
        monitor = await _generate(tmp_path)
        return (monitor / _LINUX_LAUNCHER_NAME).read_text(encoding="utf-8")

    @pytest.mark.asyncio
    async def test_the_launcher_is_written_with_unix_line_endings(self, tmp_path: Path) -> None:
        r"""A shell script full of carriage returns is one bash refuses to run.

        The application writes the guest's scripts from a Windows host, where
        text mode turns every newline into a carriage-return pair. bash then
        reads the ``\r`` as part of the last word on every line, which broke
        the launcher outright once it carried more than one statement.

        Args:
            tmp_path: Directory the shared folder is created under.
        """
        monitor = await _generate(tmp_path)
        launcher = (monitor / _LINUX_LAUNCHER_NAME).read_bytes()

        assert b"\r" not in launcher, (
            f"the guest's launcher was written with carriage returns ({launcher!r}), so bash takes each one as "
            f"part of the preceding word and the script fails before it starts the agent"
        )

    @pytest.mark.asyncio
    async def test_the_launcher_does_not_background_the_agent(self, tmp_path: Path) -> None:
        """The pid the host records has to be the agent's own.

        A backgrounded agent leaves the host holding the pid of a shell that
        has already exited 0, which is indistinguishable from a healthy start.

        Args:
            tmp_path: Directory the shared folder is created under.
        """
        launcher = await self._launcher(tmp_path)
        commands = [line.strip() for line in launcher.splitlines() if line.strip() and not line.startswith("#!")]
        agent_commands = [command for command in commands if _LINUX_AGENT_NAME in command]

        assert agent_commands, f"the launcher never starts {_LINUX_AGENT_NAME}: {launcher!r}"
        for command in agent_commands:
            assert not command.endswith("&"), (
                f"the launcher backgrounds the agent ({command!r}), so the shell exits 0 whatever becomes of it "
                f"and the pid the host records belongs to a process that already succeeded"
            )
            assert command.startswith("exec "), (
                f"the launcher runs the agent as a child ({command!r}) rather than replacing itself with it, "
                f"so the pid the host records is the shell's and not the agent's"
            )

    @pytest.mark.asyncio
    async def test_the_launcher_keeps_what_the_agent_said(self, tmp_path: Path) -> None:
        """A crashing agent has to leave its output somewhere on the guest.

        Args:
            tmp_path: Directory the shared folder is created under.
        """
        launcher = await self._launcher(tmp_path)
        agent_line = next(line for line in launcher.splitlines() if _LINUX_AGENT_NAME in line)

        assert ">>" in agent_line, (
            f"the launcher discards the agent's standard output ({agent_line!r}), so a guest-side failure leaves "
            f"no evidence anywhere and the host can only report a timeout"
        )
        assert "2>&1" in agent_line, (
            f"the launcher discards the agent's standard error ({agent_line!r}), which is where a Python "
            f"traceback goes, so the one thing that names the failure is thrown away"
        )

    @pytest.mark.asyncio
    async def test_the_launcher_creates_the_directory_it_redirects_into(self, tmp_path: Path) -> None:
        """The redirect target's directory must be made first.

        The redirect target is read out of the launcher rather than restated
        here, so this cannot pass by naming a directory the launcher does not
        actually write to.

        Args:
            tmp_path: Directory the shared folder is created under.
        """
        launcher = await self._launcher(tmp_path)
        lines = [line.strip() for line in launcher.splitlines() if line.strip()]
        agent_index = next(index for index, line in enumerate(lines) if _LINUX_AGENT_NAME in line)
        redirect = re.search(r">>\s*'([^']+)'", lines[agent_index])

        assert redirect is not None, f"the launcher's agent line carries no quoted redirect target: {lines!r}"
        log_directory = redirect.group(1).rsplit("/", 1)[0]
        created = [line for line in lines[:agent_index] if line.startswith("mkdir") and log_directory in line]

        assert created, (
            f"nothing before the agent line creates {log_directory!r}, so the redirect fails on a guest that has "
            f"never run the agent and the launcher dies before the agent starts: {lines!r}"
        )


class _BootstrapGuest:
    """Model of a Linux guest that really runs the launcher the host wrote.

    The share is already mounted, which is the state a guest reaches once
    ``fstab`` has done the work, so the start sequence goes straight to the
    bootstrap. What happens then is read out of the generated ``start_agent.sh``
    rather than assumed: each ``mkdir`` makes a directory, the line that starts
    the agent is redirected into whatever that line names, and the redirect
    fails if nothing created its parent - exactly as the shell would. The agent
    it starts then dies, leaving its traceback wherever the redirect put it, so
    a host that watches the process it launched can find it and one that does
    not cannot.

    Attributes:
        launched: Launcher paths the guest was asked to run.
    """

    launched: list[str]

    def __init__(self, share: Path, exit_code: int, message: str) -> None:
        """Configure the modelled guest.

        Args:
            share: Host directory the guest sees as its shared volume.
            exit_code: Status the agent this launcher starts exits with.
            message: What that agent writes before it goes.
        """
        self._share = share
        self._exit_code = exit_code
        self._message = message
        self._logs: dict[str, str] = {}
        self.launched = []

    def __call__(self, path: str, args: Sequence[str]) -> GuestCommandResult:
        """Execute one command against the modelled guest.

        Args:
            path: Executable the production code asked the guest to run.
            args: Argument list passed with the executable.

        Returns:
            GuestCommandResult: Exit status and captured output.
        """
        argv = list(args)
        if path == "test":
            return GuestCommandResult(exit_code=0, stdout="", stderr="")
        if path == "/bin/bash":
            return self._run_launcher(argv)
        if path == "tail":
            return self._run_tail(argv)
        return GuestCommandResult(exit_code=_NO_AGENT_LINE_EXIT, stdout="", stderr=f"{path}: command not found")

    def _run_launcher(self, argv: list[str]) -> GuestCommandResult:
        """Interpret the launcher the sandbox really generated.

        Args:
            argv: Arguments passed to ``/bin/bash``.

        Returns:
            GuestCommandResult: What the launcher leaves behind on this guest.
        """
        script = argv[0] if argv else ""
        self.launched.append(script)
        body = (self._share / _MONITOR_DIRECTORY / _LINUX_LAUNCHER_NAME).read_text(encoding="utf-8")
        created: set[str] = set()
        for line in body.splitlines():
            statement = line.strip()
            if statement.startswith("mkdir"):
                made = _QUOTED_OPERAND.search(statement)
                if made is not None:
                    created.add(made.group(1))
            elif _LINUX_AGENT_NAME in statement:
                return self._run_agent(statement, created)

        return GuestCommandResult(
            exit_code=_NO_AGENT_LINE_EXIT,
            stdout="",
            stderr=f"{script}: nothing in this launcher starts {_LINUX_AGENT_NAME}",
        )

    def _run_agent(self, statement: str, created: set[str]) -> GuestCommandResult:
        """Run the agent the way the launcher's own line runs it.

        Args:
            statement: The launcher line that starts the agent.
            created: Directories the launcher made before reaching it.

        Returns:
            GuestCommandResult: The agent's exit status, or the shell's own
            failure when the redirect had nowhere to write.
        """
        redirect = _REDIRECT_TARGET.search(statement)
        if redirect is None:
            return GuestCommandResult(exit_code=self._exit_code, stdout="", stderr="")

        target = redirect.group(1)
        if target.rsplit("/", 1)[0] not in created:
            return GuestCommandResult(
                exit_code=_REDIRECT_FAILED_EXIT,
                stdout="",
                stderr=f"{target}: No such file or directory",
            )

        self._logs[target] = self._message
        return GuestCommandResult(exit_code=self._exit_code, stdout="", stderr="")

    def _run_tail(self, argv: list[str]) -> GuestCommandResult:
        """Read back a file the launcher wrote on this guest.

        Args:
            argv: Arguments passed to ``tail``.

        Returns:
            GuestCommandResult: The file's contents, or tail's own error.
        """
        path = argv[-1] if argv else ""
        body = self._logs.get(path)
        if body is None:
            return GuestCommandResult(
                exit_code=_TAIL_MISSING_EXIT,
                stdout="",
                stderr=f"tail: cannot open '{path}' for reading: No such file or directory",
            )
        return GuestCommandResult(exit_code=0, stdout=body, stderr="")


@pytest.mark.asyncio
class TestTheHostNoticesTheAgentItStartedHasDied:
    """A dead agent must end the connect wait, not run it out."""

    async def test_a_dead_agent_fails_the_start_with_the_guests_own_words(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The start sequence must report the exit, promptly and by name.

        The modelled guest runs the launcher the sandbox really generated and
        then loses the agent, which is what a guest whose work root does not
        exist does. The connect budget is far longer than this may take, so a
        host that only ever learns the budget ran out cannot pass.

        Args:
            tmp_path: Directory the shared folder is created under.
            monkeypatch: Fixture used to pin the host platform.
        """
        monkeypatch.setattr(qemu_module, "_IS_WINDOWS", True)
        share = tmp_path / "share"
        guest = _BootstrapGuest(share, _AGENT_FAILURE_EXIT, _AGENT_TRACEBACK)
        agent_server = GuestAgentProtocolServer(guest)
        await agent_server.start()
        monitor = QmpProtocolServer()
        await monitor.start()

        sandbox = _LinuxAgentSandbox(
            config=SandboxConfig(),
            qemu_config=QEMUConfig(
                guest_os=GuestOS.LINUX,
                monitor_port=monitor.port,
                agent_port=agent_server.port - 1,
                agent_connect_timeout=_DEAD_AGENT_BUDGET_S,
            ),
        )
        await sandbox.generate_linux_scripts(share)

        started = asyncio.get_running_loop().time()
        try:
            with pytest.raises(SandboxError) as failure:
                await sandbox.attach_agents()
        finally:
            elapsed = asyncio.get_running_loop().time() - started
            await sandbox.close_clients()
            await monitor.stop()
            await agent_server.stop()

        reported = str(failure.value)
        assert guest.launched, "the start sequence never ran the launcher, so nothing about the agent was proved"
        assert f"exited {_AGENT_FAILURE_EXIT}" in reported, f"the failure does not say the agent exited or with what: {reported!r}"
        assert "FileNotFoundError" in reported, (
            f"the failure carries none of what the guest itself recorded ({reported!r}), so the operator is left "
            f"with a timeout and no way to find out why"
        )
        assert elapsed < _PROMPT_FAILURE_S, (
            f"the start took {elapsed:.1f}s of its {_DEAD_AGENT_BUDGET_S:.0f}s budget to report an agent that was "
            f"already gone, so the host is still waiting one out rather than noticing it"
        )


class _LiveGuest:
    """A running Linux guest reachable over the agent the bootstrap started."""

    def __init__(self, bridge: SandboxBridge, instance_id: str) -> None:
        """Bind the guest to the bridge that created it.

        Args:
            bridge: Bridge the instance belongs to.
            instance_id: Identifier of the running instance.
        """
        self._bridge = bridge
        self._instance_id = instance_id

    async def run(self, command: str) -> str:
        """Run a command in the guest and return its stdout.

        Args:
            command: Command line to execute inside the guest.

        Returns:
            str: The command's standard output.
        """
        result: dict[str, Any] = await self._bridge.execute(self._instance_id, command, time_limit=_COMMAND_LIMIT_S)
        return str(result["stdout"])


@pytest.mark.asyncio
class TestTheDebianGuestReachesAgentReady:
    """The reported repro, run against the image that exposed the defect."""

    async def test_the_provisioned_debian_guest_answers_a_command(self, live_debian_guest: _LiveGuest) -> None:
        """The guest booted through the bridge must run a command for us.

        This is the failure as it was reported: the same image, the same
        300-second budget. Reaching a guest that answers means the agent bound
        its port, which is exactly what a work root created too late prevented.

        Args:
            live_debian_guest: A booted Debian guest reachable over its agent.
        """
        answer = await live_debian_guest.run(_LIVE_PROBE_COMMAND)

        assert _LIVE_PROBE_ANSWER in answer, (
            f"the guest agent answered {_LIVE_PROBE_COMMAND!r} with {answer!r}, so the channel the sandbox runs "
            f"everything over is not carrying the guest's own output"
        )


@pytest_asyncio.fixture
async def live_debian_guest() -> AsyncIterator[_LiveGuest]:
    """Boot the provisioned Debian guest through the production bridge.

    Reaching the yield is itself the assertion the defect is gated by: with the
    agent unable to start, ``create`` raised ``sandbox start failed`` after the
    agent-connect wait ran out.

    Yields:
        _LiveGuest: A guest whose agent answers commands.
    """
    assert _GUEST_IMAGE.is_file(), f"the provisioned Debian guest image is missing: {_GUEST_IMAGE}"

    bridge = SandboxBridge()
    await bridge.initialize()
    config = QEMUConfig(
        guest_os=GuestOS.LINUX,
        image_path=_GUEST_IMAGE,
        cpu_cores=_GUEST_CORES,
        memory_mb=_GUEST_MEMORY_MB,
        display="vnc",
        agent_connect_timeout=_BOOT_BUDGET_S,
        guest_agent_ready_timeout=_BOOT_BUDGET_S,
    )
    created = await bridge.create(
        sandbox_type="qemu",
        timeout_seconds=int(_BOOT_BUDGET_S),
        memory_limit_mb=_GUEST_MEMORY_MB,
        qemu_config=config,
    )
    instance_id = str(created["instance_id"])
    try:
        yield _LiveGuest(bridge, instance_id)
    finally:
        await bridge.destroy(instance_id)
        await bridge.shutdown()
