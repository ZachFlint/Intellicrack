# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Gate for S18-D16: "Block telemetry endpoints" has to reach the guest.

Sandbox Settings ships that checkbox **ticked**, and until this slice the answer reached
nothing at all: no field carried it, no backend read it, and no command was ever issued
inside the guest. Measured on a real Windows guest booted with the box ticked, the guest
resolved ``v10.events.data.microsoft.com`` and completed a TCP connection to it on 443 -
the vendor traffic an analyst ticks that box to be rid of, sitting in the capture beside
the sample's own flows and indistinguishable from them.

The fix is a hosts-file sinkhole for the published telemetry FQDNs plus outbound firewall
rules for the telemetry executables, carried by ``SandboxConfig.block_telemetry``, filled
in from the dialog key by ``MainWindow._build_sandbox_config``, and applied by
``WindowsSandbox._apply_telemetry_blocking`` at the end of the start sequence.

What each part of this module protects:

* **The script really sinkholes.** The production PowerShell is executed for real and the
  hosts file it writes is read back, so a script that emits a plausible summary while
  writing nothing - the defect one layer along from the one measured - fails here.
* **Idempotency.** A guest is blocked at every start; a naive append would double the
  hosts file on every boot until name resolution itself became the problem.
* **Preservation.** The script edits a file the guest also owns, so entries it did not
  write have to come out the other side untouched.
* **The blocked set.** ``v10.events.data.microsoft.com`` is the endpoint that was caught
  in the act, and ``svchost.exe`` must never be in the program list: a blanket block on
  the service host takes the guest's whole network with it, and a sandbox whose guest
  reaches nothing measures nothing while still reporting success.
* **The dialog answer.** The setting has to survive the dialog-to-config translation and
  be compared when deciding whether a running sandbox is stale, since a field missing
  from that comparator is the same defect one layer along.
* **The backend.** ``_apply_telemetry_blocking`` builds the command and parses the reply;
  only the guest transport differs from a local run, so the local run is a real gate.

**How the real runs are kept away from this machine's own hosts file.** The script derives
its target from ``Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'``, so every run
here is aimed at a ``System32\drivers\etc`` tree underneath ``tmp_path``. The redirection
is a prelude that assigns ``$env:SystemRoot`` inside the PowerShell process rather than an
inherited environment variable, because ``powershell.exe`` refuses to start at all when
the ``SystemRoot`` it inherits is synthetic (measured: "Internal Windows PowerShell error.
Loading managed Windows PowerShell failed with error 8009001d"). The script body is the
production one, unmodified, and every run asserts that the path the script reports writing
to lies inside that tree before it asserts anything else.

The runs spawn a real ``powershell.exe`` and really attempt firewall changes, so they carry
``spawns_process`` and execute only inside the Docker sandbox container.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import shutil
import subprocess
from pathlib import Path
from typing import Final

import pytest

from intellicrack.sandbox.base import SandboxConfig
from intellicrack.sandbox.telemetry_blocking import (
    HOSTS_BLOCK_MARKER,
    SINKHOLE_ADDRESS,
    TELEMETRY_HOSTS,
    TELEMETRY_PROGRAMS,
    build_windows_blocking_script,
    parse_blocking_result,
)
from intellicrack.sandbox.windows import WindowsSandbox
from intellicrack.ui.app import MainWindow


_MEASURED_ENDPOINT: Final[str] = "v10.events.data.microsoft.com"
_SETTINGS_ENDPOINT: Final[str] = "settings-win.data.microsoft.com"
_SERVICE_HOST: Final[str] = "svchost.exe"
_PROGRAM_PREFIX: Final[str] = "%SystemRoot%\\System32\\"

_FIREWALL_BACKENDS: Final[frozenset[str]] = frozenset({"netsecurity", "netsh"})

_BEGIN_LINE: Final[str] = f"# BEGIN {HOSTS_BLOCK_MARKER}"
_END_LINE: Final[str] = f"# END {HOSTS_BLOCK_MARKER}"

_GUEST_OWNED_LINES: Final[tuple[str, ...]] = (
    "# Maintained by the guest image, not by Intellicrack",
    "10.0.2.2 corp-file-server.internal",
)

_SCRIPT_ENCODING: Final[str] = "utf-16-le"
_HOSTS_ENCODING: Final[str] = "ascii"
_SCRIPT_TIMEOUT: Final[int] = 300
_ENCODED_FLAG: Final[str] = "-EncodedCommand"
_GUEST_INTERPRETER: Final[str] = "powershell.exe"


def _powershell() -> str:
    """Locate the real PowerShell this machine runs.

    Returns:
        str: Absolute path to ``powershell.exe``.
    """
    found = shutil.which(_GUEST_INTERPRETER)
    assert found is not None, "no powershell.exe on PATH, so the guest command under test cannot be executed at all"
    return found


def _hosts_file(system_root: Path) -> Path:
    r"""Return the hosts file the script targets under a given ``SystemRoot``.

    Args:
        system_root: Directory standing in for the guest's Windows directory.

    Returns:
        Path: The ``System32\\drivers\\etc\\hosts`` path below ``system_root``.
    """
    return system_root / "System32" / "drivers" / "etc" / "hosts"


def _prepare_system_root(tmp_path: Path, seeded_lines: tuple[str, ...] = ()) -> Path:
    """Build a redirected ``SystemRoot`` tree, optionally with a pre-existing hosts file.

    Args:
        tmp_path: Pytest temporary directory that contains the tree.
        seeded_lines: Lines written to the hosts file before the script runs, standing
            in for entries the guest image already carried.

    Returns:
        Path: The directory to be used as the guest's ``SystemRoot``.
    """
    system_root = tmp_path / "guest-windows"
    hosts = _hosts_file(system_root)
    hosts.parent.mkdir(parents=True, exist_ok=True)
    if seeded_lines:
        hosts.write_text("".join(f"{line}\n" for line in seeded_lines), encoding=_HOSTS_ENCODING)
    return system_root


def _redirect_prelude(system_root: Path) -> str:
    """Build the PowerShell that points the process at a redirected ``SystemRoot``.

    Args:
        system_root: Directory the script should treat as the guest Windows directory.

    Returns:
        str: A single assignment statement, terminated by a newline.
    """
    quoted = str(system_root).replace("'", "''")
    return f"$env:SystemRoot = '{quoted}'\n"


def _encoded_argv(script: str) -> list[str]:
    """Encode a script the way the production command builder does.

    Args:
        script: PowerShell source to run.

    Returns:
        list[str]: ``powershell.exe`` arguments carrying the script as base64 UTF-16-LE.
    """
    encoded = base64.b64encode(script.encode(_SCRIPT_ENCODING)).decode("ascii")
    return ["-NoProfile", "-ExecutionPolicy", "Bypass", _ENCODED_FLAG, encoded]


def _summary_of(system_root: Path, exit_code: int, stdout: str, stderr: str) -> dict[str, object]:
    """Parse a blocking run's summary and confirm it edited the redirected tree.

    Args:
        system_root: Directory the run was pointed at.
        exit_code: Exit code the PowerShell process returned.
        stdout: Captured standard output of the run.
        stderr: Captured standard error of the run.

    Returns:
        dict[str, object]: The summary the production script reported.
    """
    assert exit_code == 0, f"the telemetry blocking script did not complete (exit {exit_code}); stderr was: {stderr[:400]}"
    summary = parse_blocking_result(stdout)
    assert summary is not None, f"the script finished without reporting what it did, so a guest could not be told either: {stdout[:400]}"

    reported = summary.get("hosts_path")
    assert isinstance(reported, str), (
        f"the script reported no hosts path, so there is no evidence it targeted a hosts file at all: {summary}"
    )
    written = Path(reported)
    assert written.is_relative_to(system_root), (
        f"the script edited {written}, outside the redirected tree - a real machine's hosts file was at risk"
    )
    assert written == _hosts_file(system_root), f"the script wrote {written} instead of the guest's hosts file"
    return summary


def _apply_blocking(system_root: Path) -> dict[str, object]:
    """Run the unmodified production script against a redirected ``SystemRoot``.

    Args:
        system_root: Directory the script should treat as the guest Windows directory.

    Returns:
        dict[str, object]: The summary the script reported.
    """
    script = _redirect_prelude(system_root) + build_windows_blocking_script()
    completed = subprocess.run(
        [_powershell(), *_encoded_argv(script)],
        capture_output=True,
        text=True,
        timeout=_SCRIPT_TIMEOUT,
        check=False,
    )
    return _summary_of(system_root, completed.returncode, completed.stdout, completed.stderr)


def _hosts_lines(system_root: Path) -> list[str]:
    """Read back the hosts file the script wrote.

    Args:
        system_root: Directory the script was pointed at.

    Returns:
        list[str]: The file's lines, newline characters removed.
    """
    hosts = _hosts_file(system_root)
    assert hosts.is_file(), f"the run reported its work but left no hosts file at {hosts}, so nothing in the guest was ever sinkholed"
    return hosts.read_text(encoding=_HOSTS_ENCODING).splitlines()


def _sinkhole_line(hostname: str) -> str:
    """Build the hosts entry that sinkholes one endpoint.

    Args:
        hostname: Fully-qualified name that must resolve nowhere.

    Returns:
        str: The exact line the guest's hosts file has to carry.
    """
    return f"{SINKHOLE_ADDRESS} {hostname}"


class _RedirectedTelemetrySandbox(WindowsSandbox):
    """``WindowsSandbox`` whose guest transport runs the command on this machine.

    Only the transport is replaced. ``_apply_telemetry_blocking`` builds the argv, this
    class decodes the very script that argv carries, re-encodes it behind a ``SystemRoot``
    redirection and runs it through a real ``powershell.exe``, then hands the genuine
    ``(exit_code, stdout, stderr)`` back for the production parser to interpret. Reaching
    it at all while telemetry blocking is configured off is a failure, because the guest
    would have been touched against the analyst's wishes.

    Attributes:
        commands: Every command the backend dispatched, in order.
    """

    commands: list[str]

    def __init__(self, config: SandboxConfig, system_root: Path) -> None:
        """Initialise the sandbox with a redirected guest Windows directory.

        Args:
            config: Sandbox configuration under test.
            system_root: Directory that stands in for the guest's ``SystemRoot``.
        """
        super().__init__(config)
        self._system_root = system_root
        self.commands = []

    async def run_command(
        self,
        command: str,
        time_limit: int | None = None,
        working_directory: str | None = None,
    ) -> tuple[int, str, str]:
        """Execute the backend's command for real against the redirected tree.

        Args:
            command: Command the backend built for the guest.
            time_limit: Time budget the backend allowed, enforced here for real.
            working_directory: Unused; the script chooses its own target.

        Returns:
            tuple[int, str, str]: The real ``(exit_code, stdout, stderr)`` of the run.
        """
        del working_directory
        self.commands.append(command)
        assert self._config.block_telemetry, "the backend reached into the guest even though telemetry blocking was configured off"

        argv = command.split(" ")
        assert argv[0] == _GUEST_INTERPRETER, f"the backend asked the guest to run something other than PowerShell: {command[:120]}"
        assert _ENCODED_FLAG in argv, (
            f"the script was not passed as an encoded command, so a cmd.exe channel would mangle it: {command[:120]}"
        )
        assert time_limit is not None, "the backend dispatched the blocking run with no time limit, so a wedged guest would hang the start"
        assert time_limit > 0, f"the backend gave the guest an unusable time budget: {time_limit}"

        script = base64.b64decode(argv[argv.index(_ENCODED_FLAG) + 1]).decode(_SCRIPT_ENCODING)
        local = [_powershell(), *_encoded_argv(_redirect_prelude(self._system_root) + script)]
        process = await asyncio.create_subprocess_exec(*local, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=time_limit)
        return (process.returncode or 0, stdout.decode(errors="replace"), stderr.decode(errors="replace"))

    def apply_blocking(self) -> None:
        """Drive the production telemetry-blocking step of the start sequence."""
        asyncio.run(self._apply_telemetry_blocking())


class _SandboxSettingsProbe(MainWindow):
    """Reaches the window's settings translation without building a window.

    Both helpers under test are static, so the dialog-to-config path can be driven
    exactly as the running application drives it while no widget is constructed.
    """

    @classmethod
    def build_config(cls, settings: dict[str, object]) -> SandboxConfig:
        """Translate a dialog settings dictionary through the production code.

        Args:
            settings: Settings dictionary as the sandbox config dialog emits it.

        Returns:
            SandboxConfig: The configuration the application would install.
        """
        return cls._build_sandbox_config(settings)

    @classmethod
    def configs_match(cls, existing: SandboxConfig, incoming: SandboxConfig) -> bool:
        """Compare two configurations through the production comparator.

        Args:
            existing: Configuration a running sandbox was started with.
            incoming: Configuration the dialog has just produced.

        Returns:
            bool: True when the application would consider the running sandbox current.
        """
        return cls._sandbox_configs_match(existing, incoming)


@pytest.mark.integration
@pytest.mark.spawns_process
class TestTheScriptSinkholesForReal:
    """The generated PowerShell has to change a real hosts file, not just report success."""

    def test_every_published_endpoint_lands_in_the_hosts_file(self, tmp_path: Path) -> None:
        """Each blocked FQDN is present exactly once, pointed at the sinkhole address.

        Args:
            tmp_path: Pytest temporary directory holding the redirected ``SystemRoot``.
        """
        system_root = _prepare_system_root(tmp_path)
        summary = _apply_blocking(system_root)

        lines = _hosts_lines(system_root)
        missing = [hostname for hostname in TELEMETRY_HOSTS if lines.count(_sinkhole_line(hostname)) != 1]
        assert not missing, f"the guest would still resolve these telemetry endpoints after the box was ticked: {missing}"
        assert lines.count(_BEGIN_LINE) == 1, f"the block Intellicrack owns is not fenced, so a later run cannot replace it: {lines}"
        assert lines.count(_END_LINE) == 1, f"the block Intellicrack owns has no end fence: {lines}"
        assert summary.get("hosts_entries") == len(TELEMETRY_HOSTS), (
            f"the script reported {summary.get('hosts_entries')} entries but the blocked set has {len(TELEMETRY_HOSTS)}"
        )
        assert lines.index(_BEGIN_LINE) < lines.index(_sinkhole_line(_MEASURED_ENDPOINT)) < lines.index(_END_LINE), (
            f"the sinkhole entries were written outside the fenced block: {lines}"
        )

    def test_the_firewall_half_is_really_attempted(self, tmp_path: Path) -> None:
        """The run reaches the firewall stage and names the backend it chose.

        The rules themselves are not asserted: a container usually has no Windows Firewall
        service, so the attempt legitimately fails there. What must not happen is the run
        skipping the second mechanism entirely, which would leave a client with a pinned
        address or DNS-over-HTTPS free to bypass the sinkhole unnoticed.

        Args:
            tmp_path: Pytest temporary directory holding the redirected ``SystemRoot``.
        """
        summary = _apply_blocking(_prepare_system_root(tmp_path))

        backend = summary.get("firewall_backend")
        assert backend in _FIREWALL_BACKENDS, f"the run never reached the firewall stage; it reported backend {backend!r}"
        assert isinstance(summary.get("firewall_rules"), int), f"the run did not report how many rules it wrote: {summary}"
        assert isinstance(summary.get("problems"), list), f"the run did not report the failures it hit, so they would be silent: {summary}"

    def test_reapplying_leaves_exactly_one_marked_block(self, tmp_path: Path) -> None:
        """A second run replaces the block instead of appending another copy.

        Args:
            tmp_path: Pytest temporary directory holding the redirected ``SystemRoot``.
        """
        system_root = _prepare_system_root(tmp_path, _GUEST_OWNED_LINES)
        _ = _apply_blocking(system_root)
        first_run = _hosts_lines(system_root)
        _ = _apply_blocking(system_root)
        second_run = _hosts_lines(system_root)

        assert second_run == first_run, f"a second start rewrote the guest's hosts file differently: {second_run}"
        assert second_run.count(_BEGIN_LINE) == 1, f"every guest start would add another block: {second_run}"
        assert second_run.count(_END_LINE) == 1, f"every guest start would add another end fence: {second_run}"
        duplicated = [hostname for hostname in TELEMETRY_HOSTS if second_run.count(_sinkhole_line(hostname)) != 1]
        assert not duplicated, f"these endpoints gained a duplicate entry on the second start: {duplicated}"
        for owned in _GUEST_OWNED_LINES:
            assert second_run.count(owned) == 1, f"re-applying the block duplicated or dropped the guest's own line {owned!r}: {second_run}"

    def test_entries_the_guest_already_had_survive(self, tmp_path: Path) -> None:
        """Lines the guest image carried come out of the run verbatim and in order.

        Args:
            tmp_path: Pytest temporary directory holding the redirected ``SystemRoot``.
        """
        system_root = _prepare_system_root(tmp_path, _GUEST_OWNED_LINES)
        _ = _apply_blocking(system_root)

        lines = _hosts_lines(system_root)
        assert lines[: len(_GUEST_OWNED_LINES)] == list(_GUEST_OWNED_LINES), (
            f"the guest's own hosts entries were rewritten or reordered by the block: {lines}"
        )
        assert lines.index(_GUEST_OWNED_LINES[-1]) < lines.index(_BEGIN_LINE), (
            f"the guest's own entries ended up inside the block Intellicrack rewrites: {lines}"
        )


class TestTheBlockedSetMatchesTheMeasurement:
    """The published list has to cover what was caught, and nothing that breaks the guest."""

    def test_the_measured_endpoints_are_in_the_blocked_set(self) -> None:
        """The endpoint measured leaking, and the settings endpoint beside it, are blocked."""
        assert _MEASURED_ENDPOINT in TELEMETRY_HOSTS, (
            f"{_MEASURED_ENDPOINT} is the endpoint a live guest was caught reaching, and it is not blocked"
        )
        assert _SETTINGS_ENDPOINT in TELEMETRY_HOSTS, (
            f"{_SETTINGS_ENDPOINT} is not blocked, so the guest keeps polling for settings during a capture"
        )

        script = build_windows_blocking_script()
        for hostname in (_MEASURED_ENDPOINT, _SETTINGS_ENDPOINT):
            assert f"'{hostname}'" in script, f"{hostname} is in the blocked set but never reaches the script the guest runs"

    def test_the_service_host_is_never_blocked(self) -> None:
        """No rule targets ``svchost.exe``, which would cost the guest its whole network."""
        leaves = [program.rsplit("\\", maxsplit=1)[-1].lower() for program in TELEMETRY_PROGRAMS]
        assert leaves, "no telemetry programs are blocked at all, so anything resolving without the hosts file gets through"
        assert _SERVICE_HOST not in leaves, (
            f"blocking the service host takes the guest's networking with it, and every run would then measure nothing: {leaves}"
        )
        assert _SERVICE_HOST not in build_windows_blocking_script().lower(), (
            "the script the guest runs mentions svchost.exe, which must never be blocked"
        )

        misplaced = [
            program for program in TELEMETRY_PROGRAMS if not program.startswith(_PROGRAM_PREFIX) or not program.lower().endswith(".exe")
        ]
        assert not misplaced, f"these firewall targets are not guest System32 executables, so the rules would match nothing: {misplaced}"

    def test_the_sinkhole_is_the_unspecified_address(self) -> None:
        """Blocked names resolve to the unspecified address, not to loopback.

        A loopback sinkhole makes the telemetry client open a connection to a local port,
        and that connection lands in the capture as traffic the sample never made. The
        unspecified address fails the connection immediately instead. The classification
        comes from :mod:`ipaddress` rather than from a literal repeated out of the
        implementation.
        """
        address = ipaddress.IPv4Address(SINKHOLE_ADDRESS)
        assert address.is_unspecified, (
            f"blocked names resolve to {SINKHOLE_ADDRESS}, which is a real destination the guest would try to reach"
        )
        assert not address.is_loopback, "sinkholing to loopback puts fabricated local connections into every capture"


class TestTheDialogAnswerReachesTheConfig:
    """The checkbox has to survive the translation into ``SandboxConfig`` and the restart check."""

    def test_unticking_the_box_reaches_the_config(self) -> None:
        """Both answers the dialog can give arrive intact in the configuration."""
        assert _SandboxSettingsProbe.build_config({"block_telemetry": False}).block_telemetry is False, (
            "an analyst who unticked the box would still get a guest with its telemetry blocked"
        )
        assert _SandboxSettingsProbe.build_config({"block_telemetry": True}).block_telemetry is True, (
            "the ticked box does not reach the configuration, which is the defect this slice fixes"
        )

    def test_an_absent_key_falls_back_to_the_shipped_default(self) -> None:
        """A settings dictionary without the key yields the dataclass default, which is on."""
        assert SandboxConfig().block_telemetry is True, "the dialog ships the box ticked, so an unconfigured sandbox must block telemetry"
        assert _SandboxSettingsProbe.build_config({}).block_telemetry is True, (
            "settings saved before this field existed would silently turn telemetry blocking off"
        )

    def test_the_restart_comparator_notices_the_field(self) -> None:
        """Changing only this setting marks a running sandbox as stale."""
        blocking = SandboxConfig(block_telemetry=True)
        permissive = SandboxConfig(block_telemetry=False)

        assert _SandboxSettingsProbe.configs_match(blocking, SandboxConfig(block_telemetry=True)) is True, (
            "two identical configurations were reported as different, so every Apply would tear down a healthy sandbox"
        )
        assert _SandboxSettingsProbe.configs_match(blocking, permissive) is False, (
            "toggling telemetry blocking leaves the running sandbox in place, so the new setting never takes effect"
        )


@pytest.mark.integration
@pytest.mark.spawns_process
class TestTheWindowsBackendAppliesIt:
    """``WindowsSandbox`` has to build, dispatch and honour the blocking step."""

    def test_a_configured_sandbox_sinkholes_the_guest(self, tmp_path: Path) -> None:
        """The backend's own command, executed for real, blocks every endpoint.

        Args:
            tmp_path: Pytest temporary directory holding the redirected ``SystemRoot``.
        """
        system_root = _prepare_system_root(tmp_path, _GUEST_OWNED_LINES)
        sandbox = _RedirectedTelemetrySandbox(SandboxConfig(block_telemetry=True), system_root)

        sandbox.apply_blocking()

        assert len(sandbox.commands) == 1, f"the backend dispatched {len(sandbox.commands)} commands instead of one blocking run"
        lines = _hosts_lines(system_root)
        missing = [hostname for hostname in TELEMETRY_HOSTS if lines.count(_sinkhole_line(hostname)) != 1]
        assert not missing, f"starting a sandbox with the box ticked left these endpoints reachable: {missing}"
        for owned in _GUEST_OWNED_LINES:
            assert owned in lines, f"the backend's run destroyed the guest's own hosts entry {owned!r}: {lines}"

    def test_an_unconfigured_sandbox_never_touches_the_guest(self, tmp_path: Path) -> None:
        """With the box unticked, no command is dispatched and the hosts file is unchanged.

        Args:
            tmp_path: Pytest temporary directory holding the redirected ``SystemRoot``.
        """
        system_root = _prepare_system_root(tmp_path, _GUEST_OWNED_LINES)
        before = _hosts_file(system_root).read_bytes()
        sandbox = _RedirectedTelemetrySandbox(SandboxConfig(block_telemetry=False), system_root)

        sandbox.apply_blocking()

        assert sandbox.commands == [], f"the backend ran a guest command despite the setting being off: {sandbox.commands}"
        assert _hosts_file(system_root).read_bytes() == before, "the guest's hosts file was modified even though telemetry blocking was off"
