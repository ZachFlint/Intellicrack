# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for S17-D10b: a live guest process picker for Memory Dump.

The Sandbox panel offered "Memory Dump" on the Windows Sandbox backend but
never supplied ``target_pid``, so ``SandboxBridge.memory_dump`` rejected every
Windows instance outright (audit7 F-0021's guard). The fix adds a real guest
process enumeration capability - :meth:`WindowsSandbox.list_processes` - that
runs ``Get-Process`` inside the guest via the dispatcher and parses the JSON
it returns with :func:`~intellicrack.sandbox.windows.parse_guest_process_list`,
so the GUI can present a picker and supply a real ``target_pid``.

Beware: a prior defect in this codebase was a UTF-8 BOM on PowerShell output
being misread (see ``_read_dispatcher_result`` and its ``_UTF8_BOM``
handling). ``parse_guest_process_list`` is tested here against a BOM-prefixed
sample - not just clean JSON - to guard against the same class of defect.

Tests for :class:`WindowsSandbox.list_processes` drive the real production
method through a ``_RecordingSandbox`` that replaces only
:meth:`WindowsSandbox.run_command`, exactly matching the pattern in
``tests/sandbox/windows/test_memory_dump_target_pid.py``, so the guard
clauses, the dispatched PowerShell script, and the parsing pipeline are all
exercised without launching a live sandbox VM.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING

import pytest

from intellicrack.sandbox.base import GuestProcessInfo, SandboxConfig, SandboxError
from intellicrack.sandbox.windows import WindowsSandbox, parse_guest_process_list


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

_BOM = "\ufeff"


class _RecordingSandbox(WindowsSandbox):
    """``WindowsSandbox`` subclass that replaces ``run_command`` with a recording layer.

    All production code in :class:`WindowsSandbox` runs unchanged; only
    :meth:`run_command` is substituted so tests can drive
    :meth:`WindowsSandbox.list_processes` without launching a real Windows
    Sandbox VM.
    """

    def __init__(self, config: SandboxConfig | None = None) -> None:
        """Initialise the recording sandbox.

        Args:
            config: Optional sandbox configuration.
        """
        super().__init__(config)
        self.commands: list[str] = []
        self._handler: Callable[[str], tuple[int, str, str]] | None = None

    def install_shared_folder(self, path: Path) -> None:
        """Pre-populate the shared folder pointer for tests.

        Args:
            path: Directory that should be treated as the shared folder root.
        """
        self._shared_folder = path

    def set_handler(self, handler: Callable[[str], tuple[int, str, str]]) -> None:
        """Install a dispatch handler for canned responses.

        Args:
            handler: Callable mapping a command string to ``(exit_code, stdout, stderr)``.
        """
        self._handler = handler

    async def run_command(
        self,
        command: str,
        time_limit: int | None = None,
        working_directory: str | None = None,
    ) -> tuple[int, str, str]:
        """Record ``command`` and dispatch to the installed handler.

        Args:
            command: Command sent to the sandbox dispatcher.
            time_limit: Ignored.
            working_directory: Ignored.

        Returns:
            tuple[int, str, str]: Canned ``(exit_code, stdout, stderr)``.
        """
        del time_limit, working_directory
        self.commands.append(command)
        return (0, "", "") if self._handler is None else self._handler(command)


def _make_recording_sandbox(tmp_path: Path, *, running: bool = True) -> _RecordingSandbox:
    """Build a recording sandbox with a shared folder, optionally already running.

    Args:
        tmp_path: Pytest temporary directory to use as the shared folder.
        running: Whether the sandbox's status is set to ``running``.

    Returns:
        _RecordingSandbox: Ready-to-use sandbox.
    """
    sb = _RecordingSandbox(config=SandboxConfig())
    sb.install_shared_folder(tmp_path)
    if running:
        sb.state.status = "running"
    return sb


class TestParseGuestProcessListHappyPath:
    """``parse_guest_process_list`` on well-formed ``Get-Process | ConvertTo-Json`` output."""

    def test_parses_a_json_array_of_processes(self) -> None:
        """A JSON array of process objects parses into matching ``GuestProcessInfo`` records."""
        payload = json.dumps(
            [
                {"Id": 4242, "ProcessName": "notepad", "Path": r"C:\Windows\notepad.exe"},
                {"Id": 8, "ProcessName": "System", "Path": None},
            ],
        )
        result = parse_guest_process_list(payload)
        assert result == [
            GuestProcessInfo(pid=4242, name="notepad", path=r"C:\Windows\notepad.exe"),
            GuestProcessInfo(pid=8, name="System", path=""),
        ]

    def test_parses_a_bare_object_when_get_process_returns_exactly_one_row(self) -> None:
        """A bare JSON object (single process, unwrapped by ``ConvertTo-Json``) still parses.

        ``ConvertTo-Json`` serialises a one-element collection as a bare
        object rather than a one-element array unless the caller forces
        array output, so the parser must accept both shapes.
        """
        payload = json.dumps({"Id": 4242, "ProcessName": "notepad", "Path": r"C:\Windows\notepad.exe"})
        result = parse_guest_process_list(payload)
        assert result == [GuestProcessInfo(pid=4242, name="notepad", path=r"C:\Windows\notepad.exe")]

    def test_empty_json_array_yields_an_empty_list(self) -> None:
        """An empty JSON array (no guest processes matched) yields an empty result."""
        assert parse_guest_process_list("[]") == []


class TestParseGuestProcessListBomHandling:
    """Regression coverage: a BOM-prefixed PowerShell stdout stream must still parse.

    A prior defect in this codebase (fixed for the dispatcher's exit-code
    file, see ``_read_dispatcher_result`` / ``_UTF8_BOM``) was a UTF-8 BOM on
    PowerShell output being misread as part of the payload. These tests
    exercise the same failure class against ``parse_guest_process_list``.
    """

    def test_bom_prefixed_array_parses_correctly(self) -> None:
        """A literal U+FEFF BOM character before a JSON array does not break parsing.

        Falsified by: removing the ``.strip(_UTF8_BOM)`` step from
        ``parse_guest_process_list`` would make ``json.loads`` receive text
        starting with U+FEFF, which raises ``json.JSONDecodeError`` (caught,
        but only because of the parser's error handling) and this test would
        then observe an empty result instead of the real records.
        """
        payload = _BOM + json.dumps([{"Id": 100, "ProcessName": "svchost", "Path": r"C:\Windows\System32\svchost.exe"}])
        result = parse_guest_process_list(payload)
        assert result == [GuestProcessInfo(pid=100, name="svchost", path=r"C:\Windows\System32\svchost.exe")]

    def test_bom_prefixed_bare_object_parses_correctly(self) -> None:
        """A BOM-prefixed bare object (single-process shape) also parses correctly."""
        payload = _BOM + json.dumps({"Id": 4242, "ProcessName": "notepad", "Path": r"C:\Windows\notepad.exe"})
        result = parse_guest_process_list(payload)
        assert result == [GuestProcessInfo(pid=4242, name="notepad", path=r"C:\Windows\notepad.exe")]

    def test_bom_with_surrounding_whitespace_parses_correctly(self) -> None:
        """A BOM plus leading/trailing whitespace (as a redirected stream might carry) still parses."""
        payload = f"  {_BOM}\r\n{json.dumps([{'Id': 7, 'ProcessName': 'svchost', 'Path': None}])}\r\n  "
        result = parse_guest_process_list(payload)
        assert result == [GuestProcessInfo(pid=7, name="svchost", path="")]

    def test_bom_only_payload_yields_an_empty_list(self) -> None:
        """A payload consisting only of a BOM (and whitespace) yields an empty list, not a parse error."""
        assert parse_guest_process_list(_BOM + "  \r\n") == []


class TestParseGuestProcessListMalformedInput:
    """``parse_guest_process_list`` must degrade to an empty list, never raise, on bad input."""

    def test_empty_string_yields_an_empty_list(self) -> None:
        """An empty string yields an empty list."""
        assert parse_guest_process_list("") == []

    def test_whitespace_only_yields_an_empty_list(self) -> None:
        """Whitespace-only text yields an empty list."""
        assert parse_guest_process_list("   \r\n\t  ") == []

    def test_invalid_json_yields_an_empty_list_not_a_raise(self) -> None:
        """Text that is not valid JSON yields an empty list instead of propagating an exception."""
        assert parse_guest_process_list("not json at all {{{") == []

    def test_scalar_json_top_level_yields_an_empty_list(self) -> None:
        """A JSON scalar (neither object nor array) at the top level yields an empty list."""
        assert parse_guest_process_list("42") == []
        assert parse_guest_process_list('"just a string"') == []

    def test_rows_missing_a_valid_id_are_dropped(self) -> None:
        """Rows with a missing, non-integer, zero, or negative ``Id`` are dropped."""
        payload = json.dumps(
            [
                {"ProcessName": "no_id_field", "Path": ""},
                {"Id": "not-an-int", "ProcessName": "string_id", "Path": ""},
                {"Id": 0, "ProcessName": "zero_id", "Path": ""},
                {"Id": -5, "ProcessName": "negative_id", "Path": ""},
                {"Id": 55, "ProcessName": "valid", "Path": ""},
            ],
        )
        result = parse_guest_process_list(payload)
        assert result == [GuestProcessInfo(pid=55, name="valid", path="")]

    def test_non_dict_array_entries_are_dropped_but_valid_ones_kept(self) -> None:
        """An array mixing non-object entries with valid ones keeps only the valid rows."""
        payload = '["not an object", 123, null, {"Id": 9, "ProcessName": "keep", "Path": ""}]'
        result = parse_guest_process_list(payload)
        assert result == [GuestProcessInfo(pid=9, name="keep", path="")]


class TestWindowsSandboxListProcesses:
    """``WindowsSandbox.list_processes`` guard clauses and dispatch, via a recording sandbox."""

    def test_raises_when_sandbox_not_running(self, tmp_path: Path) -> None:
        """Calling ``list_processes`` on a non-running sandbox raises ``SandboxError``.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sb = _make_recording_sandbox(tmp_path, running=False)
        with pytest.raises(SandboxError):
            asyncio.run(sb.list_processes())
        assert not sb.commands, "no command should be dispatched before the running-state guard fires"

    def test_raises_when_shared_folder_not_initialized(self) -> None:
        """Calling ``list_processes`` with no shared folder configured raises ``SandboxError``."""
        sb = _RecordingSandbox(config=SandboxConfig())
        sb.state.status = "running"
        with pytest.raises(SandboxError):
            asyncio.run(sb.list_processes())
        assert not sb.commands

    def test_dispatches_a_get_process_convertto_json_script(self, tmp_path: Path) -> None:
        """The dispatched PowerShell script uses ``Get-Process`` and ``ConvertTo-Json``.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sb = _make_recording_sandbox(tmp_path)

        def handler(cmd: str) -> tuple[int, str, str]:
            """Return an empty process list for any dispatched script.

            Args:
                cmd: Dispatched PowerShell command (unused; every call returns the same canned reply).

            Returns:
                tuple[int, str, str]: Empty-array success reply.
            """
            del cmd
            return (0, "[]", "")

        sb.set_handler(handler)
        asyncio.run(sb.list_processes())

        assert sb.commands, "expected at least one dispatched command"
        dispatched = sb.commands[0]
        assert "Get-Process" in dispatched
        assert "ConvertTo-Json" in dispatched

    def test_returns_the_parsed_processes_from_a_successful_command(self, tmp_path: Path) -> None:
        """A successful dispatch returns the processes ``parse_guest_process_list`` would produce.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sb = _make_recording_sandbox(tmp_path)
        canned_json = json.dumps(
            [
                {"Id": 4242, "ProcessName": "notepad", "Path": r"C:\Windows\notepad.exe"},
                {"Id": 55, "ProcessName": "svchost", "Path": None},
            ],
        )

        def handler(cmd: str) -> tuple[int, str, str]:
            """Return the canned process-list JSON.

            Args:
                cmd: Dispatched PowerShell command (unused).

            Returns:
                tuple[int, str, str]: Success reply carrying ``canned_json``.
            """
            del cmd
            return (0, canned_json, "")

        sb.set_handler(handler)
        result = asyncio.run(sb.list_processes())

        assert result == [
            GuestProcessInfo(pid=4242, name="notepad", path=r"C:\Windows\notepad.exe"),
            GuestProcessInfo(pid=55, name="svchost", path=""),
        ]

    def test_returns_the_parsed_processes_when_stdout_carries_a_bom(self, tmp_path: Path) -> None:
        """A BOM-prefixed stdout stream from the guest still yields the correct processes.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sb = _make_recording_sandbox(tmp_path)
        canned_json = _BOM + json.dumps([{"Id": 777, "ProcessName": "svchost", "Path": r"C:\Windows\System32\svchost.exe"}])

        def handler(cmd: str) -> tuple[int, str, str]:
            """Return the BOM-prefixed canned JSON.

            Args:
                cmd: Dispatched PowerShell command (unused).

            Returns:
                tuple[int, str, str]: Success reply carrying the BOM-prefixed JSON.
            """
            del cmd
            return (0, canned_json, "")

        sb.set_handler(handler)
        result = asyncio.run(sb.list_processes())

        assert result == [GuestProcessInfo(pid=777, name="svchost", path=r"C:\Windows\System32\svchost.exe")]

    def test_raises_when_the_dispatched_command_exits_non_zero(self, tmp_path: Path) -> None:
        """A non-zero exit from the dispatched script raises ``SandboxError``.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sb = _make_recording_sandbox(tmp_path)

        def failing_handler(cmd: str) -> tuple[int, str, str]:
            """Simulate a failed guest-side PowerShell invocation.

            Args:
                cmd: Dispatched PowerShell command (unused).

            Returns:
                tuple[int, str, str]: Non-zero exit tuple.
            """
            del cmd
            return (1, "", "Get-Process failed: access denied")

        sb.set_handler(failing_handler)
        with pytest.raises(SandboxError):
            asyncio.run(sb.list_processes())
        assert sb.commands, "the command must have been dispatched before the failure was surfaced"
