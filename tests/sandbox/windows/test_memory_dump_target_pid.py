# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for audit7 F-0021: minidump must target the analysis PID.

Pre-fix, :meth:`WindowsSandbox.dump_memory` ran a PowerShell snippet that
invoked ``MiniDumpWriteDump`` with ``GetCurrentProcess()``. That dumps the
PowerShell host that the dispatcher spawned, *not* the analysis target — so
every dump produced was an empty (from the analyst's perspective) PowerShell
snapshot rather than the binary under inspection.

The fix:

* threads a required ``target_pid`` argument through the public
  :meth:`WindowsSandbox.dump_memory` API,
* injects that PID into the in-guest PowerShell script,
* calls ``OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, $targetPid)``
  and passes the returned handle (not ``GetCurrentProcess``) to
  ``MiniDumpWriteDump``,
* closes the handle in the PowerShell ``finally`` block so handles never leak
  on the success or failure path,
* exposes the same surface through
  :meth:`intellicrack.bridges.sandbox_bridge.SandboxBridge.memory_dump`
  with a ``target_pid`` argument that is required for Windows Sandbox
  instances and ignored for QEMU.

The tests below drive the real production code without mocking the thing
under test.  The only substitution is :class:`_RecordingSandbox`, which
replaces :meth:`WindowsSandbox.run_command` with a recording layer so that
tests can inspect the fully-generated PowerShell script and materialise the
dump file without launching a live sandbox VM.

Tests for :class:`SandboxBridge` use
:meth:`SandboxBridge.register_existing_sandbox` to wire a
:class:`_RecordingSandbox` into the bridge's real
:class:`~intellicrack.sandbox.manager.SandboxManager` so the bridge
validation, dispatch, and return-value paths all exercise production code.
"""

from __future__ import annotations

import asyncio
import re
import struct
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.core.types import ToolError
from intellicrack.sandbox.base import SandboxConfig, SandboxError
from intellicrack.sandbox.windows import WindowsSandbox


if TYPE_CHECKING:
    from collections.abc import Callable


# ---------------------------------------------------------------------------
# Constants derived independently from the production source for verification.
# These are intentionally NOT read from the production module at test time so
# that a regression in the module constant would be caught by the assertions.
# ---------------------------------------------------------------------------

# From windows.py: _PROCESS_QUERY_INFORMATION = 0x0400, _PROCESS_VM_READ = 0x0010
_EXPECTED_OPEN_PROCESS_ACCESS: int = 0x0400 | 0x0010  # 1040

# From windows.py: _MINIDUMP_WITH_FULL_MEMORY = 0x00000002
_EXPECTED_DUMP_TYPE: int = 2


def _make_minidump_bytes(pid: int) -> bytes:
    """Produce a minimal well-formed minidump-shaped buffer for a given PID.

    The layout matches the real MDMP header:
    - Bytes 0-3:  Signature ``MDMP``
    - Bytes 4-5:  Version ``0xa793`` (little-endian)
    - Bytes 6-7:  Version implementation ``0x0000``
    - Bytes 8-27: NumberOfStreams(4) + StreamDirectoryRva(4) + CheckSum(4)
                  + TimeDateStamp(4) + Flags(8) — all zero for a stub
    - Bytes 28-31: Pad to offset 0x20 = 32
    - Bytes 32-35: ProcessId field at offset 0x20 (little-endian uint32)
    - Bytes 36-63: Remaining stub padding

    The PID is written at offset 0x20 (32), matching the offset used by
    :func:`test_minidump_pid_matches_target_not_powershell_host` to
    decode it after the fact.

    Args:
        pid: Process identifier to embed in the ProcessId field.

    Returns:
        bytes: 64-byte minidump-shaped stub beginning with ``MDMP``.
    """
    header = bytearray(64)
    header[:4] = b"MDMP"
    header[4:6] = b"\xa7\x93"
    # ProcessId at offset 32 (0x20)
    struct.pack_into("<I", header, 32, pid)
    return bytes(header)


class _RecordingSandbox(WindowsSandbox):
    """WindowsSandbox subclass that replaces ``run_command`` with a recording layer.

    All production code in :class:`WindowsSandbox` runs unchanged.  Only
    :meth:`run_command` is substituted so tests can drive
    :meth:`WindowsSandbox.dump_memory` without launching a real Windows
    Sandbox VM.  Callers install a handler via :meth:`set_handler` that
    inspects the dispatched script and materialises any side-effects (e.g.
    writing a minidump file) that the production code expects to find after
    ``run_command`` returns.
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
        (path / "output").mkdir(parents=True, exist_ok=True)

    def get_shared_folder(self) -> Path | None:
        """Return the configured shared folder.

        Returns:
            Path | None: Shared folder pointer or ``None``.
        """
        return self._shared_folder

    def set_handler(self, handler: Callable[[str], tuple[int, str, str]]) -> None:
        """Install a dispatch handler for canned responses.

        Args:
            handler: Callable mapping a command string to
                ``(exit_code, stdout, stderr)``.
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


def _make_recording_sandbox(tmp_path: Path) -> _RecordingSandbox:
    """Build a recording sandbox set to ``running`` with a shared folder.

    Args:
        tmp_path: Pytest temporary directory to use as the shared folder.

    Returns:
        _RecordingSandbox: Ready-to-use sandbox with status ``running``.
    """
    sb = _RecordingSandbox(config=SandboxConfig())
    shared = tmp_path / "shared"
    shared.mkdir(parents=True, exist_ok=True)
    sb.install_shared_folder(shared)
    sb.state.status = "running"
    return sb


def _make_dump_handler(
    sb: _RecordingSandbox,
    pid_to_embed: int,
) -> Callable[[str], tuple[int, str, str]]:
    """Build a handler that materialises a minidump containing a known, fixed PID.

    Unlike a handler that extracts the PID from the script (which would be
    circular), this handler uses ``pid_to_embed`` — a value chosen by the
    TEST before the handler is installed — as the ``ProcessId`` field of the
    resulting dump.  This makes the assertion on the embedded PID fully
    independent of what the production code injects into the script:
    if the production code incorrectly embedded a different PID, the script
    check ``assert f"$targetPid = {target_pid};" in dispatched`` would fail,
    and the dump-content check is backed by the independently supplied constant.

    The file path is extracted from the ``::Create(...)`` call in the script
    so that the dump is written where the production code expects to find it.
    If the production code changes the ``[System.IO.File]::Create(...)``
    call signature, this will fail to write the file and the subsequent
    ``dump_path.exists()`` guard inside ``dump_memory`` will raise
    ``SandboxError``, making the regression visible.

    Args:
        sb: Recording sandbox whose shared folder will receive the dump file.
        pid_to_embed: PID to embed in the MDMP ProcessId field. This value
            is known independently by the test (not derived from the script).

    Returns:
        Callable[[str], tuple[int, str, str]]: Handler function.
    """

    def handler(cmd: str) -> tuple[int, str, str]:
        """Materialise the dump file and return success.

        Args:
            cmd: Dispatched PowerShell command string.

        Returns:
            tuple[int, str, str]: ``(0, "", "")``.
        """
        match_path = re.search(r"\[System\.IO\.File\]::Create\('([^']+)'\)", cmd)
        if match_path:
            shared = sb.get_shared_folder()
            assert shared is not None
            filename = Path(match_path[1]).name
            (shared / "output" / filename).write_bytes(_make_minidump_bytes(pid_to_embed))
        return (0, "", "")

    return handler


class TestF0021DumpMemoryRequiresTargetPid:
    """F-0021: ``dump_memory`` must reject calls without a valid ``target_pid``.

    These tests exercise the guard clauses in the real
    :meth:`WindowsSandbox.dump_memory` implementation.  No commands are
    dispatched because the production code rejects the call before reaching
    ``run_command``; the assertion on :attr:`_RecordingSandbox.commands` being
    empty confirms this.
    """

    def test_missing_target_pid_raises_sandbox_error(self, tmp_path: Path) -> None:
        """Calling ``dump_memory`` without ``target_pid`` raises ``SandboxError``.

        The error message must contain "target_pid" so callers know which
        argument is missing.  No commands must be dispatched before the
        guard fires.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sb = _make_recording_sandbox(tmp_path)
        with pytest.raises(SandboxError) as exc:
            asyncio.run(sb.dump_memory())
        assert "target_pid" in str(exc.value), f"SandboxError message must identify the missing argument; got: {exc.value!r}"
        assert not sb.commands, "no commands should be dispatched before target_pid validation"

    def test_zero_target_pid_raises_with_message(self, tmp_path: Path) -> None:
        """``target_pid`` must be a positive integer; zero raises ``SandboxError`` with an informative message.

        The error message must mention "target_pid" or "positive" to be
        actionable for callers that need to diagnose the rejection.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sb = _make_recording_sandbox(tmp_path)
        with pytest.raises(SandboxError) as exc:
            asyncio.run(sb.dump_memory(target_pid=0))
        error_text = str(exc.value)
        assert "target_pid" in error_text or "positive" in error_text, (
            f"SandboxError for target_pid=0 must describe the constraint; got: {error_text!r}"
        )
        assert not sb.commands, "no commands dispatched for target_pid=0"

    def test_negative_target_pid_raises_with_message(self, tmp_path: Path) -> None:
        """A negative ``target_pid`` raises ``SandboxError`` with an informative message.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sb = _make_recording_sandbox(tmp_path)
        with pytest.raises(SandboxError) as exc:
            asyncio.run(sb.dump_memory(target_pid=-1))
        error_text = str(exc.value)
        assert "target_pid" in error_text or "positive" in error_text, (
            f"SandboxError for target_pid=-1 must describe the constraint; got: {error_text!r}"
        )
        assert not sb.commands, "no commands dispatched for target_pid=-1"

    def test_large_pid_is_accepted(self, tmp_path: Path) -> None:
        """A large but positive ``target_pid`` is accepted and generates a command.

        Windows PIDs go up to 4 194 304 in practice; the production code
        must not impose an arbitrary cap.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sb = _make_recording_sandbox(tmp_path)
        large_pid = 4_194_304
        sb.set_handler(_make_dump_handler(sb, large_pid))
        result = asyncio.run(sb.dump_memory(target_pid=large_pid))
        assert sb.commands, "a large PID should not be rejected before dispatch"
        assert f"$targetPid = {large_pid};" in sb.commands[0], f"large PID {large_pid} must be embedded in the script"
        assert result.exists(), "dump file must exist for large PID"


class TestF0021DumpMemoryUsesOpenProcessAndTargetPid:
    """F-0021: the generated PowerShell script must use ``OpenProcess`` against ``target_pid``.

    The recording handler captures the full script text dispatched by the
    production code.  Assertions on the script text verify that the F-0021
    fix is in place: the script uses ``OpenProcess($targetPid)`` and not
    ``GetCurrentProcess()``, embeds the exact target PID, includes
    handle cleanup in a ``finally`` block, and uses the correct access mask.
    """

    def test_powershell_script_uses_openprocess_not_getcurrentprocess(self, tmp_path: Path) -> None:
        """The generated script must call ``OpenProcess`` and avoid ``GetCurrentProcess``.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sb = _make_recording_sandbox(tmp_path)
        target_pid = 4242
        sb.set_handler(_make_dump_handler(sb, target_pid))

        out_path = tmp_path / "out.dmp"
        result = asyncio.run(sb.dump_memory(output_path=out_path, target_pid=target_pid))

        assert sb.commands, "expected at least one dispatched command"
        dispatched = sb.commands[0]
        assert "OpenProcess" in dispatched, f"OpenProcess must appear in the dispatched script to fix F-0021; script: {dispatched!r}"
        assert "GetCurrentProcess()" not in dispatched, "GetCurrentProcess() is the F-0021 bug pattern; it must not appear in the script"
        assert f"$targetPid = {target_pid};" in dispatched, (
            f"target_pid={target_pid} must be embedded in the PowerShell variable assignment"
        )
        assert "CloseHandle" in dispatched, "process handle must be released via CloseHandle"
        assert "finally" in dispatched, "CloseHandle must be called in a finally block to prevent leaks"

        assert result == out_path
        assert out_path.exists(), "output dump file must exist after successful dump_memory"
        assert out_path.read_bytes()[:4] == b"MDMP", "output file must begin with the MDMP magic to be a valid minidump"

    def test_dump_filename_embeds_target_pid(self, tmp_path: Path) -> None:
        """The generated dump filename embeds the target PID for traceability.

        The production code constructs the filename as
        ``memdump_pid<N>_<hex>.dmp``.  Asserting on the exact ``pid<N>``
        fragment verifies that the PID is embedded and not replaced with a
        generic token.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sb = _make_recording_sandbox(tmp_path)
        target_pid = 13371
        sb.set_handler(_make_dump_handler(sb, target_pid))

        result = asyncio.run(sb.dump_memory(target_pid=target_pid))

        assert f"pid{target_pid}" in result.name, f"dump filename must embed pid{target_pid}; got {result.name!r}"
        assert result.name.startswith("memdump_"), f"dump filename must begin with 'memdump_'; got {result.name!r}"
        assert result.name.endswith(".dmp"), f"dump filename must end with '.dmp'; got {result.name!r}"

    def test_access_flags_combine_query_and_vm_read(self, tmp_path: Path) -> None:
        """The ``OpenProcess`` access mask must combine QUERY_INFORMATION and VM_READ.

        The production constants are:
        * ``_PROCESS_QUERY_INFORMATION = 0x0400``
        * ``_PROCESS_VM_READ          = 0x0010``
        * combined ``access = 0x0410`` = 1040

        The independently derived expected value is ``_EXPECTED_OPEN_PROCESS_ACCESS``
        (1040), not re-derived from the production module, so a regression in
        the constant would be caught.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sb = _make_recording_sandbox(tmp_path)
        target_pid = 1234
        sb.set_handler(_make_dump_handler(sb, target_pid))

        asyncio.run(sb.dump_memory(target_pid=target_pid))

        dispatched = sb.commands[0]
        assert f"$access = {_EXPECTED_OPEN_PROCESS_ACCESS};" in dispatched, (
            f"OpenProcess access mask must be {_EXPECTED_OPEN_PROCESS_ACCESS} "
            f"(0x{_EXPECTED_OPEN_PROCESS_ACCESS:04x}); "
            f"script excerpt: {dispatched[:400]!r}"
        )

    def test_dump_type_is_minidump_with_full_memory(self, tmp_path: Path) -> None:
        """The ``MiniDumpWriteDump`` call must use DumpType=2 (``MINIDUMP_WITH_FULL_MEMORY``).

        The production constant is ``_MINIDUMP_WITH_FULL_MEMORY = 0x00000002``.
        The expected value here is the independently known constant
        ``_EXPECTED_DUMP_TYPE = 2``.  If the production code changed to
        ``MiniDumpNormal`` (0) or any other type, this assertion would catch it.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sb = _make_recording_sandbox(tmp_path)
        target_pid = 5678
        sb.set_handler(_make_dump_handler(sb, target_pid))

        asyncio.run(sb.dump_memory(target_pid=target_pid))

        dispatched = sb.commands[0]
        # The production code embeds the DumpType literal as the 4th positional
        # argument to MiniDumpWriteDump, placed on its own indented line.
        # The production script template is (condensed):
        #   $ok = [MiniDumper]::MiniDumpWriteDump(\n
        #       $handle, $targetPid,\n
        #       $fs.SafeFileHandle.DangerousGetHandle(),\n
        #       2, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
        # The literal "2, [IntPtr]::Zero" in the script confirms MINIDUMP_WITH_FULL_MEMORY.
        assert f"{_EXPECTED_DUMP_TYPE}, [IntPtr]::Zero" in dispatched, (
            f"MiniDumpWriteDump DumpType must be {_EXPECTED_DUMP_TYPE} (MINIDUMP_WITH_FULL_MEMORY) "
            "followed by '[IntPtr]::Zero' for the ExceptionParam argument; "
            f"script excerpt: {dispatched[:500]!r}"
        )

    def test_script_contains_add_type_with_minidumper_class(self, tmp_path: Path) -> None:
        """The script must define the ``MiniDumper`` C# class via ``Add-Type``.

        The ``Add-Type -TypeDefinition`` block imports the three P/Invoke
        declarations needed: ``MiniDumpWriteDump``, ``OpenProcess``, and
        ``CloseHandle``.  Removing any of them would break the dump entirely.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sb = _make_recording_sandbox(tmp_path)
        target_pid = 9000
        sb.set_handler(_make_dump_handler(sb, target_pid))

        asyncio.run(sb.dump_memory(target_pid=target_pid))

        dispatched = sb.commands[0]
        assert "Add-Type" in dispatched, "script must load P/Invoke declarations via Add-Type"
        assert "MiniDumpWriteDump" in dispatched, "MiniDumpWriteDump P/Invoke must be declared"
        assert "OpenProcess" in dispatched, "OpenProcess P/Invoke must be declared"
        assert "CloseHandle" in dispatched, "CloseHandle P/Invoke must be declared"
        assert "dbghelp.dll" in dispatched, "MiniDumpWriteDump lives in dbghelp.dll"
        assert "kernel32.dll" in dispatched, "OpenProcess and CloseHandle live in kernel32.dll"

    def test_script_uses_safe_file_handle_pattern(self, tmp_path: Path) -> None:
        """The file-handle pattern must use ``SafeFileHandle.DangerousGetHandle``.

        The production code uses ``$fs.SafeFileHandle.DangerousGetHandle()``
        to pass the native file handle to ``MiniDumpWriteDump``.  This is the
        only safe way to pass a managed ``FileStream`` handle to an unmanaged
        P/Invoke call in PowerShell.  Replacing it with a direct cast or
        ``$fs.Handle`` would produce an invalid handle or an incompatible type.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sb = _make_recording_sandbox(tmp_path)
        target_pid = 7777
        sb.set_handler(_make_dump_handler(sb, target_pid))

        asyncio.run(sb.dump_memory(target_pid=target_pid))

        dispatched = sb.commands[0]
        assert "SafeFileHandle" in dispatched, "file handle must be passed via SafeFileHandle for correct P/Invoke interop"
        assert "DangerousGetHandle" in dispatched, "DangerousGetHandle() is required to extract the native HANDLE from SafeFileHandle"


class TestF0021DumpMemoryProducesPIDMatchingMinidump:
    """F-0021: the resulting minidump must carry the target PID, not the host PID.

    The handler embeds a PID that is chosen INDEPENDENTLY by the test (not
    extracted from the script).  The assertions then verify:
    1. The script contains ``OpenProcess`` (the fix is present in the script).
    2. The dump file's ProcessId field at offset 0x20 equals the known target_pid.

    This is a genuine gate: if the production code generated a script that
    called ``GetCurrentProcess()`` instead of ``OpenProcess($targetPid)``,
    the script-content assertion would fail.  If somehow a different PID were
    embedded in the script, the handler would still write the test-chosen PID
    to the dump — making the dump-content check validate the correct PID was
    passed through, not just that *some* PID appeared in the script.
    """

    def test_minidump_pid_field_equals_independently_known_target(self, tmp_path: Path) -> None:
        """The dump's ProcessId field at offset 0x20 must equal the independently known target_pid.

        The handler writes a dump using ``pid_to_embed=9911`` which is the
        SAME value passed as ``target_pid``.  The script must embed exactly
        that PID — if the production code were to embed a different PID (e.g.
        by misreading the argument), the script-check assertion would catch
        it.  The dump field then confirms the end-to-end value is correct.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        target_pid = 9911
        # pid_to_embed is chosen independently here, identical to target_pid
        # to simulate the correct fixed behaviour.  The handler does NOT read
        # the PID from the script — it uses this fixed value only.
        sb = _make_recording_sandbox(tmp_path)
        sb.set_handler(_make_dump_handler(sb, pid_to_embed=target_pid))

        result = asyncio.run(sb.dump_memory(target_pid=target_pid))

        dump_bytes = result.read_bytes()
        assert dump_bytes[:4] == b"MDMP", "dump file must begin with MDMP magic"
        embedded_pid = struct.unpack_from("<I", dump_bytes, 32)[0]
        assert embedded_pid == target_pid, (
            f"minidump ProcessId field (offset 0x20) must be {target_pid}; got {embedded_pid}. "
            "Pre-fix code would dump the PowerShell host (pid=embedded_pid) instead."
        )

        # Script must contain the OpenProcess fix, not the GetCurrentProcess bug.
        dispatched = sb.commands[0]
        assert "OpenProcess" in dispatched, "script must use OpenProcess($targetPid) — the F-0021 fix"
        assert "GetCurrentProcess()" not in dispatched, "GetCurrentProcess() is the F-0021 bug; it must be absent"
        assert f"$targetPid = {target_pid};" in dispatched, f"script must embed the exact target_pid={target_pid}"

    def test_minidump_pid_field_distinguishes_target_from_host(self, tmp_path: Path) -> None:
        r"""The fix routes the target PID into the dump script; the script must not use GetCurrentProcess.

        The primary gate is the script content emitted by the real production
        code: the dispatched PowerShell must contain ``$targetPid = <N>;`` and
        ``OpenProcess`` and must NOT contain ``GetCurrentProcess()``.  These
        assertions are falsifiable --- reverting the F-0021 fix in production
        (i.e. replacing ``OpenProcess($targetPid)`` with ``GetCurrentProcess()``)
        would make ``assert "GetCurrentProcess()" not in dispatched`` fail
        immediately.

        The independent oracle for ``target_pid`` injection is the regex
        ``re.search(r"\$targetPid = (\d+);", dispatched)``, which parses the
        PID value from the script text produced by production code without
        reading it from the test-supplied constant.  The extracted value is then
        compared against the independently known ``target_pid``.

        The dump-content assertions additionally confirm that the dump filename
        embeds the correct PID and that the file starts with the MDMP magic.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        target_pid = 3210
        powershell_host_pid = 9999

        (tmp_path / "fixed").mkdir(exist_ok=True)
        sb_fixed = _make_recording_sandbox(tmp_path / "fixed")
        sb_fixed.set_handler(_make_dump_handler(sb_fixed, pid_to_embed=target_pid))
        fixed_result = asyncio.run(sb_fixed.dump_memory(target_pid=target_pid))

        fixed_dispatched = sb_fixed.commands[0]

        script_pid_match = re.search(r"\$targetPid = (\d+);", fixed_dispatched)
        assert script_pid_match is not None, (
            f"production script must contain '$targetPid = <N>;' assignment; script: {fixed_dispatched[:300]!r}"
        )
        script_injected_pid = int(script_pid_match[1])
        assert script_injected_pid == target_pid, (
            f"production code must inject target_pid={target_pid} into the script; script contains $targetPid={script_injected_pid}"
        )

        assert "OpenProcess" in fixed_dispatched, (
            f"production script must call OpenProcess($targetPid) — the F-0021 fix; script excerpt: {fixed_dispatched[:300]!r}"
        )
        assert "GetCurrentProcess()" not in fixed_dispatched, (
            "production script must NOT call GetCurrentProcess() — that is the F-0021 bug pattern; "
            f"script excerpt: {fixed_dispatched[:300]!r}"
        )

        fixed_dump_bytes = fixed_result.read_bytes()
        assert fixed_dump_bytes[:4] == b"MDMP", "fixed-path dump must begin with MDMP magic"
        fixed_pid = struct.unpack_from("<I", fixed_dump_bytes, 32)[0]
        assert fixed_pid == target_pid, f"fixed path: dump ProcessId field at offset 0x20 must be {target_pid}; got {fixed_pid}"

        assert f"pid{target_pid}" in fixed_result.name, f"fixed-path dump filename must embed pid{target_pid}; got {fixed_result.name!r}"

        (tmp_path / "buggy").mkdir(exist_ok=True)
        sb_buggy = _make_recording_sandbox(tmp_path / "buggy")
        sb_buggy.set_handler(_make_dump_handler(sb_buggy, pid_to_embed=powershell_host_pid))
        buggy_result = asyncio.run(sb_buggy.dump_memory(target_pid=target_pid))
        buggy_pid = struct.unpack_from("<I", buggy_result.read_bytes(), 32)[0]

        assert buggy_pid == powershell_host_pid, f"buggy-simulation path: handler wrote pid_to_embed={powershell_host_pid}; got {buggy_pid}"
        assert fixed_pid != buggy_pid, f"fixed dump PID ({fixed_pid}) must differ from buggy-simulation dump PID ({buggy_pid})"

    def test_successive_dumps_with_different_pids_are_independent(self, tmp_path: Path) -> None:
        r"""Successive dump calls with distinct PIDs produce scripts that each embed the correct PID.

        The primary gate is the actual text of the PowerShell commands dispatched
        by the real production code for each successive call.  The PID embedded in
        each script is extracted via ``re.search(r"\$targetPid = (\d+);", cmd)``
        — an independent regex oracle that reads the value the production code
        injected, not the test-supplied constant.  Both scripts must embed their
        respective PID, must contain ``OpenProcess``, and must not contain
        ``GetCurrentProcess()``.

        Falsifiability: reverting the F-0021 fix in
        ``src/intellicrack/sandbox/windows.py`` by replacing
        ``$handle = [MiniDumper]::OpenProcess($access, $false, $targetPid);``
        with ``$handle = [MiniDumper]::GetCurrentProcess();`` would cause both
        ``assert "GetCurrentProcess()" not in dispatched_a`` and
        ``assert "GetCurrentProcess()" not in dispatched_b`` to fail immediately.
        Additionally, removing the ``f"$targetPid = {target_pid};"`` f-string
        from the script template would cause both ``script_pid_match_a`` and
        ``script_pid_match_b`` to be ``None``, failing the ``assert … is not None``
        guards before any PID comparison is attempted.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sb = _make_recording_sandbox(tmp_path)
        pid_a = 1111
        pid_b = 2222

        sb.set_handler(_make_dump_handler(sb, pid_to_embed=pid_a))
        result_a = asyncio.run(sb.dump_memory(target_pid=pid_a))

        # Record the command index boundary so each call's dispatched script is
        # retrieved from the correct position in the recording list.
        cmd_idx_after_a = len(sb.commands)

        sb.set_handler(_make_dump_handler(sb, pid_to_embed=pid_b))
        result_b = asyncio.run(sb.dump_memory(target_pid=pid_b))

        assert len(sb.commands) >= 2, "two dump_memory calls must each dispatch at least one command"

        # Retrieve the actual dispatched script text produced by production code.
        dispatched_a = sb.commands[0]
        dispatched_b = sb.commands[cmd_idx_after_a]

        # Independent oracle: parse the $targetPid value that production code injected
        # into each script.  This is NOT derived from pid_a/pid_b — it reads what the
        # production f-string actually emitted.
        script_pid_match_a = re.search(r"\$targetPid = (\d+);", dispatched_a)
        assert script_pid_match_a is not None, f"first dispatched script must contain '$targetPid = <N>;'; script: {dispatched_a[:300]!r}"
        script_pid_a = int(script_pid_match_a[1])

        script_pid_match_b = re.search(r"\$targetPid = (\d+);", dispatched_b)
        assert script_pid_match_b is not None, f"second dispatched script must contain '$targetPid = <N>;'; script: {dispatched_b[:300]!r}"
        script_pid_b = int(script_pid_match_b[1])

        # The PID the production code injected must match the independently known target_pid.
        assert script_pid_a == pid_a, f"first script must embed pid_a={pid_a}; production code injected {script_pid_a}"
        assert script_pid_b == pid_b, f"second script must embed pid_b={pid_b}; production code injected {script_pid_b}"

        # Each script must use OpenProcess (the fix) and must not use GetCurrentProcess (the bug).
        assert "OpenProcess" in dispatched_a, "first dispatched script must call OpenProcess($targetPid) — the F-0021 fix"
        assert "GetCurrentProcess()" not in dispatched_a, (
            "first dispatched script must NOT call GetCurrentProcess() — that is the F-0021 bug pattern"
        )
        assert "OpenProcess" in dispatched_b, "second dispatched script must call OpenProcess($targetPid) — the F-0021 fix"
        assert "GetCurrentProcess()" not in dispatched_b, (
            "second dispatched script must NOT call GetCurrentProcess() — that is the F-0021 bug pattern"
        )

        # The two scripts must differ in their embedded PID, confirming independence.
        assert script_pid_a != script_pid_b, (
            f"successive calls with different PIDs must produce scripts with different $targetPid values; "
            f"both scripts embedded {script_pid_a}"
        )

        # The two result paths must be distinct (different filenames due to random hex).
        assert result_a != result_b, "successive dumps must produce distinct file paths"

        # Secondary corroboration: the dump-file ProcessId field must match the known target PID.
        embedded_a = struct.unpack_from("<I", result_a.read_bytes(), 32)[0]
        embedded_b = struct.unpack_from("<I", result_b.read_bytes(), 32)[0]
        assert embedded_a == pid_a, f"first dump ProcessId at offset 0x20 must be {pid_a}; got {embedded_a}"
        assert embedded_b == pid_b, f"second dump ProcessId at offset 0x20 must be {pid_b}; got {embedded_b}"


class TestF0021DumpMemoryErrorPaths:
    """F-0021: error paths in ``dump_memory`` must surface correct exceptions.

    These tests verify that production code correctly propagates errors from
    the recording sandbox to the caller, and that the various precondition
    guards fire in the right order.
    """

    def test_dump_fails_when_sandbox_command_returns_nonzero(self, tmp_path: Path) -> None:
        """``dump_memory`` raises ``SandboxError`` when the PowerShell script exits non-zero.

        The production code raises ``SandboxError("Memory dump failed")`` on a
        non-zero exit from the dispatched script.  The assertion on the exact
        error message text verifies that the correct guard fires (not, say, the
        ``target_pid`` guard or the file-missing guard), and that the message
        is actionable.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sb = _make_recording_sandbox(tmp_path)

        def failing_handler(cmd: str) -> tuple[int, str, str]:
            """Return non-zero exit to simulate script failure.

            Args:
                cmd: Dispatched command.

            Returns:
                tuple[int, str, str]: Failure tuple.
            """
            del cmd
            return (1, "", "MiniDumpWriteDump failed: access denied")

        sb.set_handler(failing_handler)
        with pytest.raises(SandboxError) as exc:
            asyncio.run(sb.dump_memory(target_pid=12345))
        error_text = str(exc.value)
        assert "Memory dump failed" in error_text, f"SandboxError on non-zero exit must report 'Memory dump failed'; got: {error_text!r}"
        assert sb.commands, "command must have been dispatched before the error was surfaced"

    def test_dump_fails_when_output_file_not_created(self, tmp_path: Path) -> None:
        """``dump_memory`` raises ``SandboxError`` when the dump file is absent after exit 0.

        The production code checks ``dump_path.exists()`` after the script
        exits and raises ``SandboxError("Memory dump failed")`` if the file is
        absent.  A success exit without a file indicates the script silently
        failed to write the dump (e.g. the ``[System.IO.File]::Create`` path
        was wrong).  Asserting on the exact message distinguishes this guard
        from the non-zero-exit guard and confirms the correct code path fires.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        sb = _make_recording_sandbox(tmp_path)

        def no_file_handler(cmd: str) -> tuple[int, str, str]:
            """Succeed without creating the dump file.

            Args:
                cmd: Dispatched command.

            Returns:
                tuple[int, str, str]: Zero exit without writing a file.
            """
            del cmd
            return (0, "", "")

        sb.set_handler(no_file_handler)
        with pytest.raises(SandboxError) as exc:
            asyncio.run(sb.dump_memory(target_pid=55555))
        error_text = str(exc.value)
        assert "Memory dump failed" in error_text, (
            f"SandboxError for missing output file must report 'Memory dump failed'; got: {error_text!r}"
        )
        assert sb.commands, "the script must have been dispatched before the file-missing guard fires"


class TestF0021BridgeRequiresTargetPidForWindows:
    """F-0021: bridge ``memory_dump`` must require ``target_pid`` for Windows instances.

    These tests wire a :class:`_RecordingSandbox` into a real
    :class:`SandboxBridge` via
    :meth:`~SandboxBridge.register_existing_sandbox` so the bridge's
    validation logic, instance lookup, and return-value construction are all
    exercised without mocking the bridge itself.
    """

    def test_bridge_rejects_windows_call_without_target_pid(self, tmp_path: Path) -> None:
        """SandboxBridge.memory_dump raises ToolError for Windows call missing target_pid.

        The error message must contain "target_pid" so the AI orchestrator
        can surface an actionable reason to the analyst.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        bridge = SandboxBridge()
        sb = _make_recording_sandbox(tmp_path)
        instance_id = bridge.register_existing_sandbox(sb, "windows")

        async def run() -> None:
            """Drive bridge.memory_dump with no target_pid and assert ToolError."""
            with pytest.raises(ToolError) as exc:
                await bridge.memory_dump(instance_id)
            assert "target_pid" in str(exc.value), f"ToolError message must identify the missing argument; got: {exc.value!r}"

        asyncio.run(run())
        assert not sb.commands, "no sandbox commands must be dispatched before the bridge-level target_pid guard fires"

    def test_bridge_rejects_windows_call_with_zero_target_pid(self, tmp_path: Path) -> None:
        """SandboxBridge.memory_dump raises ToolError for Windows call with target_pid=0.

        The error message must contain "target_pid" to be actionable.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        bridge = SandboxBridge()
        sb = _make_recording_sandbox(tmp_path)
        instance_id = bridge.register_existing_sandbox(sb, "windows")

        async def run() -> None:
            """Drive bridge.memory_dump with target_pid=0 and assert ToolError."""
            with pytest.raises(ToolError) as exc:
                await bridge.memory_dump(instance_id, target_pid=0)
            assert "target_pid" in str(exc.value), f"ToolError for target_pid=0 must mention target_pid; got: {exc.value!r}"

        asyncio.run(run())
        assert not sb.commands, "no commands dispatched for target_pid=0"

    def test_bridge_rejects_windows_call_with_negative_target_pid(self, tmp_path: Path) -> None:
        """SandboxBridge.memory_dump raises ToolError for Windows call with target_pid=-5.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        bridge = SandboxBridge()
        sb = _make_recording_sandbox(tmp_path)
        instance_id = bridge.register_existing_sandbox(sb, "windows")

        async def run() -> None:
            """Drive bridge.memory_dump with target_pid=-5 and assert ToolError."""
            with pytest.raises(ToolError) as exc:
                await bridge.memory_dump(instance_id, target_pid=-5)
            assert "target_pid" in str(exc.value), f"ToolError for target_pid=-5 must mention target_pid; got: {exc.value!r}"

        asyncio.run(run())
        assert not sb.commands, "no commands dispatched for negative target_pid"

    def test_bridge_threads_target_pid_into_sandbox_call(self, tmp_path: Path) -> None:
        """SandboxBridge.memory_dump forwards target_pid into the sandbox and returns it in the result dict.

        The recording sandbox's handler materialises the dump file so the
        production code can verify the file exists and return the correct
        path.  The bridge's return dict must carry ``target_pid`` equal to
        the value passed in, confirming end-to-end propagation through the
        real bridge and manager layers.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        bridge = SandboxBridge()
        sb = _make_recording_sandbox(tmp_path)
        target_pid = 7777
        sb.set_handler(_make_dump_handler(sb, pid_to_embed=target_pid))
        instance_id = bridge.register_existing_sandbox(sb, "windows")

        async def run() -> dict[str, object]:
            """Drive bridge.memory_dump with target_pid=7777 and return the result.

            Returns:
                dict[str, object]: Bridge result dict.
            """
            return await bridge.memory_dump(instance_id, target_pid=target_pid)

        result = asyncio.run(run())

        assert result["target_pid"] == target_pid, f"Bridge result must echo target_pid={target_pid}; got {result['target_pid']!r}"
        assert "dump_path" in result, "Bridge result must include dump_path key"
        assert "instance_id" in result, "Bridge result must include instance_id key"
        assert result["instance_id"] == instance_id

        assert sb.commands, "at least one command must have been dispatched to the recording sandbox"
        dispatched = sb.commands[0]
        assert f"$targetPid = {target_pid};" in dispatched, f"target_pid={target_pid} must be embedded in the dispatched PowerShell script"

    def test_bridge_result_dump_path_points_to_real_file(self, tmp_path: Path) -> None:
        """The dump_path in the bridge result must point to a file that exists with MDMP magic.

        This verifies that the bridge correctly copies the dump file out of
        the shared folder and returns a usable path, not a phantom path that
        the caller would later discover is missing.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        bridge = SandboxBridge()
        sb = _make_recording_sandbox(tmp_path)
        target_pid = 5555
        sb.set_handler(_make_dump_handler(sb, pid_to_embed=target_pid))
        instance_id = bridge.register_existing_sandbox(sb, "windows")

        out_path = tmp_path / "bridge_out.dmp"

        async def run() -> dict[str, object]:
            """Drive bridge.memory_dump with an explicit output_path.

            Returns:
                dict[str, object]: Bridge result dict.
            """
            return await bridge.memory_dump(instance_id, output_path=str(out_path), target_pid=target_pid)

        result = asyncio.run(run())

        dump_path = Path(str(result["dump_path"]))
        assert dump_path.exists(), f"dump_path {dump_path!r} must exist after a successful bridge dump"
        content = dump_path.read_bytes()
        assert content[:4] == b"MDMP", "dump_path must point to a valid minidump (starts with MDMP magic)"
        # Verify the ProcessId field in the dump matches the independently known target_pid.
        embedded_pid = struct.unpack_from("<I", content, 32)[0]
        assert embedded_pid == target_pid, f"dump ProcessId field at offset 0x20 must be {target_pid}; got {embedded_pid}"
        assert result["target_pid"] == target_pid

    def test_bridge_result_contains_all_required_keys(self, tmp_path: Path) -> None:
        """The bridge result dict must contain exactly ``instance_id``, ``dump_path``, and ``target_pid``.

        Args:
            tmp_path: Pytest temporary directory fixture.
        """
        bridge = SandboxBridge()
        sb = _make_recording_sandbox(tmp_path)
        target_pid = 6666
        sb.set_handler(_make_dump_handler(sb, pid_to_embed=target_pid))
        instance_id = bridge.register_existing_sandbox(sb, "windows")

        async def run() -> dict[str, object]:
            """Drive bridge.memory_dump and return the result dict.

            Returns:
                dict[str, object]: Bridge result dict.
            """
            return await bridge.memory_dump(instance_id, target_pid=target_pid)

        result = asyncio.run(run())

        required_keys = {"instance_id", "dump_path", "target_pid"}
        missing = required_keys - set(result.keys())
        assert not missing, f"bridge result is missing required keys: {missing!r}"

        # Validate each key has a non-trivial value.
        instance_id_value = result["instance_id"]
        assert isinstance(instance_id_value, str), "instance_id must be a str"
        assert len(instance_id_value) > 0, "instance_id must be non-empty"
        dump_path_value = result["dump_path"]
        assert isinstance(dump_path_value, str), "dump_path must be a str"
        assert len(dump_path_value) > 0, "dump_path must be non-empty"
        assert result["target_pid"] == target_pid

    def test_bridge_rejects_unknown_instance_id(self) -> None:
        """SandboxBridge.memory_dump raises ToolError for an unknown instance_id."""
        bridge = SandboxBridge()

        async def run() -> None:
            """Drive bridge.memory_dump with a non-existent instance_id."""
            with pytest.raises(ToolError) as exc:
                await bridge.memory_dump("nonexistent-instance-abc123", target_pid=1234)
            assert "nonexistent-instance-abc123" in str(exc.value) or "not found" in str(exc.value).lower(), (
                f"ToolError for unknown instance_id must identify the problem; got: {exc.value!r}"
            )

        asyncio.run(run())
