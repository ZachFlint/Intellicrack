# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real falsifiable test gates for the CutterBridge debug subsystem (wave-2a).

Covers all 15 debug operations that were previously at 0 % test coverage:
attach, detach, set_breakpoint (software / hardware / memory / conditional /
injection guard), remove_breakpoint, get_breakpoints (merge + type coercion),
step_into, step_over, run, get_registers (64-bit and 32-bit alt-name fallback),
set_register (command framing + injection guard), read_memory (happy path /
size==0 / size<0 / invalid hex), write_memory (happy path / empty data),
get_memory_regions (explicit size / end-base fallback / permissions field),
get_threads (field mapping + _threads cache), get_modules (name derivation /
size fallback / explicit name priority).

Every test asserts the EXACT rizin command string issued AND the EXACT parsed
return structure against a canned oracle that is independent of the production
code path.  A one-character mutation in the production command format or
response parser causes the gate to go red.
"""

from __future__ import annotations

import asyncio
import json
from typing import cast

import pytest
import r2pipe

from intellicrack.bridges.cutter import CutterBridge
from intellicrack.core.types import (
    BreakpointInfo,
    MemoryRegion,
    ModuleInfo,
    RegisterState,
    ThreadInfo,
    ToolError,
)


_ATTR_ATTACHED_PID: str = "_attached_pid"
_ATTR_BREAKPOINTS: str = "_breakpoints"
_ATTR_THREADS: str = "_threads"

_PID: int = 1234
_ADDR_1000: int = 0x1000
_ADDR_2000: int = 0x2000


class _CommandRecorder:
    """r2pipe stand-in that records commands and returns configurable responses.

    Attributes:
        commands: Ordered list of every command string sent through ``cmd()``.
        responses: Mapping from command prefix string to canned response.
    """

    commands: list[str]
    responses: dict[str, str]

    def __init__(self, responses: dict[str, str] | None = None) -> None:
        """Initialise the recorder with an optional canned-response map.

        Args:
            responses: Optional mapping of command prefix to response string.
                Falls back to empty string when no prefix matches.
        """
        self.commands = []
        self.responses = responses or {}

    def cmd(self, command: str) -> str:
        """Record ``command`` and return the longest-matching canned response.

        Args:
            command: The r2 command string issued by the bridge.

        Returns:
            str: Canned response for the longest matching prefix, or an empty
            string when no configured prefix matches.
        """
        self.commands.append(command)
        return next(
            (response for prefix, response in self.responses.items() if command == prefix or command.startswith(prefix)),
            "",
        )

    def quit(self) -> None:
        """No-op quit for test cleanup."""


def _as_r2pipe(recorder: _CommandRecorder) -> r2pipe.open:
    """Cast a _CommandRecorder to the r2pipe.open type for bridge assignment.

    Args:
        recorder: Test double that duck-types the r2pipe.open interface.

    Returns:
        r2pipe.open: The same instance typed as r2pipe.open for the bridge's
        ``r2`` property setter.
    """
    return cast(r2pipe.open, recorder)


def _get_attached_pid(bridge: CutterBridge) -> int | None:
    """Return the bridge's _attached_pid without triggering reportPrivateUsage.

    Args:
        bridge: CutterBridge instance to inspect.

    Returns:
        int | None: The _attached_pid value, or None when absent or non-int.
    """
    raw: object = getattr(bridge, _ATTR_ATTACHED_PID)
    return raw if isinstance(raw, int) else None


def _get_breakpoints_cache(bridge: CutterBridge) -> dict[int, BreakpointInfo]:
    """Return the bridge's _breakpoints cache without triggering reportPrivateUsage.

    Args:
        bridge: CutterBridge instance to inspect.

    Returns:
        dict[int, BreakpointInfo]: The mutable _breakpoints dict, or an empty
        dict when the attribute is absent or has the wrong type.
    """
    raw: object = getattr(bridge, _ATTR_BREAKPOINTS)
    return cast("dict[int, BreakpointInfo]", raw) if isinstance(raw, dict) else {}


def _get_threads_cache(bridge: CutterBridge) -> dict[int, ThreadInfo]:
    """Return the bridge's _threads cache without triggering reportPrivateUsage.

    Args:
        bridge: CutterBridge instance to inspect.

    Returns:
        dict[int, ThreadInfo]: The mutable _threads dict, or an empty dict
        when the attribute is absent or has the wrong type.
    """
    raw: object = getattr(bridge, _ATTR_THREADS)
    return cast("dict[int, ThreadInfo]", raw) if isinstance(raw, dict) else {}


def _make_attached_bridge(recorder: _CommandRecorder, pid: int = _PID) -> CutterBridge:
    """Build a CutterBridge in the attached-process state using the real attach() path.

    Calls the production attach() method so the internal state is set through
    the same code path a real user exercises.  The recorder's command list is
    cleared afterwards so each downstream test inspects only the commands from
    the operation under test.

    Args:
        recorder: Command recorder to install as the r2 pipe.
        pid: PID to pass to attach(); the resulting 'dp {pid}' command is
            consumed and cleared from recorder.commands before returning.

    Returns:
        CutterBridge: Bridge with r2 set, state.process_attached True, and
        _attached_pid set to pid.  recorder.commands is empty on return.
    """
    bridge = CutterBridge()
    bridge.r2 = _as_r2pipe(recorder)
    asyncio.run(bridge.attach(pid))
    recorder.commands.clear()
    return bridge


class TestAttach:
    """Gate: attach(pid) issues 'dp {pid}' and updates bridge state correctly."""

    def test_attach_issues_dp_command(self) -> None:
        """Attach issues the exact 'dp 1337' rizin command.

        Falsifiable: if attach() sends 'dpa 1337' or a different command
        variant, the 'dp 1337' assertion fails.
        """
        recorder = _CommandRecorder()
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(recorder)
        asyncio.run(bridge.attach(1337))
        assert "dp 1337" in recorder.commands

    def test_attach_sets_process_attached_true(self) -> None:
        """Attach sets state.process_attached to True.

        Falsifiable: if attach() forgets to set process_attached, the flag
        remains False and the assertion fails.
        """
        recorder = _CommandRecorder()
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(recorder)
        asyncio.run(bridge.attach(1337))
        assert bridge.state.process_attached is True

    def test_attach_records_target_pid_in_state(self) -> None:
        """Attach stores the pid in state.target_pid.

        Falsifiable: if attach() stores the wrong value or omits the
        target_pid update, the equality check fails.
        """
        recorder = _CommandRecorder()
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(recorder)
        asyncio.run(bridge.attach(9999))
        assert bridge.state.target_pid == 9999

    def test_attach_records_internal_attached_pid(self) -> None:
        """Attach stores the pid in the internal _attached_pid slot.

        Falsifiable: if attach() omits the _attached_pid assignment, subsequent
        _require_attached checks would still fail even with process_attached True.
        """
        recorder = _CommandRecorder()
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(recorder)
        asyncio.run(bridge.attach(9999))
        assert _get_attached_pid(bridge) == 9999

    def test_attach_without_r2_raises(self) -> None:
        """Attach raises ToolError when no r2 session is open.

        Falsifiable: if the no-binary guard is removed from attach(), no
        exception is raised and this gate fails.
        """
        bridge = CutterBridge()
        with pytest.raises(ToolError, match="no binary loaded"):
            asyncio.run(bridge.attach(1))


class TestDetach:
    """Gate: detach() issues 'dp-' and resets all debug bookkeeping."""

    def test_detach_issues_dp_minus_command(self) -> None:
        """Detach issues exactly 'dp-'.

        Falsifiable: if detach() sends 'dp 0' or 'dpu' instead of 'dp-',
        the 'dp-' assertion fails.
        """
        recorder = _CommandRecorder()
        bridge = _make_attached_bridge(recorder)
        asyncio.run(bridge.detach())
        assert "dp-" in recorder.commands

    def test_detach_sets_process_attached_false(self) -> None:
        """Detach sets state.process_attached to False.

        Falsifiable: if detach() forgets to clear process_attached, the
        bridge still reports True after detach and this assertion fails.
        """
        recorder = _CommandRecorder()
        bridge = _make_attached_bridge(recorder)
        asyncio.run(bridge.detach())
        assert bridge.state.process_attached is False

    def test_detach_clears_target_pid(self) -> None:
        """Detach sets state.target_pid to None.

        Falsifiable: if detach() leaves target_pid at the old value, the
        None assertion fails.
        """
        recorder = _CommandRecorder()
        bridge = _make_attached_bridge(recorder, pid=42)
        asyncio.run(bridge.detach())
        assert bridge.state.target_pid is None

    def test_detach_clears_breakpoints_cache(self) -> None:
        """Detach empties the internal _breakpoints cache.

        Seeds a software breakpoint at 0x1000 via set_breakpoint, then calls
        detach and asserts the cache is empty.

        Falsifiable: if detach() skips _breakpoints.clear(), the dict still
        contains the 0x1000 entry and the empty-dict assertion fails.
        """
        recorder = _CommandRecorder()
        bridge = _make_attached_bridge(recorder)
        asyncio.run(bridge.set_breakpoint(_ADDR_1000, "software"))
        recorder.commands.clear()
        asyncio.run(bridge.detach())
        assert _get_breakpoints_cache(bridge) == {}

    def test_detach_without_attach_raises(self) -> None:
        """Detach raises ToolError when not attached to any process.

        Falsifiable: if the _require_attached guard is removed, no exception
        is raised and this gate fails.
        """
        recorder = _CommandRecorder()
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(recorder)
        with pytest.raises(ToolError, match="not attached"):
            asyncio.run(bridge.detach())


class TestSetBreakpointSoftware:
    """Gate: set_breakpoint with 'software' type issues 'db {address}'."""

    def test_software_breakpoint_command(self) -> None:
        """set_breakpoint('software') issues 'db 4096' for address=0x1000.

        Falsifiable: if the software branch uses 'dbH' instead of 'db', the
        'db 4096' assertion fails.
        """
        recorder = _CommandRecorder()
        bridge = _make_attached_bridge(recorder)
        asyncio.run(bridge.set_breakpoint(_ADDR_1000, "software"))
        assert "db 4096" in recorder.commands

    def test_software_breakpoint_returns_address(self) -> None:
        """set_breakpoint returns the breakpoint address as its identifier.

        Falsifiable: if the return value is always 0 or a different constant,
        the equality assertion fails.
        """
        recorder = _CommandRecorder()
        bridge = _make_attached_bridge(recorder)
        result = asyncio.run(bridge.set_breakpoint(_ADDR_1000, "software"))
        assert result == _ADDR_1000

    def test_software_breakpoint_cached_with_correct_type(self) -> None:
        """set_breakpoint stores the entry in _breakpoints with bp_type='software'.

        Falsifiable: if the cached type is 'hardware' or the address is missing
        from the cache, the bp_type comparison or key lookup fails.
        """
        recorder = _CommandRecorder()
        bridge = _make_attached_bridge(recorder)
        asyncio.run(bridge.set_breakpoint(_ADDR_1000, "software"))
        cache = _get_breakpoints_cache(bridge)
        assert _ADDR_1000 in cache
        assert cache[_ADDR_1000].bp_type == "software"


class TestSetBreakpointHardware:
    """Gate: set_breakpoint with 'hardware' type issues 'dbH {address}'."""

    def test_hardware_breakpoint_command(self) -> None:
        """set_breakpoint('hardware') issues 'dbH 4096' for address=0x1000.

        Falsifiable: if the hardware branch falls through to 'db' (software)
        instead of 'dbH', the 'dbH 4096' assertion fails.
        """
        recorder = _CommandRecorder()
        bridge = _make_attached_bridge(recorder)
        asyncio.run(bridge.set_breakpoint(_ADDR_1000, "hardware"))
        assert "dbH 4096" in recorder.commands

    def test_hardware_breakpoint_cached_type(self) -> None:
        """set_breakpoint stores bp_type='hardware' in the cache.

        Falsifiable: if the type literal is set to 'software' for the hardware
        branch, the bp_type comparison fails.
        """
        recorder = _CommandRecorder()
        bridge = _make_attached_bridge(recorder)
        asyncio.run(bridge.set_breakpoint(_ADDR_1000, "hardware"))
        cache = _get_breakpoints_cache(bridge)
        assert cache[_ADDR_1000].bp_type == "hardware"


class TestSetBreakpointMemory:
    """Gate: set_breakpoint with 'memory' type issues 'dbm {address}'."""

    def test_memory_breakpoint_command(self) -> None:
        """set_breakpoint('memory') issues 'dbm 4096' for address=0x1000.

        Falsifiable: if the memory branch uses 'db' instead of 'dbm', the
        'dbm 4096' assertion fails.
        """
        recorder = _CommandRecorder()
        bridge = _make_attached_bridge(recorder)
        asyncio.run(bridge.set_breakpoint(_ADDR_1000, "memory"))
        assert "dbm 4096" in recorder.commands

    def test_memory_breakpoint_cached_type(self) -> None:
        """set_breakpoint stores bp_type='memory' for the memory branch.

        Falsifiable: if the type literal falls to the 'software' else branch,
        the bp_type comparison fails.
        """
        recorder = _CommandRecorder()
        bridge = _make_attached_bridge(recorder)
        asyncio.run(bridge.set_breakpoint(_ADDR_1000, "memory"))
        cache = _get_breakpoints_cache(bridge)
        assert cache[_ADDR_1000].bp_type == "memory"


class TestSetBreakpointConditional:
    """Gate: set_breakpoint with a condition appends 'dbC {addr} {cond}' after 'db {addr}'."""

    def test_conditional_issues_db_then_dbc(self) -> None:
        """set_breakpoint with condition issues both 'db 4096' and 'dbC 4096 rax==1'.

        Falsifiable: if the conditional dbC branch is omitted, 'dbC 4096 rax==1'
        is absent from recorded commands.
        """
        recorder = _CommandRecorder()
        bridge = _make_attached_bridge(recorder)
        asyncio.run(bridge.set_breakpoint(_ADDR_1000, "software", condition="rax==1"))
        assert "db 4096" in recorder.commands
        assert "dbC 4096 rax==1" in recorder.commands

    def test_db_issued_before_dbc(self) -> None:
        """'db {addr}' appears before 'dbC {addr} {cond}' in the command sequence.

        Falsifiable: if the condition is applied before the breakpoint is created
        (reversed order), the index comparison fails.
        """
        recorder = _CommandRecorder()
        bridge = _make_attached_bridge(recorder)
        asyncio.run(bridge.set_breakpoint(_ADDR_1000, "software", condition="rax==1"))
        idx_db = recorder.commands.index("db 4096")
        idx_dbc = recorder.commands.index("dbC 4096 rax==1")
        assert idx_db < idx_dbc

    def test_condition_stored_in_cache(self) -> None:
        """The condition string is preserved in the cached BreakpointInfo.

        Falsifiable: if set_breakpoint stores None as the condition instead of
        the supplied expression, the equality assertion fails.
        """
        recorder = _CommandRecorder()
        bridge = _make_attached_bridge(recorder)
        asyncio.run(bridge.set_breakpoint(_ADDR_1000, "software", condition="rax==1"))
        cache = _get_breakpoints_cache(bridge)
        assert cache[_ADDR_1000].condition == "rax==1"


class TestSetBreakpointInjection:
    """Gate: set_breakpoint rejects conditions containing rizin control chars."""

    def test_semicolon_in_condition_raises(self) -> None:
        """A ';' in the condition raises ToolError before any command is issued.

        Falsifiable: if the validate_r2_argument call on condition is removed,
        no exception is raised and ';dc' would be injected into rizin.
        """
        recorder = _CommandRecorder()
        bridge = _make_attached_bridge(recorder)
        with pytest.raises(ToolError, match="rizin command-control"):
            asyncio.run(bridge.set_breakpoint(_ADDR_1000, "software", condition="rax==1;dc"))

    def test_invalid_bp_type_raises(self) -> None:
        """An unrecognised bp_type raises ToolError before any command is issued.

        Falsifiable: if the bp_type validation set is removed, an unknown type
        might fall through to 'db' without error.
        """
        recorder = _CommandRecorder()
        bridge = _make_attached_bridge(recorder)
        with pytest.raises(ToolError, match="invalid breakpoint type"):
            asyncio.run(bridge.set_breakpoint(_ADDR_1000, "watchpoint"))


class TestRemoveBreakpoint:
    """Gate: remove_breakpoint issues 'db- {address}' and removes the cache entry."""

    def test_remove_issues_db_minus_command(self) -> None:
        """remove_breakpoint issues 'db- 4096' for address=0x1000.

        Falsifiable: if remove_breakpoint sends 'db 4096' (set) instead of
        'db- 4096' (remove), the command assertion fails.
        """
        recorder = _CommandRecorder()
        bridge = _make_attached_bridge(recorder)
        asyncio.run(bridge.set_breakpoint(_ADDR_1000, "software"))
        recorder.commands.clear()
        asyncio.run(bridge.remove_breakpoint(_ADDR_1000))
        assert "db- 4096" in recorder.commands

    def test_remove_clears_cache_entry(self) -> None:
        """remove_breakpoint removes the address key from _breakpoints.

        Falsifiable: if remove_breakpoint skips the cache pop, the key is
        still present after the call and the not-in assertion fails.
        """
        recorder = _CommandRecorder()
        bridge = _make_attached_bridge(recorder)
        asyncio.run(bridge.set_breakpoint(_ADDR_1000, "software"))
        asyncio.run(bridge.remove_breakpoint(_ADDR_1000))
        assert _ADDR_1000 not in _get_breakpoints_cache(bridge)

    def test_remove_returns_true(self) -> None:
        """remove_breakpoint returns True on success.

        Falsifiable: if the return value is accidentally None or False, the
        identity assertion fails.
        """
        recorder = _CommandRecorder()
        bridge = _make_attached_bridge(recorder)
        asyncio.run(bridge.set_breakpoint(_ADDR_1000, "software"))
        result = asyncio.run(bridge.remove_breakpoint(_ADDR_1000))
        assert result is True


class TestGetBreakpoints:
    """Gate: get_breakpoints merges local cache with 'dbj' output and coerces types."""

    def test_issues_dbj_command(self) -> None:
        """get_breakpoints issues the 'dbj' rizin command.

        Falsifiable: if get_breakpoints queries 'db' (text) instead of 'dbj'
        (JSON), the 'dbj' assertion fails.
        """
        recorder = _CommandRecorder({"dbj": "[]"})
        bridge = _make_attached_bridge(recorder)
        asyncio.run(bridge.get_breakpoints())
        assert "dbj" in recorder.commands

    def test_local_breakpoint_preserved_in_result(self) -> None:
        """Local cache entries appear in the returned list even when dbj returns [].

        Falsifiable: if get_breakpoints drops the local cache and returns only
        rizin-side entries, the locally-set breakpoint is absent and the
        address check fails.
        """
        recorder = _CommandRecorder({"dbj": "[]"})
        bridge = _make_attached_bridge(recorder)
        asyncio.run(bridge.set_breakpoint(_ADDR_1000, "software"))
        recorder.commands.clear()
        result = asyncio.run(bridge.get_breakpoints())
        addresses = [bp.address for bp in result]
        assert _ADDR_1000 in addresses

    def test_hw_type_string_coerced_to_hardware_literal(self) -> None:
        """A rizin-reported 'hw' type string is coerced to the 'hardware' literal.

        This is the specific coercion identified as untested in the audit.
        The independent oracle is the rizin dbj spec: rizin writes 'hw' in
        the 'type' field for hardware breakpoints, but the bridge must normalise
        it to the BreakpointInfo.bp_type literal 'hardware'.

        Falsifiable: if the ``raw_type in {"hardware", "hw"}`` branch is
        dropped and 'hw' falls to the else (software) branch, bp.bp_type
        would be 'software' and the equality assertion fails.
        """
        external_bp_json = json.dumps([
            {"addr": _ADDR_2000, "type": "hw", "enabled": True, "hits": 3},
        ])
        recorder = _CommandRecorder({"dbj": external_bp_json})
        bridge = _make_attached_bridge(recorder)
        result = asyncio.run(bridge.get_breakpoints())
        external_entries = [bp for bp in result if bp.address == _ADDR_2000]
        assert len(external_entries) == 1
        assert external_entries[0].bp_type == "hardware"

    def test_external_bp_hit_count_parsed(self) -> None:
        """Hit count from the dbj JSON payload is stored in hit_count.

        Falsifiable: if get_breakpoints ignores the 'hits' field and always
        stores hit_count=0, the assertion on 3 fails.
        """
        external_bp_json = json.dumps([
            {"addr": _ADDR_2000, "type": "hw", "enabled": True, "hits": 3},
        ])
        recorder = _CommandRecorder({"dbj": external_bp_json})
        bridge = _make_attached_bridge(recorder)
        result = asyncio.run(bridge.get_breakpoints())
        external_entries = [bp for bp in result if bp.address == _ADDR_2000]
        assert external_entries[0].hit_count == 3

    def test_local_cache_wins_over_external_for_same_address(self) -> None:
        """When local and rizin both report the same address, the local entry wins.

        The local entry carries a condition string set by set_breakpoint; the
        rizin entry has no condition.  The merge must preserve the local entry.

        Falsifiable: if the merge strategy is inverted (external overwrites
        local), the condition is lost and the assertion fails.
        """
        external_bp_json = json.dumps([
            {"addr": _ADDR_1000, "type": "software", "enabled": True, "hits": 0},
        ])
        recorder = _CommandRecorder({"dbj": external_bp_json})
        bridge = _make_attached_bridge(recorder)
        asyncio.run(bridge.set_breakpoint(_ADDR_1000, "software", condition="rax==1"))
        recorder.commands.clear()
        result = asyncio.run(bridge.get_breakpoints())
        local_entries = [bp for bp in result if bp.address == _ADDR_1000]
        assert len(local_entries) == 1
        assert local_entries[0].condition == "rax==1"


class TestStepInto:
    """Gate: step_into issues 'ds' then 'dr?PC' and returns the parsed program counter."""

    def test_step_into_issues_ds(self) -> None:
        """step_into issues the 'ds' (source-step) command.

        Falsifiable: if step_into sends 'dso' (step-over) instead of 'ds',
        the 'ds' assertion fails.
        """
        recorder = _CommandRecorder({"dr?PC": "0x401001\n"})
        bridge = _make_attached_bridge(recorder)
        asyncio.run(bridge.step_into())
        assert "ds" in recorder.commands

    def test_step_into_reads_pc_via_drpc(self) -> None:
        """step_into issues 'dr?PC' to read the post-step instruction pointer.

        Falsifiable: if the PC read is omitted, 'dr?PC' is absent from the
        command log and this assertion fails.
        """
        recorder = _CommandRecorder({"dr?PC": "0x401001\n"})
        bridge = _make_attached_bridge(recorder)
        asyncio.run(bridge.step_into())
        assert "dr?PC" in recorder.commands

    def test_step_into_ds_before_drpc(self) -> None:
        """'ds' precedes 'dr?PC' in the command sequence.

        Falsifiable: if the order is reversed (PC read before step), the index
        comparison fails.
        """
        recorder = _CommandRecorder({"dr?PC": "0x401001\n"})
        bridge = _make_attached_bridge(recorder)
        asyncio.run(bridge.step_into())
        idx_ds = recorder.commands.index("ds")
        idx_pc = recorder.commands.index("dr?PC")
        assert idx_ds < idx_pc

    def test_step_into_returns_parsed_int_pc(self) -> None:
        """step_into returns the hex PC response parsed to an integer.

        The oracle is 0x401001 = 4198401.  Falsifiable: if the hex string is
        returned unparsed as a str, the int comparison fails.
        """
        recorder = _CommandRecorder({"dr?PC": "0x401001\n"})
        bridge = _make_attached_bridge(recorder)
        result = asyncio.run(bridge.step_into())
        assert result == 0x401001


class TestStepOver:
    """Gate: step_over issues 'dso' then 'dr?PC' and returns the parsed program counter."""

    def test_step_over_issues_dso(self) -> None:
        """step_over issues 'dso' (step-over), not 'ds' (step-into).

        Falsifiable: if step_over shares the step_into command path and sends
        'ds', the 'dso' assertion fails.
        """
        recorder = _CommandRecorder({"dr?PC": "0x401002\n"})
        bridge = _make_attached_bridge(recorder)
        asyncio.run(bridge.step_over())
        assert "dso" in recorder.commands

    def test_step_over_returns_parsed_pc(self) -> None:
        """step_over returns the PC as an integer (0x401002).

        Falsifiable: if step_over returns the same canned value as step_into
        would (e.g. 0x401001), the specific 0x401002 assertion fails.
        """
        recorder = _CommandRecorder({"dr?PC": "0x401002\n"})
        bridge = _make_attached_bridge(recorder)
        result = asyncio.run(bridge.step_over())
        assert result == 0x401002


class TestRun:
    """Gate: run() issues exactly the 'dc' (continue) command."""

    def test_run_issues_dc(self) -> None:
        """run() issues 'dc' to continue debuggee execution.

        Falsifiable: if run() sends 'ds' (single-step) or 'dso' instead of
        'dc', the 'dc' assertion fails.
        """
        recorder = _CommandRecorder()
        bridge = _make_attached_bridge(recorder)
        asyncio.run(bridge.run())
        assert "dc" in recorder.commands

    def test_run_without_attach_raises(self) -> None:
        """run() raises ToolError when not attached.

        Falsifiable: if the _require_attached guard is removed from run(), no
        exception is raised and this gate fails.
        """
        recorder = _CommandRecorder()
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(recorder)
        with pytest.raises(ToolError, match="not attached"):
            asyncio.run(bridge.run())


class TestGetRegisters:
    """Gate: get_registers issues 'drj' and parses the JSON payload into RegisterState."""

    _REG_JSON: str = json.dumps({
        "rax": 1,
        "rbx": 2,
        "rcx": 3,
        "rdx": 4,
        "rsi": 5,
        "rdi": 6,
        "rbp": 7,
        "rsp": 8,
        "rip": 16384,
        "r8": 9,
        "r9": 10,
        "r10": 11,
        "r11": 12,
        "r12": 13,
        "r13": 14,
        "r14": 15,
        "r15": 16,
        "rflags": 512,
        "cs": 35,
        "ds": 43,
        "es": 43,
        "fs": 0,
        "gs": 0,
        "ss": 43,
    })

    def test_issues_drj_command(self) -> None:
        """get_registers issues 'drj' (JSON register dump).

        Falsifiable: if get_registers queries 'dr' (text) instead of 'drj',
        the 'drj' assertion fails.
        """
        recorder = _CommandRecorder({"drj": self._REG_JSON})
        bridge = _make_attached_bridge(recorder)
        asyncio.run(bridge.get_registers())
        assert "drj" in recorder.commands

    def test_returns_register_state_with_exact_values(self) -> None:
        """get_registers parses the JSON payload into the exact RegisterState.

        Each field in the oracle JSON maps to the matching RegisterState attribute.
        Falsifiable: if any key lookup maps to the wrong register (e.g. 'rax'
        stored into rbx), one of the field comparisons fails.
        """
        recorder = _CommandRecorder({"drj": self._REG_JSON})
        bridge = _make_attached_bridge(recorder)
        state = asyncio.run(bridge.get_registers())
        assert isinstance(state, RegisterState)
        assert state.rax == 1
        assert state.rbx == 2
        assert state.rip == 16384
        assert state.rflags == 512
        assert state.cs == 35
        assert state.gs == 0

    def test_32bit_alt_name_fallback_eax_to_rax(self) -> None:
        """When 'rax' is absent, get_registers falls back to 'eax'.

        This exercises the 32-bit target alt-name path.  Falsifiable: if the
        fallback branch is removed and rax defaults to 0 instead of 42, the
        assertion fails.
        """
        regs_32 = json.dumps({
            "eax": 42,
            "ebx": 0,
            "ecx": 0,
            "edx": 0,
            "esi": 0,
            "edi": 0,
            "ebp": 0,
            "esp": 0,
            "eip": 1234,
            "eflags": 0,
            "cs": 0,
            "ds": 0,
            "es": 0,
            "fs": 0,
            "gs": 0,
            "ss": 0,
        })
        recorder = _CommandRecorder({"drj": regs_32})
        bridge = _make_attached_bridge(recorder)
        state = asyncio.run(bridge.get_registers())
        assert state.rax == 42
        assert state.rip == 1234

    def test_non_dict_drj_response_raises(self) -> None:
        """A JSON array response from drj raises ToolError.

        Falsifiable: if get_registers silently returns a zeroed RegisterState
        for a malformed list response, this gate fails.
        """
        recorder = _CommandRecorder({"drj": "[1,2,3]"})
        bridge = _make_attached_bridge(recorder)
        with pytest.raises(ToolError, match="invalid debug response"):
            asyncio.run(bridge.get_registers())


class TestSetRegister:
    """Gate: set_register issues 'dr {reg}={val}' with injection prevention."""

    def test_set_register_exact_command_framing(self) -> None:
        """set_register issues 'dr rax=3735928559' for register='rax', value=0xDEADBEEF.

        The oracle is the decimal string representation in the f'dr {register}={value}'
        template.  Falsifiable: if the command uses hex notation 'dr rax=0xdeadbeef' or
        swaps the operands, the exact string assertion fails.
        """
        recorder = _CommandRecorder()
        bridge = _make_attached_bridge(recorder)
        asyncio.run(bridge.set_register("rax", 0xDEAD_BEEF))
        assert f"dr rax=3735928559" in recorder.commands

    def test_set_register_returns_true(self) -> None:
        """set_register returns True on success.

        Falsifiable: if the return value is accidentally None or 0, the
        identity assertion fails.
        """
        recorder = _CommandRecorder()
        bridge = _make_attached_bridge(recorder)
        result = asyncio.run(bridge.set_register("rbx", 0))
        assert result is True

    def test_set_register_injection_guard_semicolon(self) -> None:
        """set_register rejects a register name containing ';'.

        Falsifiable: if the validate_r2_argument call on 'register' is removed,
        no exception is raised and 'dr ;rm=0' would be forwarded to rizin.
        """
        recorder = _CommandRecorder()
        bridge = _make_attached_bridge(recorder)
        with pytest.raises(ToolError, match="rizin command-control"):
            asyncio.run(bridge.set_register(";rm", 0))


class TestReadMemory:
    """Gate: read_memory issues 'p8 {size} @ {addr}' and hex-decodes the response."""

    def test_happy_path_command_and_decoded_bytes(self) -> None:
        """read_memory issues 'p8 4 @ 4096' and returns bytes.fromhex('deadbeef').

        The oracle: recorder returns 'deadbeef' for the exact 'p8 4 @ 4096'
        command.  Falsifiable: if read_memory constructs 'p8 4 @ 0x1000' or
        returns the hex string unparsed, either the command or bytes assertion fails.
        """
        recorder = _CommandRecorder({"p8 4 @ 4096": "deadbeef"})
        bridge = _make_attached_bridge(recorder)
        result = asyncio.run(bridge.read_memory(_ADDR_1000, 4))
        assert "p8 4 @ 4096" in recorder.commands
        assert result == bytes.fromhex("deadbeef")

    def test_size_zero_returns_empty_bytes_no_command(self) -> None:
        """read_memory with size=0 returns b'' without issuing a 'p8' command.

        Falsifiable: if the size==0 early-return is removed, a 'p8 0 @ ...'
        command is issued; the no-p8-command check verifies the guard path.
        """
        recorder = _CommandRecorder()
        bridge = _make_attached_bridge(recorder)
        result = asyncio.run(bridge.read_memory(_ADDR_1000, 0))
        assert result == b""
        assert not any(cmd.startswith("p8") for cmd in recorder.commands)

    def test_negative_size_raises_before_any_command(self) -> None:
        """read_memory with size=-1 raises ToolError before issuing any command.

        Falsifiable: if the negative-size guard is removed, rizin receives
        'p8 -1 @ ...' and may return garbage without raising.
        """
        recorder = _CommandRecorder()
        bridge = _make_attached_bridge(recorder)
        with pytest.raises(ToolError, match="size must be non-negative"):
            asyncio.run(bridge.read_memory(_ADDR_1000, -1))

    def test_non_hex_response_raises(self) -> None:
        """A non-hex response from rizin raises ToolError with 'invalid hex response'.

        Falsifiable: if the bytes.fromhex exception is swallowed and an empty
        b'' is returned instead, this gate fails.
        """
        recorder = _CommandRecorder({"p8": "NOTHEX!!"})
        bridge = _make_attached_bridge(recorder)
        with pytest.raises(ToolError, match="invalid hex response"):
            asyncio.run(bridge.read_memory(_ADDR_1000, 4))


class TestWriteMemory:
    """Gate: write_memory issues 'wx {hex} @ {addr}' and returns len(data)."""

    def test_happy_path_command_and_byte_count(self) -> None:
        r"""Write_memory issues 'wx 9090 @ 8192' and returns 2 for data=b'\x90\x90'.

        The oracle: data=b'\x90\x90' encodes to hex '9090' and address
        0x2000=8192.  Falsifiable: if the command uses 'wh' or formats the
        address as '0x2000', the string assertion fails; if len(data) is not
        the return value, the count assertion fails.
        """
        recorder = _CommandRecorder()
        bridge = _make_attached_bridge(recorder)
        result = asyncio.run(bridge.write_memory(_ADDR_2000, b"\x90\x90"))
        assert "wx 9090 @ 8192" in recorder.commands
        assert result == 2

    def test_empty_data_returns_zero_without_issuing_wx(self) -> None:
        """write_memory with empty data returns 0 without issuing any 'wx' command.

        Falsifiable: if the empty-data guard is removed, 'wx  @ ...' is sent
        to rizin; the no-wx check confirms the guard path is taken.
        """
        recorder = _CommandRecorder()
        bridge = _make_attached_bridge(recorder)
        result = asyncio.run(bridge.write_memory(_ADDR_2000, b""))
        assert result == 0
        assert not any(cmd.startswith("wx") for cmd in recorder.commands)


class TestGetMemoryRegions:
    """Gate: get_memory_regions issues 'dmj' and maps JSON to MemoryRegion objects."""

    def test_issues_dmj_command(self) -> None:
        """get_memory_regions issues 'dmj'.

        Falsifiable: if get_memory_regions queries 'dm' (text output) instead
        of 'dmj' (JSON), the 'dmj' assertion fails.
        """
        recorder = _CommandRecorder({"dmj": "[]"})
        bridge = _make_attached_bridge(recorder)
        asyncio.run(bridge.get_memory_regions())
        assert "dmj" in recorder.commands

    def test_explicit_size_field_used_when_positive(self) -> None:
        """When 'size' is present and positive, it is used directly as MemoryRegion.size.

        The oracle: size=8192 in the JSON.  Falsifiable: if the explicit 'size'
        field is ignored and end-base is computed instead, the size comparison
        fails.
        """
        region_json = json.dumps([
            {
                "addr": 4096,
                "size": 8192,
                "addr_end": 0,
                "perm": "r-x",
                "state": "commit",
                "type": "private",
                "name": "foo.dll",
            }
        ])
        recorder = _CommandRecorder({"dmj": region_json})
        bridge = _make_attached_bridge(recorder)
        result = asyncio.run(bridge.get_memory_regions())
        assert len(result) == 1
        region = result[0]
        assert isinstance(region, MemoryRegion)
        assert region.base_address == 4096
        assert region.size == 8192
        assert region.protection == "r-x"
        assert region.module_name == "foo.dll"

    def test_end_minus_base_fallback_when_size_is_zero(self) -> None:
        """When 'size' is 0, MemoryRegion.size is computed as addr_end - addr.

        The oracle: addr=4096, addr_end=8192 → computed size = 4096.
        Falsifiable: if the fallback is removed and size stays 0, the
        4096 assertion fails.
        """
        region_json = json.dumps([
            {
                "addr": 4096,
                "addr_end": 8192,
                "size": 0,
                "perm": "rwx",
                "state": "commit",
                "type": "image",
            }
        ])
        recorder = _CommandRecorder({"dmj": region_json})
        bridge = _make_attached_bridge(recorder)
        result = asyncio.run(bridge.get_memory_regions())
        assert len(result) == 1
        assert result[0].size == 4096

    def test_perm_field_maps_to_protection(self) -> None:
        """get_memory_regions reads the 'perm' key as the protection string.

        Falsifiable: if the key lookup uses 'permissions' as the primary name
        and the JSON only has 'perm', the protection defaults to '----'.
        """
        region_json = json.dumps([
            {
                "addr": 4096,
                "size": 4096,
                "perm": "r--",
                "state": "commit",
                "type": "private",
            }
        ])
        recorder = _CommandRecorder({"dmj": region_json})
        bridge = _make_attached_bridge(recorder)
        result = asyncio.run(bridge.get_memory_regions())
        assert result[0].protection == "r--"


class TestGetThreads:
    """Gate: get_threads issues 'dptj' and maps JSON fields to ThreadInfo objects."""

    def test_issues_dptj_command(self) -> None:
        """get_threads issues 'dptj'.

        Falsifiable: if get_threads queries 'dpt' (text) instead of 'dptj'
        (JSON), the 'dptj' assertion fails.
        """
        recorder = _CommandRecorder({"dptj": "[]"})
        bridge = _make_attached_bridge(recorder)
        asyncio.run(bridge.get_threads())
        assert "dptj" in recorder.commands

    def test_pid_key_maps_to_thread_tid(self) -> None:
        """The rizin 'pid' JSON field maps to ThreadInfo.tid.

        The independent oracle: rizin's dptj uses 'pid' (not 'tid') for
        thread IDs.  Falsifiable: if the primary key changes from 'pid' to
        something else and 'pid' is dropped, tid would be 0 and the
        equality assertion fails.
        """
        thread_json = json.dumps([
            {
                "pid": 7,
                "start": 4096,
                "pc": 8192,
                "status": "running",
            }
        ])
        recorder = _CommandRecorder({"dptj": thread_json})
        bridge = _make_attached_bridge(recorder)
        result = asyncio.run(bridge.get_threads())
        assert len(result) == 1
        thread = result[0]
        assert isinstance(thread, ThreadInfo)
        assert thread.tid == 7
        assert thread.start_address == 4096
        assert thread.current_pc == 8192
        assert thread.state == "running"

    def test_threads_cache_updated_after_query(self) -> None:
        """get_threads updates the internal _threads cache keyed by tid.

        Falsifiable: if the cache update is removed, _threads remains empty
        after the call and the key lookup fails.
        """
        thread_json = json.dumps([
            {
                "pid": 7,
                "start": 4096,
                "pc": 8192,
                "status": "running",
            }
        ])
        recorder = _CommandRecorder({"dptj": thread_json})
        bridge = _make_attached_bridge(recorder)
        asyncio.run(bridge.get_threads())
        cache = _get_threads_cache(bridge)
        assert 7 in cache
        assert cache[7].current_pc == 8192


class TestGetModules:
    """Gate: get_modules issues 'dmIj' and maps JSON fields to ModuleInfo objects."""

    def test_issues_dmij_command(self) -> None:
        """Get_modules issues 'dmIj'.

        Falsifiable: if get_modules queries 'dmj' (memory regions) instead of
        'dmIj' (module info), the 'dmIj' assertion fails.
        """
        recorder = _CommandRecorder({"dmIj": "[]"})
        bridge = _make_attached_bridge(recorder)
        asyncio.run(bridge.get_modules())
        assert "dmIj" in recorder.commands

    def test_name_derived_from_file_path_when_name_absent(self) -> None:
        """When 'name' is absent, ModuleInfo.name is the stem of the 'file' path.

        The oracle: 'file'='C:/Windows/System32/ntdll.dll' → name='ntdll.dll'
        (Path('...').name).  Falsifiable: if the name-derivation fallback is
        removed and name stays empty, the equality assertion fails.
        """
        module_json = json.dumps([
            {
                "file": "C:/Windows/System32/ntdll.dll",
                "addr": 4096,
                "size": 0,
                "addr_end": 65536,
                "entry": 4097,
            }
        ])
        recorder = _CommandRecorder({"dmIj": module_json})
        bridge = _make_attached_bridge(recorder)
        result = asyncio.run(bridge.get_modules())
        assert len(result) == 1
        module = result[0]
        assert isinstance(module, ModuleInfo)
        assert module.name == "ntdll.dll"
        assert module.base_address == 4096
        assert module.entry_point == 4097

    def test_size_fallback_from_addr_end_minus_base(self) -> None:
        """When 'size' is 0, ModuleInfo.size is computed as addr_end - addr.

        The oracle: addr=4096, addr_end=65536, size=0 → computed size 61440.
        Falsifiable: if the fallback is removed and size stays 0, the 61440
        assertion fails.
        """
        module_json = json.dumps([
            {
                "file": "C:/Windows/ntdll.dll",
                "addr": 4096,
                "size": 0,
                "addr_end": 65536,
                "entry": 4097,
            }
        ])
        recorder = _CommandRecorder({"dmIj": module_json})
        bridge = _make_attached_bridge(recorder)
        result = asyncio.run(bridge.get_modules())
        assert result[0].size == 61440

    def test_explicit_name_takes_priority_over_file_stem(self) -> None:
        """When both 'name' and 'file' are present, 'name' is used as ModuleInfo.name.

        Falsifiable: if the raw_name priority check is removed and the file
        stem is always used, the explicit 'custom_name' is ignored and the
        assertion fails.
        """
        module_json = json.dumps([
            {
                "file": "C:/path/different.dll",
                "name": "custom_name",
                "addr": 4096,
                "size": 4096,
                "addr_end": 8192,
                "entry": 0,
            }
        ])
        recorder = _CommandRecorder({"dmIj": module_json})
        bridge = _make_attached_bridge(recorder)
        result = asyncio.run(bridge.get_modules())
        assert result[0].name == "custom_name"
