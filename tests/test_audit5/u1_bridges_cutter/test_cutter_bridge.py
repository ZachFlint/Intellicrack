# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Audit5 u1 regression tests for ``CutterBridge``.

Each test exercises one finding from audit5.md (bridges-cutter-frida) and
fails on the unfixed implementation, succeeding only after the audit
remediation lands. Tests use a plain in-memory r2pipe stand-in
(``_RecordingR2``) and drive the bridge through manual asyncio loops so
no real rizin process is required.
"""

from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest
import r2pipe

from intellicrack.bridges.cutter import (
    CutterBridge,
    is_rizin_64bit,
    validate_r2_argument,
)
from intellicrack.core.process_manager import ProcessManager, ProcessType
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import Iterator


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


class _RecordingR2:
    """Pure-Python stand-in that records every command issued by the bridge.

    The bridge only uses ``cmd(str) -> str`` and ``quit() -> None`` from
    the r2pipe surface; this class exposes exactly that subset and lets
    each test configure a prefix-keyed mapping of canned responses.
    """

    commands: list[str]
    _responses: dict[str, str]
    quit_count: int

    def __init__(self, responses: dict[str, str] | None = None) -> None:
        """Initialise the recorder.

        Args:
            responses: Mapping of command-prefix to canned response.
        """
        self.commands = []
        self._responses = responses or {}
        self.quit_count = 0

    def cmd(self, command: str) -> str:
        """Record ``command`` and return the configured response.

        Args:
            command: Command string sent by the bridge.

        Returns:
            str: Canned response string (empty when no prefix matches).
        """
        self.commands.append(command)
        for prefix, response in self._responses.items():
            if command.startswith(prefix):
                return response
        return ""

    def quit(self) -> None:
        """Record a quit invocation for shutdown-order assertions."""
        self.quit_count += 1


def _as_r2(double: _RecordingR2) -> r2pipe.open:
    """Cast a test double to the bridge's r2pipe type for assignment.

    Args:
        double: Recorder instance.

    Returns:
        r2pipe.open: The same instance typed as r2pipe for the setter.
    """
    return cast(r2pipe.open, double)


def _new_loop() -> asyncio.AbstractEventLoop:
    """Create an isolated event loop for synchronous test driving.

    Returns:
        asyncio.AbstractEventLoop: A fresh loop installed as current.
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    return loop


@pytest.fixture
def loop() -> Iterator[asyncio.AbstractEventLoop]:
    """Provide a per-test event loop and ensure it is closed afterwards.

    Yields:
        asyncio.AbstractEventLoop: Fresh loop for the test.
    """
    new = _new_loop()
    try:
        yield new
    finally:
        new.close()


@pytest.fixture
def bridge() -> CutterBridge:
    """Provide a fresh CutterBridge.

    Returns:
        CutterBridge: Newly constructed bridge with no r2 session.
    """
    return CutterBridge()


def _attach(bridge: CutterBridge, recorder: _RecordingR2) -> None:
    """Attach ``recorder`` to ``bridge.r2`` via the public setter.

    Args:
        bridge: Bridge instance under test.
        recorder: Test double to install.
    """
    bridge.r2 = _as_r2(recorder)


def _attach_and_analyze(
    bridge: CutterBridge,
    recorder: _RecordingR2,
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Attach ``recorder`` and run the public ``analyze()`` to mark analysed.

    Args:
        bridge: Bridge instance under test.
        recorder: Test double to install.
        loop: Per-test asyncio loop.
    """
    bridge.r2 = _as_r2(recorder)
    loop.run_until_complete(bridge.analyze())
    recorder.commands.clear()


# ---------------------------------------------------------------------------
# F-0001 - save_binary uses wcf, not wtf
# ---------------------------------------------------------------------------


class TestF0001SaveBinaryUsesWcf:
    """save_binary must commit cached patches via ``wcf``, not ``wtf``."""

    def test_save_binary_issues_wcf_full_image(
        self,
        bridge: CutterBridge,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        """Save command must be ``wcf`` so the full patched image is written.

        Args:
            bridge: Fresh CutterBridge fixture.
            loop: Per-test asyncio loop.
        """
        recorder = _RecordingR2()
        _attach(bridge, recorder)

        target = Path("C:/tmp/save_binary_target.bin").as_posix()
        result = loop.run_until_complete(bridge.save_binary(target))

        assert result is True
        assert any(cmd.startswith("wcf ") for cmd in recorder.commands), recorder.commands
        assert not any(cmd.startswith("wtf ") for cmd in recorder.commands), recorder.commands
        wcf_cmd = next(cmd for cmd in recorder.commands if cmd.startswith("wcf "))
        assert target in wcf_cmd

    def test_save_binary_propagates_rizin_failure(
        self,
        bridge: CutterBridge,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        """Rizin error responses surface as ToolError, not silent True.

        Args:
            bridge: Fresh CutterBridge fixture.
            loop: Per-test asyncio loop.
        """
        recorder = _RecordingR2(responses={"wcf": "error: cannot write to read-only file"})
        _attach(bridge, recorder)
        with pytest.raises(ToolError):
            loop.run_until_complete(bridge.save_binary("C:/tmp/out.bin"))


# ---------------------------------------------------------------------------
# F-0002 - assemble_at must not double-write
# ---------------------------------------------------------------------------


class TestF0002AssembleAtSingleWrite:
    """assemble_at issues exactly one write; never both ``wa`` and ``wx``."""

    def test_single_write_command(
        self,
        bridge: CutterBridge,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        """Verify only one write command is sent for a successful assembly.

        Args:
            bridge: Fresh CutterBridge fixture.
            loop: Per-test asyncio loop.
        """
        recorder = _RecordingR2(responses={"pa ": "90909090\n"})
        _attach_and_analyze(bridge, recorder, loop)

        result = loop.run_until_complete(bridge.assemble_at(0x1000, "nop"))
        assert result == bytes.fromhex("90909090")

        write_commands = [cmd for cmd in recorder.commands if cmd.startswith(("wa ", "wx "))]
        assert len(write_commands) == 1, write_commands
        assert write_commands[0].startswith("wx ")


# ---------------------------------------------------------------------------
# F-0003 - get_imports/get_exports/get_sections without _analyzed
# ---------------------------------------------------------------------------


class TestF0003LoaderEndpointsNoAnalysisGate:
    """Loader-driven listings must not be silently empty pre-analysis."""

    def test_get_imports_without_analysis_returns_loader_data(
        self,
        bridge: CutterBridge,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        """Imports come from the loader; ``aaa`` is not required.

        Args:
            bridge: Fresh CutterBridge fixture.
            loop: Per-test asyncio loop.
        """
        recorder = _RecordingR2(
            responses={
                "iij": '[{"name":"GetProcAddress","lib":"kernel32.dll","plt":4096,"ordinal":1}]',
            },
        )
        _attach(bridge, recorder)

        imports = loop.run_until_complete(bridge.get_imports())
        assert len(imports) == 1
        assert imports[0].function == "GetProcAddress"

    def test_get_exports_without_analysis_returns_loader_data(
        self,
        bridge: CutterBridge,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        """Exports likewise come from the loader.

        Args:
            bridge: Fresh CutterBridge fixture.
            loop: Per-test asyncio loop.
        """
        recorder = _RecordingR2(
            responses={"iEj": '[{"name":"DllMain","ordinal":1,"vaddr":4096}]'},
        )
        _attach(bridge, recorder)

        exports = loop.run_until_complete(bridge.get_exports())
        assert len(exports) == 1
        assert exports[0].name == "DllMain"

    def test_get_sections_without_analysis_returns_loader_data(
        self,
        bridge: CutterBridge,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        """Section table is parsed by the loader, not analysis.

        Args:
            bridge: Fresh CutterBridge fixture.
            loop: Per-test asyncio loop.
        """
        recorder = _RecordingR2(
            responses={
                "iSj": '[{"name":".text","vaddr":4096,"vsize":4096,"size":4096,"perm":5}]',
            },
        )
        _attach(bridge, recorder)

        sections = loop.run_until_complete(bridge.get_sections())
        assert len(sections) == 1
        assert sections[0].name == ".text"


# ---------------------------------------------------------------------------
# F-0004 - get_resources must not swallow ToolError
# ---------------------------------------------------------------------------


class TestF0004ResourcesPropagateErrors:
    """get_resources must raise ToolError instead of returning ``[]``."""

    def test_get_resources_propagates_json_failure(
        self,
        bridge: CutterBridge,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        """Malformed JSON from rizin must surface as ToolError.

        Args:
            bridge: Fresh CutterBridge fixture.
            loop: Per-test asyncio loop.
        """
        recorder = _RecordingR2(responses={"irj": "not valid json"})
        _attach(bridge, recorder)
        with pytest.raises(ToolError):
            loop.run_until_complete(bridge.get_resources())


# ---------------------------------------------------------------------------
# F-0016 - search_string_live / search_assembly_pattern command injection
# ---------------------------------------------------------------------------


class TestF0016NoCommandInjection:
    """User-supplied search inputs must not inject rizin commands."""

    def test_search_string_live_uses_hex_byte_search(
        self,
        bridge: CutterBridge,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        """Plain ``/j {text}`` is replaced with ``/xj <hex>``.

        Args:
            bridge: Fresh CutterBridge fixture.
            loop: Per-test asyncio loop.
        """
        recorder = _RecordingR2(responses={"/xj": "[]"})
        _attach(bridge, recorder)

        loop.run_until_complete(bridge.search_string_live("hello"))
        assert any(cmd.startswith("/xj ") for cmd in recorder.commands)
        assert not any(cmd.startswith("/j ") for cmd in recorder.commands)
        xj_cmd = next(cmd for cmd in recorder.commands if cmd.startswith("/xj "))
        assert xj_cmd.split(" ", 1)[1] == b"hello".hex()

    def test_search_string_live_rejects_empty(
        self,
        bridge: CutterBridge,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        """Empty search strings are rejected to avoid matching everything.

        Args:
            bridge: Fresh CutterBridge fixture.
            loop: Per-test asyncio loop.
        """
        recorder = _RecordingR2()
        _attach(bridge, recorder)
        with pytest.raises(ToolError):
            loop.run_until_complete(bridge.search_string_live(""))

    def test_search_assembly_pattern_rejects_injection(
        self,
        bridge: CutterBridge,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        """Patterns containing rizin command separators raise ToolError.

        Args:
            bridge: Fresh CutterBridge fixture.
            loop: Per-test asyncio loop.
        """
        recorder = _RecordingR2()
        _attach(bridge, recorder)
        with pytest.raises(ToolError):
            loop.run_until_complete(
                bridge.search_assembly_pattern("mov eax, ebx; quit"),
            )

    def test_search_assembly_pattern_accepts_clean_input(
        self,
        bridge: CutterBridge,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        """Clean assembly patterns still go through unchanged.

        Args:
            bridge: Fresh CutterBridge fixture.
            loop: Per-test asyncio loop.
        """
        recorder = _RecordingR2(responses={"/aj ": "[]"})
        _attach(bridge, recorder)
        loop.run_until_complete(bridge.search_assembly_pattern("mov eax, ebx"))
        assert any(cmd.startswith("/aj ") for cmd in recorder.commands)


def testvalidate_r2_argument_rejects_control_chars() -> None:
    """The injection-safe validator rejects every documented r2 control char."""
    for sample in (
        "name;quit",
        "name@0x100",
        "name|cat",
        "name~grep",
        "name`sub`",
        "name>out",
        "name<in",
        "name$1",
        "name#comment",
        "!ls",
    ):
        with pytest.raises(ToolError):
            validate_r2_argument(sample, field="test")


def testvalidate_r2_argument_accepts_safe_strings() -> None:
    """Safe identifiers pass through verbatim."""
    assert validate_r2_argument("symbol_name42", field="test") == "symbol_name42"


# ---------------------------------------------------------------------------
# F-0017 - _cmd_json must raise on JSON parse failure
# ---------------------------------------------------------------------------


class TestF0017CmdJsonRaisesOnParseError:
    """_cmd_json must surface JSON-parse failures as ToolError."""

    def test_invalid_json_raises_tool_error(
        self,
        bridge: CutterBridge,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        """Malformed JSON output must raise ToolError, not return ``[]``.

        Driven through the public ``get_imports`` API which routes
        through ``_cmd_json``; this avoids reaching into protected
        members while still exercising the parse path.

        Args:
            bridge: Fresh CutterBridge fixture.
            loop: Per-test asyncio loop.
        """
        recorder = _RecordingR2(responses={"iij": "<not json>"})
        _attach(bridge, recorder)
        with pytest.raises(ToolError):
            loop.run_until_complete(bridge.get_imports())

    def test_empty_response_returns_empty_list(
        self,
        bridge: CutterBridge,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        """An empty rizin reply still resolves to an empty list (not an error).

        Args:
            bridge: Fresh CutterBridge fixture.
            loop: Per-test asyncio loop.
        """
        recorder = _RecordingR2(responses={"iij": ""})
        _attach(bridge, recorder)
        result = loop.run_until_complete(bridge.get_imports())
        assert result == []


# ---------------------------------------------------------------------------
# F-0019 - get_function_address must not enumerate all functions
# ---------------------------------------------------------------------------


class TestF0019GetFunctionAddressDirect:
    """get_function_address resolves directly via ``afij <name>``."""

    def test_does_not_call_aflj(
        self,
        bridge: CutterBridge,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        """No full ``aflj`` enumeration when resolving by name.

        Args:
            bridge: Fresh CutterBridge fixture.
            loop: Per-test asyncio loop.
        """
        recorder = _RecordingR2(
            responses={
                "afij main": '[{"name":"main","offset":4096,"size":64,"cc":"cdecl"}]',
            },
        )
        _attach_and_analyze(bridge, recorder, loop)
        addr = loop.run_until_complete(bridge.get_function_address("main"))
        assert addr == 4096
        assert not any(cmd.startswith("aflj") for cmd in recorder.commands)
        assert any(cmd == "afij main" for cmd in recorder.commands)

    def test_unknown_name_returns_none(
        self,
        bridge: CutterBridge,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        """Unresolved names return None rather than raising.

        Args:
            bridge: Fresh CutterBridge fixture.
            loop: Per-test asyncio loop.
        """
        recorder = _RecordingR2(responses={"afij ": "[]"})
        _attach_and_analyze(bridge, recorder, loop)
        assert loop.run_until_complete(bridge.get_function_address("does_not_exist")) is None

    def test_rejects_command_injection(
        self,
        bridge: CutterBridge,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        """Names containing r2 control characters are rejected.

        Args:
            bridge: Fresh CutterBridge fixture.
            loop: Per-test asyncio loop.
        """
        recorder = _RecordingR2()
        _attach_and_analyze(bridge, recorder, loop)
        with pytest.raises(ToolError):
            loop.run_until_complete(bridge.get_function_address("foo;quit"))


# ---------------------------------------------------------------------------
# F-0020 - search_strings does not require analysis
# ---------------------------------------------------------------------------


class TestF0020SearchStringsNoAnalysisGate:
    """search_strings only needs the loader, not analysis."""

    def test_runs_without_analyze(
        self,
        bridge: CutterBridge,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        """Calling search_strings before analyze must not raise.

        Args:
            bridge: Fresh CutterBridge fixture.
            loop: Per-test asyncio loop.
        """
        recorder = _RecordingR2(
            responses={"izj": '[{"vaddr":4096,"string":"hello","type":"ascii","section":".rodata"}]'},
        )
        _attach(bridge, recorder)
        results = loop.run_until_complete(bridge.search_strings(".*hello.*"))
        assert len(results) == 1
        assert results[0].value == "hello"


# ---------------------------------------------------------------------------
# F-0024 - shutdown order
# ---------------------------------------------------------------------------


def _force_register_pid(bridge: CutterBridge, pid: int) -> None:
    """Drive the bridge through the same internal handler used at load time.

    Bypasses :meth:`ProcessManager.register_external_pid` so the test can use a
    synthetic PID that does not correspond to a live OS process.

    Args:
        bridge: Bridge instance under test.
        pid: Synthetic PID for the test.
    """
    bridge.state.target_pid = pid
    pm = ProcessManager.get_instance()
    registry = cast(
        "dict[int, dict[str, object]]",
        getattr(pm, "_external_pids"),
    )
    registry[pid] = {
        "name": f"cutter-test-{pid}",
        "process_type": ProcessType.EXTERNAL_TOOL,
        "metadata": {},
        "registered_at": datetime.now(tz=UTC),
    }


class TestF0024ShutdownAlwaysRunsSuper:
    """shutdown must always run super().shutdown() even if cleanup fails."""

    def test_super_shutdown_runs_when_unregister_raises(
        self,
        bridge: CutterBridge,
        loop: asyncio.AbstractEventLoop,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A raising ProcessManager must not skip the base shutdown step.

        The bridge must end up with a fresh ``BridgeState`` (the
        observable side-effect of ``super().shutdown()``) even when
        ``ProcessManager.unregister_external_pid`` raises mid-cleanup.

        Args:
            bridge: Fresh CutterBridge fixture.
            loop: Per-test asyncio loop.
            monkeypatch: pytest's monkeypatch fixture.
        """
        recorder = _RecordingR2()
        _attach(bridge, recorder)
        bridge.state.connected = True
        bridge.state.binary_loaded = True
        _force_register_pid(bridge, 4242)

        def _raise(self: ProcessManager, pid: int) -> None:
            del self, pid
            msg = "simulated unregister failure"
            raise RuntimeError(msg)

        monkeypatch.setattr(
            ProcessManager,
            "unregister_external_pid",
            _raise,
        )

        loop.run_until_complete(bridge.shutdown())

        assert bridge.r2 is None
        assert bridge.state.connected is False
        assert bridge.state.binary_loaded is False


# ---------------------------------------------------------------------------
# F-0025 - r2 setter is the canonical write path
# ---------------------------------------------------------------------------


class TestF0025R2SetterIsActive:
    """The bridge writes to ``self.r2`` (property setter), not ``self._r2``."""

    def test_setter_invoked_during_shutdown(
        self,
        bridge: CutterBridge,
        loop: asyncio.AbstractEventLoop,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Shutdown must reach the public setter so observers can react.

        Args:
            bridge: Fresh CutterBridge fixture.
            loop: Per-test asyncio loop.
            monkeypatch: pytest's monkeypatch fixture.
        """
        observed: list[bool] = []
        original_setter = CutterBridge.r2.fset
        original_getter = CutterBridge.r2.fget
        assert original_setter is not None
        assert original_getter is not None

        def _spy_setter(instance: CutterBridge, value: r2pipe.open | None) -> None:
            observed.append(value is not None)
            original_setter(instance, value)

        monkeypatch.setattr(
            CutterBridge,
            "r2",
            property(original_getter, _spy_setter),
        )

        recorder = _RecordingR2()
        bridge.r2 = _as_r2(recorder)

        loop.run_until_complete(bridge.shutdown())
        assert True in observed, observed
        assert False in observed, observed


# ---------------------------------------------------------------------------
# F-0026 - supports_dynamic_analysis aligned with ESIL emulation tools
# ---------------------------------------------------------------------------


class TestF0026DynamicAnalysisFlag:
    """Capabilities advertise ESIL emulation as dynamic analysis."""

    def test_dynamic_analysis_supported(self, bridge: CutterBridge) -> None:
        """Bridge claims dynamic analysis to match its ESIL surface.

        Args:
            bridge: Fresh CutterBridge fixture.
        """
        assert bridge.capabilities.supports_dynamic_analysis is True

    def test_esil_methods_present(self, bridge: CutterBridge) -> None:
        """Every ESIL tool the audit calls out remains exposed.

        Args:
            bridge: Fresh CutterBridge fixture.
        """
        names = {f.name for f in bridge.tool_definition.functions}
        expected = {
            "cutter.esil_eval",
            "cutter.esil_step",
            "cutter.esil_emulate_function",
            "cutter.esil_init_memory",
            "cutter.esil_set_pc",
        }
        assert expected.issubset(names)


# ---------------------------------------------------------------------------
# F-0028 - assemble_at description disambiguates bytes vs hex string
# ---------------------------------------------------------------------------


class TestF0028AssembleAtToolDocstring:
    """Tool definition for assemble_at says raw bytes object."""

    def test_returns_description_mentions_bytes_object(
        self,
        bridge: CutterBridge,
    ) -> None:
        """Returns string explicitly references a Python bytes object.

        Args:
            bridge: Fresh CutterBridge fixture.
        """
        td = bridge.tool_definition
        match = next(f for f in td.functions if f.name == "cutter.assemble_at")
        assert "bytes object" in match.returns.lower()


# ---------------------------------------------------------------------------
# F-0029 - is_64bit heuristic
# ---------------------------------------------------------------------------


class TestF0029Is64BitHeuristic:
    """The 64-bit heuristic must cover bits, arch, and class fields."""

    def test_bits_64_recognised(self) -> None:
        """Direct bits=64 still counts."""
        assert is_rizin_64bit(64, "x86", "PE") is True

    def test_64bit_arch_recognised(self) -> None:
        """A 64-bit arch keeps a 32-bit-looking ``bits`` honest."""
        assert is_rizin_64bit(0, "x86_64", "") is True
        assert is_rizin_64bit(0, "aarch64", "") is True

    def test_64bit_class_recognised(self) -> None:
        """PE32+ and ELF64 file classes count as 64-bit."""
        assert is_rizin_64bit(32, "x86", "PE32+") is True
        assert is_rizin_64bit(0, "", "ELF64") is True
        assert is_rizin_64bit(0, "", "MACH064") is True

    def test_pure_32bit_negative(self) -> None:
        """A genuine 32-bit triple stays False."""
        assert is_rizin_64bit(32, "x86", "PE") is False


# ---------------------------------------------------------------------------
# F-0031 - get_function size and location no longer hardcoded
# ---------------------------------------------------------------------------


class TestF0031GetFunctionSizeAndLocation:
    """Param/local size and location reflect rizin payload."""

    def test_register_arg_location(
        self,
        bridge: CutterBridge,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        """Register-resident argument is reported with its register name.

        Args:
            bridge: Fresh CutterBridge fixture.
            loop: Per-test asyncio loop.
        """
        recorder = _RecordingR2(
            responses={
                "afij": ('[{"name":"main","offset":4096,"size":64,"cc":"amd64","type":"int","bits":64}]'),
                "afvj": (
                    '[{"sp":[],'
                    '"bp":[{"name":"local_8h","kind":"var","type":"int64_t",'
                    '"ref":{"base":"rbp","offset":-8}}],'
                    '"reg":[{"name":"argc","kind":"arg","type":"int32_t",'
                    '"ref":{"base":"rdi","offset":0}}]}]'
                ),
                "s ": "",
            },
        )
        _attach_and_analyze(bridge, recorder, loop)
        info = loop.run_until_complete(bridge.get_function(0x1000))
        assert info is not None
        assert len(info.parameters) == 1
        assert info.parameters[0].location == "rdi"
        assert info.parameters[0].size == 4
        assert len(info.local_variables) == 1
        assert info.local_variables[0].size == 8


# ---------------------------------------------------------------------------
# F-0032 - get_classes parses methods and fields uniformly
# ---------------------------------------------------------------------------


class TestF0032GetClassesNormalisedDicts:
    """Methods and fields surface as normalised dictionaries."""

    def test_methods_have_name_and_address(
        self,
        bridge: CutterBridge,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        """Every method dict carries ``name`` and ``address`` keys.

        Args:
            bridge: Fresh CutterBridge fixture.
            loop: Per-test asyncio loop.
        """
        recorder = _RecordingR2(
            responses={
                "icj": (
                    '[{"classname":"Foo","addr":4096,'
                    '"methods":[{"name":"Foo::bar","addr":4112,"type":"FUNC"}],'
                    '"fields":[{"name":"x","offset":0,"size":4,"type":"int"}]}]'
                ),
            },
        )
        _attach(bridge, recorder)
        classes = loop.run_until_complete(bridge.get_classes())
        assert len(classes) == 1
        cls = classes[0]
        assert cls.name == "Foo"
        assert cls.address == 4096
        assert len(cls.methods) == 1
        method = cls.methods[0]
        assert method["name"] == "Foo::bar"
        assert method["address"] == 4112
        assert "type" in method
        assert len(cls.fields) == 1
        field_entry = cls.fields[0]
        assert field_entry["name"] == "x"
        assert field_entry["offset"] == 0
        assert field_entry["size"] == 4
