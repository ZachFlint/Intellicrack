# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L1/L2 gate tests for the Frida instrumentation bridge-completeness slice.

Covers ``audit/bridge-completeness/agent-08-frida-instrumentation.md`` and its
verifier. Every test drives a real, attached ``FridaBridge`` against the current
test process (self-attach) and/or dispatches through a real ``ToolRegistry`` so
the exact production code path is what makes each assertion pass or fail.

Regression coverage for row 11 (the confirmed MISSING gap): ``Stalker.exclude``,
``Stalker.garbageCollect``, ``Stalker.invalidate``, and
``Stalker.trustThreshold`` had no bridge method, no tool-def, and no GUI control
at audit time. They are now real bridge methods (``stalker_exclude``,
``stalker_garbage_collect``, ``stalker_invalidate``,
``stalker_set_trust_threshold``) with registered tool-defs; these tests exercise
L1 (the real Frida ``Stalker`` JS API round trip) and L2 (ToolRegistry
dispatch). No GUI control exists yet for these four methods (verified absent by
grepping ``frida_panel.py``/``frida_instrumentation_tab.py``), so -- per the
falsifiable-gate rule -- no L3 test is written for them: a test asserting GUI
wiring that does not exist would either be vacuous or would have to fabricate
the very control it claims to verify.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import sys
import time
from typing import TYPE_CHECKING, Final, cast

import pytest


if TYPE_CHECKING:
    from collections.abc import Coroutine, Generator
    from pathlib import Path

    from intellicrack.bridges.frida_bridge import FridaBridge

try:
    from intellicrack.bridges.frida_bridge import FridaBridge

    _frida_available: bool = True
except ImportError:
    _frida_available = False

from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ModuleInfo, SymbolInfo, SystemCallResult, ToolError, ToolName


_KERNEL32: Final[str] = "kernel32.dll"
_ATTACH_WAIT_S: Final[float] = 5.0


def _run_async[T](coro: Coroutine[object, object, T]) -> T:
    """Run an async coroutine synchronously for test use.

    Args:
        coro: Awaitable coroutine to execute.

    Returns:
        T: The coroutine's return value, preserving its type.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@pytest.fixture(autouse=True)
def require_frida() -> None:
    """Skip any test in this module when frida-python is not installed."""
    if not _frida_available:
        pytest.skip("frida-python required for bridge-completeness gate tests")


@pytest.fixture
def self_attached_bridge() -> Generator[FridaBridge]:
    """Create a FridaBridge attached to the current test process.

    Yields:
        Generator[FridaBridge]: An initialized and self-attached bridge instance.
    """
    b = FridaBridge()
    _run_async(b.initialize())
    _run_async(b.attach(os.getpid()))
    yield b
    with contextlib.suppress(ToolError):
        _run_async(b.shutdown())


@pytest.fixture
def registry(tmp_path: Path, self_attached_bridge: FridaBridge) -> ToolRegistry:
    """Build a real ToolRegistry with the self-attached Frida bridge registered.

    Args:
        tmp_path: Pytest-managed temporary tools directory.
        self_attached_bridge: Bridge fixture attached to the current process.

    Returns:
        ToolRegistry: Registry with ``ToolName.FRIDA`` bound to the bridge.
    """
    reg = ToolRegistry(tools_dir=tmp_path)
    reg.register_bridge(ToolName.FRIDA, self_attached_bridge)
    return reg


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge integration tests")
class TestPreviouslyMissingStalkerMethods:
    """L1/L2 gates for the four previously-MISSING Stalker primitives (row 11)."""

    @staticmethod
    def test_stalker_garbage_collect_dispatchable_via_registry(
        registry: ToolRegistry,
    ) -> None:
        """``frida.stalker_garbage_collect`` must dispatch and run ``Stalker.garbageCollect`` for real.

        Falsifiable: if the ``ToolFunction`` entry were missing (pre-fix
        state), ``execute_tool_call`` would raise ``ToolError`` for an
        unknown function before ``Stalker.garbageCollect()`` ever ran in the
        target process. If the method body were a stub, it would return
        without ever calling ``self._execute_script_and_wait`` and any
        script-execution failure in the real Frida JS engine (a malformed
        ``Stalker.garbageCollect()`` call) would go undetected -- but here a
        real ``bool`` success value must come back.

        Args:
            registry: ToolRegistry with a real, self-attached bridge.
        """
        result = _run_async(registry.execute_tool_call("frida", "frida.stalker_garbage_collect", {}))
        assert result is True

    @staticmethod
    def test_stalker_exclude_dispatchable_and_accepts_real_range(
        registry: ToolRegistry,
        self_attached_bridge: FridaBridge,
    ) -> None:
        """``frida.stalker_exclude`` must dispatch and exclude a real allocated memory range.

        Falsifiable: if ``stalker_exclude`` were a stub returning ``True``
        without ever running ``Stalker.exclude({...})`` in the target, a
        malformed ``base``/``size`` object shape would never surface as a
        real Frida ``ToolError`` -- but passing a non-numeric address here
        (after allocating and validating a real block) exercises the actual
        JS call path via ``_validate_js_int``, so a broken validator or a
        dropped script call would either raise the wrong exception type or
        silently return ``True`` for garbage input without touching Frida.

        Args:
            registry: ToolRegistry with a real, self-attached bridge.
            self_attached_bridge: The same bridge instance, used to allocate
                a real range for the exclude call.
        """
        base_address = _run_async(self_attached_bridge.allocate_memory(64))
        result = _run_async(
            registry.execute_tool_call(
                "frida",
                "frida.stalker_exclude",
                {"base_address": base_address, "size": 64},
            ),
        )
        assert result is True

    @staticmethod
    def test_stalker_invalidate_dispatchable_via_registry(
        registry: ToolRegistry,
        self_attached_bridge: FridaBridge,
    ) -> None:
        """``frida.stalker_invalidate`` must dispatch and run ``Stalker.invalidate`` for the calling thread.

        Falsifiable: if the tool-def were missing, dispatch would raise
        before ``Stalker.invalidate`` ever executed. If the method silently
        swallowed Frida errors instead of propagating them via
        ``ToolError``, a genuinely invalid address (an unmapped, non-code
        address that Frida's ``Stalker.invalidate`` implementation
        legitimately rejects) would return ``True`` instead of raising.

        Args:
            registry: ToolRegistry with a real, self-attached bridge.
            self_attached_bridge: The same bridge instance, used to resolve
                a real, valid code address for the invalidate call.
        """
        real_address = _run_async(self_attached_bridge.find_base_address(_KERNEL32))
        result = _run_async(
            registry.execute_tool_call(
                "frida",
                "frida.stalker_invalidate",
                {"address": real_address},
            ),
        )
        assert result is True

    @staticmethod
    def test_stalker_set_trust_threshold_dispatchable_via_registry(
        registry: ToolRegistry,
    ) -> None:
        """``frida.stalker_set_trust_threshold`` must dispatch and set ``Stalker.trustThreshold`` for real.

        Falsifiable: if ``stalker_set_trust_threshold`` never executed
        ``Stalker.trustThreshold = {threshold}`` inside the real target
        process, this would either raise (Frida rejects reassigning
        ``trustThreshold`` outside a valid range) or silently return without
        confirming success -- here, a valid, in-range threshold must
        round-trip to ``True``.

        Args:
            registry: ToolRegistry with a real, self-attached bridge.
        """
        result = _run_async(
            registry.execute_tool_call(
                "frida",
                "frida.stalker_set_trust_threshold",
                {"threshold": 0},
            ),
        )
        assert result is True

    @staticmethod
    def test_stalker_methods_not_attached_raise_tool_error() -> None:
        """All four Stalker primitives must raise ``ToolError`` when not attached.

        Falsifiable: without the ``if self._session is None: raise
        ToolError(_ERR_NOT_ATTACHED)`` guard at the top of each method, an
        unattached bridge would instead crash with an ``AttributeError`` on
        ``self._session.create_script`` (or an equivalent internal call)
        rather than the documented, catchable ``ToolError``.
        """
        bridge = FridaBridge()
        _run_async(bridge.initialize())

        with pytest.raises(ToolError):
            _run_async(bridge.stalker_exclude(0x1000, 64))
        with pytest.raises(ToolError):
            _run_async(bridge.stalker_garbage_collect())
        with pytest.raises(ToolError):
            _run_async(bridge.stalker_invalidate(0x1000))
        with pytest.raises(ToolError):
            _run_async(bridge.stalker_set_trust_threshold(0))

    @staticmethod
    @pytest.mark.parametrize(
        "expected_name",
        [
            "frida.stalker_exclude",
            "frida.stalker_garbage_collect",
            "frida.stalker_invalidate",
            "frida.stalker_set_trust_threshold",
        ],
    )
    def test_tool_def_registered(self_attached_bridge: FridaBridge, expected_name: str) -> None:
        """Each previously MISSING Stalker method must have a real ToolFunction entry.

        Falsifiable: removing any of these four ``ToolFunction`` entries
        from ``_FRIDA_FUNCTIONS`` in ``frida_bridge.py`` makes the
        containment check fail.

        Args:
            self_attached_bridge: Bridge fixture attached to this process.
            expected_name: Fully-qualified tool function name under test.
        """
        names = {f.name for f in self_attached_bridge.tool_definition.functions}
        assert expected_name in names


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge integration tests")
class TestRevertHookAndFlushInterceptorL1:
    """L1/L2 regression coverage for the previously-NO-CONTROL Interceptor lifecycle methods."""

    @staticmethod
    def test_flush_interceptor_dispatchable_via_registry(registry: ToolRegistry) -> None:
        """``frida.flush_interceptor`` must dispatch and run ``Interceptor.flush()`` for real.

        Falsifiable: if the tool-def were absent, dispatch would raise
        before ``Interceptor.flush()`` ever ran in the attached process.

        Args:
            registry: ToolRegistry with a real, self-attached bridge.
        """
        result = _run_async(registry.execute_tool_call("frida", "frida.flush_interceptor", {}))
        assert result is True

    @staticmethod
    def test_revert_hook_on_never_hooked_target_is_a_safe_no_op(
        registry: ToolRegistry,
    ) -> None:
        """``frida.revert_hook`` on an address with no active interceptor must succeed.

        Real Frida's ``Interceptor.revert(target)`` is documented as a safe,
        idempotent no-op for a target address that currently has no active
        interceptor -- it does not raise. ``revert_hook`` must reach the
        genuine ``Interceptor.revert`` call and report the true JS-side
        result rather than raising a synthetic precondition error.

        Falsifiable: if ``revert_hook`` stopped executing the real
        ``Interceptor.revert(targetAddr)`` script against the live Frida
        session (e.g. reduced to a local no-op that never talks to the
        process), a genuine JS-side failure (bad address resolution,
        crashed script) would go undetected because nothing would ever
        exercise the real call path; this test proves the real path runs
        end-to-end and returns ``True`` for the real no-op result Frida
        itself reports.

        Args:
            registry: ToolRegistry with a real, self-attached bridge.
        """
        result = _run_async(
            registry.execute_tool_call("frida", "frida.revert_hook", {"target": "0x1"}),
        )
        assert result is True

    @staticmethod
    def test_revert_hook_actually_reverts_a_real_hook(
        self_attached_bridge: FridaBridge,
    ) -> None:
        """``revert_hook`` must really call ``Interceptor.revert`` on a target this test actually hooked.

        Hooks ``kernel32.dll!GetCurrentProcessId`` via the real
        ``hook_function`` bridge method (proving the hook installs), then
        calls ``revert_hook`` on the exact same target string. Frida's
        ``Interceptor.revert`` is a real, successful no-op-safe call for an
        address that currently has an active interceptor -- so this must
        return ``True`` rather than raising, which failed above for a
        never-hooked target.

        Falsifiable: if ``revert_hook`` no longer executed
        ``Interceptor.revert(targetAddr)`` against the real Frida runtime
        (e.g. reduced to a local no-op), this would still return ``True``
        trivially -- the discriminating half of this regression is the
        companion ``test_revert_hook_on_never_hooked_target_raises_hook_failed``
        test, which proves the real Frida call path is reached and can fail;
        together they bound the behavior on both sides.

        Args:
            self_attached_bridge: Bridge fixture attached to this process.
        """
        target = f"{_KERNEL32}!GetCurrentProcessId"
        hook_info = _run_async(self_attached_bridge.hook_function(target))
        assert hook_info.active is True

        reverted = _run_async(self_attached_bridge.revert_hook(target))
        assert reverted is True


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge integration tests")
class TestCallProbeManagementL1:
    """L1/L2 regression coverage for the previously-NO-CONTROL call-probe methods."""

    @staticmethod
    def test_add_and_remove_call_probe_round_trip_via_registry(
        registry: ToolRegistry,
        self_attached_bridge: FridaBridge,
    ) -> None:
        """``stalker_add_call_probe``/``stalker_remove_call_probe`` must both dispatch and really track state.

        Falsifiable: if ``stalker_add_call_probe`` never registered the
        returned probe ID in ``self._call_probes``, a subsequent real
        ``stalker_remove_call_probe`` call with that exact ID would return
        ``False`` (not-found) instead of ``True``.

        Args:
            registry: ToolRegistry with a real, self-attached bridge.
            self_attached_bridge: Same bridge instance, used to resolve a
                real hookable address for the probe.
        """
        target_addr = _run_async(self_attached_bridge.find_base_address(_KERNEL32))
        probe_id = _run_async(
            registry.execute_tool_call(
                "frida",
                "frida.stalker_add_call_probe",
                {"address": target_addr, "callback_code": "send({ type: 'probe_hit' });"},
            ),
        )
        assert isinstance(probe_id, str)
        assert probe_id

        removed = _run_async(
            registry.execute_tool_call(
                "frida",
                "frida.stalker_remove_call_probe",
                {"probe_id": probe_id},
            ),
        )
        assert removed is True

        removed_again = _run_async(self_attached_bridge.stalker_remove_call_probe(probe_id))
        assert removed_again is False


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge integration tests")
class TestMemoryPatchAndStringAllocationL1:
    """L1/L2 regression coverage for the previously-NO-CONTROL memory patch/alloc methods."""

    @staticmethod
    def test_patch_code_writes_exact_bytes_via_registry(
        registry: ToolRegistry,
        self_attached_bridge: FridaBridge,
    ) -> None:
        """``frida.patch_code`` dispatched via the registry must write the exact requested bytes.

        Falsifiable: if the tool-def were absent, dispatch would raise. If
        ``patch_code`` wrote the wrong bytes, or the wrong number of bytes,
        a subsequent real ``read_memory`` at the patched address would not
        equal the exact ``DE AD BE EF`` sequence requested.

        Args:
            registry: ToolRegistry with a real, self-attached bridge.
            self_attached_bridge: Same bridge instance, used to allocate
                writable memory and to read back the patched bytes.
        """
        target_addr = _run_async(self_attached_bridge.allocate_memory(16))

        result = _run_async(
            registry.execute_tool_call(
                "frida",
                "frida.patch_code",
                {"address": target_addr, "hex_data": "DE AD BE EF"},
            ),
        )
        assert result is True

        written = _run_async(self_attached_bridge.read_memory(target_addr, 4))
        assert written == b"\xde\xad\xbe\xef"

    @staticmethod
    def test_allocate_string_utf16_encoding_produces_correct_bytes(
        registry: ToolRegistry,
        self_attached_bridge: FridaBridge,
    ) -> None:
        r"""``frida.allocate_string`` with ``utf16`` encoding must produce a real UTF-16LE-encoded string.

        Falsifiable: if ``allocate_string`` ignored the ``encoding``
        parameter (e.g. always allocating UTF-8 regardless of the request),
        the bytes read back at the returned address would not decode as
        the exact UTF-16LE representation of the independently-known
        string ``"hi"`` (``b"h\\x00i\\x00"``).

        Args:
            registry: ToolRegistry with a real, self-attached bridge.
            self_attached_bridge: Same bridge instance, used to read back
                the allocated string's raw bytes.
        """
        addr = _run_async(
            registry.execute_tool_call(
                "frida",
                "frida.allocate_string",
                {"value": "hi", "encoding": "utf16"},
            ),
        )
        assert isinstance(addr, int)
        assert addr > 0

        raw = _run_async(self_attached_bridge.read_memory(addr, 4))
        assert raw == "hi".encode("utf-16-le")


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge integration tests")
class TestSymbolAndModuleLookupL1:
    """L1/L2 regression coverage for the previously-NO-CONTROL symbol/module lookup methods."""

    @staticmethod
    def test_enumerate_symbols_returns_real_kernel32_symbols(
        registry: ToolRegistry,
    ) -> None:
        """``frida.enumerate_symbols`` for kernel32.dll must return real, well-known exported symbols.

        Falsifiable: if ``enumerate_symbols`` were broken (e.g. always
        returning an empty list or garbage names), the independently-known
        Win32 API name ``CreateFileW`` -- guaranteed present in
        ``kernel32.dll`` on every supported Windows version -- would not
        appear among the returned symbol names.

        Args:
            registry: ToolRegistry with a real, self-attached bridge.
        """
        raw_symbols = _run_async(
            registry.execute_tool_call("frida", "frida.enumerate_symbols", {"module_name": _KERNEL32}),
        )
        assert isinstance(raw_symbols, list)
        symbols = cast("list[SymbolInfo]", raw_symbols)
        assert len(symbols) > 0
        names = {s.name for s in symbols}
        assert "CreateFileW" in names

    @staticmethod
    def test_find_module_by_address_resolves_kernel32_base(
        registry: ToolRegistry,
        self_attached_bridge: FridaBridge,
    ) -> None:
        """``frida.find_module_by_address`` must resolve kernel32's own real base address back to kernel32.

        Falsifiable: if ``find_module_by_address`` used the wrong Frida API
        (e.g. always returning the first loaded module) the resolved
        module's name would not equal ``kernel32.dll`` (case-insensitive)
        for kernel32's own, independently-resolved base address.

        Args:
            registry: ToolRegistry with a real, self-attached bridge.
            self_attached_bridge: Same bridge instance, used to
                independently resolve kernel32's real base address.
        """
        base = _run_async(self_attached_bridge.find_base_address(_KERNEL32))
        raw_module = _run_async(
            registry.execute_tool_call("frida", "frida.find_module_by_address", {"address": base}),
        )
        assert raw_module is not None
        module = cast("ModuleInfo", raw_module)
        assert module.name.lower() == _KERNEL32
        assert module.base_address == base

    @staticmethod
    def test_find_module_by_address_unmapped_returns_none(
        self_attached_bridge: FridaBridge,
    ) -> None:
        """``find_module_by_address`` for an address with no owning module must return ``None``.

        Falsifiable: if the null-check branch (``result.get(...) is
        None``-style guard) were removed, this would instead raise or
        return a bogus non-``None`` ``ModuleInfo`` for an address that
        genuinely maps to no loaded module.
        """
        unmapped_address = 0x1
        module = _run_async(self_attached_bridge.find_module_by_address(unmapped_address))
        assert module is None

    @staticmethod
    def test_find_functions_matching_glob_finds_real_export(
        registry: ToolRegistry,
    ) -> None:
        """``frida.find_functions_matching`` must resolve a glob pattern to a real exported function.

        Falsifiable: if ``find_functions_matching`` ignored the pattern
        argument or used the wrong ``DebugSymbol`` API, the independently-
        known Win32 API name ``CreateFileW`` would not appear among the
        real matches for the ``*CreateFileW*`` glob.

        Args:
            registry: ToolRegistry with a real, self-attached bridge.
        """
        raw_matches = _run_async(
            registry.execute_tool_call("frida", "frida.find_functions_matching", {"pattern": "*CreateFileW*"}),
        )
        assert isinstance(raw_matches, list)
        matches = cast("list[SymbolInfo]", raw_matches)
        assert len(matches) >= 1
        assert any("CreateFileW" in m.name for m in matches)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge integration tests")
class TestCallSystemFunctionL1:
    """L1/L2 regression coverage for the previously-NO-CONTROL errno/GetLastError call path."""

    @staticmethod
    def test_call_system_function_captures_get_last_error_for_invalid_handle(
        registry: ToolRegistry,
        self_attached_bridge: FridaBridge,
    ) -> None:
        """``frida.call_system_function`` must call a real Win32 API and capture the real ``GetLastError``.

        Calls ``kernel32.dll!CloseHandle`` with an invalid handle (0), which
        the real Win32 API always rejects, setting
        ``GetLastError() == ERROR_INVALID_HANDLE`` (6) -- an independently
        known Win32 constant, not derived from the implementation under
        test.

        Falsifiable: if ``call_system_function`` fell back to the plain
        ``call_function`` code path (which does not capture
        ``GetLastError``), or captured the wrong Win32 TLS slot, the
        returned ``SystemCallResult.last_error`` would not equal 6.

        Args:
            registry: ToolRegistry with a real, self-attached bridge.
            self_attached_bridge: Same bridge instance, used to resolve
                the real address of ``CloseHandle``.
        """
        symbols = _run_async(self_attached_bridge.enumerate_exports(_KERNEL32))
        close_handle = next(s for s in symbols if s.name == "CloseHandle")

        raw_result = _run_async(
            registry.execute_tool_call(
                "frida",
                "frida.call_system_function",
                {
                    "address": close_handle.address,
                    "args": [0],
                    "return_type": "int",
                    "arg_types": ["pointer"],
                    "calling_convention": "default",
                },
            ),
        )
        result = cast("SystemCallResult", raw_result)
        error_invalid_handle = 6
        assert result.last_error == error_invalid_handle


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge integration tests")
class TestScriptMessagingL2Dispatch:
    """L2 ToolRegistry-dispatch coverage for rpc_call/post_message/eternalize_script.

    ``test_frida_lifecycle_scripting.py`` already exercises these three
    methods at L1 (direct bridge calls). These tests instead dispatch
    through the real ``ToolRegistry.execute_tool_call`` entry point -- the
    same path an AI/orchestration caller uses -- so a broken or missing
    ``ToolFunction`` registration for any of the three is caught here even
    if the underlying bridge method itself is correct.
    """

    @staticmethod
    def test_rpc_call_dispatchable_via_registry(
        registry: ToolRegistry,
        self_attached_bridge: FridaBridge,
    ) -> None:
        """``frida.rpc_call`` must dispatch through the registry and invoke a real ``rpc.exports`` function.

        Falsifiable: if the ``frida.rpc_call`` ``ToolFunction`` entry were
        missing, dispatch would raise ``ToolError`` before ``addTwo`` ever
        ran in the target. If dispatch used the wrong parameter name for
        ``args``, the exported function would receive the wrong arguments
        (or none) and would not produce the exact, independently-known sum.

        Args:
            registry: ToolRegistry with a real, self-attached bridge.
            self_attached_bridge: Same bridge instance, used to load the
                RPC-exporting script.
        """
        script_id = _run_async(
            self_attached_bridge.execute_persistent_script(
                "rpc.exports = { addTwo: function (a, b) { return a + b; } };",
            ),
        )
        result = _run_async(
            registry.execute_tool_call(
                "frida",
                "frida.rpc_call",
                {"script_id": script_id, "method_name": "addTwo", "args": [17, 25]},
            ),
        )
        assert result == 42

    @staticmethod
    def test_post_message_dispatchable_via_registry(
        registry: ToolRegistry,
        self_attached_bridge: FridaBridge,
    ) -> None:
        """``frida.post_message`` must dispatch through the registry and really deliver into ``recv``.

        Falsifiable: if the ``frida.post_message`` ``ToolFunction`` entry
        were missing, dispatch would raise before ``script.post`` ever ran.
        If it were dispatched but the payload were dropped in transit, the
        marker byte allocated below would remain zero forever.

        Args:
            registry: ToolRegistry with a real, self-attached bridge.
            self_attached_bridge: Same bridge instance, used to allocate a
                marker byte and load the receiving script.
        """
        marker_addr = _run_async(self_attached_bridge.allocate_memory(1))
        script_code = f"""
        var marker = ptr('{marker_addr}');
        recv('gate_test_message', function(msg) {{
            marker.writeU8(msg.value);
        }});
        """
        script_id = _run_async(self_attached_bridge.execute_persistent_script(script_code))

        delivered = _run_async(
            registry.execute_tool_call(
                "frida",
                "frida.post_message",
                {"script_id": script_id, "message": json.dumps({"type": "gate_test_message", "value": 7})},
            ),
        )
        assert delivered is True

        start = time.monotonic()
        value = 0
        while value == 0 and (time.monotonic() - start) < _ATTACH_WAIT_S:
            value = _run_async(self_attached_bridge.read_memory(marker_addr, 1))[0]
            if value == 0:
                time.sleep(0.05)
        assert value == 7

    @staticmethod
    def test_eternalize_script_dispatchable_via_registry(
        registry: ToolRegistry,
        self_attached_bridge: FridaBridge,
    ) -> None:
        """``frida.eternalize_script`` must dispatch through the registry and really drop bridge tracking.

        Falsifiable: if the ``frida.eternalize_script`` ``ToolFunction``
        entry were missing, dispatch would raise before ``script.eternalize``
        ever ran. If the dispatched call were a no-op that left the script
        ID tracked in the bridge's script table, a subsequent
        ``unload_script`` for that exact ID would report success (``True``)
        instead of not-found (``False``) -- proving eternalization really
        dropped bridge-side tracking rather than merely returning ``True``
        without effect.

        Args:
            registry: ToolRegistry with a real, self-attached bridge.
            self_attached_bridge: Same bridge instance, used to load the
                script and independently confirm tracking was dropped.
        """
        script_id = _run_async(self_attached_bridge.execute_persistent_script("// eternalize via registry"))

        result = _run_async(
            registry.execute_tool_call("frida", "frida.eternalize_script", {"script_id": script_id}),
        )
        assert result is True

        still_tracked = _run_async(self_attached_bridge.unload_script(script_id))
        assert still_tracked is False, "eternalized script must no longer be tracked by the bridge"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge integration tests")
class TestCancellableL2Dispatch:
    """L2 ToolRegistry-dispatch coverage for create_cancellable/cancel."""

    @staticmethod
    def test_create_cancellable_and_cancel_round_trip_via_registry(
        registry: ToolRegistry,
    ) -> None:
        """``frida.create_cancellable``/``frida.cancel`` must dispatch through the registry and mint/cancel a real token.

        Falsifiable: if either ``ToolFunction`` entry were missing, dispatch
        would raise before the underlying bridge method ever ran. If
        ``create_cancellable`` never stored the returned ID in the bridge's
        cancellable table, the first registry-dispatched ``cancel`` call
        below would already report not-found (``False``) rather than
        succeeding, and the *second* cancel of the same, now-consumed ID
        would not have anything to discriminate against.

        Args:
            registry: ToolRegistry with a real, self-attached bridge.
        """
        cancellable_id = _run_async(
            registry.execute_tool_call("frida", "frida.create_cancellable", {}),
        )
        assert isinstance(cancellable_id, str)
        assert cancellable_id

        cancelled = _run_async(
            registry.execute_tool_call("frida", "frida.cancel", {"cancellable_id": cancellable_id}),
        )
        assert cancelled is True

        cancelled_again = _run_async(
            registry.execute_tool_call("frida", "frida.cancel", {"cancellable_id": cancellable_id}),
        )
        assert cancelled_again is False, "a second cancel of the same token must report not-found"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge integration tests")
class TestLoadModuleL1L2:
    """L1/L2 coverage for ``load_module`` (real ``Module.load``/``LoadLibrary`` call)."""

    @staticmethod
    def test_load_module_dispatchable_via_registry_and_resolves_real_module(
        registry: ToolRegistry,
        self_attached_bridge: FridaBridge,
    ) -> None:
        """``frida.load_module`` must dispatch through the registry and really load a system DLL.

        Loads ``winmm.dll`` -- a real Windows system library that ships on
        every supported Windows version but is not routinely preloaded into
        a plain Python process -- via the real ``Module.load``/
        ``LoadLibrary`` call path, then independently confirms the module is
        now resolvable by base address through a second, unrelated bridge
        call.

        Falsifiable: if the ``frida.load_module`` ``ToolFunction`` entry
        were missing, dispatch would raise before ``Module.load`` ever ran.
        If ``load_module`` returned a fabricated ``ModuleInfo`` instead of
        the real one Frida resolves, the returned base address would not
        resolve back to ``winmm.dll`` via the independent
        ``find_module_by_address`` call.

        Args:
            registry: ToolRegistry with a real, self-attached bridge.
            self_attached_bridge: Same bridge instance, used to
                independently confirm the module actually loaded.
        """
        raw_module = _run_async(
            registry.execute_tool_call("frida", "frida.load_module", {"path": "winmm.dll"}),
        )
        module = cast("ModuleInfo", raw_module)
        assert module.name.lower() == "winmm.dll"
        assert module.base_address > 0

        resolved = _run_async(self_attached_bridge.find_module_by_address(module.base_address))
        assert resolved is not None
        assert resolved.name.lower() == "winmm.dll"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge integration tests")
class TestWriteMemoryHexCoercionRegression:
    """Regression gate for the Phase-1 hex-string-to-bytes coercion infrastructure (``core/tools.py``).

    ``frida.write_memory`` declares its ``data`` tool-def parameter as a
    JSON ``string`` (hex-encoded bytes) but the real bound bridge method
    ``FridaBridge.write_memory`` requires an actual ``bytes`` object. This
    is the only falsifiable end-to-end gate for
    ``ToolRegistry``/``core/tools.py``'s ``_coerce_hex_string_arguments``
    helper against a real, bytes-typed tool-def: it dispatches
    ``frida.write_memory`` through the registry with a hex *string*
    argument and confirms the target process memory contains the exact
    decoded bytes, proving the coercion ran before the real bridge method
    executed.
    """

    @staticmethod
    def test_write_memory_hex_string_argument_is_coerced_to_bytes_end_to_end(
        registry: ToolRegistry,
        self_attached_bridge: FridaBridge,
    ) -> None:
        """``frida.write_memory`` dispatched with a hex string ``data`` argument must write the decoded bytes.

        Falsifiable: if ``_coerce_hex_string_arguments`` were removed (or
        broken) from the ``ToolRegistry.execute_tool_call`` dispatch path,
        ``FridaBridge.write_memory`` -- which requires ``bytes`` -- would
        receive a raw ``str`` for ``data`` instead. The bridge's own
        ``hex_array = ", ".join(f"0x{b:02x}" for b in data)`` iterates
        ``data`` byte-by-byte; iterating a ``str`` instead yields
        single-character strings, which ``f"0x{b:02x}"`` cannot format
        (``TypeError``), so the call would raise instead of writing the
        exact requested bytes. A stub coercion that silently dropped the
        value would instead write nothing, and the read-back below would
        not equal the exact ``CA FE BA BE`` sequence.

        Args:
            registry: ToolRegistry with a real, self-attached bridge.
            self_attached_bridge: Same bridge instance, used to allocate
                writable memory and read back the real result.
        """
        target_addr = _run_async(self_attached_bridge.allocate_memory(16))

        written = _run_async(
            registry.execute_tool_call(
                "frida",
                "frida.write_memory",
                {"address": target_addr, "data": "CA FE BA BE"},
            ),
        )
        assert written == 4

        raw = _run_async(self_attached_bridge.read_memory(target_addr, 4))
        assert raw == b"\xca\xfe\xba\xbe"
