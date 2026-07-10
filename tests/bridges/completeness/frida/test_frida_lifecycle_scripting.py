# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""L1/L2 gate tests for the Frida lifecycle & scripting bridge-completeness slice.

Covers ``audit/bridge-completeness/agent-07-frida-lifecycle-scripting.md`` and its
verifier. Every test drives a real, attached ``FridaBridge`` against the current
test process (self-attach) and/or dispatches through a real ``ToolRegistry`` so
the exact production code path -- not a re-implementation of it -- is what makes
each assertion pass or fail.

Regression coverage for the confirmed defects:

* G1 -- ``frida.attach``'s tool-def declared a ``target`` parameter but the bound
  method only accepted ``pid: int``, so every AI-driven call TypeErrored
  unconditionally. The fix widened ``attach()`` to accept ``int | str`` and
  renamed the tool-def parameter to ``pid``. These tests dispatch through
  ``ToolRegistry.execute_tool_call`` (the real AI-facing entry point) with both a
  numeric and a name-shaped ``pid`` argument and assert the process really
  becomes attached.
* G2 -- ``attach_by_name``, ``unload_script``, ``unload_all_scripts``, and
  ``execute_persistent_script`` were real, GUI-wired bridge methods with no
  ``ToolFunction`` entry, making them unreachable by AI/orchestration callers.
  These tests assert each name is present in ``FridaBridge.tool_definition`` and
  dispatchable via ``ToolRegistry.execute_tool_call``.
* Feature 11 -- the bridge never registered Frida's async
  ``session.on("detached", ...)`` signal, so an externally terminated session
  left ``state.process_attached`` stale. This is regression-tested by detaching
  the underlying Frida session directly (bypassing the bridge's own ``detach()``)
  and asserting the bridge's state updates anyway.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest


if TYPE_CHECKING:
    from collections.abc import Coroutine, Generator

    import frida

    from intellicrack.bridges.frida_bridge import FridaBridge

try:
    from intellicrack.bridges.frida_bridge import FridaBridge

    _frida_available: bool = True
except ImportError:
    _frida_available = False

from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ToolError, ToolName


_CURRENT_PROCESS_NAME: Final[str] = Path(sys.executable).name
_ATTACH_WAIT_S: Final[float] = 5.0


if _frida_available:

    class _TestableFridaBridge(FridaBridge):
        """FridaBridge subclass exposing internal registries via public accessors for gate tests.

        Provides read-only public wrappers around the protected script,
        session, and cancellable-token registries so tests can assert on
        real bridge-internal state transitions (script registered/unloaded,
        session torn down, cancellable consumed) without triggering
        basedpyright's ``reportPrivateUsage`` diagnostic.
        """

        def has_script(self, script_id: str) -> bool:
            """Report whether ``script_id`` is currently tracked by the bridge.

            Args:
                script_id: Script identifier to look up.

            Returns:
                bool: True if the script is registered in the bridge's script table.
            """
            return script_id in self._scripts

        def script_count(self) -> int:
            """Return the number of scripts currently tracked by the bridge.

            Returns:
                int: Count of entries in the bridge's script table.
            """
            return len(self._scripts)

        def is_session_none(self) -> bool:
            """Report whether the bridge's active Frida session has been cleared.

            Returns:
                bool: True if the bridge holds no active session.
            """
            return self._session is None

        def detach_raw_session(self) -> None:
            """Detach the underlying Frida session directly, bypassing ``detach()``.

            Simulates an externally terminated session (process crash, remote
            kill) so the bridge's own ``session.on("detached", ...)`` listener
            -- not its explicit ``detach()`` method -- is what must observe
            and react to the teardown.

            Raises:
                AssertionError: If no session is currently attached.
            """
            session = self._session
            if session is None:
                msg = "no active session to detach"
                raise AssertionError(msg)
            session.detach()

        def has_cancellable(self, cancellable_id: str) -> bool:
            """Report whether ``cancellable_id`` is currently tracked by the bridge.

            Args:
                cancellable_id: Cancellable token identifier to look up.

            Returns:
                bool: True if the token is registered in the bridge's cancellable table.
            """
            return cancellable_id in self._cancellables

        def peek_raw_cancellable(self, cancellable_id: str) -> frida.Cancellable:
            """Return the real ``frida.Cancellable`` object backing a tracked token.

            Unlike popping, this does not remove the token from the bridge's
            registry, so the returned reference can be checked again after a
            later ``cancel()`` call has removed the ID from the registry.

            Args:
                cancellable_id: Cancellable token identifier to look up.

            Returns:
                frida.Cancellable: The real cancellable object.

            Raises:
                AssertionError: If the token is not tracked by the bridge.
            """
            cancellable = self._cancellables.get(cancellable_id)
            if cancellable is None:
                msg = f"cancellable {cancellable_id!r} not tracked"
                raise AssertionError(msg)
            return cancellable


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
def bridge() -> Generator[_TestableFridaBridge]:
    """Create and initialize a FridaBridge without attaching it.

    Yields:
        Generator[_TestableFridaBridge]: An initialized (device-resolved) bridge.
    """
    b = _TestableFridaBridge()
    _run_async(b.initialize())
    yield b
    with contextlib.suppress(ToolError):
        _run_async(b.shutdown())


@pytest.fixture
def registry(tmp_path: Path, bridge: _TestableFridaBridge) -> ToolRegistry:
    """Build a real ToolRegistry with the Frida bridge registered under it.

    Args:
        tmp_path: Pytest-managed temporary tools directory.
        bridge: Initialized FridaBridge fixture.

    Returns:
        ToolRegistry: Registry with ``ToolName.FRIDA`` bound to ``bridge``.
    """
    reg = ToolRegistry(tools_dir=tmp_path)
    reg.register_bridge(ToolName.FRIDA, bridge)
    return reg


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge integration tests")
class TestAttachDispatchG1:
    """Regression tests for Gap G1 (frida.attach tool-def/dispatch mismatch)."""

    @staticmethod
    def test_execute_tool_call_attach_with_numeric_pid_string(registry: ToolRegistry, bridge: _TestableFridaBridge) -> None:
        """``frida.attach`` dispatched via ToolRegistry with a numeric-string pid must attach for real.

        Falsifiable: if the tool-def's parameter were still named ``target``
        while ``attach()`` only accepts ``pid``, ``execute_tool_call`` would
        build ``attach(target=...)`` and raise ``TypeError`` -> wrapped as
        ``ToolError`` here, and this call would raise instead of returning.
        Broken production line: the tool-def parameter name at
        ``frida_bridge.py`` (``frida.attach`` ``ToolFunction``) must be
        ``pid``, matching ``FridaBridge.attach``'s real keyword.
        """
        current_pid = os.getpid()
        _run_async(
            registry.execute_tool_call("frida", "frida.attach", {"pid": str(current_pid)}),
        )
        assert bridge.state.process_attached is True
        assert bridge.state.target_pid == current_pid

    @staticmethod
    def test_execute_tool_call_attach_with_process_name(registry: ToolRegistry, bridge: _TestableFridaBridge) -> None:
        """``frida.attach`` dispatched via ToolRegistry with a name-shaped pid must resolve and attach.

        Falsifiable: if ``attach()`` did not branch on non-numeric strings to
        ``attach_by_name``, this call would try ``int(pid)`` and raise
        ``ValueError`` (wrapped as ``ToolError``). Broken production line:
        the ``isinstance(pid, str) and not pid.strip()...isdigit()`` branch in
        ``FridaBridge.attach`` (``frida_bridge.py``) that delegates to
        ``attach_by_name``.
        """
        _run_async(
            registry.execute_tool_call("frida", "frida.attach", {"pid": _CURRENT_PROCESS_NAME}),
        )
        assert bridge.state.process_attached is True
        assert bridge.state.target_pid == os.getpid()

    @staticmethod
    def test_attach_tool_def_parameter_is_named_pid_not_target(bridge: _TestableFridaBridge) -> None:
        """The registered ``frida.attach`` tool-def must declare a ``pid`` parameter, never ``target``.

        Falsifiable: reverting the tool-def rename (G1 fix) would restore a
        ``target`` parameter and drop ``pid``, failing both assertions here.
        Broken production line: the ``ToolParameter`` list of the
        ``frida.attach`` ``ToolFunction`` entry in ``_FRIDA_FUNCTIONS``.
        """
        defn = bridge.tool_definition
        attach_func = next(f for f in defn.functions if f.name == "frida.attach")
        param_names = {p.name for p in attach_func.parameters}
        assert "pid" in param_names
        assert "target" not in param_names


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge integration tests")
class TestNotRegisteredMethodsG2:
    """Regression tests for Gap G2 (four bridge methods with no tool-def)."""

    @staticmethod
    @pytest.mark.parametrize(
        "expected_name",
        [
            "frida.attach_by_name",
            "frida.unload_script",
            "frida.unload_all_scripts",
            "frida.execute_persistent_script",
        ],
    )
    def test_tool_def_registered(bridge: _TestableFridaBridge, expected_name: str) -> None:
        """Each previously NOT-REGISTERED method must have a real ToolFunction entry.

        Falsifiable: removing any of these four ``ToolFunction`` entries from
        ``_FRIDA_FUNCTIONS`` in ``frida_bridge.py`` makes the containment
        check fail.

        Args:
            bridge: Initialized FridaBridge fixture.
            expected_name: Fully-qualified tool function name under test.
        """
        names = {f.name for f in bridge.tool_definition.functions}
        assert expected_name in names

    @staticmethod
    def test_attach_by_name_dispatchable_via_registry(registry: ToolRegistry, bridge: _TestableFridaBridge) -> None:
        """``frida.attach_by_name`` must dispatch through ToolRegistry and really attach.

        Falsifiable: if the ``ToolFunction`` entry were missing (pre-fix
        state), ``execute_tool_call`` would raise ``ToolError`` for an
        unknown function name before ever reaching ``attach_by_name``.
        Broken production line: the ``frida.attach_by_name`` ``ToolFunction``
        registration in ``_FRIDA_FUNCTIONS``.
        """
        _run_async(
            registry.execute_tool_call("frida", "frida.attach_by_name", {"name": _CURRENT_PROCESS_NAME}),
        )
        assert bridge.state.process_attached is True
        assert bridge.state.target_pid == os.getpid()

    @staticmethod
    def test_execute_persistent_script_and_unload_script_round_trip(registry: ToolRegistry, bridge: _TestableFridaBridge) -> None:
        """``execute_persistent_script`` + ``unload_script`` must dispatch and perform the real operation.

        Falsifiable: if ``frida.execute_persistent_script`` or
        ``frida.unload_script`` lacked a tool-def, ``execute_tool_call`` would
        raise before the script ever loaded/unloaded. If the underlying
        methods were stubs, the bridge's script table would never gain (then
        lose) the returned ``script_id``. Broken production lines: the two
        ``ToolFunction`` registrations plus ``FridaBridge.execute_persistent_script``
        / ``FridaBridge.unload_script`` bodies in ``frida_bridge.py``.
        """
        _run_async(registry.execute_tool_call("frida", "frida.attach", {"pid": str(os.getpid())}))

        script_id = _run_async(
            registry.execute_tool_call(
                "frida",
                "frida.execute_persistent_script",
                {"script_code": "// no-op persistent script for gate test"},
            ),
        )
        assert isinstance(script_id, str)
        assert bridge.has_script(script_id)

        unloaded = _run_async(
            registry.execute_tool_call("frida", "frida.unload_script", {"script_id": script_id}),
        )
        assert unloaded is True
        assert not bridge.has_script(script_id)

    @staticmethod
    def test_unload_all_scripts_dispatchable_and_clears_registry(registry: ToolRegistry, bridge: _TestableFridaBridge) -> None:
        """``frida.unload_all_scripts`` must dispatch and unload every tracked script.

        Falsifiable: if the tool-def were missing, dispatch would raise
        before ``unload_all_scripts`` ran. If ``unload_all_scripts`` were a
        no-op stub, the bridge's script table would remain non-empty after
        the call. Broken production lines: the ``frida.unload_all_scripts``
        ``ToolFunction`` registration and ``FridaBridge.unload_all_scripts``.
        """
        _run_async(registry.execute_tool_call("frida", "frida.attach", {"pid": str(os.getpid())}))

        first_id = _run_async(bridge.execute_persistent_script("// script one"))
        second_id = _run_async(bridge.execute_persistent_script("// script two"))
        assert bridge.has_script(first_id)
        assert bridge.has_script(second_id)

        _run_async(registry.execute_tool_call("frida", "frida.unload_all_scripts", {}))

        assert bridge.script_count() == 0


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge integration tests")
class TestSessionDetachedListener:
    """Regression tests for the previously-MISSING session-detached signal (feature 11)."""

    @staticmethod
    def test_external_session_detach_updates_bridge_state(bridge: _TestableFridaBridge) -> None:
        """Detaching the raw Frida session (not via bridge.detach()) must still update bridge state.

        Simulates an externally terminated session (crash / external kill)
        by calling ``session.detach()`` directly on the underlying Frida
        session object, bypassing the bridge's own ``detach()`` entirely.

        Falsifiable: before the fix, the bridge only learned about detachment
        through its own explicit ``detach()`` call; an external detach left
        ``state.process_attached`` stuck at ``True`` forever. Broken
        production line: ``session.on("detached", on_detached)`` registration
        inside ``_register_session_detached_handler`` (called from
        ``_perform_attach``) in ``frida_bridge.py``.
        """
        _run_async(bridge.attach(os.getpid()))
        assert bridge.state.process_attached is True
        assert not bridge.is_session_none()

        bridge.detach_raw_session()

        start = time.monotonic()
        while bridge.state.process_attached and (time.monotonic() - start) < _ATTACH_WAIT_S:
            time.sleep(0.05)

        assert bridge.state.process_attached is False
        assert bridge.state.target_pid is None
        assert bridge.is_session_none()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge integration tests")
class TestScriptMessagingLifecycle:
    """L1 gates for post_message / rpc_call / eternalize_script / cancellable primitives."""

    @staticmethod
    def test_post_message_delivers_to_running_script(bridge: _TestableFridaBridge) -> None:
        """``post_message`` must really deliver a JSON payload into the running script's recv handler.

        Falsifiable: if ``post_message`` silently dropped the call instead of
        invoking ``script.post``, the persistent script would never see the
        message and the allocated marker byte would remain zero. Broken
        production line: ``await asyncio.to_thread(script.post, parsed)`` in
        ``FridaBridge.post_message`` (``frida_bridge.py``).
        """
        _run_async(bridge.attach(os.getpid()))
        marker_addr = _run_async(bridge.allocate_memory(1))

        script_code = f"""
        var marker = ptr('{marker_addr}');
        recv('gate_test_message', function(msg) {{
            marker.writeU8(msg.value);
        }});
        """
        script_id = _run_async(bridge.execute_persistent_script(script_code))

        delivered = _run_async(
            bridge.post_message(script_id, json.dumps({"type": "gate_test_message", "value": 42})),
        )
        assert delivered is True

        start = time.monotonic()
        value = 0
        while value == 0 and (time.monotonic() - start) < _ATTACH_WAIT_S:
            value = _run_async(bridge.read_memory(marker_addr, 1))[0]
            if value == 0:
                time.sleep(0.05)
        assert value == 42

    @staticmethod
    def test_post_message_invalid_json_raises_tool_error(bridge: _TestableFridaBridge) -> None:
        """``post_message`` must raise ``ToolError`` for a non-JSON message string.

        Falsifiable: if the JSON validation were removed, malformed input
        would either silently fail inside the Frida call or crash with a
        raw ``JSONDecodeError`` instead of the documented ``ToolError``.
        Broken production line: the ``try: json.loads(message)`` /
        ``except (JSONDecodeError, TypeError): raise ToolError(...)`` block
        in ``FridaBridge.post_message``.
        """
        _run_async(bridge.attach(os.getpid()))
        script_id = _run_async(bridge.execute_persistent_script("recv('x', function(m){});"))
        with pytest.raises(ToolError):
            _run_async(bridge.post_message(script_id, "{not valid json"))

    @staticmethod
    def test_rpc_call_invokes_real_exported_function(bridge: _TestableFridaBridge) -> None:
        """``rpc_call`` must invoke a real ``rpc.exports`` function and return its value.

        Falsifiable: if ``rpc_call`` used the wrong exports accessor or never
        awaited the call, this would raise ``ToolError`` or return something
        other than the exact independently-known sum. Broken production
        line: ``getattr(script.exports_sync, method_name)`` /
        ``await asyncio.to_thread(rpc_method, *args_list)`` in
        ``FridaBridge.rpc_call``.
        """
        _run_async(bridge.attach(os.getpid()))
        script_code = """
        rpc.exports = {
            addTwo: function (a, b) {
                return a + b;
            }
        };
        """
        script_id = _run_async(bridge.execute_persistent_script(script_code))

        result = _run_async(bridge.rpc_call(script_id, "addTwo", [17, 25]))
        assert result == 42

    @staticmethod
    def test_rpc_call_unknown_method_raises_tool_error(bridge: _TestableFridaBridge) -> None:
        """``rpc_call`` must raise ``ToolError`` for a method the script never exported.

        Falsifiable: if the callable check were removed, this would instead
        raise an uncaught ``AttributeError``/``TypeError`` from Frida's proxy
        object rather than the documented ``ToolError``. Broken production
        line: the ``if not callable(rpc_method): raise ToolError(...)`` guard
        in ``FridaBridge.rpc_call``.
        """
        _run_async(bridge.attach(os.getpid()))
        script_id = _run_async(bridge.execute_persistent_script("rpc.exports = {};"))
        with pytest.raises(ToolError):
            _run_async(bridge.rpc_call(script_id, "doesNotExist", []))

    @staticmethod
    def test_eternalize_script_removes_from_registry_but_keeps_running(bridge: _TestableFridaBridge) -> None:
        """``eternalize_script`` must call ``script.eternalize`` and drop bridge-side tracking.

        Falsifiable: if ``eternalize_script`` were a no-op, the script would
        remain in the bridge's script table after the call. Broken
        production line: ``await asyncio.to_thread(script.eternalize)``
        followed by ``del self._scripts[script_id]`` in
        ``FridaBridge.eternalize_script``.
        """
        _run_async(bridge.attach(os.getpid()))
        script_id = _run_async(bridge.execute_persistent_script("// eternalize target"))
        assert bridge.has_script(script_id)

        result = _run_async(bridge.eternalize_script(script_id))
        assert result is True
        assert not bridge.has_script(script_id)

    @staticmethod
    def test_eternalize_unknown_script_raises_tool_error(bridge: _TestableFridaBridge) -> None:
        """``eternalize_script`` must raise ``ToolError`` for an unknown script ID.

        Falsifiable: without the membership guard, this would raise
        ``KeyError`` on the ``self._scripts[script_id]`` lookup instead of
        the documented ``ToolError``. Broken production line: the
        ``if script_id not in self._scripts: raise ToolError(...)`` guard in
        ``FridaBridge.eternalize_script``.
        """
        _run_async(bridge.attach(os.getpid()))
        with pytest.raises(ToolError):
            _run_async(bridge.eternalize_script("nonexistent-script-id"))

    @staticmethod
    def test_create_cancellable_and_cancel_round_trip(bridge: _TestableFridaBridge) -> None:
        """``create_cancellable``/``cancel`` must create and later cancel a real ``frida.Cancellable``.

        Falsifiable: if ``create_cancellable`` never stored the token in
        ``self._cancellables``, the subsequent ``cancel`` call would return
        ``False`` (not-found) instead of ``True``. If ``cancel`` never called
        ``cancellable.cancel()``, the retained real object's
        ``is_cancelled`` property would remain ``False``. Broken production
        lines: ``self._cancellables[cancellable_id] = cancellable`` in
        ``create_cancellable`` and ``cancellable.cancel()`` in ``cancel``.
        """
        cancellable_id = _run_async(bridge.create_cancellable())
        assert bridge.has_cancellable(cancellable_id)
        raw_cancellable = bridge.peek_raw_cancellable(cancellable_id)
        assert raw_cancellable.is_cancelled is False

        cancelled = _run_async(bridge.cancel(cancellable_id))
        assert cancelled is True
        assert not bridge.has_cancellable(cancellable_id)
        assert raw_cancellable.is_cancelled is True

    @staticmethod
    def test_cancel_unknown_token_returns_false(bridge: _TestableFridaBridge) -> None:
        """``cancel`` on an unknown token must return ``False``, not raise.

        Falsifiable: if the ``.pop(cancellable_id, None)`` guard were removed
        in favour of direct indexing, this would raise ``KeyError`` instead
        of returning ``False``. Broken production line: the
        ``cancellable = self._cancellables.pop(cancellable_id, None)`` /
        ``if cancellable is None: return False`` guard in ``FridaBridge.cancel``.
        """
        result = _run_async(bridge.cancel("never-issued-token"))
        assert result is False
