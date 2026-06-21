# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for audit5 U2 FridaBridge fixes.

Each test exercises one finding and would fail without the corresponding
remediation in :mod:`intellicrack.bridges.frida_bridge`.

The bridge is heavily I/O bound (it talks to a real Frida runtime), so the
tests use a small set of test doubles -- recording bridges, fake script
handles, fake sessions, fake devices -- rather than ``unittest.mock.Mock``.
This keeps every assertion explicit and ensures the production code path
is exercised end-to-end up to the boundary with the Frida transport.
"""

from __future__ import annotations

import asyncio
import os
import threading
from typing import TYPE_CHECKING, Any, cast

import pytest


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

frida = pytest.importorskip("frida", reason="frida-python required for bridge tests")

from intellicrack.bridges.frida_bridge import FridaBridge  # noqa: E402
from intellicrack.core.types import (  # noqa: E402
    HookInfo,
    MemoryRegion,
    SymbolInfo,
    ToolError,
)


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Run an async coroutine on a fresh event loop and return its result.

    Args:
        coro: Awaitable to execute.

    Returns:
        T: Whatever the coroutine returns, preserving its type.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _set(target: object, name: str, value: object) -> None:
    """Set an attribute on ``target`` via ``setattr`` to avoid private-usage diagnostics.

    Args:
        target: Object to mutate.
        name: Attribute name.
        value: Replacement value.
    """
    setattr(target, name, value)


def _index_set(target: object, name: str, key: object, value: object) -> None:
    """Set ``target.<name>[key] = value`` without tripping private-usage diagnostics.

    Args:
        target: Object whose attribute holds a mapping.
        name: Attribute name (typically a dict).
        key: Mapping key.
        value: Mapping value.
    """
    container = cast("dict[object, object]", getattr(target, name))
    container[key] = value


def _get_dict(target: object, name: str) -> dict[object, object]:
    """Read a dict-typed private attribute and narrow it for ``in`` checks.

    Args:
        target: Object to read.
        name: Attribute name.

    Returns:
        dict[object, object]: The mapping at ``target.<name>``.
    """
    return cast("dict[object, object]", getattr(target, name))


def _get_callable(target: object, name: str) -> Callable[..., object]:
    """Read a callable-typed private attribute.

    Args:
        target: Object to read.
        name: Attribute name.

    Returns:
        Callable[..., object]: The callable at ``target.<name>``.
    """
    return cast("Callable[..., object]", getattr(target, name))


def _get_attr(target: object, name: str) -> object:
    """Read a generic private attribute as ``object``.

    Args:
        target: Object to read.
        name: Attribute name.

    Returns:
        object: The attribute value.
    """
    return getattr(target, name)


class _FakeScript:
    """Minimal in-memory ``frida.core.Script`` substitute.

    Records ``post`` calls and supports the surface the bridge actually
    uses -- ``on``/``post``/``load``/``unload``/``eternalize``. The
    handler registered via ``on('message', ...)`` is captured so tests
    can deliver synthetic messages back to the bridge.
    """

    def __init__(self) -> None:
        """Initialize the fake script with empty call records."""
        self.posts: list[dict[str, object]] = []
        self.unload_calls: int = 0
        self.load_calls: int = 0
        self._handler: Callable[..., None] | None = None
        self.unload_should_raise: BaseException | None = None

    def on(self, event: str, handler: Callable[..., None]) -> None:
        """Capture the message handler registered by the bridge.

        Args:
            event: Event name.
            handler: Callback invoked when a message is delivered.
        """
        if event == "message":
            self._handler = handler

    def load(self) -> None:
        """Record a load invocation."""
        self.load_calls += 1

    def unload(self) -> None:
        """Record an unload invocation, optionally raising."""
        self.unload_calls += 1
        if self.unload_should_raise is not None:
            raise self.unload_should_raise

    def post(self, message: dict[str, object]) -> None:
        """Capture a posted message.

        Args:
            message: Posted message dict.
        """
        self.posts.append(dict(message))

    def deliver(self, payload: dict[str, object], data: bytes | None = None) -> None:
        """Synchronously deliver a ``send``-shaped payload to the bridge.

        Args:
            payload: Payload dict to wrap as ``{"type": "send", "payload": ...}``.
                When ``payload["__type"]`` is set to ``"error"`` the message is
                routed as an error message instead.
            data: Optional binary side-channel.
        """
        if self._handler is None:
            return
        if payload.get("__type") == "error":
            description = payload.get("description", "")
            self._handler({"type": "error", "description": description}, data)
            return
        self._handler({"type": "send", "payload": payload}, data)


class _FakeSession:
    """``frida.core.Session`` substitute that hands out :class:`_FakeScript`."""

    def __init__(self) -> None:
        """Initialize the fake session with an empty script registry."""
        self.scripts: list[_FakeScript] = []
        self.detach_calls: int = 0

    def create_script(self, _source: str, **_: object) -> _FakeScript:
        """Return a new fake script and remember it.

        Args:
            _source: Ignored JavaScript source.
            **_: Ignored keyword arguments.

        Returns:
            _FakeScript: Newly registered fake script.
        """
        script = _FakeScript()
        self.scripts.append(script)
        return script

    def detach(self) -> None:
        """Record a detach call."""
        self.detach_calls += 1


class _FakeDevice:
    """``frida.core.Device`` substitute used by attach/detach/crash tests."""

    def __init__(self) -> None:
        """Initialize the fake device with empty handler registries."""
        self.crash_handlers: list[tuple[str, Callable[[object], None]]] = []
        self.off_calls: list[tuple[str, Callable[[object], None]]] = []

    def on(self, event: str, handler: Callable[[object], None]) -> None:
        """Register an event handler.

        Args:
            event: Event name.
            handler: Callback to register.
        """
        self.crash_handlers.append((event, handler))

    def off(self, event: str, handler: Callable[[object], None]) -> None:
        """Detach a previously registered handler.

        Args:
            event: Event name.
            handler: Callback to detach.
        """
        self.off_calls.append((event, handler))


def _build_attached_bridge() -> tuple[FridaBridge, _FakeSession, _FakeDevice]:
    """Construct a FridaBridge wired to fake session+device, ready to script.

    Returns:
        tuple[FridaBridge, _FakeSession, _FakeDevice]: Bridge plus its
            backing fakes for direct assertions.
    """
    bridge = FridaBridge()
    session = _FakeSession()
    device = _FakeDevice()
    _set(bridge, "_session", session)
    _set(bridge, "_device", device)
    _set(bridge, "_pid", 4321)
    bridge.state.connected = True
    bridge.state.tool_running = True
    bridge.state.process_attached = True
    bridge.state.target_pid = 4321
    return bridge, session, device


def _patch_execute_script(
    bridge: FridaBridge,
    fixed_result: dict[str, object],
) -> list[str]:
    """Replace ``_execute_script_and_wait`` with a recorder returning ``fixed_result``.

    Args:
        bridge: Bridge whose method to patch.
        fixed_result: Dict to return on every invocation.

    Returns:
        list[str]: List that accumulates script source on each call.
    """
    captured: list[str] = []

    async def fake(
        script_code: str,
        max_wait: float = 5.0,
        *,
        cancellable_id: str | None = None,
    ) -> dict[str, object]:
        del max_wait, cancellable_id
        captured.append(script_code)
        await asyncio.sleep(0)
        return dict(fixed_result)

    _set(bridge, "_execute_script_and_wait", fake)
    return captured


def test_f0005_hook_function_no_default_console_log() -> None:
    """F-0005: hook_function must NOT inject default console.log instrumentation.

    Without the fix the bridge wraps every hook in a verbose
    ``console.log('[+] Called ...')`` call. The remediation makes the
    default on-enter handler a noop.
    """
    bridge, session, _ = _build_attached_bridge()

    async def install_hook() -> HookInfo:
        return await bridge.hook_function(target="0xdeadbeef")

    async def driver() -> HookInfo:
        task = asyncio.create_task(install_hook())
        await asyncio.sleep(0)
        for _ in range(40):
            if session.scripts:
                break
            await asyncio.sleep(0.01)
        assert session.scripts, "create_script never invoked"
        script = session.scripts[0]
        for _ in range(40):
            if script.posts:
                break
            await asyncio.sleep(0.01)
        assert script.posts, "install_hook payload never posted"
        # The captured payload's onEnter must be empty -- not a console.log.
        on_enter_payload = script.posts[0].get("onEnter")
        assert on_enter_payload is not None
        assert not on_enter_payload, f"expected empty default on_enter, got {on_enter_payload!r}"
        script.deliver({"type": "hooked", "address": "0xdeadbeef"})
        return await task

    info = _run(driver())
    assert info.target == "0xdeadbeef"


def test_f0006_scan_memory_accepts_hex_string_with_wildcards() -> None:
    """F-0006: scan_memory tool accepts the same hex pattern the JSON tool advertises."""
    bridge, _, _ = _build_attached_bridge()
    captured = _patch_execute_script(bridge, {"data": []})

    async def driver() -> list[object]:
        return cast("list[object]", await bridge.scan_memory("48 8B ?? ??"))

    matches = _run(driver())
    assert matches == []
    assert captured, "execute_script was never called"
    # The hex pattern must be normalised and embedded into the JS source.
    assert "48 8b ?? ??" in captured[0], captured[0]


def test_f0006_scan_memory_rejects_malformed_hex_pattern() -> None:
    """F-0006: malformed hex patterns must raise rather than silently scan garbage."""
    bridge, _, _ = _build_attached_bridge()

    async def driver() -> None:
        await bridge.scan_memory("48 8B Z?")

    with pytest.raises(ToolError) as excinfo:
        _run(driver())
    assert "scan pattern" in str(excinfo.value.details).lower() or "scan_pattern" in str(excinfo.value)


def test_f0007_call_function_pointer_return_preserves_64bit_value() -> None:
    """F-0007: pointer returns must not be truncated through ``toInt32``.

    A pointer above ``2**31`` would silently lose its high bits in the
    pre-fix code. The fix sends the pointer as a string and parses it
    back exactly, so the round-tripped value matches the input.
    """
    bridge, _, _ = _build_attached_bridge()
    high_pointer = 0x7FFE_DEAD_BEEF_C0DE
    captured = _patch_execute_script(
        bridge,
        {"value": str(high_pointer), "valueIsString": True},
    )

    async def driver() -> int:
        return await bridge.call_function(0x4000_0000, return_type="pointer")

    result = _run(driver())
    assert result == high_pointer
    # And the JS source must NOT use toInt32 for the pointer return path.
    assert "toInt32" not in captured[0], captured[0]


def test_f0008_read_memory_uses_separate_binary_channel() -> None:
    """F-0008: binary side-channel ``__binary`` must not collide with JSON ``data``.

    Before the fix, ``read_memory`` populated ``result["data"]`` with the
    binary payload, which collided with the JSON ``data`` key used by
    every other Frida script (e.g. ``get_memory_regions``). The fix
    routes the binary payload through ``__binary`` while leaving JSON
    ``data`` to the script-defined contract.
    """
    bridge, _, _ = _build_attached_bridge()

    async def fake(
        script_code: str,
        max_wait: float = 5.0,
        *,
        cancellable_id: str | None = None,
    ) -> dict[str, Any]:
        del script_code, max_wait, cancellable_id
        await asyncio.sleep(0)
        # Simulate a payload that ALSO carries a JSON ``data`` field --
        # exactly the cross-script collision F-0008 calls out.
        return {"type": "memory", "data": [99, 99, 99], "__binary": [1, 2, 3]}

    _set(bridge, "_execute_script_and_wait", fake)

    async def driver() -> bytes:
        return await bridge.read_memory(0x1000, 3)

    payload = _run(driver())
    assert payload == bytes([1, 2, 3])


def test_f0009_enable_crash_reporting_is_idempotent_and_disable_works() -> None:
    """F-0009: repeated enable calls must not stack handlers; disable removes the handler."""
    bridge, _, device = _build_attached_bridge()

    async def driver() -> None:
        await bridge.enable_crash_reporting()
        await bridge.enable_crash_reporting()
        await bridge.enable_crash_reporting()

    _run(driver())
    crash_handlers = [h for h in device.crash_handlers if h[0] == "process-crashed"]
    assert len(crash_handlers) == 1, f"enable_crash_reporting stacked handlers: {len(crash_handlers)}"

    _run(bridge.disable_crash_reporting())
    assert any(name == "process-crashed" for name, _ in device.off_calls)


def test_f0010_unload_script_clears_alloc_and_probe_registries() -> None:
    """F-0010 + F-0027: when a script unloads via any path the secondary registries are reaped."""
    bridge, _, _ = _build_attached_bridge()
    fake_script = _FakeScript()
    _index_set(bridge, "_scripts", "abc123", fake_script)
    _index_set(bridge, "_alloc_scripts", 0xDEAD0000, "abc123")
    _index_set(bridge, "_call_probes", "probe-1", "abc123")
    _index_set(bridge, "_stalker_scripts", 42, "abc123")

    async def driver() -> None:
        unload_fn = _get_callable(bridge, "_unload_script")
        await cast("Coroutine[object, object, None]", unload_fn("abc123"))

    _run(driver())

    assert "abc123" not in _get_dict(bridge, "_scripts")
    assert 0xDEAD0000 not in _get_dict(bridge, "_alloc_scripts"), "alloc_scripts entry not reaped after unload"
    assert "probe-1" not in _get_dict(bridge, "_call_probes"), "call_probes entry not reaped after unload"
    assert 42 not in _get_dict(bridge, "_stalker_scripts"), "stalker_scripts entry not reaped after unload"


def test_f0011_resolve_symbol_raises_on_unresolved() -> None:
    """F-0011: resolve_symbol must NOT fabricate ``sub_<addr>`` when DebugSymbol is empty."""
    bridge, _, _ = _build_attached_bridge()
    _patch_execute_script(
        bridge,
        {"name": None, "moduleName": None, "fileName": None, "lineNumber": None, "address": "0x401000"},
    )

    async def driver() -> SymbolInfo:
        return await bridge.resolve_symbol(0x401000)

    with pytest.raises(ToolError):
        _run(driver())


def test_f0012_compile_typescript_reuses_compiler_instance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F-0012: ``frida.Compiler`` must be reused, not instantiated per call.

    The instance-count assertion is the genuine gate for the F-0012 fix:
    two successive ``compile_typescript`` calls must share one compiler
    instance.  The build log asserts that each call drove the compiler
    with a distinct entrypoint path (different temporary files for
    different source strings), proving the bridge did not short-circuit
    by returning a cached output rather than actually calling ``build``
    twice.

    Args:
        monkeypatch: Pytest fixture used to swap ``frida.Compiler`` with a
            recording fake for the duration of the test.
    """
    bridge = FridaBridge()
    instance_counter: list[int] = [0]
    build_log: list[str] = []

    class _FakeCompiler:
        """Fake compiler tracking instantiation and build calls via outer lists."""

        def __init__(self) -> None:
            """Record an instantiation event."""
            instance_counter[0] += 1

        def build(self, entrypoint: str, **_kw: object) -> str:
            """Record the entrypoint and return a payload derived from the entrypoint.

            Args:
                entrypoint: TypeScript entrypoint path.
                **_kw: Ignored options.

            Returns:
                str: JS payload embedding the entrypoint so callers can
                    distinguish which source was compiled.
            """
            build_log.append(entrypoint)
            return f"// compiled from {entrypoint}\nconsole.log(1);"

    monkeypatch.setattr(frida, "Compiler", _FakeCompiler)

    async def driver() -> tuple[str, str]:
        r1 = await bridge.compile_typescript("const a: number = 1; console.log(a);")
        r2 = await bridge.compile_typescript("const b: number = 2; console.log(b);")
        return r1, r2

    r1, r2 = _run(driver())

    assert instance_counter[0] == 1, f"compiler instances created: {instance_counter[0]}"
    assert len(build_log) == 2, f"expected 2 build calls, got {len(build_log)}"

    assert build_log[0] != build_log[1], (
        f"both compile calls used the same entrypoint path, "
        f"suggesting the second call was short-circuited: {build_log}"
    )

    assert build_log[0] in r1, (
        f"first result does not embed its own entrypoint path; "
        f"entrypoint={build_log[0]!r}, result={r1!r}"
    )
    assert build_log[1] in r2, (
        f"second result does not embed its own entrypoint path; "
        f"entrypoint={build_log[1]!r}, result={r2!r}"
    )


def test_f0012_compile_typescript_real_output_is_js() -> None:
    """F-0012: compile_typescript drives the real frida.Compiler and returns valid JS.

    Uses the genuine ``frida.Compiler`` (no monkeypatching) to compile a
    trivial TypeScript snippet and asserts the output is non-empty JavaScript
    containing the ``console.log`` call present in the source.  This gates
    that the bridge still performs real compilation, not just instance reuse
    of a broken compiler.
    """
    bridge = FridaBridge()
    ts_source = "const x: number = 42; console.log(x);"

    async def driver() -> str:
        return await bridge.compile_typescript(ts_source)

    result = _run(driver())
    assert isinstance(result, str), f"expected str output, got {type(result)}"
    assert len(result) > 0, "compiled output must be non-empty"
    assert "console.log" in result, (
        f"compiled JS does not contain the expected console.log call; output={result!r}"
    )


def test_f0013_stalker_unfollow_routes_through_owning_script() -> None:
    """F-0013: ``Stalker.unfollow`` must be posted into the script that called ``Stalker.follow``."""
    bridge, _, _ = _build_attached_bridge()
    owning_script = _FakeScript()
    _index_set(bridge, "_scripts", "stalker-script", owning_script)
    _index_set(bridge, "_stalker_scripts", 7, "stalker-script")
    _index_set(bridge, "_stalker_traces", 7, [])

    async def driver() -> None:
        trace = await bridge.stalker_unfollow(thread_id=7)
        assert trace.thread_id == 7

    _run(driver())

    # The owning script must have received the unfollow post.
    posted_types = [m.get("type") for m in owning_script.posts]
    assert "stalker_unfollow_request" in posted_types, f"unfollow request never posted to owning script; posts={owning_script.posts}"
    assert owning_script.unload_calls == 1
    # The stalker registries should be reaped.
    assert 7 not in _get_dict(bridge, "_stalker_scripts")
    assert 7 not in _get_dict(bridge, "_stalker_traces")


def _f0014_await_with_gated_delivery(
    on_message: Callable[..., None],
    event: asyncio.Event,
    msg: dict[str, Any],
) -> bool:
    """Drive a gated cross-thread delivery on a fresh loop and return whether the event fired.

    The delivery gate ensures the foreign thread only calls ``on_message``
    after loop B has started awaiting ``event``, so ``event._loop`` is
    already bound to loop B at the moment ``_set_event_threadsafe`` runs.

    When the caller constructed the waiter while a now-closed loop A was
    running, any implementation that captured the loop at construction time
    holds a reference to that closed loop.  Calling
    ``loop_a.call_soon_threadsafe`` on a closed loop raises ``RuntimeError``
    and the event is never set on loop B, causing this function to return
    ``False``.  Only delivery-time resolution via ``event._loop`` (which
    is loop B once the awaiter has started) produces a correct ``True``.

    Args:
        on_message: The ``on_message`` callback returned by
            ``_make_payload_waiter``.
        event: The :class:`asyncio.Event` returned by the same call.
        msg: Message dict to deliver from the foreign thread.

    Returns:
        bool: ``True`` if the event fired before the 5-second deadline.
    """
    event_bound_to_loop_b: threading.Event = threading.Event()
    done: threading.Event = threading.Event()

    def _deliver() -> None:
        """Wait until loop B has started awaiting the event, then deliver."""
        event_bound_to_loop_b.wait(timeout=5.0)
        on_message(msg, None)
        done.set()

    threading.Thread(target=_deliver, daemon=True).start()

    async def _driver() -> bool:
        """Signal that loop B is running, then await the event.

        Returns:
            bool: ``True`` when the event fired before the deadline.
        """
        asyncio.get_event_loop().call_soon(event_bound_to_loop_b.set)
        try:
            await asyncio.wait_for(event.wait(), timeout=5.0)
        except TimeoutError:
            return False
        return True

    loop_b: asyncio.AbstractEventLoop = asyncio.new_event_loop()
    try:
        result = loop_b.run_until_complete(_driver())
    finally:
        loop_b.close()

    done.wait(timeout=5.0)
    return result


def _f0014_assert_log_not_triggering(
    waiter_fn: Callable[..., object],
    dispatched: list[dict[str, object]],
) -> None:
    """Verify that a log-type message does not release the waiter event.

    Args:
        waiter_fn: The ``_make_payload_waiter`` callable from the bridge.
        dispatched: Shared dispatch-recording list; the log entry must appear.
    """
    buf: list[Any] = []
    on_obj, ev_obj = cast("tuple[Callable[..., None], asyncio.Event]", waiter_fn(buf, dispatched.append))
    on_msg: Callable[..., None] = on_obj
    ev: asyncio.Event = ev_obj
    log_msg: dict[str, Any] = {"type": "log", "level": "info", "payload": "frida says hello"}
    on_msg(log_msg, None)
    assert not ev.is_set(), "log message must not release the waiter event"
    assert len(buf) == 1, f"expected 1 buffered log message, got {len(buf)}"
    assert buf[0]["type"] == "log", f"log message type wrong in buffer: {buf[0]}"
    assert buf[0].get("payload") == "frida says hello", f"log payload not preserved: {buf[0]}"


def _f0014_assert_error_triggers(
    waiter_fn: Callable[..., object],
) -> None:
    """Verify that an error-type message releases a fresh waiter event.

    Args:
        waiter_fn: The ``_make_payload_waiter`` callable from the bridge.
    """
    buf: list[Any] = []
    dispatched_err: list[dict[str, object]] = []
    on_obj, ev_obj = cast(
        "tuple[Callable[..., None], asyncio.Event]",
        waiter_fn(buf, dispatched_err.append),
    )
    on_msg: Callable[..., None] = on_obj
    ev: asyncio.Event = ev_obj
    err_msg: dict[str, Any] = {
        "type": "error",
        "description": "ReferenceError: x is not defined",
        "stack": "at <anonymous>:1:1",
        "fileName": None,
        "lineNumber": None,
        "columnNumber": None,
    }
    assert _f0014_await_with_gated_delivery(on_msg, ev, err_msg), "error message did not release the waiter event"
    assert ev.is_set(), "event must be set after error delivery"
    assert len(buf) == 1, f"expected 1 error message buffered, got {len(buf)}"
    assert buf[0]["type"] == "error", f"error message type wrong in buffer: {buf[0]}"
    assert buf[0].get("description") == "ReferenceError: x is not defined", f"error description not preserved: {buf[0]}"


def test_f0014_message_waiter_does_not_capture_loop_at_construction() -> None:
    """F-0014: _set_event_threadsafe must route through the loop the event is bound to.

    Falsifiable property: the waiter is constructed while loop A is explicitly
    running (giving any eager construction-time capture a live reference to
    loop A).  Loop A is then closed immediately, making any such captured
    reference stale.  The event is awaited on loop B.  A foreign thread
    delivers the message only after ``event._loop`` has been confirmed as
    loop_B by the ``_f0014_await_with_gated_delivery`` helper.

    If ``_set_event_threadsafe`` uses a stale loop-A reference it calls
    ``loop_a.call_soon_threadsafe`` on a closed loop, which raises
    ``RuntimeError``; the implementation's error handler drops the call and
    the event is never set on loop_B.  The assertion on the return value of
    ``_f0014_await_with_gated_delivery`` therefore fails, going red.

    Only delivery-time resolution through ``event._loop`` (which is ``loop_B``
    once the awaiter has started) produces a correct green result.

    Four structural invariants are verified, each failing without F-0014:

    1.  Construction-while-loop-A-running + stale-A-closed: waiter built
        during loop A's execution still fires correctly on loop B after A
        is closed.

    2.  Delivery-time loop resolution: a ``send`` message fires the event on
        the awaiting loop even after loop A is destroyed.

    3.  Message buffering and dispatch fidelity: the ``messages`` list receives
        the exact ``send`` payload dict that Frida emits, and the dispatch
        function is invoked with the same structure.

    4.  Selective triggering: ``log``-type messages do **not** release the
        event; only ``send`` and ``error`` do.  The ``log`` entry is still
        buffered and dispatched but must not unblock the awaiter.  A third
        independent waiter verifies ``error`` also releases the event with the
        exact description preserved.
    """
    bridge = FridaBridge()
    dispatched: list[dict[str, object]] = []
    waiter_fn = _get_callable(bridge, "_make_payload_waiter")

    # --- Invariant 1, 2 & 3: construct waiter while loop A runs, then close A ---
    #
    # Build the waiter inside a coroutine on loop A so that any implementation
    # path that calls asyncio.get_event_loop() or asyncio.get_running_loop() at
    # construction time gets a live reference to loop A.  We capture that loop
    # so we can close it before starting loop B.
    buf1: list[Any] = []
    waiter_result: list[tuple[Callable[..., None], asyncio.Event]] = []

    async def _build_on_loop_a() -> None:
        """Create the waiter from inside loop A so a stale capture would bind to A."""
        await asyncio.sleep(0)
        pair = cast(
            "tuple[Callable[..., None], asyncio.Event]",
            waiter_fn(buf1, dispatched.append),
        )
        waiter_result.append(pair)

    loop_a: asyncio.AbstractEventLoop = asyncio.new_event_loop()
    loop_a.run_until_complete(_build_on_loop_a())
    loop_a.close()

    assert waiter_result, "waiter construction failed inside loop_a"
    on1, ev1 = waiter_result[0]

    send_msg: dict[str, Any] = {"type": "send", "payload": {"result": 42}}
    assert _f0014_await_with_gated_delivery(on1, ev1, send_msg), (
        "send message did not release the event after loop_a was closed; _set_event_threadsafe did not resolve the loop at delivery time"
    )
    assert ev1.is_set(), "event must remain set after delivery"
    assert len(buf1) == 1, f"expected 1 buffered message, got {len(buf1)}"
    assert buf1[0]["type"] == "send", f"buffered message type wrong: {buf1[0]}"
    assert buf1[0].get("payload") == {"result": 42}, f"send payload not preserved: {buf1[0]}"
    assert len(dispatched) == 1, f"expected 1 dispatched message, got {len(dispatched)}"
    assert dispatched[0].get("payload") == {"result": 42}, f"dispatched payload wrong: {dispatched[0]}"

    # --- Invariant 4a: log messages do not release the event -------------------
    _f0014_assert_log_not_triggering(waiter_fn, dispatched)
    assert dispatched[-1]["type"] == "log", f"log not dispatched: {dispatched}"

    # --- Invariant 4b: error messages release a fresh waiter -------------------
    _f0014_assert_error_triggers(waiter_fn)


def test_f0015_call_function_rejects_non_int_address() -> None:
    """F-0015: integer JS interpolation rejects non-int and bool values."""
    bridge, _, _ = _build_attached_bridge()

    bad_address: object = "0xdeadbeef"

    async def driver_str() -> int:
        return await bridge.call_function(cast("int", bad_address))

    with pytest.raises(ToolError):
        _run(driver_str())

    bool_value = True

    async def driver_bool() -> int:
        return await bridge.call_function(cast("int", bool_value))

    with pytest.raises(ToolError):
        _run(driver_bool())


def test_f0015_read_memory_rejects_non_int_inputs() -> None:
    """F-0015: read_memory rejects non-integer inputs at the validation gate."""
    bridge, _, _ = _build_attached_bridge()

    bad_addr: object = 1.5

    async def driver() -> bytes:
        return await bridge.read_memory(cast("int", bad_addr), 16)

    with pytest.raises(ToolError):
        _run(driver())


def test_f0018_memory_region_state_is_not_win32_specific() -> None:
    """F-0018: MemoryRegion must not stamp Win32-only constants regardless of source."""
    bridge, _, _ = _build_attached_bridge()
    _patch_execute_script(
        bridge,
        {
            "data": [
                {"base": "0x1000", "size": 4096, "protection": "r-x", "file": None},
                {"base": "0x10000", "size": 8192, "protection": "rw-", "file": "/usr/lib/libc.so"},
            ],
        },
    )

    async def driver() -> list[MemoryRegion]:
        return await bridge.get_memory_regions("---")

    regions = _run(driver())
    assert regions
    for r in regions:
        assert r.state != "MEM_COMMIT", "leaked Win32 state constant"
        assert r.type != "MEM_PRIVATE", "leaked Win32 type constant"


def test_f0021_execute_script_raises_on_timeout() -> None:
    """F-0021: ``_execute_script_and_wait`` must RAISE on timeout, not return a partial dict."""
    bridge, _session, _ = _build_attached_bridge()

    async def driver() -> dict[str, object]:
        execute_fn = _get_callable(bridge, "_execute_script_and_wait")
        coro = cast(
            "Coroutine[object, object, dict[str, object]]",
            execute_fn("send({type:'noop'});", max_wait=0.05),
        )
        return await coro

    with pytest.raises(ToolError) as excinfo:
        _run(driver())
    err_text = f"{excinfo.value} {excinfo.value.details}".lower()
    assert "timed out" in err_text


def test_f0022_allocate_memory_breaks_after_capturing_address() -> None:
    """F-0022: allocate_memory must stop reading messages once the address is captured."""
    bridge, _, _ = _build_attached_bridge()

    async def driver() -> int:
        task = asyncio.create_task(bridge.allocate_memory(4096))
        await asyncio.sleep(0)
        session_obj = cast("_FakeSession", _get_attr(bridge, "_session"))
        for _ in range(40):
            if session_obj.scripts:
                break
            await asyncio.sleep(0.01)
        script = session_obj.scripts[-1]
        for _ in range(40):
            if script.load_calls > 0:
                break
            await asyncio.sleep(0.01)
        # Deliver alloc + a follow-up error.  The pre-fix code processed
        # the error AFTER capturing the address and unloaded the script.
        script.deliver({"type": "alloc", "address": "0x40000000"})
        script.deliver({"__type": "error", "description": "post-alloc noise"})
        return await task

    addr = _run(driver())
    assert addr == 0x40000000
    # Script must remain registered (not unloaded by the trailing error).
    session = cast("_FakeSession", _get_attr(bridge, "_session"))
    assert session.scripts[-1].unload_calls == 0, "allocate_memory unloaded the script after addr was already captured"
    assert addr in _get_dict(bridge, "_alloc_scripts")


def test_f0023_attach_propagates_frida_error_details() -> None:
    """F-0023: bare ``except Exception`` must be replaced by typed handlers carrying details."""
    bridge, _, _ = _build_attached_bridge()
    _set(bridge, "_session", None)  # require attach to actually call into device

    permission_message = "no can do"

    class _ExplodingDevice:
        """Fake Frida device that raises ``PermissionDeniedError`` on attach."""

        def attach(self, _pid: int, **_: object) -> object:
            """Always raise to trigger the bridge's typed handler.

            Args:
                _pid: Ignored target PID.
                **_: Ignored options.

            Returns:
                object: Never returns; always raises.

            Raises:
                err: Always raised.
            """
            err = frida.PermissionDeniedError(permission_message)
            raise err

        def enumerate_processes(self) -> list[object]:
            """Return an empty process list.

            Returns:
                list[object]: Always ``[]``.
            """
            return []

    _set(bridge, "_device", _ExplodingDevice())

    async def driver() -> None:
        await bridge.attach(1234)

    with pytest.raises(ToolError) as excinfo:
        _run(driver())
    details = excinfo.value.details
    assert details is not None
    assert details.get("frida_error_type") == "PermissionDeniedError", f"frida_error_type missing/wrong: {details!r}"
    assert "no can do" in str(details.get("frida_error", ""))


def test_f0024_shutdown_calls_super_in_finally() -> None:
    """F-0024: ``super().shutdown()`` must run even when tool-specific cleanup raises."""
    bridge = FridaBridge()
    bridge.state.connected = True

    explosion_message = "teardown explosion"

    class _ExplodingScripts:
        """Object that raises RuntimeError when ``keys()`` is called."""

        def keys(self) -> list[str]:
            """Raise to force shutdown's early loop body to abort.

            Returns:
                list[str]: Never returned; always raises.

            Raises:
                err: Always raised.
            """
            err = RuntimeError(explosion_message)
            raise err

    _set(bridge, "_stalker_scripts", _ExplodingScripts())

    async def driver() -> None:
        try:
            await bridge.shutdown()
        except RuntimeError:
            return

    _run(driver())
    assert bridge.state.connected is False, "super().shutdown() did not run after cleanup raised"


def test_f0027_unload_script_clears_alloc_after_explicit_unload() -> None:
    """F-0027: ``unload_script`` from any caller must garbage-collect ``_alloc_scripts``."""
    bridge, _, _ = _build_attached_bridge()
    fake_script = _FakeScript()
    _index_set(bridge, "_scripts", "alloc-script", fake_script)
    _index_set(bridge, "_alloc_scripts", 0x12345000, "alloc-script")

    async def driver() -> bool:
        return await bridge.unload_script("alloc-script")

    ok = _run(driver())
    assert ok is True
    assert "alloc-script" not in _get_dict(bridge, "_scripts")
    assert 0x12345000 not in _get_dict(bridge, "_alloc_scripts"), "alloc_scripts entry not reaped after public unload_script"


def test_f0030_attach_does_not_reinitialize_implicitly() -> None:
    """F-0030: ``attach`` must NOT silently re-initialise; uninit must surface as device error."""
    bridge = FridaBridge()  # not initialised, no device set

    init_calls: list[None] = []
    real_initialize = cast("Callable[..., Coroutine[object, object, None]]", bridge.initialize)

    async def tracking_init(tool_path: object | None = None) -> None:
        """Track invocation and chain to the real initialize.

        Args:
            tool_path: Optional tool path forwarded to the real method.
        """
        init_calls.append(None)
        await real_initialize(tool_path)

    _set(bridge, "initialize", tracking_init)

    async def driver() -> None:
        await bridge.attach(1234)

    with pytest.raises(ToolError) as excinfo:
        _run(driver())
    assert init_calls == [], "attach() implicitly invoked initialize(); init errors will masquerade as attach errors"
    details = excinfo.value.details
    assert details is not None
    assert "initialise" in str(details.get("reason", "")).lower()
