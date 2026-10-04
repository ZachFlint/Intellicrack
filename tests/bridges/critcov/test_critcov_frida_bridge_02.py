# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Critical-coverage tests for the Frida bridge memory, symbol, stalker, device and script-control paths.

Every test that needs a live session drives the real Frida runtime against a child
process that the test itself starts (a Python interpreter blocked on stdin), never
against the pytest process. The tests cover argument validation, not-attached and
no-device guards, failures that a real target produces (unmapped addresses, missing
modules, destroyed scripts, uncompilable script source), the cancellation-token
wrappers around attach, spawn and script creation, and the pure helpers that build
and parse the JavaScript the bridge sends to the agent.
"""

from __future__ import annotations

import asyncio
import contextlib
import queue
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

import frida
import psutil
import pytest

from intellicrack.bridges.frida_bridge import FridaBridge
from intellicrack.core.subprocess_compat import DEVNULL, PIPE, Popen
from intellicrack.core.types import FridaDeviceInfo, StalkerEvent, ToolError


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Generator

    from frida import ScriptMessage


pytestmark = pytest.mark.spawns_process

_WAIT_S: Final[float] = 20.0
_ABSENT_PID: Final[int] = 0x7FFFFFFE
_NOT_ATTACHED: Final[str] = "not attached to a process"
_NO_DEVICE: Final[str] = "no Frida device available"
_NOT_INITIALIZED: Final[dict[str, object]] = {"reason": "bridge not initialised; call initialize() first"}
_TARGET_READY: Final[bytes] = b"critcov-ready"
_TARGET_SOURCE: Final[str] = "import sys\nsys.stdout.write('critcov-ready\\n')\nsys.stdout.flush()\nsys.stdin.read()\n"
_SLEEPER_SOURCE: Final[str] = "import time\ntime.sleep(120)\n"
_UNATTACHED_CALLS: Final[tuple[tuple[str, tuple[object, ...]], ...]] = (
    ("allocate_memory", (16,)),
    ("protect_memory", (0, 16, "rwx")),
    ("query_memory_protection", (0,)),
    ("find_base_address", ("kernel32.dll",)),
    ("resolve_symbol", (0,)),
    ("find_functions_named", ("Sleep",)),
    ("resolve_api", ("exports:*!Sleep",)),
    ("replace_function", ("0x1", "function () {}")),
    ("replace_function_fast", ("0x1", "function () {}")),
    ("stalker_follow", ()),
    ("stalker_unfollow", ()),
    ("enumerate_symbols", ("kernel32.dll",)),
    ("load_module", ("kernel32.dll",)),
    ("find_module_by_address", (0,)),
    ("find_functions_matching", ("*Sleep*",)),
    ("get_backtrace", ()),
    ("set_exception_handler", ()),
    ("revert_hook", ("0x1",)),
    ("flush_interceptor", ()),
    ("call_system_function", (0,)),
    ("stalker_add_call_probe", (0, "send(1);")),
    ("allocate_string", ("text",)),
    ("enable_session_child_gating", ()),
    ("disable_session_child_gating", ()),
    ("get_pending_session_children", ()),
    ("resume_session_child", (1,)),
)
_DEVICELESS_CALLS: Final[tuple[tuple[str, tuple[object, ...], dict[str, object]], ...]] = (
    ("enumerate_processes", (), _NOT_INITIALIZED),
    ("get_frontmost_application", (), _NOT_INITIALIZED),
    ("enable_child_gating", (), {}),
    ("disable_child_gating", (), {}),
    ("resume_child", (1,), {}),
    ("enable_device_lost_notifications", (), {}),
    ("enable_crash_reporting", (), {}),
    ("inject_library_file", (1, "critcov.dll", "entry", ""), {}),
)
_SESSION_GATING_CALLS: Final[tuple[tuple[str, tuple[object, ...]], ...]] = (
    ("enable_session_child_gating", ()),
    ("disable_session_child_gating", ()),
    ("get_pending_session_children", ()),
    ("resume_session_child", (1,)),
)
_NOTIFICATION_FAMILIES: Final[tuple[tuple[str, str, str, str, str, str, str, str], ...]] = (
    (
        "crash",
        "enable_crash_reporting",
        "disable_crash_reporting",
        "_teardown_crash_handler",
        "_crash_handler",
        "_crash_reporting_enabled",
        "process-crashed",
        "crash reporting setup failed",
    ),
    (
        "device_change",
        "enable_device_change_notifications",
        "disable_device_change_notifications",
        "_teardown_device_change_notifications",
        "_device_manager_changed_handler",
        "_device_change_notifications_enabled",
        "changed",
        "failed to initialize Frida device",
    ),
    (
        "device_lost",
        "enable_device_lost_notifications",
        "disable_device_lost_notifications",
        "_teardown_device_lost_notifications",
        "_device_lost_handler",
        "_device_lost_notifications_enabled",
        "lost",
        "failed to initialize Frida device",
    ),
)
_ESCAPED_CHARACTERS: Final[tuple[tuple[str, str], ...]] = (
    ("\\", "\\\\"),
    ("'", "\\'"),
    ('"', '\\"'),
    ("`", "\\`"),
    ("$", "\\$"),
    ("\n", "\\n"),
    ("\r", "\\r"),
    ("\t", "\\t"),
    ("\b", "\\b"),
    ("\f", "\\f"),
    ("\v", "\\v"),
    ("\0", "\\u0000"),
    ("\x01", "\\u0001"),
    ("\x1f", "\\u001f"),
    ("\x7f", "\\u007f"),
    ("\xe9", "\\u00e9"),
    ("€", "\\u20ac"),
    (" ", " "),
    ("~", "~"),
    ("Az09", "Az09"),
)


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Run a coroutine to completion on a private event loop and join its executor threads.

    Args:
        coro: Coroutine to execute.

    Returns:
        T: The coroutine's return value.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        try:
            loop.run_until_complete(loop.shutdown_default_executor())
        finally:
            loop.close()


def priv[T](obj: object, name: str, typ: type[T]) -> T:
    """Read a private attribute with a known static type.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name, including its leading underscore.
        typ: Static type of the attribute, used only for typing.

    Returns:
        T: The attribute value.
    """
    del typ
    value: T = getattr(obj, name)
    return value


def put(obj: object, name: str, *, value: object) -> None:
    """Set a private data attribute on an object.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name, including its leading underscore.
        value: Value to store.
    """
    setattr(obj, name, value)


def sync_method(obj: object, name: str) -> Callable[..., object]:
    """Look up a (possibly private) synchronous method by name.

    Args:
        obj: Object or class that owns the method.
        name: Method name.

    Returns:
        Callable[..., object]: The bound method or plain function.
    """
    return cast("Callable[..., object]", getattr(obj, name))


def async_method(obj: object, name: str) -> Callable[..., Coroutine[object, object, object]]:
    """Look up a (possibly private) coroutine method by name.

    Args:
        obj: Object or class that owns the method.
        name: Method name.

    Returns:
        Callable[..., Coroutine[object, object, object]]: The bound coroutine method or plain coroutine function.
    """
    return cast("Callable[..., Coroutine[object, object, object]]", getattr(obj, name))


def _start_target() -> Popen[bytes]:
    """Start a Python child that reports readiness on stdout and then blocks on stdin.

    Returns:
        Popen[bytes]: The ready child process.
    """
    proc = Popen([sys.executable, "-c", _TARGET_SOURCE], stdin=PIPE, stdout=PIPE, stderr=DEVNULL)
    ready = b""
    try:
        stdout = proc.stdout
        assert stdout is not None
        ready = stdout.readline().strip()
    finally:
        if ready != _TARGET_READY:
            _stop_target(proc)
    assert ready == _TARGET_READY
    return proc


def _stop_target(proc: Popen[bytes]) -> None:
    """Terminate a child process, wait for it and close its pipes.

    Args:
        proc: The child process to stop.
    """
    try:
        if proc.poll() is None:
            proc.terminate()
        proc.wait(timeout=_WAIT_S)
    finally:
        for stream in (proc.stdin, proc.stdout):
            if stream is not None:
                stream.close()


def _wait_for_exit(pid: int) -> None:
    """Wait until the process ``pid`` no longer runs.

    Args:
        pid: Identifier of the process expected to terminate.
    """
    with contextlib.suppress(psutil.NoSuchProcess):
        psutil.Process(pid).wait(timeout=_WAIT_S)


def _first_payload(script: frida.Script) -> object:
    """Load a script, return the payload of its first ``send`` message and unload it.

    Args:
        script: Created but not yet loaded Frida script.

    Returns:
        object: Payload of the first ``send`` message the script emitted.
    """
    received: queue.Queue[object] = queue.Queue()

    def on_message(message: ScriptMessage, data: bytes | None) -> None:
        """Queue the payload of every ``send`` message.

        Args:
            message: Message emitted by the script.
            data: Optional binary payload attached to the message.
        """
        del data
        if message["type"] == "send":
            received.put(message.get("payload"))

    script.on("message", on_message)
    script.load()
    try:
        return received.get(timeout=_WAIT_S)
    finally:
        script.unload()


def _loaded_script(bridge: FridaBridge) -> tuple[str, frida.Script]:
    """Load an inert persistent script and return its identifier and handle.

    Args:
        bridge: Attached bridge that will own the script.

    Returns:
        tuple[str, frida.Script]: The script identifier and the live Frida script.
    """
    script_id = _run(bridge.execute_persistent_script("var critcovIdle = 1;"))
    scripts = cast("dict[str, frida.Script]", priv(bridge, "_scripts", object))
    return script_id, scripts[script_id]


def _signal_source(bridge: FridaBridge, signal: str) -> frida.Device | frida.DeviceManager:
    """Return the Frida object that emits ``signal`` for the bridge.

    Args:
        bridge: Initialized bridge.
        signal: Signal name; ``changed`` belongs to the device manager, every other one to the device.

    Returns:
        frida.Device | frida.DeviceManager: The emitter the bridge registers its handler on.
    """
    if signal == "changed":
        return frida.get_device_manager()
    return priv(bridge, "_device", frida.Device)


@pytest.fixture
def target_process() -> Generator[Popen[bytes]]:
    """Start a child process for Frida to attach to and stop it afterwards.

    Yields:
        Popen[bytes]: The running child process.
    """
    proc = _start_target()
    try:
        yield proc
    finally:
        _stop_target(proc)


@pytest.fixture
def idle_bridge() -> Generator[FridaBridge]:
    """Initialize a bridge on the local Frida device without attaching and shut it down afterwards.

    Yields:
        FridaBridge: A connected bridge with no session.
    """
    bridge = FridaBridge()
    _run(bridge.initialize())
    try:
        yield bridge
    finally:
        _run(bridge.shutdown())


@pytest.fixture
def attached_bridge(target_process: Popen[bytes], idle_bridge: FridaBridge) -> FridaBridge:
    """Attach the idle bridge to the child process.

    Args:
        target_process: The running child process.
        idle_bridge: Initialized bridge without a session.

    Returns:
        FridaBridge: The bridge attached to ``target_process``.
    """
    _run(idle_bridge.attach(target_process.pid))
    return idle_bridge


@pytest.mark.parametrize(("method", "args"), _UNATTACHED_CALLS, ids=[name for name, _ in _UNATTACHED_CALLS])
def test_operation_without_session_raises_not_attached(method: str, args: tuple[object, ...]) -> None:
    """Every session-bound operation refuses to run before the bridge has attached to a process.

    Args:
        method: Name of the bridge method under test.
        args: Positional arguments for the call.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(async_method(FridaBridge(), method)(*args))
    assert excinfo.value.message == _NOT_ATTACHED


@pytest.mark.parametrize(
    ("method", "args", "details"),
    _DEVICELESS_CALLS,
    ids=[name for name, _, _ in _DEVICELESS_CALLS],
)
def test_operation_without_device_raises_no_device(method: str, args: tuple[object, ...], details: dict[str, object]) -> None:
    """Every device-bound operation refuses to run on a bridge that never initialized a Frida device.

    Args:
        method: Name of the bridge method under test.
        args: Positional arguments for the call.
        details: Expected structured details of the error.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(async_method(FridaBridge(), method)(*args))
    assert excinfo.value.message == _NO_DEVICE
    assert excinfo.value.details == details


@pytest.mark.parametrize(("method", "args"), _SESSION_GATING_CALLS, ids=[name for name, _ in _SESSION_GATING_CALLS])
def test_session_child_gating_without_device_raises_no_device(
    attached_bridge: FridaBridge,
    method: str,
    args: tuple[object, ...],
) -> None:
    """Session child gating needs a device as well as a session and reports the missing device.

    Args:
        attached_bridge: Bridge attached to the child.
        method: Name of the bridge method under test.
        args: Positional arguments for the call.
    """
    device = priv(attached_bridge, "_device", frida.Device)
    put(attached_bridge, "_device", value=None)
    try:
        with pytest.raises(ToolError) as excinfo:
            _run(async_method(attached_bridge, method)(*args))
    finally:
        put(attached_bridge, "_device", value=device)
    assert excinfo.value.message == _NO_DEVICE


def test_enable_session_child_gating_when_already_enabled_registers_nothing(attached_bridge: FridaBridge) -> None:
    """Enabling session child gating twice is a no-op that neither registers handlers nor touches the session.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    put(attached_bridge, "_session_child_gating_enabled", value=True)
    try:
        assert _run(attached_bridge.enable_session_child_gating()) is None
        assert priv(attached_bridge, "_child_added_handler", object) is None
        assert priv(attached_bridge, "_child_removed_handler", object) is None
    finally:
        put(attached_bridge, "_session_child_gating_enabled", value=False)


def test_disable_session_child_gating_when_not_enabled_is_a_no_op(attached_bridge: FridaBridge) -> None:
    """Disabling session child gating that was never enabled returns without error.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    assert _run(attached_bridge.disable_session_child_gating()) is None
    assert priv(attached_bridge, "_session_child_gating_enabled", bool) is False


def test_resume_session_child_with_absent_pid_reports_gating_failure(attached_bridge: FridaBridge) -> None:
    """Resuming a pid that Frida does not know fails with the child-gating error and keeps Frida's error as the cause.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.resume_session_child(_ABSENT_PID))
    assert excinfo.value.message == "child gating operation failed"
    assert excinfo.value.__cause__ is not None


def test_disable_child_gating_when_not_enabled_is_a_no_op(idle_bridge: FridaBridge) -> None:
    """Disabling device-wide spawn gating that was never enabled returns without error.

    Args:
        idle_bridge: Initialized bridge without a session.
    """
    assert _run(idle_bridge.disable_child_gating()) is None
    assert priv(idle_bridge, "_child_gating_enabled", bool) is False


@pytest.mark.parametrize(
    ("enable", "handler_attr", "flag_attr"),
    [(family[1], family[4], family[5]) for family in _NOTIFICATION_FAMILIES],
    ids=[family[0] for family in _NOTIFICATION_FAMILIES],
)
def test_enable_notifications_when_already_enabled_registers_no_handler(
    idle_bridge: FridaBridge,
    enable: str,
    handler_attr: str,
    flag_attr: str,
) -> None:
    """Enabling a notification family that is already marked enabled returns without registering a second handler.

    Args:
        idle_bridge: Initialized bridge without a session.
        enable: Name of the bridge method that enables the notifications.
        handler_attr: Attribute that records the registered handler.
        flag_attr: Attribute that records whether the notifications are enabled.
    """
    put(idle_bridge, flag_attr, value=True)
    try:
        assert _run(async_method(idle_bridge, enable)()) is None
        assert priv(idle_bridge, handler_attr, object) is None
    finally:
        put(idle_bridge, flag_attr, value=False)


@pytest.mark.parametrize(
    ("detach", "flag_attr"),
    [
        ("_detach_crash_handler", "_crash_reporting_enabled"),
        ("_detach_device_manager_changed_handler", "_device_change_notifications_enabled"),
        ("_detach_device_lost_handler", "_device_lost_notifications_enabled"),
    ],
    ids=["crash", "device_change", "device_lost"],
)
def test_detach_without_a_recorded_handler_only_clears_the_enabled_flag(idle_bridge: FridaBridge, detach: str, flag_attr: str) -> None:
    """Detaching a notification family that is enabled but has no recorded handler still resets the enabled flag.

    Args:
        idle_bridge: Initialized bridge without a session.
        detach: Name of the bridge method that detaches the handler.
        flag_attr: Attribute that records whether the notifications are enabled.
    """
    put(idle_bridge, flag_attr, value=True)

    sync_method(idle_bridge, detach)()

    assert priv(idle_bridge, flag_attr, bool) is False


@pytest.mark.parametrize(
    ("enable", "disable", "handler_attr", "signal", "message"),
    [(family[1], family[2], family[4], family[6], family[7]) for family in _NOTIFICATION_FAMILIES],
    ids=[family[0] for family in _NOTIFICATION_FAMILIES],
)
def test_disable_notifications_wraps_a_failure_to_detach_the_handler(
    idle_bridge: FridaBridge,
    enable: str,
    disable: str,
    handler_attr: str,
    signal: str,
    message: str,
) -> None:
    """Disabling a notification family whose handler Frida already dropped raises a tool error carrying Frida's error.

    Args:
        idle_bridge: Initialized bridge without a session.
        enable: Name of the bridge method that enables the notifications.
        disable: Name of the bridge method that disables the notifications.
        handler_attr: Attribute that records the registered handler.
        signal: Frida signal the handler listens to.
        message: Expected tool error message.
    """
    _run(async_method(idle_bridge, enable)())
    handler = cast("Callable[..., None]", priv(idle_bridge, handler_attr, object))
    sync_method(_signal_source(idle_bridge, signal), "off")(signal, handler)

    with pytest.raises(ToolError) as excinfo:
        _run(async_method(idle_bridge, disable)())

    cause = excinfo.value.__cause__
    assert cause is not None
    assert excinfo.value.message == message
    assert excinfo.value.details["frida_error"] == str(cause)
    assert excinfo.value.details["frida_error_type"] == type(cause).__name__


@pytest.mark.parametrize(
    ("enable", "teardown", "handler_attr", "signal"),
    [(family[1], family[3], family[4], family[6]) for family in _NOTIFICATION_FAMILIES],
    ids=[family[0] for family in _NOTIFICATION_FAMILIES],
)
def test_teardown_swallows_a_failure_to_detach_the_handler(
    idle_bridge: FridaBridge,
    enable: str,
    teardown: str,
    handler_attr: str,
    signal: str,
) -> None:
    """The shutdown-time teardown of a notification family logs a detach failure instead of raising it.

    Args:
        idle_bridge: Initialized bridge without a session.
        enable: Name of the bridge method that enables the notifications.
        teardown: Name of the best-effort teardown method.
        handler_attr: Attribute that records the registered handler.
        signal: Frida signal the handler listens to.
    """
    _run(async_method(idle_bridge, enable)())
    handler = cast("Callable[..., None]", priv(idle_bridge, handler_attr, object))
    sync_method(_signal_source(idle_bridge, signal), "off")(signal, handler)

    assert sync_method(idle_bridge, teardown)() is None


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("0x1000", "ptr(0x1000)"),
        ("kernel32.dll!Sleep", "Process.findModuleByName('kernel32.dll').getExportByName('Sleep')"),
        ("Sleep", "Module.getGlobalExportByName('Sleep')"),
    ],
    ids=["address", "module_export", "global_export"],
)
def test_resolve_target_js_builds_one_expression_per_target_form(target: str, expected: str) -> None:
    """Hex addresses, module!function pairs and bare export names each map to their own pointer expression.

    Args:
        target: Function target string.
        expected: Expected JavaScript expression.
    """
    assert sync_method(FridaBridge, "_resolve_target_js")(target) == expected


@pytest.mark.parametrize(
    ("pattern", "reason"),
    [
        ("", "empty scan pattern"),
        (" ", "empty scan pattern"),
        ("4d5", "scan pattern must contain whole bytes"),
        ("4 d 5", "scan pattern must contain whole bytes"),
    ],
    ids=["empty", "blank", "odd_digits", "odd_digits_spaced"],
)
def test_normalize_hex_scan_pattern_rejects_empty_and_half_byte_patterns(pattern: str, reason: str) -> None:
    """A scan pattern with no cells or with a dangling half byte is refused with a reason.

    Args:
        pattern: Hex scan pattern.
        reason: Expected failure reason.
    """
    with pytest.raises(ToolError) as excinfo:
        sync_method(FridaBridge, "_normalize_hex_scan_pattern")(pattern)
    assert excinfo.value.message == "memory read failed"
    assert excinfo.value.details == {"reason": reason}


@pytest.mark.parametrize(("raw", "escaped"), _ESCAPED_CHARACTERS, ids=[repr(raw) for raw, _ in _ESCAPED_CHARACTERS])
def test_escape_js_string_escapes_each_unsafe_character(raw: str, escaped: str) -> None:
    """Quotes, template markers, control characters and non-ASCII characters become JavaScript escapes.

    Args:
        raw: Character or text to escape.
        escaped: Expected escaped text.
    """
    assert sync_method(FridaBridge, "_escape_js_string")(raw) == escaped


def test_escape_js_string_output_is_printable_ascii_for_every_latin1_character() -> None:
    """Escaping every character below U+0100 yields printable ASCII only, so it cannot end an enclosing literal."""
    everything = "".join(chr(code) for code in range(256))

    escaped = cast("str", sync_method(FridaBridge, "_escape_js_string")(everything))

    assert all(0x20 <= ord(ch) <= 0x7E for ch in escaped)
    assert escaped.count("\\u00e9") == 1


def test_escape_js_string_encodes_astral_characters_as_surrogate_pairs() -> None:
    """A character outside the basic multilingual plane is escaped as the two UTF-16 units JavaScript expects."""
    astral = "\U0001f600"
    utf16 = astral.encode("utf-16-be")
    expected = "".join(f"\\u{int.from_bytes(utf16[index : index + 2], 'big'):04x}" for index in range(0, len(utf16), 2))

    assert sync_method(FridaBridge, "_escape_js_string")(astral) == expected


def test_allocate_string_keeps_characters_outside_the_basic_multilingual_plane(attached_bridge: FridaBridge) -> None:
    """A string containing an emoji is allocated in the target as the same UTF-8 bytes.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    text = "\U0001f600"
    encoded = text.encode("utf-8")

    address = _run(attached_bridge.allocate_string(text))

    assert _run(attached_bridge.read_memory(address, len(encoded) + 1)) == encoded + b"\x00"


def test_parse_stalker_batch_stores_dict_events_and_ignores_the_rest() -> None:
    """Dictionary events are decoded onto the registered thread; other items and unregistered threads are ignored."""
    bridge = FridaBridge()
    traces = cast("dict[int, list[StalkerEvent]]", priv(bridge, "_stalker_traces", object))
    traces[5] = []
    parse = sync_method(bridge, "_parse_stalker_batch")

    parse(5, ["junk", 7, None, {"type": "call", "from": "0x10", "to": "0x20", "depth": 2}, {"from": "32"}])
    parse(6, [{"type": "ret", "from": "0x1"}])

    assert traces == {
        5: [
            StalkerEvent(event_type="call", from_address=0x10, to_address=0x20, depth=2),
            StalkerEvent(event_type="exec", from_address=32, to_address=None, depth=0),
        ],
    }


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        ({"value": "0x1f"}, 31),
        ({"value": "42"}, 42),
        ({"value": True}, 1),
        ({"value": 7.9}, 7),
        ({"value": None}, 0),
        ({"value": [1]}, 0),
        ({}, 0),
    ],
    ids=["hex_string", "decimal_string", "bool", "float", "none", "list", "missing"],
)
def test_coerce_call_value_converts_numbers_and_numeric_text(result: dict[str, object], expected: int) -> None:
    """Numeric values and numeric strings become integers and anything else becomes zero.

    Args:
        result: Result payload of a script call.
        expected: Expected integer.
    """
    assert sync_method(FridaBridge, "_coerce_call_value")(result) == expected


def test_resolve_cancellable_resolves_registered_tokens_and_rejects_unknown_ones() -> None:
    """A missing id resolves to no token, a created id to its token and an unknown id to a tool error."""
    bridge = FridaBridge()
    resolve = sync_method(bridge, "_resolve_cancellable")
    assert resolve(None) is None

    token_id = _run(bridge.create_cancellable())
    registered = cast("dict[str, frida.Cancellable]", priv(bridge, "_cancellables", object))
    assert resolve(token_id) is registered[token_id]

    with pytest.raises(ToolError) as excinfo:
        resolve("ghost")
    assert excinfo.value.message == "unknown cancellable token"
    assert excinfo.value.details == {"cancellable_id": "ghost"}


def test_attach_with_cancellable_attaches_to_the_requested_process(target_process: Popen[bytes], idle_bridge: FridaBridge) -> None:
    """Attaching inside a cancellation scope yields a live session whose agent runs in the requested process.

    Args:
        target_process: The running child process.
        idle_bridge: Initialized bridge without a session.
    """
    device = priv(idle_bridge, "_device", frida.Device)

    session = cast(
        "frida.Session",
        sync_method(FridaBridge, "_attach_with_cancellable")(device, target_process.pid, frida.Cancellable()),
    )
    try:
        assert not session.is_detached
        assert _first_payload(session.create_script("send(Process.id);")) == target_process.pid
    finally:
        session.detach()


def test_spawn_with_cancellable_starts_the_requested_program(idle_bridge: FridaBridge) -> None:
    """Spawning inside a cancellation scope starts a process running the requested executable.

    Args:
        idle_bridge: Initialized bridge without a session.
    """
    device = priv(idle_bridge, "_device", frida.Device)

    pid = cast(
        "int",
        sync_method(FridaBridge, "_spawn_with_cancellable")(
            device,
            sys.executable,
            [sys.executable, "-c", _SLEEPER_SOURCE],
            frida.Cancellable(),
        ),
    )
    try:
        assert Path(psutil.Process(pid).exe()).resolve() == Path(sys.executable).resolve()
    finally:
        device.kill(pid)
        _wait_for_exit(pid)


def test_create_script_with_cancellable_compiles_the_given_source(target_process: Popen[bytes], attached_bridge: FridaBridge) -> None:
    """Creating a script inside a cancellation scope compiles the given source for the attached process.

    Args:
        target_process: The attached child process.
        attached_bridge: Bridge attached to the child.
    """
    session = priv(attached_bridge, "_session", frida.Session)
    script = cast(
        "frida.Script",
        sync_method(FridaBridge, "_create_script_with_cancellable")(session, "send(Process.id);", frida.Cancellable()),
    )

    assert _first_payload(script) == target_process.pid


@pytest.mark.parametrize("size", [0, -8], ids=["zero", "negative"])
def test_allocate_memory_rejects_non_positive_sizes(attached_bridge: FridaBridge, size: int) -> None:
    """A size that is zero or negative is refused with the offending value in the reason.

    Args:
        attached_bridge: Bridge attached to the child.
        size: Requested allocation size.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.allocate_memory(size))
    assert excinfo.value.message == "memory allocation failed"
    assert excinfo.value.details == {"reason": f"size must be positive, got {size}"}


@pytest.mark.parametrize("size", [0, -4096], ids=["zero", "negative"])
def test_protect_memory_rejects_non_positive_sizes(attached_bridge: FridaBridge, size: int) -> None:
    """A protection change over zero or negative bytes is refused with the offending value in the reason.

    Args:
        attached_bridge: Bridge attached to the child.
        size: Requested region size.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.protect_memory(0x1000, size, "rwx"))
    assert excinfo.value.message == "memory protection change failed"
    assert excinfo.value.details == {"reason": f"size must be positive, got {size}"}


def test_protect_memory_on_unmapped_address_does_not_report_success(attached_bridge: FridaBridge) -> None:
    """Changing the protection of the unmapped null page either raises or reports False, never True.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    changed: bool | None = None
    with contextlib.suppress(ToolError):
        changed = _run(attached_bridge.protect_memory(0, 4096, "rwx"))
    assert changed is not True
    assert _run(attached_bridge.enumerate_modules())


def test_find_base_address_of_a_module_that_is_not_loaded_raises(attached_bridge: FridaBridge) -> None:
    """Asking for the base of a module the target never loaded reports module-not-found.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.find_base_address("critcov_not_loaded.dll"))
    assert excinfo.value.message == "module not found"


def test_resolve_api_rejects_unknown_resolver_type(attached_bridge: FridaBridge) -> None:
    """A resolver type outside module, objc and swift is refused with a reason.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.resolve_api("exports:*!Sleep", resolver_type="bogus"))
    assert excinfo.value.message == "symbol resolution failed"
    assert excinfo.value.details == {"reason": "invalid resolver type: bogus"}


def test_resolve_api_with_a_resolver_missing_on_windows_reports_resolution_failure(attached_bridge: FridaBridge) -> None:
    """The Objective-C resolver does not exist in a Windows process, so Frida refuses to create it.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.resolve_api("-[NSString init*]", resolver_type="objc"))
    assert excinfo.value.message == "symbol resolution failed"


def test_replace_function_fast_rejects_unknown_calling_convention(attached_bridge: FridaBridge) -> None:
    """A calling convention outside the supported set is refused before any script is created.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.replace_function_fast("0x1", "function () {}", calling_convention="cdecl"))
    assert excinfo.value.message == "function replacement failed"
    assert excinfo.value.details == {"reason": "invalid calling convention: cdecl"}
    assert cast("dict[str, object]", priv(attached_bridge, "_scripts", object)) == {}


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"return_type": "bogus"}, "invalid return type: bogus"),
        ({"calling_convention": "cdecl"}, "invalid calling convention: cdecl"),
        ({"args": [1], "arg_types": ["bogus"]}, "invalid arg type: bogus"),
    ],
    ids=["return_type", "calling_convention", "arg_type"],
)
def test_call_system_function_rejects_invalid_type_names(attached_bridge: FridaBridge, kwargs: dict[str, object], reason: str) -> None:
    """Native type names and calling conventions outside the supported sets are refused with a reason.

    Args:
        attached_bridge: Bridge attached to the child.
        kwargs: Keyword arguments carrying one invalid name.
        reason: Expected failure reason.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(async_method(attached_bridge, "call_system_function")(0x1000, **kwargs))
    assert excinfo.value.message == "function call failed"
    assert excinfo.value.details == {"reason": reason}


def test_call_system_function_at_unmapped_address_raises_and_target_survives(attached_bridge: FridaBridge) -> None:
    """Calling the null address faults inside the target, which is reported as a call failure.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.call_system_function(0))
    assert excinfo.value.message == "function call failed"
    assert _run(attached_bridge.enumerate_modules())


def test_load_module_of_a_missing_library_reports_load_failure(attached_bridge: FridaBridge) -> None:
    """Loading a library that does not exist is reported as a module load failure.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.load_module("critcov_missing_library.dll"))
    assert excinfo.value.message == "module loading failed"


def test_disassemble_instruction_of_an_invalid_opcode_raises(attached_bridge: FridaBridge) -> None:
    """Bytes that are not a valid x86-64 instruction (PUSH ES) are reported as a resolution failure.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    address = _run(attached_bridge.allocate_memory(64))
    assert _run(attached_bridge.write_memory(address, b"\x06" * 16)) == 16

    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.disassemble_instruction(address))
    assert excinfo.value.message == "symbol resolution failed"


def test_get_backtrace_rejects_unknown_backtracer(attached_bridge: FridaBridge) -> None:
    """A backtracer other than accurate or fuzzy is refused with a reason.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.get_backtrace(backtracer="bogus"))
    assert excinfo.value.message == "symbol resolution failed"
    assert excinfo.value.details == {"reason": "invalid backtracer: bogus"}


def test_get_backtrace_rejects_a_boolean_context_address(attached_bridge: FridaBridge) -> None:
    """A boolean is not an integer address and is refused before it can reach the script.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(async_method(attached_bridge, "get_backtrace")(context_address=True))
    assert excinfo.value.message == "function call failed"
    assert excinfo.value.details == {"reason": "context_address must be int, got bool"}


def test_get_backtrace_with_a_zero_context_address_reports_resolution_failure(attached_bridge: FridaBridge) -> None:
    """A zero context address is not a CPU context, so the backtrace script fails and the failure is reported.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.get_backtrace(context_address=0))
    assert excinfo.value.message == "symbol resolution failed"
    assert _run(attached_bridge.enumerate_modules())


def test_revert_hook_of_an_unresolvable_target_fails_and_keeps_registered_hooks(attached_bridge: FridaBridge) -> None:
    """Reverting a target whose module is not loaded fails as a hook error and changes nothing.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.revert_hook("critcov_missing.dll!Nothing"))
    assert excinfo.value.message == "hook installation failed"
    assert _run(attached_bridge.get_hooks()) == []


def test_stalker_add_call_probe_with_uncompilable_callback_fails(attached_bridge: FridaBridge) -> None:
    """A probe callback that does not compile is reported as a probe failure and registers nothing.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.stalker_add_call_probe(0x1000, "var ("))
    assert excinfo.value.message == "call probe operation failed"
    assert excinfo.value.__cause__ is not None
    assert cast("dict[str, str]", priv(attached_bridge, "_call_probes", object)) == {}
    assert cast("dict[str, object]", priv(attached_bridge, "_scripts", object)) == {}


def test_stalker_follow_with_an_empty_event_name_fails_to_compile(attached_bridge: FridaBridge) -> None:
    """An empty event name produces a Stalker script that does not compile, which is reported without registering it.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.stalker_follow(events=""))
    assert excinfo.value.message == "Stalker tracing operation failed"
    assert excinfo.value.__cause__ is not None
    assert cast("dict[int, str]", priv(attached_bridge, "_stalker_scripts", object)) == {}
    assert cast("dict[str, object]", priv(attached_bridge, "_scripts", object)) == {}


def test_set_exception_handler_is_idempotent(attached_bridge: FridaBridge) -> None:
    """Installing the exception handler twice returns the same script and loads only one.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    first = _run(attached_bridge.set_exception_handler())

    second = _run(attached_bridge.set_exception_handler())

    assert second == first
    assert list(cast("dict[str, object]", priv(attached_bridge, "_scripts", object))) == [first]


def test_inject_library_file_into_an_absent_process_fails(idle_bridge: FridaBridge, tmp_path: Path) -> None:
    """Injecting a library into a process that does not exist is reported as an injection failure.

    Args:
        idle_bridge: Initialized bridge without a session.
        tmp_path: Directory holding the path of the library that does not exist.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(idle_bridge.inject_library_file(_ABSENT_PID, str(tmp_path / "critcov_missing.dll"), "entry", ""))
    assert excinfo.value.message == "library injection failed"
    assert excinfo.value.__cause__ is not None


@pytest.mark.parametrize(
    ("device_type", "host", "reason"),
    [
        ("remote", None, "host required for remote device"),
        ("remote", "", "host required for remote device"),
        ("enumerated", None, "device id required for enumerated device"),
        ("enumerated", "", "device id required for enumerated device"),
        ("bogus", None, "unknown device type: bogus"),
    ],
    ids=["remote_none", "remote_empty", "enumerated_none", "enumerated_empty", "unknown_type"],
)
def test_connect_device_rejects_invalid_requests(idle_bridge: FridaBridge, device_type: str, host: str | None, reason: str) -> None:
    """A device request without its required host or id, or with an unknown type, is refused with a reason.

    Args:
        idle_bridge: Initialized bridge without a session.
        device_type: Requested device type.
        host: Requested host or device id.
        reason: Expected failure reason.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(idle_bridge.connect_device(device_type, host))
    assert excinfo.value.message == "failed to initialize Frida device"
    assert excinfo.value.details == {"reason": reason}


@pytest.mark.parametrize(
    ("device_type", "host"),
    [("usb", None), ("enumerated", "critcov-no-such-device")],
    ids=["usb", "enumerated"],
)
def test_connect_device_to_an_unavailable_device_keeps_the_current_one(
    idle_bridge: FridaBridge,
    device_type: str,
    host: str | None,
) -> None:
    """Connecting to a device that Frida cannot find fails with Frida's error as the cause and keeps the current device.

    Args:
        idle_bridge: Initialized bridge without a session.
        device_type: Requested device type.
        host: Requested device id.
    """
    original = priv(idle_bridge, "_device", object)

    with pytest.raises(ToolError) as excinfo:
        _run(idle_bridge.connect_device(device_type, host))

    assert excinfo.value.message == "failed to initialize Frida device"
    assert excinfo.value.__cause__ is not None
    assert priv(idle_bridge, "_device", object) is original


def test_connect_device_releases_the_current_session_first(target_process: Popen[bytes], attached_bridge: FridaBridge) -> None:
    """Switching to the local device detaches the current session first and leaves the target process running.

    Args:
        target_process: The attached child process.
        attached_bridge: Bridge attached to the child.
    """
    info = _run(attached_bridge.connect_device("enumerated", "local"))

    assert isinstance(info, FridaDeviceInfo)
    assert (info.id, info.device_type) == ("local", "local")
    assert priv(attached_bridge, "_session", object) is None
    assert priv(attached_bridge, "_pid", object) is None
    assert attached_bridge.state.process_attached is False
    assert target_process.poll() is None


def test_connect_device_with_invalid_arguments_keeps_the_current_session(attached_bridge: FridaBridge) -> None:
    """A request that is rejected as invalid must not drop the session the analyst is working in.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    with pytest.raises(ToolError):
        _run(attached_bridge.connect_device("remote"))

    assert priv(attached_bridge, "_session", object) is not None
    assert attached_bridge.state.process_attached is True


@pytest.mark.parametrize(
    ("method", "kwargs"),
    [("enable_script_debugger", {"port": 34567}), ("disable_script_debugger", {}), ("terminate_script", {})],
    ids=["enable_debugger", "disable_debugger", "terminate"],
)
def test_script_control_with_unknown_script_id_raises_script_not_found(method: str, kwargs: dict[str, object]) -> None:
    """Debugger and terminate controls refuse an identifier that is not registered.

    Args:
        method: Name of the bridge method under test.
        kwargs: Keyword arguments for the call.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(async_method(FridaBridge(), method)("ghost", **kwargs))
    assert excinfo.value.message == "script not found"


@pytest.mark.parametrize(
    ("method", "kwargs", "extra"),
    [
        ("enable_script_debugger", {"port": 34567}, {"port": 34567}),
        ("disable_script_debugger", {}, {}),
        ("terminate_script", {}, {}),
    ],
    ids=["enable_debugger", "disable_debugger", "terminate"],
)
def test_script_control_on_a_destroyed_script_reports_a_script_failure(
    attached_bridge: FridaBridge,
    method: str,
    kwargs: dict[str, object],
    extra: dict[str, object],
) -> None:
    """Debugger and terminate controls on a script Frida already destroyed raise a tool error and keep the registration.

    Args:
        attached_bridge: Bridge attached to the child.
        method: Name of the bridge method under test.
        kwargs: Keyword arguments for the call.
        extra: Extra detail fields expected besides the script id and Frida's error.
    """
    script_id, script = _loaded_script(attached_bridge)
    script.unload()

    with pytest.raises(ToolError) as excinfo:
        _run(async_method(attached_bridge, method)(script_id, **kwargs))

    cause = excinfo.value.__cause__
    assert cause is not None
    assert excinfo.value.message == "script execution failed"
    assert excinfo.value.details["script_id"] == script_id
    assert excinfo.value.details["frida_error"] == str(cause)
    assert excinfo.value.details["frida_error_type"] == type(cause).__name__
    assert all(excinfo.value.details[key] == value for key, value in extra.items())
    assert script_id in cast("dict[str, frida.Script]", priv(attached_bridge, "_scripts", object))


def test_list_rpc_exports_with_unknown_script_id_raises_script_not_found() -> None:
    """Listing the exports of a script that is not registered is refused."""
    with pytest.raises(ToolError) as excinfo:
        _run(FridaBridge().list_rpc_exports("ghost"))
    assert excinfo.value.message == "script not found"


def test_list_rpc_exports_on_a_destroyed_script_reports_an_rpc_failure(attached_bridge: FridaBridge) -> None:
    """Listing the exports of a script Frida already destroyed raises a tool error carrying Frida's own message.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    script_id, script = _loaded_script(attached_bridge)
    script.unload()

    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.list_rpc_exports(script_id))

    assert excinfo.value.message == "RPC call failed"
    assert excinfo.value.details == {
        "frida_error": "script has been destroyed",
        "frida_error_type": "InvalidOperationError",
        "script_id": script_id,
    }


def test_rpc_call_of_a_name_that_is_not_an_export_function_is_refused(attached_bridge: FridaBridge) -> None:
    """A method name that resolves to a plain attribute instead of an export function is refused as not callable.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    script_id, _script = _loaded_script(attached_bridge)

    with pytest.raises(ToolError) as excinfo:
        _run(attached_bridge.rpc_call(script_id, "__doc__"))

    assert excinfo.value.message == "RPC call failed"
    assert excinfo.value.details == {"reason": "'__doc__' is not callable"}
