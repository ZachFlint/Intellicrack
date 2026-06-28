# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""FridaBridge wave-2c offline gate tests: ObjC and Java runtime families.

Exercises the eleven operations that had 0 % prior coverage:
``objc_enumerate_classes``, ``objc_enumerate_protocols``,
``objc_enumerate_loaded_classes``, ``objc_choose``,
``objc_get_class_methods``, ``objc_hook_method``,
``java_enumerate_loaded_classes``, ``java_choose``, ``java_use``,
``java_hook_method``, and ``java_deoptimize``.

Every test is fully offline — it drives the production bridge code
against hand-written fake session/script doubles without any real
Frida runtime, device, or target process.

Two categories of gates are provided per operation:

1. **Script-framing gates** — the exact JS strings embedded in the
   generated script (class names, method selectors, API call sites)
   are checked against an independent oracle derived from reading the
   bridge source.  Mutating the wrong field in the bridge causes these
   to fail.

2. **Parsed-result gates** — the return value produced by parsing the
   canned RPC response is asserted against the raw oracle values used
   to build that response, never against values the production code
   recomputed.
"""

from __future__ import annotations

import asyncio
import os
from typing import TYPE_CHECKING

import pytest

from intellicrack.bridges.frida_bridge import FridaBridge
from intellicrack.core.types import HookInfo, ToolError


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine


_NOT_ATTACHED_MATCH = r"not attached"
_OBJC_UNAVAIL_MATCH = r"Objective-C runtime"
_JAVA_UNAVAIL_MATCH = r"Java runtime"
_HOOK_FAILED_MATCH = r"hook installation"


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Run a coroutine synchronously on a fresh event loop.

    Args:
        coro: Coroutine to execute.

    Returns:
        T: The coroutine's return value.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _set(target: object, name: str, value: object) -> None:
    """Assign *value* to ``target.<name>`` via ``setattr``.

    Args:
        target: Object to mutate.
        name: Attribute name.
        value: Value to assign.
    """
    setattr(target, name, value)


class _FakeScript:
    """Minimal ``frida.core.Script`` substitute for hook-method tests.

    Records the on-message handler registered by the bridge and exposes
    a ``deliver`` helper so tests can inject synthetic Frida messages
    into the bridge's message pump without a real script runtime.
    """

    def __init__(self) -> None:
        """Initialise an idle fake script with zero invocation counts."""
        self.load_calls: int = 0
        self.unload_calls: int = 0
        self._handler: Callable[..., None] | None = None

    def on(self, event: str, handler: Callable[..., None]) -> None:
        """Capture the message handler registered by the bridge.

        Args:
            event: Event name; only ``'message'`` is acted upon.
            handler: Callback to store.
        """
        if event == "message":
            self._handler = handler

    def load(self) -> None:
        """Record a load invocation."""
        self.load_calls += 1

    def unload(self) -> None:
        """Record an unload invocation."""
        self.unload_calls += 1

    def deliver(
        self,
        payload: dict[str, object],
        data: bytes | None = None,
    ) -> None:
        """Inject a synthetic message into the bridge's on-message callback.

        Wraps *payload* as a Frida ``send``-typed message unless the
        special ``__type`` key equals ``'error'``, in which case a
        Frida error-typed message is delivered instead.

        Args:
            payload: Payload dict to inject.
            data: Optional binary data forwarded to the handler.
        """
        if self._handler is None:
            return
        if payload.get("__type") == "error":
            desc = str(payload.get("description", ""))
            self._handler({"type": "error", "description": desc}, data)
            return
        self._handler({"type": "send", "payload": payload}, data)


class _CapturingFakeSession:
    """``frida.core.Session`` substitute that records script sources.

    Unlike the standard ``_FakeSession`` helpers used elsewhere, this
    variant retains the JavaScript source passed to ``create_script``
    so tests can inspect the exact script the bridge generated.
    """

    def __init__(self) -> None:
        """Initialise with empty script and source registries."""
        self.scripts: list[_FakeScript] = []
        self.sources: list[str] = []
        self.detach_calls: int = 0

    def create_script(self, source: str, **_: object) -> _FakeScript:
        """Record *source* and return a fresh fake script.

        Args:
            source: JavaScript source passed by the bridge.
            **_: Ignored keyword arguments.

        Returns:
            _FakeScript: A new fake script appended to ``self.scripts``.
        """
        self.sources.append(source)
        script = _FakeScript()
        self.scripts.append(script)
        return script

    def detach(self) -> None:
        """Record a detach call."""
        self.detach_calls += 1


def _build_attached_bridge() -> tuple[FridaBridge, _CapturingFakeSession]:
    """Construct a FridaBridge wired to a capturing fake session.

    Returns:
        tuple[FridaBridge, _CapturingFakeSession]: The bridge and its
            backing session for direct assertions.
    """
    bridge = FridaBridge()
    session = _CapturingFakeSession()
    _set(bridge, "_session", session)
    _set(bridge, "_pid", 9999)
    bridge.state.connected = True
    bridge.state.tool_running = True
    bridge.state.process_attached = True
    bridge.state.target_pid = 9999
    return bridge, session


def _patch_execute_script(
    bridge: FridaBridge,
    fixed_result: dict[str, object],
) -> list[str]:
    """Replace ``_execute_script_and_wait`` with a recorder returning *fixed_result*.

    Args:
        bridge: Bridge whose internal method to replace.
        fixed_result: Mapping returned on every invocation.

    Returns:
        list[str]: Mutable list accumulating the JS source code passed
            on each call so callers can assert on script framing.
    """
    captured: list[str] = []

    async def _fake(
        script_code: str,
        max_wait: float = 5.0,
        *,
        cancellable_id: str | None = None,
    ) -> dict[str, object]:
        del max_wait, cancellable_id
        captured.append(script_code)
        await asyncio.sleep(0)
        return dict(fixed_result)

    _set(bridge, "_execute_script_and_wait", _fake)
    return captured


async def _deliver_after_load(
    session: _CapturingFakeSession,
    payload: dict[str, object],
) -> None:
    """Poll until the bridge has created and loaded a script, then deliver *payload*.

    Waits up to 400 ms for ``create_script`` to be called and a further
    400 ms for ``script.load()`` to complete before injecting the payload
    into the bridge's on-message handler. If no script is ever created
    (for example the bridge method raised before reaching
    ``create_script``), it returns without delivering so the caller's
    ``await task`` surfaces the underlying error rather than an index error.

    Args:
        session: Session whose ``scripts`` list is polled.
        payload: Message payload to inject into the most recently created script.
    """
    for _ in range(40):
        if session.scripts:
            break
        await asyncio.sleep(0.01)
    if not session.scripts:
        return
    script = session.scripts[-1]
    for _ in range(40):
        if script.load_calls > 0:
            break
        await asyncio.sleep(0.01)
    script.deliver(payload)


def _make_bridge_unattached() -> FridaBridge:
    """Return a freshly constructed FridaBridge with no session attached.

    Returns:
        FridaBridge: Bridge instance with ``_session`` left as ``None``.
    """
    return FridaBridge()


def test_objc_enumerate_classes_not_attached() -> None:
    """objc_enumerate_classes raises ToolError when no session is active.

    Mutation caught: if the not-attached guard is removed or the wrong
    error type is raised, this test fails.
    """
    bridge = _make_bridge_unattached()

    with pytest.raises(ToolError, match=_NOT_ATTACHED_MATCH):
        _run(bridge.objc_enumerate_classes())


def test_objc_enumerate_classes_objc_error_type() -> None:
    """objc_enumerate_classes raises when the script returns an objc_error payload.

    Mutation caught: if the bridge does not check ``result.get('type') ==
    'objc_error'`` and instead returns an empty list, the exception is not
    raised and the test fails.
    """
    bridge, _ = _build_attached_bridge()
    _patch_execute_script(bridge, {"type": "objc_error", "error": "unavailable"})

    with pytest.raises(ToolError, match=_OBJC_UNAVAIL_MATCH):
        _run(bridge.objc_enumerate_classes())


def test_objc_enumerate_classes_error_key_raises() -> None:
    """objc_enumerate_classes raises when the result dict contains an ``error`` key.

    Mutation caught: if the bridge drops the ``'error' in result`` check,
    an error response is silently treated as an empty list.
    """
    bridge, _ = _build_attached_bridge()
    _patch_execute_script(bridge, {"error": "boom", "data": []})

    with pytest.raises(ToolError, match=_OBJC_UNAVAIL_MATCH):
        _run(bridge.objc_enumerate_classes())


def test_objc_enumerate_classes_returns_data_and_embeds_objc_classes() -> None:
    """objc_enumerate_classes parses the data list and embeds ObjC.classes in the script.

    Oracle for script framing: the bridge MUST reference ``ObjC.classes``
    (not ``ObjC.protocols``) to enumerate classes.

    Oracle for parsed result: the bridge MUST return exactly
    ``['NSObject', 'NSString', 'NSURL']`` when the script delivers those
    three strings in the ``data`` array — it must not truncate, reorder,
    or add entries.

    Mutation caught: using ``ObjC.protocols`` instead of ``ObjC.classes``
    fails the framing assertion; accessing the wrong result key fails the
    value assertion.
    """
    bridge, _ = _build_attached_bridge()
    captured = _patch_execute_script(
        bridge,
        {"type": "objc_classes", "data": ["NSObject", "NSString", "NSURL"]},
    )

    result = _run(bridge.objc_enumerate_classes())

    assert result == ["NSObject", "NSString", "NSURL"], f"expected exact canned list, got {result!r}"
    assert captured, "execute_script_and_wait was never called"
    assert "ObjC.classes" in captured[0], f"script must reference ObjC.classes; got:\n{captured[0]}"
    assert "ObjC.protocols" not in captured[0], "script must not reference ObjC.protocols for class enumeration"


def test_objc_enumerate_protocols_not_attached() -> None:
    """objc_enumerate_protocols raises ToolError when no session is active.

    Mutation caught: removing the not-attached guard allows the call to
    proceed and produce a meaningless result instead of an error.
    """
    bridge = _make_bridge_unattached()

    with pytest.raises(ToolError, match=_NOT_ATTACHED_MATCH):
        _run(bridge.objc_enumerate_protocols())


def test_objc_enumerate_protocols_objc_error_raises() -> None:
    """objc_enumerate_protocols raises ToolError on objc_error response.

    Mutation caught: if the error check is removed, the method returns
    an empty list instead of raising.
    """
    bridge, _ = _build_attached_bridge()
    _patch_execute_script(bridge, {"type": "objc_error", "error": "no ObjC"})

    with pytest.raises(ToolError, match=_OBJC_UNAVAIL_MATCH):
        _run(bridge.objc_enumerate_protocols())


def test_objc_enumerate_protocols_returns_data_and_embeds_objc_protocols() -> None:
    """objc_enumerate_protocols parses protocols and embeds ObjC.protocols in script.

    Oracle for script framing: the script must reference ``ObjC.protocols``
    (not ``ObjC.classes``).

    Oracle for parsed result: the bridge must return exactly the two
    protocol strings the canned RPC delivered.

    Mutation caught: swapping ``ObjC.protocols`` for ``ObjC.classes``
    fails the framing check; accessing the wrong result key fails the
    value check.
    """
    bridge, _ = _build_attached_bridge()
    captured = _patch_execute_script(
        bridge,
        {"type": "objc_protocols", "data": ["NSCopying", "NSMutableCopying"]},
    )

    result = _run(bridge.objc_enumerate_protocols())

    assert result == ["NSCopying", "NSMutableCopying"], f"expected canned protocol list, got {result!r}"
    assert captured, "execute_script_and_wait was never called"
    assert "ObjC.protocols" in captured[0], f"script must reference ObjC.protocols; got:\n{captured[0]}"
    assert "ObjC.classes" not in captured[0], "script must not reference ObjC.classes for protocol enumeration"


def test_objc_enumerate_loaded_classes_not_attached() -> None:
    """objc_enumerate_loaded_classes raises ToolError when not attached.

    Mutation caught: removing the guard lets a None-session call proceed
    into script construction and crash with an AttributeError instead.
    """
    bridge = _make_bridge_unattached()

    with pytest.raises(ToolError, match=_NOT_ATTACHED_MATCH):
        _run(bridge.objc_enumerate_loaded_classes())


def test_objc_enumerate_loaded_classes_no_pattern_returns_all() -> None:
    """Without a pattern, all classes are pushed and the API call is present.

    Oracle for script framing: ``ObjC.enumerateLoadedClasses`` must appear
    in the generated script.  The script must NOT contain a regex variable
    when no pattern is provided (no spurious filtering).

    Oracle for parsed result: the method must return the exact list from
    ``data``.

    Mutation caught: using the wrong enumeration API
    (``ObjC.classes`` instead of ``ObjC.enumerateLoadedClasses``) fails
    the framing assertion.
    """
    bridge, _ = _build_attached_bridge()
    captured = _patch_execute_script(
        bridge,
        {"type": "objc_loaded_classes", "data": ["UIView", "UIViewController"]},
    )

    result = _run(bridge.objc_enumerate_loaded_classes())

    assert result == ["UIView", "UIViewController"], f"expected canned class list, got {result!r}"
    assert captured, "execute_script_and_wait was never called"
    assert "ObjC.enumerateLoadedClasses" in captured[0], f"script must call ObjC.enumerateLoadedClasses; got:\n{captured[0]}"
    assert "var regex" not in captured[0], "no-pattern path must not inject a regex filter"


def test_objc_enumerate_loaded_classes_with_pattern_embeds_pattern() -> None:
    """With a pattern, the pattern string and a regex variable appear in the script.

    Oracle for script framing: the pattern ``'NS*'`` must be embedded
    verbatim in the generated script so the JS side can build the glob.

    Mutation caught: if the bridge drops the pattern argument or does
    not embed it in the script, the framing assertion fails.
    """
    bridge, _ = _build_attached_bridge()
    captured = _patch_execute_script(
        bridge,
        {"type": "objc_loaded_classes", "data": ["NSObject", "NSString"]},
    )

    result = _run(bridge.objc_enumerate_loaded_classes(pattern="NS*"))

    assert result == ["NSObject", "NSString"]
    assert captured, "execute_script_and_wait was never called"
    assert "NS*" in captured[0], f"pattern 'NS*' must be embedded in the script; got:\n{captured[0]}"
    assert "var regex" in captured[0], "pattern path must inject a regex variable for glob matching"


def test_objc_choose_not_attached() -> None:
    """objc_choose raises ToolError when not attached.

    Mutation caught: omitting the session guard causes a crash instead
    of a structured error.
    """
    bridge = _make_bridge_unattached()

    with pytest.raises(ToolError, match=_NOT_ATTACHED_MATCH):
        _run(bridge.objc_choose("NSObject"))


def test_objc_choose_parses_hex_addresses_and_embeds_class_and_limit() -> None:
    """objc_choose parses hex address strings and embeds class name and limit.

    Oracle for script framing:
    - The class name ``'UIView'`` must appear in the generated script
      as the argument to ``ObjC.classes``.
    - The limit ``3`` must be embedded in the script as the comparison
      value for the ``count`` guard.

    Oracle for parsed result: hex strings ``'0x1000'``, ``'0x2000'``,
    ``'0x3000'`` must parse to integers ``4096``, ``8192``, ``12288``.

    Mutation caught: using the wrong address-parsing branch (decimal
    vs hex) produces wrong integers; injecting the wrong class name
    or limit produces wrong behaviour at JS execution time.
    """
    bridge, _ = _build_attached_bridge()
    captured = _patch_execute_script(
        bridge,
        {"type": "objc_choose", "data": ["0x1000", "0x2000", "0x3000"]},
    )

    result = _run(bridge.objc_choose("UIView", limit=3))

    assert result == [0x1000, 0x2000, 0x3000], f"hex addresses must parse to ints; got {result!r}"
    assert captured, "execute_script_and_wait was never called"
    assert "UIView" in captured[0], f"class name 'UIView' must be embedded in script; got:\n{captured[0]}"
    assert "3" in captured[0], f"limit 3 must be embedded in script; got:\n{captured[0]}"


def test_objc_choose_objc_error_raises() -> None:
    """objc_choose raises ToolError on objc_error response.

    Mutation caught: removing the error check returns an empty address
    list instead of propagating the runtime unavailability error.
    """
    bridge, _ = _build_attached_bridge()
    _patch_execute_script(bridge, {"type": "objc_error", "error": "no ObjC"})

    with pytest.raises(ToolError, match=_OBJC_UNAVAIL_MATCH):
        _run(bridge.objc_choose("UIView"))


def test_objc_get_class_methods_not_attached() -> None:
    """objc_get_class_methods raises ToolError when not attached.

    Mutation caught: removing the session guard allows the method to
    proceed into script creation with a None session.
    """
    bridge = _make_bridge_unattached()

    with pytest.raises(ToolError, match=_NOT_ATTACHED_MATCH):
        _run(bridge.objc_get_class_methods("NSObject"))


def test_objc_get_class_methods_returns_methods_and_embeds_class_name() -> None:
    """objc_get_class_methods returns the method list and embeds the class name.

    Oracle for script framing:
    - ``'NSObject'`` must appear in the script as the key into
      ``ObjC.classes``.
    - ``$ownMethods`` must be referenced to retrieve the method list.

    Oracle for parsed result: the bridge must return the three selector
    strings from the canned ``data`` array in order.

    Mutation caught: using the wrong class name field produces a lookup
    against the wrong class; using a property other than ``$ownMethods``
    returns a different (possibly inherited) method set.
    """
    bridge, _ = _build_attached_bridge()
    captured = _patch_execute_script(
        bridge,
        {"type": "objc_methods", "data": ["- init", "- dealloc", "+ new"]},
    )

    result = _run(bridge.objc_get_class_methods("NSObject"))

    assert result == ["- init", "- dealloc", "+ new"], f"expected canned method list, got {result!r}"
    assert captured, "execute_script_and_wait was never called"
    assert "NSObject" in captured[0], f"class name 'NSObject' must be embedded in script; got:\n{captured[0]}"
    assert "$ownMethods" in captured[0], f"script must access $ownMethods; got:\n{captured[0]}"


def test_objc_get_class_methods_objc_error_raises() -> None:
    """objc_get_class_methods raises ToolError on objc_error response.

    Mutation caught: removing the error guard silently returns an empty
    list even when the ObjC runtime signals unavailability.
    """
    bridge, _ = _build_attached_bridge()
    _patch_execute_script(bridge, {"type": "objc_error", "error": "no ObjC"})

    with pytest.raises(ToolError, match=_OBJC_UNAVAIL_MATCH):
        _run(bridge.objc_get_class_methods("NSObject"))


def test_objc_hook_method_not_attached() -> None:
    """objc_hook_method raises ToolError when no session is active.

    Mutation caught: removing the guard causes a crash on None session
    access rather than a structured ToolError.
    """
    bridge = _make_bridge_unattached()

    with pytest.raises(ToolError, match=_NOT_ATTACHED_MATCH):
        _run(bridge.objc_hook_method("NSURLSession", "dataTaskWithURL:"))


def test_objc_hook_method_happy_path_framing_and_result() -> None:
    """objc_hook_method embeds class/method in the script and builds HookInfo correctly.

    Oracle for script framing:
    - The class name ``'NSURLSession'`` must appear in the JS via
      ``ObjC.classes['NSURLSession']``.
    - The method selector ``'dataTaskWithURL:'`` must appear as the
      key used to look up ``.implementation``.

    Oracle for parsed result:
    - ``hook.target`` must equal ``'NSURLSession.dataTaskWithURL:'``
      (``{class_name}.{method_name}`` joining, not some other separator).
    - ``hook.address`` must equal ``0x12345678`` parsed from the hex
      string ``'0x12345678'`` delivered by the fake script.
    - ``hook.active`` must be ``True``.

    Mutation caught: changing the target string separator from ``.`` to
    ``':'`` fails the target assertion; using the wrong address field
    produces a wrong or None address.
    """
    bridge, session = _build_attached_bridge()

    async def driver() -> HookInfo:
        task: asyncio.Task[HookInfo] = asyncio.create_task(bridge.objc_hook_method("NSURLSession", "dataTaskWithURL:"))
        await asyncio.sleep(0)
        await _deliver_after_load(
            session,
            {"type": "objc_hooked", "address": "0x12345678"},
        )
        return await task

    hook = _run(driver())

    assert hook.target == "NSURLSession.dataTaskWithURL:", f"target must be 'NSURLSession.dataTaskWithURL:', got {hook.target!r}"
    assert hook.address == 0x12345678, f"address must parse from hex '0x12345678', got {hook.address!r}"
    assert hook.active is True

    assert session.sources, "create_script was never called"
    src = session.sources[0]
    assert "NSURLSession" in src, f"class name must be embedded in script; got:\n{src}"
    assert "dataTaskWithURL:" in src, f"method selector must be embedded in script; got:\n{src}"
    assert "ObjC.classes" in src, f"script must look up class via ObjC.classes; got:\n{src}"
    assert ".implementation" in src, f"script must access .implementation; got:\n{src}"


def test_objc_hook_method_objc_error_payload_raises() -> None:
    """objc_hook_method raises ToolError when the script delivers an objc_error payload.

    Mutation caught: if the message-loop check for ``'type': 'objc_error'``
    is removed, the bridge silently registers a broken hook instead of
    raising.
    """
    bridge, session = _build_attached_bridge()

    async def driver() -> None:
        task: asyncio.Task[HookInfo] = asyncio.create_task(bridge.objc_hook_method("NSObject", "init"))
        await asyncio.sleep(0)
        await _deliver_after_load(
            session,
            {"type": "objc_error", "error": "Objective-C runtime not available"},
        )
        await task

    with pytest.raises(ToolError, match=_OBJC_UNAVAIL_MATCH):
        _run(driver())


def test_objc_hook_method_js_error_raises() -> None:
    """objc_hook_method raises ToolError when the script raises a JS error.

    Mutation caught: if the ``elif msg['type'] == 'error'`` branch is
    dropped, a JavaScript runtime error is silently ignored and the
    bridge registers a hook that will never fire.
    """
    bridge, session = _build_attached_bridge()

    async def driver() -> None:
        task: asyncio.Task[HookInfo] = asyncio.create_task(bridge.objc_hook_method("NSObject", "dealloc"))
        await asyncio.sleep(0)
        await _deliver_after_load(
            session,
            {"__type": "error", "description": "ReferenceError: ObjC is not defined"},
        )
        await task

    with pytest.raises(ToolError, match=_HOOK_FAILED_MATCH):
        _run(driver())


def test_java_enumerate_loaded_classes_not_attached() -> None:
    """java_enumerate_loaded_classes raises ToolError when not attached.

    Mutation caught: removing the guard lets the call enter script
    construction with a None session.
    """
    bridge = _make_bridge_unattached()

    with pytest.raises(ToolError, match=_NOT_ATTACHED_MATCH):
        _run(bridge.java_enumerate_loaded_classes())


def test_java_enumerate_loaded_classes_no_pattern_returns_all() -> None:
    """Without a pattern, all classes are collected and the enumerate API is used.

    Oracle for script framing: ``Java.enumerateLoadedClasses`` must appear
    in the script.  No regex variable must be injected when no pattern is
    given.

    Oracle for parsed result: the method must return the exact list from
    ``data``.

    Mutation caught: using ``Java.perform`` alone without
    ``Java.enumerateLoadedClasses`` fails the framing check; accessing
    the wrong result key fails the value check.
    """
    bridge, _ = _build_attached_bridge()
    captured = _patch_execute_script(
        bridge,
        {
            "type": "java_classes",
            "data": [
                "com.example.App",
                "com.example.MainActivity",
            ],
        },
    )

    result = _run(bridge.java_enumerate_loaded_classes())

    assert result == ["com.example.App", "com.example.MainActivity"], f"expected canned class list, got {result!r}"
    assert captured, "execute_script_and_wait was never called"
    assert "Java.enumerateLoadedClasses" in captured[0], f"script must call Java.enumerateLoadedClasses; got:\n{captured[0]}"
    assert "var regex" not in captured[0], "no-pattern path must not inject a regex filter"


def test_java_enumerate_loaded_classes_with_pattern_embeds_pattern() -> None:
    """With a pattern, the pattern string appears in the generated script.

    Oracle for script framing: the pattern ``'com.*'`` must be embedded
    verbatim in the script so the JS side can build the glob regex.

    Mutation caught: dropping the pattern argument or failing to embed it
    means every class would be collected regardless of the requested filter.
    """
    bridge, _ = _build_attached_bridge()
    captured = _patch_execute_script(
        bridge,
        {"type": "java_classes", "data": ["com.example.App"]},
    )

    result = _run(bridge.java_enumerate_loaded_classes(pattern="com.*"))

    assert result == ["com.example.App"]
    assert captured, "execute_script_and_wait was never called"
    assert "com.*" in captured[0], f"pattern 'com.*' must be embedded in script; got:\n{captured[0]}"
    assert "var regex" in captured[0], "pattern path must inject a regex variable"


def test_java_enumerate_loaded_classes_java_error_raises() -> None:
    """java_enumerate_loaded_classes raises ToolError on java_error response.

    Mutation caught: removing the error check silently returns an empty
    list on Android devices where Java is unavailable during the script run.
    """
    bridge, _ = _build_attached_bridge()
    _patch_execute_script(bridge, {"type": "java_error", "error": "no Java"})

    with pytest.raises(ToolError, match=_JAVA_UNAVAIL_MATCH):
        _run(bridge.java_enumerate_loaded_classes())


def test_java_choose_not_attached() -> None:
    """java_choose raises ToolError when not attached.

    Mutation caught: removing the guard causes the method to attempt
    script construction against a None session.
    """
    bridge = _make_bridge_unattached()

    with pytest.raises(ToolError, match=_NOT_ATTACHED_MATCH):
        _run(bridge.java_choose("com.example.App"))


def test_java_choose_returns_instances_and_embeds_class_and_limit() -> None:
    """java_choose returns instance strings and embeds class name and limit.

    Oracle for script framing:
    - ``'com.example.App'`` must appear in the script as the class
      argument to ``Java.choose``.
    - ``5`` must appear as the count-guard threshold.

    Oracle for parsed result: the canned list of two instance strings
    must be returned exactly.

    Mutation caught: using the wrong class name or wrong limit produces
    incorrect JS behaviour; accessing the wrong result key produces the
    wrong list.
    """
    bridge, _ = _build_attached_bridge()
    captured = _patch_execute_script(
        bridge,
        {
            "type": "java_choose",
            "data": ["com.example.App@1a2b3c4d", "com.example.App@5e6f7a8b"],
        },
    )

    result = _run(bridge.java_choose("com.example.App", limit=5))

    assert result == ["com.example.App@1a2b3c4d", "com.example.App@5e6f7a8b"], f"expected canned instance list, got {result!r}"
    assert captured, "execute_script_and_wait was never called"
    assert "com.example.App" in captured[0], f"class name must be embedded in script; got:\n{captured[0]}"
    assert "5" in captured[0], f"limit 5 must be embedded in script; got:\n{captured[0]}"


def test_java_choose_java_error_raises() -> None:
    """java_choose raises ToolError on java_error response.

    Mutation caught: removing the error check returns an empty list
    instead of propagating the runtime unavailability signal.
    """
    bridge, _ = _build_attached_bridge()
    _patch_execute_script(bridge, {"type": "java_error", "error": "no Java"})

    with pytest.raises(ToolError, match=_JAVA_UNAVAIL_MATCH):
        _run(bridge.java_choose("com.example.App"))


def test_java_use_not_attached() -> None:
    """java_use raises ToolError when not attached.

    Mutation caught: removing the guard allows the method to proceed
    with a None session.
    """
    bridge = _make_bridge_unattached()

    with pytest.raises(ToolError, match=_NOT_ATTACHED_MATCH):
        _run(bridge.java_use("com.example.App"))


def test_java_use_returns_dict_and_embeds_class_name() -> None:
    """java_use returns the full result dict and embeds the class name via Java.use.

    Oracle for script framing:
    - ``Java.use`` must appear in the script (the bridge must call it
      rather than a different Java API).
    - ``'com.example.App'`` must appear as the argument to ``Java.use``.

    Oracle for parsed result:
    - The returned dict must contain ``className == 'com.example.App'``
      and ``methods == ['onCreate', 'checkLicense']`` — the exact values
      from the canned RPC response, not values the bridge recomputed.

    Mutation caught: calling a different Java API than ``Java.use``
    fails the framing check; accessing the wrong result key produces
    wrong or missing fields in the returned dict.
    """
    bridge, _ = _build_attached_bridge()
    canned: dict[str, object] = {
        "type": "java_use",
        "className": "com.example.App",
        "methods": ["onCreate", "checkLicense"],
    }
    captured = _patch_execute_script(bridge, canned)

    result = _run(bridge.java_use("com.example.App"))

    assert result.get("className") == "com.example.App", f"className must be 'com.example.App', got {result.get('className')!r}"
    assert result.get("methods") == ["onCreate", "checkLicense"], f"methods must match canned list, got {result.get('methods')!r}"
    assert captured, "execute_script_and_wait was never called"
    assert "Java.use" in captured[0], f"script must call Java.use; got:\n{captured[0]}"
    assert "com.example.App" in captured[0], f"class name must be embedded in script; got:\n{captured[0]}"


def test_java_use_java_error_raises() -> None:
    """java_use raises ToolError on java_error response.

    Mutation caught: removing the error guard returns an incomplete dict
    rather than signalling that the Java runtime is unavailable.
    """
    bridge, _ = _build_attached_bridge()
    _patch_execute_script(bridge, {"type": "java_error", "error": "no Java"})

    with pytest.raises(ToolError, match=_JAVA_UNAVAIL_MATCH):
        _run(bridge.java_use("com.example.App"))


def test_java_hook_method_not_attached() -> None:
    """java_hook_method raises ToolError when no session is active.

    Mutation caught: removing the guard lets the method enter script
    creation against a None session.
    """
    bridge = _make_bridge_unattached()

    with pytest.raises(ToolError, match=_NOT_ATTACHED_MATCH):
        _run(bridge.java_hook_method("com.example.App", "checkLicense"))


def test_java_hook_method_no_overloads_framing_and_result() -> None:
    """java_hook_method without overloads embeds class/method and builds HookInfo.

    Oracle for script framing:
    - ``Java.use('com.example.App')`` must appear in the script.
    - ``'checkLicense'`` must appear as the method key.
    - The overload suffix must NOT appear (no overloads requested).

    Oracle for parsed result:
    - ``hook.target`` must equal ``'com.example.App.checkLicense'``.
    - ``hook.active`` must be ``True``.
    - ``hook.address`` must be ``None`` (Java hooks carry no native address).

    Mutation caught: building the target from the wrong fields produces
    the wrong ``hook.target``; injecting a spurious overload spec
    when none was requested fails the framing check.
    """
    bridge, session = _build_attached_bridge()

    async def driver() -> HookInfo:
        task: asyncio.Task[HookInfo] = asyncio.create_task(bridge.java_hook_method("com.example.App", "checkLicense"))
        await asyncio.sleep(0)
        await _deliver_after_load(
            session,
            {
                "type": "java_hooked",
                "className": "com.example.App",
                "method": "checkLicense",
            },
        )
        return await task

    hook = _run(driver())

    assert hook.target == "com.example.App.checkLicense", f"target must be 'com.example.App.checkLicense', got {hook.target!r}"
    assert hook.active is True
    assert hook.address is None, "java hook must carry no native address"

    assert session.sources, "create_script was never called"
    src = session.sources[0]
    assert "Java.use" in src, f"script must call Java.use; got:\n{src}"
    assert "com.example.App" in src, f"class name must be embedded in script; got:\n{src}"
    assert "checkLicense" in src, f"method name must be embedded in script; got:\n{src}"
    assert ".overload(" not in src, "no overloads requested; script must not contain .overload()"


def test_java_hook_method_with_overloads_embeds_overload_spec() -> None:
    """java_hook_method with overloads embeds the overload signature in the script.

    Oracle for script framing: ``.overload('java.lang.String', 'int')``
    must appear verbatim in the generated script when
    ``overloads=['java.lang.String', 'int']`` is passed.

    Mutation caught: omitting the overload construction or joining the
    arguments in the wrong order produces the wrong selector at runtime,
    causing the hook to target the wrong overload of a polymorphic method.
    """
    bridge, session = _build_attached_bridge()

    async def driver() -> HookInfo:
        task: asyncio.Task[HookInfo] = asyncio.create_task(
            bridge.java_hook_method(
                "com.example.Crypto",
                "encrypt",
                overloads=["java.lang.String", "int"],
            ),
        )
        await asyncio.sleep(0)
        await _deliver_after_load(
            session,
            {
                "type": "java_hooked",
                "className": "com.example.Crypto",
                "method": "encrypt",
            },
        )
        return await task

    hook = _run(driver())

    assert hook.target == "com.example.Crypto.encrypt"
    assert session.sources, "create_script was never called"
    src = session.sources[0]
    assert ".overload('java.lang.String', 'int')" in src, f"overload spec must be embedded verbatim in script; got:\n{src}"


def test_java_hook_method_java_error_payload_raises() -> None:
    """java_hook_method raises ToolError when the script delivers a java_error payload.

    Mutation caught: removing the ``'type': 'java_error'`` check in the
    message loop silently registers a broken hook.
    """
    bridge, session = _build_attached_bridge()

    async def driver() -> None:
        task: asyncio.Task[HookInfo] = asyncio.create_task(bridge.java_hook_method("com.example.App", "checkLicense"))
        await asyncio.sleep(0)
        await _deliver_after_load(
            session,
            {"type": "java_error", "error": "Java runtime not available"},
        )
        await task

    with pytest.raises(ToolError, match=_JAVA_UNAVAIL_MATCH):
        _run(driver())


def test_java_deoptimize_not_attached() -> None:
    """java_deoptimize raises ToolError when not attached.

    Mutation caught: removing the session guard allows the method to
    attempt deoptimization with no active process.
    """
    bridge = _make_bridge_unattached()

    with pytest.raises(ToolError, match=_NOT_ATTACHED_MATCH):
        _run(bridge.java_deoptimize())


def test_java_deoptimize_returns_true_and_embeds_deoptimize_api() -> None:
    """java_deoptimize returns True and embeds Java.deoptimizeEverything in the script.

    Oracle for script framing: ``Java.deoptimizeEverything`` must appear
    in the generated script — the bridge must call this specific API.

    Oracle for parsed result: the method must return exactly ``True``
    (not a truthy non-boolean) when the script delivers a success payload.

    Mutation caught: calling a different deoptimization API fails the
    framing check; returning a non-boolean or the raw result dict fails
    the value assertion.
    """
    bridge, _ = _build_attached_bridge()
    captured = _patch_execute_script(
        bridge,
        {"type": "java_deoptimized", "success": True},
    )

    result = _run(bridge.java_deoptimize())

    assert result is True, f"java_deoptimize must return True, got {result!r}"
    assert captured, "execute_script_and_wait was never called"
    assert "Java.deoptimizeEverything" in captured[0], f"script must call Java.deoptimizeEverything; got:\n{captured[0]}"
    assert "Java.perform" in captured[0], f"script must wrap deoptimization in Java.perform; got:\n{captured[0]}"


def test_java_deoptimize_java_error_raises() -> None:
    """java_deoptimize raises ToolError on java_error response.

    Mutation caught: removing the error guard returns True even when the
    Java runtime signals unavailability, hiding the real failure.
    """
    bridge, _ = _build_attached_bridge()
    _patch_execute_script(bridge, {"type": "java_error", "error": "no Java"})

    with pytest.raises(ToolError, match=_JAVA_UNAVAIL_MATCH):
        _run(bridge.java_deoptimize())
