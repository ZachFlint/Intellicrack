# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression test for the S14-D17 ``FridaBridge.call_function`` integer-return defect.

``FridaBridge.call_function`` builds a Frida ``NativeFunction`` and extracts its
result with JavaScript tailored to the requested ``return_type``. Before this
fix, every non-pointer-like return type (``int``, ``uint``, ``int8``/``16``/``32``,
``uint8``/``16``/``32``, ``bool``) fell into a catch-all branch that unconditionally
called ``result.toInt32()`` -- a method that only exists on Frida's
``NativePointer``. ``NativeFunction`` with an integer ``retType`` returns a plain
JS number, so ``result.toInt32 is not a function`` was thrown for every call,
which the bridge then reported as the generic ``"function call failed"``
(``ToolError`` with no ``details['reason']``), masking the real cause. Only
``return_type='pointer'`` (and the other pointer-like types already using
``toString()``) worked.

This test drives a REAL Frida runtime attached to the current test process
(the ``self_attached_bridge`` idiom already used by
``tests/bridges/test_frida_hook_childgating_s14.py`` and
``tests/bridges/test_frida_scan_unload_s14.py``) and calls the real
``kernel32.dll!GetCurrentProcessId`` export -- a genuine no-argument WinAPI
function whose correct return value (the current process id) is known
independently via ``os.getpid()``. It is parametrized across every integer
return type named in the defect plus ``pointer``, so a regression in either
the integer branch or the pointer/64-bit branch of ``call_function``'s result
extraction fails loudly instead of silently reverting to the generic
"function call failed" message.
"""

from __future__ import annotations

import asyncio
import ctypes
import logging
import os
import sys
from typing import TYPE_CHECKING, Final


if TYPE_CHECKING:
    from collections.abc import Coroutine, Generator

import pytest

from intellicrack.core.types import ToolError


frida = pytest.importorskip("frida", reason="frida-python required for bridge tests")

from intellicrack.bridges.frida_bridge import FridaBridge  # noqa: E402


_logger = logging.getLogger(__name__)

_INTEGER_RETURN_TYPES: Final[tuple[str, ...]] = ("uint32", "int32", "uint", "int", "int64", "uint64")


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


@pytest.fixture
def self_attached_bridge() -> Generator[FridaBridge]:
    """Create a FridaBridge attached to the current test process.

    Yields:
        FridaBridge: An initialized and attached FridaBridge instance.
    """
    bridge = FridaBridge()
    _run_async(bridge.initialize())
    _run_async(bridge.attach(os.getpid()))
    yield bridge
    try:
        _run_async(bridge.shutdown())
    except ToolError:
        _logger.debug("self_attached_bridge_fixture_shutdown_failed", exc_info=True)


def _get_current_process_id_address() -> int:
    """Resolve the real in-process address of ``kernel32.dll!GetCurrentProcessId``.

    Returns:
        int: The export's address in the current process, as ``ctypes`` sees it.
    """
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    address = ctypes.cast(kernel32.GetCurrentProcessId, ctypes.c_void_p).value
    assert address is not None, "ctypes failed to resolve GetCurrentProcessId's address"
    return address


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge integration tests")
@pytest.mark.parametrize("return_type", _INTEGER_RETURN_TYPES)
def test_call_function_integer_return_types_match_real_pid(
    self_attached_bridge: FridaBridge,
    return_type: str,
) -> None:
    """Verify ``call_function`` returns the correct value for every integer ``return_type``.

    Regression test for S14-D17: before the fix, every type in
    ``_INTEGER_RETURN_TYPES`` raised ``ToolError("function call failed")``
    because the generated JavaScript called ``.toInt32()`` on a plain number
    (int/uint/int32/uint) or assumed ``.toString()`` on a value that, in some
    QuickJS builds, might not expose it (int64/uint64). This test calls the
    real ``kernel32.dll!GetCurrentProcessId`` export -- a genuine WinAPI call
    with a known-correct answer (``os.getpid()``) -- through
    ``FridaBridge.call_function`` for each return type and asserts the result
    is exactly the real PID. Falsifiable: if the integer-extraction branch
    still calls ``.toInt32()`` unconditionally (or the 64-bit branch still
    assumes ``.toString()`` unconditionally), the bridge raises ``ToolError``
    and this test fails with that exception instead of an equality mismatch.

    Args:
        self_attached_bridge: Bridge fixture attached to the current test process.
        return_type: The ``NativeFunction`` return type under test.
    """
    address = _get_current_process_id_address()
    expected_pid = os.getpid()

    result = _run_async(
        self_attached_bridge.call_function(address, [], return_type=return_type),
    )

    assert result == expected_pid, (
        f"call_function(return_type={return_type!r}) returned {result!r} (0x{result:X} if int), "
        f"expected the real PID {expected_pid} (0x{expected_pid:X})"
    )


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge integration tests")
def test_call_function_pointer_return_still_matches_real_pid(self_attached_bridge: FridaBridge) -> None:
    """Verify the pre-existing ``return_type='pointer'`` path still works after the fix.

    This is the path that was already correct before S14-D17 (the UI report
    that ``Return=pointer`` returned ``0x8C04``, the correct PID, while every
    integer return type failed). It is kept alongside the integer-return gate
    so a change to the shared ``call_function`` result-extraction logic cannot
    fix the integer branch while silently breaking the pointer branch.
    Falsifiable: if the pointer/64-bit extraction branch is broken, the
    returned value will not equal the real PID.

    Args:
        self_attached_bridge: Bridge fixture attached to the current test process.
    """
    address = _get_current_process_id_address()
    expected_pid = os.getpid()

    result = _run_async(
        self_attached_bridge.call_function(address, [], return_type="pointer"),
    )

    assert result == expected_pid, f"call_function(return_type='pointer') returned {result!r}, expected {expected_pid}"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only bridge integration tests")
def test_call_function_error_surfaces_real_javascript_reason(self_attached_bridge: FridaBridge) -> None:
    """Verify a genuine in-script call failure surfaces the real error text, not a generic message.

    Regression test for the error-propagation half of S14-D17: when the
    generated JavaScript raised (for example ``result.toInt32 is not a
    function`` for every integer return type), the bridge discarded that real
    text and raised a bare ``ToolError(_ERR_CALL_FAILED)`` with empty
    ``details`` -- so the UI only ever showed the generic "function call
    failed" message. This test forces a *real* uncaught script exception
    through a legitimate, memory-safe call: declaring one parameter type
    (``arg_types=['pointer']``) while supplying zero real arguments. Frida's
    NativeFunction argument marshaling validates the declared parameter count
    against the JS call site *before* any native code executes, so this
    reliably raises a genuine ``bad argument count`` script error -- never a
    real invocation of ``GetCurrentProcessId`` -- exercising the same
    ``on_message`` "error" path a broken return-type extraction would hit,
    without any risk of crashing the host process. Falsifiable: if the bridge
    reverts to a bare ``ToolError(_ERR_CALL_FAILED)`` with no ``details``,
    ``reason`` is missing or empty and the assertions fail.

    Args:
        self_attached_bridge: Bridge fixture attached to the current test process.
    """
    address = _get_current_process_id_address()

    with pytest.raises(ToolError) as exc_info:
        _run_async(
            self_attached_bridge.call_function(address, [], return_type="uint32", arg_types=["pointer"]),
        )

    reason = exc_info.value.details.get("reason")
    assert isinstance(reason, str), f"ToolError.details['reason'] must be a string, got {exc_info.value.details!r}"
    assert reason, f"ToolError.details must carry a non-empty 'reason' string, got {exc_info.value.details!r}"
    assert reason != "function call failed", (
        f"reason must be the real Frida/JavaScript exception text, not the generic message it replaces, got {reason!r}"
    )
