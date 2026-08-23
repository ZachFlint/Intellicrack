# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression tests for FridaBridge child-gating not-supported classification.

Covers defect A6 (S14-D18, Low): ``FridaBridge.enable_child_gating`` and
``FridaBridge.disable_child_gating`` used to catch every failure from
``Device.enable_spawn_gating`` / ``Device.disable_spawn_gating`` with a single
broad ``except Exception`` handler and set ``ToolError.details['reason']`` to
whatever ``str(e)`` happened to contain. On platforms where spawn gating is
unsupported, Frida's Python binding raises ``frida.NotSupportedError``, but
the bridge never classified that condition -- it relied entirely on fragile
third-party error text instead of a stable, distinct, user-meaningful reason.

The fix adds an explicit ``except frida.NotSupportedError`` branch (ordered
before the broad ``except Exception`` fallback) in both operations that
raises a ``ToolError`` carrying the stable ``_ERR_CHILD_GATING_NOT_SUPPORTED``
reason instead of the raw exception text, while any other exception type
still falls through to the pre-existing generic classification.

These tests drive the REAL ``FridaBridge.enable_child_gating`` /
``disable_child_gating`` code paths against a minimal device double whose
``enable_spawn_gating`` / ``disable_spawn_gating`` raise real Frida exception
instances (``frida.NotSupportedError`` for the not-supported case, a plain
``RuntimeError`` for the discriminator case). Only the external Frida
transport object is substituted -- all bridge classification logic under
test executes unchanged, and the assertions are made against the real,
un-mocked ``ToolError`` the bridge raises. Requires frida-python.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Final


if TYPE_CHECKING:
    from collections.abc import Coroutine

    import frida

    from intellicrack.bridges.frida_bridge import FridaBridge

import pytest

from intellicrack.core.types import ToolError


try:
    import frida

    from intellicrack.bridges.frida_bridge import FridaBridge

    _frida_available: bool = True
except ImportError:
    _frida_available = False


_logger = logging.getLogger(__name__)

_NOT_SUPPORTED_MESSAGE: Final[str] = "not yet supported on this OS"
_GENERIC_FAILURE_MESSAGE: Final[str] = "synthetic device failure for A6/S14-D18 discriminator"
_EXPECTED_NOT_SUPPORTED_REASON: Final[str] = "child gating is not supported on this OS"
_EXPECTED_GENERIC_MESSAGE: Final[str] = "child gating operation failed"


@pytest.fixture(autouse=True)
def require_frida() -> None:
    """Skip every test in this module when frida-python is not installed."""
    if not _frida_available:
        pytest.skip("frida-python required for bridge tests")


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


class _NotSupportedSpawnGatingDevice:
    """Device double whose spawn-gating calls raise ``frida.NotSupportedError``.

    Mirrors the shape of the real Frida local device on a platform where
    spawn gating is unavailable: ``on`` registers callbacks like the real
    ``Device.on``, and both spawn-gating operations raise the real
    ``frida.NotSupportedError`` exception class carrying the actual message
    Frida uses for this condition.
    """

    def on(self, event: str, callback: object) -> None:
        """Register an event callback, mirroring ``frida.core.Device.on``.

        Args:
            event: Event name string (e.g. ``"child-added"``).
            callback: Callable to invoke when the event fires.
        """
        del event, callback

    def enable_spawn_gating(self) -> None:
        """Raise ``frida.NotSupportedError``, mirroring an unsupported platform.

        Raises:
            frida.NotSupportedError: Always, with the real Frida message text.
        """
        raise frida.NotSupportedError(_NOT_SUPPORTED_MESSAGE)

    def disable_spawn_gating(self) -> None:
        """Raise ``frida.NotSupportedError``, mirroring an unsupported platform.

        Raises:
            frida.NotSupportedError: Always, with the real Frida message text.
        """
        raise frida.NotSupportedError(_NOT_SUPPORTED_MESSAGE)


class _GenericFailureSpawnGatingDevice:
    """Device double whose spawn-gating calls raise a non-Frida exception.

    Used as the discriminator: an exception type other than
    ``frida.NotSupportedError`` must still fall through to the pre-existing
    generic ``_ERR_CHILD_GATING_FAILED`` classification, proving that the
    not-supported branch is a real classification rather than every failure
    collapsing onto the same stable reason.
    """

    def on(self, event: str, callback: object) -> None:
        """Register an event callback, mirroring ``frida.core.Device.on``.

        Args:
            event: Event name string (e.g. ``"child-added"``).
            callback: Callable to invoke when the event fires.
        """
        del event, callback

    def enable_spawn_gating(self) -> None:
        """Raise a plain ``RuntimeError`` unrelated to platform support.

        Raises:
            RuntimeError: Always, with a synthetic message.
        """
        raise RuntimeError(_GENERIC_FAILURE_MESSAGE)

    def disable_spawn_gating(self) -> None:
        """Raise a plain ``RuntimeError`` unrelated to platform support.

        Raises:
            RuntimeError: Always, with a synthetic message.
        """
        raise RuntimeError(_GENERIC_FAILURE_MESSAGE)


def test_enable_child_gating_not_supported_yields_stable_reason() -> None:
    """Verify ``enable_child_gating`` classifies ``frida.NotSupportedError`` distinctly.

    Regression test for A6/S14-D18: drives the real ``FridaBridge.enable_child_gating``
    against a device double whose ``enable_spawn_gating`` raises the real
    ``frida.NotSupportedError``, and asserts the raised ``ToolError`` carries
    the stable ``_ERR_CHILD_GATING_NOT_SUPPORTED`` reason rather than the raw,
    fragile ``str(e)`` text. Falsifiable: if the bridge still funnels this
    exception through the broad ``except Exception`` fallback, ``details['reason']``
    would instead equal the raw Frida message text and this assertion fails.
    """
    bridge = FridaBridge()
    setattr(bridge, "_device", _NotSupportedSpawnGatingDevice())

    with pytest.raises(ToolError) as exc_info:
        _run_async(bridge.enable_child_gating())

    reason = exc_info.value.details.get("reason")
    assert reason == _EXPECTED_NOT_SUPPORTED_REASON, (
        f"expected the stable not-supported reason {_EXPECTED_NOT_SUPPORTED_REASON!r}, got {reason!r}"
    )
    assert reason != _NOT_SUPPORTED_MESSAGE, (
        "reason must not be the raw, fragile frida.NotSupportedError text -- classification must produce a stable, distinct message"
    )


def test_enable_child_gating_other_exception_yields_generic_reason() -> None:
    """Verify a non-``NotSupportedError`` failure still yields the generic reason.

    Discriminator for A6/S14-D18: drives the real ``FridaBridge.enable_child_gating``
    against a device double whose ``enable_spawn_gating`` raises a plain
    ``RuntimeError`` (not ``frida.NotSupportedError``), and asserts the raised
    ``ToolError`` still carries the pre-existing generic classification
    (``_ERR_CHILD_GATING_FAILED`` with the raw exception text as the reason).
    This proves the new ``frida.NotSupportedError`` branch is a real,
    type-specific classification rather than every failure collapsing onto
    the same stable not-supported message. Falsifiable: if the bridge were
    broken so every exception is classified as not-supported, ``reason``
    would equal ``_ERR_CHILD_GATING_NOT_SUPPORTED`` instead of the raw
    ``RuntimeError`` text and this assertion fails.
    """
    bridge = FridaBridge()
    setattr(bridge, "_device", _GenericFailureSpawnGatingDevice())

    with pytest.raises(ToolError) as exc_info:
        _run_async(bridge.enable_child_gating())

    assert exc_info.value.message == _EXPECTED_GENERIC_MESSAGE, (
        f"expected the generic classification {_EXPECTED_GENERIC_MESSAGE!r}, got {exc_info.value.message!r}"
    )
    reason = exc_info.value.details.get("reason")
    assert reason == _GENERIC_FAILURE_MESSAGE, (
        f"expected the raw exception text {_GENERIC_FAILURE_MESSAGE!r} to pass through unclassified, got {reason!r}"
    )
    assert reason != _EXPECTED_NOT_SUPPORTED_REASON, "a RuntimeError must never be classified as the not-supported condition"


def test_disable_child_gating_not_supported_yields_stable_reason() -> None:
    """Verify ``disable_child_gating`` classifies ``frida.NotSupportedError`` distinctly.

    Symmetric sibling coverage for A6/S14-D18: the same ``frida.NotSupportedError``
    classification applied to ``enable_child_gating`` must also apply to
    ``disable_child_gating``. Drives the real ``FridaBridge.disable_child_gating``
    (with ``_child_gating_enabled`` pre-set so the operation does not take its
    early no-op return path) against a device double whose
    ``disable_spawn_gating`` raises the real ``frida.NotSupportedError``, and
    asserts the raised ``ToolError`` carries the same stable
    ``_ERR_CHILD_GATING_NOT_SUPPORTED`` reason. Falsifiable: if the sibling
    operation was left with only the broad ``except Exception`` fallback,
    ``details['reason']`` would be absent (the generic branch on this
    operation does not attach a reason at all) and this assertion fails.
    """
    bridge = FridaBridge()
    setattr(bridge, "_device", _NotSupportedSpawnGatingDevice())
    setattr(bridge, "_child_gating_enabled", True)

    with pytest.raises(ToolError) as exc_info:
        _run_async(bridge.disable_child_gating())

    reason = exc_info.value.details.get("reason")
    assert reason == _EXPECTED_NOT_SUPPORTED_REASON, (
        f"expected the stable not-supported reason {_EXPECTED_NOT_SUPPORTED_REASON!r}, got {reason!r}"
    )
