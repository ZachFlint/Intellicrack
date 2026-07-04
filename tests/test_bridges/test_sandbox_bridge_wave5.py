# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-gate tests for SandboxBridge state management (Group 06 Wave 5).

Covers:
  S12-03 — ``_StateTracker`` clears ``BridgeState.last_error`` on success
            after a prior failure; the fail-then-succeed lifecycle is verified
            without mocking any production code.
  S12-04 — Replacement gates for behaviors tested with fake gates in
            ``tests/test_bridges/test_sandbox_bridge.py`` (that file uses
            ``AsyncMock``/``MagicMock``/``patch.object`` on the operations
            under test).  These gates use real ``SandboxBridge`` methods
            against deterministic code paths that require no external sandbox.

Note: ``tests/test_bridges/test_sandbox_bridge.py`` cannot be deleted per
wave-5 constraints, but its behaviors are now properly gated here.
"""

from __future__ import annotations

import asyncio
from contextlib import AbstractAsyncContextManager
from typing import cast

import pytest

from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.core.types import ToolError


_SENTINEL_ERROR_TEXT: str = "sentinel error text"
_FIRST_CALL_FAIL_TEXT: str = "first call failed"


class _SentinelError(RuntimeError):
    """Sentinel error for testing _StateTracker failure path."""


class _FirstCallError(RuntimeError):
    """Error raised on the first call in fail-then-succeed lifecycle tests."""


def _raise_sentinel() -> None:
    """Raise a SentinelError with the module-level sentinel text.

    Raises:
        _SentinelError: Always raised; used to test state tracker failure recording.
    """
    raise _SentinelError(_SENTINEL_ERROR_TEXT)


def _raise_first_call_failure() -> None:
    """Raise a FirstCallError with the module-level first-call text.

    Raises:
        _FirstCallError: Always raised; used to test fail-then-succeed lifecycle.
    """
    raise _FirstCallError(_FIRST_CALL_FAIL_TEXT)


class _TestableSandboxBridge(SandboxBridge):
    """SandboxBridge subclass exposing protected internals for white-box testing.

    Accessing single-underscore (protected) members from within a subclass is
    allowed by Python convention; this wrapper exposes them as public methods so
    test code never touches ``_private`` attributes directly.
    """

    def set_state_outcome(self, error: str | None) -> None:
        """Delegate to _set_state_outcome for test code.

        Args:
            error: Error string to record in ``last_error``, or ``None`` to clear.
        """
        self._set_state_outcome(error)

    def track_state(self, operation: str) -> AbstractAsyncContextManager[None]:
        """Expose _track_state as an async context manager for test code.

        Args:
            operation: Name of the operation being tracked.

        Returns:
            AbstractAsyncContextManager[None]: Async context manager that updates
                ``state.last_error`` on exit.
        """
        return cast(AbstractAsyncContextManager[None], self._track_state(operation))

    def simulate_shutdown(self) -> None:
        """Set the bridge into the post-shutdown state used by S12-04 tests."""
        self._manager_destroyed = True
        self._manager = None


class TestStateTrackerClearsLastErrorOnSuccess:
    """Gate for S12-03: _StateTracker clears last_error when the block succeeds."""

    def test_last_error_cleared_to_none_after_successful_op(self) -> None:
        """last_error is None after track_state succeeds following a prior failure.

        Oracle: ``_StateTracker.__aexit__`` calls ``apply_outcome(None)`` when
        ``exc is None``; ``_set_state_outcome(None)`` then writes
        ``dataclasses.replace(current, last_error=None)`` to ``self.state``.
        Mutation: calling ``apply_outcome(str(exc))`` for success (a copy-paste
        error in the None guard) would leave ``last_error`` set to ``"None"``
        (the string), failing the ``is None`` assertion.
        """
        bridge = _TestableSandboxBridge()
        bridge.set_state_outcome("prior failure message")
        assert bridge.state.last_error == "prior failure message", "Pre-condition: last_error must be set before testing clear"

        async def _run() -> None:
            async with bridge.track_state("test_success"):
                pass

        asyncio.run(_run())
        assert bridge.state.last_error is None, (
            f"last_error must be None after successful track_state block; got {bridge.state.last_error!r}"
        )

    def test_last_error_set_to_exception_text_on_failure(self) -> None:
        """last_error records the exception text when the track_state block raises.

        Oracle: ``_StateTracker.__aexit__`` calls ``apply_outcome(str(exc))``
        when an exception propagates; ``_set_state_outcome(str(exc))`` writes
        ``last_error=str(exc)`` to the state.  The exception is re-raised
        unchanged so callers can handle it normally.
        Mutation: calling ``apply_outcome(None)`` even on failure would clear
        ``last_error``, making the test fail because ``last_error`` would
        remain None instead of the error text.
        """
        bridge = _TestableSandboxBridge()

        async def _run() -> None:
            try:
                async with bridge.track_state("failing_op"):
                    _raise_sentinel()
            except _SentinelError:
                pass

        asyncio.run(_run())
        assert bridge.state.last_error == _SENTINEL_ERROR_TEXT, (
            f"last_error must be set to the exception text; got {bridge.state.last_error!r}"
        )

    def test_fail_then_succeed_clears_last_error(self) -> None:
        """Fail-then-succeed lifecycle: last_error is set then cleared to None.

        This is the exact scenario described in S12-03: the first call raises
        (setting last_error), the second call succeeds (clearing last_error).
        Oracle: ``_StateTracker`` is symmetric; success always clears regardless
        of prior state.  Mutation: adding a guard ``if self.state.last_error
        is not None: return`` before the clear would make the cycle fail.
        """
        bridge = _TestableSandboxBridge()

        async def _run() -> None:
            try:
                async with bridge.track_state("first_call_fails"):
                    _raise_first_call_failure()
            except _FirstCallError:
                pass

            assert bridge.state.last_error == _FIRST_CALL_FAIL_TEXT, "Pre-condition: last_error must be set after first failure"

            async with bridge.track_state("second_call_succeeds"):
                pass

        asyncio.run(_run())

        assert bridge.state.last_error is None, (
            f"last_error must be None after the second (successful) call; got {bridge.state.last_error!r}"
        )

    def test_set_state_outcome_no_op_when_value_unchanged(self) -> None:
        """set_state_outcome is idempotent when the value has not changed.

        Oracle: the guard ``if current.last_error == error: return`` prevents
        the state property setter from firing (and emitting log records) when
        the error value is identical.  This test verifies that calling
        ``set_state_outcome(None)`` on a fresh bridge (already None) does
        not raise and leaves last_error as None.
        Mutation: removing the equality guard would always replace the state
        object; this test would still pass but a logging-side-effect check
        would fail if added later.
        """
        bridge = _TestableSandboxBridge()
        assert bridge.state.last_error is None
        bridge.set_state_outcome(None)
        assert bridge.state.last_error is None


class TestSandboxBridgeManagerGates:
    """Gate for S12-04: SandboxBridge operation error paths without mocking.

    These tests replace the behaviors covered by fake gates in
    ``tests/test_bridges/test_sandbox_bridge.py``, which uses
    ``AsyncMock``/``MagicMock``/``patch.object`` on the operations under test.
    All tests here drive the real ``SandboxBridge`` code without patching.
    """

    def test_cont_raises_tool_error_for_unknown_instance_id(self) -> None:
        """cont() raises ToolError with 'Sandbox instance not found' for unknown ID.

        Oracle: ``sandbox_bridge.py`` — ``if instance is None: raise ToolError(...)``.
        ``SandboxManager.get()`` returns ``self._instances.get(instance_id)`` which is
        None for any ID not previously created.  This path requires zero mocking —
        the manager has no instances after ``SandboxBridge()`` construction.

        Mutation: returning an empty result dict instead of raising ToolError
        fails the ``pytest.raises`` block entirely.
        """
        bridge = SandboxBridge()

        async def _run() -> None:
            await bridge.cont("nonexistent-instance-id-99999")

        with pytest.raises(ToolError, match=r"[Ss]andbox instance not found|nonexistent-instance"):
            asyncio.run(_run())

    def test_ensure_manager_raises_tool_error_after_destruction(self) -> None:
        """ensure_manager() raises ToolError when the manager was previously destroyed.

        Oracle: ``sandbox_bridge.py`` — ``if self._manager_destroyed: raise ToolError(...)``
        where the error text is ``"manager was shut down; call create() to recreate"``.
        ``simulate_shutdown()`` on the wrapper subclass sets the post-destruction state.

        Mutation: removing the destruction guard makes ``ensure_manager()``
        create a fresh manager instead of raising, failing the ``pytest.raises`` block.
        """
        bridge = _TestableSandboxBridge()
        bridge.simulate_shutdown()

        with pytest.raises(ToolError, match=r"[Mm]anager was shut down|shut down"):
            bridge.ensure_manager()

    def test_ensure_manager_returns_manager_on_first_call(self) -> None:
        """ensure_manager() creates and returns a SandboxManager on first call.

        Oracle: ``sandbox_bridge.py`` — ``self._manager = SandboxManager()`` initializes
        the manager lazily.  The returned object must be the same instance on a
        second call (singleton within the bridge lifetime).

        Mutation: returning a new manager on each call would fail the
        ``is`` identity assertion.
        """
        bridge = SandboxBridge()
        mgr1 = bridge.ensure_manager()
        mgr2 = bridge.ensure_manager()
        assert mgr1 is mgr2, "ensure_manager() must return the same SandboxManager instance on repeated calls"

    def test_initial_bridge_state_has_no_last_error(self) -> None:
        """Freshly constructed SandboxBridge has last_error=None.

        Oracle: ``SandboxBridge.__init__`` inherits ``BridgeState()`` from
        ``ToolBridgeBase``; ``BridgeState.last_error`` defaults to ``None``.
        Mutation: setting an initial ``last_error="init"`` value in __init__
        fails the ``is None`` assertion.
        """
        bridge = SandboxBridge()
        assert bridge.state.last_error is None

    def test_set_state_outcome_sets_and_clears_last_error(self) -> None:
        """set_state_outcome sets last_error to an error string then clears it.

        Oracle: the method replaces the dataclass state object preserving all
        other fields; only ``last_error`` changes.  Mutation: failing to call
        ``dataclasses.replace`` (instead mutating the object in place) would
        leave other state fields at their zero values if the replacement
        branching is wrong.
        """
        bridge = _TestableSandboxBridge()

        bridge.set_state_outcome("bridge error")
        assert bridge.state.last_error == "bridge error", f"last_error must be 'bridge error'; got {bridge.state.last_error!r}"

        bridge.set_state_outcome(None)
        assert bridge.state.last_error is None, f"last_error must be None after clearing; got {bridge.state.last_error!r}"

    def test_cont_raises_tool_error_with_instance_id_in_message(self) -> None:
        """cont() error message includes the specific instance ID.

        Oracle: ``f"{_ERR_INSTANCE_NOT_FOUND}: {instance_id}"`` where
        ``_ERR_INSTANCE_NOT_FOUND = "Sandbox instance not found"``; the full
        message is ``"Sandbox instance not found: <instance_id>"``.
        Mutation: omitting ``{instance_id}`` from the format string makes
        the regex assertion fail.
        """
        unknown_id = "wave5-test-sentinel-id"
        bridge = SandboxBridge()

        async def _run() -> None:
            await bridge.cont(unknown_id)

        with pytest.raises(ToolError, match=unknown_id):
            asyncio.run(_run())
