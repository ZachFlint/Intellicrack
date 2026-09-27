# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Gate for :func:`tests._helpers.polling.wait_until`.

Every assertion here is made on a call count or on a bound the implementation
guarantees, never on a wall-clock upper limit, so a loaded runner cannot make it
flake and a broken helper cannot pass it: one that never re-evaluates the
condition, ignores the budget, or sleeps before the first look fails one of
these directly.
"""

from __future__ import annotations

import asyncio
from typing import Final

import pytest

from tests._helpers.polling import wait_until


_TINY_INTERVAL_S: Final[float] = 0.001
_UNREACHABLE_BUDGET_S: Final[float] = 60.0
_EXHAUSTED_BUDGET_S: Final[float] = 0.05
_OVERSIZED_INTERVAL_S: Final[float] = 5.0
_HANG_GUARD_S: Final[float] = 10.0
_FLIPS_ON_CALL: Final[int] = 4


class _CountingCondition:
    """Condition that becomes true on a chosen evaluation and counts every look."""

    def __init__(self, true_on_call: int | None) -> None:
        """Record on which evaluation the condition starts to hold.

        Args:
            true_on_call: 1-based evaluation number that returns ``True``, or
                ``None`` for a condition that never holds.
        """
        self._true_on_call = true_on_call
        self.calls = 0

    def __call__(self) -> bool:
        """Count one evaluation and report whether the condition now holds.

        Returns:
            bool: ``True`` once the configured evaluation number is reached.
        """
        self.calls += 1
        return self._true_on_call is not None and self.calls >= self._true_on_call


class TestWaitUntil:
    """``wait_until`` must look, keep looking, and stop at the budget."""

    @pytest.mark.asyncio
    async def test_state_that_already_holds_is_seen_without_a_second_look(self) -> None:
        """A condition true on entry is evaluated exactly once."""
        condition = _CountingCondition(true_on_call=1)

        await wait_until(condition, budget=_UNREACHABLE_BUDGET_S, interval=_TINY_INTERVAL_S)

        assert condition.calls == 1, f"an already-true condition was evaluated {condition.calls} times"

    @pytest.mark.asyncio
    async def test_state_that_comes_to_hold_is_reevaluated_until_it_does(self) -> None:
        """A condition that flips on the Nth look is polled exactly N times."""
        condition = _CountingCondition(true_on_call=_FLIPS_ON_CALL)

        waited = await asyncio.wait_for(
            wait_until(condition, budget=_UNREACHABLE_BUDGET_S, interval=_TINY_INTERVAL_S),
            timeout=_HANG_GUARD_S,
        )

        assert condition.calls == _FLIPS_ON_CALL, f"the condition flips on look {_FLIPS_ON_CALL} but was evaluated {condition.calls} times"
        assert waited < _UNREACHABLE_BUDGET_S, "the wait ran the whole budget although the condition held early"

    @pytest.mark.asyncio
    async def test_state_that_never_holds_stops_at_the_budget_and_polls_meanwhile(self) -> None:
        """An unreachable condition returns once the budget is spent, not before."""
        condition = _CountingCondition(true_on_call=None)

        waited = await asyncio.wait_for(
            wait_until(condition, budget=_EXHAUSTED_BUDGET_S, interval=_TINY_INTERVAL_S),
            timeout=_HANG_GUARD_S,
        )

        assert waited >= _EXHAUSTED_BUDGET_S, f"the wait gave up after {waited:.4f}s of a {_EXHAUSTED_BUDGET_S}s budget"
        assert condition.calls > 1, "the condition was looked at once and then abandoned instead of polled"

    @pytest.mark.asyncio
    async def test_an_interval_longer_than_the_budget_never_carries_the_wait_past_it(self) -> None:
        """A sleep is cut to the time left, so the budget stays a hard deadline."""
        condition = _CountingCondition(true_on_call=None)

        waited = await asyncio.wait_for(
            wait_until(condition, budget=_EXHAUSTED_BUDGET_S, interval=_OVERSIZED_INTERVAL_S),
            timeout=_HANG_GUARD_S,
        )

        assert waited < _OVERSIZED_INTERVAL_S, (
            f"a {_OVERSIZED_INTERVAL_S}s interval carried the wait to {waited:.2f}s against a {_EXHAUSTED_BUDGET_S}s budget"
        )
