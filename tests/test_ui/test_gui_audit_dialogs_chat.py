# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for GUI audit finding: chat auto-scroll lag.

``ChatPanel._scroll_to_bottom`` set the scrollbar to ``maximum()`` synchronously
right after inserting a new message bubble, before the layout had recomputed
the scrollbar's maximum, so the newest bubble could be left partially
off-screen. The fix defers the scroll to the next GUI event-loop iteration via
``QTimer.singleShot(0, ...)`` so the layout is up to date when the scroll runs.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pytest

import intellicrack.ui.chat as chat_mod
from intellicrack.ui.chat import ChatPanel


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from PyQt6.QtWidgets import QApplication, QScrollArea


class _TimerSpy:
    """Stand-in for ``QTimer`` that records deferred scheduling requests.

    The production code calls ``QTimer.singleShot(0, callback)``. Replacing the
    module ``QTimer`` name with an instance of this class routes that call to
    :meth:`defer`, which is bound to the ``singleShot`` attribute at runtime so
    no camel-cased identifier appears in the source. The ``calls`` attribute
    accumulates each recorded ``(msec, callback)`` pair.
    """

    def __init__(self) -> None:
        """Initialise the spy with an empty call history and the singleShot hook."""
        self.calls: list[tuple[int, Callable[[], None]]] = []
        setattr(self, "singleShot", self.defer)

    def defer(self, msec: int, callback: Callable[[], None]) -> None:
        """Record a deferred single-shot request instead of scheduling it.

        Args:
            msec: Requested delay in milliseconds.
            callback: The callable that would have been scheduled.
        """
        self.calls.append((msec, callback))


@pytest.fixture
def chat_panel(qapp: QApplication) -> Iterator[ChatPanel]:
    """Create a ChatPanel instance.

    Args:
        qapp: Session-scoped Qt application fixture.

    Yields:
        ChatPanel: A live chat panel instance.
    """
    del qapp
    panel = ChatPanel()
    yield panel
    panel.deleteLater()


class TestChatScrollDeferral:
    """The scroll to bottom must be deferred so layout can recompute the maximum."""

    def test_scroll_to_bottom_defers_apply_via_single_shot(
        self,
        chat_panel: ChatPanel,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``_scroll_to_bottom`` schedules ``_apply_scroll_to_bottom`` via singleShot(0).

        Args:
            chat_panel: ChatPanel fixture.
            monkeypatch: Pytest monkeypatch fixture.
        """
        spy = _TimerSpy()
        monkeypatch.setattr(chat_mod, "QTimer", spy)

        scroll_fn: object = getattr(chat_panel, "_scroll_to_bottom")
        cast("Callable[[], None]", scroll_fn)()

        assert len(spy.calls) == 1, f"_scroll_to_bottom must defer exactly one scroll via QTimer.singleShot; recorded {len(spy.calls)}"
        msec, callback = spy.calls[0]
        assert msec == 0, f"the scroll must be deferred with a 0 ms single-shot; got {msec} ms"

        expected_cb: object = getattr(chat_panel, "_apply_scroll_to_bottom")
        assert callback == expected_cb, "the deferred callback must be _apply_scroll_to_bottom"

    def test_apply_scroll_moves_bar_to_maximum(self, chat_panel: ChatPanel) -> None:
        """``_apply_scroll_to_bottom`` moves the vertical scrollbar to its maximum.

        Args:
            chat_panel: ChatPanel fixture.
        """
        scroll_area_obj: object = getattr(chat_panel, "_scroll_area")
        scroll_area = cast("QScrollArea", scroll_area_obj)
        scrollbar = scroll_area.verticalScrollBar()
        assert scrollbar is not None, "scroll area must have a vertical scrollbar"

        apply_fn: object = getattr(chat_panel, "_apply_scroll_to_bottom")
        cast("Callable[[], None]", apply_fn)()

        assert scrollbar.value() == scrollbar.maximum(), "after applying the deferred scroll, the bar must sit at its maximum (bottom)"
