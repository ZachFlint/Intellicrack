# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gate for the R06 provider-panel action-button clip fix.

``ProviderConfigDialog._setup_ui`` packs its eight action buttons two-per-row
into a left panel pinned to ``_LIST_MIN_WIDTH``/``_LIST_MAX_WIDTH`` (200/250
px). The longest label, "Write .env Template", overflowed its narrow column
and Qt centre-clipped the rendered text. The fix floors every action button's
minimum width at its own ``sizeHint().width()`` and raises the left panel's
minimum width to fit the widest two-button row, so the column grows to the
text instead of squeezing it.

This gate builds the real :class:`~intellicrack.ui.provider_config.ProviderConfigDialog`,
shows it under an offscreen ``QApplication`` so real layout geometry is
computed, and asserts every action button's rendered width is at least the
width its label needs under the real style (font metrics plus the style's
own content margins) -- never a restated pixel constant. Reverting the fix
(dropping the per-button minimum widths and the left-panel minimum-width
raise) squeezes "Write .env Template" back below its label width, turning
this gate RED.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import QSize
from PyQt6.QtGui import QFontMetrics
from PyQt6.QtWidgets import QPushButton, QStyle, QStyleOptionButton

import intellicrack.ui.provider_config as provider_config_module
from intellicrack.ui.provider_config import ProviderConfigDialog


if TYPE_CHECKING:
    from collections.abc import Coroutine

    import pytest
    from PyQt6.QtWidgets import QApplication


def _discard_async_dispatch(
    coro: Coroutine[object, object, object],
    on_success: object = None,
    on_error: object = None,
    parent: object = None,
    **_kwargs: object,
) -> None:
    """Close a bridge coroutine without running it, so no background QThread starts.

    Args:
        coro: The coroutine that would otherwise run on the bridge worker.
        on_success: Unused success callback.
        on_error: Unused error callback.
        parent: Unused Qt parent argument.
        **_kwargs: Remaining wrapper keyword arguments (ignored).
    """
    del on_success, on_error, parent
    coro.close()


def _discard_blocking_call(*args: object, **kwargs: object) -> None:
    """Swallow a blocking bridge-runner call, keeping dialog construction I/O-free.

    Args:
        *args: Positional arguments (ignored).
        **kwargs: Keyword arguments (ignored).
    """
    del args, kwargs


def _label_content_width(button: QPushButton) -> int:
    """Compute the width the real style needs to render a button's label uncut.

    Derives the figure from the button's actual font metrics and its style's
    own ``sizeFromContents`` computation (frame, padding, and margins), so the
    threshold tracks the live style rather than a hand-picked constant.

    Args:
        button: The push button whose label width is being measured.

    Returns:
        int: The minimum button width that avoids clipping the label.
    """
    metrics = QFontMetrics(button.font())
    text_size = QSize(metrics.horizontalAdvance(button.text()), metrics.height())
    style = button.style()
    assert style is not None, "button has no style; cannot compute label content width"
    option = QStyleOptionButton()
    button.initStyleOption(option)
    content_size = style.sizeFromContents(QStyle.ContentsType.CT_PushButton, option, text_size, button)
    return content_size.width()


def _build_dialog(monkeypatch: pytest.MonkeyPatch) -> ProviderConfigDialog:
    """Construct a real ``ProviderConfigDialog`` with the bridge runners silenced.

    Args:
        monkeypatch: Fixture used to patch the module-level bridge runners so
            construction dispatches no real network/keyring work.

    Returns:
        ProviderConfigDialog: A fully constructed, not-yet-shown dialog.
    """
    monkeypatch.setattr(provider_config_module, "run_bridge_coroutine_async", _discard_async_dispatch)
    monkeypatch.setattr(provider_config_module, "run_bridge_coroutine", _discard_blocking_call)
    return ProviderConfigDialog()


def _action_buttons(dialog: ProviderConfigDialog) -> dict[str, QPushButton]:
    """Return every action button the R06 finding names, keyed by its label.

    Args:
        dialog: The dialog to pull action buttons from.

    Returns:
        dict[str, QPushButton]: Mapping of button label to the real widget.
    """
    buttons = (
        dialog._set_active_btn,
        dialog._refresh_status_btn,
        dialog._refresh_creds_btn,
        dialog._migrate_creds_btn,
        dialog._create_env_btn,
        dialog._discover_models_btn,
        dialog._oauth_btn,
        dialog._revoke_btn,
    )
    return {button.text(): button for button in buttons}


def test_action_buttons_are_not_clipped(qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
    """Every action button in the left panel renders wide enough for its full label.

    Pre-fix, the two-per-row ``QHBoxLayout``s were packed into a panel pinned
    at 200-250 px with no per-button minimum width, so "Write .env Template"
    rendered narrower than its label and Qt centre-clipped it to something
    like "Vrite .env Templat". This asserts every action button's real
    rendered width, after a genuine layout pass, is at least the width its
    label needs under the live style.

    Args:
        qapp: Session-scoped offscreen QApplication fixture.
        monkeypatch: Fixture used to silence the bridge runners for
            construction.
    """
    dialog = _build_dialog(monkeypatch)
    try:
        dialog.show()
        dialog.ensurePolished()
        qapp.processEvents()

        buttons = _action_buttons(dialog)
        assert len(buttons) == 8, "expected all eight distinct action buttons"
        assert "Write .env Template" in buttons

        checked = 0
        for label, button in buttons.items():
            needed = _label_content_width(button)
            assert button.width() >= needed, (
                f"action button {label!r} is {button.width()} px wide but needs >= {needed} px to show its full label without clipping"
            )
            checked += 1
        assert checked == 8
    finally:
        dialog.close()
        dialog.deleteLater()


def test_write_env_template_button_keeps_its_tooltip(qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
    """The Write .env Template button keeps its descriptive tooltip after the width fix.

    Guards against a naive width fix that reconstructs the button (or
    otherwise drops the ``setToolTip`` call) while widening it.

    Args:
        qapp: Session-scoped offscreen QApplication fixture.
        monkeypatch: Fixture used to silence the bridge runners for
            construction.
    """
    _ = qapp
    dialog = _build_dialog(monkeypatch)
    try:
        tooltip = dialog._create_env_btn.toolTip()
        assert "non-destructive" in tooltip.lower()
        assert "backed up" in tooltip.lower()
    finally:
        dialog.close()
        dialog.deleteLater()
