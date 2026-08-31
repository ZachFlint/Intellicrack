# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for GUI audit finding: XPU requirements HTML injection.

``XPUStatusDialog._on_requirements_ready`` interpolated requirement warning
strings straight into ``setHtml`` without escaping, so a warning containing
``<``, ``>`` or ``&`` was parsed as markup and rendered as broken HTML. The
fix routes each warning through ``html.escape`` so the literal characters are
displayed verbatim.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pytest

import intellicrack.ui.xpu_status as xpu_mod
from intellicrack.ui.xpu_status import XPUStatusDialog


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from PyQt6.QtWidgets import QApplication


def _deliver_warnings(dialog: XPUStatusDialog, warnings: list[str]) -> None:
    """Render a warnings-only requirements result on the dialog.

    Builds the module-private ``_RequirementsResult`` payload and invokes the
    dialog's ``_on_requirements_ready`` handler via ``getattr`` so the test
    stays free of private-usage diagnostics.

    Args:
        dialog: The XPU status dialog whose handler is invoked.
        warnings: Warning strings to render.
    """
    result_factory = cast("Callable[..., object]", getattr(xpu_mod, "_RequirementsResult"))
    result = result_factory(all_met=False, warnings=warnings)
    handler = cast("Callable[[object], None]", getattr(dialog, "_on_requirements_ready"))
    handler(result)


@pytest.fixture
def xpu_dialog(qapp: QApplication) -> Iterator[XPUStatusDialog]:
    """Create a real XPUStatusDialog instance.

    Args:
        qapp: Session-scoped Qt application fixture.

    Yields:
        XPUStatusDialog: A live dialog instance.
    """
    del qapp
    dialog = XPUStatusDialog()
    yield dialog
    dialog.close()


class TestXpuRequirementsHtmlEscape:
    """Warning strings must be HTML-escaped before embedding in the report."""

    def test_angle_and_amp_warning_is_escaped_not_interpreted(self, xpu_dialog: XPUStatusDialog) -> None:
        """A warning containing ``<b>&x`` renders as literal text, not parsed markup.

        When the warning is escaped, the ``<b>`` and ``&`` survive as visible
        text so the plain-text projection of the rendered document contains the
        literal ``<b>&x``. When it is NOT escaped, Qt parses ``<b>`` as a bold
        tag and drops it, so the literal string is lost. Asserting on the
        plain-text projection therefore distinguishes the fixed behaviour from
        the regression.

        Args:
            xpu_dialog: XPUStatusDialog fixture.
        """
        payload = "<b>&x"
        _deliver_warnings(xpu_dialog, [payload])

        rendered_plain = xpu_dialog.requirements_text.toPlainText()
        assert payload in rendered_plain, (
            "the warning text must be HTML-escaped so '<b>&x' appears verbatim; "
            f"got plain text {rendered_plain!r} (an unescaped '<b>' would be parsed away as a bold tag)"
        )

    def test_plain_warning_still_renders(self, xpu_dialog: XPUStatusDialog) -> None:
        """A benign warning still renders its text so escaping did not break normal output.

        Args:
            xpu_dialog: XPUStatusDialog fixture.
        """
        _deliver_warnings(xpu_dialog, ["Driver update recommended"])

        assert "Driver update recommended" in xpu_dialog.requirements_text.toPlainText(), (
            "a normal warning must still be displayed after the escaping fix"
        )
