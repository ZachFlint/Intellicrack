# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression test for the requirements-status label repolish gap (D44).

``ProviderSettingsWidget._on_check_requirements`` (``src/intellicrack/ui/
provider_config.py``) sets the ``"status"`` dynamic property on
``_xpu_warnings_label`` to key the ``QLabel[status="..."]`` selectors defined
in ``theme_manager.py`` / the packaged ``.qss`` themes. Qt's style engine only
re-evaluates dynamic-property selectors when a widget is explicitly
unpolished and repolished; changing the property alone leaves the label
rendered with whatever color it was first polished with.

This test drives ``_on_check_requirements`` through success -> warning ->
error transitions against a real ``ProviderSettingsWidget`` for the
``local_transformers`` provider (the only provider that builds the XPU
requirements group) and asserts, for every transition:

1. the ``"status"`` dynamic property actually changes; and
2. the label's own style is unpolished then repolished -- observed via a
   duck-typed recording stand-in installed as the label's ``style`` bound
   method, mirroring the approach already established in
   ``tests/ui/test_theme_manager_s12d10_content_viewport_repolish.py``.

Falsifiable: removing the ``_restyle(warnings_label)`` calls from any of the
four ``_on_check_requirements`` branches (reverting to a bare
``setProperty("status", ...)``) leaves that branch's transition absent from
the stand-in's ``polished`` / ``unpolished`` lists, failing the assertion for
that transition even though the dynamic property itself still changed.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING
from unittest.mock import patch

from PyQt6.QtWidgets import QLabel

from intellicrack.ui.provider_config import ProviderSettingsWidget


if TYPE_CHECKING:
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

_SIMULATED_FAILURE_MESSAGE = "simulated requirements check failure"


class _RecordingStyleStandIn:
    """Duck-typed stand-in for ``QLabel.style()`` that records polish calls.

    Installed by reassigning the ``style`` attribute on a live ``QLabel``
    instance, so ``_restyle``'s ``widget.style().unpolish(widget)`` /
    ``widget.style().polish(widget)`` calls resolve to this recorder instead
    of the real platform style, without needing to satisfy the full
    ``QStyle`` C++ virtual-method surface.
    """

    def __init__(self) -> None:
        """Initialize the stand-in with empty call-history lists."""
        self.polished: list[QLabel] = []
        self.unpolished: list[QLabel] = []

    def polish(self, widget: QLabel) -> None:
        """Record a ``polish(widget)`` call.

        Args:
            widget: The widget being polished.
        """
        self.polished.append(widget)

    def unpolish(self, widget: QLabel) -> None:
        """Record an ``unpolish(widget)`` call.

        Args:
            widget: The widget being unpolished.
        """
        self.unpolished.append(widget)


def _make_xpu_widget(tmp_path: Path) -> ProviderSettingsWidget:
    """Construct a real ``ProviderSettingsWidget`` for the ``local_transformers`` provider.

    Args:
        tmp_path: Per-test temporary directory used for an isolated config path.

    Returns:
        ProviderSettingsWidget: A live widget exposing the XPU requirements group.
    """
    config_path = tmp_path / "local_transformers_providers.json"
    return ProviderSettingsWidget("local_transformers", config_path=config_path)


def test_requirements_label_repolishes_through_success_warning_error(
    qapp: QApplication,
    tmp_path: Path,
) -> None:
    """Each requirements-check outcome updates the status property and repolishes the label.

    Drives ``_on_check_requirements`` three times against
    ``check_windows_requirements`` results shaped as success, then warning,
    then error, and asserts on every transition that the ``"status"``
    dynamic property changed from its previous value and that the label's
    style recorded both an ``unpolish`` and a matching ``polish`` call for
    that exact label instance.

    Args:
        qapp: Session-scoped Qt application fixture.
        tmp_path: Per-test temporary directory.
    """
    del qapp
    widget = _make_xpu_widget(tmp_path)
    warnings_label = widget._xpu_warnings_label
    assert isinstance(warnings_label, QLabel)

    stand_in = _RecordingStyleStandIn()
    setattr(warnings_label, "style", lambda: stand_in)

    observed_statuses: list[str] = []

    def _run_and_check(result: tuple[bool, list[str]] | None, expected_status: str) -> None:
        """Drive one requirements-check outcome and assert the repolish contract.

        Args:
            result: The ``(all_met, warnings)`` tuple ``check_windows_requirements``
                should return, or ``None`` to raise ``RuntimeError`` instead (the
                "Failed to check requirements" branch).
            expected_status: The ``"status"`` dynamic property value expected
                after this transition.
        """
        polished_before = len(stand_in.polished)
        unpolished_before = len(stand_in.unpolished)

        if result is None:

            def _raise() -> tuple[bool, list[str]]:
                raise RuntimeError(_SIMULATED_FAILURE_MESSAGE)

            with patch(
                "intellicrack.ui.provider_config.check_windows_requirements",
                side_effect=_raise,
            ):
                widget._on_check_requirements()
        else:
            with patch(
                "intellicrack.ui.provider_config.check_windows_requirements",
                return_value=result,
            ):
                widget._on_check_requirements()

        new_status = warnings_label.property("status")
        assert new_status == expected_status, f"expected status {expected_status!r}, got {new_status!r}"
        assert not observed_statuses or observed_statuses[-1] != new_status, "status property did not change between transitions"
        observed_statuses.append(str(new_status))

        assert len(stand_in.polished) > polished_before, f"label was not repolished for status {expected_status!r}"
        assert len(stand_in.unpolished) > unpolished_before, f"label was not unpolished for status {expected_status!r}"
        assert stand_in.polished[-1] is warnings_label
        assert stand_in.unpolished[-1] is warnings_label

    _run_and_check((True, []), "success")
    _run_and_check((False, ["Intel GPU driver not detected"]), "warning")
    _run_and_check(None, "error")

    assert observed_statuses == ["success", "warning", "error"]
