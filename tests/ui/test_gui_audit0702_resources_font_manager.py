# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for ``font_manager`` config-driven font family and size selection.

``font_config.json`` is loaded into ``FontManager._font_config`` and must be consulted for actual font selection: ``_setup_fonts_from_loaded``,
``_setup_fallback_fonts``, and ``_find_available_font`` must not operate exclusively on the hardcoded ``FALLBACK_CODE_FONTS``/``FALLBACK_UI_FONTS`` module
constants, and ``get_code_font``/``get_ui_font``/``get_heading_font`` must not use hardcoded default size parameters instead of the JSON's ``font_sizes``
values. Otherwise editing ``font_config.json``'s primary/fallback font lists or ``font_sizes`` would silently do nothing.

Each test below points ``FontManager`` at a synthetic ``font_config.json``
with font family names guaranteed not to exist on the test machine and font
sizes distinct from every hardcoded default, then drives the
font-resolution code path (``load_fonts`` /
``get_code_font`` / ``get_ui_font`` / ``get_heading_font``) and asserts the
resolved family names and point sizes come from the config rather than the
hardcoded constants.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from intellicrack.ui.resources import font_manager
from intellicrack.ui.resources.font_manager import FontManager


if TYPE_CHECKING:
    from pathlib import Path

    import pytest
    from PyQt6.QtWidgets import QApplication


_SAMPLE_FONT_CONFIG: dict[str, object] = {
    "monospace_fonts": {
        "primary": ["ZzzTestCodeFontL2"],
        "fallback": [],
    },
    "ui_fonts": {
        "primary": ["ZzzTestUiFontL2"],
        "fallback": [],
    },
    "font_sizes": {
        "code_default": 17,
        "ui_default": 15,
        "ui_large": 21,
    },
}


def _fake_resource_exists(_resource_path: str) -> bool:
    """Report that no bundled font resources are present.

    Forces ``FontManager._load_fonts_from_disk`` down the
    ``_setup_fallback_fonts`` branch so family selection is driven purely by
    ``_config_font_candidates`` rather than any real ``.ttf``/``.otf`` files
    bundled with the repository.

    Args:
        _resource_path: Resource path being queried (ignored).

    Returns:
        bool: Always ``False``.
    """
    return False


def _install_font_config(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    config: dict[str, object],
) -> Path:
    """Point ``FontManager._load_font_config`` at a synthetic config file.

    Writes ``config`` to a temporary ``font_config.json`` and monkeypatches
    ``font_manager.get_font_path`` (the name ``FontManager`` calls) to
    resolve to it, and ``font_manager.resource_exists`` to report that no
    bundled font files exist so family resolution always goes through
    ``_setup_fallback_fonts``.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
        tmp_path: Pytest temporary directory used to hold the config file.
        config: JSON-serializable font configuration to install.

    Returns:
        Path: Path to the written ``font_config.json`` file.
    """
    config_path = tmp_path / "font_config.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")

    def _fake_get_font_path(_font_name: str) -> Path:
        return config_path

    monkeypatch.setattr(font_manager, "get_font_path", _fake_get_font_path)
    monkeypatch.setattr(font_manager, "resource_exists", _fake_resource_exists)
    return config_path


def test_l2_config_font_candidates_select_configured_family_over_hardcoded_fallback(
    qapp: QApplication,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Configured monospace/UI font names, not the hardcoded lists, are selected.

    ``_setup_fallback_fonts`` must not call
    ``FontManager._find_available_font(FALLBACK_CODE_FONTS)`` and
    ``FALLBACK_UI_FONTS`` directly, so it would resolve to whichever
    hardcoded candidate (``"JetBrains Mono"``, ``"Consolas"``, ``"Segoe UI"``,
    ``"monospace"``, etc.) is installed on the test machine -- never the
    config's ``"ZzzTestCodeFontL2"``/``"ZzzTestUiFontL2"`` placeholder names,
    which are guaranteed absent from the system font database. This
    assertion therefore fails against code that bypasses the config and only passes once
    ``_config_font_candidates`` is consulted first.

    Args:
        qapp: The shared QApplication fixture (required for QFontDatabase).
        tmp_path: Pytest temporary directory used to host the config file.
        monkeypatch: Pytest monkeypatch fixture used to redirect config I/O.
    """
    _ = qapp
    _install_font_config(monkeypatch, tmp_path, _SAMPLE_FONT_CONFIG)
    manager = FontManager()

    manager.load_fonts()

    assert manager.code_font_family == "ZzzTestCodeFontL2"
    assert manager.ui_font_family == "ZzzTestUiFontL2"


def test_l2_get_code_font_default_size_uses_config_code_default(
    qapp: QApplication,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``get_code_font()`` with no explicit size uses the config's ``code_default``.

    ``get_code_font`` must not use a hardcoded ``size: int = 10`` parameter
    that was used verbatim regardless of ``font_config.json``, so calling it
    without an explicit size always produced a 10pt font even though the
    config specifies ``code_default: 17``. This assertion fails against the
    hardcoded code (``pointSize() == 10``) and passes once the default resolves
    through ``_config_font_size``.

    Args:
        qapp: The shared QApplication fixture (required for QFontDatabase).
        tmp_path: Pytest temporary directory used to host the config file.
        monkeypatch: Pytest monkeypatch fixture used to redirect config I/O.
    """
    _ = qapp
    _install_font_config(monkeypatch, tmp_path, _SAMPLE_FONT_CONFIG)
    manager = FontManager()

    font = manager.get_code_font()

    assert font.pointSize() == 17


def test_l2_get_ui_font_default_size_uses_config_ui_default(
    qapp: QApplication,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``get_ui_font()`` with no explicit size uses the config's ``ui_default``.

    ``get_ui_font`` must not have a hardcoded ``size: int = 9`` parameter used
    verbatim regardless of ``font_config.json``, so calling it without an
    explicit size always produced a 9pt font even though the config
    specifies ``ui_default: 15``. This assertion fails against the hardcoded
    code (``pointSize() == 9``) and passes once the default resolves through
    ``_config_font_size``.

    Args:
        qapp: The shared QApplication fixture (required for QFontDatabase).
        tmp_path: Pytest temporary directory used to host the config file.
        monkeypatch: Pytest monkeypatch fixture used to redirect config I/O.
    """
    _ = qapp
    _install_font_config(monkeypatch, tmp_path, _SAMPLE_FONT_CONFIG)
    manager = FontManager()

    font = manager.get_ui_font()

    assert font.pointSize() == 15


def test_l2_get_heading_font_default_size_uses_config_ui_large(
    qapp: QApplication,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``get_heading_font()`` with no explicit size uses the config's ``ui_large``.

    ``get_heading_font`` must not have a hardcoded ``size: int = 12``
    parameter forwarded straight into ``get_ui_font(size)`` regardless of
    ``font_config.json``, so calling it without an explicit size always
    produced a 12pt heading font even though the config specifies
    ``ui_large: 21``. This assertion fails against the hardcoded code
    (``pointSize() == 12``) and passes once the default resolves through
    ``_config_font_size``.

    Args:
        qapp: The shared QApplication fixture (required for QFontDatabase).
        tmp_path: Pytest temporary directory used to host the config file.
        monkeypatch: Pytest monkeypatch fixture used to redirect config I/O.
    """
    _ = qapp
    _install_font_config(monkeypatch, tmp_path, _SAMPLE_FONT_CONFIG)
    manager = FontManager()

    font = manager.get_heading_font()

    assert font.pointSize() == 21
    assert font.bold() is True


def test_l2_explicit_size_argument_still_overrides_config_default(
    qapp: QApplication,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An explicit ``size`` argument still wins over the config default.

    Confirms the ``size is not None`` branch does not
    regress the pre-existing ability to request a specific size, so a caller
    that already passes an explicit size (e.g. a hex-view widget honoring a
    user zoom level) keeps working identically.

    Args:
        qapp: The shared QApplication fixture (required for QFontDatabase).
        tmp_path: Pytest temporary directory used to host the config file.
        monkeypatch: Pytest monkeypatch fixture used to redirect config I/O.
    """
    _ = qapp
    _install_font_config(monkeypatch, tmp_path, _SAMPLE_FONT_CONFIG)
    manager = FontManager()

    font = manager.get_code_font(23)

    assert font.pointSize() == 23
