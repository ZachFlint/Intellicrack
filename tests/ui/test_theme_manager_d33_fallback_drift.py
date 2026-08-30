# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""D33 drift gate: the embedded stylesheet fallback must track the ``.qss`` assets.

``ThemeManager`` falls back to an embedded stylesheet whenever the
theme-specific ``.qss`` asset cannot be read. Before this fix that fallback
was two large hand-maintained string literals (``DARK_THEME_FALLBACK`` /
``LIGHT_THEME_FALLBACK``) that had drifted from the shipped
``dark_theme.qss`` / ``light_theme.qss`` in both directions -- missing
selectors the real assets define (e.g. ``chat_panel``/``header``/
``input_bar``/``send_button`` rules) and carrying selectors the real assets
never defined (e.g. a ``QLabel[subheading="true"]`` rule).

The fix makes the ``.qss`` file the single source of truth: the fallback is
computed by reading the packaged asset (through
:func:`importlib.resources.files` primarily, the filesystem-backed
:func:`~intellicrack.ui.resources.resource_helper.get_style_path` as a
secondary route) instead of duplicating its text as Python source. These
tests drive the real ``ThemeManager`` routing logic and the real asset files
on disk -- never a restatement of either -- and are written to fail if a
future change reintroduces a hand-maintained copy that can drift from the
``.qss`` file it is supposed to mirror.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest


if TYPE_CHECKING:
    from pathlib import Path
    from typing import NoReturn

from intellicrack.ui.resources import theme_manager as theme_manager_module
from intellicrack.ui.resources.resource_helper import get_style_path
from intellicrack.ui.resources.theme_manager import (
    DARK_THEME_FALLBACK,
    LIGHT_THEME_FALLBACK,
    THEME_DARK,
    THEME_DARK2,
    THEME_LIGHT,
    THEME_LIGHT2,
    ThemeManager,
)


def _representative_asset_text(theme: str) -> str:
    """Read the real, on-disk representative ``.qss`` asset for a theme's family.

    Args:
        theme: Theme name.

    Returns:
        str: The full text of ``dark_theme.qss`` for the dark family
        (:data:`THEME_DARK`/:data:`THEME_DARK2`) or ``light_theme.qss``
        otherwise, read directly from disk with no production routing logic
        involved.
    """
    filename = "dark_theme.qss" if theme in {THEME_DARK, THEME_DARK2} else "light_theme.qss"
    return get_style_path(filename).read_text(encoding="utf-8")


def _always_missing_stylesheet_read(filename: str) -> str | None:
    """Stand-in for ``ThemeManager._read_stylesheet_file`` that always reports "missing".

    Args:
        filename: Stylesheet file name requested by ``_load_stylesheet``.

    Returns:
        str | None: Always ``None``, forcing ``_load_stylesheet`` to route
        through the family fallback for whichever theme was requested.
    """
    _ = filename
    return None


@pytest.fixture
def manager() -> ThemeManager:
    """Provide a fresh ``ThemeManager`` singleton instance for each test.

    Returns:
        ThemeManager: A fresh singleton instance.
    """
    ThemeManager.reset_instance()
    return ThemeManager.get_instance()


@pytest.mark.parametrize("theme", [THEME_DARK, THEME_DARK2, THEME_LIGHT, THEME_LIGHT2])
def test_d33_loader_fallback_matches_representative_asset_for_every_theme(
    manager: ThemeManager,
    monkeypatch: pytest.MonkeyPatch,
    theme: str,
) -> None:
    """D33: the loader's fallback for every theme equals its family's live ``.qss`` content.

    Forces the theme-specific per-file read to report "missing" (as would
    happen for a corrupted or partially-shipped install) and asserts the
    stylesheet ``ThemeManager`` actually serves is byte-for-byte identical to
    the real ``dark_theme.qss`` / ``light_theme.qss`` asset on disk -- not a
    hand-maintained approximation of it.

    Args:
        manager: Fresh ``ThemeManager`` fixture instance.
        monkeypatch: Pytest fixture used to force the theme-specific
            per-file read to report "missing".
        theme: Theme under test.
    """
    assert manager.styles_available, "styles directory must exist on disk for this scenario to be meaningful"
    monkeypatch.setattr(ThemeManager, "_read_stylesheet_file", staticmethod(_always_missing_stylesheet_read))

    served = manager._load_stylesheet(theme)

    assert served == _representative_asset_text(theme), f"the fallback served for {theme!r} has drifted from its representative .qss asset"


def test_d33_dark_fallback_constant_matches_dark_theme_qss_exactly() -> None:
    """D33: ``DARK_THEME_FALLBACK`` is byte-for-byte identical to ``dark_theme.qss``."""
    assert _representative_asset_text(THEME_DARK) == DARK_THEME_FALLBACK


def test_d33_light_fallback_constant_matches_light_theme_qss_exactly() -> None:
    """D33: ``LIGHT_THEME_FALLBACK`` is byte-for-byte identical to ``light_theme.qss``."""
    assert _representative_asset_text(THEME_LIGHT) == LIGHT_THEME_FALLBACK


def test_d33_fallback_tracks_a_live_edit_to_the_qss_asset_not_a_frozen_copy(
    manager: ThemeManager,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """D33: the fallback reflects a live edit to ``dark_theme.qss``, proving it is not a hardcoded copy.

    This is the falsifiability check for the drift bug itself: before the
    fix, ``DARK_THEME_FALLBACK`` was a hand-maintained literal that a change
    to ``dark_theme.qss`` would never touch, so a mutated selector in the
    real asset would silently NOT be reflected in what ``ThemeManager``
    actually serves as a fallback. Here the real asset content is copied to
    a scratch directory with a marker appended, the packaged-resource read
    route (:mod:`importlib.resources`) is forced to fail so the
    filesystem-backed secondary route is exercised, and the real
    ``get_style_path`` resolver is redirected at the scratch copy.
    Reintroducing a hardcoded fallback string would make this assertion
    fail, because the marker injected into the scratch copy would never
    appear in a frozen literal that was written before the mutation existed.

    Args:
        manager: Fresh ``ThemeManager`` fixture instance.
        monkeypatch: Pytest fixture used to force the packaged-resource read
            route to fail and to redirect the filesystem-backed asset
            resolution at a mutated scratch copy.
        tmp_path: Pytest-provided scratch directory.
    """
    assert manager.styles_available, "styles directory must exist on disk for this scenario to be meaningful"

    marker = "/* D33-DRIFT-PROBE-MARKER */"
    real_dark_text = get_style_path("dark_theme.qss").read_text(encoding="utf-8")
    mutated_text = f"{real_dark_text}\n{marker}\n"

    scratch_styles_dir = tmp_path / "styles"
    scratch_styles_dir.mkdir()
    (scratch_styles_dir / "dark_theme.qss").write_text(mutated_text, encoding="utf-8")

    def _fake_get_style_path(filename: str) -> Path:
        """Resolve a stylesheet file name against the mutated scratch directory.

        Args:
            filename: Stylesheet file name to resolve.

        Returns:
            Path: Path to ``filename`` inside the scratch styles directory.
        """
        return scratch_styles_dir / filename

    def _raise_module_not_found(anchor: object = None) -> NoReturn:
        """Simulate ``importlib.resources.files`` being unavailable.

        Args:
            anchor: Ignored; mirrors the ``files(anchor)`` signature.

        Raises:
            ModuleNotFoundError: Always, to force callers onto the
                filesystem-backed secondary read route.
        """
        _ = anchor
        message = "D33 test: simulate importlib.resources being unavailable"
        raise ModuleNotFoundError(message)

    monkeypatch.setattr(theme_manager_module, "get_style_path", _fake_get_style_path)
    monkeypatch.setattr(theme_manager_module.resources, "files", _raise_module_not_found)
    monkeypatch.setattr(ThemeManager, "_read_stylesheet_file", staticmethod(_always_missing_stylesheet_read))

    served = manager._load_stylesheet(THEME_DARK)

    assert marker in served, (
        "the fallback served for THEME_DARK did not track a live edit to dark_theme.qss -- it is reading a hardcoded copy instead of the packaged asset"
    )
    assert served == mutated_text
