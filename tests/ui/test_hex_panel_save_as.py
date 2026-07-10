# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate for F14: hex panel "Save Patched Binary" must never overwrite in place.

``app.py::_on_save_patched_binary`` probes the hex panel for a public
``save_as`` method. Pre-fix, ``HexEditorPanel`` only exposed public ``save()``
(unconditional in-place overwrite of the loaded source path) and a *private*
``_on_save_as``, so the probe always fell through to ``save()`` -- silently
overwriting the original binary (e.g. a system DLL/EXE) with no Save-As
prompt.

These tests drive the real, public ``HexEditorPanel.save_as()`` against a
genuine PE file loaded through ``load_file`` and a real
``intellicrack_hexcore`` document, with only ``QFileDialog.getSaveFileName``
monkeypatched (the one genuinely interactive piece). They assert the patched
bytes land at the new path chosen through the dialog, the original source
file on disk is byte-for-byte untouched, and the dialog is seeded with a
``<stem>_patched<suffix>`` suggested filename so a user confirming the
dialog without editing it still cannot clobber the source.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QFileDialog

from intellicrack.ui.panels.hex_editor.panel import HexEditorPanel


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication


pytest.importorskip("intellicrack_hexcore", reason="intellicrack_hexcore backend required for real hex documents")

pytestmark = pytest.mark.usefixtures("qapp")

_SOURCE_PE: Path = Path(r"C:\Windows\System32\notepad.exe")
_PATCH_OFFSET: int = 0x100
_PATCH_BYTE: bytes = b"\x90"


def _require_source_pe() -> None:
    """Skip the calling test if the well-known system PE fixture is unavailable."""
    if not _SOURCE_PE.is_file():
        pytest.skip(f"real fixture PE not found at {_SOURCE_PE}")


class TestF14HexPanelSaveAsExists:
    """``save_as`` must be a public, callable API distinct from ``save``."""

    def test_save_as_is_public_and_not_the_private_handler(self, qapp: QApplication) -> None:
        """``HexEditorPanel`` must expose a public ``save_as`` callable.

        This is exactly the probe ``app.py::_on_save_patched_binary`` performs
        (``getattr(hex_panel, "save_as", None)``); pre-fix it returned
        ``None`` and the caller silently fell back to in-place ``save()``.

        Args:
            qapp: The shared offscreen QApplication fixture.
        """
        del qapp
        panel = HexEditorPanel()
        try:
            save_as = getattr(panel, "save_as", None)
            assert callable(save_as), "HexEditorPanel must expose a public, callable save_as() method"
        finally:
            panel.deleteLater()

    def test_save_as_without_document_returns_false_and_does_not_prompt(
        self,
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Calling ``save_as`` with nothing loaded must be a safe no-op.

        Args:
            qapp: The shared offscreen QApplication fixture.
            monkeypatch: Pytest fixture used to detect any dialog invocation.
        """
        del qapp
        prompted: list[object] = []
        monkeypatch.setattr(
            QFileDialog,
            "getSaveFileName",
            staticmethod(lambda *args, **kwargs: (prompted.append((args, kwargs)), ("", ""))[1]),
        )
        panel = HexEditorPanel()
        try:
            assert panel.document is None
            assert panel.save_as() is False
            assert not prompted, "no document is loaded; the Save-As dialog must not be shown"
        finally:
            panel.deleteLater()


class TestF14HexPanelSaveAsNeverOverwritesSource:
    """``save_as`` must write the new path only, leaving the source binary untouched."""

    def test_save_as_writes_patched_bytes_to_new_path_and_leaves_source_untouched(
        self,
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """A byte patch saved via ``save_as`` must land only at the new path.

        Copies a real system PE into a temp source path, loads it into the
        hex panel, applies a single-byte patch through the real hexcore
        document, then drives the real ``save_as()`` with
        ``QFileDialog.getSaveFileName`` monkeypatched to return a brand new
        temp path. Asserts the patched byte appears at the new path and the
        original source file's bytes are unchanged -- the exact regression
        this finding describes.

        Args:
            qapp: The shared offscreen QApplication fixture.
            monkeypatch: Pytest fixture used to stub the Save-As dialog.
            tmp_path: Pytest-provided temporary directory.
        """
        del qapp
        _require_source_pe()
        source_path = tmp_path / "source_under_test.exe"
        shutil.copy2(_SOURCE_PE, source_path)
        original_bytes = source_path.read_bytes()
        assert original_bytes[_PATCH_OFFSET : _PATCH_OFFSET + 1] != _PATCH_BYTE, (
            "test setup error: patch offset already holds the patch byte in the unmodified source"
        )

        new_path = tmp_path / "new_destination.exe"
        monkeypatch.setattr(
            QFileDialog,
            "getSaveFileName",
            staticmethod(lambda *_a, **_k: (str(new_path), "All Files (*)")),
        )

        panel = HexEditorPanel()
        try:
            assert panel.load_file(source_path) is True
            assert panel.document is not None

            panel.document.write_bytes(_PATCH_OFFSET, _PATCH_BYTE)
            assert panel.document.read(_PATCH_OFFSET, 1) == _PATCH_BYTE

            assert panel.save_as() is True

            assert new_path.is_file(), "save_as() did not create the new destination file"
            new_bytes = new_path.read_bytes()
            assert new_bytes[_PATCH_OFFSET : _PATCH_OFFSET + 1] == _PATCH_BYTE, (
                "patched byte was not written to the new Save-As destination"
            )

            source_bytes_after = source_path.read_bytes()
            assert source_bytes_after == original_bytes, (
                "save_as() modified the original source file in place; the source must remain byte-for-byte unchanged"
            )
        finally:
            panel.deleteLater()

    def test_save_as_prefills_dialog_with_stem_patched_suffix_suggestion(
        self,
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """The Save-As dialog must be pre-filled with a ``<stem>_patched<suffix>`` suggestion.

        Even if a user confirms the dialog without editing the suggested
        name, the result must never equal the original source path -- it
        must carry a distinguishing ``_patched`` marker.

        Args:
            qapp: The shared offscreen QApplication fixture.
            monkeypatch: Pytest fixture used to capture the dialog's default directory argument.
            tmp_path: Pytest-provided temporary directory.
        """
        del qapp
        _require_source_pe()
        source_path = tmp_path / "another_source.exe"
        shutil.copy2(_SOURCE_PE, source_path)

        captured_default: list[str] = []

        def _fake_get_save_file_name(*args: object, **_kwargs: object) -> tuple[str, str]:
            default_dir = str(args[2]) if len(args) > 2 else ""
            captured_default.append(default_dir)
            return default_dir, "All Files (*)"

        monkeypatch.setattr(QFileDialog, "getSaveFileName", staticmethod(_fake_get_save_file_name))

        panel = HexEditorPanel()
        try:
            assert panel.load_file(source_path) is True
            panel.save_as()

            assert captured_default, "getSaveFileName was never invoked"
            suggested = Path(captured_default[0])
            assert suggested != source_path, "the suggested Save-As path must not equal the original source path"
            assert suggested.name == f"{source_path.stem}_patched{source_path.suffix}"
        finally:
            panel.deleteLater()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
