# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression test for finding M18: block-transform dialogs must not crash on bad input.

Pre-fix, ``_on_block_fill`` / ``_on_block_copy`` / ``_on_block_move`` /
``_on_block_swap`` called ``dlg.get_values()`` -- which parses fields with
``int(text, 0)`` and ``bytes.fromhex(...)`` -- *outside* the try/except that
guarded the document mutation. Entering ``0xZZ`` or ``GG`` and clicking OK raised
an uncaught ``ValueError`` out of the Qt slot and aborted the app. This test
replaces each dialog with a stand-in that auto-accepts and whose ``get_values``
runs the *same* ``int(_BAD_HEX, 0)`` parse the real dialog performs on malformed
input, then asserts no exception escapes each real handler, a validation warning
is surfaced, and the document mutation is never attempted.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

import pytest
from PyQt6.QtWidgets import QApplication, QDialog, QMessageBox, QWidget

from intellicrack.ui.panels.hex_editor import transforms
from intellicrack.ui.panels.hex_editor.transforms import TransformsMixin


if TYPE_CHECKING:
    from collections.abc import Iterator


_BAD_HEX: Final[str] = "0xZZ"


@pytest.fixture(scope="module")
def qapp() -> Iterator[QApplication]:
    """Provide a process-wide ``QApplication`` for Qt widget construction.

    Yields:
        QApplication: The active Qt application for the test process.
    """
    existing = QApplication.instance()
    if existing is not None and isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


class _RaisingFillDialog:
    """Fill-dialog stand-in that auto-accepts and raises on the real int() parse."""

    def __init__(self, hex_widget: object, parent: QWidget | None = None) -> None:
        """Accept and discard the real dialog's construction arguments.

        Args:
            hex_widget: Hex widget the real dialog would receive (unused).
            parent: Parent widget the real dialog would receive (unused).
        """
        del hex_widget, parent

    def exec(self) -> int:
        """Return the Accepted code without showing a modal dialog.

        Returns:
            int: The ``QDialog.DialogCode.Accepted`` integer value.
        """
        return int(QDialog.DialogCode.Accepted)

    def get_values(self) -> tuple[int, int, bytes]:
        """Reproduce the real dialog's failing parse of a malformed offset.

        Returns:
            tuple[int, int, bytes]: Never produced; ``int(_BAD_HEX, 0)`` raises
                ``ValueError`` exactly as the real dialog does on invalid input.
        """
        return int(_BAD_HEX, 0), 16, b""


class _RaisingCopyMoveDialog:
    """Copy/move-dialog stand-in that auto-accepts and raises on the real int() parse."""

    def __init__(self, title: str, parent: QWidget | None = None) -> None:
        """Accept and discard the real dialog's construction arguments.

        Args:
            title: Window title the real dialog would receive (unused).
            parent: Parent widget the real dialog would receive (unused).
        """
        del title, parent

    def exec(self) -> int:
        """Return the Accepted code without showing a modal dialog.

        Returns:
            int: The ``QDialog.DialogCode.Accepted`` integer value.
        """
        return int(QDialog.DialogCode.Accepted)

    def get_values(self) -> tuple[int, int, int]:
        """Reproduce the real dialog's failing parse of a malformed source offset.

        Returns:
            tuple[int, int, int]: Never produced; ``int(_BAD_HEX, 0)`` raises
                ``ValueError`` exactly as the real dialog does on invalid input.
        """
        return int(_BAD_HEX, 0), 16, 0


class _RaisingSwapDialog:
    """Swap-dialog stand-in that auto-accepts and raises on the real int() parse."""

    def __init__(self, parent: QWidget | None = None) -> None:
        """Accept and discard the real dialog's construction argument.

        Args:
            parent: Parent widget the real dialog would receive (unused).
        """
        del parent

    def exec(self) -> int:
        """Return the Accepted code without showing a modal dialog.

        Returns:
            int: The ``QDialog.DialogCode.Accepted`` integer value.
        """
        return int(QDialog.DialogCode.Accepted)

    def get_values(self) -> tuple[int, int, int, int]:
        """Reproduce the real dialog's failing parse of a malformed block-A offset.

        Returns:
            tuple[int, int, int, int]: Never produced; ``int(_BAD_HEX, 0)`` raises
                ``ValueError`` exactly as the real dialog does on invalid input.
        """
        return int(_BAD_HEX, 0), 16, 0, 16


class _RecordingDoc:
    """Document stub that records any block-mutation call the handler attempts."""

    def __init__(self) -> None:
        """Initialise with an empty mutation-call log."""
        self.calls: list[str] = []

    def fill_block(self, offset: int, length: int, pattern: bytes) -> None:
        """Record a fill_block invocation.

        Args:
            offset: Fill offset.
            length: Fill length.
            pattern: Fill pattern bytes.
        """
        self.calls.append(f"fill_block({offset},{length},{pattern!r})")

    def copy_block(self, src: int, length: int, dst: int) -> None:
        """Record a copy_block invocation.

        Args:
            src: Source offset.
            length: Block length.
            dst: Destination offset.
        """
        self.calls.append(f"copy_block({src},{length},{dst})")

    def move_block(self, src: int, length: int, dst: int) -> None:
        """Record a move_block invocation.

        Args:
            src: Source offset.
            length: Block length.
            dst: Destination offset.
        """
        self.calls.append(f"move_block({src},{length},{dst})")

    def swap_blocks(self, off_a: int, len_a: int, off_b: int, len_b: int) -> None:
        """Record a swap_blocks invocation.

        Args:
            off_a: Block A offset.
            len_a: Block A length.
            off_b: Block B offset.
            len_b: Block B length.
        """
        self.calls.append(f"swap_blocks({off_a},{len_a},{off_b},{len_b})")


class _BlockHarness(QWidget):
    """Harness invoking the real block-transform handlers via ``getattr``."""

    def __init__(self, document: _RecordingDoc) -> None:
        """Initialise the harness with a recording document and no hex widget.

        Args:
            document: Recording document stub installed as ``self.document``.
        """
        super().__init__()
        self.document: _RecordingDoc | None = document
        self._hex_widget: object | None = None
        self.state_holder: object | None = None

    def _refresh_widget(self) -> None:
        """No-op stand-in for the post-mutation widget refresh."""

    def run_fill(self) -> None:
        """Invoke the production ``_on_block_fill`` handler."""
        getattr(TransformsMixin, "_on_block_fill")(self)

    def run_copy(self) -> None:
        """Invoke the production ``_on_block_copy`` handler."""
        getattr(TransformsMixin, "_on_block_copy")(self)

    def run_move(self) -> None:
        """Invoke the production ``_on_block_move`` handler."""
        getattr(TransformsMixin, "_on_block_move")(self)

    def run_swap(self) -> None:
        """Invoke the production ``_on_block_swap`` handler."""
        getattr(TransformsMixin, "_on_block_swap")(self)


def _install_warning_recorder(monkeypatch: pytest.MonkeyPatch, sink: list[tuple[str, str]]) -> None:
    """Replace ``QMessageBox.warning`` with a recorder to avoid modal dialogs.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
        sink: List that receives each ``(title, text)`` warning pair.
    """

    def _warn(parent: object, title: str, text: str, *args: object, **kwargs: object) -> object:
        """Record the warning instead of displaying it.

        Args:
            parent: Parent widget (ignored).
            title: Warning title.
            text: Warning body text.
            *args: Additional positional args from the production call (ignored).
            **kwargs: Additional keyword args from the production call (ignored).

        Returns:
            object: The ``Ok`` standard button, mimicking the real return value.
        """
        del parent, args, kwargs
        sink.append((title, text))
        return QMessageBox.StandardButton.Ok

    monkeypatch.setattr(transforms.QMessageBox, "warning", _warn)


@pytest.mark.usefixtures("qapp")
class TestBlockDialogInvalidInput:
    """M18: malformed block-dialog input must be surfaced, never escape the slot."""

    @staticmethod
    def test_fill_bad_input_does_not_raise_and_warns(qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
        """Assert a bad fill offset yields a warning and no document mutation.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
            monkeypatch: Pytest monkeypatch fixture.
        """
        del qapp
        warnings: list[tuple[str, str]] = []
        _install_warning_recorder(monkeypatch, warnings)
        monkeypatch.setattr(transforms, "_BlockFillDialog", _RaisingFillDialog)
        doc = _RecordingDoc()

        _BlockHarness(doc).run_fill()

        assert warnings, "a validation warning must be surfaced for malformed fill input"
        assert doc.calls == [], f"fill_block must not be attempted on invalid input, got {doc.calls}"

    @staticmethod
    def test_copy_bad_input_does_not_raise_and_warns(qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
        """Assert a bad copy source yields a warning and no document mutation.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
            monkeypatch: Pytest monkeypatch fixture.
        """
        del qapp
        warnings: list[tuple[str, str]] = []
        _install_warning_recorder(monkeypatch, warnings)
        monkeypatch.setattr(transforms, "_BlockCopyMoveDialog", _RaisingCopyMoveDialog)
        doc = _RecordingDoc()

        _BlockHarness(doc).run_copy()

        assert warnings, "a validation warning must be surfaced for malformed copy input"
        assert doc.calls == [], f"copy_block must not be attempted on invalid input, got {doc.calls}"

    @staticmethod
    def test_move_bad_input_does_not_raise_and_warns(qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
        """Assert a bad move source yields a warning and no document mutation.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
            monkeypatch: Pytest monkeypatch fixture.
        """
        del qapp
        warnings: list[tuple[str, str]] = []
        _install_warning_recorder(monkeypatch, warnings)
        monkeypatch.setattr(transforms, "_BlockCopyMoveDialog", _RaisingCopyMoveDialog)
        doc = _RecordingDoc()

        _BlockHarness(doc).run_move()

        assert warnings, "a validation warning must be surfaced for malformed move input"
        assert doc.calls == [], f"move_block must not be attempted on invalid input, got {doc.calls}"

    @staticmethod
    def test_swap_bad_input_does_not_raise_and_warns(qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
        """Assert a bad swap block-A offset yields a warning and no document mutation.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
            monkeypatch: Pytest monkeypatch fixture.
        """
        del qapp
        warnings: list[tuple[str, str]] = []
        _install_warning_recorder(monkeypatch, warnings)
        monkeypatch.setattr(transforms, "_BlockSwapDialog", _RaisingSwapDialog)
        doc = _RecordingDoc()

        _BlockHarness(doc).run_swap()

        assert warnings, "a validation warning must be surfaced for malformed swap input"
        assert doc.calls == [], f"swap_blocks must not be attempted on invalid input, got {doc.calls}"
