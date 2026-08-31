# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gate for S14-D16: the attach auto-popup Regions dialog.

``MainWindow._on_process_attached`` -> ``_on_process_regions_listed`` (in
``src/intellicrack/ui/app.py``) builds a modal "Memory Regions" picker every
time the Process panel attaches to a target. Before the fix, this picker had
two defects:

1. The "Protection" and "State" columns were rendered as raw hex
   (``f"0x{prot:08X}"`` / ``f"0x{state:08X}"``) instead of the human-readable
   ``PAGE_*`` / ``MEM_*`` Win32 constant names.
2. The dialog never pre-selected a row, so its OK action opened whatever
   ``table.currentRow()`` happened to be (row 0 / base ``0x0``), which for a
   real process is almost always the ``MEM_FREE`` sentinel region at the
   bottom of the address space -- producing a ReadProcessMemory-failed dialog
   instead of opening a real, readable region.

The fix decodes both columns via ``MainWindow._decode_page_protection`` /
``_decode_mem_state`` and pre-selects the first committed
(``MEM_COMMIT``), readable region via ``MainWindow._default_region_row``,
so a bare "attach -> Regions popup -> OK" flow lands on real, readable
memory instead of a guaranteed-to-fail region.

This test drives the real ``MainWindow._on_process_regions_listed`` entry
point directly (bypassing the off-thread dispatch in
``_on_process_attached``, which is covered by other gates) against a real
``MainWindow`` built from real ``Config``/``Orchestrator`` instances (per the
``real_config``/``real_orchestrator`` fixtures in ``tests/ui/conftest.py``).
``QDialog.exec`` is monkeypatched to a synchronous stand-in that captures the
live table built by production code -- the same non-blocking pattern used
throughout ``tests/ui`` to drive modal dialogs headlessly -- so no real
nested Qt event loop or human interaction is required.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QApplication, QDialog, QTableWidget

from intellicrack.ui.app import MainWindow


if TYPE_CHECKING:
    from collections.abc import Generator

    from intellicrack.core.config import Config
    from intellicrack.core.orchestrator import Orchestrator

_PID = 4321
_MEM_FREE_BASE = 0x0
_MEM_FREE_SIZE = 0x1000
_MEM_FREE_PROTECTION = 0x01  # PAGE_NOACCESS, as Windows reports for MEM_FREE regions
_MEM_FREE_STATE = 0x10000  # MEM_FREE

_COMMITTED_BASE = 0x7FF600000000
_COMMITTED_SIZE = 0x2000
_COMMITTED_PROTECTION = 0x40  # PAGE_EXECUTE_READWRITE
_COMMITTED_STATE = 0x1000  # MEM_COMMIT

_REGIONS: list[tuple[int, int, int, int]] = [
    (_MEM_FREE_BASE, _MEM_FREE_SIZE, _MEM_FREE_PROTECTION, _MEM_FREE_STATE),
    (_COMMITTED_BASE, _COMMITTED_SIZE, _COMMITTED_PROTECTION, _COMMITTED_STATE),
]


@pytest.fixture
def window(qapp: QApplication, real_config: Config, real_orchestrator: Orchestrator) -> Generator[MainWindow]:
    """Construct a real ``MainWindow`` from real config/orchestrator fixtures.

    Args:
        qapp: Session QApplication fixture.
        real_config: Real ``Config`` fixture from ``tests/ui/conftest.py``.
        real_orchestrator: Real ``Orchestrator`` fixture from ``tests/ui/conftest.py``.

    Yields:
        MainWindow: The window under test.
    """
    del qapp
    win = MainWindow(real_config, real_orchestrator)
    try:
        yield win
    finally:
        win.close()


class TestAttachRegionsPopupDecodesAndDefaultsToReadableRegion:
    """S14-D16: decoded Protection/State text and a readable default selection."""

    def test_popup_decodes_columns_and_defaults_to_committed_readable_region(
        self,
        window: MainWindow,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The popup must decode Protection/State and default-select the committed region.

        Row 0 is a ``MEM_FREE`` sentinel at base ``0x0`` (the realistic shape of
        a real ``list_process_memory_regions`` result); row 1 is a real
        committed, readable region. Both the decoded table text and the
        default-selected row are captured from inside a monkeypatched
        ``QDialog.exec`` at the exact moment production code would show the
        dialog to the user, before OK is "pressed" (the stand-in returns
        ``Accepted`` immediately afterwards, without a real nested event loop).

        Args:
            window: Real MainWindow fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        captured: dict[str, object] = {}

        def _fake_exec(dialog_self: QDialog) -> int:
            """Capture the live regions table, then accept the dialog.

            Args:
                dialog_self: The ``QDialog`` instance ``exec`` was called on;
                    bound as ``self`` since this replaces the unbound method.

            Returns:
                int: ``QDialog.DialogCode.Accepted``, simulating the user
                pressing OK without a real nested event loop.
            """
            tables = dialog_self.findChildren(QTableWidget)
            assert tables, "the Memory Regions dialog must contain a QTableWidget"
            table = tables[0]
            captured["table"] = table
            captured["default_row"] = table.currentRow()
            captured["protection_text"] = [table.item(row, 2).text() for row in range(table.rowCount())]
            captured["state_text"] = [table.item(row, 3).text() for row in range(table.rowCount())]
            return int(QDialog.DialogCode.Accepted)

        monkeypatch.setattr(QDialog, "exec", _fake_exec)

        opened: list[tuple[int, int, int]] = []
        monkeypatch.setattr(
            window,
            "_open_process_memory",
            lambda pid, base_addr, region_size: opened.append((pid, base_addr, region_size)),
        )

        window._on_process_regions_listed(_PID, _REGIONS)

        protection_text = captured["protection_text"]
        state_text = captured["state_text"]
        assert isinstance(protection_text, list)
        assert isinstance(state_text, list)

        assert protection_text[0] == "PAGE_NOACCESS", (
            f"Protection column must be decoded to a symbolic PAGE_* name, not raw hex; got {protection_text[0]!r}"
        )
        assert state_text[0] == "MEM_FREE", f"State column must be decoded to a symbolic MEM_* name, not raw hex; got {state_text[0]!r}"
        assert protection_text[1] == "PAGE_EXECUTE_READWRITE", (
            f"Protection column must be decoded to a symbolic PAGE_* name, not raw hex; got {protection_text[1]!r}"
        )
        assert state_text[1] == "MEM_COMMIT", f"State column must be decoded to a symbolic MEM_* name, not raw hex; got {state_text[1]!r}"

        for text in (*protection_text, *state_text):
            assert not text.startswith("0x"), f"column text must never be raw hex; got {text!r}"

        assert captured["default_row"] == 1, (
            f"the popup must default-select the first committed, readable region (row 1, base "
            f"0x{_COMMITTED_BASE:X}), not row 0 / base 0x0 (MEM_FREE); got default_row={captured['default_row']!r}"
        )

        assert opened == [(_PID, _COMMITTED_BASE, _COMMITTED_SIZE)], (
            f"OK must open the default-selected committed region (base 0x{_COMMITTED_BASE:X}), not row 0 / base 0x0; got {opened!r}"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
