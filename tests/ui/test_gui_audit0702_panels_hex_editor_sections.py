# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for the GUI audit findings C4 and M9 in ``hex_editor.sections``.

C4: ``SectionsMixin`` declared an empty ``_select_template`` stub. Because
``HexEditorPanel``'s base-class list places ``SectionsMixin`` before
``TemplatesMixin`` and neither mixin shares a non-``object`` ancestor,
Python's MRO resolved ``self._select_template(...)`` to the stub instead of
``TemplatesMixin``'s real implementation, so ``_auto_detect_file_type``
silently never selected a structure template on file open. The fix removes
the stub (keeping only a ``Callable`` type annotation for static analysis),
letting MRO fall through to ``TemplatesMixin._select_template``.

M9: ``_populate_strings`` called ``previous.requestInterruption()`` on a
superseded strings-extraction worker, but ``GenericCallableWorker.run()``
never checks the interruption flag, so the stale worker keeps running to
completion and can emit ``call_finished`` after a newer worker already
rendered fresh results -- silently clobbering the strings tree with stale
data. The fix routes both ``call_finished`` and ``call_error`` through
``_on_strings_worker_finished`` / ``_on_strings_worker_error``, which compare
the emitting worker's identity against the live ``self._strings_worker``
reference and discard any delivery from a worker that has already been
superseded.

Every test below drives the real ``SectionsMixin`` / ``TemplatesMixin``
implementations (no mocks standing in for the mixin logic) under an
offscreen ``QApplication``, using real ``GenericCallableWorker`` QThreads for
the M9 race reproduction.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Any

from PyQt6.QtWidgets import QComboBox, QTreeWidget, QTreeWidgetItem

from intellicrack.ui.panels.async_bridge import GenericCallableWorker
from intellicrack.ui.panels.hex_editor.sections import SectionsMixin
from intellicrack.ui.panels.hex_editor.templates import TemplatesMixin


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication
    from pytestqt.qtbot import QtBot


class _SectionsThenTemplatesHost(SectionsMixin, TemplatesMixin):
    """Minimal host reproducing ``HexEditorPanel``'s MRO ordering.

    ``HexEditorPanel`` lists ``SectionsMixin`` before ``TemplatesMixin`` in
    its base-class tuple; this host preserves that exact ordering so that
    Python's C3 linearization resolves ``self._select_template`` exactly as
    it does inside the real panel. Sets ``document`` (backing document used
    for magic-byte detection), ``_template_combo`` (combo box the resolved
    ``_select_template`` mutates), ``_file_info_label`` (label mutated by
    ``_auto_detect_file_type``), and ``_bridge`` (left ``None`` to keep
    pattern-registry matching a no-op for these tests).
    """

    def __init__(self) -> None:
        """Initialise empty document/combo/bridge state."""
        self.document = None
        self._template_combo: QComboBox | None = None
        self._file_info_label = None
        self._bridge = None


class _MagicBytesDocument:
    """Fake document exposing only the ``.read`` used for magic-byte sniffing.

    Stores the leading bytes returned by :meth:`read` in ``_magic``.
    """

    def __init__(self, magic: bytes) -> None:
        """Store the magic bytes to serve from offset zero.

        Args:
            magic: Leading file bytes (e.g. a DOS/ELF/Mach-O/ZIP signature).
        """
        self._magic = magic

    def read(self, offset: int, length: int) -> bytes:
        """Return up to ``length`` bytes of the stored magic, ignoring ``offset``.

        Args:
            offset: Start offset (unused; detection always reads from zero).
            length: Number of bytes requested.

        Returns:
            bytes: The stored magic bytes truncated to ``length``.
        """
        del offset
        return self._magic[:length]


def test_c4_mro_resolves_select_template_to_templates_mixin() -> None:
    """``_select_template`` must resolve via MRO to ``TemplatesMixin``'s implementation.

    Pre-fix, ``SectionsMixin`` defined its own empty ``_select_template``
    stub, which precedes ``TemplatesMixin`` in ``HexEditorPanel``'s base
    list and therefore wins Python's MRO lookup, making
    ``TemplatesMixin._select_template`` unreachable through
    ``self._select_template(...)``. Post-fix the stub is removed, so the
    class attribute lookup falls through to the real implementation.
    """
    resolved = _SectionsThenTemplatesHost._select_template
    assert resolved is TemplatesMixin._select_template, (
        "SectionsMixin's stub still shadows TemplatesMixin._select_template through MRO; "
        f"resolved to {resolved!r} instead of {TemplatesMixin._select_template!r}"
    )


def test_c4_select_template_updates_combo_box(qapp: QApplication) -> None:
    """Calling ``self._select_template`` on the combined host must move the combo selection.

    Exercises the resolved method directly (as ``_auto_detect_file_type``
    does) and asserts the real ``QComboBox`` selection changes. Pre-fix this
    would be a no-op because the call resolved to ``SectionsMixin``'s empty
    stub, leaving the combo box on its initial index.

    Args:
        qapp: The shared offscreen QApplication fixture.
    """
    _ = qapp
    host = _SectionsThenTemplatesHost()
    combo = QComboBox()
    combo.addItems(["IMAGE_DOS_HEADER", "ELF_HEADER_64", "MACH_HEADER_64"])
    host._template_combo = combo
    combo.setCurrentIndex(1)

    host._select_template("MACH_HEADER_64")

    assert combo.currentIndex() == 2, "resolved _select_template did not move the combo box selection"
    assert combo.currentText() == "MACH_HEADER_64"


def test_c4_auto_detect_file_type_selects_pe_template_end_to_end(qapp: QApplication) -> None:
    """``_auto_detect_file_type`` must select the PE template through the real dispatch path.

    Drives the exact call site the finding describes
    (``_auto_detect_file_type`` -> ``self._select_template(...)``) with a
    document whose leading bytes are the ``MZ`` DOS signature. Pre-fix, the
    combo box would remain on its initial ``ELF_HEADER_64`` selection because
    ``self._select_template`` resolved to the no-op stub; post-fix it must
    move to ``IMAGE_DOS_HEADER``.

    Args:
        qapp: The shared offscreen QApplication fixture.
    """
    _ = qapp
    host = _SectionsThenTemplatesHost()
    host.document = _MagicBytesDocument(b"MZ\x90\x00")
    combo = QComboBox()
    combo.addItems(["IMAGE_DOS_HEADER", "ELF_HEADER_64", "MACH_HEADER_64", "ZIP_LOCAL_FILE_HEADER"])
    combo.setCurrentIndex(1)
    host._template_combo = combo

    host._auto_detect_file_type()

    assert combo.currentText() == "IMAGE_DOS_HEADER", (
        "auto-detecting a PE file did not select IMAGE_DOS_HEADER; _select_template still resolves to a no-op"
    )


class _RaceDocument:
    """Strings-extraction source that blocks its first call until released.

    Mirrors the ``extract_strings`` surface ``execute_strings_extraction``
    calls. The first invocation blocks on :attr:`release_first_call` so a
    test can hold a superseded worker's native extraction in flight while a
    second, faster worker finishes and renders its results first --
    reproducing the exact race M9 describes.

    Attributes:
        release_first_call: Event the test sets to unblock the first call.
    """

    release_first_call: threading.Event

    def __init__(self) -> None:
        """Initialise the call counter and the first-call release gate."""
        self._call_count = 0
        self._lock = threading.Lock()
        self.release_first_call = threading.Event()

    def extract_strings(
        self,
        *,
        min_length: int,
        include_ascii: bool,
        include_utf16: bool,
        max_results: int,
    ) -> list[dict[str, object]]:
        """Return a STALE-tagged record for the first call, FRESH for later ones.

        Args:
            min_length: Accepted for signature compatibility; unused.
            include_ascii: Accepted for signature compatibility; unused.
            include_utf16: Accepted for signature compatibility; unused.
            max_results: Accepted for signature compatibility; unused.

        Returns:
            list[dict[str, object]]: A single-record result list tagged
            ``STALE-RESULT`` for the first call (after blocking on
            :attr:`release_first_call`) or ``FRESH-RESULT`` for every
            subsequent call.
        """
        del min_length, include_ascii, include_utf16, max_results
        with self._lock:
            call_index = self._call_count
            self._call_count += 1
        if call_index == 0:
            self.release_first_call.wait(timeout=10.0)
            return [{"offset": 0, "text": "STALE-RESULT"}]
        return [{"offset": 0, "text": "FRESH-RESULT"}]


class _StringsHost(SectionsMixin):
    """Minimal host exposing only the state ``_populate_strings`` touches.

    Also carries a private ``_strings_tree`` (tree widget rendered by the
    strings handlers) and a private ``_strings_worker`` (currently active
    strings-extraction worker, if any).

    Attributes:
        document: Backing strings-extraction source.
    """

    document: Any | None
    _strings_tree: QTreeWidget | None
    _strings_worker: GenericCallableWorker | None

    def __init__(self) -> None:
        """Initialise empty document/tree/worker state."""
        self.document = None
        self._strings_tree = None
        self._strings_worker = None


def test_m9_superseded_slower_worker_does_not_overwrite_fresher_result(
    qapp: QApplication,
    qtbot: QtBot,
) -> None:
    """A stale worker's late ``call_finished`` must not clobber a fresher rendered result.

    Reproduces the exact race M9 describes: an old (slow) extraction is
    still in flight when a new scan is triggered; ``requestInterruption()``
    does not actually stop the old worker's native call, so it can still
    complete and emit ``call_finished`` after the new worker's results are
    already on screen. Pre-fix, ``call_finished`` connected directly to
    ``_on_strings_ready`` with no staleness check, so the stale worker's
    late delivery would clear the tree and repopulate it with
    ``STALE-RESULT``. Post-fix, ``_on_strings_worker_finished`` compares the
    emitting worker's identity against the live ``_strings_worker`` and
    discards the stale delivery.

    Args:
        qapp: The shared offscreen QApplication fixture.
        qtbot: pytest-qt bot used to pump the event loop deterministically.
    """
    _ = qapp
    host = _StringsHost()
    document = _RaceDocument()
    host.document = document
    tree = QTreeWidget()
    host._strings_tree = tree

    host._populate_strings()
    worker_a = host._strings_worker
    assert isinstance(worker_a, GenericCallableWorker)

    host._populate_strings()
    worker_b = host._strings_worker
    assert isinstance(worker_b, GenericCallableWorker)
    assert worker_b is not worker_a, "second _populate_strings call did not spawn a new worker"

    def _fresh_result_rendered() -> bool:
        """Return whether the tree currently shows the fresher worker's result.

        Returns:
            bool: ``True`` once the single tree row reads ``FRESH-RESULT``.
        """
        if tree.topLevelItemCount() != 1:
            return False
        item = tree.topLevelItem(0)
        return item is not None and item.text(2) == "FRESH-RESULT"

    qtbot.waitUntil(_fresh_result_rendered, timeout=5000)

    document.release_first_call.set()
    assert worker_a.wait(5000), "superseded worker did not finish after being released"
    qtbot.wait(300)

    assert tree.topLevelItemCount() == 1, "strings tree row count changed after the stale worker's late delivery"
    final_item = tree.topLevelItem(0)
    assert final_item is not None
    assert final_item.text(2) == "FRESH-RESULT", (
        "a superseded worker's late call_finished overwrote the fresher worker's already-rendered "
        "result; GenericCallableWorker never honours requestInterruption(), so the mixin must "
        "discard stale deliveries by comparing worker identity"
    )


def test_m9_stale_worker_error_is_discarded_by_identity_check(qapp: QApplication) -> None:
    """A superseded worker's late ``call_error`` must not clear an already-rendered tree.

    Directly exercises ``_on_strings_worker_error`` (the real production
    handler ``call_error`` is connected to) the same way Qt would invoke it
    from a stale worker's queued signal: with a worker object that is no
    longer ``self._strings_worker``. Pre-fix, ``call_error`` connected
    directly to ``_on_strings_failed_obj`` with no staleness check, so any
    late error -- even from a worker that has since been superseded -- would
    clear the tree and show an error row. Post-fix the handler must discard
    it because the emitting worker no longer matches ``self._strings_worker``.

    Args:
        qapp: The shared offscreen QApplication fixture.
    """
    _ = qapp
    host = _StringsHost()
    tree = QTreeWidget()
    tree.addTopLevelItem(QTreeWidgetItem(["0x00000000", "12", "FRESH-RESULT"]))
    host._strings_tree = tree

    stale_worker = GenericCallableWorker(lambda: None)
    fresh_worker = GenericCallableWorker(lambda: None)
    host._strings_worker = fresh_worker

    host._on_strings_worker_error(stale_worker, ValueError("stale extraction failure"))

    assert tree.topLevelItemCount() == 1, "a stale worker's error changed the strings tree row count"
    item = tree.topLevelItem(0)
    assert item is not None
    assert item.text(2) == "FRESH-RESULT", (
        "a stale worker's call_error cleared/replaced the strings tree even though a newer "
        "worker (fresh_worker) is the active _strings_worker"
    )
