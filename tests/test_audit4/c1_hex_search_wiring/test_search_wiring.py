# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for audit4 C1 - hex editor search wiring (F-0001, F-0014).

Validates that:

* ``SearchMixin._on_search`` dispatches workers against ``self.document``
  (not the dead ``self._document`` class annotation), so no ``AttributeError``
  is raised and the correct document object is passed to the background worker.

* ``SearchMixin._on_search_mode_changed`` clears search results, highlights,
  and status whenever the search mode changes so stale results from a
  previous mode are never shown.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from intellicrack.ui.panels.async_bridge import GenericCallableWorker


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PyQt6.QtWidgets import QApplication, QComboBox, QLabel, QLineEdit

from intellicrack.ui.panels.hex_editor._search import SearchMixin


class _FakeDocument:
    """Minimal real document used to back search operations in tests."""

    def __init__(self, data: bytes) -> None:
        """Store byte content for the document.

        Args:
            data: Raw bytes this document exposes.
        """
        self._data: bytes = data

    def search_hex(self, query: str, max_results: int) -> list[tuple[int, int]]:
        """Search for a hex-encoded byte pattern.

        Args:
            query: Hex string to search for (no spaces).
            max_results: Maximum result count.

        Returns:
            list[tuple[int, int]]: List of (offset, length) matches.
        """
        try:
            needle = bytes.fromhex(query.replace(" ", ""))
        except ValueError:
            return []
        results: list[tuple[int, int]] = []
        start = 0
        while len(results) < max_results:
            idx = self._data.find(needle, start)
            if idx == -1:
                break
            results.append((idx, len(needle)))
            start = idx + 1
        return results

    def search_text(
        self,
        query: str,
        encoding: str,
        *,
        case_sensitive: bool,
        max_results: int,
    ) -> list[tuple[int, int]]:
        """Search for a text string in the document.

        Args:
            query: Text string to find.
            encoding: Character encoding to use.
            case_sensitive: Whether matching is case-sensitive.
            max_results: Maximum result count.

        Returns:
            list[tuple[int, int]]: List of (offset, length) matches.
        """
        needle = query.encode(encoding)
        haystack = self._data
        if not case_sensitive:
            needle = needle.lower()
            haystack = haystack.lower()
        results: list[tuple[int, int]] = []
        start = 0
        while len(results) < max_results:
            idx = haystack.find(needle, start)
            if idx == -1:
                break
            results.append((idx, len(needle)))
            start = idx + 1
        return results

    def length(self) -> int:
        """Return the total byte length of the document.

        Returns:
            int: Number of bytes in the document.
        """
        return len(self._data)

    def read(self, offset: int, length: int) -> bytes:
        """Read a slice of bytes from the document.

        Args:
            offset: Start byte offset.
            length: Number of bytes to read.

        Returns:
            bytes: The requested byte slice.
        """
        return self._data[offset : offset + length]


class _TrackingHexWidget:
    """Fake hex widget that tracks highlight and clear calls."""

    def __init__(self) -> None:
        """Initialise tracking state."""
        self.highlight_calls: list[tuple[list[tuple[int, int, str]], str]] = []
        self.clear_calls: list[str] = []

    def highlight_offsets(
        self,
        highlights: list[tuple[int, int, str]],
        group: str,
    ) -> None:
        """Record a highlight_offsets call.

        Args:
            highlights: List of (offset, length, color) tuples.
            group: Highlight group name.
        """
        self.highlight_calls.append((highlights, group))

    def clear_highlights(self, group: str) -> None:
        """Record a clear_highlights call.

        Args:
            group: Highlight group name to clear.
        """
        self.clear_calls.append(group)


class _ConcreteSearch(SearchMixin):
    """Minimal concrete SearchMixin implementation used in tests."""

    def __init__(
        self,
        document: _FakeDocument | None,
        hex_widget: _TrackingHexWidget,
    ) -> None:
        """Set up minimal mixin state.

        Args:
            document: Document to expose as ``self.document``.
            hex_widget: Hex widget for highlight tracking.
        """
        app = QApplication.instance()
        if app is None:
            self._owned_app: QApplication | None = QApplication([])
        else:
            self._owned_app = None

        self.document: _FakeDocument | None = document
        self._hex_widget: _TrackingHexWidget = hex_widget
        self._search_results: list[tuple[int, int]] = []
        self._search_index: int = 0
        self._search_worker: GenericCallableWorker | None = None
        self._numeric_search_worker: GenericCallableWorker | None = None

        self._search_input = QLineEdit()
        self._search_mode_combo = QComboBox()
        self._search_mode_combo.addItems(["Hex", "Text", "Regex", "Numeric"])
        self._encoding_combo = QComboBox()
        self._encoding_combo.addItem("UTF-8")
        self._search_status_label = QLabel()
        self._numeric_search_frame = None
        self._numeric_value_input = None
        self._numeric_size_combo = None
        self._numeric_type_combo = None
        self._numeric_endian_combo = None
        self._numeric_align_spin = None
        self._numeric_range_check = None
        self._numeric_max_input = None


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Provide or reuse a QApplication for the test module.

    Returns:
        QApplication: Active QApplication instance.
    """
    existing = QApplication.instance()
    if isinstance(existing, QApplication):
        return existing
    return QApplication([])


class TestSearchUsesDocument:
    """F-0001: search must use ``self.document``, not dead ``self._document``."""

    @staticmethod
    def test_search_dispatches_worker_with_correct_document(qapp: QApplication) -> None:
        """Calling ``_on_search`` creates a worker bound to ``self.document``.

        Before the fix, ``_on_search`` checked ``self._document`` (the dead
        class annotation — always absent at runtime) so the guard
        ``if self._document is None`` returned early and no worker was created.
        After the fix it reads ``self.document`` via ``getattr`` and passes
        it to ``GenericCallableWorker``.

        Args:
            qapp: QApplication fixture (ensures Qt is available).
        """
        _ = qapp
        doc = _FakeDocument(b"hello world hello")
        widget = _TrackingHexWidget()
        mixin = _ConcreteSearch(doc, widget)
        mixin._search_input.setText("hello")
        mixin._search_mode_combo.setCurrentText("Text")

        mixin._on_search()

        worker = mixin._search_worker
        assert worker is not None, "_on_search must create a GenericCallableWorker"
        assert worker._args[0] is doc, "First positional arg to worker must be self.document, not None or a different object"
        worker.quit()
        worker.wait(2000)

    @staticmethod
    def test_search_no_attribute_error_when_document_set(qapp: QApplication) -> None:
        """``_on_search`` raises no ``AttributeError`` when ``self.document`` is set.

        Before the fix, ``_on_search`` evaluated ``self._document`` which is
        declared only as a class annotation and never assigned, causing an
        ``AttributeError`` on attribute access in Python strict mode or
        returning ``None`` via the class-dict lookup depending on the Python
        version.

        Args:
            qapp: QApplication fixture.
        """
        _ = qapp
        doc = _FakeDocument(b"\xde\xad\xbe\xef" * 8)
        widget = _TrackingHexWidget()
        mixin = _ConcreteSearch(doc, widget)
        mixin._search_input.setText("DEADBEEF")
        mixin._search_mode_combo.setCurrentText("Hex")

        raised: BaseException | None = None
        try:
            mixin._on_search()
        except AttributeError as exc:
            raised = exc

        assert raised is None, f"_on_search raised AttributeError: {raised}"

        worker = mixin._search_worker
        if worker is not None:
            worker.quit()
            worker.wait(2000)

    @staticmethod
    def test_search_returns_early_when_document_is_none(qapp: QApplication) -> None:
        """``_on_search`` returns early without error when no document is loaded.

        Args:
            qapp: QApplication fixture.
        """
        _ = qapp
        widget = _TrackingHexWidget()
        mixin = _ConcreteSearch(None, widget)
        mixin._search_input.setText("hello")

        mixin._on_search()

        assert mixin._search_worker is None, "_on_search must not create a worker when document is None"

    @staticmethod
    def test_dead_class_annotation_removed(qapp: QApplication) -> None:
        """``SearchMixin`` must not declare ``_document`` as a class attribute.

        The dead ``_document: Any | None`` annotation was the root cause of
        F-0001. Its removal is verified by checking it is absent from
        ``SearchMixin.__annotations__``.

        Args:
            qapp: QApplication fixture.
        """
        _ = qapp
        assert "_document" not in SearchMixin.__annotations__, (
            "SearchMixin must not declare a '_document' class annotation; "
            "the mixin accesses the document via self.document (set by HexEditorPanel)"
        )


class TestSearchResultsClearedOnModeChange:
    """F-0014: switching search modes must clear stale results and highlights."""

    @staticmethod
    def test_results_cleared_after_mode_change(qapp: QApplication) -> None:
        """Changing the search mode resets ``_search_results`` to empty.

        Simulates completing a text search (populating ``_search_results``),
        then switching the mode combo to ``Hex`` and verifying the results list
        is empty.

        Args:
            qapp: QApplication fixture.
        """
        _ = qapp
        doc = _FakeDocument(b"hello world hello")
        widget = _TrackingHexWidget()
        mixin = _ConcreteSearch(doc, widget)

        mixin._search_results = [(0, 5), (12, 5)]
        mixin._search_index = 1
        assert len(mixin._search_results) == 2

        mixin._search_mode_combo.setCurrentText("Hex")
        mixin._on_search_mode_changed("Hex")

        assert mixin._search_results == [], "_search_results must be cleared when mode changes"
        assert mixin._search_index == 0, "_search_index must reset to 0"

    @staticmethod
    def test_highlights_cleared_after_mode_change(qapp: QApplication) -> None:
        """Changing the search mode calls ``clear_highlights('search')`` on the widget.

        Args:
            qapp: QApplication fixture.
        """
        _ = qapp
        doc = _FakeDocument(b"abcdef")
        widget = _TrackingHexWidget()
        mixin = _ConcreteSearch(doc, widget)

        mixin._search_results = [(0, 3)]
        mixin._on_search_mode_changed("Regex")

        assert "search" in widget.clear_calls, "clear_highlights('search') must be called on the hex widget when mode changes"

    @staticmethod
    def test_status_label_cleared_after_mode_change(qapp: QApplication) -> None:
        """Changing the search mode clears the status label text.

        Args:
            qapp: QApplication fixture.
        """
        _ = qapp
        doc = _FakeDocument(b"abcdef")
        widget = _TrackingHexWidget()
        mixin = _ConcreteSearch(doc, widget)

        assert mixin._search_status_label is not None
        mixin._search_status_label.setText("Found 3 results")
        mixin._on_search_mode_changed("Text")

        assert not mixin._search_status_label.text(), "Status label must be cleared when mode changes"

    @staticmethod
    def test_reset_search_state_clears_all_fields(qapp: QApplication) -> None:
        """``_reset_search_state`` clears results, index, highlights, and status.

        Args:
            qapp: QApplication fixture.
        """
        _ = qapp
        doc = _FakeDocument(b"data")
        widget = _TrackingHexWidget()
        mixin = _ConcreteSearch(doc, widget)

        mixin._search_results = [(10, 4), (20, 4)]
        mixin._search_index = 1
        assert mixin._search_status_label is not None
        mixin._search_status_label.setText("Found 2 results")

        mixin._reset_search_state()

        assert mixin._search_results == []
        assert mixin._search_index == 0
        assert not mixin._search_status_label.text()
        assert "search" in widget.clear_calls

    @staticmethod
    def test_input_text_change_triggers_reset(qapp: QApplication) -> None:
        """Modifying the search input text resets stale results.

        After calling ``_setup_search_signals``, typing in the search input
        must clear any previous results so the user does not see stale
        highlights from a prior query.

        Args:
            qapp: QApplication fixture.
        """
        _ = qapp
        doc = _FakeDocument(b"hello world")
        widget = _TrackingHexWidget()
        mixin = _ConcreteSearch(doc, widget)

        mixin._setup_search_signals()
        mixin._search_results = [(0, 5)]

        assert mixin._search_input is not None
        mixin._search_input.setText("new query")

        assert mixin._search_results == [], "Changing search input text must clear _search_results"
