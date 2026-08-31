# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for the 2026-07-02 GUI audit findings in ``tool_config``.

Each test targets one audit finding and fails against the pre-fix behaviour:

* ``TestH30MidDownloadTransportError`` (H30): ``ToolInstallWorker._install_tool``
  must catch the full ``httpx.HTTPError`` hierarchy around ``_stream_download``,
  not just ``httpx.TimeoutException``/``httpx.ConnectError``, so a connection
  reset mid-download still emits ``install_finished`` instead of hanging the
  install worker forever.
* ``TestM67StatusLabelWordWrap`` (M67): ``ToolSettingsWidget.status_label``
  must have word wrap enabled and actually wrap long check-failure messages
  within the fixed-width settings panel instead of overflowing it.
* ``TestM68StatusListTooltips`` (M68): ``ToolStatusDialog``'s status list items
  must carry a tooltip with the full status/error message so text elided by
  the fixed-width left panel remains readable.

All tests drive real :class:`ToolInstallWorker`, :class:`ToolSettingsWidget`,
and :class:`ToolStatusDialog` instances under an offscreen QApplication; the
only substitution is the network transport layer for the download-worker
tests, via ``httpx.MockTransport`` (httpx's own supported test seam) rather
than mocking any Intellicrack code.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx
import pytest
from PyQt6.QtWidgets import QApplication, QVBoxLayout, QWidget

from intellicrack.ui.tool_config import (
    _COMPAT_SPLIT_LEFT,
    _SPLIT_RIGHT,
    ToolInstallWorker,
    ToolSettingsWidget,
    ToolStatusDialog,
    ToolStatusEntry,
)

from .conftest import SignalRecorder


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from pytestqt.qtbot import QtBot


_CONTAINER_TEST_HEIGHT = 900


class _MidStreamFailureStream(httpx.SyncByteStream):
    """Byte stream that yields one chunk then raises a transport error."""

    def __init__(self, error: httpx.HTTPError) -> None:
        """Store the transport error to raise mid-stream.

        Args:
            error: The httpx error instance to raise after the first chunk.
        """
        self._error = error

    def __iter__(self) -> Iterator[bytes]:
        """Yield one chunk, then raise the configured transport error.

        Yields:
            bytes: A single placeholder chunk sent before the failure.

        Raises:
            self._error: The configured mid-stream transport error.
        """
        yield b"partial-archive-bytes"
        raise self._error

    def close(self) -> None:
        """Release stream resources (no-op for this synthetic stream)."""
        return


def _install_mid_download_transport_error(monkeypatch: pytest.MonkeyPatch, error: httpx.HTTPError) -> None:
    """Force every ``httpx.Client()`` call to use a transport that fails mid-download.

    Uses ``httpx.MockTransport`` -- httpx's own supported seam for substituting
    the network layer -- so the real ``httpx.Client``/``Response.iter_bytes``
    machinery inside ``ToolInstallWorker._stream_download`` still runs; only
    the socket layer is replaced.

    Args:
        monkeypatch: Pytest monkeypatch fixture used to patch ``httpx.Client``.
        error: The transport error to raise after the response headers are sent.
    """
    real_client_cls = httpx.Client

    def _handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(200, headers={"content-length": "64"}, stream=_MidStreamFailureStream(error))

    def _factory(*_args: object, **_kwargs: object) -> httpx.Client:
        return real_client_cls(transport=httpx.MockTransport(_handler))

    monkeypatch.setattr(httpx, "Client", _factory)


@pytest.mark.usefixtures("qapp")
class TestH30MidDownloadTransportError:
    """H30: httpx transport errors mid-stream must not hang the install worker."""

    @staticmethod
    def test_h30_read_error_mid_download_emits_failure_signal(
        qtbot: QtBot,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A ``ReadError`` raised mid-stream must emit ``install_finished(False, ...)``.

        Pre-fix, ``_install_tool`` only caught ``httpx.TimeoutException`` and
        ``httpx.ConnectError`` around ``_stream_download()``. ``httpx.ReadError``
        is a distinct ``httpx.HTTPError`` subclass raised from inside
        ``response.iter_bytes()`` on a dropped connection; it escaped both that
        except block and ``run()``'s outer ``(RuntimeError, OSError, ValueError)``
        handler, so ``install_finished`` was never emitted and ``qtbot.waitSignal``
        below would time out and fail this test.

        Args:
            qtbot: pytest-qt bot fixture used to wait on Qt signals.
            tmp_path: Pytest temporary directory used as the install target.
            monkeypatch: Pytest monkeypatch fixture used to inject the transport failure.
        """
        _install_mid_download_transport_error(monkeypatch, httpx.ReadError("connection reset by peer"))
        worker = ToolInstallWorker("ghidra", tmp_path / "ghidra")

        recorder = SignalRecorder()
        _: object = worker.install_finished.connect(recorder)

        with qtbot.waitSignal(worker.install_finished, timeout=5000):
            worker.start()

        assert recorder.times_called == 1
        success, message = recorder.calls[0]
        assert success is False
        assert isinstance(message, str)
        assert "download failed" in message.lower()
        assert "connection reset" in message.lower()

    @staticmethod
    def test_h30_remote_protocol_error_mid_download_emits_failure_signal(
        qtbot: QtBot,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A ``RemoteProtocolError`` raised mid-stream is also caught and reported.

        Exercises a second ``httpx.HTTPError`` subclass outside the
        ``TimeoutException``/``ConnectError`` pair to confirm the fix added a
        broad ``except httpx.HTTPError`` fallback -- matching the sibling
        ``_fetch_github_release`` handler -- rather than special-casing a single
        exception type. Pre-fix this error also escapes ``run()`` uncaught and
        ``install_finished`` is never emitted, so ``qtbot.waitSignal`` below
        would time out and fail this test.

        Args:
            qtbot: pytest-qt bot fixture used to wait on Qt signals.
            tmp_path: Pytest temporary directory used as the install target.
            monkeypatch: Pytest monkeypatch fixture used to inject the transport failure.
        """
        _install_mid_download_transport_error(
            monkeypatch,
            httpx.RemoteProtocolError("peer closed connection without sending complete message"),
        )
        worker = ToolInstallWorker("ghidra", tmp_path / "ghidra")

        recorder = SignalRecorder()
        _: object = worker.install_finished.connect(recorder)

        with qtbot.waitSignal(worker.install_finished, timeout=5000):
            worker.start()

        assert recorder.times_called == 1
        success, message = recorder.calls[0]
        assert success is False
        assert isinstance(message, str)
        assert "download failed" in message.lower()


def _make_settings_widget(qapp: QApplication, tmp_path: Path) -> ToolSettingsWidget:
    """Build a real ``ToolSettingsWidget`` rooted at a temp tools directory.

    Args:
        qapp: The shared QApplication fixture.
        tmp_path: Per-test temporary directory used for tool storage and settings.

    Returns:
        ToolSettingsWidget: A live widget for the non-builtin ``ghidra`` tool.
    """
    _ = qapp
    return ToolSettingsWidget(
        "ghidra",
        "Ghidra",
        "Software reverse engineering suite",
        tools_directory=tmp_path / "tools",
        config_path=tmp_path / "tools.json",
    )


class TestM67StatusLabelWordWrap:
    """M67: status_label must wrap long text instead of overflowing the panel."""

    @staticmethod
    def test_m67_status_label_has_word_wrap_enabled(qapp: QApplication, tmp_path: Path) -> None:
        """``status_label`` must have word wrap enabled.

        Pre-fix the label had no ``setWordWrap(True)`` call, so its
        ``minimumSizeHint`` demanded the full single-line width of any status
        message regardless of the panel's fixed width.

        Args:
            qapp: The shared QApplication fixture.
            tmp_path: Pytest temporary directory used for tool settings storage.
        """
        widget = _make_settings_widget(qapp, tmp_path)
        try:
            assert widget.status_label.wordWrap() is True
        finally:
            widget.deleteLater()

    @staticmethod
    def test_m67_long_status_message_wraps_within_fixed_panel_width(
        qapp: QApplication,
        tmp_path: Path,
    ) -> None:
        """A long status message wraps onto multiple lines instead of overflowing.

        Reproduces the fixed-width settings panel (``_SPLIT_RIGHT`` = 570px)
        and drives the real ``_on_status_checked`` slot with a long
        ``Check failed: ...``-style message, matching what
        ``ToolStatusCheckWorker`` sends for an ``OSError``. Pre-fix (word wrap
        disabled), the label's minimum size hint equals the full single-line
        text width, which is far wider than the panel and gets clipped at its
        edge instead of wrapping. Post-fix the label's minimum size hint stays
        small and its rendered geometry wraps to multiple lines within the
        panel width.

        Args:
            qapp: The shared QApplication fixture.
            tmp_path: Pytest temporary directory used for tool settings storage.
        """
        _ = qapp
        widget = _make_settings_widget(qapp, tmp_path)
        container = QWidget()
        container_layout = QVBoxLayout(container)
        container_layout.addWidget(widget)
        container.setFixedWidth(_SPLIT_RIGHT)
        container.resize(_SPLIT_RIGHT, _CONTAINER_TEST_HEIGHT)
        container.show()
        QApplication.processEvents()
        try:
            long_message = (
                "Check failed: [WinError 5] Access is denied while probing a deeply nested "
                "network share path; retry after verifying share permissions and reconnecting "
                "the mapped drive letter"
            )
            fm = widget.status_label.fontMetrics()
            single_line_height = fm.height()
            full_text_width = fm.horizontalAdvance(long_message)
            assert full_text_width > _SPLIT_RIGHT, "test premise: message does not fit on one line at panel width"

            widget._on_status_checked("ghidra", is_available=False, message=long_message)
            QApplication.processEvents()
            container.updateGeometry()
            QApplication.processEvents()

            assert widget.status_label.text() == long_message
            geom = widget.status_label.geometry()
            assert geom.width() <= container.width(), "status label overruns the fixed-width settings panel"
            assert geom.height() > single_line_height * 1.5, "long status message did not wrap onto multiple lines"

            wrapped_hint_width = widget.status_label.minimumSizeHint().width()
            widget.status_label.setWordWrap(False)
            QApplication.processEvents()
            unwrapped_hint_width = widget.status_label.minimumSizeHint().width()
            assert wrapped_hint_width < unwrapped_hint_width, (
                "a word-wrapped label should demand far less minimum width than the single-line layout that caused the pre-fix overflow"
            )
            assert unwrapped_hint_width >= full_text_width - fm.horizontalAdvance(" "), (
                "sanity check: disabling word wrap must reproduce the pre-fix full-width demand"
            )
        finally:
            widget.deleteLater()
            container.deleteLater()


def _make_status_dialog(qapp: QApplication, statuses: dict[str, ToolStatusEntry]) -> ToolStatusDialog:
    """Build a ``ToolStatusDialog`` from a pre-fetched status snapshot.

    Passing ``tool_statuses`` renders the list synchronously via
    ``_populate_from_prefetched`` instead of spawning background
    ``ToolStatusCheckWorker`` threads, keeping the gate deterministic.

    Args:
        qapp: The shared QApplication fixture.
        statuses: Mapping of tool IDs to pre-fetched status entries.

    Returns:
        ToolStatusDialog: A live dialog populated from ``statuses``.
    """
    _ = qapp
    return ToolStatusDialog(tool_statuses=statuses)


class TestM68StatusListTooltips:
    """M68: status list rows must carry a tooltip with the full message text."""

    @staticmethod
    def test_m68_populate_from_prefetched_sets_full_message_tooltips(qapp: QApplication) -> None:
        """Every prefetched row's tooltip must carry the complete, unelided message.

        The list widget's default delegate elides overflowing text
        (``Qt.TextElideMode.ElideRight``); pre-fix, no ``setToolTip()`` call
        existed anywhere on these items, so a truncated row had no way for the
        user to read the rest of a long diagnostic message.

        Args:
            qapp: The shared QApplication fixture.
        """
        long_message = (
            "GitHub API request forbidden (HTTP 403). Download manually from: "
            "https://github.com/NationalSecurityAgency/ghidra/releases/latest"
        )
        statuses: dict[str, ToolStatusEntry] = {
            "ghidra": {"available": False, "path": None, "message": long_message},
            "frida": {"available": True, "path": None, "message": "Frida 16.1.0 available"},
        }
        dialog = _make_status_dialog(qapp, statuses)
        try:
            assert dialog._status_list.count() == 6

            ghidra_item = dialog._status_list.item(0)
            assert ghidra_item is not None
            assert ghidra_item.toolTip() == f"Ghidra - {long_message}"

            fm = dialog._status_list.fontMetrics()
            assert fm.horizontalAdvance(ghidra_item.text()) > _COMPAT_SPLIT_LEFT, (
                "test premise: the row text overflows the fixed-width left panel and would be elided"
            )

            frida_item = dialog._status_list.item(2)
            assert frida_item is not None
            assert frida_item.toolTip() == "Frida - Frida 16.1.0 available"
        finally:
            dialog.deleteLater()

    @staticmethod
    def test_m68_status_unknown_fallback_item_has_tooltip(qapp: QApplication) -> None:
        """A tool missing from the prefetched snapshot still gets a tooltip.

        Covers the ``"Status unknown"`` fallback branch, which pre-fix also
        had no ``setToolTip()`` call.

        Args:
            qapp: The shared QApplication fixture.
        """
        statuses: dict[str, ToolStatusEntry] = {
            "ghidra": {"available": True, "path": "C:/tools/ghidra", "message": "Ghidra installed"},
        }
        dialog = _make_status_dialog(qapp, statuses)
        try:
            x64dbg_item = dialog._status_list.item(1)
            assert x64dbg_item is not None
            assert x64dbg_item.text() == "... x64dbg - Status unknown"
            assert x64dbg_item.toolTip() == "x64dbg - Status unknown"
        finally:
            dialog.deleteLater()

    @staticmethod
    def test_m68_on_tool_status_received_updates_tooltip_with_full_message(qapp: QApplication) -> None:
        """A live status update replaces the row's tooltip with the new full message.

        Drives ``_on_tool_status_received`` -- the slot invoked when a real
        ``ToolStatusCheckWorker`` finishes -- directly, so the tooltip must
        always track the current, possibly-long diagnostic text rather than
        staying stuck on the initial ``"Checking..."`` placeholder tooltip.

        Args:
            qapp: The shared QApplication fixture.
        """
        statuses: dict[str, ToolStatusEntry] = {
            "ghidra": {"available": False, "path": None, "message": "Checking..."},
        }
        dialog = _make_status_dialog(qapp, statuses)
        try:
            updated_message = (
                "analyzeHeadless not found in installation; expected support/analyzeHeadless(.bat) "
                "under a ghidra_* subdirectory of the configured installation path"
            )
            dialog._on_tool_status_received("ghidra", is_available=False, message=updated_message)

            item = dialog._status_list.item(0)
            assert item is not None
            assert item.text() == f"✗  Ghidra - {updated_message}"
            assert item.toolTip() == f"Ghidra - {updated_message}"

            fm = dialog._status_list.fontMetrics()
            assert fm.horizontalAdvance(item.text()) > _COMPAT_SPLIT_LEFT, (
                "test premise: the updated row text overflows the fixed-width left panel"
            )
        finally:
            dialog.deleteLater()
