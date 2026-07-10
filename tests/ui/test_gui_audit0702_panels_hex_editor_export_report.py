# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""GUI audit regression gate for ``intellicrack.ui.panels.hex_editor.export_report``.

Covers the 2026-07-02 audit finding H4: ``_on_export_annotated_html`` and
``_on_export_annotated_pdf`` called the blocking ``run_bridge_coroutine``
directly from the Qt GUI thread, freezing the whole application (including
window repaint) for the full duration of rendering an annotated HTML/PDF
report -- a potentially huge operation since the range dialog pre-fills the
end offset with the entire document length.

The fix replaced the blocking call with ``run_bridge_coroutine_logged``,
splitting each export into a dispatch step (``_on_export_annotated_html`` /
``_on_export_annotated_pdf``) and success/error callbacks
(``_on_export_annotated_html_success`` / ``_on_export_annotated_html_error``
and the PDF equivalents) invoked once the bridge round trip completes on a
background ``BridgeCallWorker`` thread.

Every test below fails against the pre-fix module: it imported the blocking
``run_bridge_coroutine`` (not ``run_bridge_coroutine_logged``), so
monkeypatching the post-fix dispatcher name raises ``AttributeError``, and
the pre-fix handlers wrote the export file and showed the result dialog
synchronously inline rather than from a callback -- so assertions that no
file exists immediately after dispatch, or that the GUI-thread call returns
well before a slow bridge coroutine completes, would fail.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

import pytest
from PyQt6.QtWidgets import QDialog, QMessageBox, QWidget

from intellicrack.ui.panels.hex_editor import export_report as export_report_module
from intellicrack.ui.panels.hex_editor.export_report import ExportReportMixin


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Iterator

    from PyQt6.QtWidgets import QApplication

    from intellicrack.bridges.hex_editor import HexEditorBridge


pytestmark = pytest.mark.usefixtures("qapp")

_BRIDGE_DELAY_S: Final[float] = 0.4
_ELAPSED_THRESHOLD_S: Final[float] = 0.15
_POLL_INTERVAL_S: Final[float] = 0.01
_MAX_WAIT_S: Final[float] = 5.0


class _FakeDocument:
    """Minimal document stand-in exposing only the ``length()`` the mixin reads."""

    def __init__(self, length: int) -> None:
        """Store the reported document length.

        Args:
            length: Length in bytes to report from :meth:`length`.
        """
        self._length = length

    def length(self) -> int:
        """Return the configured document length.

        Returns:
            int: The document length in bytes.
        """
        return self._length


class _FakeExportBridge:
    """Fake hex-editor bridge exposing real coroutine export methods."""

    html_calls: list[tuple[int, int, int]]
    pdf_calls: list[tuple[str, int, int, int]]

    def __init__(
        self,
        *,
        html_error_message: str | None = None,
        pdf_error_message: str | None = None,
    ) -> None:
        """Initialise the fake bridge, optionally configured to fail.

        Args:
            html_error_message: When set, ``export_annotated_html`` raises
                ``OSError(html_error_message)`` instead of returning HTML.
            pdf_error_message: When set, ``export_annotated_pdf`` raises
                ``OSError(pdf_error_message)`` instead of writing a PDF.
        """
        self.html_calls: list[tuple[int, int, int]] = []
        self.pdf_calls: list[tuple[str, int, int, int]] = []
        self._html_error_message = html_error_message
        self._pdf_error_message = pdf_error_message

    async def export_annotated_html(self, start: int, end: int, bytes_per_row: int) -> str:
        """Return a deterministic HTML payload derived from the requested range.

        Args:
            start: Start offset requested by the caller.
            end: End offset requested by the caller.
            bytes_per_row: Bytes-per-row layout requested by the caller.

        Returns:
            str: A deterministic HTML string encoding the requested range.

        Raises:
            OSError: When constructed with ``html_error_message``.
        """
        self.html_calls.append((start, end, bytes_per_row))
        if self._html_error_message is not None:
            raise OSError(self._html_error_message)
        return f"<html>{start}:{end}:{bytes_per_row}</html>"

    async def export_annotated_pdf(self, output_path: str, start: int, end: int, bytes_per_row: int) -> str:
        """Write a deterministic PDF payload to ``output_path`` and return it.

        Mirrors the real ``HexEditorBridge.export_annotated_pdf`` contract of
        writing the file directly on the bridge side rather than returning
        bytes for the caller to write.

        Args:
            output_path: Filesystem path to write the PDF payload to.
            start: Start offset requested by the caller.
            end: End offset requested by the caller.
            bytes_per_row: Bytes-per-row layout requested by the caller.

        Returns:
            str: The path the payload was written to.

        Raises:
            OSError: When constructed with ``pdf_error_message``.
        """
        self.pdf_calls.append((output_path, start, end, bytes_per_row))
        if self._pdf_error_message is not None:
            raise OSError(self._pdf_error_message)
        await asyncio.to_thread(Path(output_path).write_bytes, f"PDF:{start}:{end}:{bytes_per_row}".encode())
        return output_path


class _SlowFakeBridge:
    """Fake bridge whose HTML export coroutine sleeps to simulate slow rendering."""

    def __init__(self, html: str, delay_s: float) -> None:
        """Configure the payload and artificial rendering delay.

        Args:
            html: HTML string returned once the simulated render completes.
            delay_s: Seconds the coroutine sleeps before returning.
        """
        self._html = html
        self._delay_s = delay_s
        self.completed = False

    async def export_annotated_html(self, start: int, end: int, bytes_per_row: int) -> str:
        """Sleep for the configured delay, then return the configured HTML.

        Args:
            start: Start offset requested by the caller (unused).
            end: End offset requested by the caller (unused).
            bytes_per_row: Bytes-per-row layout requested by the caller (unused).

        Returns:
            str: The configured HTML payload.
        """
        del start, end, bytes_per_row
        await asyncio.sleep(self._delay_s)
        self.completed = True
        return self._html


class _ExportHost(ExportReportMixin, QWidget):
    """Minimal QWidget host exposing only the state ``ExportReportMixin`` reads.

    Wires ``document`` and ``_bridge`` directly so the mixin's export
    handlers can run without constructing the full ``HexEditorPanel``. Being
    a real ``QWidget`` (rather than a plain object) matters for the
    end-to-end dispatch test: the mixin's success/error callbacks are bound
    methods of this host, and Qt only queues a signal emission back onto the
    receiver's own thread when the receiver is a real ``QObject`` -- so this
    class must be a genuine widget for the cross-thread marshalling gate to
    be meaningful.
    """

    def __init__(self, document: _FakeDocument, bridge: object) -> None:
        """Initialise the host with a document and bridge.

        Args:
            document: Document stand-in exposing ``length()``.
            bridge: Bridge stand-in exposing the async export coroutines.
        """
        super().__init__()
        self.document = document
        self._bridge = cast("HexEditorBridge", bridge)
        self._pending_html_export_path: str | None = None
        self._pending_pdf_export_path: str | None = None


@pytest.fixture(autouse=True)
def _accept_range_dialog(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force ``AnnotatedExportRangeDialog.exec`` to accept with its default range.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
    """
    monkeypatch.setattr(
        export_report_module.AnnotatedExportRangeDialog,
        "exec",
        lambda _self: QDialog.DialogCode.Accepted,
    )


@pytest.fixture(autouse=True)
def _non_blocking_result_dialogs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the export result dialogs from freezing the offscreen event loop.

    The export success and error callbacks report their outcome through
    ``show_info`` / ``show_warning``, which open modal ``QMessageBox`` dialogs.
    Driven synchronously by these tests, such a modal starts a nested event
    loop that never returns under the offscreen platform (there is no user to
    dismiss it), hanging the test. Replacing both with non-blocking stand-ins
    lets the callbacks run to completion and their observable side effects
    (file written, pending state reset) be asserted without a real dialog.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
    """

    def _stub_dialog(parent: object, title: str, text: str, *_args: object, **_kwargs: object) -> QMessageBox.StandardButton:
        del parent, title, text
        return QMessageBox.StandardButton.Ok

    monkeypatch.setattr(QMessageBox, "information", _stub_dialog)
    monkeypatch.setattr(QMessageBox, "warning", _stub_dialog)


@pytest.fixture
def make_host() -> Iterator[Callable[[int, object], _ExportHost]]:
    """Provide a factory for ``_ExportHost`` instances with automatic cleanup.

    Yields:
        Callable[[int, object], _ExportHost]: Factory taking a document
            length and a bridge stand-in, returning a wired host widget.
    """
    created: list[_ExportHost] = []

    def _factory(doc_length: int, bridge: object) -> _ExportHost:
        """Build and register a host widget for later cleanup.

        Args:
            doc_length: Document length reported to the range dialog.
            bridge: Bridge stand-in assigned to ``host._bridge``.

        Returns:
            _ExportHost: The constructed host widget.
        """
        host = _ExportHost(_FakeDocument(doc_length), bridge)
        created.append(host)
        return host

    yield _factory
    for host in created:
        host.deleteLater()


def _drive_sync(
    coro: Coroutine[object, object, object],
    on_success: Callable[[object], None] | None = None,
    on_error: Callable[[object], None] | None = None,
    parent: object = None,
    **_context: object,
) -> None:
    """Synchronously drive a bridge coroutine to deterministic completion.

    Mirrors the production dispatcher's success/error contract (a completed
    coroutine invokes ``on_success`` with its result; a caught exception
    invokes ``on_error``) without requiring a background thread, so
    assertions can run immediately after the call returns.

    Args:
        coro: Coroutine produced by the bridge call.
        on_success: Success callback invoked with the coroutine's result.
        on_error: Error callback invoked with the raised exception.
        parent: Unused Qt parent argument, accepted for signature parity.
        **_context: Remaining structured-logging keyword arguments, unused.
    """
    del parent, _context
    loop = asyncio.new_event_loop()
    try:
        result = loop.run_until_complete(coro)
    except (OSError, RuntimeError, ValueError) as exc:
        loop.close()
        if on_error is not None:
            on_error(exc)
        return
    loop.close()
    if on_success is not None:
        on_success(result)


def test_h4_blocking_bridge_helper_no_longer_used() -> None:
    """H4: the blocking ``run_bridge_coroutine`` helper is no longer imported.

    Pre-fix, ``export_report.py`` imported ``run_bridge_coroutine`` (the
    blocking variant) and called it directly from the two GUI-thread export
    handlers. Post-fix it imports only ``run_bridge_coroutine_logged``.
    """
    assert not hasattr(export_report_module, "run_bridge_coroutine"), (
        "export_report.py must not reference the blocking run_bridge_coroutine helper"
    )
    assert hasattr(export_report_module, "run_bridge_coroutine_logged"), (
        "export_report.py must dispatch exports through run_bridge_coroutine_logged"
    )


def test_h4_export_html_dispatches_via_logged_worker_not_inline(
    make_host: Callable[[int, object], _ExportHost],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """H4: exporting annotated HTML dispatches through the async worker, not inline.

    Pre-fix, ``_on_export_annotated_html`` called the blocking
    ``run_bridge_coroutine`` and wrote the output file inline before
    returning. Post-fix it hands a real coroutine to
    ``run_bridge_coroutine_logged`` and returns without waiting for a
    result: with a dispatcher that records the call but never invokes
    ``on_success``, the coroutine must never have run (so the bridge's call
    log stays empty) and the output file must not exist.

    Args:
        make_host: Factory fixture building a wired ``_ExportHost``.
        tmp_path: Pytest temporary directory fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    target = tmp_path / "report.html"
    monkeypatch.setattr(
        export_report_module.QFileDialog,
        "getSaveFileName",
        staticmethod(lambda *_a, **_k: (str(target), "HTML Files (*.html)")),
    )

    captured_events: list[str] = []
    captured_contexts: list[dict[str, object]] = []

    def _capture_only(
        coro: Coroutine[object, object, object],
        on_success: Callable[[object], None] | None = None,
        on_error: Callable[[object], None] | None = None,
        parent: object = None,
        *,
        event: str,
        logger: object,
        **context: object,
    ) -> None:
        """Record the dispatch call and close the coroutine without running it.

        Args:
            coro: Coroutine handed to the dispatcher; verified to be a real
                coroutine, then closed unawaited.
            on_success: Unused success callback.
            on_error: Unused error callback.
            parent: Unused Qt parent argument.
            event: Structured-logging event name to record.
            logger: Unused bound logger.
            **context: Remaining structured-logging keyword arguments.
        """
        del on_success, on_error, parent, logger
        assert asyncio.iscoroutine(coro), "run_bridge_coroutine_logged must receive a real coroutine"
        captured_events.append(event)
        captured_contexts.append(dict(context))
        coro.close()

    monkeypatch.setattr(export_report_module, "run_bridge_coroutine_logged", _capture_only)

    bridge = _FakeExportBridge()
    host = make_host(256, bridge)

    host._on_export_annotated_html()

    assert captured_events == ["hex_editor_export_annotated_html"], "the html export must dispatch exactly once"
    assert captured_contexts[0]["path"] == str(target)
    assert captured_contexts[0]["start"] == 0
    assert captured_contexts[0]["end"] == 256
    assert captured_contexts[0]["bytes_per_row"] == 16
    assert host._pending_html_export_path == str(target), "dispatch must record the pending path before returning"
    assert not bridge.html_calls, "the coroutine must be handed off, not executed inline on the GUI thread"
    assert not target.exists(), "no file may be written until the async success callback fires"


def test_h4_export_html_call_site_returns_before_slow_bridge_completes(
    qapp: QApplication,
    make_host: Callable[[int, object], _ExportHost],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """H4: the GUI-thread call returns immediately even while the bridge is still rendering.

    This is the direct end-to-end regression gate for H4, using the real
    (unmocked) ``run_bridge_coroutine_logged`` dispatcher and a genuine
    background ``BridgeCallWorker`` thread. The fake bridge sleeps for
    ``_BRIDGE_DELAY_S`` inside its coroutine to simulate rendering a large
    annotated range. Pre-fix, ``_on_export_annotated_html`` blocked on
    ``run_bridge_coroutine(...).result()`` for the full sleep duration
    before returning; post-fix it must return almost immediately, and the
    output file must only appear once the background round trip completes
    and its result is marshalled back onto this (the widget's) thread.

    Args:
        qapp: Session QApplication fixture, used to pump the event loop so
            the queued cross-thread callback can run.
        make_host: Factory fixture building a wired ``_ExportHost``.
        tmp_path: Pytest temporary directory fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    target = tmp_path / "slow_report.html"
    monkeypatch.setattr(
        export_report_module.QFileDialog,
        "getSaveFileName",
        staticmethod(lambda *_a, **_k: (str(target), "HTML Files (*.html)")),
    )

    bridge = _SlowFakeBridge("<html>slow</html>", _BRIDGE_DELAY_S)
    host = make_host(64, bridge)

    started = time.monotonic()
    host._on_export_annotated_html()
    elapsed = time.monotonic() - started

    assert elapsed < _ELAPSED_THRESHOLD_S, (
        f"_on_export_annotated_html blocked the calling thread for {elapsed:.3f}s "
        f"(bridge delay was {_BRIDGE_DELAY_S}s); it must dispatch through "
        "run_bridge_coroutine_logged and return without waiting for the result"
    )
    assert not bridge.completed, "the bridge coroutine must still be running shortly after dispatch returns"
    assert not target.exists(), "the file must not exist yet -- the write only happens once the async callback runs"

    deadline = time.monotonic() + _MAX_WAIT_S
    while not target.exists() and time.monotonic() < deadline:
        qapp.processEvents()
        time.sleep(_POLL_INTERVAL_S)

    assert bridge.completed, "the background bridge coroutine never ran to completion"
    assert target.exists(), "the async round trip never completed and wrote the file"
    assert target.read_text(encoding="utf-8") == "<html>slow</html>"
    assert host._pending_html_export_path is None, "pending path bookkeeping must be cleared once the write completes"


def test_h4_export_html_success_callback_writes_real_bridge_output(
    make_host: Callable[[int, object], _ExportHost],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """H4: the async success callback writes the bridge's genuine rendered HTML.

    Drives the coroutine handed to ``run_bridge_coroutine_logged`` to real
    completion and asserts the HTML string produced by actually executing
    the bridge coroutine ends up on disk, with the correct requested range
    forwarded, and pending-path bookkeeping cleared.

    Args:
        make_host: Factory fixture building a wired ``_ExportHost``.
        tmp_path: Pytest temporary directory fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    target = tmp_path / "report.html"
    monkeypatch.setattr(
        export_report_module.QFileDialog,
        "getSaveFileName",
        staticmethod(lambda *_a, **_k: (str(target), "HTML Files (*.html)")),
    )
    monkeypatch.setattr(export_report_module, "run_bridge_coroutine_logged", _drive_sync)

    bridge = _FakeExportBridge()
    host = make_host(256, bridge)

    host._on_export_annotated_html()

    assert bridge.html_calls == [(0, 256, 16)], "the default dialog range must be forwarded to the bridge"
    assert target.read_text(encoding="utf-8") == "<html>0:256:16</html>"
    assert host._pending_html_export_path is None


def test_h4_export_html_error_callback_reports_failure_and_resets_pending_state(
    make_host: Callable[[int, object], _ExportHost],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """H4: a bridge failure surfaces via the async error callback, not a raised exception.

    Args:
        make_host: Factory fixture building a wired ``_ExportHost``.
        tmp_path: Pytest temporary directory fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    target = tmp_path / "report.html"
    monkeypatch.setattr(
        export_report_module.QFileDialog,
        "getSaveFileName",
        staticmethod(lambda *_a, **_k: (str(target), "HTML Files (*.html)")),
    )
    monkeypatch.setattr(export_report_module, "run_bridge_coroutine_logged", _drive_sync)

    warnings: list[tuple[object, str, str]] = []
    monkeypatch.setattr(
        export_report_module,
        "show_warning",
        lambda parent, title, message: warnings.append((parent, title, message)),
    )

    bridge = _FakeExportBridge(html_error_message="render backend unavailable")
    host = make_host(256, bridge)

    host._on_export_annotated_html()

    assert not target.exists(), "a failed export must not leave a partial file behind"
    assert len(warnings) == 1, "exactly one failure warning must be shown"
    _parent, title, message = warnings[0]
    assert title == "Export Annotated HTML"
    assert str(target) in message
    assert "render backend unavailable" in message
    assert host._pending_html_export_path is None, "pending path must be cleared even on failure"


def test_h4_export_pdf_dispatches_via_logged_worker_not_inline(
    make_host: Callable[[int, object], _ExportHost],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """H4: exporting an annotated PDF dispatches through the async worker, not inline.

    Mirrors the HTML dispatch gate for the PDF export path (the second call
    site of the same defect, at ``export_report.py:230`` pre-fix).

    Args:
        make_host: Factory fixture building a wired ``_ExportHost``.
        tmp_path: Pytest temporary directory fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    target = tmp_path / "report.pdf"
    monkeypatch.setattr(
        export_report_module.QFileDialog,
        "getSaveFileName",
        staticmethod(lambda *_a, **_k: (str(target), "PDF Files (*.pdf)")),
    )

    captured_events: list[str] = []
    captured_contexts: list[dict[str, object]] = []

    def _capture_only(
        coro: Coroutine[object, object, object],
        on_success: Callable[[object], None] | None = None,
        on_error: Callable[[object], None] | None = None,
        parent: object = None,
        *,
        event: str,
        logger: object,
        **context: object,
    ) -> None:
        """Record the dispatch call and close the coroutine without running it.

        Args:
            coro: Coroutine handed to the dispatcher; verified to be a real
                coroutine, then closed unawaited.
            on_success: Unused success callback.
            on_error: Unused error callback.
            parent: Unused Qt parent argument.
            event: Structured-logging event name to record.
            logger: Unused bound logger.
            **context: Remaining structured-logging keyword arguments.
        """
        del on_success, on_error, parent, logger
        assert asyncio.iscoroutine(coro), "run_bridge_coroutine_logged must receive a real coroutine"
        captured_events.append(event)
        captured_contexts.append(dict(context))
        coro.close()

    monkeypatch.setattr(export_report_module, "run_bridge_coroutine_logged", _capture_only)

    bridge = _FakeExportBridge()
    host = make_host(256, bridge)

    host._on_export_annotated_pdf()

    assert captured_events == ["hex_editor_export_annotated_pdf"], "the pdf export must dispatch exactly once"
    assert captured_contexts[0]["path"] == str(target)
    assert captured_contexts[0]["start"] == 0
    assert captured_contexts[0]["end"] == 256
    assert captured_contexts[0]["bytes_per_row"] == 16
    assert host._pending_pdf_export_path == str(target), "dispatch must record the pending path before returning"
    assert not bridge.pdf_calls, "the coroutine must be handed off, not executed inline on the GUI thread"
    assert not target.exists(), "no file may be written until the async success callback fires"


def test_h4_export_pdf_success_callback_confirms_bridge_written_path(
    make_host: Callable[[int, object], _ExportHost],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """H4: the async success callback confirms the path the bridge itself wrote.

    The bridge writes PDF bytes directly to ``output_path`` inside the
    coroutine (mirroring the real ``HexEditorBridge.export_annotated_pdf``
    contract); the success handler must not attempt a second write and must
    only confirm the returned path and clear pending-path bookkeeping.

    Args:
        make_host: Factory fixture building a wired ``_ExportHost``.
        tmp_path: Pytest temporary directory fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    target = tmp_path / "report.pdf"
    monkeypatch.setattr(
        export_report_module.QFileDialog,
        "getSaveFileName",
        staticmethod(lambda *_a, **_k: (str(target), "PDF Files (*.pdf)")),
    )
    monkeypatch.setattr(export_report_module, "run_bridge_coroutine_logged", _drive_sync)

    infos: list[tuple[object, str, str]] = []
    monkeypatch.setattr(
        export_report_module,
        "show_info",
        lambda parent, title, message: infos.append((parent, title, message)),
    )

    bridge = _FakeExportBridge()
    host = make_host(256, bridge)

    host._on_export_annotated_pdf()

    assert bridge.pdf_calls == [(str(target), 0, 256, 16)], "the default dialog range must be forwarded to the bridge"
    assert target.read_bytes() == b"PDF:0:256:16"
    assert host._pending_pdf_export_path is None
    assert len(infos) == 1
    _parent, title, message = infos[0]
    assert title == "Export Annotated PDF"
    assert str(target) in message


def test_h4_export_pdf_error_callback_reports_failure_and_resets_pending_state(
    make_host: Callable[[int, object], _ExportHost],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """H4: a PDF bridge failure surfaces via the async error callback, not a raised exception.

    Args:
        make_host: Factory fixture building a wired ``_ExportHost``.
        tmp_path: Pytest temporary directory fixture.
        monkeypatch: Pytest monkeypatch fixture.
    """
    target = tmp_path / "report.pdf"
    monkeypatch.setattr(
        export_report_module.QFileDialog,
        "getSaveFileName",
        staticmethod(lambda *_a, **_k: (str(target), "PDF Files (*.pdf)")),
    )
    monkeypatch.setattr(export_report_module, "run_bridge_coroutine_logged", _drive_sync)

    warnings: list[tuple[object, str, str]] = []
    monkeypatch.setattr(
        export_report_module,
        "show_warning",
        lambda parent, title, message: warnings.append((parent, title, message)),
    )

    bridge = _FakeExportBridge(pdf_error_message="disk full")
    host = make_host(256, bridge)

    host._on_export_annotated_pdf()

    assert not target.exists(), "a failed export must not leave a partial file behind"
    assert len(warnings) == 1, "exactly one failure warning must be shown"
    _parent, title, message = warnings[0]
    assert title == "Export Annotated PDF"
    assert str(target) in message
    assert "disk full" in message
    assert host._pending_pdf_export_path is None, "pending path must be cleared even on failure"
