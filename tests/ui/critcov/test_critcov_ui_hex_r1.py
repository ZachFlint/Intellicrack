# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Second-pass coverage for the hex editor panels, the session manager and the tool configuration dialog.

Every test drives production code with real objects: real mixin hosts built on real Qt widgets, a genuine ``HexDocument``, a real
``HexEditorBridge``, signature databases written under ``tmp_path`` and loopback HTTP servers from ``tests/_helpers``. Expected values are
derived from byte arithmetic, the file layout of the repository, or the documented message contracts, not from the code under test.
"""

from __future__ import annotations

import io
import json
import socket
import tempfile
import types
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, cast

import intellicrack_hexcore
import pytest
from PyQt6.QtGui import QTextDocument
from PyQt6.QtWidgets import QFileDialog, QLabel, QTreeWidget, QVBoxLayout, QWidget

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.core.hexpat import PatternRegistry
from intellicrack.ui.panels.async_bridge import GenericCallableWorker, drain_bridge_workers, drain_bridge_workers_for
from intellicrack.ui.panels.hex_editor import scripting as scripting_module
from intellicrack.ui.panels.hex_editor.comparison import ComparisonMixin
from intellicrack.ui.panels.hex_editor.pattern_editor import PatternEditorMixin
from intellicrack.ui.panels.hex_editor.scripting import execute_script
from intellicrack.ui.panels.hex_editor.signatures import execute_signature_scan
from intellicrack.ui.session_manager import SessionManagerDialog
from intellicrack.ui.tool_config import ToolInstallWorker
from tests._helpers.scripted_http_server import (
    ScriptedHttpServer as RouteServer,
    json_response,
)
from tests._helpers.stalling_http import StallingServer
from tests.ui.conftest import SignalRecorder


if TYPE_CHECKING:
    from collections.abc import Callable, Generator

    from PyQt6.QtCore import pyqtBoundSignal
    from pytestqt.qtbot import QtBot


pytestmark = pytest.mark.usefixtures("qapp")


_PythonSyntaxHighlighter: Any = getattr(scripting_module, "_PythonSyntaxHighlighter")

_WAIT_MS: int = 20_000
_API_PATH: str = "/repos/demo/releases/latest"
_PROXY_VARIABLES: tuple[str, ...] = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")
_DATA_A: bytes = b"\x00" * 16 + b"\xaa" * 8 + b"\x00" * 16
_DATA_B: bytes = b"\x00" * 16 + b"\xbb" * 8 + b"\x00" * 16


class _PatternHost(PatternEditorMixin, QWidget):
    """Concrete widget host exposing the pattern editor mixin's slots, with no pane built."""

    def __init__(self) -> None:
        """Create a host whose pattern editor panes are all absent."""
        super().__init__()
        self.document = None
        self.state_holder = None
        self._document = None
        self._hex_widget = None
        self._pattern_dsl_editor = None
        self._pattern_json_preview = None
        self._pattern_library_tree = None
        self._pattern_status_label = None
        self._pattern_registry = None
        self._compiled_json = ""

    def seed_compiled_json(self, text: str) -> None:
        """Seed the compiled template text.

        Args:
            text: JSON text to hold as the compiled template.
        """
        self._compiled_json = text

    @property
    def compiled_json(self) -> str:
        """The compiled template text the mixin currently holds.

        Returns:
            str: The compiled JSON, empty when nothing is compiled.
        """
        return self._compiled_json

    @property
    def has_status_label(self) -> bool:
        """Whether a status label exists.

        Returns:
            bool: ``True`` when the mixin holds a status label.
        """
        return self._pattern_status_label is not None

    def build_library_tree(self) -> QTreeWidget:
        """Create the library tree the community patterns are listed in.

        Returns:
            QTreeWidget: The new, empty tree.
        """
        tree = QTreeWidget(self)
        self._pattern_library_tree = tree
        return tree

    def do_open(self) -> None:
        """Invoke the slot the Open button triggers."""
        self._on_pattern_open()

    def populate_hexpat_entries(self) -> None:
        """Invoke the community pattern population."""
        self._populate_hexpat_library_entries()


class _ComparisonHost(ComparisonMixin, QWidget):
    """Concrete widget host exposing the comparison mixin's slots."""

    _bridge: HexEditorBridge | None

    def __init__(self, document: object | None, bridge: HexEditorBridge | None) -> None:
        """Create a host with no comparison tab built yet.

        Args:
            document: Document the comparison belongs to.
            bridge: Hex editor bridge the diff runs through.
        """
        super().__init__()
        self.document = document
        self.file_path = None
        self._hex_widget = None
        self._bridge = bridge
        self._diff_results_tree = None
        self._diff_summary_label = None
        self._diff_worker = None
        self._diff_temp_path = None

    def build_tab(self) -> None:
        """Build the real comparison tab and place it inside the host."""
        container = self._create_comparison_tab()
        QVBoxLayout(self).addWidget(container)

    def drop_label(self) -> None:
        """Forget the summary label so the slots see it as not yet created."""
        self._diff_summary_label = None

    def compare(self) -> None:
        """Invoke the slot the Compare button triggers."""
        self._on_compare()

    @property
    def worker(self) -> GenericCallableWorker | None:
        """The worker the Compare slot started.

        Returns:
            GenericCallableWorker | None: The worker, or ``None`` when nothing was started.
        """
        return self._diff_worker

    @property
    def label(self) -> QLabel | None:
        """The summary label.

        Returns:
            QLabel | None: The label, or ``None`` after it was dropped.
        """
        return self._diff_summary_label

    @property
    def tree(self) -> QTreeWidget:
        """The results tree built by the tab.

        Returns:
            QTreeWidget: The tree widget.
        """
        tree = self._diff_results_tree
        assert tree is not None
        return tree

    def rows(self) -> list[tuple[str, str, str, str]]:
        """Return the four visible cells of every top-level row.

        Returns:
            list[tuple[str, str, str, str]]: Offset, length, type and details text per row.
        """
        collected: list[tuple[str, str, str, str]] = []
        for index in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(index)
            assert item is not None
            collected.append((item.text(0), item.text(1), item.text(2), item.text(3)))
        return collected


@dataclass(frozen=True)
class _Outcome:
    """Signals recorded while an install worker ran.

    Attributes:
        progress: Every percentage emitted through ``progress``, in order.
        finished: Every ``(success, message)`` pair emitted through ``install_finished``, in order.
    """

    progress: list[int]
    finished: list[tuple[bool, str]]


def _file_picker(path: str) -> Callable[..., tuple[str, str]]:
    """Build a file-dialog replacement that picks a fixed path.

    Args:
        path: Path the picker reports as chosen.

    Returns:
        Callable[..., tuple[str, str]]: Function with the static dialog's result shape.
    """

    def _pick(*_args: object, **_kwargs: object) -> tuple[str, str]:
        """Report the fixed path as the user's choice.

        Args:
            *_args: Ignored dialog arguments.
            **_kwargs: Ignored dialog keyword arguments.

        Returns:
            tuple[str, str]: The path and an empty filter.
        """
        return (path, "")

    return _pick


def _call(obj: object, name: str, *args: object) -> object:
    """Call a private method by name.

    Args:
        obj: Object or class that owns the method.
        name: Method name.
        *args: Positional arguments for the method.

    Returns:
        object: Whatever the method returned.
    """
    method: object = getattr(obj, name)
    return cast("Callable[..., object]", method)(*args)


def _record(signal: pyqtBoundSignal) -> SignalRecorder:
    """Connect a recorder to a signal.

    Args:
        signal: The bound signal to observe.

    Returns:
        SignalRecorder: Recorder that stores the arguments of each emission.
    """
    recorder = SignalRecorder()
    _ = signal.connect(recorder)
    return recorder


def _worker_class(urls: dict[str, dict[str, str]]) -> type[ToolInstallWorker]:
    """Build an installer subclass whose download table points at test servers.

    Args:
        urls: Tool id mapped to its download entry.

    Returns:
        type[ToolInstallWorker]: Subclass of the real installer using ``urls``.
    """

    class _ConfiguredInstallWorker(ToolInstallWorker):
        """Real installer worker with a test download table."""

        DOWNLOAD_URLS: ClassVar[dict[str, dict[str, str]]] = urls

    return _ConfiguredInstallWorker


def _run_install(worker: ToolInstallWorker) -> _Outcome:
    """Run an install worker on the calling thread and collect its signals.

    Args:
        worker: The worker to run.

    Returns:
        _Outcome: Progress percentages and finished messages in emission order.
    """
    progress = _record(worker.progress)
    finished = _record(worker.install_finished)
    worker.run()
    return _Outcome(
        progress=[int(call[0]) for call in progress.calls],
        finished=[(bool(call[0]), str(call[1])) for call in finished.calls],
    )


@pytest.fixture
def sandbox_tempdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect the per-script sandbox directories into the test's temporary directory.

    Args:
        tmp_path: Per-test temporary directory.
        monkeypatch: pytest monkeypatch fixture.

    Returns:
        Path: The directory under which sandbox directories are created.
    """
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    return tmp_path


@pytest.fixture
def direct_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make HTTP clients in this test connect straight to loopback, ignoring any proxy settings.

    Args:
        monkeypatch: Fixture that restores the environment.
    """
    for name in _PROXY_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")


@pytest.fixture
def comparison_host(qtbot: QtBot) -> Generator[_ComparisonHost]:
    """Create a comparison host over a real document and bridge, joining its workers on teardown.

    Args:
        qtbot: pytest-qt fixture that owns the host.

    Yields:
        _ComparisonHost: Host with the comparison tab built.
    """
    document = intellicrack_hexcore.HexDocument.open_bytes(_DATA_A)
    instance = _ComparisonHost(document, HexEditorBridge())
    qtbot.addWidget(instance)
    instance.build_tab()
    try:
        yield instance
    finally:
        drain_bridge_workers_for(instance)
        drain_bridge_workers()


def _closed_port() -> int:
    """Find a loopback TCP port nothing is listening on.

    Returns:
        int: A port that refuses connections.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def test_highlighter_ignores_a_block_without_text() -> None:
    """A ``None`` block is skipped without raising and leaves the document text alone."""
    document = QTextDocument()
    document.setPlainText("def f(): return 1")
    highlighter = _PythonSyntaxHighlighter(document)
    assert highlighter.highlightBlock(None) is None
    assert document.toPlainText() == "def f(): return 1"


@pytest.mark.usefixtures("sandbox_tempdir")
def test_print_to_a_sink_without_a_flush_hook_still_writes() -> None:
    """``flush=True`` with a sink that only has ``write`` writes the text and raises nothing."""
    buffer = io.StringIO()
    handles: Any = types.SimpleNamespace(plain=types.SimpleNamespace(write=buffer.write))
    result = execute_script("print('a', 'b', file=doc.plain, flush=True)", handles)
    assert result["error"] is None
    assert buffer.getvalue() == "a b\n"


def test_open_of_a_missing_pattern_without_a_status_label_changes_nothing(
    qtbot: QtBot,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A pattern file that cannot be read leaves the compiled template alone, even with no status label to update.

    Args:
        qtbot: pytest-qt fixture that owns the host.
        monkeypatch: pytest monkeypatch fixture used to answer the file dialog.
        tmp_path: Per-test temporary directory in which the chosen file does not exist.
    """
    host = _PatternHost()
    qtbot.addWidget(host)
    host.seed_compiled_json("kept-json")
    missing = tmp_path / "gone.hexpat"
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _file_picker(str(missing)))
    host.do_open()
    assert host.compiled_json == "kept-json"
    assert not host.has_status_label
    assert not missing.exists()


def test_default_community_pattern_registry_lists_the_vendored_patterns(qtbot: QtBot) -> None:
    """With no registry preset, the library lists the patterns shipped in ``vendor/community-patterns`` under one section.

    The expected categories come from a registry built directly over the repository's vendored pattern directory.

    Args:
        qtbot: pytest-qt fixture that owns the host.
    """
    patterns_dir = Path(__file__).resolve().parents[3] / "vendor" / "community-patterns" / "patterns"
    assert patterns_dir.is_dir()
    expected_categories = list(PatternRegistry([patterns_dir]).list_by_category())
    assert expected_categories
    host = _PatternHost()
    qtbot.addWidget(host)
    tree = host.build_library_tree()
    host.populate_hexpat_entries()
    assert tree.topLevelItemCount() == 1
    section = tree.topLevelItem(0)
    assert section is not None
    assert section.text(0) == "HexPat Patterns"
    children = [child.text(0) for child in (section.child(index) for index in range(section.childCount())) if child is not None]
    assert children == expected_categories


def test_compare_without_a_summary_label_still_fills_the_results_tree(
    qtbot: QtBot,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    comparison_host: _ComparisonHost,
) -> None:
    """The comparison starts and renders its rows when the caption label does not exist.

    Args:
        qtbot: pytest-qt fixture used to wait for the worker.
        monkeypatch: pytest monkeypatch fixture used to answer the file dialog.
        tmp_path: Per-test temporary directory holding the two files.
        comparison_host: Host with the tab built.
    """
    file_a = tmp_path / "a.bin"
    file_b = tmp_path / "b.bin"
    file_a.write_bytes(_DATA_A)
    file_b.write_bytes(_DATA_B)
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _file_picker(str(file_b)))
    comparison_host.file_path = file_a
    comparison_host.drop_label()
    comparison_host.compare()
    assert comparison_host.worker is not None
    qtbot.waitUntil(lambda: comparison_host.tree.topLevelItemCount() == 1, timeout=_WAIT_MS)
    changed = [index for index, (left, right) in enumerate(zip(_DATA_A, _DATA_B, strict=True)) if left != right]
    first = changed[0]
    length = len(changed)
    assert changed == list(range(first, first + length))
    assert comparison_host.label is None
    assert comparison_host.rows() == [(f"0x{first:08X}", str(length), "modified", f"Bytes {first:#010x} - {first + length:#010x}")]


def test_custom_any_entry_absent_from_the_document_is_not_reported(tmp_path: Path) -> None:
    """A full-scan entry whose pattern is not in the document is left out, while a present one is reported at its offset.

    Args:
        tmp_path: Per-test temporary directory holding the database.
    """
    document = bytes([0x00, 0x11, 0x22, 0x33, 0x44])
    database = tmp_path / "custom.json"
    entries = [
        {"name": "Absent", "type": "packer", "pattern": "de ad be ef", "offset": "any"},
        {"name": "Present", "type": "marker", "pattern": "22 33", "offset": "any"},
    ]
    database.write_text(json.dumps(entries), encoding="utf-8")
    hits = execute_signature_scan(document, "custom", str(database))
    assert [(hit["name"], hit["offset"]) for hit in hits] == [("Present", document.find(b"\x22\x33"))]


@pytest.mark.parametrize(
    ("created", "expected"),
    [("2026-02-03T04:05:06+00:00", "2026-02-03T04:05:06+00:00"), (1700000000, "1700000000")],
    ids=["text", "number"],
)
def test_export_keeps_a_non_datetime_creation_stamp_as_text(created: object, expected: str) -> None:
    """A creation stamp that is not a ``datetime`` but is non-empty is exported as its text form.

    Args:
        created: Stored creation stamp.
        expected: Text the export must carry.
    """
    data: dict[str, object] = {"id": "i", "name": "n", "created_at": created}
    result = cast("dict[str, object]", _call(SessionManagerDialog, "_prepare_export_data", data))
    assert result["created_at"] == expected


@pytest.mark.usefixtures("direct_network")
def test_install_stops_when_the_release_lookup_yields_no_download_url(tmp_path: Path) -> None:
    """A release that is not found fails the install with the manual-download hint, before anything is created on disk.

    Args:
        tmp_path: Per-test temporary directory.
    """
    install_path = tmp_path / "install"
    with RouteServer() as server:
        server.script("GET", _API_PATH, json_response(404, {}))
        origin = server.origin
        urls = {"demo": {"api_url": f"{origin}{_API_PATH}", "fallback_html": f"{origin}/releases", "name": "Demo Tool"}}
        outcome = _run_install(_worker_class(urls)("demo", install_path))
    assert outcome.finished == [(False, f"GitHub release not found (HTTP 404). Download manually from: {origin}/releases")]
    assert outcome.progress == [3]
    assert not install_path.exists()


@pytest.mark.usefixtures("direct_network")
def test_fetch_release_reports_a_server_that_never_answers() -> None:
    """An API host that accepts the connection but never replies is reported as a timeout after the 30 second limit."""
    with StallingServer() as server:
        result = _call(ToolInstallWorker, "_fetch_github_release", f"{server.url}{_API_PATH}")
    assert result == (None, "GitHub API request timed out")


@pytest.mark.usefixtures("direct_network")
def test_install_reports_connection_refused_for_the_release_lookup(tmp_path: Path) -> None:
    """A release API that refuses connections stops the install with the connection message and creates nothing.

    Args:
        tmp_path: Per-test temporary directory.
    """
    install_path = tmp_path / "install"
    urls = {"demo": {"api_url": f"http://127.0.0.1:{_closed_port()}{_API_PATH}", "name": "Demo Tool"}}
    outcome = _run_install(_worker_class(urls)("demo", install_path))
    assert outcome.finished == [(False, "Could not connect to GitHub API")]
    assert outcome.progress == [3]
    assert not install_path.exists()
