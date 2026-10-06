# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Coverage for the signature databases, scanners and panel mixin of the hex editor signatures tab.

Every test drives the production code with real objects: signature databases written to disk in the formats the product reads (DIE JSON,
ClamAV ``.hdb`` and ``.ndb``, custom JSON, YARA rules), a genuine ``intellicrack_hexcore.HexDocument`` holding known bytes, a real
``HexEditorWidget``, the real Qt controls built by ``SignaturesMixin._create_signatures_tab`` and the real asynchronous worker used by the
Scan button. Expected values are derived from byte arithmetic, the file formats, the Python standard library, or the documented contract of
each function rather than read back from the code under test.
"""

from __future__ import annotations

import hashlib
import json
import threading
from typing import TYPE_CHECKING, Any

import intellicrack_hexcore
import pytest
from PyQt6.QtCore import QCoreApplication
from PyQt6.QtWidgets import QComboBox, QFileDialog, QLabel, QPushButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget

from intellicrack.ui.panels.async_bridge import (
    GenericCallableWorker,
    drain_bridge_workers,
    drain_bridge_workers_for,
    run_callable_async,
)
from intellicrack.ui.panels.hex_editor import scripting as scripting_module
from intellicrack.ui.panels.hex_editor.signatures import (
    SignaturesMixin,
    execute_signature_scan,
    execute_signature_scan_from_source,
    read_document_for_scan,
)
from intellicrack.ui.panels.hex_editor_widget import HexEditorWidget


if TYPE_CHECKING:
    from collections.abc import Callable, Generator
    from pathlib import Path

    from pytestqt.qtbot import QtBot


pytestmark = pytest.mark.usefixtures("qapp")


_DocAPI: Any = getattr(scripting_module, "_DocAPI")

_WAIT_MS: int = 20_000
_COLUMN_COUNT: int = 5
_DEAD_BEEF: bytes = b"\xde\xad\xbe\xef"


def _blob(size: int, *placed: tuple[int, bytes]) -> bytes:
    """Build a zero-filled buffer with payloads written at fixed offsets.

    Args:
        size: Total length of the buffer in bytes.
        *placed: ``(offset, payload)`` pairs written into the buffer in order.

    Returns:
        bytes: The assembled buffer.
    """
    buffer = bytearray(size)
    for offset, payload in placed:
        buffer[offset : offset + len(payload)] = payload
    return bytes(buffer)


def _write_json(path: Path, entries: list[dict[str, Any]]) -> str:
    """Write a JSON signature database.

    Args:
        path: Destination file.
        entries: Database entries to serialize.

    Returns:
        str: The path of the written database as text.
    """
    path.write_text(json.dumps(entries), encoding="utf-8")
    return str(path)


def _write_lines(path: Path, lines: list[str]) -> str:
    """Write a line-oriented signature database.

    Args:
        path: Destination file.
        lines: Database lines, in order.

    Returns:
        str: The path of the written database as text.
    """
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


def _hit(name: str, kind: str, version: str, offset: int, details: str) -> dict[str, Any]:
    """Build the match dictionary a scanner is documented to return.

    Args:
        name: Signature name.
        kind: Signature type.
        version: Signature version.
        offset: Byte offset of the match.
        details: Human-readable match description.

    Returns:
        dict[str, Any]: Dictionary with the five documented keys.
    """
    return {"name": name, "type": kind, "version": version, "offset": offset, "details": details}


def _file_picker(path: str) -> Callable[..., tuple[str, str]]:
    """Build a file-dialog replacement that picks a fixed path.

    Args:
        path: Path the picker reports as chosen; empty text means the user cancelled.

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


def _join(worker: GenericCallableWorker | None) -> None:
    """Wait for a scan worker to finish and deliver its queued result to the Qt thread.

    Args:
        worker: Worker the Scan slot started.
    """
    assert worker is not None
    assert worker.wait(_WAIT_MS)
    QCoreApplication.processEvents()


def _cursor(widget: HexEditorWidget) -> int:
    """Read the cursor offset of a hex editor widget.

    Args:
        widget: Widget whose cursor is read.

    Returns:
        int: The widget's current cursor offset.
    """
    value: object = getattr(widget, "_cursor_offset")
    assert isinstance(value, int)
    return value


class _MemoryViewDocument(_DocAPI):
    """Real scripting document API whose ``read`` returns a ``memoryview`` instead of ``bytes``."""

    def read(self, offset: int, length: int) -> memoryview:
        """Read bytes from the real document and expose them as a ``memoryview``.

        Args:
            offset: Start offset.
            length: Number of bytes to read.

        Returns:
            memoryview: View over the bytes the real document returned.
        """
        inherited_read: Callable[[int, int], bytes] = getattr(super(), "read")
        return memoryview(inherited_read(offset, length))


class _SignaturesHost(SignaturesMixin, QWidget):
    """Concrete widget host that exposes the signatures mixin's slots to the tests."""

    def __init__(
        self,
        document: object | None,
        hex_widget: QWidget | None = None,
        file_path: Path | None = None,
    ) -> None:
        """Create a host with no signatures tab built yet.

        Args:
            document: Document the scans read, or ``None``.
            hex_widget: Widget the result navigation moves, or ``None``.
            file_path: Path of the on-disk binary the scans prefer over the document.
        """
        super().__init__()
        self.document = document
        self.file_path = file_path
        self._hex_widget = hex_widget
        self._sig_db_type_combo = None
        self._sig_db_path_label = None
        self._sig_results_tree = None
        self._sig_worker = None
        self._sig_db_path = ""
        self._bridge = None

    def build_tab(self) -> QWidget:
        """Build the real signatures tab and place it inside the host.

        Returns:
            QWidget: The tab container created by the mixin.
        """
        container = self._create_signatures_tab()
        QVBoxLayout(self).addWidget(container)
        return container

    def button(self, text: str) -> QPushButton:
        """Find a tab button by its caption.

        Args:
            text: Caption of the wanted button.

        Returns:
            QPushButton: The matching button.

        Raises:
            LookupError: If no button has that caption.
        """
        for candidate in self.findChildren(QPushButton):
            if candidate.text() == text:
                return candidate
        msg = f"no button captioned {text!r}"
        raise LookupError(msg)

    @property
    def tree(self) -> QTreeWidget:
        """The results tree created by the tab.

        Returns:
            QTreeWidget: The results tree.
        """
        tree = self._sig_results_tree
        assert tree is not None
        return tree

    @property
    def combo(self) -> QComboBox:
        """The database type selector created by the tab.

        Returns:
            QComboBox: The selector.
        """
        combo = self._sig_db_type_combo
        assert combo is not None
        return combo

    @property
    def label(self) -> QLabel:
        """The database path label created by the tab.

        Returns:
            QLabel: The label.
        """
        label = self._sig_db_path_label
        assert label is not None
        return label

    @property
    def worker(self) -> GenericCallableWorker | None:
        """The worker the Scan slot started most recently.

        Returns:
            GenericCallableWorker | None: The worker, or ``None`` when nothing has run.
        """
        return self._sig_worker

    @property
    def db_path(self) -> str:
        """The signature database path the host currently holds.

        Returns:
            str: The selected database path, empty when none is selected.
        """
        return self._sig_db_path

    def adopt_worker(self, worker: GenericCallableWorker) -> None:
        """Record a worker as the host's current scan worker.

        Args:
            worker: The worker to record.
        """
        self._sig_worker = worker

    def set_db_path(self, path: str) -> None:
        """Select a signature database without going through the file dialog.

        Args:
            path: Database path to hold.
        """
        self._sig_db_path = path

    def use_document(self, document: object | None) -> None:
        """Replace the document the scans read.

        Args:
            document: The new document, or ``None``.
        """
        self.document = document

    def set_file_path(self, path: Path | None) -> None:
        """Replace the on-disk path the scans prefer over the document.

        Args:
            path: The new path, or ``None``.
        """
        self.file_path = path

    def drop_tree(self) -> None:
        """Forget the results tree so the slots see it as not yet created."""
        self._sig_results_tree = None

    def drop_label(self) -> None:
        """Forget the path label so the slots see it as not yet created."""
        self._sig_db_path_label = None

    def add_row(self, name: str) -> None:
        """Add a placeholder row to the results tree.

        Args:
            name: Text of the first column.
        """
        self.tree.addTopLevelItem(QTreeWidgetItem([name, "", "", "", ""]))

    def rows(self) -> list[tuple[str, ...]]:
        """Read every top-level row of the results tree.

        Returns:
            list[tuple[str, ...]]: One tuple of column texts per row.
        """
        tree = self.tree
        collected: list[tuple[str, ...]] = []
        for index in range(tree.topLevelItemCount()):
            item = tree.topLevelItem(index)
            assert item is not None
            collected.append(tuple(item.text(column) for column in range(_COLUMN_COUNT)))
        return collected

    def select_database(self) -> None:
        """Invoke the slot the Select Database button triggers."""
        self._on_select_sig_db()

    def scan(self) -> None:
        """Invoke the slot the Scan button triggers."""
        self._on_scan_signatures()

    def finished(self, results: list[object]) -> None:
        """Deliver a typed result list to the finished handler.

        Args:
            results: Match dictionaries to render.
        """
        self._on_sig_scan_finished(results)

    def finished_obj(self, results: object) -> None:
        """Deliver an untyped worker result to the finished forwarder.

        Args:
            results: Raw object a worker emitted.
        """
        self._on_sig_scan_finished_obj(results)

    def error(self, message: str) -> None:
        """Deliver an error string to the error handler.

        Args:
            message: Error text.
        """
        self._on_sig_scan_error(message)

    def error_obj(self, exc: object) -> None:
        """Deliver a raw exception object to the error forwarder.

        Args:
            exc: Exception object a worker emitted.
        """
        self._on_sig_scan_error_obj(exc)

    def bridge_success(self, result: object) -> None:
        """Deliver a bridge scan result to the bridge success handler.

        Args:
            result: Raw object a bridge scan produced.
        """
        self._on_sig_scan_bridge_success(result)

    def bridge_error(self, exc: object) -> None:
        """Deliver a bridge scan failure to the bridge error handler.

        Args:
            exc: Exception object a bridge scan raised.
        """
        self._on_sig_scan_bridge_error(exc)

    def double_click(self, item: QTreeWidgetItem, column: int) -> None:
        """Deliver a double click on a result row to the navigation handler.

        Args:
            item: The clicked row.
            column: The clicked column index.
        """
        self._on_sig_result_double_clicked(item, column)


_DIE_DOC: bytes = _blob(64, (0, b"MZ"), (0x10, _DEAD_BEEF), (0x30, b"\xca\xfe"), (0x3E, b"\xf0\x0d"))
_NDB_DOC: bytes = _blob(64, (0, b"MZ\x90\x00"), (0x20, _DEAD_BEEF))
_HDB_DOC: bytes = b"intellicrack hash sample"
_HOST_DOC: bytes = _blob(64, (0, b"MZ"), (0x10, _DEAD_BEEF))


@pytest.fixture
def document() -> intellicrack_hexcore.HexDocument:
    """Open a real document over the host sample bytes.

    Returns:
        intellicrack_hexcore.HexDocument: Document holding ``_HOST_DOC``.
    """
    return intellicrack_hexcore.HexDocument.open_bytes(_HOST_DOC)


@pytest.fixture
def hex_widget(qtbot: QtBot, document: intellicrack_hexcore.HexDocument) -> HexEditorWidget:
    """Create a real hex editor widget showing the host sample document.

    Args:
        qtbot: pytest-qt fixture that owns the widget.
        document: Document to display.

    Returns:
        HexEditorWidget: Widget with the document attached.
    """
    widget = HexEditorWidget()
    qtbot.addWidget(widget)
    widget.set_document(document)
    return widget


@pytest.fixture
def host(
    qtbot: QtBot,
    document: intellicrack_hexcore.HexDocument,
    hex_widget: HexEditorWidget,
) -> Generator[_SignaturesHost]:
    """Create a host whose signatures tab is built and whose workers are joined on teardown.

    Args:
        qtbot: pytest-qt fixture that owns the host.
        document: Document the scans read.
        hex_widget: Widget the result navigation moves.

    Yields:
        _SignaturesHost: Host with the tab built.
    """
    instance = _SignaturesHost(document, hex_widget)
    qtbot.addWidget(instance)
    instance.build_tab()
    try:
        yield instance
    finally:
        drain_bridge_workers_for(instance)
        drain_bridge_workers()


def test_read_document_for_scan_rejects_an_unexpected_read_result_type(document: intellicrack_hexcore.HexDocument) -> None:
    """A document whose ``read`` returns something other than a list, bytearray or bytes is refused with a ``ValueError``.

    Args:
        document: Real document the memoryview-returning API wraps.
    """
    view_document = _MemoryViewDocument(document, None, None)
    with pytest.raises(ValueError, match=r"Unexpected document\.read return type: memoryview"):
        read_document_for_scan(view_document)


def test_scan_from_source_falls_back_to_the_document_when_the_file_is_missing(
    document: intellicrack_hexcore.HexDocument,
    tmp_path: Path,
) -> None:
    """A path that does not exist falls back to the document bytes instead of failing.

    Args:
        document: Real document holding ``_HOST_DOC``.
        tmp_path: Per-test temporary directory.
    """
    database = _write_json(
        tmp_path / "die.json",
        [{"name": "Dead", "type": "marker", "version": "2", "patterns": [{"pattern": "deadbeef", "offset": "any"}]}],
    )
    results = execute_signature_scan_from_source(str(tmp_path / "missing.bin"), document, "die", database)
    assert results == [_hit("Dead", "marker", "2", 0x10, "Full scan match at 0x10")]


def test_die_entry_point_patterns_report_hits_and_ignore_misses(tmp_path: Path) -> None:
    """A bare hex string is an entry-point pattern: a present one is reported, an absent one is not.

    Args:
        tmp_path: Per-test temporary directory.
    """
    database = _write_json(
        tmp_path / "die.json",
        [
            {"name": "MzHeader", "type": "exe", "version": "1.0", "patterns": ["4d5a"]},
            {"name": "NoSuchPattern", "type": "exe", "version": "1.0", "patterns": ["ffff"]},
        ],
    )
    assert execute_signature_scan(_DIE_DOC, "die", database) == [_hit("MzHeader", "exe", "1.0", 0, "Entry point match at +0")]


def test_die_fixed_offsets_accept_hex_and_decimal_and_respect_the_document_bounds(tmp_path: Path) -> None:
    """Fixed offsets match only when the bytes at that offset equal the pattern and fit inside the document.

    Args:
        tmp_path: Per-test temporary directory.
    """
    database = _write_json(
        tmp_path / "die.json",
        [
            {"name": "HexOffset", "patterns": [{"pattern": "deadbeef", "offset": "0x10"}]},
            {"name": "DecimalOffset", "patterns": [{"pattern": "cafe", "offset": "48"}]},
            {"name": "WrongOffset", "patterns": [{"pattern": "deadbeef", "offset": "0x11"}]},
            {"name": "PastEnd", "patterns": [{"pattern": "cafe", "offset": "0x3F"}]},
            {"name": "LastBytes", "patterns": [{"pattern": "f00d", "offset": "0x3E"}]},
        ],
    )
    assert execute_signature_scan(_DIE_DOC, "die", database) == [
        _hit("HexOffset", "unknown", "", 16, "Fixed offset match at 0x10"),
        _hit("DecimalOffset", "unknown", "", 48, "Fixed offset match at 0x30"),
        _hit("LastBytes", "unknown", "", 62, "Fixed offset match at 0x3E"),
    ]


def test_die_unparseable_offset_skips_only_that_pattern(tmp_path: Path) -> None:
    """An offset that is not a number drops that pattern and the scan carries on with the next entry.

    Args:
        tmp_path: Per-test temporary directory.
    """
    database = _write_json(
        tmp_path / "die.json",
        [
            {"name": "BadOffset", "patterns": [{"pattern": "4d5a", "offset": "later"}]},
            {"name": "After", "patterns": [{"pattern": "4d5a", "offset": "0"}]},
        ],
    )
    assert execute_signature_scan(_DIE_DOC, "die", database) == [_hit("After", "unknown", "", 0, "Fixed offset match at 0x0")]


def test_die_malformed_patterns_are_skipped(tmp_path: Path) -> None:
    """Patterns that are neither text nor objects, or whose hex does not decode, are skipped without stopping the entry.

    Args:
        tmp_path: Per-test temporary directory.
    """
    database = _write_json(
        tmp_path / "die.json",
        [
            {
                "name": "Mixed",
                "patterns": [42, None, {"pattern": "zz", "offset": "any"}, "not hex", {"pattern": "de ad be ef", "offset": "any"}],
            },
        ],
    )
    assert execute_signature_scan(_DIE_DOC, "die", database) == [_hit("Mixed", "unknown", "", 16, "Full scan match at 0x10")]


@pytest.mark.parametrize("file_name", ["known.hdb", "KNOWN.HDB"])
def test_clamav_hdb_reports_only_entries_with_matching_hash_and_size(tmp_path: Path, file_name: str) -> None:
    """Hash signatures match on the MD5 of the whole document and its exact size, whatever the case of the suffix and digest.

    Args:
        tmp_path: Per-test temporary directory.
        file_name: Database file name, in lower and upper case suffix.
    """
    digest = hashlib.md5(_HDB_DOC, usedforsecurity=False).hexdigest()
    size = len(_HDB_DOC)
    database = _write_lines(
        tmp_path / file_name,
        [
            f"{digest.upper()}:{size}:Win.Test.Hash",
            f"{digest}:{size + 1}:Wrong.Size",
            f"{'0' * 32}:{size}:Other.Hash",
            "short:line",
            f"{digest}:notanumber:Bad.Size",
            "",
            f"{digest}:{size}:Second.Hit",
            f"{digest}:{size}:With.Level:73",
        ],
    )
    detail = f"MD5 hash match (size={size})"
    assert execute_signature_scan(_HDB_DOC, "clamav", database) == [
        _hit("Win.Test.Hash", "hash", "", 0, detail),
        _hit("Second.Hit", "hash", "", 0, detail),
        _hit("With.Level", "hash", "", 0, detail),
    ]


def test_clamav_ndb_any_offset_and_entry_point_signatures(tmp_path: Path) -> None:
    """``*`` signatures are searched across the document and ``EP+0`` signatures must start the document.

    Args:
        tmp_path: Per-test temporary directory.
    """
    database = _write_lines(
        tmp_path / "sigs.ndb",
        [
            "Any.Hit:0:*:deadbeef",
            "Any.Miss:0:*:cafebabe",
            "Ep.Hit:1:EP+0:4d5a9000",
            "Ep.Miss:1:EP+0:deadbeef",
        ],
    )
    assert execute_signature_scan(_NDB_DOC, "clamav", database) == [
        _hit("Any.Hit", "ndb", "", 32, "Pattern match at 0x20"),
        _hit("Ep.Hit", "ndb", "", 0, "Entry point match"),
    ]


def test_clamav_ndb_fixed_offsets_respect_the_document_bounds(tmp_path: Path) -> None:
    """Numeric offsets in hex or decimal match only the bytes at that offset and only when they fit in the document.

    Args:
        tmp_path: Per-test temporary directory.
    """
    database = _write_lines(
        tmp_path / "sigs.ndb",
        [
            "Fixed.Hex:0:0x20:deadbeef",
            "Fixed.Dec:0:32:deadbeef",
            "Fixed.Miss:0:0x21:deadbeef",
            "Fixed.Past:0:62:deadbeef",
            "Fixed.Last:0:60:00000000",
        ],
    )
    assert execute_signature_scan(_NDB_DOC, "clamav", database) == [
        _hit("Fixed.Hex", "ndb", "", 32, "Fixed offset match at 0x20"),
        _hit("Fixed.Dec", "ndb", "", 32, "Fixed offset match at 0x20"),
        _hit("Fixed.Last", "ndb", "", 60, "Fixed offset match at 0x3C"),
    ]


def test_clamav_ndb_malformed_lines_are_skipped(tmp_path: Path) -> None:
    """Short lines, blank lines, wildcard-only or undecodable patterns and bad offsets never stop the scan.

    Args:
        tmp_path: Per-test temporary directory.
    """
    database = _write_lines(
        tmp_path / "sigs.ndb",
        [
            "too:few:fields",
            "",
            "Wild.Only:0:*:**",
            "Bad.Hex:0:*:abc",
            "Bad.Offset:0:later:deadbeef",
            "Still.Works:0:*:deadbeef",
        ],
    )
    assert execute_signature_scan(_NDB_DOC, "clamav", database) == [_hit("Still.Works", "ndb", "", 32, "Pattern match at 0x20")]


def test_custom_entry_point_window_includes_a_pattern_ending_at_byte_256(tmp_path: Path) -> None:
    """An ``ep`` signature matches within the first 256 bytes only, while ``any`` also finds later bytes.

    Args:
        tmp_path: Per-test temporary directory.
    """
    document = _blob(300, (0, b"MZ"), (252, b"\x11\x22\x33\x44"), (280, b"\x55\x66\x77\x88"))
    database = _write_json(
        tmp_path / "custom.json",
        [
            {"name": "EpInside", "type": "packer", "pattern": "11223344", "offset": "ep"},
            {"name": "EpOutside", "type": "packer", "pattern": "55667788", "offset": "ep"},
            {"name": "AnyOutside", "type": "packer", "pattern": "55667788", "offset": "any"},
        ],
    )
    assert execute_signature_scan(document, "custom", database) == [
        _hit("EpInside", "packer", "", 252, "Entry point match at +252"),
        _hit("AnyOutside", "packer", "", 280, "Full scan match at 0x118"),
    ]


def test_custom_entry_point_window_excludes_a_pattern_straddling_byte_256(tmp_path: Path) -> None:
    """A pattern that starts before byte 256 but ends after it is invisible to ``ep`` and visible to ``any``.

    Args:
        tmp_path: Per-test temporary directory.
    """
    document = _blob(300, (254, b"\x11\x22\x33\x44"))
    database = _write_json(
        tmp_path / "custom.json",
        [
            {"name": "EpStraddle", "pattern": "11223344", "offset": "ep"},
            {"name": "AnyStraddle", "pattern": "11223344", "offset": "any"},
        ],
    )
    assert execute_signature_scan(document, "custom", database) == [_hit("AnyStraddle", "unknown", "", 254, "Full scan match at 0xFE")]


def test_custom_entries_default_to_an_unknown_name_and_type_and_accept_spaced_hex(tmp_path: Path) -> None:
    """Missing name, type and offset fall back to ``unknown``, ``unknown`` and a full scan; spaces in the pattern are ignored.

    Args:
        tmp_path: Per-test temporary directory.
    """
    database = _write_json(
        tmp_path / "custom.json",
        [
            {"pattern": "4d5a"},
            {"name": "Spaced", "type": "marker", "pattern": "de ad be ef", "offset": "any"},
        ],
    )
    assert execute_signature_scan(_DIE_DOC, "custom", database) == [
        _hit("unknown", "unknown", "", 0, "Full scan match at 0x0"),
        _hit("Spaced", "marker", "", 16, "Full scan match at 0x10"),
    ]


def test_custom_fixed_offsets_accept_hex_and_decimal_and_respect_the_document_bounds(tmp_path: Path) -> None:
    """Fixed offsets match only equal bytes that fit inside the document, including a pattern ending on the last byte.

    Args:
        tmp_path: Per-test temporary directory.
    """
    document = _blob(64, (0x10, _DEAD_BEEF), (0x3C, b"\xaa\xbb\xcc\xdd"))
    database = _write_json(
        tmp_path / "custom.json",
        [
            {"name": "Hex", "pattern": "deadbeef", "offset": "0x10"},
            {"name": "Dec", "pattern": "deadbeef", "offset": "16"},
            {"name": "Miss", "pattern": "deadbeef", "offset": "17"},
            {"name": "Past", "pattern": "aabbccdd", "offset": "62"},
            {"name": "Edge", "pattern": "aabbccdd", "offset": "60"},
        ],
    )
    assert execute_signature_scan(document, "custom", database) == [
        _hit("Hex", "unknown", "", 16, "Fixed offset match at 0x10"),
        _hit("Dec", "unknown", "", 16, "Fixed offset match at 0x10"),
        _hit("Edge", "unknown", "", 60, "Fixed offset match at 0x3C"),
    ]


def test_custom_malformed_entries_are_skipped(tmp_path: Path) -> None:
    """Undecodable hex and unparseable offsets drop only their own entry.

    Args:
        tmp_path: Per-test temporary directory.
    """
    database = _write_json(
        tmp_path / "custom.json",
        [
            {"name": "BadHex", "pattern": "xyz"},
            {"name": "BadOffset", "pattern": "deadbeef", "offset": "soon"},
            {"name": "Good", "pattern": "deadbeef", "offset": "any"},
        ],
    )
    assert execute_signature_scan(_DIE_DOC, "custom", database) == [_hit("Good", "unknown", "", 16, "Full scan match at 0x10")]


def test_yara_database_reports_rule_name_version_offset_and_details(tmp_path: Path) -> None:
    """A YARA rule file is compiled under its file stem and each hit reports the first string's offset and the rule metadata.

    Args:
        tmp_path: Per-test temporary directory.
    """
    rules = tmp_path / "sigs.yar"
    rules.write_text(
        'rule FindMagic : alpha\n{\n    meta:\n        version = "2.5"\n    strings:\n        $a = "MAGICBYTES"\n    condition:\n        $a\n}\n',
        encoding="utf-8",
    )
    document = _blob(64, (2, b"MAGICBYTES"))
    assert execute_signature_scan(document, "yara", str(rules)) == [
        _hit("FindMagic", "YARA", "2.5", 2, "Namespace: sigs, Meta: {'version': '2.5'}, Tags: ['alpha']"),
    ]


def test_yara_rule_without_strings_or_metadata_reports_defaults(tmp_path: Path) -> None:
    """A matching rule with no strings reports offset zero and the default version; a rule that does not match is omitted.

    Args:
        tmp_path: Per-test temporary directory.
    """
    rules = tmp_path / "plain.yar"
    rules.write_text(
        'rule Always { condition: true }\nrule Never { strings: $x = "ZZZZ_NOT_PRESENT" condition: $x }\n',
        encoding="utf-8",
    )
    assert execute_signature_scan(_DIE_DOC, "yara", str(rules)) == [
        _hit("Always", "YARA", "1.0", 0, "Namespace: plain, Meta: {}, Tags: []"),
    ]


def test_goto_offset_moves_the_hex_widget_cursor(host: _SignaturesHost, hex_widget: HexEditorWidget) -> None:
    """Navigation asks the attached hex widget to move its cursor to the requested offset.

    Args:
        host: Host whose signatures tab is built.
        hex_widget: Widget the host navigates.
    """
    assert _cursor(hex_widget) == 0
    host.goto_offset(0x2A)
    assert _cursor(hex_widget) == 0x2A


def test_goto_offset_tolerates_a_missing_or_incapable_widget(
    qtbot: QtBot,
    document: intellicrack_hexcore.HexDocument,
    hex_widget: HexEditorWidget,
) -> None:
    """With no widget, or a widget that cannot navigate, the request is ignored and other widgets are untouched.

    Args:
        qtbot: pytest-qt fixture that owns the hosts.
        document: Real document the hosts hold.
        hex_widget: Bystander widget that must not move.
    """
    without_widget = _SignaturesHost(document)
    qtbot.addWidget(without_widget)
    without_widget.goto_offset(7)

    incapable = QLabel()
    qtbot.addWidget(incapable)
    with_label = _SignaturesHost(document, incapable)
    qtbot.addWidget(with_label)
    with_label.goto_offset(7)

    assert _cursor(hex_widget) == 0


def test_select_database_records_the_chosen_path_and_shows_its_name(
    monkeypatch: pytest.MonkeyPatch,
    host: _SignaturesHost,
    tmp_path: Path,
) -> None:
    """Choosing a database stores its full path, shows the file name and keeps the full path as the tooltip.

    Args:
        monkeypatch: pytest monkeypatch fixture used to replace the file dialog.
        host: Host whose signatures tab is built.
        tmp_path: Per-test temporary directory.
    """
    chosen = str(tmp_path / "chosen.json")
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _file_picker(chosen))
    host.button("Select Database...").click()
    assert host.db_path == chosen
    assert host.label.text() == "chosen.json"
    assert host.label.toolTip() == chosen


def test_select_database_cancelled_keeps_the_previous_selection(
    monkeypatch: pytest.MonkeyPatch,
    host: _SignaturesHost,
) -> None:
    """Cancelling the file dialog leaves the stored path and the label untouched.

    Args:
        monkeypatch: pytest monkeypatch fixture used to replace the file dialog.
        host: Host whose signatures tab is built.
    """
    host.set_db_path("previous.json")
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _file_picker(""))
    host.select_database()
    assert host.db_path == "previous.json"
    assert host.label.text() == "(none)"
    assert host.label.toolTip() == "(none)"


def test_select_database_without_a_label_still_records_the_path(
    monkeypatch: pytest.MonkeyPatch,
    host: _SignaturesHost,
    tmp_path: Path,
) -> None:
    """The stored path does not depend on the label having been created.

    Args:
        monkeypatch: pytest monkeypatch fixture used to replace the file dialog.
        host: Host whose signatures tab is built.
        tmp_path: Per-test temporary directory.
    """
    chosen = str(tmp_path / "chosen.ndb")
    host.drop_label()
    monkeypatch.setattr(QFileDialog, "getOpenFileName", _file_picker(chosen))
    host.select_database()
    assert host.db_path == chosen


def test_scan_does_nothing_without_a_document_or_a_database(
    host: _SignaturesHost,
    document: intellicrack_hexcore.HexDocument,
    tmp_path: Path,
) -> None:
    """The Scan slot returns before touching the results when there is no document or no database selected.

    Args:
        host: Host whose signatures tab is built.
        document: Real document the host normally scans.
        tmp_path: Per-test temporary directory.
    """
    database = _write_json(tmp_path / "die.json", [])
    host.add_row("keep")

    host.use_document(None)
    host.set_db_path(database)
    host.scan()
    assert host.worker is None
    assert host.rows() == [("keep", "", "", "", "")]

    host.use_document(document)
    host.set_db_path("")
    host.button("Scan").click()
    assert host.worker is None
    assert host.rows() == [("keep", "", "", "", "")]


def test_scan_is_ignored_while_a_scan_is_in_flight(host: _SignaturesHost, tmp_path: Path) -> None:
    """A second Scan request while a worker is still running neither clears the results nor replaces the worker.

    Args:
        host: Host whose signatures tab is built.
        tmp_path: Per-test temporary directory.
    """
    release = threading.Event()
    blocker = run_callable_async(release.wait, 30.0)
    try:
        host.adopt_worker(blocker)
        host.set_db_path(_write_json(tmp_path / "die.json", []))
        host.add_row("keep")
        host.scan()
        assert host.worker is blocker
        assert host.rows() == [("keep", "", "", "", "")]
    finally:
        release.set()
        joined = blocker.wait(_WAIT_MS)
    assert joined


def test_scan_without_a_results_tree_runs_and_discards_the_result(host: _SignaturesHost, tmp_path: Path) -> None:
    """A scan started with no results tree still completes, and delivering its result does not fail.

    Args:
        host: Host whose signatures tab is built.
        tmp_path: Per-test temporary directory.
    """
    host.drop_tree()
    host.set_db_path(
        _write_json(tmp_path / "die.json", [{"name": "Dead", "patterns": [{"pattern": "deadbeef", "offset": "any"}]}]),
    )
    host.scan()
    assert host.worker is not None
    _join(host.worker)


_RENDER_CASES: list[Any] = [
    pytest.param(
        0,
        "die.json",
        json.dumps([
            {"name": "DieHit", "type": "packer", "version": "3.1", "patterns": [{"pattern": "deadbeef", "offset": "any"}]},
        ]),
        ("DieHit", "packer", "3.1", "0x00000010", "Full scan match at 0x10"),
        id="die",
    ),
    pytest.param(
        1,
        "sigs.ndb",
        "Mal.Sample:0:*:deadbeef\n",
        ("Mal.Sample", "ndb", "", "0x00000010", "Pattern match at 0x10"),
        id="clamav",
    ),
    pytest.param(
        2,
        "custom.json",
        json.dumps([{"name": "CustomHit", "type": "marker", "pattern": "deadbeef", "offset": "any"}]),
        ("CustomHit", "marker", "", "0x00000010", "Full scan match at 0x10"),
        id="custom",
    ),
    pytest.param(
        3,
        "rules.yar",
        "rule YaraHit { strings: $a = { DE AD BE EF } condition: $a }\n",
        ("YaraHit", "YARA", "1.0", "0x00000010", "Namespace: rules, Meta: {}, Tags: []"),
        id="yara",
    ),
]


@pytest.mark.parametrize(("type_index", "file_name", "content", "expected_row"), _RENDER_CASES)
def test_scan_renders_the_matches_of_the_selected_database_type(
    qtbot: QtBot,
    host: _SignaturesHost,
    tmp_path: Path,
    type_index: int,
    file_name: str,
    content: str,
    expected_row: tuple[str, ...],
) -> None:
    """The Scan button dispatches by the selected database type and renders the document's matches in the tree.

    Args:
        qtbot: pytest-qt fixture used to wait for the worker.
        host: Host whose signatures tab is built.
        tmp_path: Per-test temporary directory.
        type_index: Index of the database type in the selector.
        file_name: Name of the database file to write.
        content: Text of the database file.
        expected_row: Column texts of the single row the scan must produce.
    """
    database = tmp_path / file_name
    database.write_text(content, encoding="utf-8")
    host.combo.setCurrentIndex(type_index)
    host.set_db_path(str(database))
    host.button("Scan").click()
    qtbot.waitUntil(lambda: host.tree.topLevelItemCount() == 1, timeout=_WAIT_MS)
    assert host.rows() == [expected_row]


def test_scan_prefers_the_file_on_disk_over_the_document(qtbot: QtBot, host: _SignaturesHost, tmp_path: Path) -> None:
    """When the host has an existing file path the scan reads that file, not the document.

    Args:
        qtbot: pytest-qt fixture used to wait for the worker.
        host: Host whose signatures tab is built; its document has the pattern at 0x10.
        tmp_path: Per-test temporary directory.
    """
    binary = tmp_path / "target.bin"
    binary.write_bytes(_blob(64, (0x20, _DEAD_BEEF)))
    host.set_file_path(binary)
    host.set_db_path(
        _write_json(
            tmp_path / "custom.json",
            [{"name": "OnDisk", "type": "marker", "pattern": "deadbeef", "offset": "any"}],
        ),
    )
    host.combo.setCurrentIndex(2)
    host.button("Scan").click()
    qtbot.waitUntil(lambda: host.tree.topLevelItemCount() == 1, timeout=_WAIT_MS)
    assert host.rows() == [("OnDisk", "marker", "", "0x00000020", "Full scan match at 0x20")]


def test_scan_failure_clears_the_results_tree(
    qtbot: QtBot,
    host: _SignaturesHost,
    document: intellicrack_hexcore.HexDocument,
    tmp_path: Path,
) -> None:
    """A scan whose document read fails ends with an empty results tree.

    Args:
        qtbot: pytest-qt fixture used to wait for the worker.
        host: Host whose signatures tab is built.
        document: Real document the failing API wraps.
        tmp_path: Per-test temporary directory.
    """
    host.use_document(_MemoryViewDocument(document, None, None))
    host.set_db_path(_write_json(tmp_path / "die.json", []))
    host.scan()
    host.add_row("stale")
    qtbot.waitUntil(lambda: host.tree.topLevelItemCount() == 0, timeout=_WAIT_MS)
    assert host.rows() == []


def test_finished_renders_formatted_rows_with_tooltips_and_replaces_old_rows(host: _SignaturesHost) -> None:
    """Each match becomes one row with an eight-digit hex offset, missing keys become empty text, and old rows are dropped.

    Args:
        host: Host whose signatures tab is built.
    """
    host.add_row("old")
    host.finished([
        {"name": "A", "type": "t", "version": "v", "offset": 255, "details": "d"},
        {"name": "B", "offset": "n/a"},
        {},
    ])
    assert host.rows() == [
        ("A", "t", "v", "0x000000FF", "d"),
        ("B", "", "", "n/a", ""),
        ("", "", "", "0x00000000", ""),
    ]
    first = host.tree.topLevelItem(0)
    assert first is not None
    assert [first.toolTip(column) for column in range(_COLUMN_COUNT)] == ["A", "t", "v", "0x000000FF", "d"]


def test_finished_obj_renders_lists_and_ignores_other_payloads(host: _SignaturesHost) -> None:
    """The untyped forwarder renders a list of matches and leaves the tree alone for any other payload.

    Args:
        host: Host whose signatures tab is built.
    """
    host.add_row("keep")
    host.finished_obj({"name": "not a list"})
    host.finished_obj(None)
    assert host.rows() == [("keep", "", "", "", "")]
    host.finished_obj([{"name": "Hit", "offset": 1}])
    assert host.rows() == [("Hit", "", "", "0x00000001", "")]


def test_bridge_success_renders_a_match_list(host: _SignaturesHost) -> None:
    """A list returned by a bridge scan is rendered like a worker result.

    Args:
        host: Host whose signatures tab is built.
    """
    host.bridge_success([{"name": "BridgeHit", "type": "ndb", "version": "", "offset": 0x20, "details": "Pattern match at 0x20"}])
    assert host.rows() == [("BridgeHit", "ndb", "", "0x00000020", "Pattern match at 0x20")]


def test_bridge_success_ignores_a_result_that_is_not_a_list(host: _SignaturesHost) -> None:
    """A bridge result of any other type leaves the existing rows alone instead of being iterated.

    Args:
        host: Host whose signatures tab is built.
    """
    host.add_row("keep")
    host.bridge_success({"name": "not a list"})
    host.bridge_success("text")
    assert host.rows() == [("keep", "", "", "", "")]


def test_bridge_error_and_worker_error_clear_the_results(host: _SignaturesHost) -> None:
    """A failed bridge scan or a failed worker scan empties the results tree.

    Args:
        host: Host whose signatures tab is built.
    """
    host.add_row("first")
    host.bridge_error(RuntimeError("bridge failed"))
    assert host.rows() == []

    host.add_row("second")
    host.error_obj(ValueError("worker failed"))
    assert host.rows() == []

    host.add_row("third")
    host.error("plain message")
    assert host.rows() == []


def test_handlers_tolerate_a_missing_results_tree(host: _SignaturesHost) -> None:
    """Result and error handlers return quietly when the results tree has not been created.

    Args:
        host: Host whose signatures tab is built.
    """
    detached = host.tree
    detached.addTopLevelItem(QTreeWidgetItem(["untouched", "", "", "", ""]))
    host.drop_tree()

    host.finished([{"name": "Hit"}])
    host.finished_obj([{"name": "Hit"}])
    host.bridge_success([{"name": "Hit"}])
    host.bridge_error(RuntimeError("failed"))
    host.error_obj(RuntimeError("failed"))
    host.error("failed")

    assert detached.topLevelItemCount() == 1


def test_double_clicking_a_result_moves_the_hex_widget_to_its_offset(host: _SignaturesHost, hex_widget: HexEditorWidget) -> None:
    """Double-clicking a result row navigates to the offset shown in its fourth column.

    Args:
        host: Host whose signatures tab is built.
        hex_widget: Widget the host navigates.
    """
    host.finished([{"name": "Hit", "offset": 0x2A}])
    item = host.tree.topLevelItem(0)
    assert item is not None
    assert item.text(3) == "0x0000002A"
    host.tree.itemDoubleClicked.emit(item, 0)
    assert _cursor(hex_widget) == 0x2A


def test_double_clicking_a_row_with_an_unparseable_offset_does_not_navigate(host: _SignaturesHost, hex_widget: HexEditorWidget) -> None:
    """A row whose offset text is not hexadecimal leaves the cursor where it was.

    Args:
        host: Host whose signatures tab is built.
        hex_widget: Widget the host navigates.
    """
    hex_widget.goto_offset(5)
    host.finished([{"name": "Odd", "offset": "n/a"}])
    item = host.tree.topLevelItem(0)
    assert item is not None
    host.double_click(item, 3)
    assert _cursor(hex_widget) == 5


def test_entries_with_an_empty_pattern_are_never_reported_as_matches(tmp_path: Path) -> None:
    """A custom or DIE entry whose pattern decodes to no bytes has nothing to match and must not be reported.

    Args:
        tmp_path: Per-test temporary directory.
    """
    custom = _write_json(tmp_path / "custom.json", [{"name": "NoPattern"}, {"name": "BlankPattern", "pattern": "  "}])
    assert execute_signature_scan(_DIE_DOC, "custom", custom) == []

    die = _write_json(
        tmp_path / "die.json",
        [
            {"name": "EmptyEntryPoint", "patterns": [""]},
            {"name": "EmptyAnywhere", "patterns": [{"pattern": "", "offset": "any"}]},
        ],
    )
    assert execute_signature_scan(_DIE_DOC, "die", die) == []


def test_clamav_ndb_wildcards_have_clamav_semantics(tmp_path: Path) -> None:
    """In an ``.ndb`` signature ``*`` stands for any number of bytes and ``??`` for exactly one byte.

    Args:
        tmp_path: Per-test temporary directory.
    """
    database = _write_lines(tmp_path / "wild.ndb", ["Star:0:*:de*ad", "Pair:0:*:de??ad"])

    def names(document: bytes) -> list[str]:
        """Scan a document with the wildcard database and list the matched signature names.

        Args:
            document: Document bytes to scan.

        Returns:
            list[str]: Names of the signatures that matched, in database order.
        """
        return [str(match["name"]) for match in execute_signature_scan(document, "clamav", database)]

    assert names(b"\x00\xde\x11\x22\x33\xad\x00") == ["Star"]
    assert names(b"\x00\xde\x11\xad\x00") == ["Star", "Pair"]
    assert "Pair" not in names(b"\x00\xde\xad\x00")


def test_negative_fixed_offsets_never_match_bytes_counted_from_the_end(tmp_path: Path) -> None:
    """A negative fixed offset is not a position in the document, so it must not match the byte that many places from the end.

    Args:
        tmp_path: Per-test temporary directory.
    """
    document = _blob(8, (5, b"\xaa"))
    assert document[-3:-2] == b"\xaa"

    custom = _write_json(tmp_path / "custom.json", [{"name": "Custom", "pattern": "aa", "offset": "-3"}])
    assert execute_signature_scan(document, "custom", custom) == []

    die = _write_json(tmp_path / "die.json", [{"name": "Die", "patterns": [{"pattern": "aa", "offset": "-3"}]}])
    assert execute_signature_scan(document, "die", die) == []

    ndb = _write_lines(tmp_path / "negative.ndb", ["Ndb:0:-3:aa"])
    assert execute_signature_scan(document, "clamav", ndb) == []
