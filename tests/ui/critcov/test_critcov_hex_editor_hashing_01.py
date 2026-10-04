# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Coverage for the hashing and PE checksum mixin of the hex editor panel.

Every test drives the production code with real objects: genuine ``intellicrack_hexcore.HexDocument`` instances holding known bytes, the
real ``HexEditorBridge``, a real ``HexDocumentState``, a real ``HexEditorWidget``, the Qt controls built by
``HashingMixin._create_pe_checksum_group`` and the asynchronous worker used by the panel buttons. Expected digests come from ``hashlib``,
expected PE checksums from the ``pefile`` package on a real System32 DLL or from the published checksum algorithm applied to bytes the test
builds itself.
"""

from __future__ import annotations

import functools
import hashlib
import struct
import threading
import types
from pathlib import Path
from typing import TYPE_CHECKING, Any, override

import intellicrack_hexcore
import pefile
import pytest
from PyQt6.QtWidgets import QApplication, QComboBox, QLabel, QMessageBox, QVBoxLayout, QWidget

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.bridges.hex_state import HexDocumentEvent, HexDocumentState
from intellicrack.ui.panels.async_bridge import (
    GenericCallableWorker,
    bridge_workers_for,
    drain_bridge_workers,
    drain_bridge_workers_for,
    run_callable_async,
)
from intellicrack.ui.panels.hex_editor import hashing as hashing_module
from intellicrack.ui.panels.hex_editor.hashing import HashingMixin
from intellicrack.ui.panels.hex_editor_widget import HexEditorWidget


if TYPE_CHECKING:
    from collections.abc import Callable, Generator

    from pytestqt.qtbot import QtBot


pytestmark = pytest.mark.usefixtures("qapp")


_format_hash_result: Any = getattr(hashing_module, "_format_hash_result")
_format_hash_range_result: Any = getattr(hashing_module, "_format_hash_range_result")
_verify_pe_checksum: Any = getattr(hashing_module, "_verify_pe_checksum")

_SAMPLE: bytes = bytes((index * 31 + 7) & 0xFF for index in range(1000))
_OTHER: bytes = bytes((index * 17 + 3) & 0xFF for index in range(640))
_WAIT_MS: int = 20_000
_BLOCK_TIMEOUT_S: float = 30.0
_E_LFANEW: int = 0x80
_FIELD: int = _E_LFANEW + 4 + 20 + 64
_REPAIR_SOURCE: str = "hex-editor.hashing.repair_pe_checksum"
_ALGORITHMS: list[str] = ["sha256", "md5", "sha1", "nosuchalgo"]


class _CountingHexWidget(HexEditorWidget):
    """Real hex editor widget that counts how often its viewport repaint hook runs.

    Attributes:
        viewport_updates: Number of times ``_update_viewport`` was invoked.
    """

    viewport_updates: int = 0

    @override
    def _update_viewport(self) -> None:
        """Count the repaint request and forward it to the real implementation."""
        self.viewport_updates += 1
        super()._update_viewport()


class _EventLog:
    """Observer callback that records every event a ``HexDocumentState`` delivers, with a copy of its payload, in order."""

    def __init__(self) -> None:
        """Start with an empty event list."""
        self.events: list[tuple[HexDocumentEvent, dict[str, Any]]] = []

    def __call__(self, event: HexDocumentEvent, data: dict[str, Any]) -> None:
        """Record one delivered event.

        Args:
            event: Event kind the state holder emitted.
            data: Payload delivered with the event.
        """
        self.events.append((event, dict(data)))

    def modified(self) -> list[dict[str, Any]]:
        """Return the payloads of the data-modified events seen so far.

        Returns:
            list[dict[str, Any]]: Payload of each ``DATA_MODIFIED`` event, in order.
        """
        return [data for event, data in self.events if event is HexDocumentEvent.DATA_MODIFIED]


class _HashingHost(HashingMixin, QWidget):
    """Concrete widget host that exposes the hashing mixin's slots to the tests."""

    def __init__(
        self,
        document: object | None,
        *,
        file_path: Path | None = None,
        state_holder: HexDocumentState | None = None,
        hex_widget: object | None = None,
    ) -> None:
        """Create a host with the algorithm selector, result label and PE checksum group built.

        Args:
            document: Document the mixin operates on, or ``None``.
            file_path: Path the panel reports as its own ``file_path``.
            state_holder: Real state holder the repair flow notifies.
            hex_widget: Object the repair flow asks to refresh its viewport.
        """
        super().__init__()
        self.document = document
        self._document = document
        self._hex_widget = hex_widget
        self.file_path = file_path
        self.state_holder = state_holder
        self._custom_crc_worker = None
        self._selection_start = -1
        self._selection_end = -1
        self._hash_worker = None
        self._pe_checksum_worker = None
        combo = QComboBox()
        combo.addItems(_ALGORITHMS)
        self._hash_algo_combo = combo
        self._hash_result_label = QLabel("")
        layout = QVBoxLayout(self)
        layout.addWidget(combo)
        layout.addWidget(self._hash_result_label)
        layout.addWidget(self._create_pe_checksum_group())

    @property
    def label(self) -> QLabel:
        """The hash result label created by the host.

        Returns:
            QLabel: The result label.
        """
        label = self._hash_result_label
        assert label is not None
        return label

    @property
    def status(self) -> QLabel:
        """The PE checksum status label built by the mixin.

        Returns:
            QLabel: The status label.
        """
        status = self._pe_checksum_status
        assert status is not None
        return status

    @property
    def hash_worker(self) -> GenericCallableWorker | None:
        """The worker the hash slots started most recently.

        Returns:
            GenericCallableWorker | None: The worker, or ``None`` when none was started.
        """
        return self._hash_worker

    @property
    def pe_worker(self) -> GenericCallableWorker | None:
        """The worker the PE checksum slots started most recently.

        Returns:
            GenericCallableWorker | None: The worker, or ``None`` when none was started.
        """
        return self._pe_checksum_worker

    def adopt_hash_worker(self, worker: GenericCallableWorker) -> None:
        """Record a worker as the host's current hash worker.

        Args:
            worker: The worker to record.
        """
        self._hash_worker = worker

    def adopt_pe_worker(self, worker: GenericCallableWorker) -> None:
        """Record a worker as the host's current PE checksum worker.

        Args:
            worker: The worker to record.
        """
        self._pe_checksum_worker = worker

    def drop_document(self) -> None:
        """Forget the document so the slots see no document open."""
        self.document = None

    def drop_combo(self) -> None:
        """Forget the algorithm selector so the slots see it as not yet created."""
        self._hash_algo_combo = None

    def drop_label(self) -> None:
        """Forget the result label so the slots see it as not yet created."""
        self._hash_result_label = None

    def drop_status(self) -> None:
        """Forget the status label so the slots see it as not yet created."""
        self._pe_checksum_status = None

    def use_bridge(self, bridge: HexEditorBridge | None) -> None:
        """Install the bridge the slots read through ``getattr``.

        Args:
            bridge: Bridge to attach, or ``None`` for no bridge.
        """
        setattr(self, "_bridge", bridge)

    def use_panel_path(self, value: object) -> None:
        """Install the value the panel reports as its ``file_path``.

        Args:
            value: Any object, including ones that are not valid paths.
        """
        setattr(self, "file_path", value)

    def select(self, start: int, end: int) -> None:
        """Set the selection range the selection hash reads.

        Args:
            start: Selection start offset.
            end: Selection end offset.
        """
        self._selection_start = start
        self._selection_end = end

    def choose(self, algorithm: str) -> None:
        """Pick the algorithm shown in the selector.

        Args:
            algorithm: Item text to select.
        """
        combo = self._hash_algo_combo
        assert combo is not None
        combo.setCurrentText(algorithm)

    def calculate(self) -> None:
        """Invoke the slot the hash button triggers."""
        self._on_calculate_hash()

    def hash_selection(self) -> None:
        """Invoke the slot the selection hash button triggers."""
        self._on_hash_selection()

    def verify(self) -> None:
        """Invoke the slot the Verify button triggers."""
        self._on_verify_pe_checksum()

    def repair(self) -> None:
        """Invoke the slot the Repair button triggers."""
        self._on_repair_pe_checksum()

    def custom_crc(self) -> None:
        """Invoke the slot the custom CRC button triggers."""
        self._on_custom_crc()

    def resolve_path(self) -> str | None:
        """Resolve the custom CRC file source.

        Returns:
            str | None: The path the mixin chose, or ``None``.
        """
        return self._resolve_custom_crc_file_path()

    def field_offset(self) -> int | None:
        """Locate the PE checksum field.

        Returns:
            int | None: Absolute offset of the field, or ``None``.
        """
        return self._pe_checksum_field_offset()

    def repair_and_notify(self, bridge: HexEditorBridge | None, checksum_offset: int | None) -> object:
        """Run the repair body the worker executes.

        Args:
            bridge: Bridge to route the repair through, or ``None``.
            checksum_offset: Resolved checksum field offset, or ``None``.

        Returns:
            object: Whatever the repair call returned.
        """
        return self._repair_pe_checksum_and_notify(bridge, checksum_offset)

    def spawn(
        self,
        existing: GenericCallableWorker | None,
        func: Callable[..., object],
        args: tuple[object, ...],
        on_success: Callable[[object], None],
        on_error: Callable[[object], None],
    ) -> GenericCallableWorker | None:
        """Start a worker through the mixin's dispatcher.

        Args:
            existing: Previously tracked worker.
            func: Callable to run on the worker.
            args: Positional arguments for ``func``.
            on_success: Success callback.
            on_error: Error callback.

        Returns:
            GenericCallableWorker | None: The new worker, or ``None`` when ``existing`` is still running.
        """
        return self._spawn_hex_worker(existing, func, args, on_success, on_error)

    def notify_modified(self, offset: int, length: int, *, source: str) -> None:
        """Publish a modification through the mixin's state holder hook.

        Args:
            offset: Start of the modified range.
            length: Length of the modified range.
            source: Loop-guard identifier.
        """
        self._notify_state_data_modified_for_hashing(offset, length, source=source)

    def hash_ready(self, result: object) -> None:
        """Deliver a worker result to the hash result handler.

        Args:
            result: Raw object the worker emitted.
        """
        self._on_hash_result_ready(result)

    def hash_error(self, exc: object) -> None:
        """Deliver a worker failure to the hash error handler.

        Args:
            exc: Exception the worker raised.
        """
        self._on_hash_error(exc)

    def apply_verification(self, info: object) -> None:
        """Deliver a verification result to the status updater.

        Args:
            info: Raw result of ``verify_pe_checksum``.
        """
        self._apply_pe_checksum_verification(info)

    def verify_error(self, exc: object) -> None:
        """Deliver a verification failure to its handler.

        Args:
            exc: Exception the worker raised.
        """
        self._on_pe_checksum_verify_error(exc)

    def repair_error(self, exc: object) -> None:
        """Deliver a repair failure to its handler.

        Args:
            exc: Exception the worker raised.
        """
        self._on_pe_checksum_repair_error(exc)

    def repaired(self, result: object) -> None:
        """Deliver a successful repair to its completion handler.

        Args:
            result: Raw return value of the repair call.
        """
        self._on_pe_checksum_repaired(result)

    def apply_post_repair(self, info: object) -> None:
        """Deliver a post-repair verification result to the status updater.

        Args:
            info: Raw result of ``verify_pe_checksum``.
        """
        self._apply_post_repair_verification(info)

    def post_repair_error(self, exc: object) -> None:
        """Deliver a post-repair verification failure to its handler.

        Args:
            exc: Exception the worker raised.
        """
        self._on_post_repair_verify_error(exc)


class _PlainHost(HashingMixin):
    """Host that carries the mixin without being a widget."""

    def __init__(self, document: object | None) -> None:
        """Create a host holding a status label but no widget parentage.

        Args:
            document: Document the mixin operates on, or ``None``.
        """
        self.document = document
        self._document = document
        self._hex_widget = None
        self._hash_algo_combo = None
        self._hash_result_label = None
        self.state_holder = None
        self.file_path = None
        self._selection_start = -1
        self._selection_end = -1
        self._pe_checksum_status = QLabel("Not verified")

    @property
    def status(self) -> QLabel:
        """The PE checksum status label.

        Returns:
            QLabel: The status label.
        """
        status = self._pe_checksum_status
        assert status is not None
        return status

    def custom_crc(self) -> None:
        """Invoke the slot the custom CRC button triggers."""
        self._on_custom_crc()

    def repair_error(self, exc: object) -> None:
        """Deliver a repair failure to its handler.

        Args:
            exc: Exception the worker raised.
        """
        self._on_pe_checksum_repair_error(exc)


def _open_bytes(data: bytes) -> intellicrack_hexcore.HexDocument:
    """Open a real in-memory document over ``data``.

    Args:
        data: Document contents.

    Returns:
        intellicrack_hexcore.HexDocument: The document.
    """
    return intellicrack_hexcore.HexDocument.open_bytes(data)


def _build_pe(*, stored: int = 0, body_len: int = 200) -> bytes:
    """Build a PE-shaped image with a patterned body and a chosen stored checksum.

    The layout follows the PE format: a DOS header whose offset 0x3C holds ``e_lfanew``, the four-byte PE signature, a 20-byte COFF header
    and a 224-byte optional header whose ``CheckSum`` field sits 64 bytes in.

    Args:
        stored: Value written into the ``CheckSum`` field.
        body_len: Number of bytes following the headers; must be even.

    Returns:
        bytes: The image.
    """
    image = bytearray((index * 7 + 3) & 0xFF for index in range(_E_LFANEW + 4 + 20 + 224 + body_len))
    image[0:2] = b"MZ"
    image[0x3C:0x40] = struct.pack("<I", _E_LFANEW)
    image[_E_LFANEW : _E_LFANEW + 4] = b"PE\x00\x00"
    image[_FIELD : _FIELD + 4] = struct.pack("<I", stored)
    return bytes(image)


def _pe_checksum(data: bytes, field_offset: int) -> int:
    """Compute the Microsoft PE checksum with the published algorithm.

    All 16-bit little-endian words are summed with the checksum field treated as zero, carries are folded back in, and the file length
    is added.

    Args:
        data: Complete image.
        field_offset: Offset of the four-byte ``CheckSum`` field.

    Returns:
        int: The checksum the field should hold.
    """
    buffer = bytearray(data)
    buffer[field_offset : field_offset + 4] = b"\x00\x00\x00\x00"
    if len(buffer) % 2:
        buffer.append(0)
    total = 0
    for (word,) in struct.iter_unpack("<H", bytes(buffer)):
        total += word
        if total >= 0x100000000:
            total = (total & 0xFFFFFFFF) + (total >> 32)
    total = (total & 0xFFFF) + (total >> 16)
    total += total >> 16
    total &= 0xFFFF
    return total + len(data)


def _dos_image(total: int, e_lfanew: int, *, magic: bytes = b"MZ", signature_at: int | None = None) -> bytes:
    """Build a zero-filled image with only the DOS header fields the offset resolver reads.

    Args:
        total: Image length in bytes.
        e_lfanew: Value stored at offset 0x3C when the image is long enough to hold it.
        magic: First two bytes of the image.
        signature_at: Offset at which to place the four-byte PE signature, or ``None`` for no signature.

    Returns:
        bytes: The image.
    """
    image = bytearray(total)
    image[0:2] = magic
    if total >= 0x40:
        image[0x3C:0x40] = struct.pack("<I", e_lfanew)
    if signature_at is not None:
        image[signature_at : signature_at + 4] = b"PE\x00\x00"
    return bytes(image)


def _real_dll_oracle(raw: bytes) -> tuple[int, int, int]:
    """Read the stored checksum, the correct checksum and the field offset of a real PE through ``pefile``.

    Args:
        raw: Complete bytes of a real PE image.

    Returns:
        tuple[int, int, int]: Stored checksum, checksum ``pefile`` computes, and absolute offset of the checksum field.
    """
    parsed = pefile.PE(data=raw, fast_load=True)
    try:
        stored = int(parsed.OPTIONAL_HEADER.CheckSum)
        field_offset = int(parsed.OPTIONAL_HEADER.get_file_offset()) + 0x40
        calculated = int(parsed.generate_checksum())
    finally:
        parsed.close()
    return stored, calculated, field_offset


def _ignore(_value: object) -> None:
    """Accept and discard a worker result.

    Args:
        _value: Ignored worker result.
    """


@pytest.fixture
def make_host(qtbot: QtBot) -> Generator[Callable[..., _HashingHost]]:
    """Provide a factory for hosts whose workers are joined on teardown.

    Args:
        qtbot: pytest-qt fixture that owns the hosts.

    Yields:
        Callable[..., _HashingHost]: Factory taking the document and optional collaborators.
    """
    created: list[_HashingHost] = []

    def _make(
        document: object | None,
        *,
        file_path: Path | None = None,
        state_holder: HexDocumentState | None = None,
        hex_widget: object | None = None,
    ) -> _HashingHost:
        """Create and register one host.

        Args:
            document: Document the host operates on.
            file_path: Path the panel reports as its own.
            state_holder: State holder the repair flow notifies.
            hex_widget: Object the repair flow refreshes.

        Returns:
            _HashingHost: The new host.
        """
        instance = _HashingHost(document, file_path=file_path, state_holder=state_holder, hex_widget=hex_widget)
        qtbot.addWidget(instance)
        created.append(instance)
        return instance

    try:
        yield _make
    finally:
        for instance in created:
            drain_bridge_workers_for(instance)
        drain_bridge_workers()


@pytest.fixture
def busy_host(make_host: Callable[..., _HashingHost]) -> Generator[_HashingHost]:
    """Provide a host whose hash and PE checksum worker slots hold a worker that is still running.

    Args:
        make_host: Factory for hosts.

    Yields:
        _HashingHost: Host over a PE image whose tracked workers are blocked until teardown.
    """
    host = make_host(_open_bytes(_build_pe()))
    release = threading.Event()
    worker = run_callable_async(release.wait, _BLOCK_TIMEOUT_S, parent=host)
    host.adopt_hash_worker(worker)
    host.adopt_pe_worker(worker)
    try:
        yield host
    finally:
        release.set()
        drain_bridge_workers_for(host)


@pytest.fixture
def backed_document(tmp_path: Path) -> Generator[tuple[intellicrack_hexcore.HexDocument, Path]]:
    """Open a real document over a file on disk and close it afterwards.

    Args:
        tmp_path: Per-test temporary directory.

    Yields:
        tuple[intellicrack_hexcore.HexDocument, Path]: The document and the file backing it.
    """
    target = tmp_path / "backing.bin"
    target.write_bytes(_SAMPLE)
    document = intellicrack_hexcore.HexDocument.open(str(target))
    try:
        yield document, target
    finally:
        document.close()


@pytest.fixture
def warnings_shown(monkeypatch: pytest.MonkeyPatch) -> list[tuple[QWidget | None, str, str]]:
    """Record every warning dialog the code under test requests instead of opening it.

    Args:
        monkeypatch: pytest monkeypatch fixture used to replace the static dialog function.

    Returns:
        list[tuple[QWidget | None, str, str]]: Parent, title and text of each requested warning, in order.
    """
    shown: list[tuple[QWidget | None, str, str]] = []

    def _record(parent: QWidget | None, title: str, text: str, *_args: object, **_kwargs: object) -> QMessageBox.StandardButton:
        """Remember the warning and report it as acknowledged.

        Args:
            parent: Widget that would own the dialog.
            title: Window title.
            text: Message body.
            *_args: Ignored extra dialog arguments.
            **_kwargs: Ignored extra dialog keyword arguments.

        Returns:
            QMessageBox.StandardButton: The Ok button.
        """
        shown.append((parent, title, text))
        return QMessageBox.StandardButton.Ok

    monkeypatch.setattr(QMessageBox, "warning", _record)
    return shown


@pytest.fixture
def answer_yes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Answer the repair confirmation prompt affirmatively.

    Args:
        monkeypatch: pytest monkeypatch fixture used to replace the static dialog function.
    """

    def _yes(*_args: object, **_kwargs: object) -> QMessageBox.StandardButton:
        """Report the Yes button.

        Args:
            *_args: Ignored dialog arguments.
            **_kwargs: Ignored dialog keyword arguments.

        Returns:
            QMessageBox.StandardButton: The Yes button.
        """
        return QMessageBox.StandardButton.Yes

    monkeypatch.setattr(QMessageBox, "question", _yes)


def test_hash_result_comes_from_attached_bridge_not_fallback_document() -> None:
    """With a bridge attached the digest is that of the bridge's document and the fallback document is ignored."""
    bridge = HexEditorBridge()
    bridge.document = _open_bytes(_SAMPLE)
    decoy = _open_bytes(_OTHER)

    result = _format_hash_result(bridge, decoy, "sha256")

    assert result == f"sha256: {hashlib.sha256(_SAMPLE).hexdigest()}"


def test_hash_result_falls_back_to_document_without_bridge() -> None:
    """Without a bridge the document hashes itself and the algorithm name is echoed back unchanged."""
    result = _format_hash_result(None, _open_bytes(_OTHER), "MD5")

    assert result == f"MD5: {hashlib.md5(_OTHER, usedforsecurity=False).hexdigest()}"


def test_hash_result_reraises_unsupported_algorithm() -> None:
    """An algorithm name the document rejects surfaces as a ``ValueError`` naming the algorithm."""
    with pytest.raises(ValueError, match="unsupported algorithm: nosuchalgo"):
        _format_hash_result(None, _open_bytes(_SAMPLE), "nosuchalgo")


def test_hash_range_result_comes_from_attached_bridge_not_fallback_document() -> None:
    """With a bridge attached the range digest is that of the bridge's document, and offsets render as upper-case hex."""
    bridge = HexEditorBridge()
    bridge.document = _open_bytes(_SAMPLE)
    decoy = _open_bytes(_OTHER)

    result = _format_hash_range_result(bridge, decoy, 5, 0x1F, "sha1")

    assert result == f"sha1 (0x5-0x1F): {hashlib.sha1(_SAMPLE[5:0x1F], usedforsecurity=False).hexdigest()}"


def test_hash_range_result_falls_back_to_document_without_bridge() -> None:
    """Without a bridge the document hashes the half-open byte range itself."""
    result = _format_hash_range_result(None, _open_bytes(_OTHER), 0x10, 0xAB, "sha256")

    assert result == f"sha256 (0x10-0xAB): {hashlib.sha256(_OTHER[0x10:0xAB]).hexdigest()}"


def test_hash_range_result_reraises_inverted_range() -> None:
    """A range whose start lies past its end surfaces as a ``ValueError`` describing the range."""
    with pytest.raises(ValueError, match="invalid range"):
        _format_hash_range_result(None, _open_bytes(_SAMPLE), 9, 3, "sha1")


def test_verify_checksum_comes_from_attached_bridge_not_fallback_document() -> None:
    """With a bridge attached the verification describes the bridge's image and the fallback document is ignored."""
    bridged = _build_pe(stored=0, body_len=200)
    bridge = HexEditorBridge()
    bridge.document = _open_bytes(bridged)
    decoy = _open_bytes(_build_pe(stored=0x1234, body_len=100))

    info = _verify_pe_checksum(bridge, decoy)

    assert info == {"stored": 0, "calculated": _pe_checksum(bridged, _FIELD), "offset": _FIELD, "valid": False}


def test_verify_checksum_falls_back_to_document_without_bridge() -> None:
    """Without a bridge the document verifies itself and reports a matching checksum as valid."""
    correct = _pe_checksum(_build_pe(), _FIELD)

    info = _verify_pe_checksum(None, _open_bytes(_build_pe(stored=correct)))

    assert info == {"stored": correct, "calculated": correct, "offset": _FIELD, "valid": True}


def test_verify_checksum_agrees_with_pefile_on_real_dll(real_pe_dll: Path) -> None:
    """The verification of a real System32 DLL reports the same stored value, checksum and field offset as ``pefile``.

    Args:
        real_pe_dll: Real PE DLL fixture path.
    """
    raw = real_pe_dll.read_bytes()
    stored, calculated, field_offset = _real_dll_oracle(raw)

    info = _verify_pe_checksum(None, _open_bytes(raw))

    assert info == {"stored": stored, "calculated": calculated, "offset": field_offset, "valid": stored == calculated}


def test_notify_without_state_holder_does_nothing(make_host: Callable[..., _HashingHost]) -> None:
    """A host with no state holder accepts a modification notice and publishes nothing.

    Args:
        make_host: Factory for hosts.
    """
    host = make_host(_open_bytes(_SAMPLE))

    outcome: object = host.notify_modified(0, 4, source="critcov")

    assert host.state_holder is None
    assert outcome is None


def test_notify_with_holder_lacking_notify_hook_does_nothing(make_host: Callable[..., _HashingHost]) -> None:
    """A state holder object without a callable ``notify_data_modified`` is skipped instead of being called.

    Args:
        make_host: Factory for hosts.
    """
    host = make_host(_open_bytes(_SAMPLE))
    setattr(host, "state_holder", object())

    outcome: object = host.notify_modified(0, 4, source="critcov")

    assert outcome is None


def test_notify_publishes_range_and_source_to_state_holder(make_host: Callable[..., _HashingHost]) -> None:
    """A real state holder delivers the offset, length and source of the modification to its observers.

    Args:
        make_host: Factory for hosts.
    """
    holder = HexDocumentState()
    log = _EventLog()
    holder.register_callback(log, source_id="observer")
    host = make_host(_open_bytes(_SAMPLE), state_holder=holder)

    host.notify_modified(0x98, 4, source="critcov-source")

    assert log.modified() == [{"offset": 0x98, "length": 4, "source": "critcov-source"}]


def test_resolve_path_is_none_for_in_memory_document_without_panel_path(make_host: Callable[..., _HashingHost]) -> None:
    """A purely in-memory document with no panel path has no file for the streaming CRC worker.

    Args:
        make_host: Factory for hosts.
    """
    host = make_host(_open_bytes(_SAMPLE))

    assert host.resolve_path() is None


def test_resolve_path_is_none_without_document_or_panel_path(make_host: Callable[..., _HashingHost]) -> None:
    """With neither a panel path nor a document there is nothing to resolve.

    Args:
        make_host: Factory for hosts.
    """
    assert make_host(None).resolve_path() is None


def test_resolve_path_uses_document_path_when_panel_path_is_not_a_path(
    make_host: Callable[..., _HashingHost],
    backed_document: tuple[intellicrack_hexcore.HexDocument, Path],
) -> None:
    """A panel path that cannot be converted to a filesystem path is skipped and the document's own file is used.

    Args:
        make_host: Factory for hosts.
        backed_document: Document opened from a file on disk, with that file's path.
    """
    document, target = backed_document
    host = make_host(document)
    host.use_panel_path(123)

    resolved = host.resolve_path()

    assert resolved is not None
    assert Path(resolved).samefile(target)


@pytest.mark.parametrize("panel_path", ["", "missing-file.bin"], ids=["empty", "nonexistent"])
def test_resolve_path_skips_unusable_panel_candidates(
    make_host: Callable[..., _HashingHost],
    backed_document: tuple[intellicrack_hexcore.HexDocument, Path],
    tmp_path: Path,
    panel_path: str,
) -> None:
    """An empty or non-existent panel path is passed over and the next candidate, the document's file, is returned.

    Args:
        make_host: Factory for hosts.
        backed_document: Document opened from a file on disk, with that file's path.
        tmp_path: Per-test temporary directory.
        panel_path: Panel path to try first; relative names are placed inside ``tmp_path``.
    """
    document, target = backed_document
    host = make_host(document)
    host.use_panel_path(str(tmp_path / panel_path) if panel_path else "")

    resolved = host.resolve_path()

    assert resolved is not None
    assert Path(resolved).samefile(target)


def test_resolve_path_is_none_when_document_has_no_file_path_accessor(make_host: Callable[..., _HashingHost]) -> None:
    """A document object without a callable ``file_path`` contributes no candidate.

    Args:
        make_host: Factory for hosts.
    """
    assert make_host(object()).resolve_path() is None


def test_resolve_path_is_none_when_document_path_lookup_fails(make_host: Callable[..., _HashingHost], tmp_path: Path) -> None:
    """A ``file_path`` accessor that raises an ``OSError`` is tolerated and yields no candidate.

    Args:
        make_host: Factory for hosts.
        tmp_path: Per-test temporary directory; reading a directory as a file raises ``OSError``.
    """
    failing_document = types.SimpleNamespace(file_path=tmp_path.read_bytes)

    assert make_host(failing_document).resolve_path() is None


def test_resolve_path_accepts_path_like_document_path(make_host: Callable[..., _HashingHost], tmp_path: Path) -> None:
    """A ``file_path`` accessor that returns a path object rather than a string is converted and used.

    Args:
        make_host: Factory for hosts.
        tmp_path: Per-test temporary directory.
    """
    target = tmp_path / "pathlike.bin"
    target.write_bytes(_SAMPLE)
    document = types.SimpleNamespace(file_path=functools.partial(Path, str(target)))

    assert make_host(document).resolve_path() == str(target)


def test_resolve_path_ignores_document_path_of_unusable_type(make_host: Callable[..., _HashingHost]) -> None:
    """A ``file_path`` accessor that returns something that is not a path at all yields no candidate.

    Args:
        make_host: Factory for hosts.
    """
    document = types.SimpleNamespace(file_path=functools.partial(int, 7))

    assert make_host(document).resolve_path() is None


def test_spawn_declines_while_tracked_worker_is_still_running(busy_host: _HashingHost) -> None:
    """The dispatcher starts nothing and returns ``None`` while the previously tracked worker is still running.

    Args:
        busy_host: Host whose tracked workers are blocked.
    """
    running = busy_host.hash_worker
    assert running is not None

    started = busy_host.spawn(running, len, ("abc",), _ignore, _ignore)

    assert started is None
    assert bridge_workers_for(busy_host) == [running]


def test_calculate_hash_keeps_label_while_previous_hash_is_running(busy_host: _HashingHost) -> None:
    """Pressing the hash button during a running hash neither replaces the worker nor rewrites the label.

    Args:
        busy_host: Host whose tracked workers are blocked.
    """
    running = busy_host.hash_worker
    busy_host.label.setText("previous result")

    busy_host.calculate()

    assert busy_host.hash_worker is running
    assert busy_host.label.text() == "previous result"


def test_hash_selection_keeps_label_while_previous_hash_is_running(busy_host: _HashingHost) -> None:
    """Pressing the selection hash button during a running hash neither replaces the worker nor rewrites the label.

    Args:
        busy_host: Host whose tracked workers are blocked.
    """
    running = busy_host.hash_worker
    busy_host.select(2, 10)
    busy_host.label.setText("previous result")

    busy_host.hash_selection()

    assert busy_host.hash_worker is running
    assert busy_host.label.text() == "previous result"


def test_verify_keeps_status_while_previous_check_is_running(busy_host: _HashingHost) -> None:
    """Pressing Verify during a running PE checksum operation neither replaces the worker nor rewrites the status.

    Args:
        busy_host: Host whose tracked workers are blocked.
    """
    running = busy_host.pe_worker

    busy_host.verify()

    assert busy_host.pe_worker is running
    assert busy_host.status.text() == "Not verified"


@pytest.mark.usefixtures("answer_yes")
def test_repair_leaves_document_untouched_while_previous_check_is_running(busy_host: _HashingHost) -> None:
    """Confirming a repair during a running PE checksum operation changes neither the status nor the document.

    Args:
        busy_host: Host whose tracked workers are blocked.
    """
    document: Any = busy_host.document
    before = bytes(document.read(0, document.length()))
    running = busy_host.pe_worker

    busy_host.repair()

    assert busy_host.pe_worker is running
    assert busy_host.status.text() == "Not verified"
    assert bytes(document.read(0, document.length())) == before


def test_repaired_callback_keeps_status_while_previous_check_is_running(busy_host: _HashingHost) -> None:
    """The completion handler does not start the re-verification while the tracked worker is still running.

    Args:
        busy_host: Host whose tracked workers are blocked.
    """
    running = busy_host.pe_worker

    busy_host.repaired(None)

    assert busy_host.pe_worker is running
    assert busy_host.status.text() == "Not verified"


@pytest.mark.parametrize("missing", ["document", "combo", "label"])
def test_hash_slots_do_nothing_without_their_inputs(make_host: Callable[..., _HashingHost], missing: str) -> None:
    """Both hash slots return at once when the document, the algorithm selector or the result label is missing.

    Args:
        make_host: Factory for hosts.
        missing: Which input to remove.
    """
    host = make_host(_open_bytes(_SAMPLE))
    host.select(2, 10)
    label = host.label
    label.setText("untouched")
    if missing == "document":
        host.drop_document()
    elif missing == "combo":
        host.drop_combo()
    else:
        host.drop_label()

    host.calculate()
    host.hash_selection()

    assert host.hash_worker is None
    assert bridge_workers_for(host) == []
    assert label.text() == "untouched"


@pytest.mark.usefixtures("answer_yes")
def test_verify_and_repair_do_nothing_without_a_document(make_host: Callable[..., _HashingHost]) -> None:
    """Verify and Repair return at once when no document is open.

    Args:
        make_host: Factory for hosts.
    """
    host = make_host(_open_bytes(_build_pe()))
    host.drop_document()

    host.verify()
    host.repair()

    assert host.pe_worker is None
    assert bridge_workers_for(host) == []
    assert host.status.text() == "Not verified"


@pytest.mark.parametrize(
    ("start", "end"),
    [(-1, 8), (4, -1), (8, 8), (9, 3)],
    ids=["negative-start", "negative-end", "empty", "inverted"],
)
def test_hash_selection_reports_no_selection_for_unusable_range(
    make_host: Callable[..., _HashingHost],
    start: int,
    end: int,
) -> None:
    """A selection that is unset, empty or inverted is reported as such and no hash is started.

    Args:
        make_host: Factory for hosts.
        start: Selection start offset.
        end: Selection end offset.
    """
    host = make_host(_open_bytes(_SAMPLE))
    host.select(start, end)

    host.hash_selection()

    assert host.label.text() == "No selection"
    assert host.hash_worker is None
    assert bridge_workers_for(host) == []


def test_hash_result_handler_ignores_non_text_results(make_host: Callable[..., _HashingHost]) -> None:
    """Only a string result is shown; anything else leaves the label alone, and a missing label is tolerated.

    Args:
        make_host: Factory for hosts.
    """
    host = make_host(_open_bytes(_SAMPLE))
    label = host.label

    host.hash_ready("md5: 00")
    host.hash_ready(12345)
    assert label.text() == "md5: 00"

    host.drop_label()
    host.hash_ready("sha1: 11")
    assert label.text() == "md5: 00"


def test_hash_error_handler_shows_error_text(make_host: Callable[..., _HashingHost]) -> None:
    """A worker failure is shown on the label as ``Error: <message>``, and a missing label is tolerated.

    Args:
        make_host: Factory for hosts.
    """
    host = make_host(_open_bytes(_SAMPLE))
    label = host.label

    host.hash_error(RuntimeError("disk vanished"))
    assert label.text() == "Error: disk vanished"

    host.drop_label()
    host.hash_error(RuntimeError("ignored"))
    assert label.text() == "Error: disk vanished"


def test_verification_with_reason_shows_the_reason(make_host: Callable[..., _HashingHost]) -> None:
    """An invalid result that carries a reason shows that reason instead of the stored and expected values.

    Args:
        make_host: Factory for hosts.
    """
    host = make_host(_open_bytes(_SAMPLE))

    host.apply_verification({"valid": False, "reason": "optional header truncated", "stored": 1, "calculated": 2})

    assert host.status.text() == "optional header truncated"


def test_verification_result_is_ignored_without_status_label(make_host: Callable[..., _HashingHost]) -> None:
    """A verification result arriving after the status label is gone is dropped without raising.

    Args:
        make_host: Factory for hosts.
    """
    host = make_host(_open_bytes(_SAMPLE))
    status = host.status
    host.drop_status()

    host.apply_verification({"stored": 1, "calculated": 1})

    assert status.text() == "Not verified"


def test_verify_error_handler_shows_error_text(make_host: Callable[..., _HashingHost]) -> None:
    """A verification failure is shown as ``Error: <message>``, and a missing status label is tolerated.

    Args:
        make_host: Factory for hosts.
    """
    host = make_host(_open_bytes(_SAMPLE))
    status = host.status

    host.verify_error(ValueError("not a PE file"))
    assert status.text() == "Error: not a PE file"

    host.drop_status()
    host.verify_error(ValueError("ignored"))
    assert status.text() == "Error: not a PE file"


@pytest.mark.parametrize(
    ("info", "expected"),
    [
        pytest.param({"calculated": 0xBEEF}, "Repaired: 0x0000BEEF", id="calculated"),
        pytest.param({"stored": 0x10}, "Repaired: 0x00000010", id="falls-back-to-stored"),
        pytest.param({"calculated": "n/a"}, "Repaired", id="non-int-calculated"),
        pytest.param({}, "Repaired", id="empty-dict"),
        pytest.param(None, "Repaired", id="none"),
        pytest.param("text", "Repaired", id="text"),
    ],
)
def test_post_repair_verification_formats_checksum_or_plain_repaired(
    make_host: Callable[..., _HashingHost],
    info: object,
    expected: str,
) -> None:
    """The post-repair status shows the checksum as eight hex digits when one is available and plain ``Repaired`` otherwise.

    Args:
        make_host: Factory for hosts.
        info: Verification result delivered to the handler.
        expected: Status text the handler should produce.
    """
    host = make_host(_open_bytes(_SAMPLE))

    host.apply_post_repair(info)

    assert host.status.text() == expected


def test_post_repair_verification_is_ignored_without_status_label(make_host: Callable[..., _HashingHost]) -> None:
    """A post-repair result arriving after the status label is gone is dropped without raising.

    Args:
        make_host: Factory for hosts.
    """
    host = make_host(_open_bytes(_SAMPLE))
    status = host.status
    host.drop_status()

    host.apply_post_repair({"calculated": 1})

    assert status.text() == "Not verified"


def test_post_repair_verify_error_handler_shows_error_text(make_host: Callable[..., _HashingHost]) -> None:
    """A failed re-verification keeps the repair visible and appends the failure, and a missing status label is tolerated.

    Args:
        make_host: Factory for hosts.
    """
    host = make_host(_open_bytes(_SAMPLE))
    status = host.status

    host.post_repair_error(RuntimeError("scan interrupted"))
    assert status.text() == "Repaired (verify failed: scan interrupted)"

    host.drop_status()
    host.post_repair_error(RuntimeError("ignored"))
    assert status.text() == "Repaired (verify failed: scan interrupted)"


def test_repair_error_handler_warns_with_widget_parent_and_shows_error(
    make_host: Callable[..., _HashingHost],
    warnings_shown: list[tuple[QWidget | None, str, str]],
) -> None:
    """A repair failure raises a warning owned by the panel and shows ``Error: <message>`` on the status label.

    Args:
        make_host: Factory for hosts.
        warnings_shown: Recorder for requested warning dialogs.
    """
    host = make_host(_open_bytes(_SAMPLE))

    host.repair_error(RuntimeError("write refused"))

    assert warnings_shown == [(host, "Repair Failed", "write refused")]
    assert host.status.text() == "Error: write refused"


def test_repair_error_handler_warns_without_parent_for_non_widget_host(
    warnings_shown: list[tuple[QWidget | None, str, str]],
) -> None:
    """A host that is not a widget raises the repair warning with no parent and still updates the status.

    Args:
        warnings_shown: Recorder for requested warning dialogs.
    """
    host = _PlainHost(None)

    host.repair_error(RuntimeError("write refused"))

    assert warnings_shown == [(None, "Repair Failed", "write refused")]
    assert host.status.text() == "Error: write refused"


def test_repair_error_handler_tolerates_missing_status_label(
    make_host: Callable[..., _HashingHost],
    warnings_shown: list[tuple[QWidget | None, str, str]],
) -> None:
    """The warning is still raised when the status label is gone.

    Args:
        make_host: Factory for hosts.
        warnings_shown: Recorder for requested warning dialogs.
    """
    host = make_host(_open_bytes(_SAMPLE))
    status = host.status
    host.drop_status()

    host.repair_error(RuntimeError("write refused"))

    assert warnings_shown == [(host, "Repair Failed", "write refused")]
    assert status.text() == "Not verified"


def test_repaired_callback_tolerates_widget_without_viewport_hook(qtbot: QtBot, make_host: Callable[..., _HashingHost]) -> None:
    """A hex widget object without a callable ``_update_viewport`` is skipped and the re-verification still runs.

    Args:
        qtbot: pytest-qt fixture used to wait for the re-verification.
        make_host: Factory for hosts.
    """
    image = _build_pe()
    host = make_host(_open_bytes(image), hex_widget=object())

    host.repaired(None)

    qtbot.waitUntil(lambda: host.status.text() == f"Repaired: 0x{_pe_checksum(image, _FIELD):08X}", timeout=_WAIT_MS)


def test_field_offset_is_none_without_document(make_host: Callable[..., _HashingHost]) -> None:
    """Without a document there is no checksum field to locate.

    Args:
        make_host: Factory for hosts.
    """
    host = make_host(_open_bytes(_SAMPLE))
    host.drop_document()

    assert host.field_offset() is None


@pytest.mark.parametrize(
    ("image", "expected"),
    [
        pytest.param(_build_pe(), _FIELD, id="e_lfanew-0x80"),
        pytest.param(_dos_image(0x100, 0x40, signature_at=0x40), 0x40 + 4 + 20 + 64, id="e_lfanew-0x40"),
    ],
)
def test_field_offset_is_e_lfanew_plus_signature_coff_header_and_optional_header_displacement(
    make_host: Callable[..., _HashingHost],
    image: bytes,
    expected: int,
) -> None:
    """The checksum field lies at ``e_lfanew`` plus the 4-byte signature, the 20-byte COFF header and 64 header bytes.

    Args:
        make_host: Factory for hosts.
        image: Well-formed PE-shaped image.
        expected: Offset derived from the PE format.
    """
    assert make_host(_open_bytes(image)).field_offset() == expected


@pytest.mark.parametrize(
    "image",
    [
        pytest.param(_dos_image(0x3B, 0), id="shorter-than-dos-header"),
        pytest.param(_dos_image(0x100, 0x40, magic=b"ZM", signature_at=0x40), id="not-mz"),
        pytest.param(_dos_image(0x100, 0), id="e_lfanew-zero"),
        pytest.param(_dos_image(0x100, 0x200), id="e_lfanew-past-end"),
        pytest.param(_dos_image(0x100, 0x40), id="no-pe-signature"),
        pytest.param(_dos_image(0x40 + 4 + 20 + 30, 0x40, signature_at=0x40), id="optional-header-truncated"),
    ],
)
def test_field_offset_is_none_for_malformed_images(make_host: Callable[..., _HashingHost], image: bytes) -> None:
    """Images that are not well-formed PE files have no locatable checksum field.

    Args:
        make_host: Factory for hosts.
        image: Malformed image.
    """
    assert make_host(_open_bytes(image)).field_offset() is None


def test_field_offset_is_none_when_document_cannot_be_read(make_host: Callable[..., _HashingHost]) -> None:
    """An object that cannot report its length is tolerated and yields no offset.

    Args:
        make_host: Factory for hosts.
    """
    assert make_host(object()).field_offset() is None


def test_repair_body_requires_a_document(make_host: Callable[..., _HashingHost]) -> None:
    """The repair body refuses to run when the document disappeared before the worker started.

    Args:
        make_host: Factory for hosts.
    """
    host = make_host(_open_bytes(_build_pe()))
    host.drop_document()

    with pytest.raises(RuntimeError, match="document became unavailable before the PE checksum repair could run"):
        host.repair_and_notify(None, _FIELD)


def test_repair_body_writes_correct_checksum_and_notifies_observers(make_host: Callable[..., _HashingHost]) -> None:
    """Repairing through the document writes the correct checksum and publishes exactly that four-byte range to observers.

    Args:
        make_host: Factory for hosts.
    """
    image = _build_pe()
    document = _open_bytes(image)
    holder = HexDocumentState()
    log = _EventLog()
    holder.register_callback(log, source_id="observer")
    host = make_host(document, state_holder=holder)

    result = host.repair_and_notify(None, _FIELD)

    assert result is None
    assert document.read(_FIELD, 4) == struct.pack("<I", _pe_checksum(image, _FIELD))
    assert log.modified() == [{"offset": _FIELD, "length": 4, "source": _REPAIR_SOURCE}]


def test_repair_body_without_resolved_offset_repairs_but_publishes_nothing(make_host: Callable[..., _HashingHost]) -> None:
    """When the field offset could not be resolved the repair still happens but no modification is published.

    Args:
        make_host: Factory for hosts.
    """
    image = _build_pe()
    document = _open_bytes(image)
    holder = HexDocumentState()
    log = _EventLog()
    holder.register_callback(log, source_id="observer")
    host = make_host(document, state_holder=holder)

    host.repair_and_notify(None, None)

    assert document.read(_FIELD, 4) == struct.pack("<I", _pe_checksum(image, _FIELD))
    assert log.modified() == []


def test_repair_body_routes_through_attached_bridge(make_host: Callable[..., _HashingHost]) -> None:
    """With a bridge attached the bridge's document is repaired, the host's own document is not, and the bridge's report is returned.

    Args:
        make_host: Factory for hosts.
    """
    bridged_image = _build_pe(body_len=200)
    bridged = _open_bytes(bridged_image)
    bridge = HexEditorBridge()
    bridge.document = bridged
    hosted = _open_bytes(_build_pe(body_len=100))
    holder = HexDocumentState()
    log = _EventLog()
    holder.register_callback(log, source_id="observer")
    host = make_host(hosted, state_holder=holder)

    result = host.repair_and_notify(bridge, _FIELD)

    correct = _pe_checksum(bridged_image, _FIELD)
    assert result == {"old_checksum": 0, "new_checksum": correct, "offset": _FIELD}
    assert bridged.read(_FIELD, 4) == struct.pack("<I", correct)
    assert hosted.read(_FIELD, 4) == b"\x00\x00\x00\x00"
    assert log.modified() == [{"offset": _FIELD, "length": 4, "source": _REPAIR_SOURCE}]


def test_custom_crc_without_document_does_nothing(
    make_host: Callable[..., _HashingHost],
    warnings_shown: list[tuple[QWidget | None, str, str]],
) -> None:
    """The custom CRC slot returns at once when no document is open.

    Args:
        make_host: Factory for hosts.
        warnings_shown: Recorder for requested warning dialogs.
    """
    host = make_host(_open_bytes(_SAMPLE))
    host.drop_document()

    host.custom_crc()

    assert warnings_shown == []


def test_custom_crc_warns_when_document_length_is_unavailable(
    make_host: Callable[..., _HashingHost],
    warnings_shown: list[tuple[QWidget | None, str, str]],
) -> None:
    """A document that cannot report its length produces a warning owned by the panel, quoting the failure.

    Args:
        make_host: Factory for hosts.
        warnings_shown: Recorder for requested warning dialogs.
    """
    host = make_host(object())

    host.custom_crc()

    assert len(warnings_shown) == 1
    parent, title, text = warnings_shown[0]
    assert parent is host
    assert title == "Custom CRC"
    assert text.startswith("Failed to read document length:\n")
    assert text.endswith("has no attribute 'length'")


def test_custom_crc_stays_silent_for_non_widget_host_when_length_is_unavailable(
    warnings_shown: list[tuple[QWidget | None, str, str]],
) -> None:
    """A host that is not a widget has no dialog owner, so the length failure is swallowed without a warning.

    Args:
        warnings_shown: Recorder for requested warning dialogs.
    """
    host = _PlainHost(object())

    host.custom_crc()

    assert warnings_shown == []


@pytest.mark.parametrize("with_bridge", [False, True], ids=["document", "bridge"])
def test_calculate_hash_flow_shows_progress_then_digest(
    qtbot: QtBot,
    make_host: Callable[..., _HashingHost],
    *,
    with_bridge: bool,
) -> None:
    """The hash button shows a progress label at once and then the digest of the document that actually holds the bytes.

    Args:
        qtbot: pytest-qt fixture used to wait for the worker's result.
        make_host: Factory for hosts.
        with_bridge: Whether the bytes live in an attached bridge's document rather than the host's own.
    """
    document = _open_bytes(_SAMPLE)
    host = make_host(_open_bytes(_OTHER) if with_bridge else document)
    if with_bridge:
        bridge = HexEditorBridge()
        bridge.document = document
        host.use_bridge(bridge)
    host.choose("sha256")

    host.calculate()

    assert host.label.text() == "sha256: Computing..."
    expected = f"sha256: {hashlib.sha256(_SAMPLE).hexdigest()}"
    qtbot.waitUntil(lambda: host.label.text() == expected, timeout=_WAIT_MS)


def test_calculate_hash_flow_shows_error_for_unsupported_algorithm(qtbot: QtBot, make_host: Callable[..., _HashingHost]) -> None:
    """An algorithm the document rejects ends up on the label as an error naming the algorithm.

    Args:
        qtbot: pytest-qt fixture used to wait for the worker's result.
        make_host: Factory for hosts.
    """
    host = make_host(_open_bytes(_SAMPLE))
    host.choose("nosuchalgo")

    host.calculate()

    qtbot.waitUntil(lambda: host.label.text().startswith("Error:"), timeout=_WAIT_MS)
    assert "unsupported algorithm: nosuchalgo" in host.label.text()


def test_hash_selection_flow_shows_progress_then_range_digest(qtbot: QtBot, make_host: Callable[..., _HashingHost]) -> None:
    """The selection hash button shows a progress label at once and then the digest of exactly the selected bytes.

    Args:
        qtbot: pytest-qt fixture used to wait for the worker's result.
        make_host: Factory for hosts.
    """
    host = make_host(_open_bytes(_SAMPLE))
    host.choose("sha1")
    host.select(5, 0x1F)

    host.hash_selection()

    assert host.label.text() == "sha1 (0x5-0x1F): Computing..."
    expected = f"sha1 (0x5-0x1F): {hashlib.sha1(_SAMPLE[5:0x1F], usedforsecurity=False).hexdigest()}"
    qtbot.waitUntil(lambda: host.label.text() == expected, timeout=_WAIT_MS)


@pytest.mark.parametrize("with_bridge", [False, True], ids=["document", "bridge"])
@pytest.mark.parametrize("stored_is_correct", [True, False], ids=["valid", "invalid"])
def test_verify_flow_reports_valid_or_invalid_checksum(
    qtbot: QtBot,
    make_host: Callable[..., _HashingHost],
    *,
    with_bridge: bool,
    stored_is_correct: bool,
) -> None:
    """Verify shows a progress label at once and then whether the stored checksum matches the one computed for the image.

    Args:
        qtbot: pytest-qt fixture used to wait for the worker's result.
        make_host: Factory for hosts.
        with_bridge: Whether the image lives in an attached bridge's document rather than the host's own.
        stored_is_correct: Whether the image stores its correct checksum.
    """
    correct = _pe_checksum(_build_pe(), _FIELD)
    stored = correct if stored_is_correct else 0
    document = _open_bytes(_build_pe(stored=stored))
    host = make_host(_open_bytes(_build_pe(stored=0xFFFF, body_len=100)) if with_bridge else document)
    if with_bridge:
        bridge = HexEditorBridge()
        bridge.document = document
        host.use_bridge(bridge)

    host.verify()

    assert host.status.text() == "Verifying..."
    expected = f"Valid: 0x{correct:08X}" if stored_is_correct else f"Invalid: stored=0x{stored:08X}, expected=0x{correct:08X}"
    qtbot.waitUntil(lambda: host.status.text() == expected, timeout=_WAIT_MS)


def test_verify_flow_shows_error_for_image_that_is_not_a_pe(qtbot: QtBot, make_host: Callable[..., _HashingHost]) -> None:
    """Verifying a document without the ``MZ`` signature ends on an error status that carries the reason.

    Args:
        qtbot: pytest-qt fixture used to wait for the worker's result.
        make_host: Factory for hosts.
    """
    host = make_host(_open_bytes(bytes(0x80)))

    host.verify()

    qtbot.waitUntil(lambda: host.status.text().startswith("Error:"), timeout=_WAIT_MS)
    assert "missing MZ signature" in host.status.text()


def test_verify_flow_without_status_label_still_completes(make_host: Callable[..., _HashingHost]) -> None:
    """Verify works without a status label: the worker is started and its result is dropped quietly.

    Args:
        make_host: Factory for hosts.
    """
    host = make_host(_open_bytes(_build_pe()))
    status = host.status
    host.drop_status()

    host.verify()
    drain_bridge_workers_for(host)
    QApplication.processEvents()

    assert host.pe_worker is not None
    assert status.text() == "Not verified"


@pytest.mark.usefixtures("answer_yes")
def test_repair_flow_writes_checksum_notifies_refreshes_viewport_and_reports(
    qtbot: QtBot,
    make_host: Callable[..., _HashingHost],
) -> None:
    """Confirming a repair writes the correct checksum, notifies observers, refreshes the hex view and shows the repaired value.

    Args:
        qtbot: pytest-qt fixture used to wait for the re-verification.
        make_host: Factory for hosts.
    """
    image = _build_pe()
    correct = _pe_checksum(image, _FIELD)
    document = _open_bytes(image)
    holder = HexDocumentState()
    log = _EventLog()
    holder.register_callback(log, source_id="observer")
    widget = _CountingHexWidget()
    qtbot.addWidget(widget)
    widget.set_document(document)
    host = make_host(document, state_holder=holder, hex_widget=widget)
    updates_before = widget.viewport_updates

    host.repair()
    drain_bridge_workers_for(host)

    qtbot.waitUntil(lambda: host.status.text() == f"Repaired: 0x{correct:08X}", timeout=_WAIT_MS)
    assert document.read(_FIELD, 4) == struct.pack("<I", correct)
    assert log.modified() == [{"offset": _FIELD, "length": 4, "source": _REPAIR_SOURCE}]
    assert widget.viewport_updates > updates_before


@pytest.mark.usefixtures("answer_yes")
def test_repair_flow_matches_pefile_checksum_for_real_dll(
    qtbot: QtBot,
    make_host: Callable[..., _HashingHost],
    real_pe_dll: Path,
) -> None:
    """Repairing an in-memory copy of a real System32 DLL writes the checksum ``pefile`` computes at the offset ``pefile`` reports.

    Args:
        qtbot: pytest-qt fixture used to wait for the re-verification.
        make_host: Factory for hosts.
        real_pe_dll: Real PE DLL fixture path.
    """
    raw = real_pe_dll.read_bytes()
    _stored, correct, field_offset = _real_dll_oracle(raw)
    document = _open_bytes(raw)
    host = make_host(document)

    host.repair()
    drain_bridge_workers_for(host)

    qtbot.waitUntil(lambda: host.status.text() == f"Repaired: 0x{correct:08X}", timeout=_WAIT_MS)
    assert document.read(field_offset, 4) == struct.pack("<I", correct)


@pytest.mark.usefixtures("answer_yes")
def test_repair_flow_reports_failure_for_image_that_is_not_a_pe(
    qtbot: QtBot,
    make_host: Callable[..., _HashingHost],
    warnings_shown: list[tuple[QWidget | None, str, str]],
) -> None:
    """Repairing a document without the ``MZ`` signature warns, shows the error and leaves every byte unchanged.

    Args:
        qtbot: pytest-qt fixture used to wait for the failure to be delivered.
        make_host: Factory for hosts.
        warnings_shown: Recorder for requested warning dialogs.
    """
    document = _open_bytes(bytes(0x80))
    host = make_host(document)

    host.repair()
    drain_bridge_workers_for(host)

    qtbot.waitUntil(lambda: host.status.text().startswith("Error:"), timeout=_WAIT_MS)
    assert "missing MZ signature" in host.status.text()
    assert len(warnings_shown) == 1
    parent, title, text = warnings_shown[0]
    assert parent is host
    assert title == "Repair Failed"
    assert "missing MZ signature" in text
    assert document.read(0, 0x80) == bytes(0x80)
