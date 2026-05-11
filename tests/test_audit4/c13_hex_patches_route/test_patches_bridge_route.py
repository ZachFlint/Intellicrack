# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for audit4 C13 (F-0007): hex patches bridge routing.

The defect: ``PatchesMixin._on_export_patches`` and
``_on_import_patches`` previously called ``document.export_patches_*``
and ``document.import_patches_*`` directly. The bridge's
``export_patches`` / ``import_patches`` methods exist precisely so the
GUI, AI tools and CLI agree on patch wire-format bytes including the
bridge's Python-only fallback for hexcore builds without a native IPS
exporter. The panel-side path skipped that fallback and produced
different bytes when the native build was missing.

The fix routes both ends of the panel patch flow through the bridge:

- ``_on_export_patches`` calls ``bridge.export_patches(format, original_path)``
  via ``run_bridge_coroutine`` and base64-decodes the result before
  writing to disk.
- ``_on_import_patches`` reads the file, base64-encodes the bytes, and
  calls ``bridge.import_patches(b64, original_path)``. The bridge
  inspects magic bytes and dispatches to the correct format.
- BPS/UPS export and import require the original unmodified file on
  disk; the panel passes ``self.file_path`` and rejects the operation
  with a user-visible warning if no source file is available.

These tests construct a ``PatchesMixin``-backed harness wired to a fake
bridge that records every call, then drive both the export and import
paths and assert the bridge contract is honoured.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Any, Final

import pytest
from PyQt6.QtWidgets import QApplication, QFileDialog, QTreeWidget, QTreeWidgetItem, QWidget

from intellicrack.ui.panels.hex_editor._patches import PatchesMixin


if TYPE_CHECKING:
    from collections.abc import Callable, Generator
    from pathlib import Path


_DOC_LEN: Final[int] = 64
_PATCH_OFFSET: Final[int] = 0x10
_PATCH_BYTES: Final[bytes] = b"PATCH\x00\x00\x10\x00\x01ZEOF"
_BPS_BYTES: Final[bytes] = b"BPS1\x00\x00\x00\x00"


@pytest.fixture(scope="module")
def qapp() -> Generator[QApplication]:
    """Provide a process-wide ``QApplication`` for Qt widget construction.

    Yields:
        Generator[QApplication]: Qt application instance shared across tests.
    """
    existing = QApplication.instance()
    if existing is not None and isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


class _FakeBridge:
    """Bridge stand-in recording every export/import call.

    The bridge methods are coroutines in production; the harness wraps
    them in real ``async def`` so ``run_bridge_coroutine`` accepts them.
    """

    def __init__(self, export_payload: bytes, import_count: int) -> None:
        """Initialise the fake bridge with deterministic responses.

        Args:
            export_payload: Raw patch bytes the bridge will base64-encode and return.
            import_count: Count the bridge's ``import_patches`` will return.
        """
        self._export_payload: bytes = export_payload
        self._import_count: int = import_count
        self.export_calls: list[tuple[str, str | None]] = []
        self.import_calls: list[tuple[str, str | None]] = []

    async def export_patches(self, patch_format: str, original_path: str | None = None) -> str:
        """Record the export call and return the configured base64 payload.

        Args:
            patch_format: Format identifier the panel selected.
            original_path: Source file path the panel passed (BPS/UPS only).

        Returns:
            str: Base64-encoded patch bytes.
        """
        self.export_calls.append((patch_format, original_path))
        return base64.b64encode(self._export_payload).decode("ascii")

    async def import_patches(self, data_b64: str, original_path: str | None = None) -> int:
        """Record the import call and return the configured patch count.

        Args:
            data_b64: Base64-encoded patch bytes.
            original_path: Source file path the panel passed (BPS/UPS only).

        Returns:
            int: Configured patch count (validated against decoded payload).
        """
        decoded = base64.b64decode(data_b64.encode("ascii"))
        assert decoded, "panel must encode non-empty patch payload"
        self.import_calls.append((data_b64, original_path))
        return self._import_count


class _StubHexWidget:
    """Minimal hex widget used only so the import-success path has something to viewport."""

    def __init__(self) -> None:
        """Initialise the stub with no observed updates."""
        self.update_count: int = 0

    def _update_viewport(self) -> None:
        """Increment the observed update counter."""
        self.update_count += 1


class _PanelHarness(PatchesMixin, QWidget):
    """Test harness exposing :class:`PatchesMixin` against a fake bridge."""

    def __init__(self, bridge: _FakeBridge | None, file_path: Path | None = None) -> None:
        """Initialise the harness with the supplied bridge stub.

        Args:
            bridge: Stub bridge published to the mixin via ``_bridge``.
            file_path: Optional document file path the BPS/UPS branch checks.
        """
        super().__init__()
        self.document: Any | None = object()
        self._document: Any | None = self.document
        self._hex_widget: _StubHexWidget = _StubHexWidget()
        self._patches_tree: QTreeWidget | None = QTreeWidget(self)
        self._patches_tree.setColumnCount(3)
        self._patches_tree.addTopLevelItem(QTreeWidgetItem(["0x00000010", "0x00", "0x5A"]))
        self._original_data_cache: dict[int, int] = {_PATCH_OFFSET: 0}
        self._bridge: Any | None = bridge
        self.file_path: Path | None = file_path
        self.dialog_messages: list[tuple[str, str]] = []

    def trigger_export_for_test(self) -> None:
        """Drive the export path."""
        self._on_export_patches()

    def trigger_import_for_test(self) -> None:
        """Drive the import path."""
        self._on_import_patches()

    def hex_widget_update_count_for_test(self) -> int:
        """Return the number of viewport repaints the harness has observed.

        Returns:
            int: Stub hex widget's ``_update_viewport`` call count.
        """
        return self._hex_widget.update_count


@pytest.fixture
def silence_dialogs(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str, str]]:
    """Stub the panel's user-dialog helpers so tests don't block on Qt modals.

    Args:
        monkeypatch: pytest monkeypatch fixture.

    Returns:
        list[tuple[str, str, str]]: Captured ``(kind, title, message)``
            tuples for assertions against user-facing surface text.
    """
    captured: list[tuple[str, str, str]] = []

    def _capture(kind: str) -> Callable[[object, str, str], None]:
        def _cap(_parent: object, title: str, message: str) -> None:
            captured.append((kind, title, message))

        return _cap

    monkeypatch.setattr(
        "intellicrack.ui.panels.hex_editor._patches.show_info",
        _capture("info"),
    )
    monkeypatch.setattr(
        "intellicrack.ui.panels.hex_editor._patches.show_warning",
        _capture("warning"),
    )
    return captured


@pytest.fixture
def stub_save_dialog_ips(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Make ``QFileDialog.getSaveFileName`` return a deterministic .ips path.

    Args:
        monkeypatch: pytest monkeypatch fixture.
        tmp_path: pytest temporary path fixture.

    Returns:
        Path: The path the stubbed dialog will return.
    """
    target = tmp_path / "audit4_c13.ips"

    def _save(*_args: object, **_kwargs: object) -> tuple[str, str]:
        return (str(target), "IPS Patches (*.ips)")

    monkeypatch.setattr(QFileDialog, "getSaveFileName", _save)
    return target


@pytest.fixture
def stub_save_dialog_bps(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Make ``QFileDialog.getSaveFileName`` return a deterministic .bps path.

    Args:
        monkeypatch: pytest monkeypatch fixture.
        tmp_path: pytest temporary path fixture.

    Returns:
        Path: The path the stubbed dialog will return.
    """
    target = tmp_path / "audit4_c13.bps"

    def _save(*_args: object, **_kwargs: object) -> tuple[str, str]:
        return (str(target), "BPS Patches (*.bps)")

    monkeypatch.setattr(QFileDialog, "getSaveFileName", _save)
    return target


@pytest.fixture
def stub_open_dialog_ips(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Make ``QFileDialog.getOpenFileName`` return a deterministic .ips path.

    Args:
        monkeypatch: pytest monkeypatch fixture.
        tmp_path: pytest temporary path fixture.

    Returns:
        Path: The path the stubbed dialog will return; written with sample IPS bytes.
    """
    source = tmp_path / "input_audit4_c13.ips"
    source.write_bytes(_PATCH_BYTES)

    def _open(*_args: object, **_kwargs: object) -> tuple[str, str]:
        return (str(source), "Patch Files (*.ips *.ips32 *.bps *.ups)")

    monkeypatch.setattr(QFileDialog, "getOpenFileName", _open)
    return source


@pytest.mark.usefixtures("qapp", "silence_dialogs")
class TestExportRoutesThroughBridge:
    """Export must call the bridge and decode base64 to disk verbatim."""

    @staticmethod
    def test_ips_export_writes_decoded_bytes(
        qapp: QApplication,
        stub_save_dialog_ips: Path,
    ) -> None:
        """``.ips`` export calls bridge with format=ips, original_path=None.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
            stub_save_dialog_ips: Path the stubbed save dialog returns.
        """
        del qapp
        bridge = _FakeBridge(export_payload=_PATCH_BYTES, import_count=0)
        harness = _PanelHarness(bridge)

        harness.trigger_export_for_test()

        assert bridge.export_calls == [("ips", None)], (
            "panel must call bridge.export_patches with the right format and no original_path for IPS"
        )
        written = stub_save_dialog_ips.read_bytes()
        assert written == _PATCH_BYTES, "panel must base64-decode the bridge payload and write the raw bytes verbatim"

    @staticmethod
    def test_bps_export_requires_file_path(
        qapp: QApplication,
        stub_save_dialog_bps: Path,
        silence_dialogs: list[tuple[str, str, str]],
    ) -> None:
        """``.bps`` export with no ``file_path`` warns the user and skips the bridge call.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
            stub_save_dialog_bps: Path the stubbed save dialog returns.
            silence_dialogs: Captured dialog messages from ``silence_dialogs`` fixture.
        """
        del qapp
        bridge = _FakeBridge(export_payload=_BPS_BYTES, import_count=0)
        harness = _PanelHarness(bridge, file_path=None)

        harness.trigger_export_for_test()

        assert bridge.export_calls == [], "panel must NOT call the bridge when BPS export lacks an original file"
        assert any(kind == "warning" for kind, _t, _m in silence_dialogs), (
            "panel must surface a warning when BPS export lacks an original file"
        )
        assert not stub_save_dialog_bps.exists(), "panel must not write a partial BPS file when prerequisites are missing"

    @staticmethod
    def test_bps_export_passes_file_path(
        qapp: QApplication,
        stub_save_dialog_bps: Path,
        tmp_path: Path,
    ) -> None:
        """``.bps`` export with a real file_path passes ``original_path`` to the bridge.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
            stub_save_dialog_bps: Path the stubbed save dialog returns.
            tmp_path: pytest temporary path fixture.
        """
        del qapp
        original = tmp_path / "audit4_c13_source.bin"
        original.write_bytes(b"\x00" * _DOC_LEN)
        bridge = _FakeBridge(export_payload=_BPS_BYTES, import_count=0)
        harness = _PanelHarness(bridge, file_path=original)

        harness.trigger_export_for_test()

        assert bridge.export_calls == [("bps", str(original))], "panel must pass the resolved original file path to the bridge"
        assert stub_save_dialog_bps.read_bytes() == _BPS_BYTES


@pytest.mark.usefixtures("qapp", "silence_dialogs")
class TestImportRoutesThroughBridge:
    """Import must read disk, base64-encode, and call the bridge."""

    @staticmethod
    def test_ips_import_calls_bridge_and_updates_viewport(
        qapp: QApplication,
        stub_open_dialog_ips: Path,
    ) -> None:
        """``.ips`` import sends base64 of file bytes, no original_path, and refreshes viewport.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
            stub_open_dialog_ips: Path of the stubbed source patch file.
        """
        del qapp
        bridge = _FakeBridge(export_payload=b"", import_count=3)
        harness = _PanelHarness(bridge)

        harness.trigger_import_for_test()

        assert len(bridge.import_calls) == 1
        sent_b64, sent_original = bridge.import_calls[0]
        assert sent_original is None, "panel must NOT supply original_path when importing an IPS patch"
        assert base64.b64decode(sent_b64.encode("ascii")) == _PATCH_BYTES, "panel must base64-encode the on-disk patch bytes verbatim"
        assert harness.hex_widget_update_count_for_test() == 1, "successful import must repaint the hex widget viewport exactly once"
        assert stub_open_dialog_ips.exists()

    @staticmethod
    def test_bps_import_without_file_path_skips_bridge(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        silence_dialogs: list[tuple[str, str, str]],
    ) -> None:
        """BPS import without a host file path must warn and skip the bridge.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
            monkeypatch: pytest monkeypatch fixture.
            tmp_path: pytest temporary path fixture.
            silence_dialogs: Captured dialog messages from ``silence_dialogs`` fixture.
        """
        del qapp
        source = tmp_path / "input.bps"
        source.write_bytes(_BPS_BYTES)

        def _open_bps(*_args: object, **_kwargs: object) -> tuple[str, str]:
            return (str(source), "Patch Files (*.ips *.ips32 *.bps *.ups)")

        monkeypatch.setattr(QFileDialog, "getOpenFileName", _open_bps)
        bridge = _FakeBridge(export_payload=b"", import_count=1)
        harness = _PanelHarness(bridge, file_path=None)

        harness.trigger_import_for_test()

        assert bridge.import_calls == [], "panel must NOT call the bridge when BPS import lacks an original file"
        assert any(kind == "warning" for kind, _t, _m in silence_dialogs), (
            "panel must surface a warning when BPS import lacks an original file"
        )

    @staticmethod
    def test_bps_import_passes_file_path(
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """BPS import with a real file_path passes ``original_path`` to the bridge.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
            monkeypatch: pytest monkeypatch fixture.
            tmp_path: pytest temporary path fixture.
        """
        del qapp
        source = tmp_path / "input.bps"
        source.write_bytes(_BPS_BYTES)
        original = tmp_path / "src.bin"
        original.write_bytes(b"\x00" * _DOC_LEN)

        def _open_bps(*_args: object, **_kwargs: object) -> tuple[str, str]:
            return (str(source), "Patch Files (*.ips *.ips32 *.bps *.ups)")

        monkeypatch.setattr(QFileDialog, "getOpenFileName", _open_bps)
        bridge = _FakeBridge(export_payload=b"", import_count=1)
        harness = _PanelHarness(bridge, file_path=original)

        harness.trigger_import_for_test()

        assert len(bridge.import_calls) == 1
        _b64, sent_original = bridge.import_calls[0]
        assert sent_original == str(original), "panel must pass the resolved original file path for BPS import"
