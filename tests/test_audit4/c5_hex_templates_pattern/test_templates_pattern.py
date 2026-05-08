# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit4 C5 regression tests for templates + pattern editor mixins.

Covers the three findings shipped together in audit4 unit C5:

* **F-0003** -- Every byte / document mutation reachable from
  ``TemplatesMixin`` (template apply / import / remove and the PE/ELF
  auto-bookmark walk) must publish the matching
  :class:`HexDocumentState` event so observers (the hex viewport, the
  bridge layer, the AI tool registry) refresh after a GUI mutation
  instead of analysing stale state.

* **F-0012** -- Both the pattern editor and templates mixin must use
  the shared ``_sync_template_state`` helper to fully cover every
  state-holder sync path.  Tests register a recorder against the
  state holder and assert each user-action path (template apply,
  template import, template remove, pattern apply via interpreter,
  pattern apply via compile-register-apply) emits the matching
  notification.

* **F-0017** -- ``_on_pattern_apply`` has two execution branches: the
  HexPat interpreter path and the compile-register-apply path.  Both
  must emit the appropriate template notification.  The interpreter
  path emits ``notify_pattern_executed`` for the inline source; the
  compile path emits ``notify_template_registered`` for the new
  template **and** ``notify_pattern_executed`` for the apply.

All tests would fail against pre-audit code: the recorder would be
empty for the template / bookmark mutations, and the interpreter
branch of ``_on_pattern_apply`` would emit no notification at all.
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING, Any

import pytest
from PyQt6.QtWidgets import QComboBox, QFileDialog, QMessageBox, QTreeWidget, QWidget

from intellicrack.bridges.hex_state import HexDocumentEvent, HexDocumentState
from intellicrack.ui.panels.hex_editor._pattern_editor import PatternEditorMixin
from intellicrack.ui.panels.hex_editor._templates import TemplatesMixin


if TYPE_CHECKING:
    from pathlib import Path


# Real-world PE constants used to build a synthetic but valid PE
# header so the auto-bookmark walk traverses the DOS header, the
# PE signature, the optional header and a single section entry.
_PE_DOS_HEADER_SIZE: int = 0x40
_PE_LFANEW: int = 0x40
_PE_OPTIONAL_HEADER_OFFSET: int = 24
_PE_OPTIONAL_HEADER_SIZE: int = 224
_PE_SECTION_ENTRY_SIZE: int = 40
_PE_SECTION_COUNT: int = 1


def _build_minimal_pe() -> bytes:
    """Construct a synthetic PE buffer that survives the auto-bookmark walk.

    The buffer satisfies every length / signature check that
    :meth:`TemplatesMixin._bookmark_pe_structure` performs and exposes
    a single section header so the section bookmark loop runs at
    least once.

    Returns:
        bytes: PE-shaped payload large enough to bookmark.
    """
    body = bytearray(b"\x00" * 0x800)
    body[0:2] = b"MZ"
    struct.pack_into("<I", body, 0x3C, _PE_LFANEW)
    body[_PE_LFANEW : _PE_LFANEW + 4] = b"PE\x00\x00"
    coff_offset = _PE_LFANEW + 4
    struct.pack_into("<H", body, coff_offset + 2, _PE_SECTION_COUNT)
    struct.pack_into("<H", body, coff_offset + 16, _PE_OPTIONAL_HEADER_SIZE)
    section_off = _PE_LFANEW + _PE_OPTIONAL_HEADER_OFFSET + _PE_OPTIONAL_HEADER_SIZE
    body[section_off : section_off + 5] = b".text"
    return bytes(body)


def _build_minimal_elf64() -> bytes:
    """Construct a synthetic ELF64 buffer with one program and section header.

    The buffer satisfies every length / class check that
    :meth:`TemplatesMixin._bookmark_elf_structure` performs in the
    ``ei_class == ELFCLASS64`` branch.

    Returns:
        bytes: ELF64-shaped payload large enough to bookmark.
    """
    body = bytearray(b"\x00" * 0x400)
    body[0:4] = b"\x7fELF"
    body[4] = 2  # ELFCLASS64
    struct.pack_into("<Q", body, 32, 0x80)  # e_phoff
    struct.pack_into("<Q", body, 40, 0x100)  # e_shoff
    struct.pack_into("<H", body, 56, 1)  # e_phnum
    struct.pack_into("<H", body, 58, 1)  # e_shnum
    return bytes(body)


class StubTemplateDocument:
    """In-memory document mirroring the surface used by the templates mixin.

    Records every :meth:`add_bookmark`, :meth:`apply_template`,
    :meth:`register_json_template` and :meth:`remove_template` call so
    tests can assert on call counts as well as on state-holder events.
    """

    def __init__(
        self,
        data: bytes,
        *,
        templates: list[tuple[str, str]] | None = None,
        register_name: str = "REGISTERED",
        apply_fields: list[dict[str, Any]] | None = None,
    ) -> None:
        """Wire test-supplied collaborators into the stub document.

        Args:
            data: Initial document content.
            templates: Optional template registry rows returned by
                :meth:`list_templates`.
            register_name: Name returned from
                :meth:`register_json_template` for every payload.
            apply_fields: Field list returned by :meth:`apply_template`.
        """
        self._data: bytearray = bytearray(data)
        self._templates: list[tuple[str, str]] = list(templates) if templates is not None else []
        self._register_name: str = register_name
        self._apply_fields: list[dict[str, Any]] = list(apply_fields) if apply_fields is not None else []
        self.bookmarks: list[tuple[int, int, str, str]] = []
        self.applied_templates: list[tuple[str, int]] = []
        self.registered_payloads: list[str] = []
        self.removed_templates: list[str] = []

    def length(self) -> int:
        """Return the document length in bytes.

        Returns:
            int: Number of bytes currently stored.
        """
        return len(self._data)

    def read(self, offset: int, length: int) -> bytes:
        """Return a slice of the document body.

        Args:
            offset: Inclusive start offset.
            length: Maximum number of bytes to copy.

        Returns:
            bytes: Slice of the document content.
        """
        return bytes(self._data[offset : offset + length])

    def add_bookmark(self, offset: int, length: int, label: str, color: str) -> int:
        """Record an :meth:`add_bookmark` call.

        Args:
            offset: Start byte offset of the bookmark.
            length: Length of the bookmarked region.
            label: Display label for the bookmark.
            color: Hex color string for the bookmark.

        Returns:
            int: Sequential bookmark index for the new entry.
        """
        self.bookmarks.append((offset, length, label, color))
        return len(self.bookmarks) - 1

    def list_bookmarks(self) -> list[tuple[int, int, str, str]]:
        """Return all recorded bookmarks.

        Returns:
            list[tuple[int, int, str, str]]: All bookmark tuples added
                so far via :meth:`add_bookmark`.
        """
        return list(self.bookmarks)

    def list_templates(self) -> list[tuple[str, str]]:
        """Return the configured template registry rows.

        Returns:
            list[tuple[str, str]]: Tuple rows of ``(name, description)``.
        """
        return list(self._templates)

    def apply_template(self, template_name: str, offset: int) -> list[dict[str, Any]]:
        """Record an :meth:`apply_template` call and return decoded fields.

        Args:
            template_name: Name of the template being applied.
            offset: Document offset at which the template is applied.

        Returns:
            list[dict[str, Any]]: Field rows configured by the test.
        """
        self.applied_templates.append((template_name, offset))
        return list(self._apply_fields)

    def register_json_template(self, json_str: str) -> str:
        """Record a JSON template registration call.

        Args:
            json_str: JSON template definition supplied by the panel.

        Returns:
            str: Configured template name returned to the panel.
        """
        self.registered_payloads.append(json_str)
        return self._register_name

    def remove_template(self, template_name: str) -> bool:
        """Record a template removal call.

        Args:
            template_name: Name of the template being removed.

        Returns:
            bool: Always ``True`` for the regression tests.
        """
        self.removed_templates.append(template_name)
        return True


class TemplatesHarness(QWidget, TemplatesMixin):
    """Concrete ``TemplatesMixin`` consumer used by the regression tests.

    Provides the attribute slots the mixin's type stubs declare so
    direct attribute access in :class:`TemplatesMixin` resolves at
    runtime without raising ``AttributeError``.
    """

    def __init__(
        self,
        *,
        document: StubTemplateDocument,
        state_holder: HexDocumentState,
        template_combo_text: str = "",
    ) -> None:
        """Wire the mixin slots up to test-supplied collaborators.

        Args:
            document: Stub document the mixin invokes for template
                and bookmark operations.
            state_holder: Real :class:`HexDocumentState` whose
                notifications the test asserts on.
            template_combo_text: Initial text loaded into the template
                combo so the apply / remove flows have a non-empty
                selection.
        """
        QWidget.__init__(self)
        self._document = document
        self.document = document
        self._hex_widget = None
        self._template_combo = QComboBox(self)
        if template_combo_text:
            self._template_combo.addItem(template_combo_text)
            self._template_combo.setCurrentIndex(0)
        self._templates_tree = QTreeWidget(self)
        self.state_holder = state_holder

    def _refresh_bookmarks_tree(self) -> None:
        """Stub bookmark-tree refresh for the mixin's auto-bookmark path.

        The audit-targeted code expects the panel to refresh the
        bookmark tree after the auto-bookmark walk; the test does not
        need that UI side-effect, so the override is intentionally a
        no-op.
        """

    def trigger_apply_template(self) -> None:
        """Drive ``_on_apply_template`` exactly as the panel's apply button would."""
        self._on_apply_template()

    def trigger_import_template(self) -> None:
        """Drive ``_on_import_template`` exactly as the panel's import button would."""
        self._on_import_template()

    def trigger_remove_template(self) -> None:
        """Drive ``_on_remove_template`` exactly as the panel's remove button would."""
        self._on_remove_template()

    def trigger_auto_bookmark_structure(self) -> None:
        """Drive ``_on_auto_bookmark_structure`` exactly as the panel toolbar would."""
        self._on_auto_bookmark_structure()


class PatternHarness(QWidget, PatternEditorMixin):
    """Concrete ``PatternEditorMixin`` consumer used by the F-0017 tests.

    Provides the attribute slots the mixin's type stubs declare and
    surfaces test hooks for the compile / interpreter execution paths
    via attributes rather than dialog interaction.
    """

    def __init__(
        self,
        *,
        document: StubTemplateDocument,
        state_holder: HexDocumentState,
        compiled_json: str = "",
    ) -> None:
        """Wire the mixin slots up to test-supplied collaborators.

        Args:
            document: Stub document the mixin invokes for template
                application.
            state_holder: Real :class:`HexDocumentState` whose
                notifications the test asserts on.
            compiled_json: Pre-populated compiled JSON payload that
                short-circuits the interpreter path so the test can
                exercise the compile-register-apply branch
                independently.
        """
        QWidget.__init__(self)
        self._document = document
        self.document = document
        self._hex_widget = None
        self._file_path = None
        self._pattern_frame = None
        self._pattern_dsl_editor = None
        self._pattern_json_preview = None
        self._pattern_library_tree = None
        self._pattern_error_display = None
        self._pattern_status_label = None
        self._pattern_visible = False
        self._compiled_json = compiled_json
        self._main_vsplit = None
        self._interpreter = None
        self._pattern_registry = None
        self._templates_tree = None
        self._template_combo = None
        self._state_holder = state_holder
        self.state_holder = state_holder

    def _populate_template_tree(self, fields: list[dict[str, object]]) -> None:
        """Override the tree population to a no-op for the regression tests.

        Args:
            fields: Decoded template fields the panel would render.
        """

    def _highlight_template_fields(self, fields: list[dict[str, object]]) -> None:
        """Override the highlight overlay to a no-op for the regression tests.

        Args:
            fields: Decoded template fields the panel would highlight.
        """

    def _populate_template_combo(self) -> None:
        """Override the combo refresh to a no-op for the regression tests."""

    def trigger_pattern_apply(self) -> None:
        """Drive ``_on_pattern_apply`` exactly as the panel apply button would."""
        self._on_pattern_apply()

    def trigger_apply_via_interpreter(self, source: str, offset: int) -> None:
        """Drive ``_apply_via_interpreter`` directly with the supplied source.

        Args:
            source: HexPat DSL source code to execute.
            offset: Byte offset to apply at.
        """
        self._apply_via_interpreter(source, offset)


class _StubInterpreter:
    """Minimal HexPat interpreter stub used by the interpreter branch tests.

    Returns a fixed list of fields from :meth:`execute` so the tests
    can assert on the field count carried through the
    ``notify_pattern_executed`` payload.
    """

    def __init__(self, fields: list[dict[str, Any]]) -> None:
        """Capture the field list to return from :meth:`execute`.

        Args:
            fields: Field rows returned to every interpreter call.
        """
        self._fields: list[dict[str, Any]] = list(fields)
        self.calls: list[tuple[str, object, int]] = []

    def execute(self, source: str, document: object, offset: int) -> list[dict[str, Any]]:
        """Record a call and return the configured field list.

        Args:
            source: HexPat DSL source code.
            document: Document the interpreter would read from.
            offset: Byte offset at which to apply the pattern.

        Returns:
            list[dict[str, Any]]: Configured field rows.
        """
        self.calls.append((source, document, offset))
        return list(self._fields)


class NotifyRecorder:
    """Capture every ``notify_*`` event emitted on a state holder."""

    def __init__(self) -> None:
        """Initialise the recorder with an empty event list."""
        self.events: list[tuple[HexDocumentEvent, dict[str, Any]]] = []

    def __call__(self, event_type: HexDocumentEvent, data: dict[str, Any]) -> None:
        """Append the received event to the recorder.

        Args:
            event_type: Event type emitted by the state holder.
            data: Payload dict supplied with the event.
        """
        self.events.append((event_type, dict(data)))


@pytest.fixture
def message_box_yes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force every ``QMessageBox.question`` call to return ``Yes``.

    The remove-template flow asks the user to confirm the deletion;
    the regression test must approve the prompt without manual
    interaction.

    Args:
        monkeypatch: pytest monkeypatch fixture used to patch the
            ``QMessageBox.question`` static method for the duration
            of one test.
    """

    def fake_question(
        _parent: QWidget | None,
        _title: str,
        _text: str,
        *_args: object,
        **_kwargs: object,
    ) -> QMessageBox.StandardButton:
        """Return ``Yes`` so the confirmation prompt always passes.

        Args:
            _parent: Ignored parent widget.
            _title: Ignored dialog title.
            _text: Ignored dialog body text.
            *_args: Ignored extra positional arguments.
            **_kwargs: Ignored keyword arguments.

        Returns:
            QMessageBox.StandardButton: The ``Yes`` enum value.
        """
        return QMessageBox.StandardButton.Yes

    monkeypatch.setattr(QMessageBox, "question", fake_question)


@pytest.fixture
def file_dialog_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> Path:
    """Patch ``QFileDialog.getOpenFileName`` to return a fixed JSON path.

    Args:
        monkeypatch: pytest monkeypatch fixture used to patch the
            ``QFileDialog.getOpenFileName`` static method for the
            duration of one test.
        tmp_path: Pytest temporary directory used to stage the
            synthetic template JSON.

    Returns:
        Path: Path to the staged JSON file the dialog will return.
    """
    json_path = tmp_path / "import_target.json"
    json_path.write_text('{"name": "FAKE", "fields": []}\n', encoding="utf-8")

    def fake_get_open(
        _parent: QWidget | None,
        _caption: str,
        _directory: str,
        _filter: str,
    ) -> tuple[str, str]:
        """Return the staged JSON path so the import flow proceeds.

        Args:
            _parent: Ignored parent widget.
            _caption: Ignored dialog caption.
            _directory: Ignored start directory.
            _filter: Ignored file filter string.

        Returns:
            tuple[str, str]: ``(path, filter)`` two-tuple matching the
                Qt return shape.
        """
        return str(json_path), "JSON Files (*.json);;All Files (*)"

    monkeypatch.setattr(QFileDialog, "getOpenFileName", fake_get_open)
    return json_path


@pytest.mark.usefixtures("qapp")
class TestTemplatesMixinNotifications:
    """F-0003 + F-0012 -- ``TemplatesMixin`` mutation paths emit state events."""

    @staticmethod
    def test_apply_template_emits_pattern_executed() -> None:
        """``_on_apply_template`` must emit ``PATTERN_EXECUTED`` after apply.

        The bridge fires ``notify_pattern_executed`` after every
        ``apply_template`` call.  The panel's apply path must mirror
        that so AI / CLI subscribers refresh after a GUI apply.
        """
        document = StubTemplateDocument(
            b"\x00" * 256,
            apply_fields=[{"name": "magic", "offset": 0, "size": 2}],
        )
        state = HexDocumentState()
        recorder = NotifyRecorder()
        state.register_callback(recorder, source_id="test")

        harness = TemplatesHarness(
            document=document,
            state_holder=state,
            template_combo_text="MY_TPL",
        )
        try:
            harness.trigger_apply_template()
        finally:
            harness.deleteLater()

        assert document.applied_templates == [("MY_TPL", 0)]
        executed = [evt for evt in recorder.events if evt[0] is HexDocumentEvent.PATTERN_EXECUTED]
        assert len(executed) == 1, f"expected one PATTERN_EXECUTED event, got {recorder.events}"
        _, payload = executed[0]
        assert payload == {"pattern_name": "MY_TPL", "field_count": 1}

    @staticmethod
    def test_apply_template_uses_audit_source(message_box_yes: None) -> None:
        """The apply notification must use the audit-defined source label.

        Registering the recorder with the same ``source_id`` the
        mixin passes proves the mixin used the documented identifier
        instead of an unrelated string -- the loop-guard filter
        suppresses the echo only when the source labels match
        exactly.

        Args:
            message_box_yes: Auto-yes confirmation fixture (unused
                here but kept consistent with sibling tests).
        """
        del message_box_yes
        document = StubTemplateDocument(b"\x00" * 256, apply_fields=[])
        state = HexDocumentState()
        recorder = NotifyRecorder()
        state.register_callback(
            recorder,
            source_id="hex-editor.templates.apply",
        )

        harness = TemplatesHarness(
            document=document,
            state_holder=state,
            template_combo_text="MY_TPL",
        )
        try:
            harness.trigger_apply_template()
        finally:
            harness.deleteLater()

        executed = [evt for evt in recorder.events if evt[0] is HexDocumentEvent.PATTERN_EXECUTED]
        assert executed == [], (
            "expected the loop-guard filter to suppress the apply echo "
            "when the recorder registers with the apply source_id; got: " + repr(executed)
        )

    @staticmethod
    def test_import_template_emits_template_registered(file_dialog_path: Path) -> None:
        """``_on_import_template`` must emit ``TEMPLATE_REGISTERED`` after registration.

        The bridge fires ``notify_template_registered`` on every
        ``register_template`` call.  The panel's import path must
        mirror that so subscribers see the new template name without
        having to poll ``list_templates``.

        Args:
            file_dialog_path: Path to the staged JSON file returned by
                the patched ``QFileDialog.getOpenFileName`` fixture.
        """
        document = StubTemplateDocument(b"\x00" * 256, register_name="IMPORTED_TPL")
        state = HexDocumentState()
        recorder = NotifyRecorder()
        state.register_callback(recorder, source_id="test")

        harness = TemplatesHarness(document=document, state_holder=state)
        try:
            harness.trigger_import_template()
        finally:
            harness.deleteLater()

        assert document.registered_payloads == [file_dialog_path.read_text(encoding="utf-8")]
        registered = [evt for evt in recorder.events if evt[0] is HexDocumentEvent.TEMPLATE_REGISTERED]
        assert len(registered) == 1, f"expected one TEMPLATE_REGISTERED event, got {recorder.events}"
        _, payload = registered[0]
        assert payload == {"template_name": "IMPORTED_TPL"}

    @staticmethod
    def test_remove_template_emits_template_removed(message_box_yes: None) -> None:
        """``_on_remove_template`` must emit ``TEMPLATE_REMOVED`` after removal.

        The bridge fires ``notify_template_removed`` on every
        ``remove_template`` call.  The panel's remove path must
        mirror that so subscribers prune the template from their
        local registries instead of caching a stale copy.

        Args:
            message_box_yes: Auto-yes confirmation fixture so the
                "Remove Template" dialog approves the deletion.
        """
        del message_box_yes
        document = StubTemplateDocument(b"\x00" * 256)
        state = HexDocumentState()
        recorder = NotifyRecorder()
        state.register_callback(recorder, source_id="test")

        harness = TemplatesHarness(
            document=document,
            state_holder=state,
            template_combo_text="DROPME",
        )
        try:
            harness.trigger_remove_template()
        finally:
            harness.deleteLater()

        assert document.removed_templates == ["DROPME"]
        removed = [evt for evt in recorder.events if evt[0] is HexDocumentEvent.TEMPLATE_REMOVED]
        assert len(removed) == 1, f"expected one TEMPLATE_REMOVED event, got {recorder.events}"
        _, payload = removed[0]
        assert payload == {"template_name": "DROPME"}


@pytest.mark.usefixtures("qapp")
class TestAutoBookmarkNotifications:
    """F-0003 -- bookmark mutation paths must publish ``DATA_MODIFIED`` events."""

    @staticmethod
    def test_pe_auto_bookmark_emits_data_modified_per_region() -> None:
        """The PE walk must emit a ``DATA_MODIFIED`` event for each bookmarked region.

        The DOS header, PE file header, optional header and each
        section header are all bookmarked.  Every bookmark adds an
        annotation observers should refresh against; the audit-defined
        remediation requires a ``notify_data_modified`` per region so
        AI / CLI consumers receive the same fan-out the bridge would
        produce after equivalent mutations.
        """
        body = _build_minimal_pe()
        document = StubTemplateDocument(body)
        state = HexDocumentState()
        recorder = NotifyRecorder()
        state.register_callback(recorder, source_id="test")

        harness = TemplatesHarness(document=document, state_holder=state)
        try:
            harness.trigger_auto_bookmark_structure()
        finally:
            harness.deleteLater()

        # Four bookmarks expected: DOS header, PE file header,
        # optional header, exactly one section header.
        assert len(document.bookmarks) == 4, document.bookmarks
        data_events = [evt for evt in recorder.events if evt[0] is HexDocumentEvent.DATA_MODIFIED]
        assert len(data_events) == len(document.bookmarks), (
            f"expected one DATA_MODIFIED event per bookmark; bookmarks={document.bookmarks!r} events={data_events!r}"
        )

        # Pair each bookmark to its emitted event so a regression that
        # drops one specific bookmark notification surfaces clearly.
        observed = {(evt[1]["offset"], evt[1]["length"]) for evt in data_events}
        expected = {(off, length) for off, length, _label, _color in document.bookmarks}
        assert observed == expected

    @staticmethod
    def test_elf_auto_bookmark_emits_data_modified_per_region() -> None:
        """The ELF64 walk must emit a ``DATA_MODIFIED`` event per bookmarked region.

        The ELF header, the program header table and the section
        header table are all bookmarked.  Each must be mirrored as a
        ``notify_data_modified`` event with the matching offset and
        length so observers refresh after the GUI walk.
        """
        body = _build_minimal_elf64()
        document = StubTemplateDocument(body)
        state = HexDocumentState()
        recorder = NotifyRecorder()
        state.register_callback(recorder, source_id="test")

        harness = TemplatesHarness(document=document, state_holder=state)
        try:
            harness.trigger_auto_bookmark_structure()
        finally:
            harness.deleteLater()

        assert len(document.bookmarks) == 3, document.bookmarks
        data_events = [evt for evt in recorder.events if evt[0] is HexDocumentEvent.DATA_MODIFIED]
        assert len(data_events) == len(document.bookmarks)
        observed = {(evt[1]["offset"], evt[1]["length"]) for evt in data_events}
        expected = {(off, length) for off, length, _label, _color in document.bookmarks}
        assert observed == expected


@pytest.mark.usefixtures("qapp")
class TestPatternApplyBranches:
    """F-0017 -- both ``_on_pattern_apply`` branches must emit notifications."""

    @staticmethod
    def test_compile_register_apply_emits_registered_and_executed(
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Compile-register-apply must emit BOTH ``TEMPLATE_REGISTERED`` and ``PATTERN_EXECUTED``.

        Pre-audit code only emitted ``TEMPLATE_REGISTERED`` for the
        new template; subscribers waiting for a ``PATTERN_EXECUTED``
        event to refresh decoded fields would never see one for the
        compile branch and would fall out of sync with the
        interpreter branch.

        Args:
            monkeypatch: pytest monkeypatch fixture used to disable
                the interpreter branch so the compile path runs.
        """
        # Force the compile branch by disabling the interpreter
        # availability flag in the mixin's import surface.
        monkeypatch.setattr(
            "intellicrack.ui.panels.hex_editor._pattern_editor.hexpat_interpreter_available",
            False,
        )
        monkeypatch.setattr(
            "intellicrack.ui.panels.hex_editor._pattern_editor.HexPatInterpreter_cls",
            None,
        )

        document = StubTemplateDocument(
            b"\x00" * 256,
            register_name="COMPILED_TPL",
            apply_fields=[
                {"name": "magic", "offset": 0, "size": 2},
                {"name": "size", "offset": 2, "size": 4},
            ],
        )
        state = HexDocumentState()
        recorder = NotifyRecorder()
        state.register_callback(recorder, source_id="test")

        harness = PatternHarness(
            document=document,
            state_holder=state,
            compiled_json='{"name": "COMPILED_TPL", "fields": []}',
        )
        try:
            harness.trigger_pattern_apply()
        finally:
            harness.deleteLater()

        assert document.registered_payloads == [
            '{"name": "COMPILED_TPL", "fields": []}',
        ]
        assert document.applied_templates == [("COMPILED_TPL", 0)]

        registered = [evt for evt in recorder.events if evt[0] is HexDocumentEvent.TEMPLATE_REGISTERED]
        executed = [evt for evt in recorder.events if evt[0] is HexDocumentEvent.PATTERN_EXECUTED]

        assert len(registered) == 1, f"expected exactly one TEMPLATE_REGISTERED event; got {recorder.events}"
        assert registered[0][1] == {"template_name": "COMPILED_TPL"}

        assert len(executed) == 1, f"expected exactly one PATTERN_EXECUTED event; got {recorder.events}"
        assert executed[0][1] == {"pattern_name": "COMPILED_TPL", "field_count": 2}

    @staticmethod
    def test_interpreter_branch_emits_pattern_executed(
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The interpreter branch must emit ``PATTERN_EXECUTED`` for the inline source.

        Pre-audit code emitted no notification at all from the
        interpreter branch, leaving subscribers unaware that an
        inline HexPat pattern produced fresh decoded fields.  The
        audit-defined remediation requires
        ``notify_pattern_executed("<inline>", len(fields))`` mirroring
        the bridge ``execute_pattern`` behaviour.

        Args:
            monkeypatch: pytest monkeypatch fixture used to substitute
                the interpreter class with a deterministic stub.
        """
        stub = _StubInterpreter([
            {"name": "f1", "offset": 0, "size": 2},
            {"name": "f2", "offset": 2, "size": 4},
            {"name": "f3", "offset": 6, "size": 8},
        ])

        # The mixin imports the interpreter class lazily from the
        # base module; the test substitutes a deterministic stub so
        # the executed-fields fan-out has a known length.
        class _ConstructibleStub:
            """Callable wrapper that returns the prepared interpreter stub."""

            def __call__(self) -> _StubInterpreter:
                """Return the prepared interpreter stub.

                Returns:
                    _StubInterpreter: Pre-prepared interpreter the
                        mixin should drive.
                """
                return stub

        monkeypatch.setattr(
            "intellicrack.ui.panels.hex_editor._pattern_editor.hexpat_interpreter_available",
            True,
        )
        monkeypatch.setattr(
            "intellicrack.ui.panels.hex_editor._pattern_editor.HexPatInterpreter_cls",
            _ConstructibleStub(),
        )

        document = StubTemplateDocument(b"\x00" * 256)
        state = HexDocumentState()
        recorder = NotifyRecorder()
        state.register_callback(recorder, source_id="test")

        harness = PatternHarness(
            document=document,
            state_holder=state,
        )
        # Drive the interpreter branch directly so the test exercises
        # the audit-targeted helper without depending on QPlainTextEdit
        # text-input plumbing.
        try:
            harness.trigger_apply_via_interpreter("struct S { u32 x; };", 0)
        finally:
            harness.deleteLater()

        assert len(stub.calls) == 1
        executed = [evt for evt in recorder.events if evt[0] is HexDocumentEvent.PATTERN_EXECUTED]
        assert len(executed) == 1, f"expected one PATTERN_EXECUTED event; got {recorder.events}"
        assert executed[0][1] == {"pattern_name": "<inline>", "field_count": 3}

    @staticmethod
    def test_interpreter_branch_uses_audit_source(
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The interpreter branch must use the audit-defined source label.

        Args:
            monkeypatch: pytest monkeypatch fixture used to substitute
                the interpreter class with a deterministic stub so
                the test exercises only the notification fan-out.
        """
        stub = _StubInterpreter([{"name": "f1", "offset": 0, "size": 4}])

        class _ConstructibleStub:
            """Callable wrapper that returns the prepared interpreter stub."""

            def __call__(self) -> _StubInterpreter:
                """Return the prepared interpreter stub.

                Returns:
                    _StubInterpreter: Pre-prepared interpreter the
                        mixin should drive.
                """
                return stub

        monkeypatch.setattr(
            "intellicrack.ui.panels.hex_editor._pattern_editor.hexpat_interpreter_available",
            True,
        )
        monkeypatch.setattr(
            "intellicrack.ui.panels.hex_editor._pattern_editor.HexPatInterpreter_cls",
            _ConstructibleStub(),
        )

        document = StubTemplateDocument(b"\x00" * 256)
        state = HexDocumentState()
        recorder = NotifyRecorder()
        state.register_callback(
            recorder,
            source_id="hex-editor.pattern_editor.apply.interpreter",
        )

        harness = PatternHarness(document=document, state_holder=state)
        try:
            harness.trigger_apply_via_interpreter("struct S { u32 x; };", 0)
        finally:
            harness.deleteLater()

        executed = [evt for evt in recorder.events if evt[0] is HexDocumentEvent.PATTERN_EXECUTED]
        assert executed == [], (
            "expected the loop-guard filter to suppress the interpreter echo "
            "when the recorder registers with the interpreter source_id; got: " + repr(executed)
        )

    @staticmethod
    def test_compile_branch_uses_distinct_audit_sources(
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Compile branch register and apply notifications must use distinct sources.

        Each notification carries its own audit-defined source so
        loop-guard filters can suppress the registration echo
        independently from the apply echo.

        Args:
            monkeypatch: pytest monkeypatch fixture used to disable
                the interpreter branch so the compile path runs.
        """
        monkeypatch.setattr(
            "intellicrack.ui.panels.hex_editor._pattern_editor.hexpat_interpreter_available",
            False,
        )
        monkeypatch.setattr(
            "intellicrack.ui.panels.hex_editor._pattern_editor.HexPatInterpreter_cls",
            None,
        )

        document = StubTemplateDocument(
            b"\x00" * 256,
            register_name="COMPILED_TPL",
            apply_fields=[],
        )
        state = HexDocumentState()
        register_recorder = NotifyRecorder()
        apply_recorder = NotifyRecorder()
        state.register_callback(
            register_recorder,
            source_id="hex-editor.pattern_editor.apply.register",
        )
        state.register_callback(
            apply_recorder,
            source_id="hex-editor.pattern_editor.apply.execute",
        )

        harness = PatternHarness(
            document=document,
            state_holder=state,
            compiled_json='{"name": "COMPILED_TPL", "fields": []}',
        )
        try:
            harness.trigger_pattern_apply()
        finally:
            harness.deleteLater()

        # The recorder registered with the register source must NOT
        # see the registration event but MUST still see the apply
        # event (and vice versa). This proves both notifications use
        # their own distinct source identifiers rather than sharing
        # one label.
        register_seen = [evt for evt in register_recorder.events if evt[0] is HexDocumentEvent.TEMPLATE_REGISTERED]
        register_apply = [evt for evt in register_recorder.events if evt[0] is HexDocumentEvent.PATTERN_EXECUTED]
        assert register_seen == [], "loop guard must suppress the register echo on its own source: " + repr(register_seen)
        assert len(register_apply) == 1, "register-source recorder must still receive the apply event: " + repr(register_recorder.events)

        apply_register = [evt for evt in apply_recorder.events if evt[0] is HexDocumentEvent.TEMPLATE_REGISTERED]
        apply_seen = [evt for evt in apply_recorder.events if evt[0] is HexDocumentEvent.PATTERN_EXECUTED]
        assert apply_seen == [], "loop guard must suppress the apply echo on its own source: " + repr(apply_seen)
        assert len(apply_register) == 1, "apply-source recorder must still receive the register event: " + repr(apply_recorder.events)
