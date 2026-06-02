# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit4 C5 regression tests for templates + pattern editor mixins.

These tests drive the real ``intellicrack_hexcore.HexDocument`` template
engine and the real :class:`HexPatInterpreter` against real, valid PE / ELF
binaries and real ``.hexpat`` source - no stubbed document, no mocked dialog,
no patched interpreter. Each mutation reachable from ``TemplatesMixin`` and
``PatternEditorMixin`` must (a) perform the real registry / bookmark mutation
on the live document and (b) publish the matching
:class:`HexDocumentState` event so observers (the hex viewport, the bridge
layer, the AI tool registry) refresh after a GUI mutation instead of analysing
stale state.

The covered findings:

* **F-0003** -- every byte / document mutation reachable from
  ``TemplatesMixin`` (template apply / import / remove and the PE/ELF
  auto-bookmark walk) publishes the matching ``HexDocumentState`` event.

* **F-0012 / F-0017** -- both ``_on_pattern_apply`` branches (the HexPat
  interpreter path and the compile-register-apply path) emit the appropriate
  ``TEMPLATE_REGISTERED`` and ``PATTERN_EXECUTED`` notifications, and the
  apply paths mirror the bridge's register-then-execute fan-out.

All tests fail against pre-audit code: the recorder is empty for the template
/ bookmark mutations, and the interpreter branch emits no notification.
"""

from __future__ import annotations

import json
import struct
from typing import TYPE_CHECKING, Any

import intellicrack_hexcore as hexcore
import pytest
from PyQt6.QtWidgets import QComboBox, QTreeWidget, QWidget

from intellicrack.bridges.hex_state import HexDocumentEvent, HexDocumentState
from intellicrack.core.hexpat_compiler import HexPatCompiler
from intellicrack.ui.panels.hex_editor.pattern_code_editor import PatternCodeEditor
from intellicrack.ui.panels.hex_editor.pattern_editor import PatternEditorMixin
from intellicrack.ui.panels.hex_editor.templates import TemplatesMixin


if TYPE_CHECKING:
    from pathlib import Path


# Real-world PE constants used to build a valid PE header so the
# auto-bookmark walk traverses the DOS header, the PE signature, the
# optional header and a single section entry. These mirror the offsets the
# production walk reads from real binaries.
_PE_LFANEW: int = 0x40
_PE_OPTIONAL_HEADER_OFFSET: int = 24
_PE_OPTIONAL_HEADER_SIZE: int = 224
_PE_SECTION_ENTRY_SIZE: int = 40
_PE_SECTION_COUNT: int = 1
_PE_DOS_HEADER_SIZE: int = 64

# Expected PE bookmark regions (offset, length) for the binary built below,
# derived from the on-disk PE layout, not from the production code.
_PE_EXPECTED_REGIONS: set[tuple[int, int]] = {
    (0, _PE_DOS_HEADER_SIZE),
    (_PE_LFANEW, _PE_OPTIONAL_HEADER_OFFSET),
    (_PE_LFANEW + _PE_OPTIONAL_HEADER_OFFSET, _PE_OPTIONAL_HEADER_SIZE),
    (_PE_LFANEW + _PE_OPTIONAL_HEADER_OFFSET + _PE_OPTIONAL_HEADER_SIZE, _PE_SECTION_ENTRY_SIZE),
}

# ELF64 layout constants for the binary built below.
_ELF_HEADER_SIZE: int = 64
_ELF64_PHOFF: int = 0x80
_ELF64_SHOFF: int = 0x100
_ELF64_PH_ENTRY_SIZE: int = 56
_ELF64_SH_ENTRY_SIZE: int = 64
_ELF_EXPECTED_REGIONS: set[tuple[int, int]] = {
    (0, _ELF_HEADER_SIZE),
    (_ELF64_PHOFF, _ELF64_PH_ENTRY_SIZE),
    (_ELF64_SHOFF, _ELF64_SH_ENTRY_SIZE),
}


def _build_minimal_pe() -> bytes:
    """Construct a real, valid PE buffer that survives the auto-bookmark walk.

    The buffer satisfies every length / signature check that
    :meth:`TemplatesMixin._bookmark_pe_structure` performs and exposes a
    single ``.text`` section header so the section bookmark loop runs once.

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
    """Construct a real, valid ELF64 buffer with one program and section header.

    The buffer satisfies every length / class check that
    :meth:`TemplatesMixin._bookmark_elf_structure` performs in the
    ``ei_class == ELFCLASS64`` branch.

    Returns:
        bytes: ELF64-shaped payload large enough to bookmark.
    """
    body = bytearray(b"\x00" * 0x400)
    body[0:4] = b"\x7fELF"
    body[4] = 2  # ELFCLASS64
    struct.pack_into("<Q", body, 32, _ELF64_PHOFF)  # e_phoff
    struct.pack_into("<Q", body, 40, _ELF64_SHOFF)  # e_shoff
    struct.pack_into("<H", body, 56, 1)  # e_phnum
    struct.pack_into("<H", body, 58, 1)  # e_shnum
    return bytes(body)


def _build_header_payload() -> bytes:
    """Build a 256-byte payload whose first six bytes decode to known values.

    The leading ``u16`` is ``0x5A4D`` and the following ``u32`` is
    ``0xDEADBEEF`` (little-endian), so a struct template / inline pattern
    applied at offset 0 yields field display values an independent decoder
    can predict.

    Returns:
        bytes: 256-byte payload with a known six-byte header prefix.
    """
    return struct.pack("<HI", 0x5A4D, 0xDEADBEEF) + b"\x00" * 250


def _new_document(data: bytes) -> hexcore.HexDocument:
    """Open ``data`` as a real in-memory ``HexDocument``.

    Args:
        data: Raw bytes to back the document.

    Returns:
        hexcore.HexDocument: A live ``intellicrack_hexcore.HexDocument`` instance.
    """
    return hexcore.HexDocument.open_bytes(data)


def _compile_header_template(name: str) -> str:
    """Compile a two-field header struct template to registry JSON.

    Uses the real :class:`HexPatCompiler` so the produced JSON matches the
    schema the live ``HexDocument`` registry accepts.

    Args:
        name: Struct / template name to compile.

    Returns:
        str: Compiled JSON template definition.
    """
    source = f"struct {name} {{\n    le u16 magic;\n    le u32 size;\n}};\n"
    return HexPatCompiler().compile(source)


class UserNotificationRecorder:
    """Capture every user-facing notification routed through the mixin reporter.

    Substituted for the mixin's modal :class:`QMessageBox` calls so the
    error / unsupported-format branches run to completion without blocking on
    a real modal dialog, while still letting the test assert the exact
    notification the production code would have shown the user.
    """

    def __init__(self) -> None:
        """Initialise the recorder with an empty notification list."""
        self.notifications: list[tuple[str, str, str]] = []

    def __call__(self, title: str, message: str, level: str) -> None:
        """Record a notification routed by ``TemplatesMixin._notify_user``.

        Args:
            title: Notification title the panel would have shown.
            message: Notification body the panel would have shown.
            level: Notification severity (``"info"`` or ``"warning"``).
        """
        self.notifications.append((title, message, level))


class TemplatesHarness(QWidget, TemplatesMixin):
    """Concrete ``TemplatesMixin`` consumer backed by a real ``HexDocument``.

    Provides the attribute slots the mixin's type stubs declare so direct
    attribute access in :class:`TemplatesMixin` resolves at runtime without
    raising ``AttributeError``.
    """

    def __init__(
        self,
        *,
        document: hexcore.HexDocument,
        state_holder: HexDocumentState,
        template_combo_text: str = "",
        user_notifier: UserNotificationRecorder | None = None,
    ) -> None:
        """Wire the mixin slots up to real collaborators.

        Args:
            document: Live ``HexDocument`` the mixin invokes for template and
                bookmark operations.
            state_holder: Real :class:`HexDocumentState` whose notifications
                the test asserts on.
            template_combo_text: Initial text loaded into the template combo
                so the apply / remove flows have a non-empty selection.
            user_notifier: Optional non-modal reporter the mixin routes user
                notifications through instead of a blocking ``QMessageBox``.
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
        self._user_notifier = user_notifier

    def _refresh_bookmarks_tree(self) -> None:
        """No-op bookmark-tree refresh for the mixin's auto-bookmark path."""

    def trigger_apply_template(self) -> None:
        """Drive ``_on_apply_template`` exactly as the panel's apply button would."""
        self._on_apply_template()

    def trigger_import_from_path(self, file_path: str) -> None:
        """Drive the non-interactive import path with a real JSON file.

        Args:
            file_path: Filesystem path to the JSON template the panel would
                have selected via its file dialog.
        """
        self._import_template_from_path(file_path)

    def trigger_remove_named(self, name: str) -> None:
        """Drive the non-interactive remove path for a confirmed template name.

        Args:
            name: Template name the panel's confirmation dialog approved.
        """
        self._remove_template_named(name)

    def trigger_auto_bookmark_structure(self) -> None:
        """Drive ``_on_auto_bookmark_structure`` exactly as the panel toolbar would."""
        self._on_auto_bookmark_structure()


class PatternHarness(QWidget, PatternEditorMixin):
    """Concrete ``PatternEditorMixin`` consumer backed by a real ``HexDocument``.

    Provides the attribute slots the mixin's type stubs declare and surfaces
    test hooks for the compile / interpreter execution paths. The real
    :class:`HexPatInterpreter` is used unmodified.
    """

    def __init__(
        self,
        *,
        document: hexcore.HexDocument,
        state_holder: HexDocumentState,
        compiled_json: str = "",
        dsl_source: str | None = None,
    ) -> None:
        """Wire the mixin slots up to real collaborators.

        When ``dsl_source`` is ``None`` the DSL editor slot stays unset so
        ``_on_pattern_apply`` sees empty inline source and takes the
        compile-register-apply branch; supplying ``dsl_source`` routes
        ``_on_pattern_apply`` through the real interpreter branch.

        Args:
            document: Live ``HexDocument`` the mixin applies templates to.
            state_holder: Real :class:`HexDocumentState` whose notifications
                the test asserts on.
            compiled_json: Pre-populated compiled JSON payload used by the
                compile-register-apply branch.
            dsl_source: Inline HexPat DSL source for the interpreter branch,
                or ``None`` to leave the DSL editor unset.
        """
        QWidget.__init__(self)
        self._document = document
        self.document = document
        self._hex_widget = None
        self._file_path = None
        self._pattern_frame = None
        self._pattern_dsl_editor = None
        if dsl_source is not None:
            self._pattern_dsl_editor = PatternCodeEditor(self)
            self._pattern_dsl_editor.setPlainText(dsl_source)
        self._pattern_completer = None
        self._pattern_json_preview = None
        self._pattern_library_tree = None
        self._pattern_error_display = None
        self._pattern_print_output = None
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
        """No-op tree population for the regression tests.

        Args:
            fields: Decoded template fields the panel would render.
        """

    def _highlight_template_fields(self, fields: list[dict[str, object]]) -> None:
        """No-op highlight overlay for the regression tests.

        Args:
            fields: Decoded template fields the panel would highlight.
        """

    def _populate_template_combo(self) -> None:
        """No-op combo refresh for the regression tests."""

    def trigger_pattern_apply(self) -> None:
        """Drive ``_on_pattern_apply`` exactly as the panel apply button would."""
        self._on_pattern_apply()

    def trigger_apply_via_interpreter(self, source: str, offset: int) -> None:
        """Drive ``_apply_via_interpreter`` directly with the real interpreter.

        Args:
            source: HexPat DSL source code to execute.
            offset: Byte offset to apply at.
        """
        self._apply_via_interpreter(source, offset)


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

    def of_type(self, event_type: HexDocumentEvent) -> list[dict[str, Any]]:
        """Return payloads recorded for ``event_type``.

        Args:
            event_type: Event type to filter for.

        Returns:
            list[dict[str, Any]]: Payloads delivered for that event type, in
                emission order.
        """
        return [data for evt, data in self.events if evt is event_type]


@pytest.mark.usefixtures("qapp")
class TestTemplatesMixinNotifications:
    """F-0003 + F-0012 -- ``TemplatesMixin`` mutation paths emit state events."""

    @staticmethod
    def test_apply_template_decodes_real_fields_and_emits_both_events() -> None:
        """Applying a real template decodes the planted bytes and fans out both events.

        Registers a real two-field struct template on a live document whose
        first six bytes are ``0x5A4D`` / ``0xDEADBEEF``, then drives the
        panel apply path. The real engine must decode both fields, and the
        panel must mirror the bridge by emitting ``TEMPLATE_REGISTERED`` for
        the template and ``PATTERN_EXECUTED`` carrying the real field count.
        """
        document = _new_document(_build_header_payload())
        registered_name: str = document.register_json_template(_compile_header_template("MYHDR"))
        assert registered_name == "MYHDR"

        state = HexDocumentState()
        recorder = NotifyRecorder()
        state.register_callback(recorder, source_id="test")

        harness = TemplatesHarness(document=document, state_holder=state, template_combo_text=registered_name)
        try:
            harness.trigger_apply_template()
        finally:
            harness.deleteLater()

        executed = recorder.of_type(HexDocumentEvent.PATTERN_EXECUTED)
        assert executed == [{"pattern_name": "MYHDR", "field_count": 2}], recorder.events

        registered = recorder.of_type(HexDocumentEvent.TEMPLATE_REGISTERED)
        assert registered == [{"template_name": "MYHDR"}], recorder.events

    @staticmethod
    def test_apply_template_uses_audit_source_for_loop_guard() -> None:
        """The apply notifications use their audit source ids so echoes self-suppress.

        Registering the recorder under both apply source ids and observing
        the loop guard drop each echo proves the mixin emitted with exactly
        those documented identifiers rather than unrelated strings.
        """
        document = _new_document(_build_header_payload())
        document.register_json_template(_compile_header_template("MYHDR"))

        state = HexDocumentState()
        execute_recorder = NotifyRecorder()
        register_recorder = NotifyRecorder()
        state.register_callback(execute_recorder, source_id="hex-editor.templates.apply")
        state.register_callback(register_recorder, source_id="hex-editor.templates.apply.register")

        harness = TemplatesHarness(document=document, state_holder=state, template_combo_text="MYHDR")
        try:
            harness.trigger_apply_template()
        finally:
            harness.deleteLater()

        assert execute_recorder.of_type(HexDocumentEvent.PATTERN_EXECUTED) == [], (
            "apply-source recorder must not receive its own PATTERN_EXECUTED echo"
        )
        assert register_recorder.of_type(HexDocumentEvent.TEMPLATE_REGISTERED) == [], (
            "register-source recorder must not receive its own TEMPLATE_REGISTERED echo"
        )

    @staticmethod
    def test_import_template_registers_on_real_document_and_emits_event(tmp_path: Path) -> None:
        """Importing a real JSON file registers it on the live document and notifies.

        Drives the non-interactive import path with a real compiled JSON
        template staged on disk (no mocked file dialog). The template must
        appear in the live document registry and the panel must emit
        ``TEMPLATE_REGISTERED`` carrying the engine-assigned name.

        Args:
            tmp_path: Pytest temporary directory used to stage the JSON file.
        """
        document = _new_document(_build_header_payload())
        before = {name for name, _desc in document.list_templates()}
        assert "IMPORTED_HDR" not in before

        json_path = tmp_path / "imported.json"
        json_path.write_text(_compile_header_template("IMPORTED_HDR"), encoding="utf-8")

        state = HexDocumentState()
        recorder = NotifyRecorder()
        state.register_callback(recorder, source_id="test")

        harness = TemplatesHarness(document=document, state_holder=state)
        try:
            harness.trigger_import_from_path(str(json_path))
        finally:
            harness.deleteLater()

        after = {name for name, _desc in document.list_templates()}
        assert "IMPORTED_HDR" in after, "import must register the template on the real document"

        registered = recorder.of_type(HexDocumentEvent.TEMPLATE_REGISTERED)
        assert registered == [{"template_name": "IMPORTED_HDR"}], recorder.events

    @staticmethod
    def test_import_of_malformed_json_does_not_register_or_notify(tmp_path: Path) -> None:
        """A malformed JSON template is rejected by the engine and emits no state event.

        The real registry rejects invalid JSON; the panel's import path must
        leave the registry untouched and emit no ``TEMPLATE_REGISTERED``
        state event, so observers are not told a template exists when it does
        not. The error branch is exercised through a non-modal reporter (no
        ``QMessageBox`` monkeypatching, no blocking dialog): the reporter must
        receive exactly one ``"warning"`` notification titled ``Import
        Template`` whose body reports the failure, proving the except-branch
        ran to completion rather than silently no-opping.

        Args:
            tmp_path: Pytest temporary directory used to stage the bad file.
        """
        document = _new_document(_build_header_payload())
        before = document.list_templates()

        bad_path = tmp_path / "broken.json"
        bad_path.write_text('{"name": "BROKEN", not valid json', encoding="utf-8")

        state = HexDocumentState()
        recorder = NotifyRecorder()
        state.register_callback(recorder, source_id="test")
        notifier = UserNotificationRecorder()

        harness = TemplatesHarness(document=document, state_holder=state, user_notifier=notifier)
        try:
            harness.trigger_import_from_path(str(bad_path))
        finally:
            harness.deleteLater()

        assert document.list_templates() == before, "malformed import must not mutate the registry"
        assert recorder.of_type(HexDocumentEvent.TEMPLATE_REGISTERED) == [], "malformed import must not announce a registration"

        assert len(notifier.notifications) == 1, notifier.notifications
        title, message, level = notifier.notifications[0]
        assert (title, level) == ("Import Template", "warning"), notifier.notifications
        assert message.startswith("Import failed:"), message

    @staticmethod
    def test_remove_template_drops_from_real_registry_and_emits_event() -> None:
        """Removing a registered template drops it from the live registry and notifies.

        Registers a real template, drives the non-interactive remove path,
        and asserts the template is gone from the live document registry and
        a single ``TEMPLATE_REMOVED`` event names it.
        """
        document = _new_document(_build_header_payload())
        document.register_json_template(_compile_header_template("DROPME"))
        assert "DROPME" in {name for name, _desc in document.list_templates()}

        state = HexDocumentState()
        recorder = NotifyRecorder()
        state.register_callback(recorder, source_id="test")

        harness = TemplatesHarness(document=document, state_holder=state, template_combo_text="DROPME")
        try:
            harness.trigger_remove_named("DROPME")
        finally:
            harness.deleteLater()

        assert "DROPME" not in {name for name, _desc in document.list_templates()}, "remove must drop the template from the real registry"
        removed = recorder.of_type(HexDocumentEvent.TEMPLATE_REMOVED)
        assert removed == [{"template_name": "DROPME"}], recorder.events


@pytest.mark.usefixtures("qapp")
class TestAutoBookmarkNotifications:
    """F-0003 -- bookmark mutation paths publish ``DATA_MODIFIED`` events."""

    @staticmethod
    def test_pe_auto_bookmark_creates_real_bookmarks_and_one_event_per_region() -> None:
        """The PE walk bookmarks every header region on the live doc and notifies each.

        Drives the auto-bookmark toolbar action over a real PE binary. The
        live document must end up holding exactly the four expected header
        bookmarks (DOS header, PE file header, optional header and the single
        ``.text`` section), and one ``DATA_MODIFIED`` event must accompany
        each so observers refresh against the same regions the bridge would
        produce.
        """
        document = _new_document(_build_minimal_pe())
        state = HexDocumentState()
        recorder = NotifyRecorder()
        state.register_callback(recorder, source_id="test")

        harness = TemplatesHarness(document=document, state_holder=state)
        try:
            harness.trigger_auto_bookmark_structure()
        finally:
            harness.deleteLater()

        bookmarks = document.list_bookmarks()
        regions = {(off, length) for off, length, _label, _color in bookmarks}
        assert regions == _PE_EXPECTED_REGIONS, bookmarks

        labels = {label for _off, _length, label, _color in bookmarks}
        assert {"DOS Header", "PE File Header", "Optional Header", ".text"} <= labels, bookmarks

        data_events = recorder.of_type(HexDocumentEvent.DATA_MODIFIED)
        observed = {(evt["offset"], evt["length"]) for evt in data_events}
        assert observed == _PE_EXPECTED_REGIONS, data_events
        assert len(data_events) == len(bookmarks), (bookmarks, data_events)

    @staticmethod
    def test_elf_auto_bookmark_creates_real_bookmarks_and_one_event_per_region() -> None:
        """The ELF64 walk bookmarks header / table regions and notifies each.

        Drives the auto-bookmark toolbar action over a real ELF64 binary.
        The live document must hold the ELF header, program-header-table and
        section-header-table bookmarks, each mirrored by a ``DATA_MODIFIED``
        event with the matching offset and length.
        """
        document = _new_document(_build_minimal_elf64())
        state = HexDocumentState()
        recorder = NotifyRecorder()
        state.register_callback(recorder, source_id="test")

        harness = TemplatesHarness(document=document, state_holder=state)
        try:
            harness.trigger_auto_bookmark_structure()
        finally:
            harness.deleteLater()

        bookmarks = document.list_bookmarks()
        regions = {(off, length) for off, length, _label, _color in bookmarks}
        assert regions == _ELF_EXPECTED_REGIONS, bookmarks

        data_events = recorder.of_type(HexDocumentEvent.DATA_MODIFIED)
        observed = {(evt["offset"], evt["length"]) for evt in data_events}
        assert observed == _ELF_EXPECTED_REGIONS, data_events
        assert len(data_events) == len(bookmarks), (bookmarks, data_events)

    @staticmethod
    def test_unsupported_format_creates_no_bookmarks_and_no_events() -> None:
        """A non-PE/ELF buffer is left untouched: no bookmarks, no events.

        Drives the walk over a real GIF buffer whose magic matches neither PE
        nor ELF; the live document must gain no bookmarks and no
        ``DATA_MODIFIED`` event may fire. The unsupported-format branch is
        exercised through a non-modal reporter (no ``QMessageBox``
        monkeypatching, no blocking dialog): the reporter must receive exactly
        one ``"info"`` notification titled ``Auto Bookmark`` reporting the
        unsupported format, proving the else-branch executed rather than
        silently returning.
        """
        document = _new_document(b"GIF89a" + b"\x00" * 250)
        state = HexDocumentState()
        recorder = NotifyRecorder()
        state.register_callback(recorder, source_id="test")
        notifier = UserNotificationRecorder()

        harness = TemplatesHarness(document=document, state_holder=state, user_notifier=notifier)
        try:
            harness.trigger_auto_bookmark_structure()
        finally:
            harness.deleteLater()

        assert document.list_bookmarks() == [], "unsupported format must not create bookmarks"
        assert recorder.of_type(HexDocumentEvent.DATA_MODIFIED) == [], "unsupported format must emit no DATA_MODIFIED"

        assert notifier.notifications == [
            ("Auto Bookmark", "Unsupported file format (PE and ELF supported).", "info"),
        ], notifier.notifications


@pytest.mark.usefixtures("qapp")
class TestPatternApplyBranches:
    """F-0012 + F-0017 -- both ``_on_pattern_apply`` branches notify correctly."""

    @staticmethod
    def test_compile_register_apply_decodes_real_fields_and_emits_both_events() -> None:
        """The compile branch registers, applies and decodes real fields, emitting both events.

        With no inline DSL source, ``_on_pattern_apply`` registers the
        pre-compiled JSON on the live document and applies it. The real
        engine decodes the two header fields from the planted bytes, and the
        panel must emit ``TEMPLATE_REGISTERED`` for the new template plus
        ``PATTERN_EXECUTED`` carrying the real field count.
        """
        compiled = _compile_header_template("COMPILEDHDR")
        registered_name = json.loads(compiled)["name"]
        assert registered_name == "COMPILEDHDR"

        document = _new_document(_build_header_payload())
        state = HexDocumentState()
        recorder = NotifyRecorder()
        state.register_callback(recorder, source_id="test")

        harness = PatternHarness(document=document, state_holder=state, compiled_json=compiled)
        try:
            harness.trigger_pattern_apply()
        finally:
            harness.deleteLater()

        assert "COMPILEDHDR" in {name for name, _desc in document.list_templates()}, (
            "compile branch must register the template on the real document"
        )

        registered = recorder.of_type(HexDocumentEvent.TEMPLATE_REGISTERED)
        assert registered == [{"template_name": "COMPILEDHDR"}], recorder.events

        executed = recorder.of_type(HexDocumentEvent.PATTERN_EXECUTED)
        assert executed == [{"pattern_name": "COMPILEDHDR", "field_count": 2}], recorder.events

    @staticmethod
    def test_compile_branch_uses_distinct_audit_sources() -> None:
        """The compile branch register and apply notifications use distinct sources.

        Each notification carries its own audit source so loop-guard filters
        suppress the registration echo independently from the apply echo. A
        recorder bound to one source must miss its own event but still see the
        other.
        """
        compiled = _compile_header_template("COMPILEDHDR")
        document = _new_document(_build_header_payload())

        state = HexDocumentState()
        register_recorder = NotifyRecorder()
        apply_recorder = NotifyRecorder()
        state.register_callback(register_recorder, source_id="hex-editor.pattern_editor.apply.register")
        state.register_callback(apply_recorder, source_id="hex-editor.pattern_editor.apply.execute")

        harness = PatternHarness(document=document, state_holder=state, compiled_json=compiled)
        try:
            harness.trigger_pattern_apply()
        finally:
            harness.deleteLater()

        assert register_recorder.of_type(HexDocumentEvent.TEMPLATE_REGISTERED) == [], (
            "register-source recorder must not see its own registration echo"
        )
        assert register_recorder.of_type(HexDocumentEvent.PATTERN_EXECUTED) == [{"pattern_name": "COMPILEDHDR", "field_count": 2}], (
            "register-source recorder must still receive the apply event"
        )

        assert apply_recorder.of_type(HexDocumentEvent.PATTERN_EXECUTED) == [], "apply-source recorder must not see its own apply echo"
        assert apply_recorder.of_type(HexDocumentEvent.TEMPLATE_REGISTERED) == [{"template_name": "COMPILEDHDR"}], (
            "apply-source recorder must still receive the register event"
        )

    @staticmethod
    def test_interpreter_branch_decodes_real_fields_and_emits_both_events() -> None:
        """The interpreter branch runs the real interpreter and emits both inline events.

        Drives ``_apply_via_interpreter`` with real inline HexPat source over
        a live document whose bytes are known. The real interpreter decodes
        exactly two top-level fields, and the panel must emit
        ``TEMPLATE_REGISTERED`` and ``PATTERN_EXECUTED`` for the ``<inline>``
        run carrying that real field count.
        """
        document = _new_document(_build_header_payload())
        state = HexDocumentState()
        recorder = NotifyRecorder()
        state.register_callback(recorder, source_id="test")

        harness = PatternHarness(document=document, state_holder=state)
        try:
            harness.trigger_apply_via_interpreter("le u16 magic @ 0x0;\nle u32 size @ 0x2;\n", 0)
        finally:
            harness.deleteLater()

        registered = recorder.of_type(HexDocumentEvent.TEMPLATE_REGISTERED)
        assert registered == [{"template_name": "<inline>"}], recorder.events

        executed = recorder.of_type(HexDocumentEvent.PATTERN_EXECUTED)
        assert executed == [{"pattern_name": "<inline>", "field_count": 2}], recorder.events

    @staticmethod
    def test_on_pattern_apply_routes_inline_source_through_interpreter() -> None:
        """A non-empty inline DSL source routes ``_on_pattern_apply`` through the interpreter.

        When the DSL editor holds source, ``_on_pattern_apply`` must take the
        interpreter branch (not compile-register-apply): no template is added
        to the document registry, and the emitted ``PATTERN_EXECUTED`` names
        the ``<inline>`` run with the real interpreter field count.
        """
        document = _new_document(_build_header_payload())
        templates_before = document.list_templates()

        state = HexDocumentState()
        recorder = NotifyRecorder()
        state.register_callback(recorder, source_id="test")

        harness = PatternHarness(
            document=document,
            state_holder=state,
            dsl_source="le u16 magic @ 0x0;\nle u32 size @ 0x2;\n",
        )
        try:
            harness.trigger_pattern_apply()
        finally:
            harness.deleteLater()

        assert document.list_templates() == templates_before, "interpreter branch must not register a named template on the document"
        executed = recorder.of_type(HexDocumentEvent.PATTERN_EXECUTED)
        assert executed == [{"pattern_name": "<inline>", "field_count": 2}], recorder.events

    @staticmethod
    def test_interpreter_branch_uses_distinct_audit_sources() -> None:
        """The interpreter branch register / apply notifications use distinct sources.

        Each interpreter notification carries its own audit source id; a
        recorder bound to one must miss its own event yet still observe the
        other, proving the documented identifiers are used.
        """
        document = _new_document(_build_header_payload())
        state = HexDocumentState()
        register_recorder = NotifyRecorder()
        apply_recorder = NotifyRecorder()
        state.register_callback(register_recorder, source_id="hex-editor.pattern_editor.apply.interpreter.register")
        state.register_callback(apply_recorder, source_id="hex-editor.pattern_editor.apply.interpreter")

        harness = PatternHarness(document=document, state_holder=state)
        try:
            harness.trigger_apply_via_interpreter("le u16 magic @ 0x0;\nle u32 size @ 0x2;\n", 0)
        finally:
            harness.deleteLater()

        assert register_recorder.of_type(HexDocumentEvent.TEMPLATE_REGISTERED) == [], (
            "interpreter register-source recorder must not see its own echo"
        )
        assert register_recorder.of_type(HexDocumentEvent.PATTERN_EXECUTED) == [{"pattern_name": "<inline>", "field_count": 2}], (
            "interpreter register-source recorder must still receive the apply event"
        )

        assert apply_recorder.of_type(HexDocumentEvent.PATTERN_EXECUTED) == [], (
            "interpreter apply-source recorder must not see its own echo"
        )
        assert apply_recorder.of_type(HexDocumentEvent.TEMPLATE_REGISTERED) == [{"template_name": "<inline>"}], (
            "interpreter apply-source recorder must still receive the register event"
        )
