# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit7 regression tests for hex panel template notification fan-out.

Covers two audit7 findings that the panel was silently dropping
``notify_template_registered`` notifications even though the bridge
emits the matching event for the equivalent programmatic action:

* **F-0012** — :meth:`TemplatesMixin._on_apply_template` previously only
  emitted ``notify_pattern_executed`` after a successful
  ``document.apply_template`` call.  AI / CLI consumers calling
  ``hex_editor.list_templates`` after a GUI apply via the templates
  mixin would receive stale state because the template-registered event
  for the freshly-resolved name never reached the state holder.  The
  remediation mirrors the existing import path
  (:meth:`TemplatesMixin._on_import_template`) and now emits
  ``_notify_state_template_registered`` from the apply path as well.

* **F-0017** — :meth:`PatternEditorMixin._apply_via_interpreter` is the
  interpreter fast-path through :meth:`PatternEditorMixin._on_pattern_apply`.
  The non-interpreter (compile-register-apply) branch emits both
  ``notify_template_registered`` and ``notify_pattern_executed``; the
  interpreter branch previously emitted only the latter.  The fix
  brings the interpreter branch to parity so subscribers always learn
  the inline pattern registered an executable template.

Both tests register a real :class:`HexDocumentState` plus a recorder
callback and drive the audit-targeted handler from a Qt harness that
backs the mixin's type-stub attribute slots with real widgets.  Each
test would have failed against pre-fix source: the recorder would
contain zero ``TEMPLATE_REGISTERED`` events for the corresponding
handler.
"""

from __future__ import annotations

from typing import Any

import pytest
from PyQt6.QtWidgets import QComboBox, QTreeWidget, QWidget

from intellicrack.bridges.hex_state import HexDocumentEvent, HexDocumentState
from intellicrack.ui.panels.hex_editor._pattern_editor import PatternEditorMixin
from intellicrack.ui.panels.hex_editor._templates import TemplatesMixin


class _StubDocument:
    """In-memory document mirroring the surface the audit-targeted handlers use.

    Records every :meth:`apply_template` / :meth:`register_json_template`
    call so the regression tests can pair recorded state-holder events
    with the underlying document operations that triggered them.
    """

    def __init__(
        self,
        *,
        register_name: str = "REGISTERED",
        apply_fields: list[dict[str, Any]] | None = None,
    ) -> None:
        """Wire the test-supplied return values into the stub document.

        Args:
            register_name: Name returned from
                :meth:`register_json_template` for every payload.
            apply_fields: Field rows returned from
                :meth:`apply_template`; defaults to an empty list.
        """
        self._register_name: str = register_name
        self._apply_fields: list[dict[str, Any]] = list(apply_fields) if apply_fields is not None else []
        self.applied_templates: list[tuple[str, int]] = []
        self.registered_payloads: list[str] = []

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


class _TemplatesHarness(QWidget, TemplatesMixin):
    """Concrete :class:`TemplatesMixin` consumer for the F-0012 regression."""

    def __init__(
        self,
        *,
        document: _StubDocument,
        state_holder: HexDocumentState,
        template_combo_text: str,
    ) -> None:
        """Wire the mixin slots up to test-supplied collaborators.

        Args:
            document: Stub document the mixin invokes for template
                application.
            state_holder: Real :class:`HexDocumentState` whose
                notifications the test asserts on.
            template_combo_text: Initial text loaded into the template
                combo so the apply flow has a non-empty selection.
        """
        QWidget.__init__(self)
        self._document = document
        self.document = document
        self._hex_widget = None
        self._template_combo = QComboBox(self)
        self._template_combo.addItem(template_combo_text)
        self._template_combo.setCurrentIndex(0)
        self._templates_tree = QTreeWidget(self)
        self.state_holder = state_holder

    def _refresh_bookmarks_tree(self) -> None:
        """No-op override for the mixin's auto-bookmark side effect."""

    def trigger_apply_template(self) -> None:
        """Drive ``_on_apply_template`` exactly as the panel's apply button would."""
        self._on_apply_template()


class _PatternHarness(QWidget, PatternEditorMixin):
    """Concrete :class:`PatternEditorMixin` consumer for the F-0017 regression."""

    def __init__(
        self,
        *,
        document: _StubDocument,
        state_holder: HexDocumentState,
    ) -> None:
        """Wire the mixin slots up to test-supplied collaborators.

        Args:
            document: Stub document used by the interpreter path; the
                interpreter substitution does not actually read it but
                the mixin guards on ``self.document is None`` before
                executing.
            state_holder: Real :class:`HexDocumentState` whose
                notifications the test asserts on.
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
        self._compiled_json = ""
        self._main_vsplit = None
        self._interpreter = None
        self._pattern_registry = None
        self._templates_tree = None
        self._template_combo = None
        self._state_holder = state_holder
        self.state_holder = state_holder

    def _populate_template_tree(self, fields: list[dict[str, object]]) -> None:
        """No-op override for the tree-population side effect.

        Args:
            fields: Decoded template fields the panel would render.
        """

    def _highlight_template_fields(self, fields: list[dict[str, object]]) -> None:
        """No-op override for the highlight-overlay side effect.

        Args:
            fields: Decoded template fields the panel would highlight.
        """

    def _populate_template_combo(self) -> None:
        """No-op override for the combo refresh side effect."""

    def trigger_apply_via_interpreter(self, source: str, offset: int) -> None:
        """Drive ``_apply_via_interpreter`` directly with the supplied source.

        Args:
            source: HexPat DSL source code to execute.
            offset: Byte offset to apply at.
        """
        self._apply_via_interpreter(source, offset)


class _StubInterpreter:
    """Deterministic HexPat interpreter stub used by the F-0017 test.

    Returns a fixed list of fields from :meth:`execute` so the test can
    assert on the field count carried through the
    ``notify_pattern_executed`` payload while focusing on the
    additional ``notify_template_registered`` fan-out F-0017 requires.
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


class _NotifyRecorder:
    """Capture every ``(event_type, payload)`` tuple emitted on a state holder."""

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


@pytest.mark.usefixtures("qapp")
class TestTemplateNotifF0012:
    """F-0012 -- ``_on_apply_template`` must emit ``TEMPLATE_REGISTERED``."""

    @staticmethod
    def test_template_notif_apply_emits_template_registered() -> None:
        """``_on_apply_template`` must publish ``TEMPLATE_REGISTERED``.

        Pre-fix code only emitted ``PATTERN_EXECUTED`` from the apply
        path even though the import path emitted both
        ``TEMPLATE_REGISTERED`` and (via the document) the equivalent
        execution event.  AI / CLI consumers that subscribe only to
        ``TEMPLATE_REGISTERED`` (because they track the template
        registry surface) would never learn about templates applied
        from the GUI templates combo until the next bridge re-sync.
        """
        document = _StubDocument(
            apply_fields=[{"name": "magic", "offset": 0, "size": 2}],
        )
        state = HexDocumentState()
        recorder = _NotifyRecorder()
        state.register_callback(recorder, source_id="test")

        harness = _TemplatesHarness(
            document=document,
            state_holder=state,
            template_combo_text="APPLIED_TPL",
        )
        try:
            harness.trigger_apply_template()
        finally:
            harness.deleteLater()

        assert document.applied_templates == [("APPLIED_TPL", 0)]

        registered = [evt for evt in recorder.events if evt[0] is HexDocumentEvent.TEMPLATE_REGISTERED]
        executed = [evt for evt in recorder.events if evt[0] is HexDocumentEvent.PATTERN_EXECUTED]

        assert len(registered) == 1, (
            f"F-0012: expected exactly one TEMPLATE_REGISTERED event for the applied template name; got {recorder.events!r}"
        )
        assert registered[0][1] == {"template_name": "APPLIED_TPL"}

        assert len(executed) == 1, f"expected one PATTERN_EXECUTED event; got {recorder.events!r}"
        assert executed[0][1] == {"pattern_name": "APPLIED_TPL", "field_count": 1}

    @staticmethod
    def test_template_notif_apply_uses_distinct_register_source() -> None:
        """The register notification must carry its own audit-defined source.

        The apply path emits both ``TEMPLATE_REGISTERED`` and
        ``PATTERN_EXECUTED``; each must use a distinct source label so
        loop-guard filters can suppress one echo independently of the
        other.  Registering a recorder against the register source must
        leave the register echo filtered but still deliver the
        pattern-executed event.
        """
        document = _StubDocument(apply_fields=[])
        state = HexDocumentState()
        register_recorder = _NotifyRecorder()
        execute_recorder = _NotifyRecorder()
        state.register_callback(
            register_recorder,
            source_id="hex-editor.templates.apply.register",
        )
        state.register_callback(
            execute_recorder,
            source_id="hex-editor.templates.apply",
        )

        harness = _TemplatesHarness(
            document=document,
            state_holder=state,
            template_combo_text="APPLIED_TPL",
        )
        try:
            harness.trigger_apply_template()
        finally:
            harness.deleteLater()

        # Register-source recorder: TEMPLATE_REGISTERED echo suppressed, PATTERN_EXECUTED delivered.
        register_seen = [evt for evt in register_recorder.events if evt[0] is HexDocumentEvent.TEMPLATE_REGISTERED]
        register_executed = [evt for evt in register_recorder.events if evt[0] is HexDocumentEvent.PATTERN_EXECUTED]
        assert register_seen == [], "loop guard must suppress the register echo on its own source: " + repr(register_seen)
        assert len(register_executed) == 1, "register-source recorder must still receive the pattern-executed event: " + repr(
            register_recorder.events,
        )

        # Execute-source recorder: TEMPLATE_REGISTERED delivered, PATTERN_EXECUTED echo suppressed.
        execute_seen = [evt for evt in execute_recorder.events if evt[0] is HexDocumentEvent.PATTERN_EXECUTED]
        execute_registered = [evt for evt in execute_recorder.events if evt[0] is HexDocumentEvent.TEMPLATE_REGISTERED]
        assert execute_seen == [], "loop guard must suppress the execute echo on its own source: " + repr(execute_seen)
        assert len(execute_registered) == 1, "execute-source recorder must still receive the template-registered event: " + repr(
            execute_recorder.events,
        )


@pytest.mark.usefixtures("qapp")
class TestPatternApplyF0017:
    """F-0017 -- ``_apply_via_interpreter`` must emit ``TEMPLATE_REGISTERED``."""

    @staticmethod
    def test_pattern_apply_interpreter_emits_template_registered(
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The interpreter branch must publish ``TEMPLATE_REGISTERED``.

        Pre-fix code emitted only ``PATTERN_EXECUTED`` from the
        interpreter fast-path; the compile-register-apply branch of
        :meth:`PatternEditorMixin._on_pattern_apply` emits both events.
        Bringing the interpreter branch to parity ensures subscribers
        that filter on ``TEMPLATE_REGISTERED`` learn about every inline
        DSL execution regardless of which apply path the panel took.

        Args:
            monkeypatch: pytest monkeypatch fixture used to substitute
                the interpreter class with a deterministic stub so the
                executed-field fan-out has a known length.
        """
        stub = _StubInterpreter([
            {"name": "f1", "offset": 0, "size": 2},
            {"name": "f2", "offset": 2, "size": 4},
            {"name": "f3", "offset": 6, "size": 8},
        ])

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

        document = _StubDocument()
        state = HexDocumentState()
        recorder = _NotifyRecorder()
        state.register_callback(recorder, source_id="test")

        harness = _PatternHarness(document=document, state_holder=state)
        try:
            harness.trigger_apply_via_interpreter("struct S { u32 x; };", 0)
        finally:
            harness.deleteLater()

        assert len(stub.calls) == 1

        registered = [evt for evt in recorder.events if evt[0] is HexDocumentEvent.TEMPLATE_REGISTERED]
        executed = [evt for evt in recorder.events if evt[0] is HexDocumentEvent.PATTERN_EXECUTED]

        assert len(registered) == 1, (
            f"F-0017: expected exactly one TEMPLATE_REGISTERED event from the interpreter branch; got {recorder.events!r}"
        )
        assert registered[0][1] == {"template_name": "<inline>"}

        assert len(executed) == 1, f"expected one PATTERN_EXECUTED event; got {recorder.events!r}"
        assert executed[0][1] == {"pattern_name": "<inline>", "field_count": 3}

    @staticmethod
    def test_pattern_apply_interpreter_uses_distinct_register_source(
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The interpreter register notification must carry its own source.

        Each notification needs an independent source label so
        loop-guard filters can suppress one echo without losing the
        other.  Registering a recorder against the register source
        must filter the register echo but still deliver the
        pattern-executed event from the same handler invocation.

        Args:
            monkeypatch: pytest monkeypatch fixture used to substitute
                the interpreter class with a deterministic stub.
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

        document = _StubDocument()
        state = HexDocumentState()
        register_recorder = _NotifyRecorder()
        execute_recorder = _NotifyRecorder()
        state.register_callback(
            register_recorder,
            source_id="hex-editor.pattern_editor.apply.interpreter.register",
        )
        state.register_callback(
            execute_recorder,
            source_id="hex-editor.pattern_editor.apply.interpreter",
        )

        harness = _PatternHarness(document=document, state_holder=state)
        try:
            harness.trigger_apply_via_interpreter("struct S { u32 x; };", 0)
        finally:
            harness.deleteLater()

        register_seen = [evt for evt in register_recorder.events if evt[0] is HexDocumentEvent.TEMPLATE_REGISTERED]
        register_executed = [evt for evt in register_recorder.events if evt[0] is HexDocumentEvent.PATTERN_EXECUTED]
        assert register_seen == [], "loop guard must suppress the interpreter-register echo on its own source: " + repr(register_seen)
        assert len(register_executed) == 1, "register-source recorder must still receive the pattern-executed event: " + repr(
            register_recorder.events,
        )

        execute_seen = [evt for evt in execute_recorder.events if evt[0] is HexDocumentEvent.PATTERN_EXECUTED]
        execute_registered = [evt for evt in execute_recorder.events if evt[0] is HexDocumentEvent.TEMPLATE_REGISTERED]
        assert execute_seen == [], "loop guard must suppress the interpreter-execute echo on its own source: " + repr(execute_seen)
        assert len(execute_registered) == 1, "execute-source recorder must still receive the template-registered event: " + repr(
            execute_recorder.events,
        )
