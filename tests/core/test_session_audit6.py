# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for audit6 CORE-A findings on src/intellicrack/core/session.py and types.py.

Covers:
    F-0006 - auto-save loop must survive failures and re-arm.
    F-0007 - Session.tool_states writer methods exist and persist round-trip.
    F-0008 - Session.tags writer methods exist and persist round-trip.
    F-0009 - duplicate Session dataclass in types.py is removed.
    F-0022 - HexDocumentLike/HexDocumentFull Protocol bodies collapse to ``...``.
    F-0024 - SessionManager.update offloads SQLite I/O via asyncio.to_thread + lock.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from intellicrack.core import types as core_types_module
from intellicrack.core.session import Session, SessionManager, SessionStore
from intellicrack.core.types import (
    HexDocumentFull,
    HexDocumentLike,
    ProviderName,
    ToolName,
    ToolState,
)


if TYPE_CHECKING:
    from collections.abc import Callable


def _make_session(name: str = "audit6") -> Session:
    """Create a fresh Session for tests.

    Args:
        name: Session name.

    Returns:
        Session: New Session instance.
    """
    return Session.create(provider=ProviderName.ANTHROPIC, model="claude", name=name)


def _swap_session_store_save(replacement: Callable[[SessionStore, Session], None]) -> Callable[[SessionStore, Session], None]:
    """Swap SessionStore.save with ``replacement`` and return the original implementation.

    Args:
        replacement: Function to install in place of ``SessionStore.save``.

    Returns:
        Callable[[SessionStore, Session], None]: The original SessionStore.save function.
    """
    original = SessionStore.save
    setattr(SessionStore, "save", replacement)
    return original


def _restore_session_store_save(original: Callable[[SessionStore, Session], None]) -> None:
    """Restore SessionStore.save to ``original``.

    Args:
        original: Function previously returned by ``_swap_session_store_save``.
    """
    setattr(SessionStore, "save", original)


# =====================================================================
# F-0006 - Auto-save loop must survive a failure and re-arm.
# =====================================================================


class TestAutoSaveLoopSurvivesFailures:
    """F-0006: an exception in save() must not kill the auto-save task.

    The loop must re-arm across multiple consecutive failures and eventually
    complete a successful save.  ``save_attempts >= 2`` is not sufficient because
    a loop that stops after the first success (without ever re-entering after
    a failure) would satisfy that condition.  We inject exactly three failures
    then let the fourth attempt succeed, and require that all three failures
    were individually survived and that the fourth attempt wrote a loadable
    session to disk.
    """

    @staticmethod
    @pytest.mark.asyncio
    async def test_auto_save_loop_survives_exception_and_resumes(tmp_path: Path) -> None:
        """Verify auto-save loop continues after three consecutive save() failures.

        The flaky save function fails the first three calls and succeeds on
        the fourth.  The test asserts that exactly three failures were
        individually observed (i.e. the loop re-entered the except branch three
        separate times) and that the fourth call persisted a loadable record.

        Args:
            tmp_path: Pytest temporary directory.
        """
        db_path = tmp_path / "sessions.db"
        store = SessionStore(db_path)
        manager = SessionManager(store, save_interval=0)
        session = await manager.create(provider=ProviderName.ANTHROPIC, model="claude", name="autosave")

        save_attempts: int = 0
        failure_serial_numbers: list[int] = []
        save_completed = threading.Event()
        original_save = SessionStore.save

        def multi_flaky_save(self_store: SessionStore, sess: Session) -> None:
            """Fail the first three attempts, then succeed on the fourth.

            Args:
                self_store: SessionStore instance.
                sess: Session being saved.

            Raises:
                RuntimeError: Raised on the first three invocations so that the
                    auto-save loop must survive and re-arm three separate times
                    before a successful persistence path is exercised.
            """
            nonlocal save_attempts
            if save_completed.is_set():
                original_save(self_store, sess)
                return
            save_attempts += 1
            attempt = save_attempts
            if attempt <= 3:
                failure_serial_numbers.append(attempt)
                msg = f"transient sqlite failure #{attempt}"
                raise RuntimeError(msg)
            original_save(self_store, sess)
            save_completed.set()

        previous = _swap_session_store_save(multi_flaky_save)
        try:
            completed = await asyncio.to_thread(save_completed.wait, 10.0)
            assert completed is True, "auto-save worker must complete a successful save within 10s"
            await manager.stop_auto_save()
        finally:
            _restore_session_store_save(previous)
            await manager.close()

        assert failure_serial_numbers == [1, 2, 3], f"Expected exactly three numbered failures to be survived; got {failure_serial_numbers}"
        assert save_attempts == 4, f"Expected exactly four save attempts (3 failures + 1 success); got {save_attempts}"
        loaded = store.load(session.id)
        assert loaded is not None, "Session must be readable from SQLite after the fourth save succeeds"
        assert loaded.id == session.id, "Loaded session id must match"
        assert loaded.name == "autosave", f"Loaded session name must be 'autosave', got {loaded.name!r}"

    @staticmethod
    @pytest.mark.asyncio
    async def test_auto_save_loop_task_is_active_after_create(tmp_path: Path) -> None:
        """Verify the auto-save background worker is running after session creation.

        Args:
            tmp_path: Pytest temporary directory.
        """
        store = SessionStore(tmp_path / "sessions.db")
        manager = SessionManager(store, save_interval=300)
        await manager.create(provider=ProviderName.ANTHROPIC, model="claude", name="task-active")
        try:
            assert manager.is_auto_saving is True, "is_auto_saving must be True after create()"
        finally:
            await manager.close()

        assert manager.is_auto_saving is False, "is_auto_saving must be False after close()"

    @staticmethod
    @pytest.mark.asyncio
    async def test_close_from_different_event_loop_succeeds(tmp_path: Path) -> None:
        """Verify close() works when invoked on a different event loop than create().

        Reproduces the production shutdown path: session lifecycle starts on one
        loop (GUI bridge) and close runs on another (application main loop).
        A loop-bound asyncio auto-save task would raise RuntimeError here.

        Args:
            tmp_path: Pytest temporary directory.
        """
        store = SessionStore(tmp_path / "sessions.db")
        manager = SessionManager(store, save_interval=300)
        session = await manager.create(
            provider=ProviderName.ANTHROPIC,
            model="claude",
            name="cross-loop",
        )
        session.notes = "flushed-on-cross-loop-close"
        session_id = session.id
        assert manager.is_auto_saving is True, "auto-save must be running before cross-loop close"

        def _close_on_foreign_loop() -> None:
            """Run manager.close() on a brand-new event loop in this thread.

            Raises:
                RuntimeError: Propagated if close is not loop-agnostic.
            """
            foreign_loop = asyncio.new_event_loop()
            try:
                foreign_loop.run_until_complete(manager.close())
            finally:
                foreign_loop.close()

        await asyncio.to_thread(_close_on_foreign_loop)

        assert manager.current is None, "current session must be cleared after close"
        assert manager.is_auto_saving is False, "auto-save must stop after close"
        loaded = store.load(session_id)
        assert loaded is not None, "session must remain readable after cross-loop close"
        assert loaded.notes == "flushed-on-cross-loop-close", f"final flush must persist notes; got {loaded.notes!r}"

    @staticmethod
    @pytest.mark.asyncio
    async def test_stop_auto_save_is_prompt_with_long_interval(tmp_path: Path) -> None:
        """Verify stop_auto_save returns without waiting for a long save interval.

        Args:
            tmp_path: Pytest temporary directory.
        """
        store = SessionStore(tmp_path / "sessions.db")
        manager = SessionManager(store, save_interval=300)
        await manager.create(
            provider=ProviderName.ANTHROPIC,
            model="claude",
            name="prompt-stop",
        )
        assert manager.is_auto_saving is True

        started = time.monotonic()
        await manager.stop_auto_save()
        elapsed = time.monotonic() - started

        assert manager.is_auto_saving is False, "worker must be stopped"
        assert elapsed < 5.0, f"stop must be prompt; took {elapsed:.3f}s with 300s interval"
        await manager.close()

    @staticmethod
    @pytest.mark.asyncio
    async def test_close_final_save_persists_mutations(tmp_path: Path) -> None:
        """Verify close() flushes in-memory mutations after stopping auto-save.

        Args:
            tmp_path: Pytest temporary directory.
        """
        store = SessionStore(tmp_path / "sessions.db")
        manager = SessionManager(store, save_interval=300)
        session = await manager.create(
            provider=ProviderName.ANTHROPIC,
            model="claude",
            name="final-flush",
        )
        session.notes = "post-create-mutation"
        session_id = session.id
        await manager.close()

        loaded = store.load(session_id)
        assert loaded is not None, "session must load after close"
        assert loaded.notes == "post-create-mutation", f"close must flush mutations; got {loaded.notes!r}"
        assert manager.is_auto_saving is False

    @staticmethod
    @pytest.mark.asyncio
    async def test_auto_save_disabled_does_not_start_worker(tmp_path: Path) -> None:
        """Verify auto_save=False leaves the background worker stopped.

        Args:
            tmp_path: Pytest temporary directory.
        """
        store = SessionStore(tmp_path / "sessions.db")
        manager = SessionManager(store, auto_save=False, save_interval=1)
        await manager.create(
            provider=ProviderName.ANTHROPIC,
            model="claude",
            name="no-autosave",
        )
        try:
            assert manager.is_auto_saving is False, "auto_save=False must not start a worker"
        finally:
            await manager.close()


# =====================================================================
# F-0007 - Session.tool_states writer: behavioral correctness
# =====================================================================


class TestSessionToolStatesWriters:
    """F-0007: Session.tool_states must have a concrete writer that persists.

    The canonical writer is ``Session.set_tool_state``.  Verifying its
    existence via ``hasattr`` is insufficient because a stub that merely
    stores ``None`` at the key would also satisfy that check.  These tests
    drive the writer with specific inputs and assert the exact structure
    stored in ``tool_states``, the exact key used, identity of the stored
    object, the return value, and the ``updated_at`` mutation.
    """

    @staticmethod
    def test_set_tool_state_stores_at_tool_key_with_exact_fields() -> None:
        """Verify set_tool_state writes the state under state.tool and returns None.

        The independence oracle: the expected key is ``ToolName.GHIDRA`` (a
        known constant), the expected stored value is the exact object passed
        in (identity check, not re-implementation), and the expected return
        value is ``None`` as the docstring specifies.
        """
        session = _make_session()
        target = Path("C:/Windows/System32/notepad.exe")
        state = ToolState(
            tool=ToolName.GHIDRA,
            connected=True,
            process_attached=False,
            target_path=target,
            last_error=None,
        )
        before_updated_at = session.updated_at

        result = session.set_tool_state(state)

        assert result is None, "set_tool_state must return None"
        assert ToolName.GHIDRA in session.tool_states, "state must be keyed by ToolName.GHIDRA"
        stored = session.tool_states[ToolName.GHIDRA]
        assert stored is state, "set_tool_state must store the exact ToolState object passed in"
        assert stored.tool is ToolName.GHIDRA, f"stored.tool must be ToolName.GHIDRA, got {stored.tool!r}"
        assert stored.connected is True, "stored.connected must be True"
        assert stored.process_attached is False, "stored.process_attached must be False"
        assert stored.target_path == target, f"stored.target_path must be {target}, got {stored.target_path!r}"
        assert stored.last_error is None, "stored.last_error must be None"
        assert session.updated_at > before_updated_at, "set_tool_state must update updated_at"

    @staticmethod
    def test_set_tool_state_round_trips_through_store(tmp_path: Path) -> None:
        """Verify set_tool_state survives save/load through SQLite.

        Args:
            tmp_path: Pytest temporary directory.
        """
        store = SessionStore(tmp_path / "sessions.db")
        session = _make_session()

        target = Path("C:/Windows/System32/notepad.exe")
        state = ToolState(
            tool=ToolName.GHIDRA,
            connected=True,
            process_attached=False,
            target_path=target,
            last_error=None,
        )
        session.set_tool_state(state)

        store.save(session)
        loaded = store.load(session.id)

        assert loaded is not None
        assert ToolName.GHIDRA in loaded.tool_states
        round_tripped = loaded.tool_states[ToolName.GHIDRA]
        assert round_tripped.tool is ToolName.GHIDRA
        assert round_tripped.connected is True
        assert round_tripped.process_attached is False
        assert round_tripped.target_path == target
        assert round_tripped.last_error is None

    @staticmethod
    def test_set_tool_state_overwrites_previous_entry() -> None:
        """Verify set_tool_state replaces an earlier ToolState for the same tool."""
        session = _make_session()
        first = ToolState(
            tool=ToolName.X64DBG,
            connected=False,
            process_attached=False,
            target_path=None,
            last_error="not connected",
        )
        second = ToolState(
            tool=ToolName.X64DBG,
            connected=True,
            process_attached=True,
            target_path=Path("C:/bin/target.exe"),
            last_error=None,
        )
        session.set_tool_state(first)
        session.set_tool_state(second)

        assert session.tool_states[ToolName.X64DBG] is second
        assert len(session.tool_states) == 1, "Only one entry must exist for X64DBG"

    @staticmethod
    def test_set_tool_state_multiple_tools_are_independent() -> None:
        """Verify separate tools each get their own entry without interfering.

        The oracle: three different ToolName values each map to their own
        ToolState.  Deleting or overwriting one must not affect the others.
        """
        session = _make_session()
        states = {
            ToolName.GHIDRA: ToolState(tool=ToolName.GHIDRA, connected=True, process_attached=False, target_path=None, last_error=None),
            ToolName.FRIDA: ToolState(
                tool=ToolName.FRIDA,
                connected=False,
                process_attached=True,
                target_path=None,
                last_error="frida crash",
            ),
            ToolName.X64DBG: ToolState(
                tool=ToolName.X64DBG,
                connected=True,
                process_attached=True,
                target_path=Path("C:/t.exe"),
                last_error=None,
            ),
        }
        for state in states.values():
            session.set_tool_state(state)

        assert len(session.tool_states) == 3
        for tool_name, expected_state in states.items():
            assert session.tool_states[tool_name] is expected_state, (
                f"session.tool_states[{tool_name}] must be the exact object that was set"
            )

        removed = session.clear_tool_state(ToolName.FRIDA)
        assert removed is True, "clear_tool_state must return True when a state was removed"
        assert ToolName.FRIDA not in session.tool_states, "FRIDA state must be gone"
        assert ToolName.GHIDRA in session.tool_states, "GHIDRA state must be unaffected"
        assert ToolName.X64DBG in session.tool_states, "X64DBG state must be unaffected"

    @staticmethod
    def test_clear_tool_state_returns_false_when_not_present() -> None:
        """Verify clear_tool_state returns False for a tool that was never set."""
        session = _make_session()
        result = session.clear_tool_state(ToolName.SANDBOX)
        assert result is False, "clear_tool_state must return False when no state was present"
        assert len(session.tool_states) == 0


# =====================================================================
# F-0008 - Session.tags writers: behavioral correctness
# =====================================================================


class TestSessionTagsWriters:
    """F-0008: Session.tags must have concrete writer methods that persist.

    ``hasattr`` checks cannot gate correctness: a stub that always returns
    ``None`` would pass.  These tests assert exact return values (``True``/
    ``False``), exact tag list contents, whitespace normalization, rejection
    of empty strings, and that both writers update ``updated_at``.
    """

    @staticmethod
    def test_add_tag_returns_true_on_first_add_and_false_on_duplicate() -> None:
        """Verify add_tag returns True for a new tag and False for a duplicate.

        The oracle: Python's built-in ``True``/``False`` values are the
        specified contract; see Session.add_tag docstring.
        """
        session = _make_session()
        first_result = session.add_tag("malware")
        second_result = session.add_tag("malware")

        assert first_result is True, "add_tag must return True when the tag is new"
        assert second_result is False, "add_tag must return False for a duplicate tag"
        assert session.tags == ["malware"], f"tags list must contain exactly ['malware'], got {session.tags}"

    @staticmethod
    def test_add_tag_strips_whitespace_and_deduplicates_normalised() -> None:
        """Verify add_tag strips leading/trailing whitespace before storing.

        The oracle: the stored tag must equal the stripped form and a
        subsequent call with the same stripped value must be treated as a
        duplicate.
        """
        session = _make_session()
        first = session.add_tag("  priority  ")
        second = session.add_tag("priority")

        assert first is True, "add_tag must return True for the first normalised form"
        assert second is False, "add_tag must return False when the normalised form is already present"
        assert session.tags == ["priority"], f"tag must be stored in stripped form, got {session.tags}"

    @staticmethod
    def test_add_tag_raises_value_error_for_empty_and_whitespace_only() -> None:
        """Verify add_tag raises ValueError for empty or whitespace-only inputs."""
        session = _make_session()
        with pytest.raises(ValueError, match="non-empty"):
            session.add_tag("")
        with pytest.raises(ValueError, match="non-empty"):
            session.add_tag("   ")
        with pytest.raises(ValueError, match="non-empty"):
            session.add_tag("\t\n")
        assert session.tags == [], "No tags must have been added when ValueError is raised"

    @staticmethod
    def test_add_tag_updates_updated_at() -> None:
        """Verify add_tag mutates updated_at on a successful add."""
        session = _make_session()
        before = session.updated_at
        session.add_tag("triage")
        assert session.updated_at > before, "add_tag must update updated_at"

    @staticmethod
    def test_remove_tag_returns_true_when_found_false_when_absent() -> None:
        """Verify remove_tag returns True for a present tag and False for an absent one.

        The oracle: Python's built-in ``True``/``False`` values as specified
        in Session.remove_tag docstring.
        """
        session = _make_session()
        session.add_tag("critical")
        session.add_tag("reviewed")

        removed = session.remove_tag("critical")
        absent = session.remove_tag("critical")
        never_present = session.remove_tag("missing-tag")

        assert removed is True, "remove_tag must return True when the tag was found"
        assert absent is False, "remove_tag must return False when the tag is no longer present"
        assert never_present is False, "remove_tag must return False for a tag that was never added"
        assert session.tags == ["reviewed"], f"tags must be ['reviewed'] after removal, got {session.tags}"

    @staticmethod
    def test_add_tag_round_trip_through_store(tmp_path: Path) -> None:
        """Verify add_tag persists into session_tags table and back.

        Args:
            tmp_path: Pytest temporary directory.
        """
        store = SessionStore(tmp_path / "sessions.db")
        session = _make_session()
        session.add_tag("priority")
        session.add_tag("triage")
        session.add_tag("priority")

        store.save(session)
        loaded = store.load(session.id)

        assert loaded is not None
        assert sorted(loaded.tags) == ["priority", "triage"]

    @staticmethod
    def test_remove_tag_persists(tmp_path: Path) -> None:
        """Verify remove_tag drops a tag and the change persists.

        Args:
            tmp_path: Pytest temporary directory.
        """
        store = SessionStore(tmp_path / "sessions.db")
        session = _make_session()
        session.add_tag("a")
        session.add_tag("b")
        session.remove_tag("a")
        session.remove_tag("missing")

        store.save(session)
        loaded = store.load(session.id)

        assert loaded is not None
        assert loaded.tags == ["b"]


# =====================================================================
# F-0009 - duplicate Session dataclass in types.py is gone
# =====================================================================


class TestDuplicateSessionRemoved:
    """F-0009: types.py must not export a stale Session dataclass."""

    @staticmethod
    def test_types_module_does_not_export_session() -> None:
        """Verify intellicrack.core.types no longer defines a Session dataclass."""
        assert not hasattr(core_types_module, "Session"), "types.py must not redefine Session"
        exported = getattr(core_types_module, "__all__", [])
        assert "Session" not in exported, "Session must not be in types.__all__"


# =====================================================================
# F-0022 - Protocol bodies must collapse to `...`
# =====================================================================


class TestProtocolBodiesHaveNoConcreteImplementation:
    """F-0022: Protocol method bodies must not provide concrete logic.

    A Protocol method body is allowed to be:
        * a single docstring (string Constant Expression), or
        * a single ``...`` (Ellipsis Constant Expression),
        * or a docstring followed by ``...``.

    Anything else (assignments, returns, raises) is a violation of Protocol
    semantics because it would shadow the structural contract with a real
    implementation that could silently succeed when no provider is wired in.

    The AST check is complemented by a runtime ``isinstance`` structural
    typing check: objects that expose all required methods must pass
    ``isinstance(..., Protocol)``, and objects missing methods must fail.
    This runtime check catches cases where a Protocol's ``__abstractmethods__``
    are stripped away by concrete implementations hiding in the body.
    """

    @staticmethod
    def _is_docstring_or_ellipsis(stmt: ast.stmt) -> bool:
        """Return True if ``stmt`` is a docstring or Ellipsis expression statement.

        Args:
            stmt: AST statement to classify.

        Returns:
            bool: True for docstring/Ellipsis expression statements.
        """
        if not isinstance(stmt, ast.Expr):
            return False
        value = stmt.value
        if not isinstance(value, ast.Constant):
            return False
        return value.value is ... or isinstance(value.value, str)

    @staticmethod
    def _expect_protocol_body_is_declarative(protocol_cls: type) -> None:
        """Assert every method on ``protocol_cls`` has a declarative body only.

        Args:
            protocol_cls: Protocol class to inspect.
        """
        source = inspect.getsource(protocol_cls)
        module = ast.parse(source)
        cls_node = module.body[0]
        assert isinstance(cls_node, ast.ClassDef)
        method_count = 0
        forbidden_types = (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Return, ast.Raise, ast.For, ast.While, ast.If, ast.With, ast.Try)
        for item in cls_node.body:
            if not isinstance(item, ast.FunctionDef):
                continue
            method_count += 1
            for stmt in item.body:
                assert not isinstance(stmt, forbidden_types), (
                    f"{protocol_cls.__name__}.{item.name} contains forbidden runtime statement {type(stmt).__name__}"
                )
                assert TestProtocolBodiesHaveNoConcreteImplementation._is_docstring_or_ellipsis(stmt), (
                    f"{protocol_cls.__name__}.{item.name} contains a non-declarative expression"
                )
        assert method_count > 0, f"{protocol_cls.__name__} has no methods to inspect"

    def test_hex_document_like_protocol_body_is_declarative(self) -> None:
        """Verify HexDocumentLike protocol method bodies have no concrete logic."""
        self._expect_protocol_body_is_declarative(HexDocumentLike)

    def test_hex_document_full_protocol_body_is_declarative(self) -> None:
        """Verify HexDocumentFull protocol method bodies have no concrete logic."""
        self._expect_protocol_body_is_declarative(HexDocumentFull)

    @staticmethod
    def test_hex_document_like_runtime_isinstance_accepts_compliant_class() -> None:
        """Verify runtime isinstance accepts a fully compliant HexDocumentLike.

        The oracle: a class that exposes exactly the two methods specified
        in HexDocumentLike (``read`` and ``length``) must be accepted by the
        runtime_checkable Protocol isinstance check.  This test would fail
        if the Protocol body had concrete implementations that raised
        unconditionally (preventing structural subtyping from working).
        """

        class MinimalHexDoc:
            """Minimal class satisfying HexDocumentLike."""

            def read(self, _offset: int, _length: int) -> list[int]:
                """Read bytes.

                Args:
                    _offset: Byte offset.
                    _length: Number of bytes.

                Returns:
                    list[int]: Empty list.
                """
                return []

            def length(self) -> int:
                """Return length.

                Returns:
                    int: Always zero.
                """
                return 0

        instance = MinimalHexDoc()
        assert isinstance(instance, HexDocumentLike), "A class with read() and length() must satisfy HexDocumentLike at runtime"

    @staticmethod
    def test_hex_document_like_runtime_isinstance_rejects_non_compliant_class() -> None:
        """Verify runtime isinstance rejects a class missing required methods.

        The oracle: an object without ``read`` and ``length`` must NOT be
        accepted as HexDocumentLike.  This validates that the Protocol's
        runtime_checkable structural typing is functioning (not vacuously
        True for all objects).
        """

        class NoMethods:
            """Class with no relevant methods."""

        instance = NoMethods()
        assert not isinstance(instance, HexDocumentLike), "A class missing read() and length() must be rejected by HexDocumentLike"

    @staticmethod
    def test_hex_document_full_runtime_isinstance_accepts_fully_compliant_class() -> None:
        """Verify runtime isinstance accepts a class satisfying all HexDocumentFull methods.

        The oracle: a class that exposes all nine methods specified by
        HexDocumentFull (inherited read/length plus the seven new ones) must
        be accepted.  If the Protocol body contained concrete logic that
        raised or branched, the structural subtype check could fail even for
        a correct implementation.
        """

        class FullHexDoc:
            """Class satisfying HexDocumentFull."""

            def read(self, _offset: int, _length: int) -> list[int]:
                """Read bytes.

                Args:
                    _offset: Byte offset.
                    _length: Number of bytes.

                Returns:
                    list[int]: Empty list.
                """
                return []

            def length(self) -> int:
                """Return length.

                Returns:
                    int: Zero.
                """
                return 0

            def write(self, _offset: int, _data: bytes) -> None:
                """Write bytes.

                Args:
                    _offset: Byte offset.
                    _data: Bytes to write.
                """

            def list_templates(self) -> list[tuple[str, str]]:
                """List templates.

                Returns:
                    list[tuple[str, str]]: Empty list.
                """
                return []

            def list_templates_detailed(self) -> list[object]:
                """List templates with detail.

                Returns:
                    list[object]: Empty list.
                """
                return []

            def register_json_template(self, _name: str, _json_str: str) -> None:
                """Register template.

                Args:
                    _name: Template name.
                    _json_str: JSON string.
                """

            def remove_template(self, _name: str) -> None:
                """Remove template.

                Args:
                    _name: Template name.
                """

            def export_template_json(self, _name: str) -> str:
                """Export template as JSON.

                Args:
                    _name: Template name.

                Returns:
                    str: Empty string.
                """
                return ""

            def inspect_at(self, _offset: int) -> dict[str, object]:
                """Inspect at offset.

                Args:
                    _offset: Byte offset.

                Returns:
                    dict[str, object]: Empty dict.
                """
                return {}

        instance = FullHexDoc()
        assert isinstance(instance, HexDocumentFull), (
            "A class implementing all HexDocumentFull methods must satisfy the Protocol at runtime"
        )
        assert isinstance(instance, HexDocumentLike), "HexDocumentFull implementors must also satisfy HexDocumentLike (inheritance)"

    @staticmethod
    def test_hex_document_full_runtime_isinstance_rejects_partial_implementation() -> None:
        """Verify runtime isinstance rejects a class missing HexDocumentFull-only methods.

        The oracle: a class that only implements the HexDocumentLike subset
        (``read`` and ``length``) must NOT satisfy HexDocumentFull.
        """

        class OnlyLike:
            """Class implementing only HexDocumentLike, not HexDocumentFull."""

            def read(self, _offset: int, _length: int) -> list[int]:
                """Read bytes.

                Args:
                    _offset: Byte offset.
                    _length: Number of bytes.

                Returns:
                    list[int]: Empty list.
                """
                return []

            def length(self) -> int:
                """Return length.

                Returns:
                    int: Zero.
                """
                return 0

        instance = OnlyLike()
        assert isinstance(instance, HexDocumentLike), "OnlyLike must satisfy HexDocumentLike"
        assert not isinstance(instance, HexDocumentFull), (
            "OnlyLike must NOT satisfy HexDocumentFull because it is missing the full-document methods"
        )


# =====================================================================
# F-0024 - SessionManager.update must offload SQLite I/O and serialize concurrent writers
# =====================================================================


class TestSessionManagerUpdateOffloadsAndSerialises:
    """F-0024: update() must run SQLite I/O off the event loop and never race."""

    @staticmethod
    @pytest.mark.asyncio
    async def test_update_runs_in_worker_thread(tmp_path: Path) -> None:
        """Verify SessionManager.update offloads SQLite I/O via asyncio.to_thread.

        Args:
            tmp_path: Pytest temporary directory.
        """
        store = SessionStore(tmp_path / "sessions.db")
        manager = SessionManager(store, auto_save=False)
        session = _make_session()
        store.save(session)

        loop_thread = threading.get_ident()
        observed_threads: list[int] = []
        original_save = SessionStore.save

        def thread_recording_save(self_store: SessionStore, session_arg: Session) -> None:
            """Record the calling thread id and delegate.

            Args:
                self_store: SessionStore instance.
                session_arg: Session passed to save.
            """
            observed_threads.append(threading.get_ident())
            original_save(self_store, session_arg)

        previous = _swap_session_store_save(thread_recording_save)
        try:
            await manager.update(session)
        finally:
            _restore_session_store_save(previous)

        assert observed_threads, "save was never invoked"
        assert all(tid != loop_thread for tid in observed_threads), "SessionManager.update must run SQLite I/O off the event loop thread"

    @staticmethod
    @pytest.mark.asyncio
    async def test_concurrent_updates_serialise_and_complete(tmp_path: Path) -> None:
        """Verify many concurrent SessionManager.update calls do not corrupt SQLite.

        Args:
            tmp_path: Pytest temporary directory.
        """
        store = SessionStore(tmp_path / "sessions.db")
        manager = SessionManager(store, auto_save=False)

        sessions = [_make_session(f"concurrent-{i}") for i in range(8)]
        for session in sessions:
            store.save(session)

        active_calls: list[int] = []
        max_concurrent = 0
        original_save = SessionStore.save

        def overlap_tracking_save(self_store: SessionStore, session_arg: Session) -> None:
            """Track the maximum concurrent SQLite writers.

            Args:
                self_store: SessionStore instance.
                session_arg: Session passed to save.
            """
            nonlocal max_concurrent
            active_calls.append(1)
            max_concurrent = max(max_concurrent, len(active_calls))
            time.sleep(0.05)
            active_calls.pop()
            original_save(self_store, session_arg)

        previous = _swap_session_store_save(overlap_tracking_save)
        try:
            await asyncio.gather(*(manager.update(s) for s in sessions))
        finally:
            _restore_session_store_save(previous)

        assert max_concurrent == 1, f"SessionManager.update must serialise SQLite writes; saw {max_concurrent} concurrent writers"
        for session in sessions:
            loaded = store.load(session.id)
            assert loaded is not None
            assert loaded.id == session.id

    @staticmethod
    @pytest.mark.asyncio
    async def test_update_lock_does_not_deadlock_with_save(tmp_path: Path) -> None:
        """Verify update() and save() share the lock without deadlocking.

        Args:
            tmp_path: Pytest temporary directory.
        """
        store = SessionStore(tmp_path / "sessions.db")
        manager = SessionManager(store, auto_save=False)
        session = await manager.create(
            provider=ProviderName.OPENAI,
            model="gpt-4",
            name="lock-test",
        )

        await asyncio.wait_for(
            asyncio.gather(
                manager.update(session),
                manager.save(),
                manager.update(session),
                manager.save(),
            ),
            timeout=5.0,
        )
