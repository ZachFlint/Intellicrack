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
import json
import sqlite3
import threading
from pathlib import Path

import intellicrack_hexcore
import pytest

from intellicrack.core import types as core_types_module
from intellicrack.core.session import Session, SessionManager, SessionStore
from intellicrack.core.template_manager import TemplateManager
from intellicrack.core.types import (
    HexDocumentFull,
    HexDocumentLike,
    ProviderName,
    ToolName,
    ToolState,
)


def _make_session(name: str = "audit6") -> Session:
    """Create a fresh Session for tests.

    Args:
        name: Session name.

    Returns:
        Session: New Session instance.
    """
    return Session.create(provider=ProviderName.ANTHROPIC, model="claude", name=name)


# =====================================================================
# F-0006 - Auto-save loop must survive a failure and re-arm.
# =====================================================================


class TestAutoSaveLoopSurvivesFailures:
    """F-0006: a real transient SQLite failure must not kill the auto-save task."""

    @staticmethod
    async def _wait_for_persisted_tag(manager: SessionManager, session_id: str, tag: str, *, deadline_seconds: float) -> bool:
        """Poll the manager until ``tag`` is persisted for ``session_id`` or timeout.

        Reads through ``manager.get`` so every database access is serialised
        against the auto-save loop via the manager's shared lock, then yields
        control between polls so the running auto-save task can make progress.
        No bare ``sleep`` drives correctness: the loop terminates as soon as the
        real persisted state contains the sentinel tag.

        Args:
            manager: SessionManager whose store backs the session.
            session_id: Identifier of the session being auto-saved.
            tag: Sentinel tag whose persistence proves a save succeeded.
            deadline_seconds: Maximum seconds to wait before giving up.

        Returns:
            bool: ``True`` if the tag was observed persisted before the
                deadline, ``False`` otherwise.
        """
        loop = asyncio.get_running_loop()
        deadline = loop.time() + deadline_seconds
        while loop.time() < deadline:
            loaded = await manager.get(session_id)
            if loaded is not None and tag in loaded.tags:
                return True
            await asyncio.sleep(0.01)
        return False

    @staticmethod
    @pytest.mark.asyncio
    async def test_auto_save_loop_survives_real_locked_db_and_resumes(tmp_path: Path) -> None:
        """Verify the auto-save loop survives a real locked SQLite DB then persists.

        Uses no monkeypatch: a second SQLite connection holds a ``BEGIN
        EXCLUSIVE`` transaction so every ``store.save`` issued by the auto-save
        loop genuinely fails with ``OperationalError: database is locked``. The
        test first proves the lock truly blocks a save, then keeps the loop
        running against the locked database, mutates the session with a
        sentinel tag, releases the lock, and asserts the loop recovers and
        persists the sentinel - and that the background task is still alive
        afterwards. Removing the loop's broad failure guard kills the task on
        the first lock error, so the sentinel never persists and this fails.

        Args:
            tmp_path: Pytest temporary directory.
        """
        sentinel = "recovered-after-lock"
        db_path = tmp_path / "sessions.db"
        store = SessionStore(db_path)
        manager = SessionManager(store, save_interval=0)
        session = await manager.create(provider=ProviderName.ANTHROPIC, model="claude", name="autosave")

        lock_conn = sqlite3.connect(str(db_path), isolation_level=None)
        lock_conn.execute("BEGIN EXCLUSIVE")
        try:
            with pytest.raises(sqlite3.OperationalError, match="database is locked"):
                await asyncio.to_thread(store.save, session)

            session.add_tag(sentinel)

            for _ in range(20):
                await asyncio.sleep(0.005)
            assert manager.is_auto_saving is True, "auto-save task must stay alive through repeated lock failures"
        finally:
            lock_conn.execute("ROLLBACK")
            lock_conn.close()

        try:
            persisted = await TestAutoSaveLoopSurvivesFailures._wait_for_persisted_tag(
                manager,
                session.id,
                sentinel,
                deadline_seconds=5.0,
            )
            assert persisted is True, "auto-save loop must persist the sentinel once the lock is released"
            assert manager.is_auto_saving is True, "auto-save task must remain alive after recovering"
        finally:
            await manager.close()

        final = store.load(session.id)
        assert final is not None
        assert sentinel in final.tags


# =====================================================================
# F-0007 / F-0008 - Session writers for tool_states and tags
# =====================================================================


class TestSessionToolStatesWriters:
    """F-0007: Session.tool_states must have a concrete writer that persists."""

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
        assert round_tripped.target_path == target

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


class TestSessionTagsWriters:
    """F-0008: Session.tags must have concrete writer methods that persist."""

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


class _IncompleteHexDocument:
    """A hex document missing the template surface of ``HexDocumentFull``.

    Implements only the read access of ``HexDocumentLike`` so a runtime
    ``isinstance`` check against ``HexDocumentFull`` must reject it. Used as the
    negative case proving the protocol actually constrains structure.
    """

    def read(self, offset: int, length: int) -> list[int]:
        """Return a deterministic byte slice.

        Args:
            offset: Byte offset to start reading from.
            length: Number of bytes to read.

        Returns:
            list[int]: ``length`` zero bytes.
        """
        _ = offset
        return [0] * length

    def length(self) -> int:
        """Return a fixed document length.

        Returns:
            int: Constant length of 16 bytes.
        """
        return 16


class _RealHexDocumentAdapter:
    """A ``HexDocumentFull`` implementation backed by a real hexcore document.

    Wraps an ``intellicrack_hexcore.HexDocument`` and exposes the exact method
    surface (and signatures) of ``HexDocumentFull``, delegating every call to
    the real document. Unlike the raw ``HexDocument`` (which exposes
    ``write_bytes`` and ``bytes``-returning ``read``), this adapter genuinely
    conforms to the protocol, so it can drive consumers typed against
    ``HexDocumentFull`` while exercising real hexcore behaviour.
    """

    def __init__(self, document: intellicrack_hexcore.HexDocument) -> None:
        """Wrap a real hexcore document.

        Args:
            document: Live ``intellicrack_hexcore.HexDocument`` to delegate to.
        """
        self._document = document

    def read(self, offset: int, length: int) -> list[int]:
        """Read bytes from the real document as integer values.

        Args:
            offset: Byte offset to start reading from.
            length: Number of bytes to read.

        Returns:
            list[int]: The bytes read, as integer values.
        """
        return list(self._document.read(offset, length))

    def length(self) -> int:
        """Return the real document's length in bytes.

        Returns:
            int: Document length.
        """
        return self._document.length()

    def write(self, offset: int, data: bytes) -> None:
        """Write bytes to the real document.

        Args:
            offset: Byte offset to write at.
            data: Bytes to write.
        """
        self._document.write_bytes(offset, data)

    def list_templates(self) -> list[tuple[str, str]]:
        """List available templates as (name, description) pairs.

        Returns:
            list[tuple[str, str]]: Template name/description pairs.
        """
        return self._document.list_templates()

    def list_templates_detailed(self) -> list[object]:
        """List templates with full detail tuples from the real document.

        Returns:
            list[object]: Detailed template entries.
        """
        return list(self._document.list_templates_detailed())

    def register_json_template(self, name: str, json_str: str) -> None:
        """Register a JSON-defined template on the real document.

        Args:
            name: Template name (recorded for the protocol signature; the
                hexcore derives the canonical name from the JSON payload).
            json_str: JSON string defining the template.
        """
        _ = name
        self._document.register_json_template(json_str)

    def remove_template(self, name: str) -> None:
        """Remove a registered template from the real document.

        Args:
            name: Template name to remove.
        """
        self._document.remove_template(name)

    def export_template_json(self, name: str) -> str:
        """Export a template as a JSON string from the real document.

        Args:
            name: Template name to export.

        Returns:
            str: JSON representation of the template.
        """
        return self._document.export_template_json(name)

    def inspect_at(self, offset: int) -> dict[str, object]:
        """Inspect data at the given offset on the real document.

        Args:
            offset: Byte offset to inspect.

        Returns:
            dict[str, object]: Inspection results.
        """
        return dict(self._document.inspect_at(offset))


class TestHexDocumentFullContractWithRealImplementation:
    """Pair the declarative-body check with a real behavioural protocol contract.

    The AST test only proves the Protocol stays declarative. These tests prove
    the contract is meaningful: a real ``intellicrack_hexcore.HexDocument``
    drives the real ``TemplateManager.bootstrap_builtins`` consumer (typed
    against ``HexDocumentFull``) end to end, and the ``runtime_checkable``
    protocol discriminates a structurally complete object from an incomplete
    one.
    """

    @staticmethod
    def test_runtime_checkable_full_rejects_incomplete_document() -> None:
        """Verify HexDocumentFull's runtime check rejects a read-only document.

        A document exposing only ``read``/``length`` satisfies
        ``HexDocumentLike`` but lacks the template/write surface, so
        ``isinstance(obj, HexDocumentFull)`` must be ``False`` while
        ``isinstance(obj, HexDocumentLike)`` is ``True``. This proves the
        protocol enforces the extra methods rather than accepting anything.
        """
        partial = _IncompleteHexDocument()

        assert isinstance(partial, HexDocumentLike) is True, "read+length must satisfy HexDocumentLike"
        assert isinstance(partial, HexDocumentFull) is False, "HexDocumentFull must require the template surface"

    @staticmethod
    def test_real_adapter_satisfies_full_protocol_at_runtime() -> None:
        """Verify a real-document-backed adapter conforms to HexDocumentFull.

        The adapter wraps a live ``intellicrack_hexcore.HexDocument`` and
        exposes the full protocol surface, so ``isinstance`` against the
        ``runtime_checkable`` ``HexDocumentFull`` must succeed and its delegated
        read access must return the real document's bytes as integers.
        """
        document = intellicrack_hexcore.HexDocument.open_bytes(b"MZ\x90\x00" + b"\x00" * 64)
        adapter = _RealHexDocumentAdapter(document)

        assert isinstance(adapter, HexDocumentFull) is True, "the adapter must satisfy HexDocumentFull"
        assert adapter.read(0, 4) == [0x4D, 0x5A, 0x90, 0x00], "adapter read must surface the real document bytes"
        assert adapter.length() == 68, "adapter length must reflect the real document size"

    @staticmethod
    def test_template_manager_bootstrap_drives_real_document_through_protocol(tmp_path: Path) -> None:
        """Verify a real document drives the HexDocumentFull consumer contract.

        Drives the real ``TemplateManager.bootstrap_builtins`` consumer - whose
        ``document`` parameter is typed ``HexDocumentFull`` - with a real
        hexcore document wrapped in a protocol-conforming adapter. The bootstrap
        must export every built-in template the document reports, writing
        matching JSON files whose ``name`` field equals the registry name and
        whose content equals the document's own export. This exercises the
        protocol's ``list_templates_detailed`` and ``export_template_json``
        methods against a real implementation, not a structural stub.

        Args:
            tmp_path: Pytest temporary directory.
        """
        document = intellicrack_hexcore.HexDocument.open_bytes(b"MZ" + b"\x00" * 256)
        adapter = _RealHexDocumentAdapter(document)

        detailed = document.list_templates_detailed()
        expected_names = {entry[0] for entry in detailed}
        assert expected_names, "real hexcore must report built-in templates"

        manager = TemplateManager(tmp_path)
        manager.bootstrap_builtins(adapter)

        assert manager.failed_templates == [], f"no template export must fail: {manager.failed_templates}"

        written = list((tmp_path / "templates" / "builtin").rglob("*.json"))
        written_names = {path.stem for path in written}
        assert expected_names.issubset(written_names), f"missing exported templates: {expected_names - written_names}"

        sample_name = min(expected_names)
        sample_path = next(path for path in written if path.stem == sample_name)
        parsed = json.loads(sample_path.read_text(encoding="utf-8"))
        assert parsed["name"] == sample_name, "exported template JSON must round-trip the registry name"
        expected_json = document.export_template_json(sample_name)
        assert sample_path.read_text(encoding="utf-8") == expected_json, "written file must equal the document's own export"


# =====================================================================
# F-0024 - SessionManager.update must offload SQLite I/O and serialize concurrent writers
# =====================================================================


class _InstrumentedSessionStore(SessionStore):
    """Real SessionStore subclass that records save threads and write overlap.

    Drives genuine SQLite persistence through ``super().save`` while recording
    the thread each save runs on and the peak number of overlapping save calls.
    This is a real store (not a mock): every recorded save persists real data.
    """

    def __init__(self, db_path: Path) -> None:
        """Initialise the instrumented store.

        Args:
            db_path: Path to the SQLite database file.
        """
        super().__init__(db_path)
        self.save_thread_ids: list[int] = []
        self._overlap_lock = threading.Lock()
        self._active_saves = 0
        self.max_concurrent_saves = 0

    def save(self, session: Session) -> None:
        """Persist ``session`` while recording thread and concurrency.

        Args:
            session: Session to persist.
        """
        with self._overlap_lock:
            self._active_saves += 1
            self.max_concurrent_saves = max(self.max_concurrent_saves, self._active_saves)
            self.save_thread_ids.append(threading.get_ident())
        try:
            super().save(session)
        finally:
            with self._overlap_lock:
                self._active_saves -= 1


class TestSessionManagerUpdateOffloadsAndSerialises:
    """F-0024: update() must run SQLite I/O off the event loop and never race."""

    @staticmethod
    @pytest.mark.asyncio
    async def test_update_runs_in_worker_thread(tmp_path: Path) -> None:
        """Verify SessionManager.update offloads SQLite I/O off the event loop thread.

        Uses a real SessionStore subclass (no monkeypatch) that records the
        thread each persisted save runs on. The recorded thread must differ
        from the event loop thread, proving ``asyncio.to_thread`` is used.

        Args:
            tmp_path: Pytest temporary directory.
        """
        store = _InstrumentedSessionStore(tmp_path / "sessions.db")
        manager = SessionManager(store, auto_save=False)
        session = _make_session()
        store.save(session)

        loop_thread = threading.get_ident()
        session.add_tag("offloaded")
        await manager.update(session)

        update_save_threads = store.save_thread_ids[1:]
        assert update_save_threads, "manager.update must invoke store.save"
        assert all(tid != loop_thread for tid in update_save_threads), "SessionManager.update must run SQLite I/O off the event loop thread"

        loaded = store.load(session.id)
        assert loaded is not None
        assert "offloaded" in loaded.tags, "the offloaded update must actually persist"

    @staticmethod
    @pytest.mark.asyncio
    async def test_concurrent_updates_serialise_and_persist_each_session(tmp_path: Path) -> None:
        """Verify concurrent updates serialise and persist every session intact.

        Mutates eight distinct sessions with unique tags and tool states, then
        issues all ``manager.update`` calls concurrently against a real
        instrumented store. The store records that at most one save ran at a
        time (lock serialisation), and every session is reloaded from SQLite
        and asserted field-by-field so partial or corrupted writes would fail.

        Args:
            tmp_path: Pytest temporary directory.
        """
        store = _InstrumentedSessionStore(tmp_path / "sessions.db")
        manager = SessionManager(store, auto_save=False)

        sessions = [_make_session(f"concurrent-{i}") for i in range(8)]
        targets = [Path(f"C:/samples/target-{i}.exe") for i in range(8)]
        for index, session in enumerate(sessions):
            session.add_tag(f"tag-{index}")
            session.set_tool_state(
                ToolState(
                    tool=ToolName.GHIDRA,
                    connected=True,
                    process_attached=index % 2 == 0,
                    target_path=targets[index],
                    last_error=None,
                ),
            )
            store.save(session)

        baseline_saves = len(store.save_thread_ids)
        await asyncio.gather(*(manager.update(session) for session in sessions))

        update_saves = len(store.save_thread_ids) - baseline_saves
        assert update_saves == len(sessions), f"every update must persist exactly once; saw {update_saves}"
        assert store.max_concurrent_saves == 1, f"updates must serialise SQLite writes; saw {store.max_concurrent_saves} overlapping"

        for index, session in enumerate(sessions):
            loaded = store.load(session.id)
            assert loaded is not None, f"session {index} vanished"
            assert loaded.id == session.id
            assert loaded.name == f"concurrent-{index}"
            assert loaded.tags == [f"tag-{index}"], f"tags corrupted for session {index}: {loaded.tags}"
            assert ToolName.GHIDRA in loaded.tool_states, f"tool state lost for session {index}"
            restored = loaded.tool_states[ToolName.GHIDRA]
            assert restored.connected is True
            assert restored.process_attached is (index % 2 == 0)
            assert restored.target_path == targets[index]

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
