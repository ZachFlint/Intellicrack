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
    """F-0006: an exception in save() must not kill the auto-save task."""

    @staticmethod
    @pytest.mark.asyncio
    async def test_auto_save_loop_survives_exception_and_resumes(tmp_path: Path) -> None:
        """Verify auto-save loop continues after a transient save() failure.

        Args:
            tmp_path: Pytest temporary directory.
        """
        store = SessionStore(tmp_path / "sessions.db")
        manager = SessionManager(store, save_interval=0)
        await manager.create(provider=ProviderName.ANTHROPIC, model="claude", name="autosave")

        save_attempts = 0
        save_completed = asyncio.Event()
        original_save = SessionStore.save

        def flaky_save(self_store: SessionStore, session: Session) -> None:
            """Fail the first attempt, then succeed.

            Args:
                self_store: SessionStore instance.
                session: Session being saved.

            Raises:
                RuntimeError: Always raised on the very first invocation so
                    the auto-save loop must recover; subsequent invocations
                    delegate to the original ``SessionStore.save``.
            """
            nonlocal save_attempts
            save_attempts += 1
            if save_attempts == 1:
                msg = "transient sqlite failure"
                raise RuntimeError(msg)
            original_save(self_store, session)
            save_completed.set()

        previous = _swap_session_store_save(flaky_save)
        try:
            await asyncio.wait_for(save_completed.wait(), timeout=5.0)
        finally:
            _restore_session_store_save(previous)
            await manager.close()

        assert save_attempts >= 2, "auto-save loop must keep running after a save() failure"


# =====================================================================
# F-0007 / F-0008 - Session writers for tool_states and tags
# =====================================================================


class TestSessionToolStatesWriters:
    """F-0007: Session.tool_states must have a concrete writer that persists."""

    @staticmethod
    def test_session_has_set_tool_state() -> None:
        """Verify Session exposes a set_tool_state writer."""
        session = _make_session()
        assert hasattr(session, "set_tool_state"), "Session must expose set_tool_state writer"

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
    def test_session_has_add_tag() -> None:
        """Verify Session exposes add_tag and remove_tag writers."""
        session = _make_session()
        assert hasattr(session, "add_tag")
        assert hasattr(session, "remove_tag")

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
