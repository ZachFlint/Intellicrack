# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for Intellicrack main module initialization.

Tests validate:
- SessionStore initialization with database path
- SessionManager initialization with SessionStore (not db path directly)
- Application configuration loading
- Provider registry initialization
- Tool registry initialization
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from contextlib import AbstractContextManager
from typing import TYPE_CHECKING, cast


if TYPE_CHECKING:
    from pathlib import Path

import pytest

from intellicrack.core.config import Config, get_config_dir
from intellicrack.core.logging import get_logger
from intellicrack.core.script_gen import ScriptGenerator, ScriptManager, ScriptValidator
from intellicrack.core.session import Session, SessionManager, SessionStore
from intellicrack.core.template_manager import TemplateManager
from intellicrack.core.types import ProviderName
from intellicrack.main import init_script_engine, init_template_manager


def _store_connection(store: SessionStore) -> AbstractContextManager[sqlite3.Connection]:
    """Return the SessionStore's connection context manager via ``getattr``.

    Args:
        store: The SessionStore whose connection manager should be returned.

    Returns:
        AbstractContextManager[sqlite3.Connection]: Context manager yielding a
        configured sqlite3 connection with ``sqlite3.Row`` row factory.
    """
    connection_method = cast(
        Callable[[], AbstractContextManager[sqlite3.Connection]],
        getattr(store, "_connection"),
    )
    return connection_method()


DEFAULT_SAVE_INTERVAL = 300
CUSTOM_SAVE_INTERVAL = 60
EXPECTED_MIN_SESSION_COUNT = 2


class TestSessionStoreInitialization:
    """Test SessionStore initialization with database paths."""

    @staticmethod
    def test_session_store_creates_database_file(tmp_path: Path) -> None:
        """Verify SessionStore creates the database file on init.

        Args:
            tmp_path: Pytest temporary directory for the session database.
        """
        db_path = tmp_path / "sessions.db"
        assert not db_path.exists()

        store = SessionStore(db_path)

        assert db_path.exists()
        assert store.db_path == db_path

    @staticmethod
    def test_session_store_creates_parent_directories(tmp_path: Path) -> None:
        """Verify SessionStore creates parent directories if missing.

        Args:
            tmp_path: Pytest temporary directory used as the parent root.
        """
        db_path = tmp_path / "data" / "subdir" / "sessions.db"
        assert not db_path.parent.exists()

        _store = SessionStore(db_path)

        assert db_path.parent.exists()
        assert db_path.exists()

    @staticmethod
    def test_session_store_initializes_schema(tmp_path: Path) -> None:
        """Verify SessionStore creates required database tables.

        Args:
            tmp_path: Pytest temporary directory for the session database.
        """
        db_path = tmp_path / "sessions.db"
        store = SessionStore(db_path)

        with _store_connection(store) as conn:
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            rows = cast(list[sqlite3.Row], cursor.fetchall())
            table_names = {str(row["name"]) for row in rows}

        assert "sessions" in table_names
        assert "session_tags" in table_names


class TestSessionManagerInitialization:
    """Test SessionManager initialization with SessionStore."""

    @staticmethod
    def test_session_manager_requires_session_store(tmp_path: Path) -> None:
        """Verify SessionManager is initialized with SessionStore instance.

        Args:
            tmp_path: Pytest temporary directory for the session database.
        """
        db_path = tmp_path / "sessions.db"
        store = SessionStore(db_path)

        manager = SessionManager(store)

        assert manager.store is store
        assert manager.current is None

    @staticmethod
    def test_session_manager_requires_session_store_type(tmp_path: Path) -> None:
        """Verify manager.store performs a full-field round-trip through the real SQLite backend.

        The gate checks every injected field (name, provider, model, notes, tags)
        against the values read back via manager.store.load(), AND independently
        queries the raw SQLite ``sessions.provider`` column via a direct
        sqlite3.connect() call to confirm the enum value was serialised correctly.

        This distinguishes it from TestSessionDataIntegrity.test_session_roundtrip
        (which calls store directly): this test verifies the SessionManager.store
        reference is wired to the same real backend, not a stub.

        Falsifiability mutation (documented, not executed):
            In src/intellicrack/core/session.py SessionStore._save_session_transaction(),
            replace ``session.provider.value`` with ``"openai"`` in the INSERT VALUES
            tuple. The direct SQL oracle query ``SELECT provider FROM sessions WHERE id=?``
            would then return ``"openai"`` instead of ``"anthropic"``, failing
            ``assert raw_provider == ProviderName.ANTHROPIC.value``.

        Args:
            tmp_path: Pytest temporary directory for the session database.
        """
        db_path = tmp_path / "sessions.db"
        store = SessionStore(db_path)
        manager = SessionManager(store)

        session = Session.create(
            provider=ProviderName.ANTHROPIC,
            model="claude-3-opus-20240229",
            name="Store-type gate",
        )
        session.notes = "manager-wiring-check"
        session.tags = ["gate", "manager"]

        manager.store.save(session)
        loaded = manager.store.load(session.id)

        assert loaded is not None
        assert loaded.id == session.id
        assert loaded.name == "Store-type gate"
        assert loaded.provider == ProviderName.ANTHROPIC
        assert loaded.model == "claude-3-opus-20240229"
        assert loaded.notes == "manager-wiring-check"
        assert set(loaded.tags) == {"gate", "manager"}

        raw_conn = sqlite3.connect(str(db_path))
        raw_conn.row_factory = sqlite3.Row
        try:
            row = raw_conn.execute(
                "SELECT provider, name, model, notes FROM sessions WHERE id = ?",
                (session.id,),
            ).fetchone()
        finally:
            raw_conn.close()

        assert row is not None
        raw_provider = str(row["provider"])
        raw_name = str(row["name"])
        raw_model = str(row["model"])
        raw_notes = str(row["notes"])

        assert raw_provider == ProviderName.ANTHROPIC.value
        assert raw_name == "Store-type gate"
        assert raw_model == "claude-3-opus-20240229"
        assert raw_notes == "manager-wiring-check"

    @staticmethod
    def test_session_manager_auto_save_default(tmp_path: Path) -> None:
        """Verify SessionManager has auto_save enabled by default.

        Args:
            tmp_path: Pytest temporary directory for the session database.
        """
        store = SessionStore(tmp_path / "sessions.db")
        manager = SessionManager(store)

        assert manager.auto_save is True

    @staticmethod
    def test_session_manager_auto_save_can_be_disabled(tmp_path: Path) -> None:
        """Verify SessionManager auto_save can be disabled.

        Args:
            tmp_path: Pytest temporary directory for the session database.
        """
        store = SessionStore(tmp_path / "sessions.db")
        manager = SessionManager(store, auto_save=False)

        assert manager.auto_save is False

    @staticmethod
    def test_session_manager_save_interval_default(tmp_path: Path) -> None:
        """Verify SessionManager has default save interval of 300 seconds.

        Args:
            tmp_path: Pytest temporary directory for the session database.
        """
        store = SessionStore(tmp_path / "sessions.db")
        manager = SessionManager(store)

        assert manager.save_interval == DEFAULT_SAVE_INTERVAL

    @staticmethod
    def test_session_manager_save_interval_configurable(tmp_path: Path) -> None:
        """Verify SessionManager save interval is configurable.

        Args:
            tmp_path: Pytest temporary directory for the session database.
        """
        store = SessionStore(tmp_path / "sessions.db")
        manager = SessionManager(store, save_interval=CUSTOM_SAVE_INTERVAL)

        assert manager.save_interval == CUSTOM_SAVE_INTERVAL


class TestSessionManagerOperations:
    """Test SessionManager CRUD operations."""

    @staticmethod
    @pytest.fixture
    def manager(tmp_path: Path) -> SessionManager:
        """Create a SessionManager with temporary database.

        Args:
            tmp_path: Pytest temporary directory.

        Returns:
            SessionManager: A session manager with a temporary database.
        """
        store = SessionStore(tmp_path / "sessions.db")
        return SessionManager(store)

    @staticmethod
    @pytest.mark.asyncio
    async def test_create_session(manager: SessionManager) -> None:
        """Verify SessionManager can create a new session.

        Args:
            manager: SessionManager fixture backed by a temporary database.
        """
        session = await manager.create(
            provider=ProviderName.ANTHROPIC,
            model="claude-3-opus-20240229",
            name="Test Session",
        )

        assert session.name == "Test Session"
        assert session.provider == ProviderName.ANTHROPIC
        assert session.model == "claude-3-opus-20240229"
        assert manager.current is session

    @staticmethod
    @pytest.mark.asyncio
    async def test_save_and_load_session(manager: SessionManager) -> None:
        """Verify SessionManager can save and load sessions.

        Args:
            manager: SessionManager fixture backed by a temporary database.
        """
        session = await manager.create(
            provider=ProviderName.OPENAI,
            model="gpt-4",
            name="Persistent Session",
        )
        session_id = session.id

        await manager.save()

        new_store = SessionStore(manager.store.db_path)
        new_manager = SessionManager(new_store)

        loaded = await new_manager.load(session_id)

        assert loaded is not None
        assert loaded.name == "Persistent Session"
        assert loaded.provider == ProviderName.OPENAI

    @staticmethod
    @pytest.mark.asyncio
    async def test_list_sessions(manager: SessionManager) -> None:
        """Verify SessionManager can list all sessions.

        Args:
            manager: SessionManager fixture backed by a temporary database.
        """
        await manager.create(
            provider=ProviderName.ANTHROPIC,
            model="claude-3-opus-20240229",
            name="Session 1",
        )
        await manager.save()

        await manager.create(
            provider=ProviderName.OPENAI,
            model="gpt-4",
            name="Session 2",
        )
        await manager.save()

        sessions = manager.list_sessions()

        assert len(sessions) >= EXPECTED_MIN_SESSION_COUNT
        names = {s.name for s in sessions}
        assert "Session 1" in names
        assert "Session 2" in names


class TestSessionDataIntegrity:
    """Test session data persistence integrity."""

    @staticmethod
    @pytest.fixture
    def store(tmp_path: Path) -> SessionStore:
        """Create a SessionStore with temporary database.

        Args:
            tmp_path: Pytest temporary directory.

        Returns:
            SessionStore: A session store with a temporary database.
        """
        return SessionStore(tmp_path / "sessions.db")

    @staticmethod
    def test_session_roundtrip(store: SessionStore) -> None:
        """Verify session data survives save/load cycle.

        Args:
            store: SessionStore fixture backed by a temporary database.
        """
        session = Session.create(
            provider=ProviderName.GOOGLE,
            model="gemini-pro",
            name="Roundtrip Test",
        )
        session.notes = "Test notes for integrity check"
        session.tags = ["test", "integrity"]

        store.save(session)
        loaded = store.load(session.id)

        assert loaded is not None
        assert loaded.id == session.id
        assert loaded.name == session.name
        assert loaded.provider == session.provider
        assert loaded.model == session.model
        assert loaded.notes == session.notes
        assert set(loaded.tags) == set(session.tags)

    @staticmethod
    def test_session_not_found_returns_none(store: SessionStore) -> None:
        """Verify loading non-existent session returns None.

        Args:
            store: SessionStore fixture backed by a temporary database.
        """
        result = store.load("nonexistent-session-id")
        assert result is None

    @staticmethod
    def test_session_delete(store: SessionStore) -> None:
        """Verify session can be deleted.

        Args:
            store: SessionStore fixture backed by a temporary database.
        """
        session = Session.create(
            provider=ProviderName.OLLAMA,
            model="llama2",
            name="Delete Test",
        )
        store.save(session)

        assert store.load(session.id) is not None

        deleted = store.delete(session.id)

        assert deleted is True
        assert store.load(session.id) is None

    @staticmethod
    def test_delete_nonexistent_session_returns_false(store: SessionStore) -> None:
        """Verify deleting non-existent session returns False.

        Args:
            store: SessionStore fixture backed by a temporary database.
        """
        result = store.delete("nonexistent-session-id")
        assert result is False


class TestStartupWiring:
    """Test startup-time wiring of TemplateManager and ScriptGenerator."""

    @staticmethod
    def test_init_script_engine_returns_three_components(tmp_path: Path) -> None:
        """_init_script_engine returns (manager, validator, generator) triple.

        Args:
            tmp_path: Pytest temporary directory used as the data root.
        """
        config = Config.default()
        config.data_directory = tmp_path / "data"
        config.data_directory.mkdir(parents=True, exist_ok=True)
        logger = get_logger("test")

        manager, validator, generator = init_script_engine(config, logger)

        assert isinstance(manager, ScriptManager)
        assert isinstance(validator, ScriptValidator)
        assert isinstance(generator, ScriptGenerator)
        assert (config.data_directory / "scripts").is_dir()

    @staticmethod
    def test_init_template_manager_creates_directories() -> None:
        """_init_template_manager builds template tree under config_dir."""
        logger = get_logger("test")
        manager = init_template_manager(logger)

        assert isinstance(manager, TemplateManager)
        templates_dir = get_config_dir() / "templates"
        assert templates_dir.is_dir()
        assert (templates_dir / "builtin").is_dir()
        assert (templates_dir / "user").is_dir()
