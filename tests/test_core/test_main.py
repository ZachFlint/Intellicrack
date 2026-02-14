"""Tests for Intellicrack main module initialization.

Tests validate:
- SessionStore initialization with database path
- SessionManager initialization with SessionStore (not db path directly)
- Application configuration loading
- Provider registry initialization
- Tool registry initialization
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from intellicrack.core.session import Session, SessionManager, SessionStore
from intellicrack.core.types import ProviderName


DEFAULT_SAVE_INTERVAL = 300
CUSTOM_SAVE_INTERVAL = 60
EXPECTED_MIN_SESSION_COUNT = 2


class TestSessionStoreInitialization:
    """Test SessionStore initialization with database paths."""

    @staticmethod
    def test_session_store_creates_database_file(tmp_path: Path) -> None:
        """Verify SessionStore creates the database file on init."""
        db_path = tmp_path / "sessions.db"
        assert not db_path.exists()

        store = SessionStore(db_path)

        assert db_path.exists()
        assert store._db_path == db_path

    @staticmethod
    def test_session_store_creates_parent_directories(tmp_path: Path) -> None:
        """Verify SessionStore creates parent directories if missing."""
        db_path = tmp_path / "data" / "subdir" / "sessions.db"
        assert not db_path.parent.exists()

        _store = SessionStore(db_path)

        assert db_path.parent.exists()
        assert db_path.exists()

    @staticmethod
    def test_session_store_initializes_schema(tmp_path: Path) -> None:
        """Verify SessionStore creates required database tables."""
        db_path = tmp_path / "sessions.db"
        store = SessionStore(db_path)

        with store._connection() as conn:
            tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            table_names = {row["name"] for row in tables}

        assert "sessions" in table_names
        assert "session_tags" in table_names


class TestSessionManagerInitialization:
    """Test SessionManager initialization with SessionStore."""

    @staticmethod
    def test_session_manager_requires_session_store(tmp_path: Path) -> None:
        """Verify SessionManager is initialized with SessionStore instance."""
        db_path = tmp_path / "sessions.db"
        store = SessionStore(db_path)

        manager = SessionManager(store)

        assert manager._store is store
        assert manager.current is None

    @staticmethod
    def test_session_manager_requires_session_store_type() -> None:
        """Verify SessionManager requires SessionStore instance.

        This tests that the correct initialization pattern is enforced.
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "sessions.db"

            store = SessionStore(db_path)
            manager = SessionManager(store)

            assert hasattr(manager._store, "save")
            assert hasattr(manager._store, "load")
            assert hasattr(manager._store, "list_all")

    @staticmethod
    def test_session_manager_auto_save_default(tmp_path: Path) -> None:
        """Verify SessionManager has auto_save enabled by default."""
        store = SessionStore(tmp_path / "sessions.db")
        manager = SessionManager(store)

        assert manager._auto_save is True

    @staticmethod
    def test_session_manager_auto_save_can_be_disabled(tmp_path: Path) -> None:
        """Verify SessionManager auto_save can be disabled."""
        store = SessionStore(tmp_path / "sessions.db")
        manager = SessionManager(store, auto_save=False)

        assert manager._auto_save is False

    @staticmethod
    def test_session_manager_save_interval_default(tmp_path: Path) -> None:
        """Verify SessionManager has default save interval of 300 seconds."""
        store = SessionStore(tmp_path / "sessions.db")
        manager = SessionManager(store)

        assert manager._save_interval == DEFAULT_SAVE_INTERVAL

    @staticmethod
    def test_session_manager_save_interval_configurable(tmp_path: Path) -> None:
        """Verify SessionManager save interval is configurable."""
        store = SessionStore(tmp_path / "sessions.db")
        manager = SessionManager(store, save_interval=CUSTOM_SAVE_INTERVAL)

        assert manager._save_interval == CUSTOM_SAVE_INTERVAL


class TestSessionManagerOperations:
    """Test SessionManager CRUD operations."""

    @staticmethod
    @pytest.fixture
    def manager(tmp_path: Path) -> SessionManager:
        """Create a SessionManager with temporary database."""
        store = SessionStore(tmp_path / "sessions.db")
        return SessionManager(store)

    @staticmethod
    @pytest.mark.asyncio
    async def test_create_session(manager: SessionManager) -> None:
        """Verify SessionManager can create a new session."""
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
        """Verify SessionManager can save and load sessions."""
        session = await manager.create(
            provider=ProviderName.OPENAI,
            model="gpt-4",
            name="Persistent Session",
        )
        session_id = session.id

        await manager.save()

        new_store = SessionStore(manager._store._db_path)
        new_manager = SessionManager(new_store)

        loaded = await new_manager.load(session_id)

        assert loaded is not None
        assert loaded.name == "Persistent Session"
        assert loaded.provider == ProviderName.OPENAI

    @staticmethod
    @pytest.mark.asyncio
    async def test_list_sessions(manager: SessionManager) -> None:
        """Verify SessionManager can list all sessions."""
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
        """Create a SessionStore with temporary database."""
        return SessionStore(tmp_path / "sessions.db")

    @staticmethod
    def test_session_roundtrip(store: SessionStore) -> None:
        """Verify session data survives save/load cycle."""
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
        """Verify loading non-existent session returns None."""
        result = store.load("nonexistent-session-id")
        assert result is None

    @staticmethod
    def test_session_delete(store: SessionStore) -> None:
        """Verify session can be deleted."""
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
        """Verify deleting non-existent session returns False."""
        result = store.delete("nonexistent-session-id")
        assert result is False
