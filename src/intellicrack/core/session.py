# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Session management for Intellicrack.

This module provides session state management including conversation history,
binary analysis state, and persistence to SQLite database.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from .logging import get_logger, log_session_operation
from .types import (
    BinaryInfo,
    ExportInfo,
    ImportInfo,
    LicensingAnalysis,
    Message,
    PatchInfo,
    ProviderName,
    SectionInfo,
    ToolCall,
    ToolName,
    ToolResult,
    ToolState,
)


if TYPE_CHECKING:
    from collections.abc import Iterator


_ERR_FILE_NOT_FOUND = "session file not found"
_ERR_INVALID_FORMAT = "invalid session file format"
_ERR_SESSION_NOT_FOUND = "session not found"
_ERR_SESSION_EXISTS = "session already exists"
_ERR_NO_CURRENT_SESSION = "no current session"

_logger = get_logger("core.session")


@dataclass
class SessionMetadata:
    """Metadata about a session.

    Attributes:
        id: Unique session identifier.
        name: Human-readable session name.
        created_at: When the session was created.
        updated_at: When the session was last modified.
        provider: LLM provider used.
        model: Model identifier.
        binary_count: Number of binaries loaded.
        message_count: Number of messages.
    """

    id: str
    name: str
    created_at: datetime
    updated_at: datetime
    provider: ProviderName
    model: str
    binary_count: int = 0
    message_count: int = 0


@dataclass
class Session:
    """Complete session state.

    Attributes:
        id: Unique session identifier.
        name: Human-readable session name.
        created_at: When the session was created.
        updated_at: When the session was last modified.
        binaries: List of loaded binaries.
        active_binary_index: Index of active binary.
        provider: LLM provider being used.
        model: Model identifier.
        messages: Conversation history.
        tool_states: State of each tool bridge.
        patches: Applied patches.
        licensing_analyses: Mapping of binary names to their licensing analysis.
        notes: User notes.
        tags: Session tags.
    """

    id: str
    name: str
    created_at: datetime
    updated_at: datetime
    provider: ProviderName
    model: str
    binaries: list[BinaryInfo] = field(default_factory=list)
    active_binary_index: int = -1
    messages: list[Message] = field(default_factory=list)
    tool_states: dict[ToolName, ToolState] = field(default_factory=dict)
    patches: list[PatchInfo] = field(default_factory=list)
    licensing_analyses: dict[str, LicensingAnalysis] = field(default_factory=dict)
    notes: str = ""
    tags: list[str] = field(default_factory=list)

    @classmethod
    def create(
        cls,
        provider: ProviderName,
        model: str,
        name: str | None = None,
    ) -> Session:
        """Create a new session.

        Args:
            provider: LLM provider to use.
            model: Model identifier.
            name: Optional session name.

        Returns:
            New Session instance.
        """
        session_id = str(uuid4())
        now = datetime.now()

        return cls(
            id=session_id,
            name=name or f"Session {now.strftime('%Y-%m-%d %H:%M')}",
            created_at=now,
            updated_at=now,
            provider=provider,
            model=model,
        )

    @property
    def active_binary(self) -> BinaryInfo | None:
        """Get the currently active binary.

        Returns:
            Active BinaryInfo or None.
        """
        if 0 <= self.active_binary_index < len(self.binaries):
            return self.binaries[self.active_binary_index]
        return None

    def add_binary(self, binary: BinaryInfo) -> None:
        """Add a binary to the session.

        Args:
            binary: Binary information to add.
        """
        self.binaries.append(binary)
        self.active_binary_index = max(self.active_binary_index, 0)
        self.updated_at = datetime.now()

    def add_message(self, message: Message) -> None:
        """Add a message to the conversation.

        Args:
            message: Message to add.
        """
        self.messages.append(message)
        self.updated_at = datetime.now()

    def add_patch(self, patch: PatchInfo) -> None:
        """Add a patch to the session.

        Args:
            patch: Patch information to add.
        """
        self.patches.append(patch)
        self.updated_at = datetime.now()

    def add_licensing_analysis(self, binary_name: str, analysis: LicensingAnalysis) -> None:
        """Add licensing analysis for a binary.

        Args:
            binary_name: Name of the analyzed binary.
            analysis: Licensing analysis results.
        """
        self.licensing_analyses[binary_name] = analysis
        self.updated_at = datetime.now()

    def get_licensing_analysis(self, binary_name: str) -> LicensingAnalysis | None:
        """Get licensing analysis for a binary.

        Args:
            binary_name: Name of the binary.

        Returns:
            LicensingAnalysis if available, None otherwise.
        """
        return self.licensing_analyses.get(binary_name)


class SessionStore:
    """SQLite-based session persistence.

    Handles storing and retrieving sessions from a SQLite database.

    Attributes:
        _db_path: Path to the SQLite database file.
    """

    def __init__(self, db_path: Path) -> None:
        """Initialize the session store.

        Args:
            db_path: Path to the SQLite database file.
        """
        self._db_path = db_path
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        _logger.debug("session_store_init", extra={"db_path": str(db_path)})
        self._init_database()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        """Get a database connection.

        Yields:
            SQLite connection.

        Raises:
            Exception: Re-raised from any database operation after rollback.
        """
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        _logger.debug("db_connection_opened", extra={"db_path": str(self._db_path)})
        try:
            yield conn
            conn.commit()
            _logger.debug("db_connection_committed", extra={"db_path": str(self._db_path)})
        except Exception:
            conn.rollback()
            _logger.exception("db_connection_rollback", extra={"db_path": str(self._db_path)})
            raise
        finally:
            conn.close()
            _logger.debug("db_connection_closed", extra={"db_path": str(self._db_path)})

    def _init_database(self) -> None:
        """Initialize the database schema."""
        _logger.debug("database_schema_init_start", extra={"db_path": str(self._db_path)})
        with self._connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    model TEXT NOT NULL,
                    active_binary_index INTEGER DEFAULT -1,
                    notes TEXT DEFAULT '',
                    data TEXT NOT NULL
                )
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_sessions_updated
                ON sessions (updated_at DESC)
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS session_tags (
                    session_id TEXT NOT NULL,
                    tag TEXT NOT NULL,
                    PRIMARY KEY (session_id, tag),
                    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
                )
            """)

            _logger.debug("database_schema_initialized")

    def save(self, session: Session) -> None:
        """Save a session to the database.

        Args:
            session: Session to save.
        """
        _logger.debug("session_save_start", extra={"session_id": session.id})
        session_data = {
            "binaries": [self._serialize_binary(b) for b in session.binaries],
            "messages": [self._serialize_message(m) for m in session.messages],
            "tool_states": {k.value: self._serialize_tool_state(v) for k, v in session.tool_states.items()},
            "patches": [self._serialize_patch(p) for p in session.patches],
        }

        with self._connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO sessions
                (id, name, created_at, updated_at, provider, model, active_binary_index, notes, data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    session.id,
                    session.name,
                    session.created_at.isoformat(),
                    session.updated_at.isoformat(),
                    session.provider.value,
                    session.model,
                    session.active_binary_index,
                    session.notes,
                    json.dumps(session_data),
                ),
            )

            conn.execute(
                "DELETE FROM session_tags WHERE session_id = ?",
                (session.id,),
            )

            for tag in session.tags:
                conn.execute(
                    "INSERT INTO session_tags (session_id, tag) VALUES (?, ?)",
                    (session.id, tag),
                )

        _logger.debug("session_saved", extra={"session_id": session.id})

    def load(self, session_id: str) -> Session | None:
        """Load a session from the database.

        Args:
            session_id: Session identifier.

        Returns:
            Session instance or None if not found.
        """
        _logger.debug("session_load_query", extra={"session_id": session_id})
        with self._connection() as conn:
            row = conn.execute(
                "SELECT * FROM sessions WHERE id = ?",
                (session_id,),
            ).fetchone()

            if row is None:
                _logger.debug("session_load_not_found", extra={"session_id": session_id})
                return None

            tags_rows = conn.execute(
                "SELECT tag FROM session_tags WHERE session_id = ?",
                (session_id,),
            ).fetchall()

            tags = [r["tag"] for r in tags_rows]

            data = json.loads(row["data"])

            session = Session(
                id=row["id"],
                name=row["name"],
                created_at=datetime.fromisoformat(row["created_at"]),
                updated_at=datetime.fromisoformat(row["updated_at"]),
                provider=ProviderName(row["provider"]),
                model=row["model"],
                active_binary_index=row["active_binary_index"],
                notes=row["notes"],
                tags=tags,
                binaries=[self._deserialize_binary(b) for b in data.get("binaries", [])],
                messages=[self._deserialize_message(m) for m in data.get("messages", [])],
                tool_states={ToolName(k): self._deserialize_tool_state(v) for k, v in data.get("tool_states", {}).items()},
                patches=[self._deserialize_patch(p) for p in data.get("patches", [])],
            )

            _logger.debug("session_loaded", extra={"session_id": session_id})
            return session

    def delete(self, session_id: str) -> bool:
        """Delete a session from the database.

        Args:
            session_id: Session identifier.

        Returns:
            True if deleted, False if not found.
        """
        _logger.debug("session_delete_query", extra={"session_id": session_id})
        with self._connection() as conn:
            cursor = conn.execute(
                "DELETE FROM sessions WHERE id = ?",
                (session_id,),
            )
            deleted = cursor.rowcount > 0

        if deleted:
            _logger.info("session_deleted", extra={"session_id": session_id})

        return deleted

    def list_all(self, limit: int = 100) -> list[SessionMetadata]:
        """List all sessions.

        Args:
            limit: Maximum number of sessions to return.

        Returns:
            List of session metadata.
        """
        _logger.debug("session_list_all_query", extra={"limit": limit})
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT id, name, created_at, updated_at, provider, model, data
                FROM sessions
                ORDER BY updated_at DESC
                LIMIT ?
            """,
                (limit,),
            ).fetchall()

            result: list[SessionMetadata] = []
            for row in rows:
                data = json.loads(row["data"])
                result.append(
                    SessionMetadata(
                        id=row["id"],
                        name=row["name"],
                        created_at=datetime.fromisoformat(row["created_at"]),
                        updated_at=datetime.fromisoformat(row["updated_at"]),
                        provider=ProviderName(row["provider"]),
                        model=row["model"],
                        binary_count=len(data.get("binaries", [])),
                        message_count=len(data.get("messages", [])),
                    )
                )

            _logger.debug("session_list_all_result", extra={"count": len(result)})
            return result

    def search_by_tag(self, tag: str) -> list[SessionMetadata]:
        """Search sessions by tag.

        Args:
            tag: Tag to search for.

        Returns:
            List of matching session metadata.
        """
        _logger.debug("session_search_by_tag_query", extra={"tag": tag})
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT s.id, s.name, s.created_at, s.updated_at, s.provider, s.model, s.data
                FROM sessions s
                INNER JOIN session_tags t ON s.id = t.session_id
                WHERE t.tag = ?
                ORDER BY s.updated_at DESC
            """,
                (tag,),
            ).fetchall()

            result: list[SessionMetadata] = []
            for row in rows:
                data = json.loads(row["data"])
                result.append(
                    SessionMetadata(
                        id=row["id"],
                        name=row["name"],
                        created_at=datetime.fromisoformat(row["created_at"]),
                        updated_at=datetime.fromisoformat(row["updated_at"]),
                        provider=ProviderName(row["provider"]),
                        model=row["model"],
                        binary_count=len(data.get("binaries", [])),
                        message_count=len(data.get("messages", [])),
                    )
                )

            _logger.debug("session_search_by_tag_result", extra={"tag": tag, "count": len(result)})
            return result

    def cleanup_old(self, days: int = 30) -> int:
        """Delete sessions older than specified days.

        Args:
            days: Number of days to keep.

        Returns:
            Number of sessions deleted.
        """
        _logger.debug("session_cleanup_old_start", extra={"days": days})
        cutoff = datetime.now().isoformat()

        with self._connection() as conn:
            cursor = conn.execute(
                """
                DELETE FROM sessions
                WHERE julianday(?) - julianday(updated_at) > ?
            """,
                (cutoff, days),
            )

            deleted = cursor.rowcount

        if deleted > 0:
            _logger.info("sessions_cleaned_up", extra={"deleted_count": deleted})

        return deleted

    @staticmethod
    def _serialize_binary(binary: BinaryInfo) -> dict[str, Any]:
        """Serialize BinaryInfo to dictionary.

        Args:
            binary: BinaryInfo instance to serialize.

        Returns:
            Dictionary representation of the binary information.
        """
        return {
            "path": str(binary.path),
            "name": binary.name,
            "size": binary.size,
            "md5": binary.md5,
            "sha256": binary.sha256,
            "file_type": binary.file_type,
            "architecture": binary.architecture,
            "is_64bit": binary.is_64bit,
            "entry_point": binary.entry_point,
            "sections": [asdict(s) for s in binary.sections],
            "imports": [asdict(i) for i in binary.imports],
            "exports": [asdict(e) for e in binary.exports],
        }

    @staticmethod
    def _deserialize_binary(data: dict[str, Any]) -> BinaryInfo:
        """Deserialize dictionary to BinaryInfo.

        Args:
            data: Dictionary containing serialized binary information.

        Returns:
            Reconstructed BinaryInfo instance.
        """
        return BinaryInfo(
            path=Path(data["path"]),
            name=data["name"],
            size=data["size"],
            md5=data["md5"],
            sha256=data["sha256"],
            file_type=data["file_type"],
            architecture=data["architecture"],
            is_64bit=data["is_64bit"],
            entry_point=data["entry_point"],
            sections=[SectionInfo(**s) for s in data.get("sections", [])],
            imports=[ImportInfo(**i) for i in data.get("imports", [])],
            exports=[ExportInfo(**e) for e in data.get("exports", [])],
        )

    @staticmethod
    def _serialize_message(message: Message) -> dict[str, Any]:
        """Serialize Message to dictionary.

        Args:
            message: Message instance to serialize.

        Returns:
            Dictionary representation of the message.
        """
        result: dict[str, Any] = {
            "role": message.role,
            "content": message.content,
            "timestamp": message.timestamp.isoformat(),
        }

        if message.tool_calls:
            result["tool_calls"] = [asdict(tc) for tc in message.tool_calls]

        if message.tool_results:
            result["tool_results"] = [
                {
                    "call_id": tr.call_id,
                    "success": tr.success,
                    "result": tr.result,
                    "error": tr.error,
                    "duration_ms": tr.duration_ms,
                }
                for tr in message.tool_results
            ]

        return result

    @staticmethod
    def _deserialize_message(data: dict[str, Any]) -> Message:
        """Deserialize dictionary to Message.

        Args:
            data: Dictionary containing serialized message data.

        Returns:
            Reconstructed Message instance.
        """
        tool_calls = None
        if "tool_calls" in data:
            tool_calls = [ToolCall(**tc) for tc in data["tool_calls"]]

        tool_results = None
        if "tool_results" in data:
            tool_results = [ToolResult(**tr) for tr in data["tool_results"]]

        return Message(
            role=data["role"],
            content=data["content"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            tool_calls=tool_calls,
            tool_results=tool_results,
        )

    @staticmethod
    def _serialize_tool_state(state: ToolState) -> dict[str, Any]:
        """Serialize ToolState to dictionary.

        Args:
            state: ToolState instance to serialize.

        Returns:
            Dictionary representation of the tool state.
        """
        return {
            "tool": state.tool.value,
            "connected": state.connected,
            "process_attached": state.process_attached,
            "target_path": str(state.target_path) if state.target_path else None,
            "last_error": state.last_error,
        }

    @staticmethod
    def _deserialize_tool_state(data: dict[str, Any]) -> ToolState:
        """Deserialize dictionary to ToolState.

        Args:
            data: Dictionary containing serialized tool state data.

        Returns:
            Reconstructed ToolState instance.
        """
        return ToolState(
            tool=ToolName(data["tool"]),
            connected=data["connected"],
            process_attached=data["process_attached"],
            target_path=Path(data["target_path"]) if data.get("target_path") else None,
            last_error=data.get("last_error"),
        )

    @staticmethod
    def _serialize_patch(patch: PatchInfo) -> dict[str, Any]:
        """Serialize PatchInfo to dictionary.

        Args:
            patch: PatchInfo instance to serialize.

        Returns:
            Dictionary representation of the patch information.
        """
        return {
            "address": patch.address,
            "original_bytes": patch.original_bytes.hex(),
            "new_bytes": patch.new_bytes.hex(),
            "description": patch.description,
            "applied": patch.applied,
        }

    @staticmethod
    def _deserialize_patch(data: dict[str, Any]) -> PatchInfo:
        """Deserialize dictionary to PatchInfo.

        Args:
            data: Dictionary containing serialized patch data.

        Returns:
            Reconstructed PatchInfo instance.
        """
        return PatchInfo(
            address=data["address"],
            original_bytes=bytes.fromhex(data["original_bytes"]),
            new_bytes=bytes.fromhex(data["new_bytes"]),
            description=data["description"],
            applied=data["applied"],
        )

    def export_to_json(self, session: Session, path: Path) -> None:
        """Export a session to a JSON file.

        Args:
            session: Session to export.
            path: Path to write the JSON file.
        """
        export_data = {
            "export_version": "1.0",
            "exported_at": datetime.now().isoformat(),
            "session": {
                "id": session.id,
                "name": session.name,
                "created_at": session.created_at.isoformat(),
                "updated_at": session.updated_at.isoformat(),
                "provider": session.provider.value,
                "model": session.model,
                "active_binary_index": session.active_binary_index,
                "notes": session.notes,
                "tags": session.tags,
                "binaries": [self._serialize_binary(b) for b in session.binaries],
                "messages": [self._serialize_message(m) for m in session.messages],
                "tool_states": {k.value: self._serialize_tool_state(v) for k, v in session.tool_states.items()},
                "patches": [self._serialize_patch(p) for p in session.patches],
            },
        }

        path.parent.mkdir(parents=True, exist_ok=True)
        _logger.debug("session_export_file_write", extra={"session_id": session.id, "path": str(path)})
        with open(path, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)

        _logger.info("session_exported", extra={"session_id": session.id, "path": str(path)})

    def import_from_json(self, path: Path) -> Session:
        """Import a session from a JSON file.

        Args:
            path: Path to the JSON file.

        Returns:
            Imported Session instance.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the file format is invalid.
        """
        if not path.exists():
            raise FileNotFoundError(_ERR_FILE_NOT_FOUND)

        _logger.debug("session_import_file_read", extra={"path": str(path)})
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        session_data = data.get("session", data)

        if "id" not in session_data or "provider" not in session_data:
            raise ValueError(_ERR_INVALID_FORMAT)

        tool_states: dict[ToolName, ToolState] = {}
        for key, value in session_data.get("tool_states", {}).items():
            try:
                tool_name = ToolName(key)
                tool_states[tool_name] = self._deserialize_tool_state(value)
            except ValueError:
                _logger.warning("unknown_tool_name_in_import", extra={"tool_name": key})
                continue

        session = Session(
            id=session_data["id"],
            name=session_data.get("name", "Imported Session"),
            created_at=datetime.fromisoformat(session_data["created_at"]),
            updated_at=datetime.fromisoformat(session_data["updated_at"]),
            provider=ProviderName(session_data["provider"]),
            model=session_data.get("model", "unknown"),
            active_binary_index=session_data.get("active_binary_index", -1),
            notes=session_data.get("notes", ""),
            tags=session_data.get("tags", []),
            binaries=[self._deserialize_binary(b) for b in session_data.get("binaries", [])],
            messages=[self._deserialize_message(m) for m in session_data.get("messages", [])],
            tool_states=tool_states,
            patches=[self._deserialize_patch(p) for p in session_data.get("patches", [])],
        )

        _logger.info("session_imported", extra={"session_id": session.id, "path": str(path)})
        return session


class SessionManager:
    """Manages session lifecycle and persistence.

    Coordinates between the active session and the session store.

    Attributes:
        _store: Session persistence store.
        _current: Currently active session.
        _auto_save: Whether to auto-save changes.
        _save_interval: Interval between auto-saves in seconds.
    """

    def __init__(
        self,
        store: SessionStore,
        auto_save: bool = True,
        save_interval: int = 300,
    ) -> None:
        """Initialize the session manager.

        Args:
            store: Session persistence store.
            auto_save: Whether to auto-save changes.
            save_interval: Interval between auto-saves in seconds.
        """
        self._store = store
        self._current: Session | None = None
        self._auto_save = auto_save
        self._save_interval = save_interval
        self._save_task: asyncio.Task[None] | None = None
        _logger.debug("session_manager_init", extra={"auto_save": auto_save, "save_interval": save_interval})

    @property
    def current(self) -> Session | None:
        """Get the current session.

        Returns:
            Current session or None.
        """
        return self._current

    async def create(
        self,
        provider: ProviderName,
        model: str,
        name: str | None = None,
    ) -> Session:
        """Create a new session.

        Args:
            provider: LLM provider to use.
            model: Model identifier.
            name: Optional session name.

        Returns:
            New Session instance.
        """
        if self._current is not None:
            await self.save()

        session = Session.create(provider, model, name)
        self._current = session

        await self.save()
        await self._start_auto_save()

        log_session_operation("create", session.id, provider=provider.value, model=model)
        _logger.info("session_created", extra={"session_id": session.id})
        return session

    async def load(self, session_id: str) -> Session | None:
        """Load a session.

        Args:
            session_id: Session identifier.

        Returns:
            Session instance or None if not found.
        """
        if self._current is not None:
            await self.save()

        session = self._store.load(session_id)

        if session is not None:
            self._current = session
            await self._start_auto_save()
            _logger.info("session_loaded", extra={"session_id": session_id})

        return session

    async def get(self, session_id: str) -> Session | None:
        """Get a session by ID without making it current.

        Args:
            session_id: Session identifier.

        Returns:
            Session instance or None if not found.
        """
        return self._store.load(session_id)

    async def update(self, session: Session) -> None:
        """Update a session in the store.

        Args:
            session: Session to update.
        """
        self._store.save(session)
        _logger.debug("session_updated", extra={"session_id": session.id})

    async def save(self) -> None:
        """Save the current session."""
        if self._current is not None:
            self._store.save(self._current)
            log_session_operation("save", self._current.id)
            _logger.debug("current_session_saved", extra={"session_id": self._current.id})

    async def close(self) -> None:
        """Close the current session."""
        await self._stop_auto_save()

        if self._current is not None:
            await self.save()
            _logger.info("session_closed", extra={"session_id": self._current.id})
            self._current = None

    async def delete(self, session_id: str) -> bool:
        """Delete a session.

        Args:
            session_id: Session identifier.

        Returns:
            True if deleted.
        """
        if self._current is not None and self._current.id == session_id:
            await self._stop_auto_save()
            self._current = None

        return self._store.delete(session_id)

    def list_sessions(self, limit: int = 100) -> list[SessionMetadata]:
        """List all sessions.

        Args:
            limit: Maximum number to return.

        Returns:
            List of session metadata.
        """
        return self._store.list_all(limit)

    def search_by_tag(self, tag: str) -> list[SessionMetadata]:
        """Search sessions by tag.

        Args:
            tag: Tag to search for.

        Returns:
            List of matching session metadata.
        """
        return self._store.search_by_tag(tag)

    async def cleanup(self, days: int = 30) -> int:
        """Clean up old sessions.

        Args:
            days: Number of days to keep.

        Returns:
            Number of sessions deleted.
        """
        return self._store.cleanup_old(days)

    async def export_json(self, session_id: str, path: Path) -> None:
        """Export a session to a JSON file.

        Args:
            session_id: Session identifier to export.
            path: Path to write the JSON file.

        Raises:
            ValueError: If the session is not found.
        """
        session = self._store.load(session_id)
        if session is None:
            raise ValueError(_ERR_SESSION_NOT_FOUND)

        self._store.export_to_json(session, path)

    async def import_json(self, path: Path, replace: bool = False) -> Session:
        """Import a session from a JSON file.

        Args:
            path: Path to the JSON file.
            replace: Whether to replace existing session with same ID.

        Returns:
            Imported Session instance.

        Raises:
            ValueError: If session with same ID already exists and replace=False.
        """
        session = self._store.import_from_json(path)

        existing = self._store.load(session.id)
        if existing is not None and not replace:
            raise ValueError(_ERR_SESSION_EXISTS)

        self._store.save(session)
        return session

    async def export_current(self, path: Path) -> None:
        """Export the current session to a JSON file.

        Args:
            path: Path to write the JSON file.

        Raises:
            ValueError: If no current session exists.
        """
        if self._current is None:
            raise ValueError(_ERR_NO_CURRENT_SESSION)

        self._store.export_to_json(self._current, path)

    async def _start_auto_save(self) -> None:
        """Start the auto-save task."""
        await self._stop_auto_save()

        if self._auto_save:
            self._save_task = asyncio.create_task(self._auto_save_loop())

    async def _stop_auto_save(self) -> None:
        """Stop the auto-save task."""
        if self._save_task is not None:
            self._save_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._save_task
            self._save_task = None

    async def _auto_save_loop(self) -> None:
        """Auto-save loop."""
        while True:
            await asyncio.sleep(self._save_interval)
            await self.save()
