# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Session management for Intellicrack.

This module provides session state management including conversation history, binary analysis state, and persistence to SQLite database.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from .logging import get_logger, log_session_operation
from .types import (
    BinaryInfo,
    BridgeAnalysisSummary,
    ExportInfo,
    FunctionInfo,
    ImportInfo,
    Message,
    ParameterInfo,
    PatchInfo,
    ProviderName,
    SectionInfo,
    StringInfo,
    ToolCall,
    ToolName,
    ToolResult,
    ToolState,
    VariableInfo,
)


if TYPE_CHECKING:
    from collections.abc import Generator


_ERR_FILE_NOT_FOUND = "session file not found"
_ERR_INVALID_FORMAT = "invalid session file format"
_ERR_SESSION_NOT_FOUND = "session not found"
_ERR_SESSION_EXISTS = "session already exists"
_ERR_NO_CURRENT_SESSION = "no current session"
_ERR_EMPTY_TAG = "session tag must be a non-empty, non-whitespace string"

_logger = get_logger(__name__)


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
        created_at: Timestamp when the session was created.
        updated_at: Timestamp of the last session update.
        provider: LLM provider used for this session.
        model: Model identifier used for this session.
        binaries: List of loaded binaries.
        active_binary_index: Index of active binary.
        messages: Conversation history.
        tool_states: State of each tool bridge.
        patches: Applied patches.
        bridge_analyses: Mapping of binary names to their bridge analysis summary.
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
    bridge_analyses: dict[str, BridgeAnalysisSummary] = field(default_factory=dict)
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
            Session: New Session instance.
        """
        session_id = str(uuid4())
        now = datetime.now(tz=UTC)

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
            BinaryInfo | None: Active BinaryInfo or None.
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
        self.updated_at = datetime.now(tz=UTC)

    def add_message(self, message: Message) -> None:
        """Add a message to the conversation.

        Args:
            message: Message to add.
        """
        self.messages.append(message)
        self.updated_at = datetime.now(tz=UTC)

    def add_patch(self, patch: PatchInfo) -> None:
        """Add a patch to the session.

        Args:
            patch: Patch information to add.
        """
        self.patches.append(patch)
        self.updated_at = datetime.now(tz=UTC)

    def add_bridge_analysis(self, binary_name: str, analysis: BridgeAnalysisSummary) -> None:
        """Add bridge analysis summary for a binary.

        Args:
            binary_name: Name of the analyzed binary.
            analysis: Bridge analysis summary results.
        """
        self.bridge_analyses[binary_name] = analysis
        self.updated_at = datetime.now(tz=UTC)

    def get_bridge_analysis(self, binary_name: str) -> BridgeAnalysisSummary | None:
        """Get bridge analysis summary for a binary.

        Args:
            binary_name: Name of the binary.

        Returns:
            BridgeAnalysisSummary | None: BridgeAnalysisSummary if available, None otherwise.
        """
        return self.bridge_analyses.get(binary_name)

    def set_tool_state(self, state: ToolState) -> None:
        """Record or replace the tool bridge state for ``state.tool``.

        This is the canonical writer for ``Session.tool_states``. Bridges call
        this whenever they connect, attach to a process, or surface an error so
        the persisted session reflects the current state of every integrated
        tool.

        Args:
            state: ToolState describing the bridge's current connection,
                attachment, target, and last error.
        """
        self.tool_states[state.tool] = state
        self.updated_at = datetime.now(tz=UTC)

    def clear_tool_state(self, tool: ToolName) -> bool:
        """Remove the recorded state for ``tool`` if present.

        Args:
            tool: Tool whose state should be cleared.

        Returns:
            bool: True if a state was removed, False if no state existed.
        """
        if tool in self.tool_states:
            del self.tool_states[tool]
            self.updated_at = datetime.now(tz=UTC)
            return True
        return False

    def add_tag(self, tag: str) -> bool:
        """Add a tag to the session.

        Args:
            tag: Non-empty tag string. Whitespace-only tags are rejected.

        Returns:
            bool: True if the tag was added, False if it was already present.

        Raises:
            ValueError: If ``tag`` is empty or whitespace-only.
        """
        normalised = tag.strip()
        if not normalised:
            raise ValueError(_ERR_EMPTY_TAG)
        if normalised in self.tags:
            return False
        self.tags.append(normalised)
        self.updated_at = datetime.now(tz=UTC)
        return True

    def remove_tag(self, tag: str) -> bool:
        """Remove a tag from the session if present.

        Args:
            tag: Tag string to remove. Leading/trailing whitespace is stripped
                to match the normalisation performed by ``add_tag``.

        Returns:
            bool: True if the tag was removed, False if it was not present.
        """
        normalised = tag.strip()
        if normalised in self.tags:
            self.tags.remove(normalised)
            self.updated_at = datetime.now(tz=UTC)
            return True
        return False


class SessionStore:
    """SQLite-based session persistence.

    Handles storing and retrieving sessions from a SQLite database.
    """

    def __init__(self, db_path: Path) -> None:
        """Initialize the SessionStore with a database path.

        Args:
            db_path: Path to the SQLite database file.
        """
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        _logger.debug("session_store_init", db_path=str(db_path))
        self._init_database()

    @contextmanager
    def _connection(self) -> Generator[sqlite3.Connection]:
        """Get a database connection.

        Yields:
            Generator[sqlite3.Connection]: Active database connection with
                auto-commit/rollback.

        Raises:
            sqlite3.Error: On database-level errors (re-raised after rollback).
            OSError: On filesystem-level errors (re-raised after rollback).
        """
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        _logger.debug("db_connection_opened", db_path=str(self.db_path))
        try:
            yield conn
            conn.commit()
            _logger.debug("db_connection_committed", db_path=str(self.db_path))
        except (sqlite3.Error, OSError):
            conn.rollback()
            _logger.exception("db_connection_rollback", db_path=str(self.db_path))
            raise
        finally:
            conn.close()
            _logger.info("db_connection_closed", db_path=str(self.db_path))

    def _init_database(self) -> None:
        """Initialize the database schema."""
        _logger.debug("database_schema_init_start", db_path=str(self.db_path))
        with self._connection() as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS sessions ( id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT
                NOT NULL, provider TEXT NOT NULL, model TEXT NOT NULL, active_binary_index INTEGER DEFAULT -1, notes TEXT DEFAULT '',

                data TEXT NOT NULL )
                """
                   ,
            )

            conn.execute(
                """CREATE INDEX IF NOT EXISTS idx_sessions_updated ON sessions (updated_at DESC)"""
                                                                                                   ,
            )

            conn.execute(
                """CREATE TABLE IF NOT EXISTS session_tags ( session_id TEXT NOT NULL, tag TEXT NOT NULL, PRIMARY KEY (session_id, tag),

                FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE )
                """
                   ,
            )

            _logger.debug("database_schema_initialized", db_path=str(self.db_path))

    def save(self, session: Session) -> None:
        """Save a session to the database.

        Persists the full session state inside a single SQLite transaction
        initiated with ``BEGIN IMMEDIATE`` so that the tag rewrite and the
        session upsert cannot be interleaved with a concurrent save (for
        example, from the auto-save loop).

        Args:
            session: Session to save.

        Raises:
            sqlite3.Error: If the SQLite engine reports a database-level error
                while writing the session or its tags.
            OSError: If the underlying SQLite file cannot be opened or written.
        """
        _logger.debug("session_save_start", session_id=session.id)
        session_data = {
            "binaries": [self._serialize_binary(b) for b in session.binaries],
            "messages": [self._serialize_message(m) for m in session.messages],
            "tool_states": {k.value: self._serialize_tool_state(v) for k, v in session.tool_states.items()},
            "patches": [self._serialize_patch(p) for p in session.patches],
            "bridge_analyses": {name: self._serialize_bridge_analysis(analysis) for name, analysis in session.bridge_analyses.items()},
        }

        conn = sqlite3.connect(str(self.db_path), isolation_level=None)
        _logger.debug("db_connection_opened", db_path=str(self.db_path))
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    """INSERT OR REPLACE INTO sessions (id, name, created_at, updated_at, provider, model, active_binary_index, notes, data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """
                       ,
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
                conn.execute("COMMIT")
                _logger.debug("db_connection_committed", db_path=str(self.db_path))
            except (sqlite3.Error, OSError):
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    _logger.exception("rollback_noop_failed", db_path=str(self.db_path))
                _logger.exception("db_connection_rollback", db_path=str(self.db_path))
                raise
        finally:
            conn.close()
            _logger.info("db_connection_closed", db_path=str(self.db_path))

        _logger.debug("session_saved", session_id=session.id)

    def load(self, session_id: str) -> Session | None:
        """Load a session from the database.

        Args:
            session_id: Session identifier.

        Returns:
            Session | None: Session instance or None if not found.
        """
        _logger.debug("session_load_query", session_id=session_id)
        with self._connection() as conn:
            row = conn.execute(
                "SELECT * FROM sessions WHERE id = ?",
                (session_id,),
            ).fetchone()

            if row is None:
                _logger.debug("session_load_not_found", session_id=session_id)
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
                bridge_analyses={name: self._deserialize_bridge_analysis(value) for name, value in data.get("bridge_analyses", {}).items()},
            )

            _logger.debug("session_loaded", session_id=session_id)
            return session

    def delete(self, session_id: str) -> bool:
        """Delete a session from the database.

        Args:
            session_id: Session identifier.

        Returns:
            bool: True if deleted, False if not found.
        """
        _logger.info("session_delete_query", session_id=session_id)
        with self._connection() as conn:
            cursor = conn.execute(
                "DELETE FROM sessions WHERE id = ?",
                (session_id,),
            )
            deleted = cursor.rowcount > 0

        if deleted:
            _logger.info("session_deleted", session_id=session_id)

        return deleted

    def list_all(self, limit: int = 100) -> list[SessionMetadata]:
        """List all sessions.

        Args:
            limit: Maximum number of sessions to return.

        Returns:
            list[SessionMetadata]: List of session metadata.
        """
        _logger.debug("session_list_all_query", limit=limit)
        with self._connection() as conn:
            rows = conn.execute(
                """SELECT id, name, created_at, updated_at, provider, model, data FROM sessions ORDER BY updated_at DESC LIMIT ?"""
                                                                                                                                   ,
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
                    ),
                )

            _logger.debug("session_list_all_result", count=len(result))
            return result

    def search_by_tag(self, tag: str) -> list[SessionMetadata]:
        """Search sessions by tag.

        Args:
            tag: Tag to search for.

        Returns:
            list[SessionMetadata]: List of matching session metadata.
        """
        _logger.debug("session_search_by_tag_query", tag=tag)
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
                    ),
                )

            _logger.debug("session_search_by_tag_result", tag=tag, count=len(result))
            return result

    def cleanup_old(self, days: int = 30) -> int:
        """Delete sessions older than specified days.

        The cutoff timestamp is precomputed in Python and compared directly
        against the stored ISO-8601 ``updated_at`` column via lexicographic
        ordering so SQLite's ``julianday`` does not need to parse
        timezone-aware ISO strings.

        Args:
            days: Number of days to keep.

        Returns:
            int: Number of sessions deleted.
        """
        _logger.debug("session_cleanup_old_start", days=days)
        cutoff = (datetime.now(tz=UTC) - timedelta(days=days)).isoformat()

        with self._connection() as conn:
            cursor = conn.execute(
                "DELETE FROM sessions WHERE updated_at < ?",
                (cutoff,),
            )

            deleted = cursor.rowcount

        if deleted > 0:
            _logger.info("sessions_cleaned_up", deleted_count=deleted)

        return deleted

    @staticmethod
    def _serialize_binary(binary: BinaryInfo) -> dict[str, Any]:
        """Serialize BinaryInfo to dictionary.

        Args:
            binary: BinaryInfo instance to serialize.

        Returns:
            dict[str, Any]: Dictionary representation of the binary information.
        """
        return {
            "path": str(binary.path),
            "name": binary.name,
            "size": binary.size,
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
            BinaryInfo: Reconstructed BinaryInfo instance.
        """
        return BinaryInfo(
            path=Path(data["path"]),
            name=data["name"],
            size=data["size"],
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
            dict[str, Any]: Dictionary representation of the message.
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
            Message: Reconstructed Message instance.
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
            dict[str, Any]: Dictionary representation of the tool state.
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
            ToolState: Reconstructed ToolState instance.
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
            dict[str, Any]: Dictionary representation of the patch information.
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
            PatchInfo: Reconstructed PatchInfo instance.
        """
        return PatchInfo(
            address=data["address"],
            original_bytes=bytes.fromhex(data["original_bytes"]),
            new_bytes=bytes.fromhex(data["new_bytes"]),
            description=data["description"],
            applied=data["applied"],
        )

    @staticmethod
    def _serialize_function(function: FunctionInfo) -> dict[str, Any]:
        """Serialize FunctionInfo to dictionary.

        Args:
            function: FunctionInfo instance to serialize.

        Returns:
            dict[str, Any]: Dictionary representation of the function information.
        """
        return {
            "name": function.name,
            "address": function.address,
            "size": function.size,
            "calling_convention": function.calling_convention,
            "return_type": function.return_type,
            "parameters": [asdict(p) for p in function.parameters],
            "local_variables": [asdict(v) for v in function.local_variables],
            "decompiled_code": function.decompiled_code,
            "disassembly": function.disassembly,
        }

    @staticmethod
    def _deserialize_function(data: dict[str, Any]) -> FunctionInfo:
        """Deserialize dictionary to FunctionInfo.

        Args:
            data: Dictionary containing serialized function data.

        Returns:
            FunctionInfo: Reconstructed FunctionInfo instance.
        """
        return FunctionInfo(
            name=data["name"],
            address=data["address"],
            size=data["size"],
            calling_convention=data["calling_convention"],
            return_type=data["return_type"],
            parameters=[ParameterInfo(**p) for p in data.get("parameters", [])],
            local_variables=[VariableInfo(**v) for v in data.get("local_variables", [])],
            decompiled_code=data.get("decompiled_code"),
            disassembly=data.get("disassembly"),
        )

    @classmethod
    def _serialize_bridge_analysis(cls, analysis: BridgeAnalysisSummary) -> dict[str, Any]:
        """Serialize BridgeAnalysisSummary to dictionary.

        Args:
            analysis: BridgeAnalysisSummary instance to serialize.

        Returns:
            dict[str, Any]: Dictionary representation of the bridge analysis summary.
        """
        return {
            "binary_name": analysis.binary_name,
            "strings": [asdict(s) for s in analysis.strings],
            "imports": [asdict(i) for i in analysis.imports],
            "exports": [asdict(e) for e in analysis.exports],
            "sections": [asdict(s) for s in analysis.sections],
            "functions": [cls._serialize_function(f) for f in analysis.functions],
            "format_info": analysis.format_info,
            "architecture": analysis.architecture,
            "source_bridges": list(analysis.source_bridges),
            "analysis_notes": list(analysis.analysis_notes),
        }

    @classmethod
    def _deserialize_bridge_analysis(cls, data: dict[str, Any]) -> BridgeAnalysisSummary:
        """Deserialize dictionary to BridgeAnalysisSummary.

        Args:
            data: Dictionary containing serialized bridge analysis data.

        Returns:
            BridgeAnalysisSummary: Reconstructed BridgeAnalysisSummary instance.
        """
        return BridgeAnalysisSummary(
            binary_name=data["binary_name"],
            strings=[StringInfo(**s) for s in data.get("strings", [])],
            imports=[ImportInfo(**i) for i in data.get("imports", [])],
            exports=[ExportInfo(**e) for e in data.get("exports", [])],
            sections=[SectionInfo(**s) for s in data.get("sections", [])],
            functions=[cls._deserialize_function(f) for f in data.get("functions", [])],
            format_info=data["format_info"],
            architecture=data["architecture"],
            source_bridges=list(data.get("source_bridges", [])),
            analysis_notes=list(data.get("analysis_notes", [])),
        )

    def export_to_json(self, session: Session, path: Path) -> None:
        """Export a session to a JSON file.

        Args:
            session: Session to export.
            path: Path to write the JSON file.
        """
        export_data = {
            "export_version": "1.0",
            "exported_at": datetime.now(tz=UTC).isoformat(),
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
                "bridge_analyses": {name: self._serialize_bridge_analysis(analysis) for name, analysis in session.bridge_analyses.items()},
            },
        }

        path.parent.mkdir(parents=True, exist_ok=True)
        _logger.info("session_export_file_write", session_id=session.id, path=str(path))
        with path.open("w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)

        _logger.info("session_exported", session_id=session.id, path=str(path))

    def import_from_json(self, path: Path) -> Session:
        """Import a session from a JSON file.

        Args:
            path: Path to the JSON file.

        Returns:
            Session: Imported Session instance.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the file format is invalid.
        """
        if not path.exists():
            _logger.error("session_import_file_missing", path=str(path))
            raise FileNotFoundError(_ERR_FILE_NOT_FOUND)

        _logger.debug("session_import_file_read", path=str(path))
        with path.open(encoding="utf-8") as f:
            data = json.load(f)

        session_data = data.get("session", data)

        if "id" not in session_data or "provider" not in session_data:
            _logger.error("session_import_invalid_format", path=str(path))
            raise ValueError(_ERR_INVALID_FORMAT)

        tool_states: dict[ToolName, ToolState] = {}
        for key, value in session_data.get("tool_states", {}).items():
            try:
                tool_name = ToolName(key)
                tool_states[tool_name] = self._deserialize_tool_state(value)
            except ValueError:
                _logger.warning("unknown_tool_name_in_import", tool_name=key)
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
            bridge_analyses={
                name: self._deserialize_bridge_analysis(value) for name, value in session_data.get("bridge_analyses", {}).items()
            },
        )

        _logger.info("session_imported", session_id=session.id, path=str(path))
        return session


class SessionManager:
    """Manages session lifecycle and persistence.

    Coordinates between the active session and the session store.
    """

    def __init__(
        self,
        store: SessionStore,
        *,
        auto_save: bool = True,
        save_interval: int = 300,
    ) -> None:
        """Initialize the SessionManager with a store and save settings.

        Args:
            store: Session persistence store.
            auto_save: Whether to auto-save changes.
            save_interval: Interval between auto-saves in seconds.
        """
        self.store = store
        self._current: Session | None = None
        self.auto_save = auto_save
        self.save_interval = save_interval
        self._save_task: asyncio.Task[None] | None = None
        # SQLite can corrupt under concurrent writes from a single process; this
        # lock serialises every SQLite operation routed through the manager so
        # ``update`` and ``save`` (called from the auto-save loop, the GUI, and
        # bridges) cannot interleave their transactions.
        self._db_lock = asyncio.Lock()
        _logger.debug("session_manager_init", auto_save=auto_save, save_interval=save_interval)

    @property
    def current(self) -> Session | None:
        """Get the current session.

        Returns:
            Session | None: Current session or None.
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
            Session: New Session instance.
        """
        if self._current is not None:
            await self.save()

        session = Session.create(provider, model, name)
        self._current = session

        await self.save()
        await self._start_auto_save()

        log_session_operation("create", session.id, provider=provider.value, model=model)
        _logger.info("session_created", session_id=session.id)
        return session

    async def load(self, session_id: str) -> Session | None:
        """Load a session.

        Args:
            session_id: Session identifier.

        Returns:
            Session | None: Session instance or None if not found.
        """
        if self._current is not None:
            await self.save()

        async with self._db_lock:
            session = await asyncio.to_thread(self.store.load, session_id)

        if session is not None:
            self._current = session
            await self._start_auto_save()
            _logger.info("session_loaded", session_id=session_id)

        return session

    async def get(self, session_id: str) -> Session | None:
        """Get a session by ID without making it current.

        Args:
            session_id: Session identifier.

        Returns:
            Session | None: Session instance or None if not found.
        """
        _logger.debug("session_get_invoked", session_id=session_id)
        async with self._db_lock:
            return await asyncio.to_thread(self.store.load, session_id)

    async def update(self, session: Session) -> None:
        """Update a session in the store.

        SQLite I/O is offloaded to a worker thread so the event loop is never
        blocked by disk I/O, and serialised against every other writer through
        ``self._db_lock`` to keep SQLite from racing with the auto-save loop or
        concurrent ``update`` callers.

        Args:
            session: Session to update.
        """

        async with self._db_lock:
            await asyncio.to_thread(self.store.save, session)
        _logger.debug("session_updated", session_id=session.id)

    async def save(self) -> None:
        """Save the current session.

        Like ``update``, the SQLite work is run via ``asyncio.to_thread`` under the same lock so ``save`` and ``update`` cannot interleave
        their transactions.
        """
        if self._current is None:
            return
        current = self._current
        async with self._db_lock:
            await asyncio.to_thread(self.store.save, current)
        log_session_operation("save", current.id)
        _logger.debug("current_session_saved", session_id=current.id)

    async def close(self) -> None:
        """Close the current session."""
        await self._stop_auto_save()

        if self._current is not None:
            await self.save()
            _logger.info("session_closed", session_id=self._current.id)
            self._current = None

    async def delete(self, session_id: str) -> bool:
        """Delete a session.

        Args:
            session_id: Session identifier.

        Returns:
            bool: True if deleted.
        """
        is_current = self._current is not None and self._current.id == session_id
        _logger.info("session_deleting", session_id=session_id, is_current=is_current)
        if self._current is not None and self._current.id == session_id:
            await self._stop_auto_save()
            self._current = None

        async with self._db_lock:
            return await asyncio.to_thread(self.store.delete, session_id)

    def list_sessions(self, limit: int = 100) -> list[SessionMetadata]:
        """List all sessions.

        Args:
            limit: Maximum number to return.

        Returns:
            list[SessionMetadata]: List of session metadata.
        """
        return self.store.list_all(limit)

    def search_by_tag(self, tag: str) -> list[SessionMetadata]:
        """Search sessions by tag.

        Args:
            tag: Tag to search for.

        Returns:
            list[SessionMetadata]: List of matching session metadata.
        """
        return self.store.search_by_tag(tag)

    async def cleanup(self, days: int = 30) -> int:
        """Clean up old sessions.

        Args:
            days: Number of days to keep.

        Returns:
            int: Number of sessions deleted.
        """
        _logger.info("session_cleanup_requested", days=days)
        async with self._db_lock:
            return await asyncio.to_thread(self.store.cleanup_old, days)

    async def export_json(self, session_id: str, path: Path) -> None:
        """Export a session to a JSON file.

        Args:
            session_id: Session identifier to export.
            path: Path to write the JSON file.

        Raises:
            ValueError: If the session is not found.
        """
        _logger.info("session_exporting", session_id=session_id, path=str(path))
        async with self._db_lock:
            session = await asyncio.to_thread(self.store.load, session_id)
        if session is None:
            raise ValueError(_ERR_SESSION_NOT_FOUND)

        await asyncio.to_thread(self.store.export_to_json, session, path)

    async def import_json(self, path: Path, *, replace: bool = False) -> Session:
        """Import a session from a JSON file.

        Args:
            path: Path to the JSON file.
            replace: Whether to replace existing session with same ID.

        Returns:
            Session: Imported Session instance.

        Raises:
            ValueError: If session with same ID already exists and replace=False.
        """
        session = await asyncio.to_thread(self.store.import_from_json, path)

        async with self._db_lock:
            existing = await asyncio.to_thread(self.store.load, session.id)
            if existing is not None and not replace:
                raise ValueError(_ERR_SESSION_EXISTS)

            await asyncio.to_thread(self.store.save, session)
        return session

    async def export_current(self, path: Path) -> None:
        """Export the current session to a JSON file.

        Args:
            path: Path to write the JSON file.

        Raises:
            ValueError: If no current session exists.
        """
        _logger.info("current_session_exporting", path=str(path))
        if self._current is None:
            raise ValueError(_ERR_NO_CURRENT_SESSION)

        await asyncio.to_thread(self.store.export_to_json, self._current, path)

    @property
    def is_auto_saving(self) -> bool:
        """Whether the auto-save background task is currently running.

        Returns:
            bool: ``True`` when an auto-save task has been started and has
                not yet been cancelled or finished.
        """
        return self._save_task is not None and not self._save_task.done()

    async def stop_auto_save(self) -> None:
        """Cancel the auto-save background task.

        Public counterpart to :meth:`_stop_auto_save` for callers (test harnesses, embedding applications) that need to cleanly cancel the
        background save loop without reaching into private members. No-op when no task is currently running.
        """
        await self._stop_auto_save()

    async def _start_auto_save(self) -> None:
        """Start the auto-save task."""
        await self._stop_auto_save()

        if self.auto_save:
            self._save_task = asyncio.create_task(self._auto_save_loop())

    async def _stop_auto_save(self) -> None:
        """Stop the auto-save task."""
        if self._save_task is not None:
            self._save_task.cancel()
            try:
                await self._save_task
            except asyncio.CancelledError:
                _logger.debug("autosave_task_cancel_expected", exc_info=True)
            self._save_task = None

    async def _auto_save_loop(self) -> None:
        """Periodically persist the current session.

        The loop is wrapped in a broad exception guard because it has to keep
        running across transient failure modes (filesystem hiccups, locked
        SQLite databases, exhausted disk, intermittent permission errors). A
        single ``raise`` would otherwise terminate the task and silently leave
        the application without auto-save until restart. ``asyncio.CancelledError``
        is intentionally re-raised so ``_stop_auto_save`` continues to cancel
        cleanly.

        Raises:
            asyncio.CancelledError: Re-raised so ``_stop_auto_save`` can cancel
                the task without it being swallowed by the broad exception guard.
        """
        while True:
            try:
                await asyncio.sleep(self.save_interval)
                await self.save()
            except asyncio.CancelledError:
                _logger.warning("autosave_loop_cancelled")
                raise
            except Exception:
                _logger.exception(
                    "autosave_loop_iteration_failed",
                    session_id=self._current.id if self._current is not None else None,
                )
