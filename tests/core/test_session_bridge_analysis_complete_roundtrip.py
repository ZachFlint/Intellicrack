# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate for the ``complete`` flag surviving session persistence.

``BridgeAnalysisSummary.complete`` is the authoritative "a real analysis
bridge contributed data" signal, and Full Analysis relies on it to decide
whether to tell the user that no disassembler backend is connected. Both
halves of ``SessionStore``'s bridge-analysis codec omitted the field: the
serializer never wrote it and the deserializer never read it, so the
dataclass default (``False``) silently replaced the real value on every load.
A session saved with a genuinely complete analysis therefore came back
claiming no bridge had contributed.

Both persistence routes are gated here against a real on-disk SQLite store
and a real JSON export, with no doubles anywhere: the flag is written by the
production serializer and read back by the production deserializer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from intellicrack.core.session import Session, SessionStore
from intellicrack.core.types import (
    BridgeAnalysisSummary,
    ProviderName,
    SectionInfo,
    StringInfo,
)


if TYPE_CHECKING:
    from pathlib import Path

_BINARY_NAME = "complete-flag-target.exe"


def _complete_summary() -> BridgeAnalysisSummary:
    """Build a summary a real bridge would have produced.

    Returns:
        BridgeAnalysisSummary: Summary carrying ``complete=True`` alongside
        enough real nested records that the codec's other branches run too.
    """
    return BridgeAnalysisSummary(
        binary_name=_BINARY_NAME,
        strings=[
            StringInfo(address=0x140002100, value="licensed-to", encoding="ascii", section=".rdata"),
        ],
        imports=[],
        exports=[],
        sections=[
            SectionInfo(
                name=".text",
                virtual_address=0x140001000,
                virtual_size=0x1200,
                raw_size=0x1200,
                characteristics=0x60000020,
                entropy=6.4,
            ),
        ],
        functions=[],
        format_info="PE32+",
        architecture="x86_64",
        source_bridges=["rizin"],
        analysis_notes=["aggregated from 1 bridge"],
        complete=True,
    )


def _saved_session(tmp_path: Path) -> tuple[SessionStore, Session]:
    """Persist a session holding a complete analysis through the real store.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        tuple[SessionStore, Session]: The live store and the saved session.
    """
    store = SessionStore(tmp_path / "sessions.db")
    session = Session.create(provider=ProviderName.OLLAMA, model="complete-flag-model")
    session.add_bridge_analysis(_BINARY_NAME, _complete_summary())
    store.save(session)
    return store, session


def test_complete_flag_survives_a_sqlite_round_trip(tmp_path: Path) -> None:
    """A complete analysis must still read as complete after save then load.

    Args:
        tmp_path: Pytest temporary directory fixture.
    """
    store, session = _saved_session(tmp_path)

    loaded = store.load(session.id)

    assert loaded is not None, "the session was not found in the store it was just saved to"
    restored = loaded.get_bridge_analysis(_BINARY_NAME)
    assert restored is not None, "the bridge analysis did not survive the round trip at all"
    assert restored.source_bridges == ["rizin"], "the round trip lost the contributing bridge list"
    assert restored.complete is True, "the loaded analysis reports complete=False, so Full Analysis would claim no backend contributed"


def test_complete_flag_survives_a_json_export_and_import(tmp_path: Path) -> None:
    """The JSON export/import path must preserve the flag as well.

    Args:
        tmp_path: Pytest temporary directory fixture.
    """
    store, session = _saved_session(tmp_path)
    export_path = tmp_path / "session-export.json"

    store.export_to_json(session, export_path)
    imported = store.import_from_json(export_path)

    restored = imported.get_bridge_analysis(_BINARY_NAME)
    assert restored is not None, "the bridge analysis did not survive the JSON round trip at all"
    assert restored.complete is True, "the exported/imported analysis lost its complete flag"


def test_an_incomplete_analysis_stays_incomplete(tmp_path: Path) -> None:
    """The flag must round-trip its false value too, not merely default to it.

    Without this the fix could be faked by defaulting ``complete`` to ``True``
    on read, which would be a worse bug: an empty analysis would then claim a
    backend contributed.

    Args:
        tmp_path: Pytest temporary directory fixture.
    """
    store = SessionStore(tmp_path / "sessions.db")
    session = Session.create(provider=ProviderName.OLLAMA, model="complete-flag-model")
    empty = BridgeAnalysisSummary(
        binary_name=_BINARY_NAME,
        strings=[],
        imports=[],
        exports=[],
        sections=[],
        functions=[],
        format_info="unknown",
        architecture="unknown",
        source_bridges=[],
        analysis_notes=["no analysis bridges connected"],
        complete=False,
    )
    session.add_bridge_analysis(_BINARY_NAME, empty)
    store.save(session)

    loaded = store.load(session.id)

    assert loaded is not None, "the session was not found in the store it was just saved to"
    restored = loaded.get_bridge_analysis(_BINARY_NAME)
    assert restored is not None, "the bridge analysis did not survive the round trip at all"
    assert restored.complete is False, "an analysis no bridge contributed to came back claiming it was complete"
