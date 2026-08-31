# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gates for audit F2 (chat context) and Export Analysis.

* **F2a** -- the system prompt injects a bounded bridge-analysis summary for the
  active binary, so the model can answer binary-specific questions from context
  instead of issuing a tool call.
* **F2b** -- a large tool result is truncated to a bounded preview before it
  re-enters the model context, so a full hex dump cannot balloon token usage.
* **Export** -- ``BridgeAnalysisSummary.to_dict`` serialises nested dataclasses
  into structured JSON objects (not Python ``repr`` strings), so exported
  sections are JSON objects with typed fields.

Tests drive the real ``Orchestrator``/``Session``/``BridgeAnalysisSummary`` with
real data. The private cancel-free seams (``_current_session`` injection,
``_bound_tool_result``) are reached reflectively only to exercise real logic.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, cast

from intellicrack.core.orchestrator import Orchestrator
from intellicrack.core.session import Session, SessionManager, SessionStore
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import (
    BinaryInfo,
    BridgeAnalysisSummary,
    FunctionInfo,
    ImportInfo,
    ProviderName,
    SectionInfo,
    StringInfo,
)
from intellicrack.providers.registry import ProviderRegistry


if TYPE_CHECKING:
    from collections.abc import Callable

    _BoundResultFn = Callable[[object], object]


_MODEL_ID: str = "f2-model"
_LARGE_PAYLOAD_CHARS: int = 40_000
_TRUNCATION_MARKER: str = "truncated"


def _make_orchestrator(tmp_path: Path) -> Orchestrator:
    """Build a minimal orchestrator with empty registries.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        Orchestrator: A ready orchestrator instance.
    """
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    return Orchestrator(
        provider_registry=ProviderRegistry(),
        tool_registry=ToolRegistry(tools_dir=tools_dir),
        session_manager=SessionManager(store=SessionStore(db_path=tmp_path / "sessions.db")),
    )


def _make_summary(binary_name: str) -> BridgeAnalysisSummary:
    """Build a real analysis summary with distinctive sampleable values.

    Args:
        binary_name: Name recorded on the summary and its binary.

    Returns:
        BridgeAnalysisSummary: A populated summary.
    """
    return BridgeAnalysisSummary(
        binary_name=binary_name,
        strings=[StringInfo(address=0x401000, value="LICENSE_MARKER_STRING", encoding="ascii", section=".rdata")],
        imports=[ImportInfo(dll="kernel32.dll", function="IsDebuggerPresent", ordinal=None, address=0x402000)],
        exports=[],
        sections=[
            SectionInfo(
                name=".text",
                virtual_address=0x1000,
                virtual_size=0x2000,
                raw_size=0x1800,
                characteristics=0x60000020,
                entropy=6.5,
                raw_offset=0x400,
            ),
        ],
        functions=[
            FunctionInfo(
                name="verify_serial",
                address=0x1100,
                size=256,
                calling_convention="stdcall",
                return_type="int",
                parameters=[],
                local_variables=[],
            ),
        ],
        format_info="PE32+",
        architecture="x86_64",
        source_bridges=["cutter"],
        analysis_notes=[],
        complete=True,
    )


def _make_binary(name: str) -> BinaryInfo:
    """Build a minimal ``BinaryInfo`` for the given name.

    Args:
        name: Binary name/path stem.

    Returns:
        BinaryInfo: A minimal PE-typed binary record.
    """
    return BinaryInfo(
        path=Path(name),
        name=name,
        size=1024,
        sha256="0" * 64,
        file_type="pe",
        architecture="x86_64",
        is_64bit=True,
        entry_point=0x1400,
        sections=[],
        imports=[],
        exports=[],
    )


def test_system_prompt_injects_bridge_analysis_summary(tmp_path: Path) -> None:
    """F2a: the prompt must carry counts and samples from the cached analysis.

    Args:
        tmp_path: Pytest temporary directory.
    """
    orch = _make_orchestrator(tmp_path)
    session = Session.create(provider=ProviderName.OPENAI, model=_MODEL_ID, name="f2")
    binary = _make_binary("target.exe")
    session.binaries.append(binary)
    session.active_binary_index = 0
    session.add_bridge_analysis(binary.name, _make_summary(binary.name))
    setattr(orch, "_current_session", session)

    prompt = orch.build_system_prompt()

    assert "Bridge analysis summary" in prompt, "analysis summary was not injected into the system prompt (F2)"
    assert "verify_serial" in prompt, "sampled function name missing from prompt"
    assert "IsDebuggerPresent" in prompt, "sampled import missing from prompt"
    assert "LICENSE_MARKER_STRING" in prompt, "sampled string missing from prompt"


def test_bound_tool_result_truncates_large_payload() -> None:
    """F2b: a large payload must be truncated to a bounded preview with a marker."""
    bound = cast("_BoundResultFn", getattr(Orchestrator, "_bound_tool_result"))
    large = "A" * _LARGE_PAYLOAD_CHARS
    result = bound(large)

    assert isinstance(result, str)
    assert len(result) < _LARGE_PAYLOAD_CHARS, "large payload was not truncated (F2 regression)"
    assert _TRUNCATION_MARKER in result, "truncated payload lacks its truncation marker"


def test_bound_tool_result_preserves_small_payload() -> None:
    """A small payload must be returned unchanged."""
    bound = cast("_BoundResultFn", getattr(Orchestrator, "_bound_tool_result"))
    small = {"registers": {"rax": 1, "rip": 0x401000}}
    assert bound(small) == small


def test_summary_to_dict_serializes_nested_sections_as_objects(tmp_path: Path) -> None:
    """Export: ``to_dict`` must yield JSON objects with typed section fields.

    Args:
        tmp_path: Pytest temporary directory for the round-trip file.
    """
    summary = _make_summary("export.exe")
    export_path = tmp_path / "analysis_export.json"
    export_path.write_text(json.dumps(summary.to_dict(), default=str), encoding="utf-8")

    reloaded = cast("dict[str, object]", json.loads(export_path.read_text(encoding="utf-8")))
    sections_obj = cast("list[object]", reloaded["sections"])
    assert sections_obj, "sections did not serialise to a non-empty list"
    first_raw = sections_obj[0]
    assert isinstance(first_raw, dict), "section serialised as a repr string instead of a JSON object (regression)"
    first = cast("dict[str, object]", first_raw)
    assert first["name"] == ".text"
    assert first["virtual_address"] == 0x1000
    assert first["raw_offset"] == 0x400
