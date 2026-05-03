# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Audit1 bridges-core regression tests.

Covers the seven findings tracked in audit1.md against
``src/intellicrack/bridges/{schemas,__init__,_win32_types,base}.py`` and the
``src/intellicrack/core/orchestrator.py`` validation call site.

Each finding has at least one red/green pair documenting the buggy old
behaviour (assertion would have fired before the fix) and the corrected
behaviour after the fix lands.
"""

from __future__ import annotations

import importlib
import sys
from typing import Final

import pytest
import structlog.testing

import intellicrack.bridges as bridges_pkg
from intellicrack.bridges._lazy import resolve as resolve_lazy
from intellicrack.bridges._win32_types import (
    MEM_COMMIT,
    MEM_FREE,
    MEM_IMAGE,
    MEM_MAPPED,
    MEM_PRIVATE,
    MEM_RESERVE,
    PAGE_EXECUTE,
    PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY,
    PAGE_GUARD,
    PAGE_NOACCESS,
    PAGE_READONLY,
    PAGE_READWRITE,
    PAGE_WRITECOPY,
    MemoryProtectionFlags,
    decode_protection,
    mem_type_to_string,
    protection_to_string,
    state_to_string,
)
from intellicrack.bridges.base import ToolBridgeBase
from intellicrack.bridges.cutter import CutterBridge
from intellicrack.bridges.frida_bridge import FridaBridge
from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.bridges.process import ProcessBridge
from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.bridges.schemas import (
    ValidationError,
    is_recognized_type,
    normalize_type,
    validate_tool_for_provider,
    validate_tool_parameter,
)
from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.core.types import (
    ProviderName,
    ToolDefinition,
    ToolFunction,
    ToolName,
    ToolParameter,
)


_PARAM_DESC: Final[str] = "test parameter"


def _make_tool(*params: ToolParameter) -> ToolDefinition:
    """Build a minimal valid ``ToolDefinition`` with one function.

    Args:
        *params: Parameters to attach to the synthetic tool function.

    Returns:
        ToolDefinition: A small tool definition suitable for schema tests.
    """
    return ToolDefinition(
        tool_name=ToolName.PROCESS,
        description="audit1 fixture tool",
        functions=[
            ToolFunction(
                name="process.fixture",
                description="audit1 fixture function",
                parameters=list(params),
                returns="None",
            ),
        ],
    )


# ---------------------------------------------------------------------------
# F-0001: normalize_type silently downgrades unknown types -> raise/warn.
# ---------------------------------------------------------------------------


def test_f0001_normalize_type_unknown_emits_warning() -> None:
    """Red/green: an unrecognised type now emits ``schema_type_fallback``.

    The pre-fix behaviour silently coerced any unrecognised string to
    ``"string"`` with no diagnostic. The fix preserves the coercion as
    a backwards-compatible fallback but logs a warning so the offending
    type can be surfaced through the validation pipeline.
    """
    with structlog.testing.capture_logs() as captured:
        result = normalize_type("custom_unknown_type")
    assert result == "string"
    fallbacks = [c for c in captured if c.get("event") == "schema_type_fallback"]
    assert fallbacks, f"expected schema_type_fallback warning, got: {captured}"
    assert fallbacks[0].get("log_level") == "warning"
    assert fallbacks[0].get("param_type") == "custom_unknown_type"


def test_f0001_normalize_type_known_emits_no_warning() -> None:
    """Recognised types must NOT emit the fallback warning."""
    with structlog.testing.capture_logs() as captured:
        for known in ("str", "int", "float", "bool", "list", "dict", "string", "integer", "number"):
            normalize_type(known)
    fallbacks = [c for c in captured if c.get("event") == "schema_type_fallback"]
    assert not fallbacks, "schema_type_fallback must not fire for recognised types"


# ---------------------------------------------------------------------------
# F-0002: validate_tool_parameter type check dead -> validate before normalize.
# ---------------------------------------------------------------------------


def test_f0002_validate_tool_parameter_flags_unknown_type() -> None:
    """Red/green: parameter validation now flags unrecognised types.

    Before the fix, ``validate_tool_parameter`` normalised the type
    first and then re-checked membership in
    ``VALID_JSON_SCHEMA_TYPES`` -- the post-normalisation value was
    always either a valid type or ``"string"``, so the branch was
    unreachable. After the fix, ``is_recognized_type`` is consulted
    against the *raw* input so genuinely malformed types produce a
    diagnostic.
    """
    param = ToolParameter(
        name="bad",
        type="list[int]",
        description=_PARAM_DESC,
        required=True,
    )
    errors = validate_tool_parameter(param, "fixture")
    invalid_type_errors = [e for e in errors if "Invalid type" in e.message]
    assert invalid_type_errors, "validate_tool_parameter must reject parameterised generics"
    assert invalid_type_errors[0].severity == "warning"


def test_f0002_validate_tool_parameter_accepts_python_alias() -> None:
    """Python aliases such as ``int`` must NOT be flagged."""
    param = ToolParameter(
        name="ok",
        type="int",
        description=_PARAM_DESC,
        required=True,
    )
    errors = validate_tool_parameter(param, "fixture")
    invalid_type_errors = [e for e in errors if "Invalid type" in e.message]
    assert not invalid_type_errors, "Python alias types must not raise validation diagnostics"


def test_f0002_is_recognized_type_rejects_unknown() -> None:
    """``is_recognized_type`` must reject types that fall back to ``string``."""
    assert not is_recognized_type("list[int]")
    assert not is_recognized_type("Foo")
    assert is_recognized_type("string")
    assert is_recognized_type("int")
    assert is_recognized_type("  STRING  ")


# ---------------------------------------------------------------------------
# F-0003: validate_and_convert results unused -> wire pure validation pass.
# ---------------------------------------------------------------------------


def test_f0003_validate_tool_for_provider_returns_errors_only() -> None:
    """Red/green: orchestrator's pure validation pass returns no schemas.

    Before the fix the orchestrator threw away the converted schemas
    from ``validate_and_convert`` (and re-allocated them again via
    ``get_all_schemas_for_provider``). The new
    ``validate_tool_for_provider`` is a pure validation pass that does
    not allocate schemas at all, so the orchestrator can keep the
    diagnostics without paying the conversion cost.
    """
    tool = _make_tool(
        ToolParameter(
            name="addr",
            type="int",
            description=_PARAM_DESC,
            required=True,
        ),
    )
    errors = validate_tool_for_provider(tool, ProviderName.OPENAI)
    assert isinstance(errors, list)
    assert all(isinstance(e, ValidationError) for e in errors)
    assert not [e for e in errors if e.severity == "error"]


def test_f0003_validate_tool_for_provider_flags_missing_function() -> None:
    """Tool with no functions must produce an error-level diagnostic."""
    tool = ToolDefinition(
        tool_name=ToolName.PROCESS,
        description="empty tool",
        functions=[],
    )
    errors = validate_tool_for_provider(tool, ProviderName.OPENAI)
    error_messages = [e.message for e in errors if e.severity == "error"]
    assert any("at least one function" in m for m in error_messages)


# ---------------------------------------------------------------------------
# F-0004: bridges/__init__.py eager imports -> lazy ``__getattr__``.
# ---------------------------------------------------------------------------


def test_f0004_bridges_package_does_not_eager_load_heavy_submodules() -> None:
    """Importing ``intellicrack.bridges`` must NOT load heavy submodules.

    The pre-fix ``__init__.py`` eagerly imported every bridge
    (Ghidra, Frida, x64dbg, Cutter, sandbox, hex_editor, process,
    installer). After the fix, the package only loads those modules
    on first attribute access via PEP 562 ``__getattr__``.
    """
    heavy = [
        "intellicrack.bridges.ghidra",
        "intellicrack.bridges.frida_bridge",
        "intellicrack.bridges.x64dbg",
        "intellicrack.bridges.cutter",
        "intellicrack.bridges.sandbox_bridge",
        "intellicrack.bridges.hex_editor",
        "intellicrack.bridges.process",
        "intellicrack.bridges.installer",
    ]
    for mod in [*heavy, "intellicrack.bridges"]:
        sys.modules.pop(mod, None)
    importlib.import_module("intellicrack.bridges")
    loaded = [m for m in heavy if m in sys.modules]
    assert not loaded, f"unexpected eager imports: {loaded}"


def test_f0004_bridges_lazy_accessor_returns_class() -> None:
    """Lazy access via ``_lazy.resolve`` must yield the real bridge class.

    Exercises the typed ``resolve`` entry point directly so the test
    is a fully-typed call rather than a stringly-typed ``getattr``
    workaround. The package-level ``__getattr__`` is a one-line
    delegate to this function.
    """
    sys.modules.pop("intellicrack.bridges.process", None)
    scratch_globals: dict[str, object] = {}
    cls = resolve_lazy("ProcessBridge", scratch_globals)
    assert cls.__name__ == "ProcessBridge"
    assert "intellicrack.bridges.process" in sys.modules
    assert "ProcessBridge" in scratch_globals
    assert bridges_pkg.__name__ == "intellicrack.bridges"


def test_f0004_bridges_unknown_attribute_raises() -> None:
    """Unknown attributes must still raise ``AttributeError`` from ``resolve``."""
    scratch_globals: dict[str, object] = {}
    with pytest.raises(AttributeError, match="NotARealBridge"):
        resolve_lazy("NotARealBridge", scratch_globals)
    assert bridges_pkg.__name__ == "intellicrack.bridges"


# ---------------------------------------------------------------------------
# F-0005: protection_to_string contract drift -> TypedDict redesign.
# ---------------------------------------------------------------------------


def test_f0005_decode_protection_returns_typed_dict() -> None:
    """Red/green: ``decode_protection`` returns the new TypedDict shape.

    Before the fix the only API was ``protection_to_string`` which lost
    the structured access bits behind a string like ``"rwx+G"``. The
    redesign introduces ``decode_protection`` returning a typed dict
    with ``read``/``write``/``execute``/``copy_on_write``/``guard``
    booleans plus the original raw value, while keeping
    ``protection_to_string`` as a thin formatter built on top.
    """
    flags = decode_protection(PAGE_EXECUTE_READWRITE)
    assert flags["read"]
    assert flags["write"]
    assert flags["execute"]
    assert not flags["copy_on_write"]
    assert not flags["guard"]
    assert flags["raw"] == PAGE_EXECUTE_READWRITE


def test_f0005_decode_protection_guard_and_copy_on_write() -> None:
    """Guard and copy-on-write bits must be reported through the TypedDict."""
    flags = decode_protection(PAGE_EXECUTE_WRITECOPY | PAGE_GUARD)
    assert flags["read"]
    assert flags["execute"]
    assert flags["write"]
    assert flags["copy_on_write"]
    assert flags["guard"]


def test_f0005_decode_protection_no_access() -> None:
    """``PAGE_NOACCESS`` clears every access bit."""
    flags = decode_protection(PAGE_NOACCESS)
    assert not flags["read"]
    assert not flags["write"]
    assert not flags["execute"]
    assert not flags["copy_on_write"]
    assert not flags["guard"]


def test_f0005_protection_to_string_uses_decoder() -> None:
    """``protection_to_string`` continues to render the same legacy strings."""
    assert protection_to_string(PAGE_NOACCESS) == "---"
    assert protection_to_string(PAGE_READONLY) == "r--"
    assert protection_to_string(PAGE_READWRITE) == "rw-"
    assert protection_to_string(PAGE_WRITECOPY) == "rw-c"
    assert protection_to_string(PAGE_EXECUTE) == "--x"
    assert protection_to_string(PAGE_EXECUTE_READ) == "r-x"
    assert protection_to_string(PAGE_EXECUTE_READWRITE) == "rwx"
    assert protection_to_string(PAGE_EXECUTE_WRITECOPY) == "rwxc"
    assert protection_to_string(PAGE_READWRITE | PAGE_GUARD) == "rw-+G"


def test_f0005_memory_protection_flags_typeddict_keys() -> None:
    """Confirm the TypedDict exposes exactly the expected keys."""
    flags: MemoryProtectionFlags = decode_protection(PAGE_READWRITE)
    assert set(flags.keys()) == {"read", "write", "execute", "copy_on_write", "guard", "raw"}


# ---------------------------------------------------------------------------
# F-0006: state_to_string / mem_type_to_string silent ``unknown``.
# ---------------------------------------------------------------------------


def test_f0006_state_to_string_known_values() -> None:
    """Recognised state values continue to render the existing labels."""
    assert state_to_string(MEM_COMMIT) == "committed"
    assert state_to_string(MEM_RESERVE) == "reserved"
    assert state_to_string(MEM_FREE) == "free"


def test_f0006_state_to_string_unknown_includes_value() -> None:
    """Unknown state values render ``unknown(0x...)`` and emit debug log."""
    with structlog.testing.capture_logs() as captured:
        out = state_to_string(0x9999)
    assert out == "unknown(0x9999)"
    events = [c for c in captured if c.get("event") == "unknown_memory_state"]
    assert events, f"expected unknown_memory_state debug log, got: {captured}"
    assert events[0].get("log_level") == "debug"
    assert events[0].get("state") == "0x9999"


def test_f0006_mem_type_to_string_known_values() -> None:
    """Recognised type values continue to render the existing labels."""
    assert mem_type_to_string(MEM_PRIVATE) == "private"
    assert mem_type_to_string(MEM_MAPPED) == "mapped"
    assert mem_type_to_string(MEM_IMAGE) == "image"


def test_f0006_mem_type_to_string_unknown_includes_value() -> None:
    """Unknown memory type values render ``unknown(0x...)`` and emit debug log."""
    with structlog.testing.capture_logs() as captured:
        out = mem_type_to_string(0x12345)
    assert out == "unknown(0x12345)"
    events = [c for c in captured if c.get("event") == "unknown_memory_type"]
    assert events, f"expected unknown_memory_type debug log, got: {captured}"
    assert events[0].get("log_level") == "debug"
    assert events[0].get("mem_type") == "0x12345"


# ---------------------------------------------------------------------------
# F-0007: ToolBridgeBase.shutdown non-abstract -> mark ``@abstractmethod``.
# ---------------------------------------------------------------------------


def test_f0007_toolbridgebase_shutdown_is_abstract() -> None:
    """Red/green: ``ToolBridgeBase.shutdown`` is now an abstract method.

    Before the fix the base class supplied a default body so subclasses
    could silently skip overriding it. After the fix every concrete
    bridge must provide its own ``shutdown``.
    """
    abstract_methods = ToolBridgeBase.__abstractmethods__
    assert "shutdown" in abstract_methods


def test_f0007_concrete_bridges_override_shutdown() -> None:
    """All concrete bridges must override ``shutdown`` directly."""
    bridge_classes: tuple[type[ToolBridgeBase], ...] = (
        CutterBridge,
        FridaBridge,
        GhidraBridge,
        HexEditorBridge,
        ProcessBridge,
        SandboxBridge,
        X64DbgBridge,
    )
    for cls in bridge_classes:
        assert "shutdown" in cls.__dict__, f"{cls.__name__} does not override shutdown directly"
