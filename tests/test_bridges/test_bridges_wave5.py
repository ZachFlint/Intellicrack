# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Wave 5 gates for Group 01: bridge framework, hex editor bridge (F01-F13).

Closes the following NOT_RESOLVED findings from group-01-report.md:

F01 - TOOL_CAPABILITY_MAP scripting family (base.py:74-82)
F02 - TOOL_CAPABILITY_MAP decompilation entry (base.py:62)
F03 - BinaryOperationsBridge.__init__ capability values (base.py:1046-1054)
F04 - resolve() warning log on unknown attribute (lazy.py:60)
F05 - resolve() TypeError for non-bridge attribute (lazy.py:68-71)
F06 - build_schema_property array+object recursive (schemas.py:258-267)
F07 - validate_tool_parameter unrecognized items_type (schemas.py:419-422)
F08 - validate_tool_parameter array-of-objects no item_properties (schemas.py:427-434)
F09 - _assert_never (schemas.py:28-48) -- UNTESTABLE (documented below)
F10 - _read_exact timeout raises ToolError (named_pipe_client.py:597-605)
F11 - _cancel_io log emission (named_pipe_client.py:869-882)
F12 - bridges/__init__.py __dir__ sorted-union (bridges/__init__.py:90-96)
F13 - HexEditorBridge.get_selection exact tuple (hex_editor.py:5928)

F09 is architecturally unreachable: get_schema_for_provider uses an exhaustive
if/elif/else chain whose else clause calls _assert_never.  Because every
ProviderName value is handled by a named branch, the else is dead code that
cannot be reached through any legal caller.  There is no production-code path
that exercises it.  Marking it UNTESTABLE per WAVE5-INSTRUCTIONS.md.
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import TYPE_CHECKING, Any, Final, cast

import jsonschema
import pytest

import intellicrack.bridges as bridges_pkg
import intellicrack.bridges.lazy as _lazy_mod
import intellicrack.bridges.named_pipe_client as _npc_mod
from intellicrack.bridges import __all__ as _bridges_all
from intellicrack.bridges.base import (
    TOOL_CAPABILITY_MAP,
    BinaryOperationsBridge,
)
from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.bridges.lazy import LAZY_EXPORTS, resolve
from intellicrack.bridges.named_pipe_client import NamedPipeClient, PipeConfig
from intellicrack.bridges.schemas import (
    build_schema_property,
    validate_tool_parameter,
)
from intellicrack.core.types import (
    BinaryInfo,
    PatchInfo,
    ToolDefinition,
    ToolError,
    ToolName,
    ToolParameter,
)


if TYPE_CHECKING:
    from collections.abc import Coroutine
    from pathlib import Path


_FAKE_HANDLE: Final[int] = 0xABCDEF


# ---------------------------------------------------------------------------
# Log capture helper (mirrors _LogSink in test_named_pipe_client_errors_wave2d.py)
# ---------------------------------------------------------------------------


class _LogSink:
    """Recording stand-in for a module-level structlog ``_logger``.

    Replaces a module-level ``_logger`` via monkeypatch so the real
    production code runs unchanged while its structured-log calls are
    captured deterministically.  Thread-safe because some log calls
    originate from background threads.
    """

    def __init__(self, target: str = "") -> None:
        """Initialise the sink.

        Args:
            target: Optional event name to watch for (for future use).
        """
        self._target = target
        self.records: list[tuple[str, str, dict[str, object]]] = []
        self._lock: threading.Lock = threading.Lock()

    def _emit(self, level: str, event: str, **fields: object) -> None:
        """Record a single log call.

        Args:
            level: Severity name of the originating call.
            event: Structlog event key.
            **fields: Structured key/value fields.
        """
        with self._lock:
            self.records.append((level, event, dict(fields)))

    def debug(self, event: str, **fields: object) -> None:
        """Record a debug-level event.

        Args:
            event: Structlog event key.
            **fields: Structured fields.
        """
        self._emit("debug", event, **fields)

    def info(self, event: str, **fields: object) -> None:
        """Record an info-level event.

        Args:
            event: Structlog event key.
            **fields: Structured fields.
        """
        self._emit("info", event, **fields)

    def warning(self, event: str, **fields: object) -> None:
        """Record a warning-level event.

        Args:
            event: Structlog event key.
            **fields: Structured fields.
        """
        self._emit("warning", event, **fields)

    def error(self, event: str, **fields: object) -> None:
        """Record an error-level event.

        Args:
            event: Structlog event key.
            **fields: Structured fields.
        """
        self._emit("error", event, **fields)

    def exception(self, event: str, **fields: object) -> None:
        """Record an exception-level event.

        Args:
            event: Structlog event key.
            **fields: Structured fields.
        """
        self._emit("exception", event, **fields)

    def bind(self, **_fields: object) -> _LogSink:
        """Return self so chained ``bind(...)`` calls keep recording.

        Args:
            **_fields: Bound context fields (ignored).

        Returns:
            _LogSink: This sink instance.
        """
        return self

    def has_event(self, event: str, level: str | None = None) -> bool:
        """Check whether a named event was recorded at the given level.

        Args:
            event: Event name to search for.
            level: Optional severity level to additionally match.

        Returns:
            bool: True if a matching record exists.
        """
        with self._lock:
            return any(
                r[1] == event and (level is None or r[0] == level)
                for r in self.records
            )


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Drive a coroutine to completion with a fresh event loop.

    Args:
        coro: Coroutine to execute.

    Returns:
        T: Return value of the coroutine.
    """
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# F01 -- TOOL_CAPABILITY_MAP scripting family (base.py:74-82)
# ---------------------------------------------------------------------------


class TestToolCapabilityMapScripting:
    """Assert exact TOOL_CAPABILITY_MAP values for all nine scripting entries.

    Oracle: the documented map constant at base.py:74-82; values are the
    ``"scripting"`` string literal.  Mutation caught: removing or
    misspelling any key or changing any value breaks the exact-equality
    assertion.
    """

    _SCRIPTING_OPS: Final[tuple[str, ...]] = (
        "execute_script",
        "execute_script_with_params",
        "run_python_script",
        "script_load",
        "script_run",
        "script_cmd",
        "script_abort",
        "compile_typescript",
        "create_cmodule",
    )

    def test_execute_script_maps_to_scripting(self) -> None:
        """execute_script must map to 'scripting' in TOOL_CAPABILITY_MAP.

        Mutation caught: removing or renaming the key causes ``.get()``
        to return ``None``, failing the equality check.
        """
        assert TOOL_CAPABILITY_MAP.get("execute_script") == "scripting"

    def test_execute_script_with_params_maps_to_scripting(self) -> None:
        """execute_script_with_params must map to 'scripting'.

        Mutation caught: missing key returns None != "scripting".
        """
        assert TOOL_CAPABILITY_MAP.get("execute_script_with_params") == "scripting"

    def test_run_python_script_maps_to_scripting(self) -> None:
        """run_python_script must map to 'scripting'.

        Mutation caught: missing or wrong-value key fails equality.
        """
        assert TOOL_CAPABILITY_MAP.get("run_python_script") == "scripting"

    def test_script_load_maps_to_scripting(self) -> None:
        """script_load must map to 'scripting'.

        Mutation caught: missing key returns None != "scripting".
        """
        assert TOOL_CAPABILITY_MAP.get("script_load") == "scripting"

    def test_script_run_maps_to_scripting(self) -> None:
        """script_run must map to 'scripting'.

        Mutation caught: missing or wrong-value key fails equality.
        """
        assert TOOL_CAPABILITY_MAP.get("script_run") == "scripting"

    def test_script_cmd_maps_to_scripting(self) -> None:
        """script_cmd must map to 'scripting'.

        Mutation caught: missing or wrong-value key fails equality.
        """
        assert TOOL_CAPABILITY_MAP.get("script_cmd") == "scripting"

    def test_script_abort_maps_to_scripting(self) -> None:
        """script_abort must map to 'scripting'.

        Mutation caught: missing or wrong-value key fails equality.
        """
        assert TOOL_CAPABILITY_MAP.get("script_abort") == "scripting"

    def test_compile_typescript_maps_to_scripting(self) -> None:
        """compile_typescript must map to 'scripting'.

        Mutation caught: missing or wrong-value key fails equality.
        """
        assert TOOL_CAPABILITY_MAP.get("compile_typescript") == "scripting"

    def test_create_cmodule_maps_to_scripting(self) -> None:
        """create_cmodule must map to 'scripting'.

        Mutation caught: missing or wrong-value key fails equality.
        """
        assert TOOL_CAPABILITY_MAP.get("create_cmodule") == "scripting"

    def test_all_scripting_ops_are_present_in_map(self) -> None:
        """All nine scripting ops must appear in TOOL_CAPABILITY_MAP with value 'scripting'.

        Mutation caught: removing any single key causes the subset check to
        fail.
        """
        for op in self._SCRIPTING_OPS:
            assert TOOL_CAPABILITY_MAP.get(op) == "scripting", f"op {op!r} missing or wrong value"


# ---------------------------------------------------------------------------
# F02 -- TOOL_CAPABILITY_MAP decompilation entry (base.py:62)
# ---------------------------------------------------------------------------


class TestToolCapabilityMapDecompilation:
    """Assert exact TOOL_CAPABILITY_MAP value for the decompile entry.

    Oracle: documented constant at base.py:62.  Mutation caught: changing
    ``"decompile": "decompilation"`` to ``"decompile": "static_analysis"``
    breaks the equality assertion.
    """

    def test_decompile_maps_to_decompilation(self) -> None:
        """'decompile' must map to 'decompilation', not 'static_analysis'.

        Mutation caught: changing the value to any other string fails the
        exact-equality check.
        """
        assert TOOL_CAPABILITY_MAP.get("decompile") == "decompilation"

    def test_decompile_key_exists(self) -> None:
        """'decompile' key must be present in TOOL_CAPABILITY_MAP.

        Mutation caught: removing the key causes ``.get()`` to return None
        which is != 'decompilation'.
        """
        assert "decompile" in TOOL_CAPABILITY_MAP


# ---------------------------------------------------------------------------
# F03 -- BinaryOperationsBridge.__init__ capability values (base.py:1046-1054)
# ---------------------------------------------------------------------------


class _ConcreteBinaryBridge(BinaryOperationsBridge):
    """Minimal concrete subclass of BinaryOperationsBridge for capability tests."""

    @property
    def name(self) -> ToolName:
        """Sentinel tool name for this concrete subclass.

        Returns:
            ToolName: GHIDRA sentinel value.
        """
        return ToolName.GHIDRA

    @property
    def tool_definition(self) -> ToolDefinition:
        """Not implemented for test purposes.

        Returns:
            ToolDefinition: Never returns; raises NotImplementedError.

        Raises:
            NotImplementedError: Always; this stub is only for capability inspection.
        """
        raise NotImplementedError

    async def initialize(self, tool_path: Path | None = None) -> None:
        """Not implemented for test purposes.

        Args:
            tool_path: Unused.

        Raises:
            NotImplementedError: Always; this stub is only for capability inspection.
        """
        raise NotImplementedError

    async def shutdown(self) -> None:
        """Not implemented for test purposes.

        Raises:
            NotImplementedError: Always; this stub is only for capability inspection.
        """
        raise NotImplementedError

    async def is_available(self) -> bool:
        """Not implemented for test purposes.

        Returns:
            bool: Never returns; raises NotImplementedError.

        Raises:
            NotImplementedError: Always; this stub is only for capability inspection.
        """
        raise NotImplementedError

    async def load_file(self, path: Path) -> BinaryInfo:
        """Not implemented for test purposes.

        Args:
            path: Unused.

        Returns:
            BinaryInfo: Never returns; raises NotImplementedError.

        Raises:
            NotImplementedError: Always; this stub is only for capability inspection.
        """
        raise NotImplementedError

    async def read_bytes(self, offset: int, size: int) -> bytes:
        """Not implemented for test purposes.

        Args:
            offset: Unused.
            size: Unused.

        Returns:
            bytes: Never returns; raises NotImplementedError.

        Raises:
            NotImplementedError: Always; this stub is only for capability inspection.
        """
        raise NotImplementedError

    async def write_bytes(self, offset: int, data: bytes) -> None:
        """Not implemented for test purposes.

        Args:
            offset: Unused.
            data: Unused.

        Raises:
            NotImplementedError: Always; this stub is only for capability inspection.
        """
        raise NotImplementedError

    async def apply_patch(self, patch: PatchInfo) -> bool:
        """Not implemented for test purposes.

        Args:
            patch: Unused.

        Returns:
            bool: Never returns; raises NotImplementedError.

        Raises:
            NotImplementedError: Always; this stub is only for capability inspection.
        """
        raise NotImplementedError

    async def revert_patch(self, patch: PatchInfo) -> bool:
        """Not implemented for test purposes.

        Args:
            patch: Unused.

        Returns:
            bool: Never returns; raises NotImplementedError.

        Raises:
            NotImplementedError: Always; this stub is only for capability inspection.
        """
        raise NotImplementedError

    async def save(self, path: Path | None = None) -> Path:
        """Not implemented for test purposes.

        Args:
            path: Unused.

        Returns:
            Path: Never returns; raises NotImplementedError.

        Raises:
            NotImplementedError: Always; this stub is only for capability inspection.
        """
        raise NotImplementedError

    async def search_pattern(
        self,
        pattern: bytes,
        start_offset: int = 0,
        max_results: int = 100,
    ) -> list[int]:
        """Not implemented for test purposes.

        Args:
            pattern: Unused.
            start_offset: Unused.
            max_results: Unused.

        Returns:
            list[int]: Never returns; raises NotImplementedError.

        Raises:
            NotImplementedError: Always; this stub is only for capability inspection.
        """
        raise NotImplementedError

    async def calculate_checksum(self, algorithm: str = "sha256") -> str:
        """Not implemented for test purposes.

        Args:
            algorithm: Unused.

        Returns:
            str: Never returns; raises NotImplementedError.

        Raises:
            NotImplementedError: Always; this stub is only for capability inspection.
        """
        raise NotImplementedError


class TestBinaryOperationsBridgeCapabilities:
    """Assert that BinaryOperationsBridge.__init__ installs correct capability values.

    Oracle: the literal values in base.py:1046-1054.
    Mutation caught: changing supports_static_analysis=True to False,
    changing supported_formats to omit 'pe', etc.
    """

    def test_supports_static_analysis_is_true(self) -> None:
        """BinaryOperationsBridge must set supports_static_analysis to True.

        Mutation caught: changing the constructor argument to False makes
        the assertion fail.
        """
        bridge = _ConcreteBinaryBridge()
        assert bridge.capabilities.supports_static_analysis is True

    def test_supports_patching_is_true(self) -> None:
        """BinaryOperationsBridge must set supports_patching to True.

        Mutation caught: changing the constructor argument to False makes
        the assertion fail.
        """
        bridge = _ConcreteBinaryBridge()
        assert bridge.capabilities.supports_patching is True

    def test_supported_formats_contains_pe(self) -> None:
        """BinaryOperationsBridge must list 'pe' in supported_formats.

        Mutation caught: removing 'pe' from the list makes the assertion
        fail.
        """
        bridge = _ConcreteBinaryBridge()
        assert "pe" in bridge.capabilities.supported_formats

    def test_supported_formats_contains_elf(self) -> None:
        """BinaryOperationsBridge must list 'elf' in supported_formats.

        Mutation caught: removing 'elf' from the list fails the assertion.
        """
        bridge = _ConcreteBinaryBridge()
        assert "elf" in bridge.capabilities.supported_formats

    def test_supported_formats_contains_macho(self) -> None:
        """BinaryOperationsBridge must list 'macho' in supported_formats.

        Mutation caught: removing 'macho' from the list fails the assertion.
        """
        bridge = _ConcreteBinaryBridge()
        assert "macho" in bridge.capabilities.supported_formats

    def test_supported_formats_contains_raw(self) -> None:
        """BinaryOperationsBridge must list 'raw' in supported_formats.

        Mutation caught: removing 'raw' from the list fails the assertion.
        """
        bridge = _ConcreteBinaryBridge()
        assert "raw" in bridge.capabilities.supported_formats

    def test_supported_formats_exact_set(self) -> None:
        """supported_formats must be exactly ['pe', 'elf', 'macho', 'raw'].

        Mutation caught: adding or removing elements changes the set.
        """
        bridge = _ConcreteBinaryBridge()
        assert sorted(bridge.capabilities.supported_formats) == sorted(["pe", "elf", "macho", "raw"])

    def test_supported_architectures_contains_arm64(self) -> None:
        """BinaryOperationsBridge must list 'arm64' in supported_architectures.

        Mutation caught: removing 'arm64' from the list fails the assertion.
        """
        bridge = _ConcreteBinaryBridge()
        assert "arm64" in bridge.capabilities.supported_architectures

    def test_supported_architectures_exact_set(self) -> None:
        """supported_architectures must be exactly ['x86', 'x86_64', 'arm', 'arm64'].

        Mutation caught: adding or removing elements changes the set.
        """
        bridge = _ConcreteBinaryBridge()
        expected = sorted(["x86", "x86_64", "arm", "arm64"])
        assert sorted(bridge.capabilities.supported_architectures) == expected


# ---------------------------------------------------------------------------
# F04 -- resolve() warning log on unknown attribute (lazy.py:60)
# ---------------------------------------------------------------------------


class TestResolveLazyWarningLog:
    """Assert that resolve() emits the warning log for unknown attribute names.

    Oracle: the literal event name 'lazy_resolve_unknown_attribute' and
    level 'warning' from lazy.py:61.
    Mutation caught: removing the _logger.warning call means has_event()
    returns False and the assertion fails.
    """

    def test_resolve_unknown_name_logs_warning(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """resolve() must log 'lazy_resolve_unknown_attribute' before raising AttributeError.

        A name absent from LAZY_EXPORTS must trigger the warning log at
        level 'warning' before the AttributeError is raised.

        Args:
            monkeypatch: Pytest monkeypatch fixture.
        """
        sink = _LogSink()
        monkeypatch.setattr(_lazy_mod, "_logger", sink)

        with pytest.raises(AttributeError, match=r"has no attribute"):
            resolve("_AbsolutelyNonexistentBridge", {})

        assert sink.has_event("lazy_resolve_unknown_attribute", level="warning"), (
            "Expected 'lazy_resolve_unknown_attribute' warning log event to be emitted"
        )

    def test_resolve_unknown_name_log_carries_attribute_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The warning log must record the requested attribute_name field.

        Oracle: lazy.py:61 passes ``attribute_name=name`` as a structured
        field.  Mutation caught: omitting the field makes the field check fail.

        Args:
            monkeypatch: Pytest monkeypatch fixture.
        """
        sink = _LogSink()
        monkeypatch.setattr(_lazy_mod, "_logger", sink)
        target = "_VeryUnlikelyBridgeName_XYZ123"

        with pytest.raises(AttributeError):
            resolve(target, {})

        matching = [r for r in sink.records if r[1] == "lazy_resolve_unknown_attribute"]
        assert len(matching) == 1
        assert matching[0][2].get("attribute_name") == target


# ---------------------------------------------------------------------------
# F05 -- resolve() TypeError for non-bridge/non-installer (lazy.py:68-71)
# ---------------------------------------------------------------------------


class TestResolveLazyTypeError:
    """Assert that resolve() raises TypeError when the resolved attribute is not a bridge class.

    Oracle: the exact error message prefix in lazy.py:69 and the literal
    exception type.  Mutation caught: removing the isinstance guard lets
    the function return a non-class value instead of raising.
    """

    def test_resolve_non_class_attr_raises_type_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """resolve() must raise TypeError when the lazy export resolves to a non-class.

        A LAZY_EXPORTS entry that points to a module-level logger object
        (which is not a type, hence not a bridge) must cause TypeError with
        the expected message.

        Args:
            monkeypatch: Pytest monkeypatch fixture.
        """
        monkeypatch.setitem(
            LAZY_EXPORTS,
            "_TestBadExport",
            ("intellicrack.bridges.lazy", "_logger"),
        )
        with pytest.raises(TypeError, match=r"is not a bridge or installer class"):
            resolve("_TestBadExport", {})

    def test_resolve_non_bridge_logs_warning(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """resolve() must log 'lazy_resolve_non_bridge_attribute' when TypeError is raised.

        Oracle: lazy.py:70 emits a warning before raising TypeError.
        Mutation caught: removing the log call leaves has_event() returning
        False.

        Args:
            monkeypatch: Pytest monkeypatch fixture.
        """
        sink = _LogSink()
        monkeypatch.setattr(_lazy_mod, "_logger", sink)
        monkeypatch.setitem(
            LAZY_EXPORTS,
            "_TestBadExport2",
            ("intellicrack.bridges.lazy", "_logger"),
        )
        with pytest.raises(TypeError):
            resolve("_TestBadExport2", {})

        assert sink.has_event("lazy_resolve_non_bridge_attribute", level="warning")


# ---------------------------------------------------------------------------
# F06 -- build_schema_property array+object recursive (schemas.py:258-267)
# ---------------------------------------------------------------------------


class TestBuildSchemaPropertyArrayObject:
    """Assert that build_schema_property correctly emits nested object items for array params.

    Oracle: jsonschema.Draft7Validator validates a known document against
    the produced schema; structural assertions on the exact field layout.
    Mutation caught: omitting 'properties' / 'required' in the items dict,
    or returning {"type": "string"} instead of the nested object schema.
    """

    def _make_array_of_objects_param(self) -> ToolParameter:
        """Build a ToolParameter of type array with one object item property.

        Returns:
            ToolParameter: Parameter with items_type='object' and one nested property.
        """
        nested = ToolParameter(
            name="key",
            type="string",
            description="a string key",
            required=True,
        )
        return ToolParameter(
            name="entries",
            type="array",
            description="list of entry objects",
            items_type="object",
            item_properties=[nested],
        )

    def test_items_type_is_object(self) -> None:
        """The items sub-schema must have type 'object'.

        Mutation caught: _build_array_items returning {'type': 'string'} for
        object element type fails this exact-equality check.
        """
        param = self._make_array_of_objects_param()
        result: dict[str, Any] = cast("dict[str, Any]", build_schema_property(param))
        assert result["items"]["type"] == "object"

    def test_items_properties_contains_nested_key(self) -> None:
        """The items.properties dict must contain the nested parameter name 'key'.

        Mutation caught: omitting the properties key from items causes a
        KeyError on access or an assertion failure on the membership test.
        """
        param = self._make_array_of_objects_param()
        result: dict[str, Any] = cast("dict[str, Any]", build_schema_property(param))
        assert "properties" in result["items"]
        assert "key" in result["items"]["properties"]

    def test_nested_property_type_is_string(self) -> None:
        """The nested 'key' property must have type 'string'.

        Oracle: ToolParameter.type='string' fed to build_schema_property
        should produce {'type': 'string', ...}.  Mutation caught: wrong
        type in nested property fails exact-equality.
        """
        param = self._make_array_of_objects_param()
        result: dict[str, Any] = cast("dict[str, Any]", build_schema_property(param))
        nested_prop: dict[str, Any] = result["items"]["properties"]["key"]
        assert nested_prop["type"] == "string"

    def test_items_required_list_contains_key(self) -> None:
        """items.required must list 'key' when the nested param is required.

        Mutation caught: omitting the required list or leaving 'key' out of
        it makes the assertion fail.
        """
        param = self._make_array_of_objects_param()
        result: dict[str, Any] = cast("dict[str, Any]", build_schema_property(param))
        assert "required" in result["items"]
        assert "key" in result["items"]["required"]

    def test_schema_accepts_valid_document(self) -> None:
        """The produced schema must accept a valid array-of-objects document via jsonschema.

        Oracle: jsonschema.validate() passes [{"key": "hello"}] against the produced
        schema without raising.  Mutation caught: structurally broken schema
        (e.g. items omitted) raises jsonschema.ValidationError on a valid doc.
        """
        param = self._make_array_of_objects_param()
        schema: dict[str, Any] = cast("dict[str, Any]", build_schema_property(param))
        valid_doc: list[dict[str, str]] = [{"key": "hello"}]
        jsonschema.validate(instance=valid_doc, schema=schema)

    def test_schema_rejects_doc_missing_required_field(self) -> None:
        """The produced schema must reject an object missing the required 'key' field.

        Oracle: jsonschema.validate() raises jsonschema.ValidationError when
        the document [{}] is validated against the produced schema (which
        requires 'key').  Mutation caught: omitting 'required' from items
        lets the schema accept the invalid document without raising.
        """
        param = self._make_array_of_objects_param()
        schema: dict[str, Any] = cast("dict[str, Any]", build_schema_property(param))
        invalid_doc: list[dict[str, str]] = [{}]
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=invalid_doc, schema=schema)


# ---------------------------------------------------------------------------
# F07 -- validate_tool_parameter unrecognized items_type (schemas.py:419-422)
# ---------------------------------------------------------------------------


class TestValidateToolParameterUnrecognizedItemsType:
    """Assert that validate_tool_parameter emits a ValidationError for unknown items_type.

    Oracle: the exact message prefix 'Array parameter has unrecognized items_type'
    from schemas.py:422.  Mutation caught: removing the items_type recognition
    guard produces an empty error list, failing the length assertion.
    """

    def test_array_with_custom_items_type_produces_error(self) -> None:
        """An array param with items_type='CustomClass' must produce a ValidationError.

        Mutation caught: removing the `if not is_recognized_type(param.items_type)`
        check means no error is appended, making the non-empty assertion fail.
        """
        param = ToolParameter(
            name="data",
            type="array",
            description="array of custom objects",
            items_type="CustomClass",
        )
        errors = validate_tool_parameter(param, "test_func")
        messages = [e.message for e in errors]
        assert any("unrecognized items_type" in m for m in messages), (
            f"Expected 'unrecognized items_type' error; got: {messages}"
        )

    def test_array_with_custom_items_type_error_is_warning(self) -> None:
        """The unrecognized items_type error must have severity 'warning'.

        Oracle: schemas.py:424 passes severity='warning' to ValidationError.
        Mutation caught: changing the severity to 'error' fails the exact
        comparison.
        """
        param = ToolParameter(
            name="data",
            type="array",
            description="array of custom objects",
            items_type="CustomClass",
        )
        errors = validate_tool_parameter(param, "test_func")
        items_errors = [e for e in errors if "unrecognized items_type" in e.message]
        assert len(items_errors) == 1
        assert items_errors[0].severity == "warning"

    def test_array_with_recognized_items_type_no_items_error(self) -> None:
        """An array param with recognized items_type must not produce an items_type error.

        Confirms the gate is specific: only unrecognized types trigger the
        error.  Mutation caught: unconditionally appending the error would
        make this assertion fail.
        """
        param = ToolParameter(
            name="data",
            type="array",
            description="array of strings",
            items_type="string",
        )
        errors = validate_tool_parameter(param, "test_func")
        items_errors = [e for e in errors if "unrecognized items_type" in e.message]
        assert items_errors == []


# ---------------------------------------------------------------------------
# F08 -- validate_tool_parameter array-of-objects no item_properties (schemas.py:427-434)
# ---------------------------------------------------------------------------


class TestValidateToolParameterArrayObjectsNoItemProperties:
    """Assert that validate_tool_parameter flags array-of-objects with empty item_properties.

    Oracle: the exact message prefix 'Array of objects requires item_properties'
    from schemas.py:430 and severity 'error'.  Mutation caught: removing the
    guard lets the error list stay empty, failing the non-empty assertion.
    """

    def test_array_of_objects_empty_item_properties_produces_error(self) -> None:
        """An array with items_type='object' and item_properties=[] must produce an error.

        Mutation caught: removing the `elif normalize_type(param.items_type) == 'object'`
        branch produces an empty error list, failing the length assertion.
        """
        param = ToolParameter(
            name="rows",
            type="array",
            description="table rows",
            items_type="object",
            item_properties=[],
        )
        errors = validate_tool_parameter(param, "test_func")
        messages = [e.message for e in errors]
        assert any("requires item_properties" in m for m in messages), (
            f"Expected 'requires item_properties' error; got: {messages}"
        )

    def test_array_of_objects_no_item_properties_error_is_error_severity(self) -> None:
        """The item_properties error must have severity 'error'.

        Oracle: schemas.py:428-433 uses default severity ('error') by omitting
        the severity kwarg.  Mutation caught: if severity changed to 'warning',
        the exact comparison fails.
        """
        param = ToolParameter(
            name="rows",
            type="array",
            description="table rows",
            items_type="object",
            item_properties=[],
        )
        errors = validate_tool_parameter(param, "test_func")
        ip_errors = [e for e in errors if "requires item_properties" in e.message]
        assert len(ip_errors) == 1
        assert ip_errors[0].severity == "error"

    def test_array_of_objects_with_item_properties_no_error(self) -> None:
        """An array-of-objects with non-empty item_properties must not produce this error.

        Confirms the gate is specific.  Mutation caught: unconditionally
        appending the error would fail this assertion.
        """
        nested = ToolParameter(name="id", type="integer", description="row id")
        param = ToolParameter(
            name="rows",
            type="array",
            description="table rows",
            items_type="object",
            item_properties=[nested],
        )
        errors = validate_tool_parameter(param, "test_func")
        ip_errors = [e for e in errors if "requires item_properties" in e.message]
        assert ip_errors == []


# ---------------------------------------------------------------------------
# F09 -- _assert_never (schemas.py:28-48) -- UNTESTABLE
# ---------------------------------------------------------------------------
# Architecturally unreachable: get_schema_for_provider uses an exhaustive
# if/elif/else chain whose final else calls _assert_never.  Because every
# ProviderName enum value has a dedicated branch, the else clause is dead
# code.  No legal caller can reach it without bypassing the exhaustive
# dispatch.  No fake gate is written; the finding is documented here as
# UNTESTABLE per WAVE5-INSTRUCTIONS.md.


# ---------------------------------------------------------------------------
# F10 -- _read_exact timeout raises ToolError (named_pipe_client.py:597-605)
# ---------------------------------------------------------------------------


class TestReadExactTimeout:
    """Assert that _read_exact raises ToolError when the I/O operation times out.

    Oracle: the exact message 'Timed out reading from pipe' from
    named_pipe_client.py:604.  Mutation caught: removing the
    ``except TimeoutError`` block lets the asyncio.TimeoutError propagate
    unhandled, raising a different exception type and failing ``pytest.raises``.
    """

    def test_read_exact_timeout_raises_tool_error(self) -> None:
        """_read_exact must raise ToolError(match='Timed out reading from pipe') on timeout.

        A fake _read_exact_sync that sleeps longer than io_timeout triggers
        asyncio.wait_for to cancel the task, which the production code
        catches and re-raises as ToolError.

        Mutation caught: removing the TimeoutError handler propagates
        asyncio.TimeoutError (not ToolError) -- pytest.raises(ToolError)
        fails with an unexpected exception type.
        """
        config = PipeConfig(
            pipe_name=r"\\.\pipe\intellicrack_wave5_timeout",
            io_timeout=0.05,
        )
        client = NamedPipeClient(config=config)
        setattr(client, "_handle", _FAKE_HANDLE)

        def _blocking_sync(size: int) -> bytes:
            """Block for longer than io_timeout to force a timeout.

            Args:
                size: Ignored; returns placeholder bytes after sleeping.

            Returns:
                bytes: Placeholder bytes (never reached in normal test flow).
            """
            time.sleep(0.3)
            return bytes(size)

        setattr(client, "_read_exact_sync", _blocking_sync)

        read_exact = getattr(client, "_read_exact")
        with pytest.raises(ToolError, match=r"Timed out reading from pipe"):
            asyncio.run(read_exact(8))

    def test_read_exact_timeout_error_message_exact(self) -> None:
        """ToolError raised on timeout must carry the exact message string.

        Oracle: named_pipe_client.py:604 sets error_message = 'Timed out reading from pipe'.
        Mutation caught: changing the message text fails the match assertion.
        """
        config = PipeConfig(
            pipe_name=r"\\.\pipe\intellicrack_wave5_timeout2",
            io_timeout=0.05,
        )
        client = NamedPipeClient(config=config)
        setattr(client, "_handle", _FAKE_HANDLE)

        def _blocking_sync2(size: int) -> bytes:
            """Block past io_timeout to force ToolError on timeout.

            Args:
                size: Ignored.

            Returns:
                bytes: Placeholder bytes (unreachable in normal test flow).
            """
            time.sleep(0.3)
            return bytes(size)

        setattr(client, "_read_exact_sync", _blocking_sync2)

        read_exact = getattr(client, "_read_exact")
        with pytest.raises(ToolError, match=r"^Timed out reading from pipe$"):
            asyncio.run(read_exact(8))


# ---------------------------------------------------------------------------
# F11 -- _cancel_io log emission (named_pipe_client.py:869-882)
# ---------------------------------------------------------------------------


class TestCancelIOLogEmission:
    """Assert that _cancel_io emits both pipe_cancelling_io and pipe_io_cancelled debug logs.

    Oracle: the literal event names at named_pipe_client.py:880 and 882.
    Mutation caught: removing either _logger.debug call leaves the corresponding
    has_event() check returning False.
    """

    def test_cancel_io_emits_pipe_cancelling_io(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """_cancel_io must emit 'pipe_cancelling_io' at debug level before CancelIoEx.

        Args:
            monkeypatch: Pytest monkeypatch fixture.
        """
        sink = _LogSink()
        monkeypatch.setattr(_npc_mod, "_logger", sink)

        client = NamedPipeClient(config=PipeConfig())
        setattr(client, "_handle", _FAKE_HANDLE)
        getattr(client, "_cancel_io")()

        assert sink.has_event("pipe_cancelling_io", level="debug"), (
            "Expected 'pipe_cancelling_io' debug log event to be emitted before CancelIoEx"
        )

    def test_cancel_io_emits_pipe_io_cancelled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """_cancel_io must emit 'pipe_io_cancelled' at debug level after CancelIoEx.

        CancelIoEx returns FALSE for an invalid handle but does not raise,
        so the post-call log must still be emitted.

        Args:
            monkeypatch: Pytest monkeypatch fixture.
        """
        sink = _LogSink()
        monkeypatch.setattr(_npc_mod, "_logger", sink)

        client = NamedPipeClient(config=PipeConfig())
        setattr(client, "_handle", _FAKE_HANDLE)
        getattr(client, "_cancel_io")()

        assert sink.has_event("pipe_io_cancelled", level="debug"), (
            "Expected 'pipe_io_cancelled' debug log event to be emitted after CancelIoEx"
        )

    def test_cancel_io_noop_when_handle_is_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """_cancel_io must be a no-op (no log events) when _handle is None.

        Mutation caught: if the early-return guard was removed, the None
        handle would be passed to CancelIoEx (crash or wrong behavior) and
        log events would be emitted unexpectedly.

        Args:
            monkeypatch: Pytest monkeypatch fixture.
        """
        sink = _LogSink()
        monkeypatch.setattr(_npc_mod, "_logger", sink)

        client = NamedPipeClient(config=PipeConfig())
        getattr(client, "_cancel_io")()

        assert not sink.has_event("pipe_cancelling_io"), (
            "No log events should be emitted when _handle is None"
        )

    def test_cancel_io_log_carries_handle_value(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The pipe_cancelling_io log must carry the handle value as a field.

        Oracle: named_pipe_client.py:880 passes ``handle=self._handle``.
        Mutation caught: omitting the handle field makes the field check fail.

        Args:
            monkeypatch: Pytest monkeypatch fixture.
        """
        sink = _LogSink()
        monkeypatch.setattr(_npc_mod, "_logger", sink)

        client = NamedPipeClient(config=PipeConfig())
        setattr(client, "_handle", _FAKE_HANDLE)
        getattr(client, "_cancel_io")()

        matching = [r for r in sink.records if r[1] == "pipe_cancelling_io"]
        assert len(matching) == 1
        assert matching[0][2].get("handle") == _FAKE_HANDLE


# ---------------------------------------------------------------------------
# F12 -- bridges/__init__.py __dir__ sorted-union (bridges/__init__.py:90-96)
# ---------------------------------------------------------------------------


class TestBridgesPackageDirSortedUnion:
    """Assert that dir(intellicrack.bridges) returns the sorted union of __all__ and globals().

    Oracle: the semantics of the __dir__ implementation at bridges/__init__.py:90-96.
    Mutation caught: removing set(__all__) from __dir__ drops 'CutterBridge'
    (which is in __all__ but not in globals() until lazily resolved), causing
    the subset assertion to fail.
    """

    def test_all_entries_appear_in_dir(self) -> None:
        """Every name in bridges.__all__ must appear in dir(bridges_pkg).

        Mutation caught: removing `set(__all__)` from the sorted union
        causes all lazy-class names to vanish from the result.
        """
        dir_result = dir(bridges_pkg)
        missing = [name for name in _bridges_all if name not in dir_result]
        assert missing == [], f"Names from __all__ missing from dir(): {missing}"

    def test_lazy_exports_appear_in_dir(self) -> None:
        """Every key in LAZY_EXPORTS must appear in dir(bridges_pkg).

        LAZY_EXPORTS keys are listed in __all__; this test confirms the
        join is correct.  Mutation caught: omitting the __all__ union
        drops all lazy names from the result.
        """
        dir_result = dir(bridges_pkg)
        missing = [name for name in LAZY_EXPORTS if name not in dir_result]
        assert missing == [], f"LAZY_EXPORTS keys missing from dir(): {missing}"

    def test_dir_result_is_sorted(self) -> None:
        """dir(bridges_pkg) must return a sorted list.

        Oracle: __dir__ wraps its result in sorted(...).
        Mutation caught: removing sorted(...) produces an unsorted list
        that fails the equality check against its sorted version.
        """
        dir_result = dir(bridges_pkg)
        assert dir_result == sorted(dir_result), "dir(bridges_pkg) must be sorted"

    def test_cutter_bridge_specifically_present(self) -> None:
        """CutterBridge must be in dir(bridges_pkg) before it is lazily loaded.

        CutterBridge is only in globals() after first access, so it tests
        the __all__ contribution path specifically.

        Mutation caught: using only globals() without __all__ misses
        CutterBridge before it is accessed.
        """
        assert "CutterBridge" in dir(bridges_pkg)

    def test_bridge_capabilities_present(self) -> None:
        """BridgeCapabilities (an eagerly imported name) must also be in dir().

        This is in globals() via the eager import, confirming the globals()
        union works for eagerly loaded names too.

        Mutation caught: using only __all__ without globals() would miss
        private helpers or non-__all__ public names.
        """
        assert "BridgeCapabilities" in dir(bridges_pkg)


# ---------------------------------------------------------------------------
# F13 -- HexEditorBridge.get_selection exact tuple (hex_editor.py:5928)
# ---------------------------------------------------------------------------


class TestHexEditorBridgeGetSelectionExact:
    """Assert that get_selection returns exactly the (start, end) set by select_range.

    Oracle: the constructor arguments (4, 12) passed to select_range.
    Mutation caught: swapping start/end in select_range (``self._selection = (end, start)``)
    produces (12, 4) which fails the exact-equality assertion.
    """

    def test_get_selection_returns_exact_tuple_after_select_range(self) -> None:
        """get_selection() must return (4, 12) after select_range(4, 12).

        Does not require intellicrack_hexcore; both methods only operate
        on self._selection.  Mutation caught: assigning (end, start) instead
        of (start, end) produces (12, 4) != (4, 12).
        """
        bridge = HexEditorBridge()
        set_ok = _run(bridge.select_range(4, 12))
        assert set_ok is True
        result = _run(bridge.get_selection())
        assert result == (4, 12)

    def test_get_selection_returns_none_before_select(self) -> None:
        """get_selection() must return None when no selection has been set.

        Oracle: _HexEditorBridgeBase.__init__ sets _selection = None.
        Mutation caught: initialising _selection to (0, 0) would fail this
        exact None assertion.
        """
        bridge = HexEditorBridge()
        result = _run(bridge.get_selection())
        assert result is None

    def test_get_selection_updates_after_second_select_range(self) -> None:
        """get_selection() must reflect the most recent select_range call.

        Confirms that _selection is overwritten, not appended.
        Mutation caught: if _selection were a list that accumulated ranges,
        the return value would not equal (100, 200) after the second call.
        """
        bridge = HexEditorBridge()
        _run(bridge.select_range(4, 12))
        _run(bridge.select_range(100, 200))
        result = _run(bridge.get_selection())
        assert result == (100, 200)
