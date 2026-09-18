# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tool registry for managing tool bridges.

This module provides a registry for tool bridges that handles
initialization, availability checking, and tool schema generation
for LLM function calling.
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import time
import types
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, fields, is_dataclass
from typing import TYPE_CHECKING, Any, Union, cast, get_args, get_origin, get_type_hints

from intellicrack.bridges.base import TOOL_CAPABILITY_MAP
from intellicrack.bridges.cutter import CutterBridge
from intellicrack.bridges.frida_bridge import FridaBridge
from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.bridges.installer import ToolInstaller
from intellicrack.bridges.process import ProcessBridge
from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.bridges.schemas import RESERVED_TOOL_NAMESPACES
from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.core.logging import get_logger, log_tool_call
from intellicrack.core.types import ToolDefinition, ToolError, ToolName


ExternalToolExecutor = Callable[[str, dict[str, Any]], Awaitable[object]]
"""Signature an external namespace's executor must satisfy.

It receives the canonical dotted function name and the parsed arguments, and
returns whatever the tool produced -- a plain value for a simple tool, or a
list of :class:`~intellicrack.core.types.ToolResultPart` entries for one whose
output is more than text.
"""

ExternalDefinitionProvider = Callable[[], list[ToolDefinition]]
"""Signature an external namespace's definition provider must satisfy.

Called every time the registry is asked what tools exist, so a source whose
catalog changes at runtime -- a server that added a tool, or one the operator
just turned off -- is reflected on the next turn without re-registering.
"""


if TYPE_CHECKING:
    from pathlib import Path

    from intellicrack.bridges.base import ToolBridgeBase
    from intellicrack.core.session import Session


_logger = get_logger(__name__)

_ERR_RESERVED_NAMESPACE = "namespace is reserved for an Intellicrack bridge"
_ERR_INVALID_NAMESPACE = "namespace must be a non-empty identifier"
_ERR_EXTERNAL_FAILED = "external tool call failed"


class ExternalToolRegistry:
    """Namespaces served by tool executors outside Intellicrack's own bridges.

    The wire contract for externally-sourced tools -- raw JSON Schema,
    multi-part results, reversible wire names -- is complete without any
    particular source of such tools, so this registry ships now and stays
    empty until something registers into it. An MCP client is the obvious
    first tenant.

    Bridge namespaces are refused at registration rather than shadowed at
    dispatch, so the failure is a clear error at the point of the mistake
    instead of a bridge silently stopping working.
    """

    def __init__(self) -> None:
        """Initialize an empty external-tool registry."""
        self._executors: dict[str, ExternalToolExecutor] = {}
        self._definitions: dict[str, ExternalDefinitionProvider] = {}

    def register(
        self,
        namespace: str,
        executor: ExternalToolExecutor,
        *,
        definitions: ExternalDefinitionProvider | None = None,
    ) -> None:
        """Register an executor, and optionally a definition provider, for one namespace.

        Args:
            namespace: The namespace the executor serves, e.g. ``mcp-files``.
            executor: Awaitable callable invoked with the canonical dotted
                function name and the parsed arguments.
            definitions: Callable returning this namespace's tool definitions,
                consulted every time the registry is asked what exists. A
                namespace registered without one can still be dispatched to,
                it is simply never advertised.

        Raises:
            ToolError: If the namespace is empty, malformed, or reserved for
                an Intellicrack bridge.
        """
        key = namespace.strip().lower()
        if not key or not key.replace("_", "").replace("-", "").isalnum():
            _logger.warning("external_tool_namespace_invalid", namespace=namespace)
            raise ToolError(_ERR_INVALID_NAMESPACE, tool_name=namespace)
        if key in RESERVED_TOOL_NAMESPACES:
            _logger.warning("external_tool_namespace_reserved", namespace=key)
            raise ToolError(_ERR_RESERVED_NAMESPACE, tool_name=key)
        self._executors[key] = executor
        if definitions is not None:
            self._definitions[key] = definitions
        _logger.info("external_tool_namespace_registered", namespace=key, advertises=definitions is not None)

    def unregister(self, namespace: str) -> bool:
        """Remove an external namespace's executor and definition provider.

        Args:
            namespace: The namespace to remove.

        Returns:
            bool: ``True`` when an executor was removed.
        """
        key = namespace.strip().lower()
        removed = self._executors.pop(key, None) is not None
        _ = self._definitions.pop(key, None)
        if removed:
            _logger.info("external_tool_namespace_unregistered", namespace=namespace)
        return removed

    def definitions(self) -> list[ToolDefinition]:
        """Collect the tool definitions every registered namespace advertises.

        Each provider is isolated: one that raises contributes nothing and the
        rest still report, so a single unreachable server cannot empty the
        catalog and leave the model with no tools at all.

        Returns:
            list[ToolDefinition]: Definitions in registration order.
        """
        collected: list[ToolDefinition] = []
        for namespace, provider in self._definitions.items():
            try:
                collected.extend(provider())
            except (OSError, RuntimeError, ValueError, TypeError, AttributeError, KeyError, ToolError) as exc:
                _logger.warning(
                    "external_tool_definitions_failed",
                    namespace=namespace,
                    error=str(exc),
                    error_type=type(exc).__name__,
                )
        return collected

    def get(self, namespace: str) -> ExternalToolExecutor | None:
        """Look up the executor serving a namespace.

        Args:
            namespace: The namespace to resolve.

        Returns:
            ExternalToolExecutor | None: The executor, or ``None`` when the
            namespace is not registered.
        """
        return self._executors.get(namespace.strip().lower())

    def namespaces(self) -> list[str]:
        """List every registered external namespace.

        Returns:
            list[str]: Registered namespaces, in registration order.
        """
        return list(self._executors)


_ERR_BRIDGE_NA = "bridge not available"
_ERR_UNKNOWN_TOOL = "unknown tool"
_ERR_NOT_REGISTERED = "not registered"
_ERR_UNKNOWN_FUNC = "unknown function"
_ERR_NOT_CALLABLE = "not callable"
_ERR_CALL_FAILED = "call failed"
_ERR_MISSING_CAPABILITY = "missing capability"
_ERR_INVALID_HEX_ARGUMENT = "invalid hex string argument"
_ERR_UNKNOWN_DATACLASS_FIELD = "unknown field for dataclass tool parameter"
_ERR_DATACLASS_CONSTRUCTION_FAILED = "cannot construct dataclass tool parameter"

_BridgeMethod = Callable[..., Any]

_ANNOTATION_RESOLUTION_ERRORS: tuple[type[Exception], ...] = (NameError, TypeError, AttributeError, SyntaxError)

_LOCAL_INIT_TOOLS: frozenset[ToolName] = frozenset(
    {
        ToolName.PROCESS,
        ToolName.FRIDA,
        ToolName.SANDBOX,
        ToolName.HEX_EDITOR,
        ToolName.CUTTER,
    },
)


def _is_bytes_annotation(annotation: object) -> bool:
    """Determine whether a parameter annotation requires ``bytes``.

    Matches the bare ``bytes`` annotation as well as ``bytes | None``
    (or ``Optional[bytes]``) unions used by optional bytes parameters.
    Annotations that also accept ``str`` (e.g. ``bytes | str``) are
    intentionally excluded: those methods already decode hex strings
    internally, so re-encoding them here would be redundant and would
    discard the method's own string-handling semantics (such as
    wildcard patterns).

    Args:
        annotation: The ``inspect.Parameter.annotation`` value to inspect.

    Returns:
        bool: True if the annotation is ``bytes`` or a union of
        ``bytes`` with only ``None``.
    """
    if annotation is bytes:
        return True
    annotation_str = str(annotation)
    tokens = {token.strip() for token in annotation_str.split("|")}
    return "bytes" in tokens and tokens <= {"bytes", "None"}


def _coerce_hex_string_arguments(method: _BridgeMethod, arguments: dict[str, Any]) -> dict[str, Any]:
    """Decode hex-string arguments into ``bytes`` for byte-typed parameters.

    Tool definitions expose binary payloads to LLM callers as JSON
    strings containing hex-encoded bytes (JSON has no native binary
    type). The underlying bridge methods, however, declare those
    parameters as ``bytes`` so GUI callers can pass real byte objects
    directly. This inspects ``method``'s real signature and decodes any
    argument bound to a ``bytes``-annotated parameter from a hex string
    before dispatch, leaving all other arguments untouched.

    Args:
        method: The resolved bridge method about to be invoked.
        arguments: Raw arguments supplied by the tool caller.

    Returns:
        dict[str, Any]: A copy of ``arguments`` with hex-string values
        for ``bytes``-typed parameters decoded into ``bytes``.

    Raises:
        ToolError: If a value bound to a ``bytes``-typed parameter is a
            string that is not valid hex.
    """
    try:
        signature = inspect.signature(method)
    except (TypeError, ValueError):
        return arguments

    coerced = dict(arguments)
    for name, value in arguments.items():
        parameter = signature.parameters.get(name)
        if parameter is None or not isinstance(value, str):
            continue
        if not _is_bytes_annotation(parameter.annotation):
            continue
        try:
            coerced[name] = bytes.fromhex(value.replace(" ", ""))
        except ValueError as exc:
            raise ToolError(_ERR_INVALID_HEX_ARGUMENT) from exc

    return coerced


def _resolve_type_hints(target: _BridgeMethod | type[object]) -> dict[str, Any]:
    """Resolve the real annotations of a bridge method or a dataclass type.

    Wraps :func:`typing.get_type_hints`, which evaluates the string-form
    annotations produced by ``from __future__ import annotations`` against
    the defining module's own globals - the only place forward references
    on a bound method or class can be resolved correctly. Resolution can
    fail, for example when an annotation names a type imported only under
    ``typing.TYPE_CHECKING`` and therefore absent at runtime; when that
    happens every parameter or field is treated as unresolved rather than
    raising, so a single unresolvable annotation degrades dispatch back to
    today's un-hydrated behavior instead of breaking it outright.

    Args:
        target: A bound bridge method or a dataclass type whose annotations
            should be resolved.

    Returns:
        dict[str, Any]: Mapping of parameter or field name to resolved
        type. Empty if resolution failed.
    """
    try:
        return get_type_hints(target)
    except _ANNOTATION_RESOLUTION_ERRORS:
        return {}


def _dataclass_type_from_annotation(annotation: object) -> type[Any] | None:
    """Return the dataclass type a resolved annotation targets, if any.

    Matches a bare dataclass type directly, and a dataclass wrapped in an
    ``Optional``/``| None`` union by discarding ``NoneType`` and requiring
    exactly one dataclass type to remain. Any other shape - a plain
    non-dataclass type, a union of more than one non-``None`` member, or a
    typing construct that resolves to neither - is not a hydration target.

    Args:
        annotation: A resolved (non-string) annotation, as returned by
            :func:`_resolve_type_hints`.

    Returns:
        type[Any] | None: The dataclass type the annotation targets, or
        ``None`` if it does not target exactly one dataclass type.
    """
    if isinstance(annotation, type) and is_dataclass(annotation):
        return annotation

    origin = get_origin(annotation)
    if origin is Union or origin is types.UnionType:
        members = [member for member in get_args(annotation) if member is not type(None)]
        if len(members) == 1 and isinstance(members[0], type) and is_dataclass(members[0]):
            return members[0]

    return None


def _build_dataclass_instance(
    dataclass_type: type[Any],
    mapping: Mapping[str, Any],
    *,
    parameter_name: str,
) -> object:
    """Construct a dataclass instance from a tool-supplied mapping.

    Recursively hydrates any field of ``dataclass_type`` whose own resolved
    type targets a dataclass (bare, or as a ``| None`` union) when the
    corresponding value in ``mapping`` is itself a mapping, so a nested
    payload is converted all the way down before ``dataclass_type`` itself
    is constructed. Field-name validation uses :func:`dataclasses.fields`,
    which reports real field names independent of whether their types can
    be resolved, so an unknown key is always caught even when nested-field
    type resolution fails.

    Args:
        dataclass_type: Dataclass type to construct.
        mapping: Field values supplied by the tool caller.
        parameter_name: Dotted path identifying the tool parameter or
            field being hydrated, used only to compose error messages.

    Returns:
        object: A new instance of ``dataclass_type``.

    Raises:
        ToolError: If ``mapping`` contains a key that is not a field of
            ``dataclass_type``, or if the resolved fields cannot construct
            a valid instance.
    """
    valid_names = {field.name for field in fields(dataclass_type)}
    unknown = sorted(set(mapping) - valid_names)
    if unknown:
        msg = f"{_ERR_UNKNOWN_DATACLASS_FIELD} {parameter_name!r}: {unknown} not in {sorted(valid_names)}"
        raise ToolError(msg)

    field_hints = _resolve_type_hints(dataclass_type)
    hydrated: dict[str, Any] = {}
    for key, value in mapping.items():
        nested_type = _dataclass_type_from_annotation(field_hints.get(key))
        if nested_type is not None and isinstance(value, Mapping):
            nested_mapping = cast("Mapping[str, Any]", value)
            hydrated[key] = _build_dataclass_instance(nested_type, nested_mapping, parameter_name=f"{parameter_name}.{key}")
        else:
            hydrated[key] = value

    try:
        return dataclass_type(**hydrated)
    except TypeError as exc:
        msg = f"{_ERR_DATACLASS_CONSTRUCTION_FAILED} {parameter_name!r} ({dataclass_type.__name__}): {exc}"
        raise ToolError(msg) from exc


def _hydrate_dataclass_arguments(method: _BridgeMethod, arguments: dict[str, Any]) -> dict[str, Any]:
    """Construct real dataclass instances for dataclass-typed tool parameters.

    Tool-call arguments arrive as plain JSON-decoded values, so a parameter
    a bridge method annotates with a dataclass type (bare, or as
    ``SomeDataclass | None``) is supplied by an AI/orchestrator caller as a
    plain mapping rather than a real instance. Bridge methods perform
    genuine attribute access on such parameters, so passing the mapping
    straight through fails deep inside the call instead of at the dispatch
    boundary. This inspects ``method``'s resolved parameter types and
    converts any mapping bound to a dataclass-typed parameter into a real
    instance of that dataclass - recursively, for dataclass-typed fields -
    before dispatch.

    Only parameters whose resolved type targets a dataclass (bare, or an
    ``Optional``/``| None`` union naming exactly one dataclass type) are
    considered, and only when the supplied value is a plain mapping; every
    other parameter - including one already holding a real dataclass
    instance - passes through unchanged. A method whose parameter
    annotations cannot be resolved at all (for example, one naming a type
    imported only under ``typing.TYPE_CHECKING``) is left entirely
    un-hydrated, matching dispatch behavior prior to this function's
    introduction. Propagates :class:`ToolError` from
    :func:`_build_dataclass_instance` when a mapping supplied for a
    dataclass-typed parameter names an unknown field or cannot construct
    the dataclass.

    Args:
        method: The resolved bridge method about to be invoked.
        arguments: Arguments already coerced by
            :func:`_coerce_hex_string_arguments`.

    Returns:
        dict[str, Any]: A copy of ``arguments`` with mapping values bound to
        dataclass-typed parameters replaced by real dataclass instances.
    """
    parameter_hints = _resolve_type_hints(method)
    if not parameter_hints:
        return arguments

    hydrated = dict(arguments)
    for name, value in arguments.items():
        if not isinstance(value, Mapping):
            continue
        dataclass_type = _dataclass_type_from_annotation(parameter_hints.get(name))
        if dataclass_type is None:
            continue
        nested_mapping = cast("Mapping[str, Any]", value)
        hydrated[name] = _build_dataclass_instance(dataclass_type, nested_mapping, parameter_name=name)

    return hydrated


@dataclass
class ToolStatus:
    """Status of a registered tool.

    Attributes:
        name: Identifier of the tool.
        available: Whether the tool is available on the system.
        connected: Whether the tool is currently connected.
        version: Tool version if known.
        path: Installation path if known.
        error: Last error if any.
    """

    name: ToolName
    available: bool
    connected: bool
    version: str | None = None
    path: Path | None = None
    error: str | None = None


class ToolRegistry:
    """Registry for tool bridges.

    Manages initialization, availability, and provides unified access
    to all tool bridges.
    """

    def __init__(self, tools_dir: Path) -> None:
        """Initialize the ToolRegistry with a tools directory.

        Args:
            tools_dir: Directory for tool installations.
        """
        self._bridges: dict[ToolName, ToolBridgeBase] = {}
        self._external_tools = ExternalToolRegistry()
        self._installer = ToolInstaller(tools_dir)
        self._tools_dir = tools_dir
        self._initialized = False
        self._session: Session | None = None
        _logger.debug("tool_registry_init", tools_dir=str(tools_dir))

    @property
    def external_tools(self) -> ExternalToolRegistry:
        """The registry of namespaces served outside Intellicrack's bridges.

        Returns:
            ExternalToolRegistry: The registry a tool source registers into.
        """
        return self._external_tools

    def _resolve_bridge(self, namespace: str) -> ToolBridgeBase | None:
        """Resolve a namespace against the bridge registry.

        The bridge registry is consulted first and its keying is unchanged, so
        every existing bridge call routes exactly as it did. Only a namespace
        no bridge owns reaches the external registry.

        Args:
            namespace: The already-normalized tool namespace.

        Returns:
            ToolBridgeBase | None: The bridge owning the namespace, or
            ``None`` when no bridge does.

        Raises:
            ToolError: If a bridge owns the namespace but is not registered.
        """
        try:
            tool_enum = ToolName(namespace)
        except ValueError:
            return None
        bridge = self._bridges.get(tool_enum)
        if bridge is None:
            _logger.debug("execute_tool_call_not_registered", tool_name=namespace)
            raise ToolError(_ERR_NOT_REGISTERED)
        return bridge

    @staticmethod
    async def _execute_external(
        *,
        namespace: str,
        executor: ExternalToolExecutor,
        function_name: str,
        arguments: dict[str, Any],
    ) -> object:
        """Run one externally-registered tool call.

        Args:
            namespace: The external namespace serving the call.
            executor: The registered executor.
            function_name: Canonical dotted function name to invoke.
            arguments: Parsed function arguments.

        Returns:
            object: Whatever the executor produced.

        Raises:
            ToolError: If the executor raised.
        """
        start = time.monotonic()
        success = True
        try:
            return await executor(function_name, arguments)
        except (OSError, RuntimeError, ValueError, TypeError, ToolError, KeyError, AttributeError) as exc:
            success = False
            _logger.warning(
                "external_tool_call_failed",
                namespace=namespace,
                function_name=function_name,
                error=str(exc),
            )
            message = f"{_ERR_EXTERNAL_FAILED}: {exc}"
            raise ToolError(message, tool_name=namespace) from exc
        finally:
            log_tool_call(
                tool_name=namespace,
                function_name=function_name,
                arguments=arguments,
                duration_ms=(time.monotonic() - start) * 1000,
                success=success,
            )

    def set_session(self, session: Session | None) -> None:
        """Attach (or detach) the active session for every registered bridge.

        Propagates the supplied session to every bridge so each bridge's
        lifecycle transitions (connect, attach, error, detach) flow into
        the session's ``tool_states`` registry. Newly registered bridges
        added via :meth:`register_bridge` inherit the current session
        automatically.

        Args:
            session: The active ``Session`` to publish state into, or
                ``None`` to detach all bridges from any previously
                attached session.
        """
        self._session = session
        for bridge in self._bridges.values():
            bridge.set_session(session)
        _logger.debug(
            "tool_registry_session_set",
            attached=session is not None,
            bridge_count=len(self._bridges),
        )

    @property
    def tools_directory(self) -> Path:
        """The tools directory.

        Returns:
            Path: Path to tools directory.
        """
        return self._tools_dir

    def _instantiate_bridge(
        self,
        *,
        tool_name: ToolName,
        module_path: str,
        class_name: str,
    ) -> None:
        """Import and instantiate a bridge class, registering it in the registry.

        Any exception raised while importing the module, resolving the class,
        instantiating it, or wiring the session propagates so the caller can
        decide how to log and recover.

        Args:
            tool_name: Registry key for the bridge.
            module_path: Dotted module path containing the bridge class.
            class_name: Bridge class name within ``module_path``.
        """
        mod = importlib.import_module(module_path)
        cls = getattr(mod, class_name)
        bridge_instance = cls()
        self._bridges[tool_name] = bridge_instance
        if self._session is not None:
            bridge_instance.set_session(self._session)

    async def initialize(self) -> None:
        """Initialize all tool bridges.

        Creates bridge instances for all supported tools.
        """
        _logger.debug("tool_registry_initialize_entry", already_initialized=self._initialized)
        if self._initialized:
            _logger.debug("tool_registry_initialize_early_return", reason="already_initialized")
            return

        bridge_specs: list[tuple[ToolName, str, str]] = [
            (ToolName.PROCESS, "intellicrack.bridges.process", "ProcessBridge"),
            (ToolName.FRIDA, "intellicrack.bridges.frida_bridge", "FridaBridge"),
            (ToolName.GHIDRA, "intellicrack.bridges.ghidra", "GhidraBridge"),
            (ToolName.CUTTER, "intellicrack.bridges.cutter", "CutterBridge"),
            (ToolName.X64DBG, "intellicrack.bridges.x64dbg", "X64DbgBridge"),
            (ToolName.SANDBOX, "intellicrack.bridges.sandbox_bridge", "SandboxBridge"),
            (ToolName.HEX_EDITOR, "intellicrack.bridges.hex_editor", "HexEditorBridge"),
        ]
        for tool_name, module_path, class_name in bridge_specs:
            try:
                self._instantiate_bridge(tool_name=tool_name, module_path=module_path, class_name=class_name)
            except Exception:
                _logger.exception("bridge_import_failed", bridge=tool_name.value)
        _logger.debug(
            "bridges_instantiated",
            bridge_names=[n.value for n in self._bridges],
        )

        for tool_name in _LOCAL_INIT_TOOLS:
            if tool_name in self._bridges:
                try:
                    await self._bridges[tool_name].initialize()
                except Exception:
                    _logger.exception("bridge_init_failed", bridge=tool_name.value)

        _logger.info("tool_registry_initialized", bridge_count=len(self._bridges))
        self._initialized = True

    async def _initialize_tool_bridge(
        self,
        *,
        name: ToolName,
        bridge: ToolBridgeBase,
        port: int | None,
    ) -> None:
        """Ensure the tool's binary is available and initialize its bridge.

        Propagates ``OSError`` from the installer when the tool cannot be
        located or staged, ``RuntimeError`` when bridge initialization reports
        a runtime failure, and ``ToolError`` when the bridge rejects the
        initialization request.

        Args:
            name: Tool identifier; used to choose Ghidra-specific wiring.
            bridge: The bridge instance previously registered for ``name``.
            port: Network port forwarded to the Ghidra bridge when set.
        """
        tool_path = await self._installer.ensure_tool(name)
        if name == ToolName.GHIDRA and port is not None:
            ghidra = cast("GhidraBridge", bridge)
            ghidra.set_port(port)
            await ghidra.initialize(tool_path)
        else:
            await bridge.initialize(tool_path)
        _logger.info("tool_initialized", tool_name=name.value, tool_path=str(tool_path))

    async def initialize_tool(
        self,
        name: ToolName,
        port: int | None = None,
    ) -> bool:
        """Initialize a specific tool.

        Finds or installs the tool and initializes its bridge.

        Args:
            name: Tool to initialize.
            port: Network port for bridge communication if applicable.

        Returns:
            bool: True if initialization succeeded.
        """
        if name not in self._bridges:
            _logger.warning("unknown_tool", tool_name=name)
            return False

        bridge = self._bridges[name]

        if name in _LOCAL_INIT_TOOLS:
            if not await bridge.is_available():
                await bridge.initialize()
            return await bridge.is_available()

        success = False
        try:
            await self._initialize_tool_bridge(name=name, bridge=bridge, port=port)
            success = True
        except (OSError, RuntimeError, ToolError) as exc:
            _logger.warning("tool_initialization_failed", tool_name=name.value, error=str(exc))

        return success

    async def shutdown(self) -> None:
        """Shutdown all tool bridges.

        Clears ``self._bridges`` after every bridge has been shut down so a
        subsequent call to :meth:`initialize` rebuilds the registry from
        scratch instead of reusing closed bridge instances. Without this,
        callers observing ``_bridges`` after shutdown would see references to
        bridges whose underlying tool processes have been terminated.
        """
        bridge_count = len(self._bridges)
        for name, bridge in self._bridges.items():
            try:
                await bridge.shutdown()
                _logger.info("bridge_shutdown", bridge_name=name.value)
            except (OSError, RuntimeError, ToolError) as e:
                _logger.warning("bridge_shutdown_error", bridge_name=name.value, error=str(e))

        self._bridges.clear()
        self._initialized = False
        _logger.info("tool_registry_shutdown", bridge_count=bridge_count)

    def get(self, name: ToolName) -> ToolBridgeBase | None:
        """Get a tool bridge by name.

        Args:
            name: Tool name.

        Returns:
            ToolBridgeBase | None: Tool bridge or None if not registered.
        """
        bridge = self._bridges.get(name)
        if bridge is not None:
            _logger.debug("bridge_cache_hit", tool_name=name.value)
        else:
            _logger.debug("bridge_cache_miss", tool_name=name.value)
        return bridge

    def register_bridge(self, name: ToolName, bridge: ToolBridgeBase) -> None:
        """Register or replace a tool bridge.

        Allows callers to plug in a pre-built bridge supplied by an embedding
        application or a test harness without going through :meth:`initialize`.
        Replaces any existing bridge registered under the same name and logs
        the swap so the change is auditable.

        Args:
            name: Tool name to register the bridge under.
            bridge: Bridge instance to register.
        """
        previous = self._bridges.get(name)
        self._bridges[name] = bridge
        if self._session is not None:
            bridge.set_session(self._session)
        _logger.info(
            "bridge_registered",
            tool_name=name.value,
            replaced_existing=previous is not None,
        )

    def get_process_bridge(self) -> ProcessBridge:
        """Get the process control bridge.

        Returns:
            ProcessBridge: ProcessBridge instance.

        Raises:
            ToolError: If bridge not available.
        """
        bridge = self._bridges.get(ToolName.PROCESS)
        if bridge is None or not isinstance(bridge, ProcessBridge):
            raise ToolError(_ERR_BRIDGE_NA)
        _logger.debug("get_process_bridge_success", bridge_type=type(bridge).__name__)
        return bridge

    def get_frida_bridge(self) -> FridaBridge:
        """Get the Frida instrumentation bridge.

        Returns:
            FridaBridge: FridaBridge instance.

        Raises:
            ToolError: If bridge not available.
        """
        bridge = self._bridges.get(ToolName.FRIDA)
        if bridge is None or not isinstance(bridge, FridaBridge):
            raise ToolError(_ERR_BRIDGE_NA)
        _logger.debug("get_frida_bridge_success", bridge_type=type(bridge).__name__)
        return bridge

    def get_ghidra_bridge(self) -> GhidraBridge:
        """Get the Ghidra analysis bridge.

        Returns:
            GhidraBridge: GhidraBridge instance.

        Raises:
            ToolError: If bridge not available.
        """
        bridge = self._bridges.get(ToolName.GHIDRA)
        if bridge is None or not isinstance(bridge, GhidraBridge):
            raise ToolError(_ERR_BRIDGE_NA)
        _logger.debug("get_ghidra_bridge_success", bridge_type=type(bridge).__name__)
        return bridge

    def get_cutter_bridge(self) -> CutterBridge:
        """Get the Cutter/Rizin analysis bridge.

        Returns:
            CutterBridge: CutterBridge instance.

        Raises:
            ToolError: If bridge not available.
        """
        bridge = self._bridges.get(ToolName.CUTTER)
        if bridge is None or not isinstance(bridge, CutterBridge):
            raise ToolError(_ERR_BRIDGE_NA)
        _logger.debug("get_cutter_bridge_success", bridge_type=type(bridge).__name__)
        return bridge

    def get_x64dbg_bridge(self) -> X64DbgBridge:
        """Get the x64dbg debugger bridge.

        Returns:
            X64DbgBridge: X64DbgBridge instance.

        Raises:
            ToolError: If bridge not available.
        """
        bridge = self._bridges.get(ToolName.X64DBG)
        if bridge is None or not isinstance(bridge, X64DbgBridge):
            raise ToolError(_ERR_BRIDGE_NA)
        _logger.debug("get_x64dbg_bridge_success", bridge_type=type(bridge).__name__)
        return bridge

    def get_sandbox_bridge(self) -> SandboxBridge:
        """Get the sandbox bridge.

        Returns:
            SandboxBridge: SandboxBridge instance.

        Raises:
            ToolError: If bridge not available.
        """
        bridge = self._bridges.get(ToolName.SANDBOX)
        if bridge is None or not isinstance(bridge, SandboxBridge):
            raise ToolError(_ERR_BRIDGE_NA)
        _logger.debug("get_sandbox_bridge_success", bridge_type=type(bridge).__name__)
        return bridge

    def get_hex_editor_bridge(self) -> HexEditorBridge:
        """Get the hex editor bridge.

        Returns:
            HexEditorBridge: HexEditorBridge instance.

        Raises:
            ToolError: If bridge not available.
        """
        bridge = self._bridges.get(ToolName.HEX_EDITOR)
        if bridge is None or not isinstance(bridge, HexEditorBridge):
            raise ToolError(_ERR_BRIDGE_NA)
        _logger.debug("get_hex_editor_bridge_success", bridge_type=type(bridge).__name__)
        return bridge

    async def _build_tool_status(
        self,
        *,
        name: ToolName,
        bridge: ToolBridgeBase,
    ) -> ToolStatus:
        """Probe a bridge and assemble its :class:`ToolStatus` snapshot.

        Propagates ``OSError``, ``RuntimeError``, or :class:`ToolError` from
        the availability probe so the caller can convert those failures into
        a :class:`ToolStatus` with the error captured.

        Args:
            name: Tool name being queried.
            bridge: The bridge instance registered for ``name``.

        Returns:
            ToolStatus: Status snapshot including availability, connection
            state, resolved path (for installable tools), and detected version.
        """
        available = await bridge.is_available()
        state = bridge.state

        version = None
        path = None

        if name not in _LOCAL_INIT_TOOLS:
            try:
                path = await self._installer.find_tool(name)
                if path is not None:
                    version = await self._installer.get_version(name, path)
            except (OSError, RuntimeError, ToolError) as e:
                _logger.exception(
                    "tool_path_version_lookup_failed",
                    tool_name=name.value,
                    error_str=str(e),
                )

        return ToolStatus(
            name=name,
            available=available,
            connected=state.connected,
            version=str(version) if version is not None else None,
            path=path,
            error=state.last_error,
        )

    async def get_status(self, name: ToolName) -> ToolStatus:
        """Get status of a tool.

        Args:
            name: Tool name.

        Returns:
            ToolStatus: ToolStatus instance.
        """
        _logger.debug("get_status_entry", tool_name=name.value)
        bridge = self._bridges.get(name)
        if bridge is None:
            _logger.debug("get_status_not_registered", tool_name=name.value)
            return ToolStatus(
                name=name,
                available=False,
                connected=False,
                error="Tool not registered",
            )

        try:
            return await self._build_tool_status(name=name, bridge=bridge)

        except (OSError, RuntimeError, ToolError) as e:
            _logger.warning("tool_status_check_failed", tool_name=name.value, error=str(e))
            return ToolStatus(
                name=name,
                available=False,
                connected=False,
                error=str(e),
            )

    async def get_all_status(self) -> list[ToolStatus]:
        """Get status of all tools.

        Returns:
            list[ToolStatus]: List of ToolStatus instances.
        """
        _logger.debug("get_all_status_entry", bridge_count=len(self._bridges))
        tasks = [self.get_status(name) for name in self._bridges]
        results: list[ToolStatus] = list(await asyncio.gather(*tasks))
        _logger.debug("get_all_status_complete", status_count=len(results))
        return results

    def get_tool_definitions(self) -> list[ToolDefinition]:
        """Get tool definitions for LLM function calling.

        Bridge definitions come first and externally-sourced ones follow, so
        a provider that truncates a long tool list at its own cap drops
        third-party tools before it drops an Intellicrack bridge.

        Returns:
            list[ToolDefinition]: List of ToolDefinition instances.
        """
        _logger.debug("get_tool_definitions_entry", bridge_count=len(self._bridges))
        definitions: list[ToolDefinition] = []

        for bridge in self._bridges.values():
            try:
                definitions.append(bridge.tool_definition)
            except (AttributeError, RuntimeError, ToolError) as e:
                _logger.warning("tool_definition_retrieval_failed", error=str(e))

        definitions.extend(self._external_tools.definitions())

        function_count = sum(len(definition.functions) for definition in definitions)
        _logger.debug(
            "get_tool_definitions_complete",
            definition_count=len(definitions),
            function_count=function_count,
        )
        return definitions

    def get_available_tools(self) -> list[ToolName]:
        """Get list of available tools.

        Returns:
            list[ToolName]: List of available tool names.
        """
        tools = list(self._bridges.keys())
        _logger.debug(
            "get_available_tools",
            tool_count=len(tools),
            tool_names=[t.value for t in tools],
        )
        return tools

    async def execute_tool_call(
        self,
        tool_name: str,
        function_name: str,
        arguments: dict[str, Any],
    ) -> object:
        """Execute a tool function call.

        Args:
            tool_name: Name of the tool (e.g., "ghidra", "frida").
            function_name: Function to call (e.g., "decompile", "hook_function").
            arguments: Function arguments.

        Returns:
            object: Result of the function call.

        Raises:
            ToolError: If execution fails.
        """
        _logger.debug(
            "execute_tool_call_entry",
            tool_name=tool_name,
            function_name=function_name,
        )
        namespace = tool_name.strip().lower()
        bridge = self._resolve_bridge(namespace)
        if bridge is None:
            executor = self._external_tools.get(namespace)
            if executor is not None:
                return await self._execute_external(
                    namespace=namespace,
                    executor=executor,
                    function_name=function_name,
                    arguments=arguments,
                )
            _logger.debug("execute_tool_call_unresolved", tool_name=tool_name)
            raise ToolError(_ERR_UNKNOWN_TOOL)

        attr_name = function_name.split(".", maxsplit=1)[-1] if "." in function_name else function_name
        method = getattr(bridge, attr_name, None)
        if method is None:
            _logger.debug(
                "execute_tool_call_unknown_func",
                tool_name=namespace,
                function_name=function_name,
                attr_name=attr_name,
            )
            raise ToolError(_ERR_UNKNOWN_FUNC)

        if not callable(method):
            _logger.debug(
                "execute_tool_call_not_callable",
                tool_name=namespace,
                function_name=function_name,
            )
            raise ToolError(_ERR_NOT_CALLABLE)

        self._require_capability(
            bridge=bridge,
            namespace=namespace,
            function_name=function_name,
            attr_name=attr_name,
        )

        dispatch_arguments = _coerce_hex_string_arguments(method, arguments)
        dispatch_arguments = _hydrate_dataclass_arguments(method, dispatch_arguments)

        start = time.monotonic()
        result: object = None
        success = True
        try:
            if inspect.iscoroutinefunction(method):
                result = await method(**dispatch_arguments)
            else:
                result = await asyncio.to_thread(method, **dispatch_arguments)
        except (OSError, RuntimeError, ValueError, TypeError, ToolError, KeyError, AttributeError) as e:
            success = False
            _logger.warning("tool_call_failed", tool_name=tool_name, function_name=function_name, error=str(e))
            msg = f"{_ERR_CALL_FAILED}: {e}"
            raise ToolError(msg) from e
        finally:
            elapsed_ms = (time.monotonic() - start) * 1000
            log_tool_call(
                tool_name=tool_name,
                function_name=function_name,
                arguments=arguments,
                duration_ms=elapsed_ms,
                success=success,
            )

        if success:
            state = getattr(bridge, "state", None)
            if state is not None and hasattr(state, "clear_error"):
                state.clear_error()

        return result

    @staticmethod
    def _require_capability(
        *,
        bridge: ToolBridgeBase,
        namespace: str,
        function_name: str,
        attr_name: str,
    ) -> None:
        """Refuse a call whose bridge does not advertise the needed capability.

        Args:
            bridge: The bridge that owns the function.
            namespace: The tool namespace, for log records.
            function_name: Canonical dotted function name.
            attr_name: Bare method name on the bridge.

        Raises:
            ToolError: If the bridge lacks the capability the function needs.
        """
        caps = getattr(bridge, "capabilities", None)
        required_capability = TOOL_CAPABILITY_MAP.get(function_name) or TOOL_CAPABILITY_MAP.get(attr_name)
        if caps is None or required_capability is None:
            return
        has_cap = caps.has_capability(required_capability)
        _logger.debug(
            "execute_tool_call_capability_check",
            tool_name=namespace,
            function_name=function_name,
            capability=required_capability,
            has_capability=has_cap,
        )
        if not has_cap:
            _logger.warning(
                "execute_tool_call_missing_capability",
                tool_name=namespace,
                function_name=function_name,
                capability=required_capability,
            )
            missing_message = f"{_ERR_MISSING_CAPABILITY}: {namespace} lacks supports_{required_capability}"
            raise ToolError(missing_message)

    async def ensure_tool_ready(self, name: ToolName) -> bool:
        """Ensure a tool is ready for use.

        Initializes the tool if not already initialized.

        Args:
            name: Tool name.

        Returns:
            bool: True if tool is ready.
        """
        _logger.debug("ensure_tool_ready_entry", tool_name=name.value)
        bridge = self._bridges.get(name)
        if bridge is None:
            _logger.debug("ensure_tool_ready_not_found", tool_name=name.value)
            return False

        if await bridge.is_available():
            _logger.debug("ensure_tool_ready_already_available", tool_name=name.value)
            return True

        _logger.debug("ensure_tool_ready_initializing", tool_name=name.value)
        return await self.initialize_tool(name)
