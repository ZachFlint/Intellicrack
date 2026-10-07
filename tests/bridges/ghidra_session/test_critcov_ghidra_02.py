# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-object coverage for the second slice of ``intellicrack.bridges.ghidra``.

The slice is the error handling and not-connected guarding of the label,
bookmark, function, structure, memory-block, register, reference, namespace and
debug-info accessors, plus the transport primitives ``_execute_remote`` and
``_execute_remote_eval``.

Three kinds of real object stand in for a running Ghidra:

* a genuine ``ghidra_bridge.GhidraBridge`` RPC client pointed at a closed
  loopback port, attached through ``attach_remote_bridge``, so every remote call
  fails the way a vanished Ghidra peer does;
* ``_ScriptedBridge``, a subclass of the real ``GhidraBridge`` that replaces only
  the two transport primitives with a queue of outcomes, so the accessor code
  that sits around a remote call (error wrapping, payload validation, readback
  checking) runs unchanged against a chosen answer;
* one module-scoped headless Ghidra session, started once through PyGhidra on a
  private copy of a System32 executable and shut down in ``finally``, behind the
  ``live_session`` fixture. Only the tests that need a live program use it.
"""

from __future__ import annotations

import asyncio
import importlib
import os
import re
import shutil
import socket
import types
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

import pefile
import pytest
from structlog.testing import capture_logs

from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import Iterator


_LIVE_STEP_TIMEOUT_SECONDS: Final[float] = 600.0
_FAILURE_TEXT: Final[str] = "scripted-failure"
_REMOTE_FAILURE_PATTERN: Final[str] = r"^Remote execution failed"
_NOT_CONNECTED_PATTERN: Final[str] = r"^Ghidra not connected$"
_SENTINEL_PREFIX: Final[str] = "_intellicrack_ghidra_result_"
_UNENCODABLE_RESULT_SCRIPT: Final[str] = "lone = '\\ud800'\nlone\n"
_DWARF_EXTENSIONS: Final[list[str]] = [".debug", ".dwarf", ".dbg", ".so", ".dylib", ".o", ".elf"]

_BridgeCall = Callable[[GhidraBridge], Awaitable[object]]

_PASSTHROUGH_CALLS: Final[list[tuple[str, _BridgeCall]]] = [
    ("set_label", lambda bridge: bridge.set_label(0x1000, "lbl")),
    ("get_labels", lambda bridge: bridge.get_labels(0x1000)),
    ("create_bookmark", lambda bridge: bridge.create_bookmark(0x1000, "cat", "text")),
    ("get_bookmarks", lambda bridge: bridge.get_bookmarks()),
    ("delete_function", lambda bridge: bridge.delete_function(0x1000)),
    ("get_structures", lambda bridge: bridge.get_structures()),
    ("get_memory_map", lambda bridge: bridge.get_memory_map()),
    ("create_uninitialized_block", lambda bridge: bridge.create_uninitialized_block("blk", 0x1000, 0x10)),
    ("create_byte_mapped_block", lambda bridge: bridge.create_byte_mapped_block("blk", 0x1000, 0x2000, 0x10)),
    ("create_bit_mapped_block", lambda bridge: bridge.create_bit_mapped_block("blk", 0x1000, 0x2000, 0x10)),
    ("get_call_graph", lambda bridge: bridge.get_call_graph(0x1000)),
    ("get_segments", lambda bridge: bridge.get_segments()),
    ("get_program_info", lambda bridge: bridge.get_program_info()),
    ("write_bytes", lambda bridge: bridge.write_bytes(0x1000, "90")),
    ("read_bytes", lambda bridge: bridge.read_bytes(0x1000, 4)),
    ("get_pcode", lambda bridge: bridge.get_pcode(0x1000)),
    ("get_basic_blocks", lambda bridge: bridge.get_basic_blocks(0x1000)),
    ("get_slice", lambda bridge: bridge.get_slice(0x1000)),
    ("get_callers", lambda bridge: bridge.get_callers(0x1000)),
    ("get_register_value", lambda bridge: bridge.get_register_value(0x1000, "EAX")),
    ("set_register_value", lambda bridge: bridge.set_register_value(0x1000, 0x1003, "EAX", 5)),
    ("add_reference", lambda bridge: bridge.add_reference(0x1000, 0x2000)),
    ("delete_reference", lambda bridge: bridge.delete_reference(0x1000, 0x2000)),
    ("get_relocations", lambda bridge: bridge.get_relocations()),
    ("get_namespaces", lambda bridge: bridge.get_namespaces()),
]

_WRAPPED_CALLS: Final[list[tuple[str, _BridgeCall, str]]] = [
    ("set_data_type", lambda bridge: bridge.set_data_type(0x1000, "dword"), r"^Failed to set data type: Remote execution failed"),
    (
        "edit_function_signature",
        lambda bridge: bridge.edit_function_signature(0x1000, name="renamed"),
        r"^Edit function signature failed: Remote execution failed",
    ),
    (
        "set_function_flags",
        lambda bridge: bridge.set_function_flags(0x1000, no_return=True),
        r"^Set function flags failed: Remote execution failed",
    ),
    (
        "set_function_variable_type",
        lambda bridge: bridge.set_function_variable_type(0x1000, "var", "int"),
        r"^Set variable type failed: Remote execution failed",
    ),
    (
        "rename_function_variable",
        lambda bridge: bridge.rename_function_variable(0x1000, "old", "new"),
        r"^Rename variable failed: Remote execution failed",
    ),
    (
        "apply_structure_at",
        lambda bridge: bridge.apply_structure_at(0x1000, "S"),
        r"^Apply structure failed: Remote execution failed",
    ),
    ("undo", lambda bridge: bridge.undo(), r"^Undo failed: Remote execution failed"),
    ("redo", lambda bridge: bridge.redo(), r"^Redo failed: Remote execution failed"),
    (
        "create_namespace",
        lambda bridge: bridge.create_namespace("ns"),
        r"^Create namespace failed: Remote execution failed",
    ),
]

_UNCONNECTED_CALLS: Final[list[tuple[str, _BridgeCall]]] = [
    ("set_function_flags", lambda bridge: bridge.set_function_flags(0x1000, no_return=True)),
    ("rename_function_variable", lambda bridge: bridge.rename_function_variable(0x1000, "old", "new")),
    ("create_uninitialized_block", lambda bridge: bridge.create_uninitialized_block("blk", 0x1000, 0x10)),
    ("create_byte_mapped_block", lambda bridge: bridge.create_byte_mapped_block("blk", 0x1000, 0x2000, 0x10)),
    ("create_bit_mapped_block", lambda bridge: bridge.create_bit_mapped_block("blk", 0x1000, 0x2000, 0x10)),
    ("set_register_value", lambda bridge: bridge.set_register_value(0x1000, 0x1003, "EAX", 5)),
]

_UNEXPECTED_FAILURE_CASES: Final[list[tuple[str, _BridgeCall, str, str]]] = [
    ("set_label", lambda bridge: bridge.set_label(0x1000, "lbl"), "ghidra_set_label_failed", f"Set label failed: {_FAILURE_TEXT}"),
    ("get_labels", lambda bridge: bridge.get_labels(0x1000), "get_labels_failed", f"Get labels failed at 0x1000: {_FAILURE_TEXT}"),
    (
        "create_bookmark",
        lambda bridge: bridge.create_bookmark(0x1000, "cat", "text"),
        "ghidra_create_bookmark_failed",
        f"Create bookmark failed: {_FAILURE_TEXT}",
    ),
    ("get_bookmarks", lambda bridge: bridge.get_bookmarks(), "get_bookmarks_failed", f"Get bookmarks failed: {_FAILURE_TEXT}"),
    (
        "delete_function",
        lambda bridge: bridge.delete_function(0x1000),
        "ghidra_delete_function_failed",
        f"Delete function failed: {_FAILURE_TEXT}",
    ),
    ("get_structures", lambda bridge: bridge.get_structures(), "get_structures_failed", f"Get structures failed: {_FAILURE_TEXT}"),
    ("get_memory_map", lambda bridge: bridge.get_memory_map(), "get_memory_map_failed", f"Get memory map failed: {_FAILURE_TEXT}"),
    (
        "create_uninitialized_block",
        lambda bridge: bridge.create_uninitialized_block("blk", 0x1000, 0x10),
        "ghidra_create_uninitialized_block_failed",
        f"Create uninitialized block failed: {_FAILURE_TEXT}",
    ),
    (
        "create_byte_mapped_block",
        lambda bridge: bridge.create_byte_mapped_block("blk", 0x1000, 0x2000, 0x10),
        "ghidra_create_byte_mapped_block_failed",
        f"Create byte-mapped block failed: {_FAILURE_TEXT}",
    ),
    (
        "create_bit_mapped_block",
        lambda bridge: bridge.create_bit_mapped_block("blk", 0x1000, 0x2000, 0x10),
        "ghidra_create_bit_mapped_block_failed",
        f"Create bit-mapped block failed: {_FAILURE_TEXT}",
    ),
    (
        "get_call_graph",
        lambda bridge: bridge.get_call_graph(0x1000),
        "ghidra_get_call_graph_failed",
        f"Get call graph failed: {_FAILURE_TEXT}",
    ),
    ("get_segments", lambda bridge: bridge.get_segments(), "get_segments_failed", f"Get segments failed: {_FAILURE_TEXT}"),
    (
        "get_program_info",
        lambda bridge: bridge.get_program_info(),
        "get_program_info_failed",
        f"Get program info failed: {_FAILURE_TEXT}",
    ),
    (
        "write_bytes",
        lambda bridge: bridge.write_bytes(0x1000, "90"),
        "ghidra_write_bytes_failed",
        f"Write bytes failed: {_FAILURE_TEXT}",
    ),
    ("read_bytes", lambda bridge: bridge.read_bytes(0x1000, 4), "read_bytes_failed", f"Read bytes failed: {_FAILURE_TEXT}"),
    ("get_pcode", lambda bridge: bridge.get_pcode(0x1000), "get_pcode_failed", f"Get pcode failed at 0x1000: {_FAILURE_TEXT}"),
    (
        "get_basic_blocks",
        lambda bridge: bridge.get_basic_blocks(0x1000),
        "get_basic_blocks_failed",
        f"Get basic blocks failed at 0x1000: {_FAILURE_TEXT}",
    ),
    ("get_slice", lambda bridge: bridge.get_slice(0x1000), "get_slice_failed", f"Get slice failed at 0x1000: {_FAILURE_TEXT}"),
    ("get_callers", lambda bridge: bridge.get_callers(0x1000), "get_callers_failed", f"Get callers failed at 0x1000: {_FAILURE_TEXT}"),
    (
        "get_register_value",
        lambda bridge: bridge.get_register_value(0x1000, "EAX"),
        "get_register_value_failed",
        f"Get register value failed at 0x1000 for EAX: {_FAILURE_TEXT}",
    ),
    (
        "set_register_value",
        lambda bridge: bridge.set_register_value(0x1000, 0x1003, "EAX", 5),
        "ghidra_set_register_value_failed",
        f"Set register value failed for 'EAX': {_FAILURE_TEXT}",
    ),
    (
        "add_reference",
        lambda bridge: bridge.add_reference(0x1000, 0x2000),
        "ghidra_add_reference_failed",
        f"Add reference failed: {_FAILURE_TEXT}",
    ),
    (
        "delete_reference",
        lambda bridge: bridge.delete_reference(0x1000, 0x2000),
        "delete_reference_failed",
        f"Delete reference 0x1000 -> 0x2000 failed: {_FAILURE_TEXT}",
    ),
    (
        "get_relocations",
        lambda bridge: bridge.get_relocations(),
        "get_relocations_failed",
        f"Get relocations failed: {_FAILURE_TEXT}",
    ),
    ("get_namespaces", lambda bridge: bridge.get_namespaces(), "get_namespaces_failed", f"Get namespaces failed: {_FAILURE_TEXT}"),
]

_READBACK_CASES: Final[list[tuple[str, _BridgeCall, list[object], str, str]]] = [
    (
        "set_label",
        lambda bridge: bridge.set_label(0x1000, "lbl"),
        [None],
        "ghidra_set_label_readback_failed",
        f"Set label readback failed: {_FAILURE_TEXT}",
    ),
    (
        "create_bookmark",
        lambda bridge: bridge.create_bookmark(0x1000, "cat", "text"),
        [None],
        "ghidra_create_bookmark_readback_failed",
        f"Create bookmark readback failed: {_FAILURE_TEXT}",
    ),
    (
        "add_reference",
        lambda bridge: bridge.add_reference(0x1000, 0x2000),
        [None],
        "ghidra_add_reference_readback_failed",
        f"Add reference readback failed: {_FAILURE_TEXT}",
    ),
    (
        "set_register_value",
        lambda bridge: bridge.set_register_value(0x1000, 0x1003, "EAX", 5),
        [{"set": True, "reason": None}],
        "ghidra_set_register_value_readback_failed",
        f"Set register value readback failed for 'EAX': {_FAILURE_TEXT}",
    ),
]

_NO_PAYLOAD_CALLS: Final[list[tuple[str, _BridgeCall, str]]] = [
    ("read_bytes", lambda bridge: bridge.read_bytes(0x1000, 4), "Read bytes returned no payload at 0x1000"),
    ("get_pcode", lambda bridge: bridge.get_pcode(0x1000), "Get pcode returned no payload at 0x1000"),
    ("get_basic_blocks", lambda bridge: bridge.get_basic_blocks(0x1000), "Get basic blocks returned no payload at 0x1000"),
    ("get_slice", lambda bridge: bridge.get_slice(0x1000), "Get slice returned no payload at 0x1000"),
    ("get_register_value", lambda bridge: bridge.get_register_value(0x1000, "EAX"), "Get register value returned no payload at 0x1000"),
]


@dataclass(frozen=True)
class _PeFacts:
    """Header facts of a PE file, read with ``pefile`` independently of Ghidra.

    Attributes:
        image_base: The preferred load address from the optional header.
        size_of_image: Size in memory of the whole mapped image.
        entry_point: Absolute address of the entry point.
    """

    image_base: int
    size_of_image: int
    entry_point: int


class _ScriptedBridge(GhidraBridge):
    """Real Ghidra bridge whose remote exchange replays scripted outcomes.

    Only ``_execute_remote`` and ``_execute_remote_eval`` are replaced. Each call
    takes the next outcome from its queue: an exception instance is raised, any
    other value is returned. Every accessor around the exchange runs unchanged.
    """

    def __init__(self, exec_outcomes: Sequence[object] = (), eval_outcomes: Sequence[object] = ()) -> None:
        """Create a bridge that is attached to a placeholder client and scripted.

        Args:
            exec_outcomes: Outcomes for successive ``_execute_remote`` calls.
            eval_outcomes: Outcomes for successive ``_execute_remote_eval`` calls.
        """
        super().__init__()
        self._scripted_exec: list[object] = list(exec_outcomes)
        self._scripted_eval: list[object] = list(eval_outcomes)
        self.attach_remote_bridge(types.SimpleNamespace())

    async def _execute_remote(self, code: str) -> object:
        """Replay the next scripted outcome instead of running ``code`` remotely.

        Args:
            code: Jython source the accessor would have dispatched.

        Returns:
            object: The next scripted value.
        """
        del code
        return _replay(self._scripted_exec)

    async def _execute_remote_eval(self, expression: str) -> object:
        """Replay the next scripted outcome instead of evaluating ``expression``.

        Args:
            expression: Jython expression the accessor would have evaluated.

        Returns:
            object: The next scripted value.
        """
        del expression
        return _replay(self._scripted_eval)


def _replay(queue: list[object]) -> object:
    """Take the next outcome from a scripted queue, raising it when it is an exception.

    Args:
        queue: Remaining outcomes, consumed from the front.

    Returns:
        object: The next scripted value.

    Raises:
        outcome: The scripted exception instance, when the next outcome is one.
    """
    outcome = queue.pop(0)
    if isinstance(outcome, BaseException):
        raise outcome
    return outcome


def _failure() -> RuntimeError:
    """Build the unexpected error that scripted transports raise.

    Returns:
        RuntimeError: A fresh error carrying the shared failure text.
    """
    return RuntimeError(_FAILURE_TEXT)


def _async_method(obj: object, name: str) -> Callable[..., Awaitable[object]]:
    """Resolve a (possibly private) coroutine method by name.

    Args:
        obj: Instance that owns the attribute.
        name: Attribute name to look up.

    Returns:
        Callable[..., Awaitable[object]]: The bound coroutine function.
    """
    return cast("Callable[..., Awaitable[object]]", getattr(obj, name))


def _close_client(client: object) -> None:
    """Close the socket and communications thread of a real RPC client.

    Args:
        client: The ``ghidra_bridge`` client to close.
    """
    cast("Callable[[object], None]", getattr(GhidraBridge, "_close_bridge_client"))(client)


def _events_named(events: Sequence[Mapping[str, object]], name: str) -> list[Mapping[str, object]]:
    """Filter captured structlog events by event name.

    Args:
        events: Events captured with ``structlog.testing.capture_logs``.
        name: Event name to keep.

    Returns:
        list[Mapping[str, object]]: The matching events in emission order.
    """
    return [event for event in events if event.get("event") == name]


def _reserve_free_port() -> int:
    """Reserve an ephemeral loopback TCP port and release it immediately.

    Returns:
        int: A port that nothing listens on at the moment of the call.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def _make_rpc_client(port: int) -> object:
    """Build a real, lazy ``ghidra_bridge`` RPC client for a loopback port.

    Args:
        port: Loopback TCP port the client would connect to on first use.

    Returns:
        object: The ``ghidra_bridge.GhidraBridge`` client instance.
    """
    module = importlib.import_module("ghidra_bridge")
    factory = cast("Callable[..., object]", getattr(module, "GhidraBridge"))
    return factory(namespace=None, connect_to_host="127.0.0.1", connect_to_port=port, response_timeout=5)


def _read_pe_facts(path: Path) -> _PeFacts:
    """Read the load address, image size and entry point of a PE file.

    Args:
        path: PE file to parse.

    Returns:
        _PeFacts: The header facts, with the entry point as an absolute address.
    """
    parsed = pefile.PE(data=path.read_bytes(), fast_load=True)
    try:
        image_base = int(parsed.OPTIONAL_HEADER.ImageBase)
        return _PeFacts(
            image_base=image_base,
            size_of_image=int(parsed.OPTIONAL_HEADER.SizeOfImage),
            entry_point=image_base + int(parsed.OPTIONAL_HEADER.AddressOfEntryPoint),
        )
    finally:
        parsed.close()


@pytest.fixture(scope="module")
def dead_rpc_client() -> Iterator[object]:
    """Provide a real ``ghidra_bridge`` client aimed at a closed loopback port.

    Every remote call made through it fails with a socket error, which the
    bridge must surface as a ``ToolError``.

    Yields:
        object: The RPC client instance.
    """
    client = _make_rpc_client(_reserve_free_port())
    try:
        yield client
    finally:
        _close_client(client)


@pytest.fixture
def dead_bridge(dead_rpc_client: object) -> GhidraBridge:
    """Provide a bridge whose RPC peer is unreachable.

    Args:
        dead_rpc_client: Real RPC client pointed at a closed port.

    Returns:
        GhidraBridge: A fresh bridge attached to the dead client.
    """
    bridge = GhidraBridge()
    bridge.attach_remote_bridge(dead_rpc_client)
    return bridge


@pytest.fixture(scope="module")
def live_target(real_pe_exe: Path, tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    """Copy a System32 executable to a private directory for Ghidra to import.

    Args:
        real_pe_exe: Real PE executable resolved from System32.
        tmp_path_factory: Pytest factory for the private directory.

    Yields:
        Path: The private copy; the System32 original is never touched.
    """
    directory = tmp_path_factory.mktemp("critcov_ghidra_02_binary")
    target = directory / "critcov_target.exe"
    shutil.copyfile(real_pe_exe, target)
    try:
        yield target
    finally:
        shutil.rmtree(directory, ignore_errors=True)


@pytest.fixture(scope="module")
def pe_facts(live_target: Path) -> _PeFacts:
    """Read the header facts of the imported copy with ``pefile``.

    Args:
        live_target: The executable copy Ghidra imports.

    Returns:
        _PeFacts: Independent facts about the program the live session holds.
    """
    return _read_pe_facts(live_target)


@pytest.fixture(scope="module")
def live_session(live_target: Path, tmp_path_factory: pytest.TempPathFactory) -> Iterator[GhidraBridge]:
    """Start one headless Ghidra session on the private executable copy.

    The session is shut down and its project directory removed in ``finally``
    even when the start fails halfway.

    Args:
        live_target: The executable copy to import.
        tmp_path_factory: Pytest factory for the Ghidra project directory.

    Yields:
        GhidraBridge: A connected bridge with ``live_target`` imported.
    """
    install_text = os.environ.get("GHIDRA_INSTALL_DIR", "").strip()
    if not install_text:
        pytest.fail("GHIDRA_INSTALL_DIR is not set, so the container does not name a Ghidra installation", pytrace=False)
    bridge = GhidraBridge()
    bridge.set_port(_reserve_free_port())
    bridge.ghidra_path = Path(install_text)
    project_dir = tmp_path_factory.mktemp("critcov_ghidra_02_project")
    try:
        try:
            asyncio.run(asyncio.wait_for(bridge.start_headless(project_dir, "critcov_ghidra_02"), timeout=_LIVE_STEP_TIMEOUT_SECONDS))
            asyncio.run(asyncio.wait_for(bridge.load_binary(live_target), timeout=_LIVE_STEP_TIMEOUT_SECONDS))
        except (ToolError, OSError) as exc:
            pytest.fail(
                f"Headless Ghidra could not start or import {live_target} inside this container "
                f"(install {install_text}): {type(exc).__name__}: {exc}",
                pytrace=False,
            )
        yield bridge
    finally:
        try:
            asyncio.run(bridge.shutdown())
        finally:
            shutil.rmtree(project_dir, ignore_errors=True)


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "call"), _PASSTHROUGH_CALLS, ids=[name for name, _ in _PASSTHROUGH_CALLS])
async def test_dead_peer_failure_surfaces_unchanged_from_the_accessor(dead_bridge: GhidraBridge, name: str, call: _BridgeCall) -> None:
    """A vanished Ghidra peer surfaces as the transport's own ``ToolError``, not a re-wrapped one.

    The message must start with the transport-level text, and the error's cause
    must be the socket failure rather than another ``ToolError``; a handler that
    wrapped the already-typed error would prefix it with the accessor's wording.

    Args:
        dead_bridge: Bridge whose RPC peer is unreachable.
        name: Accessor name, used for the test id.
        call: Coroutine factory invoking the accessor on ``dead_bridge``.
    """
    with pytest.raises(ToolError, match=_REMOTE_FAILURE_PATTERN) as excinfo:
        await call(dead_bridge)

    assert not isinstance(excinfo.value.__cause__, ToolError), name


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "call", "pattern"), _WRAPPED_CALLS, ids=[name for name, _, _ in _WRAPPED_CALLS])
async def test_dead_peer_failure_is_wrapped_with_the_accessor_context(
    dead_bridge: GhidraBridge,
    name: str,
    call: _BridgeCall,
    pattern: str,
) -> None:
    """Accessors that catch every error prefix the transport failure with their own wording.

    Args:
        dead_bridge: Bridge whose RPC peer is unreachable.
        name: Accessor name, used for the test id.
        call: Coroutine factory invoking the accessor on ``dead_bridge``.
        pattern: Regular expression the wrapped message must match.
    """
    with pytest.raises(ToolError, match=pattern) as excinfo:
        await call(dead_bridge)

    assert isinstance(excinfo.value.__cause__, ToolError), name
    assert str(excinfo.value.__cause__).startswith("Remote execution failed")


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "call"), _UNCONNECTED_CALLS, ids=[name for name, _ in _UNCONNECTED_CALLS])
async def test_accessor_refuses_to_run_without_a_connection(name: str, call: _BridgeCall) -> None:
    """The accessors fail fast with the standard not-connected error on a bridge with no client.

    Args:
        name: Accessor name, used for the test id.
        call: Coroutine factory invoking the accessor on a fresh bridge.
    """
    bridge = GhidraBridge()

    with pytest.raises(ToolError, match=_NOT_CONNECTED_PATTERN):
        await call(bridge)

    assert bridge.state.connected is False, name


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("name", "call", "event", "message"),
    _UNEXPECTED_FAILURE_CASES,
    ids=[case[0] for case in _UNEXPECTED_FAILURE_CASES],
)
async def test_unexpected_remote_error_is_wrapped_logged_and_chained(name: str, call: _BridgeCall, event: str, message: str) -> None:
    """A non-``ToolError`` raised by the remote exchange is logged and re-raised as a ``ToolError``.

    Args:
        name: Accessor name, used for the test id.
        call: Coroutine factory invoking the accessor on the scripted bridge.
        event: Structured log event the failure path must emit.
        message: Exact ``ToolError`` text the accessor must produce.
    """
    bridge = _ScriptedBridge(exec_outcomes=[_failure()])

    with capture_logs() as events, pytest.raises(ToolError) as excinfo:
        await call(bridge)

    assert str(excinfo.value) == message, name
    assert isinstance(excinfo.value.__cause__, RuntimeError)
    assert str(excinfo.value.__cause__) == _FAILURE_TEXT
    assert len(_events_named(events, event)) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("name", "call", "exec_outcomes", "event", "message"),
    _READBACK_CASES,
    ids=[case[0] for case in _READBACK_CASES],
)
async def test_unexpected_readback_error_is_wrapped_logged_and_chained(
    name: str,
    call: _BridgeCall,
    exec_outcomes: list[object],
    event: str,
    message: str,
) -> None:
    """A non-``ToolError`` raised by the verification readback is logged and wrapped.

    Args:
        name: Accessor name, used for the test id.
        call: Coroutine factory invoking the accessor on the scripted bridge.
        exec_outcomes: Outcomes that let the write step succeed.
        event: Structured log event the readback failure path must emit.
        message: Exact ``ToolError`` text the accessor must produce.
    """
    bridge = _ScriptedBridge(exec_outcomes=exec_outcomes, eval_outcomes=[_failure()])

    with capture_logs() as events, pytest.raises(ToolError) as excinfo:
        await call(bridge)

    assert str(excinfo.value) == message, name
    assert isinstance(excinfo.value.__cause__, RuntimeError)
    assert len(_events_named(events, event)) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("name", "call", "exec_outcomes"),
    [(case[0], case[1], case[2]) for case in _READBACK_CASES],
    ids=[case[0] for case in _READBACK_CASES],
)
async def test_readback_tool_error_propagates_without_rewrapping(name: str, call: _BridgeCall, exec_outcomes: list[object]) -> None:
    """A ``ToolError`` from the verification readback reaches the caller as the very same object.

    Args:
        name: Accessor name, used for the test id.
        call: Coroutine factory invoking the accessor on the scripted bridge.
        exec_outcomes: Outcomes that let the write step succeed.
    """
    failure = ToolError("scripted readback tool error")
    bridge = _ScriptedBridge(exec_outcomes=exec_outcomes, eval_outcomes=[failure])

    with pytest.raises(ToolError) as excinfo:
        await call(bridge)

    assert excinfo.value is failure, name


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "call", "message"), _NO_PAYLOAD_CALLS, ids=[name for name, _, _ in _NO_PAYLOAD_CALLS])
async def test_accessor_rejects_a_remote_result_that_is_not_a_payload_dict(name: str, call: _BridgeCall, message: str) -> None:
    """A remote result that is not a dict is reported as a missing payload instead of being returned.

    Args:
        name: Accessor name, used for the test id.
        call: Coroutine factory invoking the accessor on the scripted bridge.
        message: Exact ``ToolError`` text the accessor must produce.
    """
    bridge = _ScriptedBridge(exec_outcomes=[None])

    with pytest.raises(ToolError) as excinfo:
        await call(bridge)

    assert str(excinfo.value) == message, name


@pytest.mark.asyncio
async def test_create_bookmark_skips_readback_entries_that_are_not_category_comment_pairs() -> None:
    """Readback entries that are not sequences, or are too short, are ignored; the real pair still verifies."""
    bridge = _ScriptedBridge(exec_outcomes=[None], eval_outcomes=[[123, ("only-one",), ["cat", "text"], ("other", "note")]])

    result = await bridge.create_bookmark(0x1000, "cat", "text")

    assert result == {"address": "0x1000", "category": "cat", "comment": "text", "bookmark_type": "Note", "success": True}


@pytest.mark.asyncio
async def test_create_bookmark_rejects_a_readback_that_is_not_a_list() -> None:
    """A readback that is not a list yields no pairs, so the bookmark cannot be verified."""
    bridge = _ScriptedBridge(exec_outcomes=[None], eval_outcomes=[None])

    with pytest.raises(ToolError) as excinfo:
        await bridge.create_bookmark(0x1000, "cat", "text")

    assert str(excinfo.value) == "Bookmark verification failed at 0x1000: ('cat', 'text') not in []"


@pytest.mark.asyncio
async def test_add_reference_ignores_readback_offsets_that_are_not_integers() -> None:
    """Offsets that cannot be converted to integers are skipped; the real target still verifies."""
    bridge = _ScriptedBridge(exec_outcomes=[None], eval_outcomes=[[None, "not-a-number", 0x2000]])

    result = await bridge.add_reference(0x1000, 0x2000)

    assert result == {"from": "0x1000", "to": "0x2000", "type": "DATA", "success": True}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("readback", "observed"),
    [(None, "[]"), ([None, "not-a-number", 0x3000], "['0x3000']")],
    ids=["not-a-list", "unparsable-offsets-skipped"],
)
async def test_add_reference_rejects_a_readback_without_the_requested_target(readback: object, observed: str) -> None:
    """A readback that does not contain the target fails verification and lists only the usable targets.

    Args:
        readback: Scripted answer to the readback expression.
        observed: Rendering of the usable targets the error must report.
    """
    bridge = _ScriptedBridge(exec_outcomes=[None], eval_outcomes=[readback])

    with pytest.raises(ToolError) as excinfo:
        await bridge.add_reference(0x1000, 0x2000)

    assert str(excinfo.value) == f"Reference verification failed: 0x1000 -> 0x2000 not present in {observed}"


@pytest.mark.asyncio
async def test_delete_function_reports_a_removal_that_ghidra_refused() -> None:
    """A function that exists but is not removed is reported as a refused removal."""
    bridge = _ScriptedBridge(exec_outcomes=[{"exists": True, "name": "sub_1000", "removed": False}])

    with pytest.raises(ToolError) as excinfo:
        await bridge.delete_function(0x1000)

    assert str(excinfo.value) == "Delete function failed: Ghidra refused removal at 0x1000"


@pytest.mark.asyncio
async def test_define_structure_returns_the_payload_ghidra_produced() -> None:
    """A truthy remote result is returned to the caller unchanged."""
    payload = {"name": "S", "size": 5, "field_count": 2}
    bridge = _ScriptedBridge(exec_outcomes=[payload])

    result = await bridge.define_structure("S", [{"name": "a", "type": "dword", "size": 4}])

    assert result == payload


@pytest.mark.asyncio
@pytest.mark.parametrize("empty", [None, {}], ids=["none", "empty-dict"])
async def test_define_structure_reports_failure_when_ghidra_returns_nothing(empty: object) -> None:
    """An empty remote result becomes an explicit unsuccessful result carrying the requested name.

    Args:
        empty: Falsy scripted result.
    """
    bridge = _ScriptedBridge(exec_outcomes=[empty])

    result = await bridge.define_structure("S", [{"name": "a", "type": "dword", "size": 4}])

    assert result == {"name": "S", "success": False}


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", [None, {"name": None, "success": False}], ids=["no-payload", "unsuccessful"])
async def test_byte_and_bit_mapped_blocks_report_an_unsuccessful_creation(outcome: object) -> None:
    """A creation result that is not a successful dict is reported as a failure naming the block.

    Args:
        outcome: Scripted remote result that does not report success.
    """
    byte_bridge = _ScriptedBridge(exec_outcomes=[outcome])
    bit_bridge = _ScriptedBridge(exec_outcomes=[outcome])

    with pytest.raises(ToolError) as byte_error:
        await byte_bridge.create_byte_mapped_block("blk", 0x1000, 0x2000, 0x10)
    with pytest.raises(ToolError) as bit_error:
        await bit_bridge.create_bit_mapped_block("blk", 0x1000, 0x2000, 0x10)

    assert str(byte_error.value) == "Create byte-mapped block failed: 'blk'"
    assert str(bit_error.value) == "Create bit-mapped block failed: 'blk'"


@pytest.mark.asyncio
async def test_write_bytes_rejects_a_payload_that_is_not_hexadecimal() -> None:
    """An even-length payload with non-hex digits is rejected with the parser's own explanation."""
    with pytest.raises(ValueError, match="invalid literal") as oracle:
        _ = int("zz", 16)
    bridge = _ScriptedBridge()

    with capture_logs() as events, pytest.raises(ToolError) as excinfo:
        await bridge.write_bytes(0x1000, "zz")

    assert str(excinfo.value) == f"Invalid hex payload: {oracle.value}"
    assert isinstance(excinfo.value.__cause__, ValueError)
    rejected = _events_named(events, "ghidra_write_bytes_invalid_hex")
    assert len(rejected) == 1
    assert rejected[0]["error"] == str(oracle.value)


@pytest.mark.asyncio
async def test_write_bytes_reports_the_error_ghidra_returned_for_the_write() -> None:
    """A write error carried in the remote result becomes a ``ToolError`` with that text."""
    bridge = _ScriptedBridge(exec_outcomes=[{"write_error": "denied by scripted memory", "readback_bytes": []}])

    with pytest.raises(ToolError) as excinfo:
        await bridge.write_bytes(0x1000, "90")

    assert str(excinfo.value) == "Write bytes failed: denied by scripted memory"


@pytest.mark.asyncio
@pytest.mark.parametrize("extension", _DWARF_EXTENSIONS)
async def test_import_debug_info_classifies_dwarf_bearing_extensions(tmp_path: Path, extension: str) -> None:
    """Every DWARF-bearing extension is dispatched as a ``dwarf`` import.

    Args:
        tmp_path: Pytest temporary directory holding the symbol file.
        extension: File extension the symbol file carries.
    """
    symbol_file = tmp_path / f"symbols{extension}"
    symbol_file.write_bytes(b"debug")
    bridge = _ScriptedBridge(exec_outcomes=[{"success": True}])

    response = await bridge.import_debug_info(str(symbol_file))

    assert response["type"] == "dwarf"
    assert response["success"] is True
    assert response["path"] == str(symbol_file)
    assert isinstance(response["analyzer"], str)
    assert not response["analyzer"]
    assert response["error"] is None


@pytest.mark.asyncio
async def test_import_debug_info_surfaces_a_tool_error_from_the_remote_exchange(tmp_path: Path, dead_bridge: GhidraBridge) -> None:
    """A transport failure during the import is re-raised as the transport's own ``ToolError``.

    Args:
        tmp_path: Pytest temporary directory holding the symbol file.
        dead_bridge: Bridge whose RPC peer is unreachable.
    """
    symbol_file = tmp_path / "symbols.debug"
    symbol_file.write_bytes(b"debug")

    with pytest.raises(ToolError, match=_REMOTE_FAILURE_PATTERN) as excinfo:
        await dead_bridge.import_debug_info(str(symbol_file))

    assert not isinstance(excinfo.value.__cause__, ToolError)


@pytest.mark.asyncio
async def test_import_debug_info_wraps_an_unexpected_remote_error(tmp_path: Path) -> None:
    """A non-``ToolError`` raised during the import is logged and wrapped with the import wording.

    Args:
        tmp_path: Pytest temporary directory holding the symbol file.
    """
    symbol_file = tmp_path / "symbols.pdb"
    symbol_file.write_bytes(b"debug")
    bridge = _ScriptedBridge(exec_outcomes=[_failure()])

    with capture_logs() as events, pytest.raises(ToolError) as excinfo:
        await bridge.import_debug_info(str(symbol_file))

    assert str(excinfo.value) == f"Debug info import failed: {_FAILURE_TEXT}"
    assert isinstance(excinfo.value.__cause__, RuntimeError)
    failures = _events_named(events, "ghidra_import_debug_info_failed")
    assert len(failures) == 1
    assert failures[0]["path"] == str(symbol_file)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("outcome", "expected"),
    [
        ({"success": False, "error": "no dwarf sections"}, "Debug info import failed: no dwarf sections"),
        ({"success": False}, "Debug info import failed: unknown error"),
        ({"success": False, "error": ""}, "Debug info import failed: unknown error"),
        (None, "Debug info import failed: unknown error"),
    ],
    ids=["reported-error", "no-error-key", "empty-error", "no-payload"],
)
async def test_import_debug_info_reports_an_unsuccessful_import(tmp_path: Path, outcome: object, expected: str) -> None:
    """An import that does not report success fails with Ghidra's error text or a generic one.

    Args:
        tmp_path: Pytest temporary directory holding the symbol file.
        outcome: Scripted remote result that does not report success.
        expected: Exact ``ToolError`` text the import must produce.
    """
    symbol_file = tmp_path / "symbols.pdb"
    symbol_file.write_bytes(b"debug")
    bridge = _ScriptedBridge(exec_outcomes=[outcome])

    with pytest.raises(ToolError) as excinfo:
        await bridge.import_debug_info(str(symbol_file))

    assert str(excinfo.value) == expected


@pytest.mark.asyncio
async def test_execute_remote_reports_a_client_without_remote_exec() -> None:
    """An attached client that offers no ``remote_exec`` is refused before any script is sent."""
    bridge = GhidraBridge()
    bridge.attach_remote_bridge(object())

    with pytest.raises(ToolError, match=r"^Ghidra bridge missing remote_exec$"):
        await bridge.execute_script("6 * 7")


@pytest.mark.asyncio
async def test_execute_remote_reports_a_client_without_remote_eval() -> None:
    """An attached client that offers ``remote_exec`` but no ``remote_eval`` is refused."""
    bridge = GhidraBridge()
    bridge.attach_remote_bridge(types.SimpleNamespace(remote_exec=str))

    with pytest.raises(ToolError, match=r"^Ghidra bridge missing remote_eval$"):
        await bridge.execute_script("6 * 7")


@pytest.mark.asyncio
async def test_execute_remote_eval_requires_a_connection() -> None:
    """The evaluation primitive refuses to run on a bridge with no client."""
    bridge = GhidraBridge()

    with pytest.raises(ToolError, match=_NOT_CONNECTED_PATTERN):
        await _async_method(bridge, "_execute_remote_eval")("1 + 1")


@pytest.mark.asyncio
async def test_execute_remote_eval_reports_a_client_without_remote_eval() -> None:
    """The evaluation primitive refuses a client that offers no ``remote_eval``."""
    bridge = GhidraBridge()
    bridge.attach_remote_bridge(object())

    with pytest.raises(ToolError, match=r"^Ghidra bridge missing remote_eval$"):
        await _async_method(bridge, "_execute_remote_eval")("1 + 1")


@pytest.mark.asyncio
async def test_execute_remote_eval_wraps_a_transport_failure(dead_bridge: GhidraBridge) -> None:
    """A failing evaluation is logged and re-raised as a ``ToolError`` that chains the cause.

    Args:
        dead_bridge: Bridge whose RPC peer is unreachable.
    """
    with capture_logs() as events, pytest.raises(ToolError, match=r"^Remote eval failed: ") as excinfo:
        await _async_method(dead_bridge, "_execute_remote_eval")("1 + 1")

    assert excinfo.value.__cause__ is not None
    assert not isinstance(excinfo.value.__cause__, ToolError)
    assert len(_events_named(events, "ghidra_remote_eval_failed")) == 1


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_live_get_labels_reports_the_entry_point_symbol_inside_the_window(live_session: GhidraBridge, pe_facts: _PeFacts) -> None:
    """Ghidra's own symbol at the PE entry point is returned, and nothing outside the radius is.

    The entry point address comes from the PE optional header read with
    ``pefile``, not from Ghidra.

    Args:
        live_session: Connected headless Ghidra bridge.
        pe_facts: Header facts of the imported executable.
    """
    radius = 0x40

    labels = await live_session.get_labels(pe_facts.entry_point, radius)

    assert pe_facts.entry_point in [label["address"] for label in labels]
    for label in labels:
        assert isinstance(label["name"], str)
        assert label["name"]
        assert pe_facts.entry_point - radius <= label["address"] <= pe_facts.entry_point + radius


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_live_edit_function_signature_reports_no_function_in_the_pe_header(live_session: GhidraBridge, pe_facts: _PeFacts) -> None:
    """The image base holds the PE header, where no function exists, so the edit is refused.

    Args:
        live_session: Connected headless Ghidra bridge.
        pe_facts: Header facts of the imported executable.
    """
    with pytest.raises(ToolError) as excinfo:
        await live_session.edit_function_signature(pe_facts.image_base, return_type="int", name="critcov_renamed")

    assert str(excinfo.value) == f"No function at {hex(pe_facts.image_base)}"


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_live_write_bytes_into_unmapped_memory_reports_ghidras_error(live_session: GhidraBridge, pe_facts: _PeFacts) -> None:
    """Writing past the end of the mapped image fails inside Ghidra and the error text is relayed.

    The target lies a fixed distance beyond ``ImageBase + SizeOfImage`` from the
    PE header, so no memory block of the program can cover it.

    Args:
        live_session: Connected headless Ghidra bridge.
        pe_facts: Header facts of the imported executable.
    """
    unmapped = pe_facts.image_base + pe_facts.size_of_image + 0x10000
    prefix = "Write bytes failed: "

    with pytest.raises(ToolError) as excinfo:
        await live_session.write_bytes(unmapped, "90 90")

    message = str(excinfo.value)
    assert message.startswith(prefix)
    assert message[len(prefix) :].strip()


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_live_result_the_wire_cannot_encode_is_a_remote_evaluation_failure(live_session: GhidraBridge) -> None:
    """A trailing value that the bridge server cannot serialize fails the readback and is reported.

    A lone surrogate cannot be encoded as UTF-8, so the server answers the
    evaluation of the result variable with an error even though the script
    itself ran. The session must stay usable afterwards.

    Args:
        live_session: Connected headless Ghidra bridge.
    """
    with capture_logs() as events, pytest.raises(ToolError, match=r"^Remote evaluation failed: "):
        await live_session.execute_script(_UNENCODABLE_RESULT_SCRIPT)

    failures = _events_named(events, "ghidra_remote_eval_failed")
    assert len(failures) == 1
    assert re.fullmatch(re.escape(_SENTINEL_PREFIX) + r"\d+", str(failures[0]["sentinel"]))
    assert await live_session.execute_script("6 * 7") == "42"


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_live_define_structure_creates_a_structure_with_the_summed_field_sizes(live_session: GhidraBridge) -> None:
    """A structure of a four-byte and a one-byte field is five bytes long with two components.

    The expectation is plain arithmetic over the requested field sizes. The
    structure is then listed by name to prove it persists in the program.

    Args:
        live_session: Connected headless Ghidra bridge.
    """
    name = "critcov_struct"
    fields = [{"name": "first", "type": "dword", "size": 4}, {"name": "second", "type": "byte", "size": 1}]

    created = await live_session.define_structure(name, fields)
    listed = await live_session.get_structures(name)

    assert created["name"] == name
    assert created["size"] == 4 + 1
    assert created["field_count"] == len(fields)
    matching = [entry for entry in listed if entry["name"] == name]
    assert len(matching) == 1
    assert matching[0]["size"] == 4 + 1
    assert matching[0]["field_count"] == len(fields)
