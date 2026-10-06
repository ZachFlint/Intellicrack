# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-object coverage for the third slice of ``intellicrack.bridges.ghidra``.

The slice is the error handling that surrounds the remote calls of the analysis
and editing accessors: the not-connected guards, the ``except ToolError: raise``
and ``except Exception`` wrappers, the "no payload" and "flag not set" checks on
the dict Ghidra hands back, the decompiler-option merge, and the headless batch
launcher.

Two kinds of real object drive it:

* a ``GhidraBridge`` subclass whose remote script and remote eval exchanges
  replay one chosen outcome (a returned value or a raised exception), attached
  to a genuine, never-connected ``ghidra_bridge`` RPC client; every other line
  of the bridge under test is the production code;
* one module-scoped headless Ghidra session on a copy of a System32 binary,
  started once through PyGhidra and shut down in ``finally``, for the checks
  that need a program Ghidra really loaded.
"""

from __future__ import annotations

import asyncio
import importlib
import os
import shutil
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

import pefile
import pytest

from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.core.types import BinaryInfo, ToolError


if TYPE_CHECKING:
    from collections.abc import Iterator


pytestmark = pytest.mark.spawns_process

_LIVE_STEP_TIMEOUT_SECONDS: Final[float] = 600.0
_SCRIPTED_FAILURE_TEXT: Final[str] = "scripted failure"
_NOT_CONNECTED: Final[str] = "Ghidra not connected"
_MISSING_BLOCK: Final[str] = "critcov_missing_block"
_MISSING_TREE: Final[str] = "critcov_missing_tree"
_EQUATE_NAME: Final[str] = "CRITCOV_EQUATE"
_EQUATE_VALUE: Final[int] = 0x1337
_BLOCK_NAMES_SCRIPT: Final[str] = '"|".join(sorted(str(block.getName()) for block in currentProgram.getMemory().getBlocks()))'
_TREE_NAMES_SCRIPT: Final[str] = '"|".join(sorted(str(name) for name in currentProgram.getListing().getTreeNames()))'
_EQUATE_VALUE_SCRIPT: Final[str] = f'int(currentProgram.getEquateTable().getEquate("{_EQUATE_NAME}").getValue())'
_EQUATE_REFS_SCRIPT: Final[str] = (
    '"|".join(str(ref.getAddress().getOffset()) for ref in currentProgram.getEquateTable().getEquate("'
    + _EQUATE_NAME
    + '").getReferences())'
)

_Call = Callable[[GhidraBridge, Path], Awaitable[object]]

_WRAPPED_FAILURES: Final[list[tuple[str, _Call, str]]] = [
    ("create_equate", lambda bridge, _header: bridge.create_equate(0x1000, 5, "EQ"), "Create equate failed"),
    ("get_equates", lambda bridge, _header: bridge.get_equates(), "Get equates failed"),
    ("search_symbols", lambda bridge, _header: bridge.search_symbols("main"), "Search symbols failed for 'main'"),
    ("get_stack_frame", lambda bridge, _header: bridge.get_stack_frame(0x1000), "Get stack frame failed at 0x1000"),
    (
        "assign_fragment_range",
        lambda bridge, _header: bridge.assign_fragment_range("Tree", "Frag", 0x1000, 0x1FFF),
        "Assign fragment range failed",
    ),
    ("get_function_body", lambda bridge, _header: bridge.get_function_body(0x1000), "Get function body failed at 0x1000"),
    ("get_call_tree", lambda bridge, _header: bridge.get_call_tree(0x1000), "Get call tree failed at 0x1000"),
    ("get_calling_conventions", lambda bridge, _header: bridge.get_calling_conventions(), "Get calling conventions failed"),
    ("get_instruction_flow", lambda bridge, _header: bridge.get_instruction_flow(0x1000), "Get instruction flow failed at 0x1000"),
    ("get_instruction_pcode", lambda bridge, _header: bridge.get_instruction_pcode(0x1000), "Get instruction pcode failed at 0x1000"),
    ("disassemble_range", lambda bridge, _header: bridge.disassemble_range(0x1000, 0x1010), "Disassemble range failed"),
    ("clear_code_bytes", lambda bridge, _header: bridge.clear_code_bytes(0x1000, 0x1010), "Clear code bytes failed"),
    ("create_data_type", lambda bridge, _header: bridge.create_data_type("/Cat", "Name", "enum"), "Create data type failed"),
    ("get_data_type_tree", lambda bridge, _header: bridge.get_data_type_tree("/Cat"), "Get data type tree failed"),
    ("import_c_header", lambda bridge, header: bridge.import_c_header(str(header)), "C header import failed"),
    (
        "export_data_type_archive",
        lambda bridge, _header: bridge.export_data_type_archive("types.gdt"),
        "Export data type archive failed",
    ),
    (
        "import_data_type_archive",
        lambda bridge, _header: bridge.import_data_type_archive("types.gdt"),
        "Import data type archive failed",
    ),
    ("create_data", lambda bridge, _header: bridge.create_data(0x1000, "dword"), "Create data failed"),
    ("configure_analysis", lambda bridge, _header: bridge.configure_analysis("Analyzer", enabled=True), "Configure analysis failed"),
    (
        "set_decompiler_options",
        lambda bridge, _header: bridge.set_decompiler_options(extra={"key": "value"}),
        "Set decompiler options failed",
    ),
    ("create_memory_block", lambda bridge, _header: bridge.create_memory_block("blk", 0x1000, 0x10), "Create memory block failed"),
    ("remove_memory_block", lambda bridge, _header: bridge.remove_memory_block("blk"), "Remove memory block failed"),
    ("split_memory_block", lambda bridge, _header: bridge.split_memory_block("blk", 0x2000), "Split memory block failed"),
    ("move_memory_block", lambda bridge, _header: bridge.move_memory_block("blk", 0x3000), "Move memory block failed"),
    ("rename_memory_block", lambda bridge, _header: bridge.rename_memory_block("blk", "new"), "Rename memory block failed"),
    (
        "set_memory_block_comment",
        lambda bridge, _header: bridge.set_memory_block_comment("blk", "text"),
        "Set memory block comment failed",
    ),
    ("join_memory_blocks", lambda bridge, _header: bridge.join_memory_blocks("a", "b"), "Join memory blocks failed"),
    ("get_comments", lambda bridge, _header: bridge.get_comments(0x1000), "Get comments failed at 0x1000"),
    ("get_all_comments", lambda bridge, _header: bridge.get_all_comments(), "Get all comments failed"),
    ("create_program_tree", lambda bridge, _header: bridge.create_program_tree("Tree"), "Create program tree failed"),
    ("get_program_tree", lambda bridge, _header: bridge.get_program_tree(), "Get program tree failed"),
    (
        "edit_program_tree",
        lambda bridge, _header: bridge.edit_program_tree("Tree", "create_module", "Parent", "Child"),
        "Edit program tree failed",
    ),
    ("get_properties", lambda bridge, _header: bridge.get_properties(0x1000), "Get properties failed at 0x1000"),
    ("diff_programs", lambda bridge, _header: bridge.diff_programs("other.exe"), "Diff programs failed"),
    ("set_color", lambda bridge, _header: bridge.set_color(0x1000, 0xFF0000), "Set color failed"),
]

_WRAP_ONLY_NAMES: Final[frozenset[str]] = frozenset({"create_data_type", "create_data", "configure_analysis", "create_memory_block"})

_PASS_THROUGH_CASES: Final[list[tuple[str, _Call, str]]] = [case for case in _WRAPPED_FAILURES if case[0] not in _WRAP_ONLY_NAMES]

_UNCONNECTED_CASES: Final[list[tuple[str, _Call]]] = [
    (
        "assign_fragment_range",
        lambda bridge, _header: bridge.assign_fragment_range("Tree", "Frag", 0x1000, 0x1FFF),
    ),
    ("get_instruction_pcode", lambda bridge, _header: bridge.get_instruction_pcode(0x1000)),
    ("disassemble_range", lambda bridge, _header: bridge.disassemble_range(0x1000, 0x1010)),
    ("clear_code_bytes", lambda bridge, _header: bridge.clear_code_bytes(0x1000, 0x1010)),
    ("get_data_type_tree", lambda bridge, _header: bridge.get_data_type_tree("/Cat")),
    ("import_c_header", lambda bridge, _header: bridge.import_c_header("types.h")),
    ("export_data_type_archive", lambda bridge, _header: bridge.export_data_type_archive("types.gdt")),
    ("import_data_type_archive", lambda bridge, _header: bridge.import_data_type_archive("types.gdt")),
    ("remove_memory_block", lambda bridge, _header: bridge.remove_memory_block("blk")),
    ("split_memory_block", lambda bridge, _header: bridge.split_memory_block("blk", 0x2000)),
    ("move_memory_block", lambda bridge, _header: bridge.move_memory_block("blk", 0x3000)),
    ("rename_memory_block", lambda bridge, _header: bridge.rename_memory_block("blk", "new")),
    ("set_memory_block_comment", lambda bridge, _header: bridge.set_memory_block_comment("blk", "text")),
    ("join_memory_blocks", lambda bridge, _header: bridge.join_memory_blocks("a", "b")),
    ("create_program_tree", lambda bridge, _header: bridge.create_program_tree("Tree")),
    ("edit_program_tree", lambda bridge, _header: bridge.edit_program_tree("Tree", "create_module", "Parent", "Child")),
]

_BAD_PAYLOAD_CASES: Final[list[tuple[str, _Call, object, str]]] = [
    ("get_stack_frame", lambda bridge, _header: bridge.get_stack_frame(0x1000), None, "Get stack frame returned no payload at 0x1000"),
    ("get_call_tree", lambda bridge, _header: bridge.get_call_tree(0x1000), None, "Get call tree returned no payload at 0x1000"),
    (
        "get_instruction_flow",
        lambda bridge, _header: bridge.get_instruction_flow(0x1000),
        None,
        "Get instruction flow returned no payload at 0x1000",
    ),
    (
        "get_instruction_pcode",
        lambda bridge, _header: bridge.get_instruction_pcode(0x1000),
        None,
        "Get instruction pcode returned no payload at 0x1000",
    ),
    (
        "clear_code_bytes",
        lambda bridge, _header: bridge.clear_code_bytes(0x1000, 0x1010),
        None,
        "Clear code bytes returned no payload for range 0x1000-0x1010",
    ),
    (
        "get_data_type_tree",
        lambda bridge, _header: bridge.get_data_type_tree("/Cat"),
        ["not", "a", "dict"],
        "Get data type tree returned no payload for '/Cat'",
    ),
    ("get_properties", lambda bridge, _header: bridge.get_properties(0x1000), None, "Get properties returned no payload at 0x1000"),
    ("diff_programs", lambda bridge, _header: bridge.diff_programs("other.exe"), None, "Diff programs returned no payload"),
]

_UNSET_FLAG_CASES: Final[list[tuple[str, _Call, object, str]]] = [
    (
        "assign_fragment_range",
        lambda bridge, _header: bridge.assign_fragment_range("Tree", "Frag", 0x1000, 0x1FFF),
        {"tree_found": True, "fragment_found": True, "ok": False},
        "Assign fragment range failed: 0x1000-0x1fff into 'Frag'",
    ),
    (
        "remove_memory_block",
        lambda bridge, _header: bridge.remove_memory_block("blk"),
        {"found": True, "ok": False},
        "Remove memory block failed: 'blk'",
    ),
    (
        "split_memory_block",
        lambda bridge, _header: bridge.split_memory_block("blk", 0x2000),
        {"found": True, "in_range": True, "ok": False},
        "Split memory block failed: 'blk' at 0x2000",
    ),
    (
        "move_memory_block",
        lambda bridge, _header: bridge.move_memory_block("blk", 0x3000),
        {"found": True, "ok": False},
        "Move memory block failed: 'blk' to 0x3000",
    ),
    (
        "rename_memory_block",
        lambda bridge, _header: bridge.rename_memory_block("blk", "new"),
        {"found": True, "ok": False},
        "Rename memory block failed: 'blk' -> 'new'",
    ),
    (
        "set_memory_block_comment",
        lambda bridge, _header: bridge.set_memory_block_comment("blk", "text"),
        {"found": True, "ok": False},
        "Set memory block comment failed: 'blk'",
    ),
    (
        "join_memory_blocks",
        lambda bridge, _header: bridge.join_memory_blocks("a", "b"),
        {"found1": True, "found2": True, "ok": False},
        "Join memory blocks failed: 'a' + 'b'",
    ),
    (
        "create_program_tree",
        lambda bridge, _header: bridge.create_program_tree("Tree"),
        {"already_exists": False, "created": False},
        "Failed to create program tree: 'Tree'",
    ),
    (
        "edit_program_tree",
        lambda bridge, _header: bridge.edit_program_tree("Tree", "rename", "Parent", "Child", new_name="Renamed"),
        {"tree_found": True, "parent_found": True, "child_found": True, "ok": False},
        "Edit program tree failed: rename 'Child' under 'Parent'",
    ),
]


@dataclass(frozen=True)
class _LiveProgram:
    """A connected headless Ghidra session and the facts known about its program.

    Attributes:
        bridge: Bridge connected to the running headless Ghidra.
        info: What ``load_binary`` reported for the imported copy.
        entry_address: Entry point address computed from the PE header with ``pefile``.
    """

    bridge: GhidraBridge
    info: BinaryInfo
    entry_address: int


def _replay(outcome: object) -> object:
    """Return a scripted outcome, or raise it when it is an exception.

    Args:
        outcome: The scripted value or exception instance.

    Returns:
        object: ``outcome`` itself when it is not an exception.

    Raises:
        outcome: The scripted exception instance itself, when ``outcome`` is one.
    """
    if isinstance(outcome, BaseException):
        raise outcome
    return outcome


class _ScriptedBridge(GhidraBridge):
    """Real bridge whose remote script and remote eval exchanges replay chosen outcomes.

    Only the two methods that talk to the Ghidra RPC peer are replaced; every
    accessor above them runs its production code against the scripted answer.
    """

    def __init__(self, script_outcome: object = None, eval_outcome: object = None) -> None:
        """Remember the outcomes the exchanges will replay.

        Args:
            script_outcome: Value returned (or exception raised) by every script exchange.
            eval_outcome: Value returned (or exception raised) by every eval exchange.
        """
        super().__init__()
        self._script_outcome = script_outcome
        self._eval_outcome = eval_outcome

    async def _execute_remote(self, code: str) -> object:
        """Replay the scripted script-exchange outcome.

        Args:
            code: The Jython source the accessor would have sent; unused.

        Returns:
            object: The scripted outcome.
        """
        _ = code
        return _replay(self._script_outcome)

    async def _execute_remote_eval(self, expression: str) -> object:
        """Replay the scripted eval-exchange outcome.

        Args:
            expression: The Jython expression the accessor would have sent; unused.

        Returns:
            object: The scripted outcome.
        """
        _ = expression
        return _replay(self._eval_outcome)


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


def _scripted_bridge(client: object, script_outcome: object = None, eval_outcome: object = None) -> _ScriptedBridge:
    """Build a scripted bridge attached to a real RPC client.

    Args:
        client: Real, never-connected ``ghidra_bridge`` client.
        script_outcome: Outcome replayed by every script exchange.
        eval_outcome: Outcome replayed by every eval exchange.

    Returns:
        _ScriptedBridge: A bridge that reports itself connected.
    """
    scripted = _ScriptedBridge(script_outcome, eval_outcome)
    scripted.attach_remote_bridge(client)
    return scripted


def _pe_entry_address(path: Path) -> int:
    """Compute the entry point address of a PE file from its optional header.

    Args:
        path: PE file to inspect.

    Returns:
        int: ``ImageBase + AddressOfEntryPoint``.
    """
    with pefile.PE(str(path), fast_load=True) as parsed:
        return int(parsed.OPTIONAL_HEADER.ImageBase) + int(parsed.OPTIONAL_HEADER.AddressOfEntryPoint)


@pytest.fixture(scope="module")
def idle_rpc_client() -> Iterator[object]:
    """Provide a real ``ghidra_bridge`` client that is never used for a call.

    Yields:
        object: The RPC client instance, closed at teardown.
    """
    client = _make_rpc_client(_reserve_free_port())
    try:
        yield client
    finally:
        getattr(GhidraBridge, "_close_bridge_client")(client)


@pytest.fixture(scope="module")
def live_program(real_pe_exe: Path, tmp_path_factory: pytest.TempPathFactory) -> Iterator[_LiveProgram]:
    """Start one headless Ghidra session on a temporary copy of a System32 binary.

    The JVM can start only once per process, so this is the single place the
    module starts it. The session is shut down, and the project and binary
    directories removed, in ``finally`` even when the start fails halfway.

    Args:
        real_pe_exe: Real PE executable resolved from System32.
        tmp_path_factory: Pytest factory for the project and binary directories.

    Yields:
        _LiveProgram: The connected bridge, the load report and the entry address.
    """
    install_text = os.environ.get("GHIDRA_INSTALL_DIR", "").strip()
    if not install_text:
        pytest.fail("GHIDRA_INSTALL_DIR is not set, so the container does not name a Ghidra installation", pytrace=False)
    binary_dir = tmp_path_factory.mktemp("critcov_ghidra_03_binary")
    project_dir = tmp_path_factory.mktemp("critcov_ghidra_03_project")
    binary = binary_dir / real_pe_exe.name
    shutil.copyfile(real_pe_exe, binary)
    bridge = GhidraBridge()
    bridge.set_port(_reserve_free_port())
    bridge.ghidra_path = Path(install_text)
    try:
        try:
            asyncio.run(asyncio.wait_for(bridge.start_headless(project_dir, "critcov_ghidra_03"), timeout=_LIVE_STEP_TIMEOUT_SECONDS))
            info = asyncio.run(asyncio.wait_for(bridge.load_binary(binary), timeout=_LIVE_STEP_TIMEOUT_SECONDS))
        except (ToolError, OSError) as exc:
            pytest.fail(
                f"Headless Ghidra could not start or import {binary} inside this container "
                f"(install {install_text}): {type(exc).__name__}: {exc}",
                pytrace=False,
            )
        yield _LiveProgram(bridge=bridge, info=info, entry_address=_pe_entry_address(binary))
    finally:
        asyncio.run(bridge.shutdown())
        shutil.rmtree(project_dir, ignore_errors=True)
        shutil.rmtree(binary_dir, ignore_errors=True)


@pytest.fixture
def header_file(tmp_path: Path) -> Path:
    """Write a small C header that the header-path validator accepts.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        Path: Path of the header file.
    """
    path = tmp_path / "types.h"
    path.write_text("typedef int widget_t;\n", encoding="utf-8")
    return path


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "call"), _UNCONNECTED_CASES, ids=[name for name, _ in _UNCONNECTED_CASES])
async def test_accessors_refuse_to_run_without_a_connection(name: str, call: _Call, tmp_path: Path) -> None:
    """Each accessor fails fast with the standard error when no RPC client is attached.

    Args:
        name: Accessor name, used for the test id.
        call: Coroutine factory invoking the accessor on a fresh bridge.
        tmp_path: Pytest temporary directory passed through as the unused header path.
    """
    fresh = GhidraBridge()

    with pytest.raises(ToolError, match=r"^Ghidra not connected$"):
        await call(fresh, tmp_path)

    assert fresh.state.connected is False, name


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("name", "call", "prefix"),
    _PASS_THROUGH_CASES,
    ids=[case[0] for case in _PASS_THROUGH_CASES],
)
async def test_accessors_re_raise_a_remote_tool_error_unchanged(
    idle_rpc_client: object,
    header_file: Path,
    name: str,
    call: _Call,
    prefix: str,
) -> None:
    """A ``ToolError`` from the remote exchange reaches the caller as the very same object.

    The handler that wraps unexpected exceptions would build a new, prefixed
    error; identity proves the dedicated ``except ToolError: raise`` ran first.

    Args:
        idle_rpc_client: Real, never-connected RPC client.
        header_file: Existing header file for the accessor that validates a path.
        name: Accessor name, used for the test id.
        call: Coroutine factory invoking the accessor on the scripted bridge.
        prefix: Wrapping message prefix; not expected in the re-raised error.
    """
    original = ToolError(f"{_SCRIPTED_FAILURE_TEXT} from {name}")
    scripted = _scripted_bridge(idle_rpc_client, script_outcome=original, eval_outcome=original)

    with pytest.raises(ToolError) as excinfo:
        await call(scripted, header_file)

    assert excinfo.value is original
    assert prefix not in str(excinfo.value)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("name", "call", "prefix"),
    _WRAPPED_FAILURES,
    ids=[case[0] for case in _WRAPPED_FAILURES],
)
async def test_accessors_wrap_an_unexpected_remote_exception(
    idle_rpc_client: object,
    header_file: Path,
    name: str,
    call: _Call,
    prefix: str,
) -> None:
    """Any other exception from the remote exchange becomes a prefixed ``ToolError`` chained to it.

    Args:
        idle_rpc_client: Real, never-connected RPC client.
        header_file: Existing header file for the accessor that validates a path.
        name: Accessor name, used for the test id.
        call: Coroutine factory invoking the accessor on the scripted bridge.
        prefix: The accessor's documented failure wording.
    """
    failure = RuntimeError(_SCRIPTED_FAILURE_TEXT)
    scripted = _scripted_bridge(idle_rpc_client, script_outcome=failure, eval_outcome=failure)

    with pytest.raises(ToolError) as excinfo:
        await call(scripted, header_file)

    assert str(excinfo.value) == f"{prefix}: {_SCRIPTED_FAILURE_TEXT}", name
    assert excinfo.value.__cause__ is failure


@pytest.mark.asyncio
async def test_create_equate_re_raises_a_tool_error_from_the_readback(idle_rpc_client: object) -> None:
    """A ``ToolError`` raised while reading the equate back is propagated as the same object.

    Args:
        idle_rpc_client: Real, never-connected RPC client.
    """
    original = ToolError("readback refused")
    scripted = _scripted_bridge(idle_rpc_client, script_outcome=None, eval_outcome=original)

    with pytest.raises(ToolError) as excinfo:
        await scripted.create_equate(0x1000, 5, "EQ")

    assert excinfo.value is original


@pytest.mark.asyncio
async def test_create_equate_wraps_an_unexpected_exception_from_the_readback(idle_rpc_client: object) -> None:
    """Any other exception while reading the equate back becomes a readback-specific ``ToolError``.

    Args:
        idle_rpc_client: Real, never-connected RPC client.
    """
    failure = RuntimeError(_SCRIPTED_FAILURE_TEXT)
    scripted = _scripted_bridge(idle_rpc_client, script_outcome=None, eval_outcome=failure)

    with pytest.raises(ToolError) as excinfo:
        await scripted.create_equate(0x1000, 5, "EQ")

    assert str(excinfo.value) == f"Create equate readback failed: {_SCRIPTED_FAILURE_TEXT}"
    assert excinfo.value.__cause__ is failure


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("name", "call", "payload", "message"),
    _BAD_PAYLOAD_CASES,
    ids=[case[0] for case in _BAD_PAYLOAD_CASES],
)
async def test_accessors_reject_a_payload_that_is_not_a_dict(
    idle_rpc_client: object,
    header_file: Path,
    name: str,
    call: _Call,
    payload: object,
    message: str,
) -> None:
    """A remote answer that is not the expected dict is reported with the accessor's own wording.

    Args:
        idle_rpc_client: Real, never-connected RPC client.
        header_file: Existing header file passed through to the call factory.
        name: Accessor name, used for the test id.
        call: Coroutine factory invoking the accessor on the scripted bridge.
        payload: The non-dict answer the remote exchange returns.
        message: Exact error text the accessor documents.
    """
    scripted = _scripted_bridge(idle_rpc_client, script_outcome=payload)

    with pytest.raises(ToolError) as excinfo:
        await call(scripted, header_file)

    assert str(excinfo.value) == message, name


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("name", "call", "payload", "message"),
    _UNSET_FLAG_CASES,
    ids=[case[0] for case in _UNSET_FLAG_CASES],
)
async def test_accessors_report_a_mutation_ghidra_did_not_confirm(
    idle_rpc_client: object,
    header_file: Path,
    name: str,
    call: _Call,
    payload: object,
    message: str,
) -> None:
    """When Ghidra answers that the mutation was found but not applied, the accessor raises.

    Args:
        idle_rpc_client: Real, never-connected RPC client.
        header_file: Existing header file passed through to the call factory.
        name: Accessor name, used for the test id.
        call: Coroutine factory invoking the accessor on the scripted bridge.
        payload: The flag dict the remote exchange returns, with ``ok`` false.
        message: Exact error text the accessor documents.
    """
    scripted = _scripted_bridge(idle_rpc_client, script_outcome=payload)

    with pytest.raises(ToolError) as excinfo:
        await call(scripted, header_file)

    assert str(excinfo.value) == message, name


@pytest.mark.asyncio
async def test_get_calling_conventions_returns_an_empty_list_for_a_non_list_answer(idle_rpc_client: object) -> None:
    """Only a list answer is converted to names; any other answer yields an empty list.

    Args:
        idle_rpc_client: Real, never-connected RPC client.
    """
    listed = _scripted_bridge(idle_rpc_client, script_outcome=["__cdecl", 7])
    unlisted = _scripted_bridge(idle_rpc_client, script_outcome={"__cdecl": 1})

    assert await listed.get_calling_conventions() == ["__cdecl", "7"]
    assert await unlisted.get_calling_conventions() == []


@pytest.mark.asyncio
async def test_get_program_tree_falls_back_to_an_empty_tree_list(idle_rpc_client: object) -> None:
    """A dict answer is returned as given; any other answer becomes ``{"trees": []}``.

    Args:
        idle_rpc_client: Real, never-connected RPC client.
    """
    tree_answer = {"trees": [{"name": "Program Tree", "root": None}]}
    answered = _scripted_bridge(idle_rpc_client, script_outcome=tree_answer)
    unanswered = _scripted_bridge(idle_rpc_client, script_outcome=None)

    assert await answered.get_program_tree() == tree_answer
    assert await unanswered.get_program_tree() == {"trees": []}


@pytest.mark.asyncio
async def test_set_decompiler_options_merges_extras_and_keeps_values_left_unset(idle_rpc_client: object) -> None:
    """Options passed as ``None`` leave the stored value alone, and extras accumulate across calls.

    Args:
        idle_rpc_client: Real, never-connected RPC client.
    """
    scripted = _scripted_bridge(idle_rpc_client, script_outcome={"success": True})

    first = await scripted.set_decompiler_options(extra={"alpha": 1})
    second = await scripted.set_decompiler_options(extra={"beta": 2})
    configured = await scripted.set_decompiler_options(simplification="normalize", max_instructions=500)
    kept = await scripted.set_decompiler_options(extra={"gamma": 3})

    assert first == {"simplification": None, "max_instructions": None, "extra": {"alpha": 1}, "success": True}
    assert second["extra"] == {"alpha": 1, "beta": 2}
    assert configured["simplification"] == "normalize"
    assert configured["max_instructions"] == 500
    assert kept == {
        "simplification": "normalize",
        "max_instructions": 500,
        "extra": {"alpha": 1, "beta": 2, "gamma": 3},
        "success": True,
    }
    assert scripted.decompiler_options == {
        "simplification": "normalize",
        "max_instructions": 500,
        "extra": {"alpha": 1, "beta": 2, "gamma": 3},
    }


@pytest.mark.asyncio
async def test_run_headless_batch_requires_a_ghidra_path(tmp_path: Path) -> None:
    """A batch without an installation path is refused before anything is spawned.

    Args:
        tmp_path: Pytest temporary directory passed as the project directory.
    """
    fresh = GhidraBridge()

    with pytest.raises(ToolError, match=r"^Ghidra path not set$"):
        await fresh.run_headless_batch(tmp_path, [str(tmp_path / "sample.bin")])


@pytest.mark.asyncio
async def test_live_split_memory_block_rejects_a_block_the_program_does_not_have(live_program: _LiveProgram) -> None:
    """Ghidra reports no block of that name, and the memory map is left as it was.

    Args:
        live_program: Connected headless Ghidra session.
    """
    live = live_program.bridge
    before = await live.execute_script(_BLOCK_NAMES_SCRIPT)

    with pytest.raises(ToolError) as excinfo:
        await live.split_memory_block(_MISSING_BLOCK, live_program.entry_address)

    assert before
    assert _MISSING_BLOCK not in before.split("|")
    assert str(excinfo.value) == f"Memory block not found: {_MISSING_BLOCK!r}"
    assert await live.execute_script(_BLOCK_NAMES_SCRIPT) == before


@pytest.mark.asyncio
async def test_live_join_memory_blocks_names_the_first_block_when_it_is_missing(live_program: _LiveProgram) -> None:
    """Joining a missing block with a real one blames the missing first block and changes nothing.

    Args:
        live_program: Connected headless Ghidra session.
    """
    live = live_program.bridge
    before = await live.execute_script(_BLOCK_NAMES_SCRIPT)
    real_block = before.split("|")[0]

    with pytest.raises(ToolError) as excinfo:
        await live.join_memory_blocks(_MISSING_BLOCK, real_block)

    assert real_block
    assert str(excinfo.value) == f"Memory block not found: {_MISSING_BLOCK!r}"
    assert await live.execute_script(_BLOCK_NAMES_SCRIPT) == before


@pytest.mark.asyncio
async def test_live_assign_fragment_range_rejects_a_program_tree_the_program_does_not_have(live_program: _LiveProgram) -> None:
    """Ghidra has no tree of that name, so the range is refused and no tree appears.

    Args:
        live_program: Connected headless Ghidra session.
    """
    live = live_program.bridge
    before = await live.execute_script(_TREE_NAMES_SCRIPT)

    with pytest.raises(ToolError) as excinfo:
        await live.assign_fragment_range(_MISSING_TREE, "fragment", live_program.entry_address, live_program.entry_address + 1)

    assert _MISSING_TREE not in before.split("|")
    assert str(excinfo.value) == f"Program tree not found: {_MISSING_TREE!r}"
    assert await live.execute_script(_TREE_NAMES_SCRIPT) == before


@pytest.mark.asyncio
async def test_live_edit_program_tree_rejects_a_program_tree_the_program_does_not_have(live_program: _LiveProgram) -> None:
    """Ghidra has no tree of that name, so nothing is created under it and no tree appears.

    Args:
        live_program: Connected headless Ghidra session.
    """
    live = live_program.bridge
    before = await live.execute_script(_TREE_NAMES_SCRIPT)

    with pytest.raises(ToolError) as excinfo:
        await live.edit_program_tree(_MISSING_TREE, "create_module", "Parent", "Child")

    assert _MISSING_TREE not in before.split("|")
    assert str(excinfo.value) == f"Program tree not found: {_MISSING_TREE!r}"
    assert await live.execute_script(_TREE_NAMES_SCRIPT) == before


@pytest.mark.asyncio
async def test_live_create_equate_persists_the_equate_at_the_entry_point(live_program: _LiveProgram) -> None:
    """A created equate is really stored by Ghidra with its value and a reference at the address.

    The address comes from the PE header via ``pefile``; the stored value and
    reference are read back through independent scripts, not through the
    bridge's own readback.

    Args:
        live_program: Connected headless Ghidra session.
    """
    live = live_program.bridge
    address = live_program.entry_address

    result = await live.create_equate(address, _EQUATE_VALUE, _EQUATE_NAME)

    assert result == {"name": _EQUATE_NAME, "value": _EQUATE_VALUE, "address": hex(address), "success": True}
    assert await live.execute_script(_EQUATE_VALUE_SCRIPT) == str(_EQUATE_VALUE)
    assert str(address) in (await live.execute_script(_EQUATE_REFS_SCRIPT)).split("|")
