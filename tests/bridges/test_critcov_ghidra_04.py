# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-object coverage for the fourth slice of ``intellicrack.bridges.ghidra``.

The slice is the tail of the analysis surface: ``set_program_metadata``,
``execute_script_with_params``, the thunk, function-tag, external-reference,
bookmark, label and overlay accessors, and their error handling.

Three kinds of real object drive it:

* a genuine ``ghidra_bridge.GhidraBridge`` RPC client pointed at a closed
  loopback port, so every remote call fails the way a vanished Ghidra peer does;
* real ``GhidraBridge`` subclasses that script only the remote script exchange
  (one payload, or one failure) so the handlers that inspect a payload or wrap an
  unexpected error run unchanged on the real bridge methods;
* one module-scoped headless Ghidra session, started once through PyGhidra on a
  copy of a System32 executable and shut down in ``finally``. Every mutation lands
  in Ghidra's in-memory program for that copy; the System32 original is never
  touched. Expectations for live calls are read back with direct Ghidra API
  scripts, a code path independent of the bridge methods under test.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import re
import shutil
import socket
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

import pytest

from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import Iterator


pytestmark = pytest.mark.spawns_process

_LIVE_STEP_TIMEOUT_SECONDS: Final[float] = 600.0
_REMOTE_FAILURE_PATTERN: Final[str] = r"^Remote execution failed"
_FUNCTION_NOT_FOUND: Final[str] = "Function not found at address"
_SCRIPTED_FAILURE: Final[str] = "scripted remote failure"
_HUGE_ADDRESS: Final[int] = 10**4300
_HUGE_ADDRESS_TEXT: Final[str] = hex(_HUGE_ADDRESS)
_SLOT_BASE: Final[int] = 0x100
_SLOT_STRIDE: Final[int] = 0x40
_IMAGE_BASE_SHIFT: Final[int] = 0x10000

_BridgeCall = Callable[[GhidraBridge], Awaitable[object]]

_UNCONNECTED_CALLS: Final[list[tuple[str, _BridgeCall]]] = [
    ("create_function_tag", lambda bridge: bridge.create_function_tag("critcov_tag")),
    ("set_function_tags", lambda bridge: bridge.set_function_tags(0x1000, "critcov_tag", "add")),
    ("get_function_tags", lambda bridge: bridge.get_function_tags()),
    ("promote_symbol_to_primary", lambda bridge: bridge.promote_symbol_to_primary(0x1000, "critcov_label")),
]

_DEAD_PEER_CALLS: Final[list[tuple[str, _BridgeCall]]] = [
    ("set_program_metadata", lambda bridge: bridge.set_program_metadata(name="renamed.exe")),
    ("execute_script_with_params", lambda bridge: bridge.execute_script_with_params("params", {"key": "value"})),
    ("get_thunk_info", lambda bridge: bridge.get_thunk_info(0x1000)),
    ("create_function_tag", lambda bridge: bridge.create_function_tag("critcov_tag", "comment")),
    ("set_function_tags_add", lambda bridge: bridge.set_function_tags(0x1000, "critcov_tag", "add")),
    ("set_function_tags_remove", lambda bridge: bridge.set_function_tags(0x1000, "critcov_tag", "remove")),
    ("get_function_tags_all", lambda bridge: bridge.get_function_tags()),
    ("get_function_tags_one", lambda bridge: bridge.get_function_tags(0x1000)),
    ("get_external_references", lambda bridge: bridge.get_external_references(0x1000)),
    ("create_overlay_space", lambda bridge: bridge.create_overlay_space("critcov_overlay")),
    ("add_bookmark", lambda bridge: bridge.add_bookmark(0x1000, "category", "comment")),
    ("remove_bookmark", lambda bridge: bridge.remove_bookmark(0x1000)),
    ("add_label", lambda bridge: bridge.add_label(0x1000, "critcov_label")),
    ("remove_label", lambda bridge: bridge.remove_label(0x1000, "critcov_label")),
    ("promote_symbol_to_primary", lambda bridge: bridge.promote_symbol_to_primary(0x1000, "critcov_label")),
    ("add_thunk", lambda bridge: bridge.add_thunk(0x1000, 0x2000)),
    ("remove_thunk", lambda bridge: bridge.remove_thunk(0x1000)),
    ("add_external_reference", lambda bridge: bridge.add_external_reference(0x1000, "critcov.dll", "CritcovExport")),
    ("remove_external_reference", lambda bridge: bridge.remove_external_reference(0x1000)),
]

_HUGE_ADDRESS_CALLS: Final[list[tuple[str, _BridgeCall, str]]] = [
    ("get_thunk_info", lambda bridge: bridge.get_thunk_info(_HUGE_ADDRESS), f"Get thunk info failed at {_HUGE_ADDRESS_TEXT}: "),
    (
        "get_external_references",
        lambda bridge: bridge.get_external_references(_HUGE_ADDRESS),
        f"Get external references failed at {_HUGE_ADDRESS_TEXT}: ",
    ),
    ("add_bookmark", lambda bridge: bridge.add_bookmark(_HUGE_ADDRESS, "category", "comment"), "Add bookmark failed: "),
    ("remove_bookmark", lambda bridge: bridge.remove_bookmark(_HUGE_ADDRESS), "Remove bookmark failed: "),
    ("add_label", lambda bridge: bridge.add_label(_HUGE_ADDRESS, "critcov_label"), "Add label failed: "),
    ("remove_label", lambda bridge: bridge.remove_label(_HUGE_ADDRESS, "critcov_label"), "Remove label failed: "),
    (
        "promote_symbol_to_primary",
        lambda bridge: bridge.promote_symbol_to_primary(_HUGE_ADDRESS, "critcov_label"),
        "Promote symbol failed: ",
    ),
    ("add_thunk", lambda bridge: bridge.add_thunk(_HUGE_ADDRESS, 0x2000), "Add thunk failed: "),
    ("remove_thunk", lambda bridge: bridge.remove_thunk(_HUGE_ADDRESS), "Remove thunk failed: "),
    (
        "add_external_reference",
        lambda bridge: bridge.add_external_reference(_HUGE_ADDRESS, "critcov.dll", "CritcovExport"),
        "Add external reference failed: ",
    ),
    (
        "remove_external_reference",
        lambda bridge: bridge.remove_external_reference(_HUGE_ADDRESS),
        "Remove external reference failed: ",
    ),
]

_UNEXPECTED_ERROR_CALLS: Final[list[tuple[str, _BridgeCall, str]]] = [
    ("create_function_tag", lambda bridge: bridge.create_function_tag("critcov_tag", "comment"), "Create function tag failed: "),
    ("set_function_tags", lambda bridge: bridge.set_function_tags(0x1000, "critcov_tag", "add"), "Set function tags failed: "),
    ("get_function_tags", lambda bridge: bridge.get_function_tags(), "Get function tags failed: "),
    ("create_overlay_space", lambda bridge: bridge.create_overlay_space("critcov_overlay"), "Create overlay space failed: "),
    ("set_program_metadata", lambda bridge: bridge.set_program_metadata(name="renamed.exe"), "Set program metadata failed: "),
]

_PAYLOAD_FAILURES: Final[list[tuple[str, object, _BridgeCall, str]]] = [
    (
        "thunk-info-without-payload",
        None,
        lambda bridge: bridge.get_thunk_info(0x1000),
        "Get thunk info returned no payload at 0x1000",
    ),
    (
        "function-tag-refused",
        {"success": False},
        lambda bridge: bridge.create_function_tag("critcov_tag", "comment"),
        "Create function tag failed: Ghidra refused tag 'critcov_tag'",
    ),
    (
        "function-tag-not-applied",
        {"found": True, "applied": False},
        lambda bridge: bridge.set_function_tags(0x1000, "critcov_tag", "add"),
        "Set function tags failed: add 'critcov_tag' at 0x1000",
    ),
    (
        "bookmark-not-created",
        {"created": False},
        lambda bridge: bridge.add_bookmark(0x1000, "category", "comment"),
        "Add bookmark failed at 0x1000",
    ),
    (
        "thunk-not-added",
        {"thunk_found": True, "target_found": True, "ok": False},
        lambda bridge: bridge.add_thunk(0x1000, 0x2000),
        "Add thunk failed at 0x1000",
    ),
    (
        "thunk-not-removed",
        {"found": True, "was_thunk": True, "ok": False},
        lambda bridge: bridge.remove_thunk(0x1000),
        "Remove thunk failed at 0x1000",
    ),
    (
        "external-reference-not-added",
        {"ok": False},
        lambda bridge: bridge.add_external_reference(0x1000, "critcov.dll", "CritcovExport"),
        "Add external reference failed at 0x1000",
    ),
]


class _PayloadBridge(GhidraBridge):
    """Real bridge whose remote script exchange reports one scripted payload.

    Only ``_execute_remote`` is replaced. Every other line of the bridge method
    under test, including its payload inspection, runs unchanged.
    """

    def __init__(self, client: object, payload: object) -> None:
        """Attach the RPC client and remember the scripted payload.

        Args:
            client: Real RPC client attached so the bridge counts as connected.
            payload: Value the remote script exchange reports back.
        """
        super().__init__()
        self.attach_remote_bridge(client)
        self.payload = payload

    async def _execute_remote(self, code: str) -> object:
        """Report the scripted payload instead of running ``code`` remotely.

        Args:
            code: Script the bridge method wanted to run; ignored.

        Returns:
            object: The scripted payload.
        """
        _ = code
        return self.payload


class _FailingExchangeBridge(GhidraBridge):
    """Real bridge whose remote script exchange fails with a non-``ToolError``."""

    def __init__(self, client: object, message: str) -> None:
        """Attach the RPC client and remember the failure text.

        Args:
            client: Real RPC client attached so the bridge counts as connected.
            message: Text of the ``RuntimeError`` the exchange raises.
        """
        super().__init__()
        self.attach_remote_bridge(client)
        self.message = message

    async def _execute_remote(self, code: str) -> object:
        """Fail instead of running ``code`` remotely.

        Args:
            code: Script the bridge method wanted to run; ignored.

        Returns:
            object: Never returned, because the call always raises.

        Raises:
            RuntimeError: Always, with the scripted message.
        """
        _ = code
        raise RuntimeError(self.message)


class _FailingReadbackBridge(_PayloadBridge):
    """Real bridge whose write exchange succeeds and whose readback fails unexpectedly."""

    def __init__(self, client: object, message: str) -> None:
        """Attach the RPC client and remember the readback failure text.

        Args:
            client: Real RPC client attached so the bridge counts as connected.
            message: Text of the ``RuntimeError`` the readback raises.
        """
        super().__init__(client, None)
        self.readback_message = message

    async def _execute_remote_eval(self, expression: str) -> object:
        """Fail instead of evaluating ``expression`` remotely.

        Args:
            expression: Expression the bridge method wanted to evaluate; ignored.

        Returns:
            object: Never returned, because the call always raises.

        Raises:
            RuntimeError: Always, with the scripted message.
        """
        _ = expression
        raise RuntimeError(self.readback_message)


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


def _close_rpc_client(client: object) -> None:
    """Close a ``ghidra_bridge`` client through the bridge's own helper.

    Args:
        client: RPC client to close.
    """
    closer = cast("Callable[[object], object]", getattr(GhidraBridge, "_close_bridge_client"))
    closer(client)


def _rpc_client_of(bridge: GhidraBridge) -> object:
    """Read the RPC client attached to a bridge.

    Args:
        bridge: Bridge that owns the client.

    Returns:
        object: The attached RPC client.
    """
    return cast("object", getattr(bridge, "_bridge"))


async def _query(bridge: GhidraBridge, script: str) -> object:
    """Run a Ghidra script that ends in ``json.dumps`` and decode its answer.

    Args:
        bridge: Live bridge that runs the script.
        script: Script whose last expression is a JSON string.

    Returns:
        object: The decoded JSON value.
    """
    raw = await bridge.execute_script(script)
    decoded: object = json.loads(raw)
    return decoded


def _slot_start(entry_point: int, slot: int) -> int:
    """Compute a search start address a fixed distance below the entry point.

    Args:
        entry_point: Entry point address of the loaded program.
        slot: Distinct slot number for the test.

    Returns:
        int: The address where the free-address search starts.
    """
    return entry_point - _SLOT_BASE - _SLOT_STRIDE * slot


async def _find_free_address(bridge: GhidraBridge, start: int) -> int:
    """Find an address at or below ``start`` that no function contains.

    Args:
        bridge: Live bridge that runs the search.
        start: Address where the downward search begins.

    Returns:
        int: An address inside the program that no function covers.
    """
    answer = await _query(
        bridge,
        f"""
        import json
        fm = currentProgram.getFunctionManager()
        candidate = toAddr({start})
        guard = 0
        while fm.getFunctionContaining(candidate) is not None and guard < 4096:
            candidate = candidate.subtract(16)
            guard += 1
        json.dumps(dict(address=candidate.getOffset(), free=fm.getFunctionContaining(candidate) is None))
        """,
    )
    payload = cast("dict[str, object]", answer)
    assert payload["free"] is True
    return int(cast("int", payload["address"]))


async def _create_function(bridge: GhidraBridge, entry_point: int, slot: int, name: str) -> int:
    """Create a one-byte function at a free address through Ghidra's own API.

    Args:
        bridge: Live bridge that runs the script.
        entry_point: Entry point address of the loaded program.
        slot: Distinct slot number for the test.
        name: Name for the new function.

    Returns:
        int: The entry address of the created function.
    """
    free = await _find_free_address(bridge, _slot_start(entry_point, slot))
    answer = await _query(
        bridge,
        f"""
        import json
        from ghidra.program.model.address import AddressSet
        from ghidra.program.model.symbol import SourceType
        entry = toAddr({free})
        fm = currentProgram.getFunctionManager()
        tx_id = currentProgram.startTransaction('critcov.create_function')
        try:
            func = fm.createFunction({json.dumps(name)}, entry, AddressSet(entry), SourceType.USER_DEFINED)
        finally:
            currentProgram.endTransaction(tx_id, True)
        json.dumps(dict(entry=func.getEntryPoint().getOffset(), name=str(func.getName())))
        """,
    )
    payload = cast("dict[str, object]", answer)
    assert payload == {"entry": free, "name": name}
    return free


async def _thunk_state(bridge: GhidraBridge, address: int) -> dict[str, object]:
    """Read a function's thunk state directly from Ghidra.

    Args:
        bridge: Live bridge that runs the script.
        address: Entry address of the function.

    Returns:
        dict[str, object]: ``is_thunk`` and the entry address of the thunked
        function, or ``None`` when the function is not a thunk.
    """
    answer = await _query(
        bridge,
        f"""
        import json
        func = currentProgram.getFunctionManager().getFunctionAt(toAddr({address}))
        thunked = func.getThunkedFunction(False) if func.isThunk() else None
        json.dumps(dict(is_thunk=bool(func.isThunk()), target=(thunked.getEntryPoint().getOffset() if thunked is not None else None)))
        """,
    )
    return cast("dict[str, object]", answer)


async def _external_reference_count(bridge: GhidraBridge, address: int) -> int:
    """Count the external references that start at an address, straight from Ghidra.

    Args:
        bridge: Live bridge that runs the script.
        address: Source address of the references.

    Returns:
        int: Number of references from ``address`` that are external.
    """
    answer = await _query(
        bridge,
        f"""
        import json
        refs = currentProgram.getReferenceManager().getReferencesFrom(toAddr({address}))
        json.dumps(sum(1 for ref in refs if ref.isExternalReference()))
        """,
    )
    return int(cast("int", answer))


@pytest.fixture(scope="module")
def dead_rpc_client() -> Iterator[object]:
    """Provide a real ``ghidra_bridge`` client aimed at a closed loopback port.

    Every remote call made through it fails with a socket error, which the
    bridge must surface as a ``ToolError``. The client is shared by the module
    so the (slow on Windows) refused connection is paid once.

    Yields:
        object: The RPC client instance.
    """
    client = _make_rpc_client(_reserve_free_port())
    try:
        yield client
    finally:
        _close_rpc_client(client)


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
def live_bridge(real_pe_exe: Path, tmp_path_factory: pytest.TempPathFactory) -> Iterator[GhidraBridge]:
    """Start one headless Ghidra session on a temporary copy of a System32 binary.

    The JVM can start only once per process, so this is the single place the
    module starts it. The session is shut down, and its project and the binary
    copy removed, in ``finally`` even when the start fails halfway.

    Args:
        real_pe_exe: Real PE executable resolved from System32.
        tmp_path_factory: Pytest factory for the Ghidra project and the copy.

    Yields:
        GhidraBridge: A connected bridge with the copy of ``real_pe_exe`` imported.
    """
    install_text = os.environ.get("GHIDRA_INSTALL_DIR", "").strip()
    if not install_text:
        pytest.fail("GHIDRA_INSTALL_DIR is not set, so the container does not name a Ghidra installation", pytrace=False)
    work_dir = tmp_path_factory.mktemp("critcov_ghidra_04_work")
    project_dir = tmp_path_factory.mktemp("critcov_ghidra_04_project")
    program_copy = work_dir / real_pe_exe.name
    shutil.copyfile(real_pe_exe, program_copy)
    bridge = GhidraBridge()
    bridge.set_port(_reserve_free_port())
    bridge.ghidra_path = Path(install_text)
    try:
        try:
            asyncio.run(asyncio.wait_for(bridge.start_headless(project_dir, "critcov_ghidra_04"), timeout=_LIVE_STEP_TIMEOUT_SECONDS))
            asyncio.run(asyncio.wait_for(bridge.load_binary(program_copy), timeout=_LIVE_STEP_TIMEOUT_SECONDS))
        except (ToolError, OSError) as exc:
            pytest.fail(
                f"Headless Ghidra could not start or import {program_copy} inside this container "
                f"(install {install_text}): {type(exc).__name__}: {exc}",
                pytrace=False,
            )
        yield bridge
    finally:
        asyncio.run(bridge.shutdown())
        shutil.rmtree(project_dir, ignore_errors=True)
        shutil.rmtree(work_dir, ignore_errors=True)


@pytest.fixture(scope="module")
def entry_point(live_bridge: GhidraBridge) -> int:
    """Read the loaded program's entry point straight from Ghidra.

    Args:
        live_bridge: Connected headless Ghidra bridge.

    Returns:
        int: The entry point address of the program the session imported.
    """
    raw = asyncio.run(
        live_bridge.execute_script(
            "entry_points = currentProgram.getSymbolTable().getExternalEntryPointIterator()\n"
            "entry_points.next().getOffset() if entry_points.hasNext() else 0",
        ),
    )
    resolved = int(raw)
    assert resolved != 0
    return resolved


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "call"), _UNCONNECTED_CALLS, ids=[name for name, _ in _UNCONNECTED_CALLS])
async def test_tag_and_symbol_accessors_refuse_to_run_without_a_connection(name: str, call: _BridgeCall) -> None:
    """The tag and symbol accessors fail fast with the standard not-connected error.

    Args:
        name: Accessor name, used for the test id.
        call: Coroutine factory invoking the accessor on a fresh bridge.
    """
    bridge = GhidraBridge()

    with pytest.raises(ToolError, match=r"^Ghidra not connected$"):
        await call(bridge)

    assert bridge.state.connected is False, name


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "call"), _DEAD_PEER_CALLS, ids=[name for name, _ in _DEAD_PEER_CALLS])
async def test_accessors_propagate_the_remote_failure_unchanged(dead_bridge: GhidraBridge, name: str, call: _BridgeCall) -> None:
    """A vanished Ghidra peer surfaces as the remote ``ToolError``, not a re-wrapped one.

    The message must start with the transport-level text; a handler that wrapped
    the already-typed error would prefix it with the accessor's own wording.

    Args:
        dead_bridge: Bridge whose RPC peer is unreachable.
        name: Accessor name, used for the test id.
        call: Coroutine factory invoking the accessor on ``dead_bridge``.
    """
    with pytest.raises(ToolError, match=_REMOTE_FAILURE_PATTERN):
        await call(dead_bridge)

    assert dead_bridge.state.connected is True, name


@pytest.mark.asyncio
@pytest.mark.parametrize("address", [None, 0x1000], ids=["without-address", "with-address"])
async def test_add_external_function_prefixes_a_remote_failure(dead_bridge: GhidraBridge, address: int | None) -> None:
    """``add_external_function`` wraps every failure, including a typed remote one.

    Args:
        dead_bridge: Bridge whose RPC peer is unreachable.
        address: Optional address to link the external function to.
    """
    with pytest.raises(ToolError, match=r"^Add external function failed: Remote execution failed") as excinfo:
        await dead_bridge.add_external_function("critcov.dll", "CritcovExport", address)

    assert isinstance(excinfo.value.__cause__, ToolError)
    assert str(excinfo.value.__cause__).startswith("Remote execution failed")


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "call", "prefix"), _HUGE_ADDRESS_CALLS, ids=[name for name, _, _ in _HUGE_ADDRESS_CALLS])
async def test_an_address_beyond_the_integer_text_limit_is_reported_as_a_tool_error(
    dead_bridge: GhidraBridge,
    name: str,
    call: _BridgeCall,
    prefix: str,
) -> None:
    """An integer too long to render as decimal text fails inside the handler, not the caller.

    Python refuses to convert an integer of more than 4300 decimal digits to
    text, so building the remote script raises ``ValueError``. The accessor must
    turn that into its own ``ToolError`` and keep the original as the cause.

    Args:
        dead_bridge: Connected bridge; the remote peer is never reached.
        name: Accessor name, used for the test id.
        call: Coroutine factory invoking the accessor with the oversized address.
        prefix: Start of the message the accessor's generic handler writes.
    """
    with pytest.raises(ToolError) as excinfo:
        await call(dead_bridge)

    assert str(excinfo.value).startswith(prefix), name
    assert isinstance(excinfo.value.__cause__, ValueError)


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "call", "prefix"), _UNEXPECTED_ERROR_CALLS, ids=[name for name, _, _ in _UNEXPECTED_ERROR_CALLS])
async def test_an_unexpected_remote_error_is_wrapped_by_the_accessor(
    dead_rpc_client: object,
    name: str,
    call: _BridgeCall,
    prefix: str,
) -> None:
    """A non-``ToolError`` failure of the remote exchange is wrapped with the accessor's wording.

    Args:
        dead_rpc_client: Real RPC client attached so the bridge counts as connected.
        name: Accessor name, used for the test id.
        call: Coroutine factory invoking the accessor.
        prefix: Start of the message the accessor's generic handler writes.
    """
    bridge = _FailingExchangeBridge(dead_rpc_client, _SCRIPTED_FAILURE)

    with pytest.raises(ToolError) as excinfo:
        await call(bridge)

    assert str(excinfo.value) == f"{prefix}{_SCRIPTED_FAILURE}", name
    assert isinstance(excinfo.value.__cause__, RuntimeError)


@pytest.mark.asyncio
async def test_set_program_metadata_propagates_a_failed_readback(dead_rpc_client: object) -> None:
    """A typed failure of the readback reaches the caller unchanged.

    The write exchange reports success and the readback runs on the dead peer,
    so it fails with the bridge's own ``ToolError``.

    Args:
        dead_rpc_client: Real RPC client pointed at a closed port.
    """
    bridge = _PayloadBridge(dead_rpc_client, None)

    with pytest.raises(ToolError, match=r"^Remote eval failed"):
        await bridge.set_program_metadata(name="renamed.exe")


@pytest.mark.asyncio
async def test_set_program_metadata_wraps_an_unexpected_readback_error(dead_rpc_client: object) -> None:
    """A non-``ToolError`` failure of the readback is wrapped with the readback wording.

    Args:
        dead_rpc_client: Real RPC client attached so the bridge counts as connected.
    """
    bridge = _FailingReadbackBridge(dead_rpc_client, "scripted readback failure")

    with pytest.raises(ToolError) as excinfo:
        await bridge.set_program_metadata(name="renamed.exe")

    assert str(excinfo.value) == "Set program metadata readback failed: scripted readback failure"
    assert isinstance(excinfo.value.__cause__, RuntimeError)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("payload", "call", "message"),
    [(payload, call, message) for _, payload, call, message in _PAYLOAD_FAILURES],
    ids=[name for name, _, _, _ in _PAYLOAD_FAILURES],
)
async def test_a_failure_payload_from_ghidra_is_rejected_with_a_specific_error(
    dead_rpc_client: object,
    payload: object,
    call: _BridgeCall,
    message: str,
) -> None:
    """When Ghidra reports that it did not apply a change, the accessor raises instead of reporting success.

    Args:
        dead_rpc_client: Real RPC client attached so the bridge counts as connected.
        payload: What the remote script exchange reports back.
        call: Coroutine factory invoking the accessor.
        message: The exact error text the accessor must raise.
    """
    bridge = _PayloadBridge(dead_rpc_client, payload)

    with pytest.raises(ToolError, match=rf"^{re.escape(message)}$"):
        await call(bridge)


@pytest.mark.asyncio
async def test_add_external_function_returns_the_remote_payload(dead_rpc_client: object) -> None:
    """A dict answer from Ghidra is returned as the accessor's result.

    Args:
        dead_rpc_client: Real RPC client attached so the bridge counts as connected.
    """
    payload = {"library": "critcov.dll", "name": "CritcovExport", "address": 0x1000, "success": True}
    bridge = _PayloadBridge(dead_rpc_client, payload)

    assert await bridge.add_external_function("critcov.dll", "CritcovExport", 0x1000) == payload


@pytest.mark.asyncio
@pytest.mark.parametrize("address", [None, 0x1000], ids=["without-address", "with-address"])
async def test_add_external_function_reports_failure_when_ghidra_answers_nothing(dead_rpc_client: object, address: int | None) -> None:
    """Without a dict answer the accessor reports an unsuccessful result that echoes the request.

    Args:
        dead_rpc_client: Real RPC client attached so the bridge counts as connected.
        address: Optional address handed to the accessor.
    """
    bridge = _PayloadBridge(dead_rpc_client, None)

    result = await bridge.add_external_function("critcov.dll", "CritcovExport", address)

    assert result == {"library": "critcov.dll", "name": "CritcovExport", "address": address, "success": False}


@pytest.mark.asyncio
async def test_create_overlay_space_returns_the_remote_payload(dead_rpc_client: object) -> None:
    """A dict answer from Ghidra is returned as the overlay accessor's result.

    Args:
        dead_rpc_client: Real RPC client attached so the bridge counts as connected.
    """
    payload = {"name": "critcov_overlay", "success": True}
    bridge = _PayloadBridge(dead_rpc_client, payload)

    assert await bridge.create_overlay_space("critcov_overlay") == payload


@pytest.mark.asyncio
async def test_create_overlay_space_reports_failure_when_ghidra_answers_nothing(dead_rpc_client: object) -> None:
    """Without a dict answer the overlay accessor reports an unsuccessful result.

    Args:
        dead_rpc_client: Real RPC client attached so the bridge counts as connected.
    """
    bridge = _PayloadBridge(dead_rpc_client, None)

    assert await bridge.create_overlay_space("critcov_overlay") == {"name": "critcov_overlay", "success": False}


@pytest.mark.asyncio
async def test_execute_script_with_params_injects_the_params_dict(live_bridge: GhidraBridge) -> None:
    """The script sees the dict it was given as ``params`` and its last expression is returned.

    Args:
        live_bridge: Connected headless Ghidra bridge.
    """
    result = await live_bridge.execute_script_with_params('str(params["left"] + params["right"])', {"left": 19, "right": 23})

    assert result == "42"


@pytest.mark.asyncio
async def test_execute_script_with_params_injects_an_empty_dict_by_default(live_bridge: GhidraBridge) -> None:
    """Without parameters the script still gets an empty ``params`` dict.

    Args:
        live_bridge: Connected headless Ghidra bridge.
    """
    result = await live_bridge.execute_script_with_params("str(len(params))")

    assert result == "0"


@pytest.mark.asyncio
async def test_execute_script_with_params_preserves_quotes_and_newlines(live_bridge: GhidraBridge) -> None:
    """Text with quotes, backslashes and a newline survives the double JSON encoding unchanged.

    Args:
        live_bridge: Connected headless Ghidra bridge.
    """
    text = 'say "hi" \\ it\'s\nsecond line'

    result = await live_bridge.execute_script_with_params('params["text"]', {"text": text})

    assert result == text


@pytest.mark.asyncio
async def test_execute_script_with_params_returns_empty_text_for_a_statement_script(live_bridge: GhidraBridge) -> None:
    """A script with no trailing expression yields an empty string, yet its assignment took effect.

    Args:
        live_bridge: Connected headless Ghidra bridge.
    """
    result = await live_bridge.execute_script_with_params('critcov_param_probe = params["probe"] * 2', {"probe": 21})

    assert not result
    assert await live_bridge.execute_script("str(critcov_param_probe)") == "42"


@pytest.mark.asyncio
async def test_set_program_metadata_rejects_an_image_base_that_did_not_take(live_bridge: GhidraBridge) -> None:
    """When the program still reports its old image base, the requested one is refused.

    The write exchange is skipped, so the real readback from Ghidra shows the
    unchanged base, which is also read here directly from the program.

    Args:
        live_bridge: Connected headless Ghidra bridge.
    """
    original = int(await live_bridge.execute_script("currentProgram.getImageBase().getOffset()"))
    requested = original + _IMAGE_BASE_SHIFT
    bridge = _PayloadBridge(_rpc_client_of(live_bridge), None)

    with pytest.raises(ToolError) as excinfo:
        await bridge.set_program_metadata(image_base=requested)

    assert str(excinfo.value) == f"Program image base verification failed: expected {hex(requested)}, observed {hex(original)}"
    assert int(await live_bridge.execute_script("currentProgram.getImageBase().getOffset()")) == original


@pytest.mark.asyncio
async def test_get_thunk_info_reports_no_thunk_where_no_function_exists(live_bridge: GhidraBridge, entry_point: int) -> None:
    """An address inside no function yields a payload with no thunk and no target.

    Args:
        live_bridge: Connected headless Ghidra bridge.
        entry_point: Entry point address of the loaded program.
    """
    address = await _find_free_address(live_bridge, _slot_start(entry_point, 6))

    info = await live_bridge.get_thunk_info(address)

    assert info == {"address": address, "is_thunk": False, "thunked_function": None, "thunked_address": None}


@pytest.mark.asyncio
async def test_thunk_lifecycle_round_trips_through_ghidra(live_bridge: GhidraBridge, entry_point: int) -> None:
    """A function is turned into a thunk, reported as one, and turned back.

    Each step is confirmed by reading the function's thunk state directly from
    Ghidra rather than through the accessors under test.

    Args:
        live_bridge: Connected headless Ghidra bridge.
        entry_point: Entry point address of the loaded program.
    """
    thunk = await _create_function(live_bridge, entry_point, 1, "critcov_thunk_source")
    target = await _create_function(live_bridge, entry_point, 2, "critcov_thunk_target")
    assert await _thunk_state(live_bridge, thunk) == {"is_thunk": False, "target": None}

    added = await live_bridge.add_thunk(thunk, target)

    assert added == {"address": hex(thunk), "thunked_address": hex(target), "success": True}
    assert await _thunk_state(live_bridge, thunk) == {"is_thunk": True, "target": target}
    info = await live_bridge.get_thunk_info(thunk)
    assert info == {"address": thunk, "is_thunk": True, "thunked_function": "critcov_thunk_target", "thunked_address": target}

    removed = await live_bridge.remove_thunk(thunk)

    assert removed == {"address": hex(thunk), "success": True}
    assert await _thunk_state(live_bridge, thunk) == {"is_thunk": False, "target": None}
    after = await live_bridge.get_thunk_info(thunk)
    assert after == {"address": thunk, "is_thunk": False, "thunked_function": None, "thunked_address": None}


@pytest.mark.asyncio
async def test_add_thunk_refuses_a_target_that_is_not_a_function(live_bridge: GhidraBridge, entry_point: int) -> None:
    """A thunk cannot point at an address where no function exists, and nothing changes.

    Args:
        live_bridge: Connected headless Ghidra bridge.
        entry_point: Entry point address of the loaded program.
    """
    thunk = await _create_function(live_bridge, entry_point, 3, "critcov_orphan_thunk")
    missing = await _find_free_address(live_bridge, _slot_start(entry_point, 4))

    with pytest.raises(ToolError) as excinfo:
        await live_bridge.add_thunk(thunk, missing)

    assert str(excinfo.value) == f"{_FUNCTION_NOT_FOUND}: {hex(missing)}"
    assert await _thunk_state(live_bridge, thunk) == {"is_thunk": False, "target": None}


@pytest.mark.asyncio
async def test_remove_thunk_refuses_an_address_without_a_function(live_bridge: GhidraBridge, entry_point: int) -> None:
    """Clearing a thunk where no function exists is reported as a missing function.

    Args:
        live_bridge: Connected headless Ghidra bridge.
        entry_point: Entry point address of the loaded program.
    """
    missing = await _find_free_address(live_bridge, _slot_start(entry_point, 5))

    with pytest.raises(ToolError) as excinfo:
        await live_bridge.remove_thunk(missing)

    assert str(excinfo.value) == f"{_FUNCTION_NOT_FOUND}: {hex(missing)}"


@pytest.mark.asyncio
@pytest.mark.parametrize(("bookmark_type", "slot"), [("Note", 7), ("Warning", 8)], ids=["note", "warning"])
async def test_add_bookmark_stores_the_bookmark_in_the_program(
    live_bridge: GhidraBridge,
    entry_point: int,
    bookmark_type: str,
    slot: int,
) -> None:
    """The bookmark appears in Ghidra's bookmark manager with the requested type, category and text.

    Args:
        live_bridge: Connected headless Ghidra bridge.
        entry_point: Entry point address of the loaded program.
        bookmark_type: Bookmark type handed to the accessor.
        slot: Distinct slot number that picks the bookmark address.
    """
    address = await _find_free_address(live_bridge, _slot_start(entry_point, slot))

    result = await live_bridge.add_bookmark(address, "critcov-category", "critcov bookmark text", bookmark_type)

    assert result == {
        "address": hex(address),
        "category": "critcov-category",
        "comment": "critcov bookmark text",
        "bookmark_type": bookmark_type,
        "success": True,
    }
    stored = await _query(
        live_bridge,
        f"""
        import json
        marks = currentProgram.getBookmarkManager().getBookmarks(toAddr({address}))
        json.dumps([[str(mark.getTypeString()), str(mark.getCategory()), str(mark.getComment())] for mark in marks])
        """,
    )
    assert stored == [[bookmark_type, "critcov-category", "critcov bookmark text"]]


@pytest.mark.asyncio
async def test_external_reference_lifecycle_round_trips_through_ghidra(live_bridge: GhidraBridge, entry_point: int) -> None:
    """An external reference is added, listed with its library and name, and removed again.

    Args:
        live_bridge: Connected headless Ghidra bridge.
        entry_point: Entry point address of the loaded program.
    """
    address = await _find_free_address(live_bridge, _slot_start(entry_point, 9))
    assert await _external_reference_count(live_bridge, address) == 0

    added = await live_bridge.add_external_reference(address, "critcov_ref.dll", "CritcovExport")

    assert added == {"from_addr": hex(address), "library": "critcov_ref.dll", "name": "CritcovExport", "success": True}
    assert await _external_reference_count(live_bridge, address) == 1
    listed = await live_bridge.get_external_references(address)
    assert len(listed) == 1
    assert listed[0]["address"] == address
    assert listed[0]["external_name"] == "CritcovExport"
    assert listed[0]["library"] == "critcov_ref.dll"

    removed = await live_bridge.remove_external_reference(address)

    assert removed == {"from_addr": hex(address), "removed": 1, "success": True}
    assert await _external_reference_count(live_bridge, address) == 0
    assert await live_bridge.get_external_references(address) == []


@pytest.mark.asyncio
async def test_add_external_function_registers_the_function_in_the_program(live_bridge: GhidraBridge) -> None:
    """The external function appears under its library in Ghidra's external symbols.

    Ghidra writes to the program database only inside a transaction, so a
    script that does not open one cannot succeed against a real program.

    Args:
        live_bridge: Connected headless Ghidra bridge.
    """
    result = await live_bridge.add_external_function("critcov_func_lib.dll", "CritcovFunction")

    assert result == {"library": "critcov_func_lib.dll", "name": "CritcovFunction", "address": None, "success": True}
    pairs = await _query(
        live_bridge,
        """
        import json
        pairs = []
        for sym in currentProgram.getSymbolTable().getExternalSymbols():
            parent = sym.getParentSymbol()
            pairs.append([str(parent.getName()) if parent else '', str(sym.getName())])
        json.dumps(pairs)
        """,
    )
    assert ["critcov_func_lib.dll", "CritcovFunction"] in cast("list[list[str]]", pairs)


@pytest.mark.asyncio
async def test_create_overlay_space_adds_the_space_to_the_program(live_bridge: GhidraBridge) -> None:
    """The overlay space appears among the program's address spaces.

    Ghidra 12.1 creates overlay spaces through ``Program.createOverlaySpace``;
    its ``Memory`` interface has no such method.

    Args:
        live_bridge: Connected headless Ghidra bridge.
    """
    result = await live_bridge.create_overlay_space("critcov_overlay")

    assert result == {"name": "critcov_overlay", "success": True}
    names = await _query(
        live_bridge,
        """
        import json
        json.dumps([str(space.getName()) for space in currentProgram.getAddressFactory().getAllAddressSpaces()])
        """,
    )
    assert "critcov_overlay" in cast("list[str]", names)
