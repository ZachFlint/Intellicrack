# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-object coverage for the fifth slice of ``intellicrack.bridges.ghidra``.

The slice is what ``test_critcov_ghidra_01`` left uncovered in the analysis
accessors: the architecture resolution table, the payload checks of
``decompile``, ``search_bytes`` and the metadata sweep, and the handlers that
wrap an unexpected failure of the remote exchange or of a readback.

Three kinds of real object drive it:

* a genuine ``ghidra_bridge.GhidraBridge`` RPC client pointed at a closed
  loopback port, attached to every bridge so the bridge counts as connected;
* ``_ScriptedBridge``, a subclass of the real ``GhidraBridge`` that replaces only
  the two transport primitives with a queue of outcomes, so the accessor code
  around a remote call (error wrapping, payload validation, readback checks) runs
  unchanged against a chosen answer;
* one module-scoped headless Ghidra session, started once through PyGhidra on a
  private copy of a System32 executable and shut down in ``finally``. Expected
  values for the live searches come from ``pefile`` and from a brute-force scan
  of Ghidra's own memory blocks, a path independent of ``Memory.findBytes``.
"""

from __future__ import annotations

import asyncio
import importlib
import io
import json
import os
import shutil
import socket
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


pytestmark = pytest.mark.spawns_process

_LIVE_STEP_TIMEOUT_SECONDS: Final[float] = 600.0
_FAILURE_TEXT: Final[str] = "scripted failure"
_TYPED_FAILURE_TEXT: Final[str] = "scripted typed failure"
_HIGH_BIT: Final[int] = 0x80
_PE_SIGNATURE_PROBE_LENGTH: Final[int] = 12
_ABSENT_NEEDLE: Final[bytes] = b"critcov-absent-needle-0123456789"

_BridgeCall = Callable[[GhidraBridge], Awaitable[object]]

_ARCH_CASES: Final[list[tuple[str, int, tuple[str, bool]]]] = [
    ("AARCH64", 8, ("arm64", True)),
    ("ARM", 8, ("arm64", True)),
    ("ARM", 4, ("arm", False)),
    ("MIPS", 4, ("mips", False)),
    ("MIPS", 8, ("mips64", True)),
    ("PowerPC", 4, ("ppc", False)),
    ("PowerPC", 8, ("ppc64", True)),
    ("PPC", 4, ("ppc", False)),
    ("RISCV", 4, ("riscv", False)),
    ("RISCV", 8, ("riscv64", True)),
    ("RISC-V", 8, ("riscv64", True)),
    ("sparc", 4, ("sparc", False)),
    ("SPARC", 8, ("sparc64", True)),
    ("AVR8", 2, ("avr8", False)),
    ("Xtensa", 8, ("xtensa", True)),
]

_UNUSABLE_ARCH_PAYLOADS: Final[list[tuple[str, object]]] = [
    ("no-payload", None),
    ("text", "x86"),
    ("list", [1]),
    ("empty-processor", {"processor": "", "pointer_size": 8}),
    ("unknown-processor", {"processor": "Unknown", "pointer_size": 8}),
    ("missing-processor", {"pointer_size": 8}),
]

_NON_DICT_PAYLOADS: Final[list[tuple[str, object]]] = [
    ("no-payload", None),
    ("text", "plain text"),
    ("list", [1, 2]),
]

_EMPTY_DECOMPILE_PAYLOADS: Final[list[tuple[str, object]]] = [
    ("empty-code", {"status": "ok", "code": ""}),
    ("null-code", {"status": "ok", "code": None}),
    ("missing-code", {"status": "ok"}),
    ("non-text-code", {"status": "ok", "code": 42}),
]

_UNEXPECTED_FAILURE_CALLS: Final[list[tuple[str, _BridgeCall, str]]] = [
    ("analyze_kickoff", lambda bridge: bridge.analyze(), f"Analysis failed: {_FAILURE_TEXT}"),
    ("get_functions", lambda bridge: bridge.get_functions(), f"Get functions failed: {_FAILURE_TEXT}"),
    ("get_function", lambda bridge: bridge.get_function(0x1000), f"Get function failed: {_FAILURE_TEXT}"),
    ("decompile", lambda bridge: bridge.decompile(0x1000), f"Decompilation failed: {_FAILURE_TEXT}"),
    ("disassemble", lambda bridge: bridge.disassemble(0x1000, 3), f"Disassembly failed at 0x1000: {_FAILURE_TEXT}"),
    ("get_xrefs_to", lambda bridge: bridge.get_xrefs_to(0x1000), f"Get xrefs to failed at 0x1000: {_FAILURE_TEXT}"),
    ("get_xrefs_from", lambda bridge: bridge.get_xrefs_from(0x1000), f"Get xrefs from failed at 0x1000: {_FAILURE_TEXT}"),
    ("search_strings", lambda bridge: bridge.search_strings("needle"), f"String search failed for 'needle': {_FAILURE_TEXT}"),
    (
        "search_bytes_hex",
        lambda bridge: bridge.search_bytes(hex_pattern="4D 5A"),
        f"Byte search (hex/wildcard) failed: {_FAILURE_TEXT}",
    ),
    ("search_bytes_raw", lambda bridge: bridge.search_bytes(b"MZ"), f"Byte search failed: {_FAILURE_TEXT}"),
    ("rename_function", lambda bridge: bridge.rename_function(0x1000, "renamed"), f"Rename failed: {_FAILURE_TEXT}"),
    ("add_comment", lambda bridge: bridge.add_comment(0x1000, "note"), f"Add comment failed: {_FAILURE_TEXT}"),
    ("remove_comment", lambda bridge: bridge.remove_comment(0x1000), f"Remove comment failed: {_FAILURE_TEXT}"),
    ("get_imports", lambda bridge: bridge.get_imports(), f"Get imports failed: {_FAILURE_TEXT}"),
    ("get_exports", lambda bridge: bridge.get_exports(), f"Get exports failed: {_FAILURE_TEXT}"),
    ("get_data_type", lambda bridge: bridge.get_data_type(0x1000), f"Get data type failed at 0x1000: {_FAILURE_TEXT}"),
]

_READBACK_CALLS: Final[list[tuple[str, _BridgeCall, str]]] = [
    ("analyze_poll", lambda bridge: bridge.analyze(), f"Analysis failed: {_FAILURE_TEXT}"),
    ("rename_function", lambda bridge: bridge.rename_function(0x1000, "renamed"), f"Rename readback failed: {_FAILURE_TEXT}"),
    ("add_comment", lambda bridge: bridge.add_comment(0x1000, "note"), f"Add comment readback failed: {_FAILURE_TEXT}"),
    ("remove_comment", lambda bridge: bridge.remove_comment(0x1000), f"Remove comment readback failed: {_FAILURE_TEXT}"),
]


@dataclass(frozen=True)
class _PeFacts:
    """Header facts of a PE file, read with ``pefile`` independently of Ghidra.

    Attributes:
        image_base: The preferred load address from the optional header.
        header_offset: File offset of the four-byte PE signature.
    """

    image_base: int
    header_offset: int


class _ScriptedBridge(GhidraBridge):
    """Real Ghidra bridge whose remote exchange replays scripted outcomes.

    Only ``_execute_remote`` and ``_execute_remote_eval`` are replaced. Each call
    takes the next outcome from its queue: an exception instance is raised, any
    other value is returned. Every accessor around the exchange runs unchanged.
    """

    def __init__(
        self,
        client: object,
        exec_outcomes: Sequence[object] = (),
        eval_outcomes: Sequence[object] = (),
    ) -> None:
        """Attach the RPC client and remember the scripted outcomes.

        Args:
            client: Real RPC client attached so the bridge counts as connected.
            exec_outcomes: Outcomes for successive ``_execute_remote`` calls.
            eval_outcomes: Outcomes for successive ``_execute_remote_eval`` calls.
        """
        super().__init__()
        self.attach_remote_bridge(client)
        self.exec_outcomes: list[object] = list(exec_outcomes)
        self.eval_outcomes: list[object] = list(eval_outcomes)

    async def _execute_remote(self, code: str) -> object:
        """Replay the next scripted outcome instead of running ``code`` remotely.

        Args:
            code: Jython source the accessor would have dispatched; ignored.

        Returns:
            object: The next scripted value.
        """
        del code
        return _replay(self.exec_outcomes)

    async def _execute_remote_eval(self, expression: str) -> object:
        """Replay the next scripted outcome instead of evaluating ``expression``.

        Args:
            expression: Jython expression the accessor would have evaluated; ignored.

        Returns:
            object: The next scripted value.
        """
        del expression
        return _replay(self.eval_outcomes)


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


def _method(obj: object, name: str) -> Callable[..., object]:
    """Resolve a (possibly private) synchronous method or static method by name.

    Args:
        obj: Instance or class that owns the attribute.
        name: Attribute name to look up.

    Returns:
        Callable[..., object]: The bound callable.
    """
    return cast("Callable[..., object]", getattr(obj, name))


def _async_method(obj: object, name: str) -> Callable[..., Awaitable[object]]:
    """Resolve a (possibly private) coroutine method by name.

    Args:
        obj: Instance that owns the attribute.
        name: Attribute name to look up.

    Returns:
        Callable[..., Awaitable[object]]: The bound coroutine function.
    """
    return cast("Callable[..., Awaitable[object]]", getattr(obj, name))


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
    """Read the load address and signature offset of a PE file.

    Args:
        path: PE file to parse.

    Returns:
        _PeFacts: The header facts.
    """
    parsed = pefile.PE(data=path.read_bytes(), fast_load=True)
    try:
        return _PeFacts(
            image_base=int(parsed.OPTIONAL_HEADER.ImageBase),
            header_offset=int(parsed.DOS_HEADER.e_lfanew),
        )
    finally:
        parsed.close()


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


async def _scan_program_memory(bridge: GhidraBridge, needle: bytes) -> list[int]:
    """Find every occurrence of a byte string by scanning Ghidra's initialized blocks.

    The scan reads each block's bytes through the flat API and searches them with
    ``bytes.find``, so it shares no code with ``Memory.findBytes``.

    Args:
        bridge: Live bridge that runs the scan script.
        needle: Byte string to look for.

    Returns:
        list[int]: Ascending addresses at which ``needle`` starts.
    """
    answer = await _query(
        bridge,
        f"""
        import json
        needle = bytes({list(needle)})
        hits = []
        for block in currentProgram.getMemory().getBlocks():
            if not block.isInitialized():
                continue
            start = block.getStart()
            content = bytes(int(value) & 0xFF for value in getBytes(start, int(block.getSize())))
            position = content.find(needle)
            while position != -1:
                hits.append(int(start.getOffset()) + position)
                position = content.find(needle, position + 1)
        json.dumps(sorted(hits))
        """,
    )
    return [int(address) for address in cast("list[int]", answer)]


@pytest.fixture(scope="module")
def dead_rpc_client() -> Iterator[object]:
    """Provide a real ``ghidra_bridge`` client aimed at a closed loopback port.

    Yields:
        object: The RPC client instance.
    """
    client = _make_rpc_client(_reserve_free_port())
    try:
        yield client
    finally:
        _method(GhidraBridge, "_close_bridge_client")(client)


@pytest.fixture(scope="module")
def live_target(real_pe_exe: Path, tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    """Copy a System32 executable to a private directory for Ghidra to import.

    Args:
        real_pe_exe: Real PE executable resolved from System32.
        tmp_path_factory: Pytest factory for the private directory.

    Yields:
        Path: The private copy; the System32 original is never touched.
    """
    directory = tmp_path_factory.mktemp("critcov_ghidra_05_binary")
    target = directory / "critcov_target.exe"
    shutil.copyfile(real_pe_exe, target)
    try:
        yield target
    finally:
        shutil.rmtree(directory, ignore_errors=True)


@pytest.fixture(scope="module")
def target_bytes(live_target: Path) -> bytes:
    """Read the bytes of the imported copy straight from disk.

    Args:
        live_target: The executable copy Ghidra imports.

    Returns:
        bytes: The whole file content.
    """
    return live_target.read_bytes()


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
def live_bridge(live_target: Path, tmp_path_factory: pytest.TempPathFactory) -> Iterator[GhidraBridge]:
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
    project_dir = tmp_path_factory.mktemp("critcov_ghidra_05_project")
    try:
        try:
            asyncio.run(asyncio.wait_for(bridge.start_headless(project_dir, "critcov_ghidra_05"), timeout=_LIVE_STEP_TIMEOUT_SECONDS))
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


def test_drain_stream_logs_a_pipe_that_cannot_be_closed(tmp_path: Path) -> None:
    """A stream whose descriptor is already gone fails to read and to close; both are logged.

    Args:
        tmp_path: Pytest temporary directory holding the file behind the stream.
    """
    source = tmp_path / "drained.bin"
    source.write_bytes(b"first line\n")
    descriptor = os.open(source, os.O_RDONLY | os.O_BINARY)
    stream = io.BufferedReader(io.FileIO(descriptor, "rb", closefd=True))
    os.close(descriptor)
    collected: list[str] = []

    with capture_logs() as events:
        result = _method(GhidraBridge, "_drain_stream")(stream, "stdout", collected.append)

    assert result is None
    assert collected == []
    terminated = _events_named(events, "ghidra_pipe_drain_terminated")
    assert len(terminated) == 1
    assert terminated[0]["stream"] == "stdout"
    failures = _events_named(events, "ghidra_pipe_close_failed")
    assert len(failures) == 1
    assert failures[0]["stream"] == "stdout"
    assert failures[0]["log_level"] == "warning"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("processor", "pointer_size", "expected"),
    _ARCH_CASES,
    ids=[f"{processor}-{pointer_size}" for processor, pointer_size, _ in _ARCH_CASES],
)
async def test_query_ghidra_arch_names_the_processor_family(
    dead_rpc_client: object,
    processor: str,
    pointer_size: int,
    expected: tuple[str, bool],
) -> None:
    """The processor Ghidra reports is mapped to a canonical architecture name and bitness.

    Args:
        dead_rpc_client: Real RPC client attached so the bridge counts as connected.
        processor: Processor name Ghidra reports for the program.
        pointer_size: Default address-space pointer size in bytes.
        expected: The architecture name and 64-bit flag the family maps to.
    """
    bridge = _ScriptedBridge(dead_rpc_client, [{"processor": processor, "pointer_size": pointer_size}])

    assert await _async_method(bridge, "_query_ghidra_arch")() == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [payload for _, payload in _UNUSABLE_ARCH_PAYLOADS],
    ids=[name for name, _ in _UNUSABLE_ARCH_PAYLOADS],
)
async def test_query_ghidra_arch_is_none_without_a_usable_answer(dead_rpc_client: object, payload: object) -> None:
    """A reply that is not a dict, or names no real processor, yields no architecture.

    Args:
        dead_rpc_client: Real RPC client attached so the bridge counts as connected.
        payload: What the remote script exchange reports back.
    """
    bridge = _ScriptedBridge(dead_rpc_client, [payload])

    assert await _async_method(bridge, "_query_ghidra_arch")() is None


@pytest.mark.asyncio
async def test_query_ghidra_arch_logs_an_unexpected_error_and_reports_none(dead_rpc_client: object) -> None:
    """A non-``ToolError`` failure of the query is logged with its traceback and reported as ``None``.

    Args:
        dead_rpc_client: Real RPC client attached so the bridge counts as connected.
    """
    bridge = _ScriptedBridge(dead_rpc_client, [RuntimeError(_FAILURE_TEXT)])

    with capture_logs() as events:
        result = await _async_method(bridge, "_query_ghidra_arch")()

    assert result is None
    failures = _events_named(events, "ghidra_arch_query_failed")
    assert len(failures) == 1
    assert failures[0]["log_level"] == "error"
    assert not _events_named(events, "ghidra_arch_query_tool_error")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [payload for _, payload in _NON_DICT_PAYLOADS],
    ids=[name for name, _ in _NON_DICT_PAYLOADS],
)
async def test_extract_binary_metadata_is_empty_when_ghidra_answers_with_a_non_dict(dead_rpc_client: object, payload: object) -> None:
    """A metadata reply that is not a dict yields the same four empty values as no bridge.

    Args:
        dead_rpc_client: Real RPC client attached so the bridge counts as connected.
        payload: What the remote script exchange reports back.
    """
    bridge = _ScriptedBridge(dead_rpc_client, [payload])

    assert await _async_method(bridge, "_extract_binary_metadata")() == (0, [], [], [])


@pytest.mark.asyncio
async def test_load_binary_wraps_an_unexpected_import_failure(dead_rpc_client: object, real_pe_exe: Path) -> None:
    """A non-``ToolError`` failure of the remote import is wrapped and keeps its cause.

    Args:
        dead_rpc_client: Real RPC client attached so the bridge counts as connected.
        real_pe_exe: Real PE executable whose bytes ``load_binary`` would hash.
    """
    failure = RuntimeError(_FAILURE_TEXT)
    bridge = _ScriptedBridge(dead_rpc_client, [failure])

    with pytest.raises(ToolError) as excinfo:
        await bridge.load_binary(real_pe_exe)

    assert str(excinfo.value) == f"Failed to import binary into Ghidra: {_FAILURE_TEXT}"
    assert excinfo.value.__cause__ is failure
    assert bridge.state.binary_loaded is False


@pytest.mark.asyncio
async def test_load_binary_records_a_failed_metadata_extraction(dead_rpc_client: object, real_pe_exe: Path) -> None:
    """A metadata reply that cannot be parsed marks the load as failed and reports why.

    The import succeeds; the metadata reply carries an entry point that is not a
    number, so building the result raises ``ValueError``.

    Args:
        dead_rpc_client: Real RPC client attached so the bridge counts as connected.
        real_pe_exe: Real PE executable whose bytes ``load_binary`` would hash.
    """
    bridge = _ScriptedBridge(
        dead_rpc_client,
        [{"imported": True, "name": real_pe_exe.name}, {"entry_point": "not-a-number"}],
    )

    with pytest.raises(ToolError) as excinfo:
        await bridge.load_binary(real_pe_exe)

    cause = excinfo.value.__cause__
    assert isinstance(cause, ValueError)
    assert str(excinfo.value) == f"Ghidra metadata extraction failed: {cause}"
    assert bridge.state.binary_loaded is False
    assert bridge.state.target_path is None
    assert bridge.state.last_error == str(cause)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("name", "call", "message"),
    _UNEXPECTED_FAILURE_CALLS,
    ids=[name for name, _, _ in _UNEXPECTED_FAILURE_CALLS],
)
async def test_an_unexpected_remote_failure_is_wrapped_with_the_accessor_wording(
    dead_rpc_client: object,
    name: str,
    call: _BridgeCall,
    message: str,
) -> None:
    """A non-``ToolError`` failure of the remote exchange is wrapped and keeps its cause.

    Args:
        dead_rpc_client: Real RPC client attached so the bridge counts as connected.
        name: Accessor name, used for the test id.
        call: Coroutine factory invoking the accessor.
        message: The exact error text the accessor's generic handler writes.
    """
    failure = RuntimeError(_FAILURE_TEXT)
    bridge = _ScriptedBridge(dead_rpc_client, [failure])

    with pytest.raises(ToolError) as excinfo:
        await call(bridge)

    assert str(excinfo.value) == message, name
    assert excinfo.value.__cause__ is failure


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("name", "call", "message"),
    _READBACK_CALLS,
    ids=[name for name, _, _ in _READBACK_CALLS],
)
async def test_an_unexpected_readback_failure_is_wrapped_with_the_accessor_wording(
    dead_rpc_client: object,
    name: str,
    call: _BridgeCall,
    message: str,
) -> None:
    """A non-``ToolError`` failure of the verification step is wrapped and keeps its cause.

    The write exchange succeeds; only the readback or polling evaluation fails.

    Args:
        dead_rpc_client: Real RPC client attached so the bridge counts as connected.
        name: Accessor name, used for the test id.
        call: Coroutine factory invoking the accessor.
        message: The exact error text the accessor's readback handler writes.
    """
    failure = RuntimeError(_FAILURE_TEXT)
    bridge = _ScriptedBridge(dead_rpc_client, [None], [failure])

    with pytest.raises(ToolError) as excinfo:
        await call(bridge)

    assert str(excinfo.value) == message, name
    assert excinfo.value.__cause__ is failure


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("name", "call"),
    [(name, call) for name, call, _ in _READBACK_CALLS],
    ids=[name for name, _, _ in _READBACK_CALLS],
)
async def test_a_typed_readback_failure_reaches_the_caller_unchanged(dead_rpc_client: object, name: str, call: _BridgeCall) -> None:
    """A ``ToolError`` from the verification step is re-raised as is, not re-wrapped.

    Args:
        dead_rpc_client: Real RPC client attached so the bridge counts as connected.
        name: Accessor name, used for the test id.
        call: Coroutine factory invoking the accessor.
    """
    typed = ToolError(_TYPED_FAILURE_TEXT)
    bridge = _ScriptedBridge(dead_rpc_client, [None], [typed])

    with pytest.raises(ToolError) as excinfo:
        await call(bridge)

    assert excinfo.value is typed, name
    assert str(excinfo.value) == _TYPED_FAILURE_TEXT


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [payload for _, payload in _NON_DICT_PAYLOADS],
    ids=[name for name, _ in _NON_DICT_PAYLOADS],
)
async def test_decompile_rejects_a_reply_that_is_not_a_dict(dead_rpc_client: object, payload: object) -> None:
    """A decompiler outcome that is not a dict is reported as an unexpected response.

    Args:
        dead_rpc_client: Real RPC client attached so the bridge counts as connected.
        payload: What the remote script exchange reports back.
    """
    bridge = _ScriptedBridge(dead_rpc_client, [payload])

    with pytest.raises(ToolError) as excinfo:
        await bridge.decompile(0x1000)

    assert str(excinfo.value) == "Decompilation failed: unexpected response from Ghidra"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [payload for _, payload in _EMPTY_DECOMPILE_PAYLOADS],
    ids=[name for name, _ in _EMPTY_DECOMPILE_PAYLOADS],
)
async def test_decompile_rejects_a_successful_outcome_without_code(dead_rpc_client: object, payload: object) -> None:
    """A decompiler that reports success but delivers no text is an error, not an empty result.

    Args:
        dead_rpc_client: Real RPC client attached so the bridge counts as connected.
        payload: What the remote script exchange reports back.
    """
    bridge = _ScriptedBridge(dead_rpc_client, [payload])

    with pytest.raises(ToolError) as excinfo:
        await bridge.decompile(0x1000)

    assert str(excinfo.value) == "Decompilation produced empty output"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [None, "not a list", {"address": 4096}],
    ids=["no-payload", "text", "dict"],
)
async def test_search_bytes_returns_no_addresses_when_ghidra_answers_with_a_non_list(dead_rpc_client: object, payload: object) -> None:
    """A raw-byte search whose reply is not a list reports no matches.

    Args:
        dead_rpc_client: Real RPC client attached so the bridge counts as connected.
        payload: What the remote script exchange reports back.
    """
    bridge = _ScriptedBridge(dead_rpc_client, [payload])

    assert await bridge.search_bytes(b"MZ") == []


@pytest.mark.asyncio
async def test_search_bytes_converts_every_reported_address_to_an_integer(dead_rpc_client: object) -> None:
    """Addresses reported as integers, numeric text or floats all come back as integers in order.

    Args:
        dead_rpc_client: Real RPC client attached so the bridge counts as connected.
    """
    bridge = _ScriptedBridge(dead_rpc_client, [[4096, "8192", 12288.0]])

    found = await bridge.search_bytes(b"MZ")

    assert found == [4096, 8192, 12288]
    assert all(type(address) is int for address in found)


@pytest.mark.asyncio
async def test_search_bytes_finds_every_occurrence_of_the_pe_signature(
    live_bridge: GhidraBridge,
    target_bytes: bytes,
    pe_facts: _PeFacts,
) -> None:
    """A raw search for the PE signature returns the addresses a brute-force memory scan finds.

    The signature offset comes from ``pefile``; the headers map one to one at the
    image base, so the signature must be reported there.

    Args:
        live_bridge: Connected headless Ghidra bridge.
        target_bytes: Content of the executable copy Ghidra imported.
        pe_facts: Header facts of that copy, read with ``pefile``.
    """
    needle = b"PE\x00\x00"
    start = pe_facts.header_offset
    assert target_bytes[start : start + len(needle)] == needle
    expected = await _scan_program_memory(live_bridge, needle)

    found = await live_bridge.search_bytes(needle)

    assert found == expected
    assert pe_facts.image_base + pe_facts.header_offset in found
    assert found == sorted(found)


@pytest.mark.asyncio
async def test_search_bytes_finds_a_raw_pattern_made_of_high_bit_bytes(
    live_bridge: GhidraBridge,
    target_bytes: bytes,
    pe_facts: _PeFacts,
) -> None:
    """A raw search whose bytes include values of 0x80 and above still finds the pattern.

    The pattern is the PE signature, machine type, section count and timestamp
    read from the file; a 64-bit image carries 0x86 in its machine type.

    Args:
        live_bridge: Connected headless Ghidra bridge.
        target_bytes: Content of the executable copy Ghidra imported.
        pe_facts: Header facts of that copy, read with ``pefile``.
    """
    start = pe_facts.header_offset
    needle = target_bytes[start : start + _PE_SIGNATURE_PROBE_LENGTH]
    assert len(needle) == _PE_SIGNATURE_PROBE_LENGTH
    assert any(value >= _HIGH_BIT for value in needle)
    expected = await _scan_program_memory(live_bridge, needle)
    assert pe_facts.image_base + pe_facts.header_offset in expected

    found = await live_bridge.search_bytes(needle)

    assert found == expected


@pytest.mark.asyncio
async def test_search_bytes_reports_nothing_for_a_pattern_the_program_lacks(live_bridge: GhidraBridge, target_bytes: bytes) -> None:
    """A raw search for bytes that are not in the program returns an empty list.

    Args:
        live_bridge: Connected headless Ghidra bridge.
        target_bytes: Content of the executable copy Ghidra imported.
    """
    assert _ABSENT_NEEDLE not in target_bytes

    assert await live_bridge.search_bytes(_ABSENT_NEEDLE) == []
