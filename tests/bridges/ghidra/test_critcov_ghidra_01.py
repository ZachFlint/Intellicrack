# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-object coverage for the first slice of ``intellicrack.bridges.ghidra``.

The slice covers the script-rewriting helpers, the path validators, the Win32
job-object and project-lock helpers, the headless-launch plumbing (JDK
discovery, drain threads, bridge-script deployment, port polling), the
architecture resolution, and the ``except ToolError: raise`` and not-connected
guards of the read and edit accessors.

Three kinds of real object stand in for a running Ghidra:

* a genuine ``ghidra_bridge.GhidraBridge`` RPC client pointed at a closed
  loopback port, attached through ``attach_remote_bridge``, so every remote
  call fails the way a vanished Ghidra peer does;
* real temporary directory trees, real pipes and real child processes for the
  filesystem and process helpers;
* one module-scoped headless Ghidra session, started once through PyGhidra and
  shut down in ``finally``, behind the ``live_session`` fixture. Only the tests
  that need a live program use it; every other test passes without it.
"""

from __future__ import annotations

import ast
import asyncio
import importlib
import io
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
from collections.abc import Awaitable, Callable, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

import pytest
from structlog.testing import capture_logs

from intellicrack.bridges import ghidra as ghidra_module
from intellicrack.bridges.ghidra import GhidraBridge, prepare_remote_script
from intellicrack.core.types import ToolError
from tests._helpers.process_cleanup import ManagedProcess


if TYPE_CHECKING:
    from collections.abc import Iterator


pytestmark = pytest.mark.spawns_process

_LIVE_STEP_TIMEOUT_SECONDS: Final[float] = 600.0
_PE_MACHINE_TO_ARCH: Final[dict[int, tuple[str, bool]]] = {
    0x8664: ("x86_64", True),
    0x14C: ("x86", False),
}
_DOS_E_LFANEW_OFFSET: Final[int] = 0x3C
_PE_MACHINE_OFFSET_FROM_SIGNATURE: Final[int] = 4
_REMOTE_FAILURE_PATTERN: Final[str] = r"^Remote execution failed"
_STDERR_MARKER: Final[str] = "critcov-stderr-line"

_BridgeCall = Callable[[GhidraBridge], Awaitable[object]]

_DEAD_PEER_CALLS: Final[list[tuple[str, _BridgeCall]]] = [
    ("get_functions", lambda bridge: bridge.get_functions()),
    ("get_function", lambda bridge: bridge.get_function(0x1000)),
    ("disassemble", lambda bridge: bridge.disassemble(0x1000, 3)),
    ("get_xrefs_to", lambda bridge: bridge.get_xrefs_to(0x1000)),
    ("get_xrefs_from", lambda bridge: bridge.get_xrefs_from(0x1000)),
    ("search_strings", lambda bridge: bridge.search_strings("needle")),
    ("search_bytes_hex", lambda bridge: bridge.search_bytes(hex_pattern="4D 5A")),
    ("search_bytes_hex_positional", lambda bridge: bridge.search_bytes("4D 5A")),
    ("search_bytes_raw", lambda bridge: bridge.search_bytes(b"MZ")),
    ("search_bytes_none", lambda bridge: bridge.search_bytes()),
    ("rename_function", lambda bridge: bridge.rename_function(0x1000, "renamed")),
    ("add_comment", lambda bridge: bridge.add_comment(0x1000, "note")),
    ("remove_comment", lambda bridge: bridge.remove_comment(0x1000)),
    ("get_imports", lambda bridge: bridge.get_imports()),
    ("get_exports", lambda bridge: bridge.get_exports()),
    ("get_data_type", lambda bridge: bridge.get_data_type(0x1000)),
]

_UNCONNECTED_CALLS: Final[list[tuple[str, _BridgeCall]]] = [
    ("rename_function", lambda bridge: bridge.rename_function(0x1000, "renamed")),
    ("add_comment", lambda bridge: bridge.add_comment(0x1000, "note")),
    ("remove_comment", lambda bridge: bridge.remove_comment(0x1000)),
]


def _module_fn(name: str) -> Callable[..., object]:
    """Resolve a module-level helper of the Ghidra bridge by name.

    Args:
        name: Attribute name inside ``intellicrack.bridges.ghidra``.

    Returns:
        Callable[..., object]: The helper, typed as a generic callable.
    """
    return cast("Callable[..., object]", getattr(ghidra_module, name))


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


def _attr(obj: object, name: str) -> object:
    """Read a (possibly private) data attribute by name.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name to read.

    Returns:
        object: The attribute value.
    """
    return getattr(obj, name)


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


def _sleeper_argv() -> list[str]:
    """Build the argv of a disposable child that outlives every assertion here.

    Returns:
        list[str]: Interpreter command line that sleeps for two minutes.
    """
    return [sys.executable, "-c", "import time; time.sleep(120)"]


def _block_until_eof(peer: socket.socket) -> None:
    """Block on a socket until its other end is closed.

    Args:
        peer: Connected socket whose partner will be closed by the test.
    """
    _ = peer.recv(1)


def _do_nothing() -> None:
    """Return immediately; used as the target of a thread that is never started."""


def _events_named(events: Sequence[Mapping[str, object]], name: str) -> list[Mapping[str, object]]:
    """Filter captured structlog events by event name.

    Args:
        events: Events captured with ``structlog.testing.capture_logs``.
        name: Event name to keep.

    Returns:
        list[Mapping[str, object]]: The matching events in emission order.
    """
    return [event for event in events if event.get("event") == name]


def _pe_machine(path: Path) -> int:
    """Read the COFF ``Machine`` field of a PE file with ``struct``.

    Args:
        path: PE file to inspect.

    Returns:
        int: The 16-bit machine code from the PE file header.
    """
    data = path.read_bytes()
    (e_lfanew,) = struct.unpack_from("<I", data, _DOS_E_LFANEW_OFFSET)
    (machine,) = struct.unpack_from("<H", data, e_lfanew + _PE_MACHINE_OFFSET_FROM_SIGNATURE)
    return int(machine)


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
        _method(GhidraBridge, "_close_bridge_client")(client)


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


@pytest.fixture
def listener() -> Iterator[tuple[socket.socket, int]]:
    """Provide a real loopback listener that accepts TCP connections.

    Yields:
        tuple[socket.socket, int]: The listening socket and its port.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        yield sock, int(sock.getsockname()[1])
    finally:
        sock.close()


@pytest.fixture(scope="module")
def live_session(real_pe_exe: Path, tmp_path_factory: pytest.TempPathFactory) -> Iterator[GhidraBridge]:
    """Start one headless Ghidra session on a real System32 binary.

    The JVM can start only once per process, so this is the single place the
    module starts it. The session is shut down in ``finally`` even when the
    start fails halfway.

    Args:
        real_pe_exe: Real PE executable resolved from System32.
        tmp_path_factory: Pytest factory for the Ghidra project directory.

    Yields:
        GhidraBridge: A connected bridge with ``real_pe_exe`` imported.
    """
    install_text = os.environ.get("GHIDRA_INSTALL_DIR", "").strip()
    if not install_text:
        pytest.fail("GHIDRA_INSTALL_DIR is not set, so the container does not name a Ghidra installation", pytrace=False)
    bridge = GhidraBridge()
    bridge.set_port(_reserve_free_port())
    bridge.ghidra_path = Path(install_text)
    project_dir = tmp_path_factory.mktemp("critcov_ghidra_01_project")
    try:
        try:
            asyncio.run(asyncio.wait_for(bridge.start_headless(project_dir, "critcov_ghidra_01"), timeout=_LIVE_STEP_TIMEOUT_SECONDS))
            asyncio.run(asyncio.wait_for(bridge.load_binary(real_pe_exe), timeout=_LIVE_STEP_TIMEOUT_SECONDS))
        except (ToolError, OSError) as exc:
            pytest.fail(
                f"Headless Ghidra could not start or import {real_pe_exe} inside this container "
                f"(install {install_text}): {type(exc).__name__}: {exc}",
                pytrace=False,
            )
        yield bridge
    finally:
        asyncio.run(bridge.shutdown())


@pytest.fixture
def text_file(tmp_path: Path) -> Path:
    """Write a plain text file that no Ghidra loader recognizes.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        Path: Path of the text file.
    """
    path = tmp_path / "plain_notes.txt"
    path.write_text("These are meeting notes, not an executable image.\n" * 8, encoding="utf-8")
    return path


@pytest.fixture
def sample_file(tmp_path: Path) -> Path:
    """Write a small file for ``load_binary`` to find on disk.

    Args:
        tmp_path: Pytest temporary directory.

    Returns:
        Path: Path of the sample file.
    """
    path = tmp_path / "sample.bin"
    path.write_bytes(b"MZ" + b"\x00" * 62)
    return path


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("first = second = 1\n", None),
        ("holder.attr = 1\n", None),
        ("left, right = 1, 2\n", None),
        ("value = 1\n", "value"),
        ("if cond:\n    a = 1\nelse:\n    b = 2\n", None),
        ("if cond:\n    a = 1\nelse:\n    print(2)\n", None),
        ("if cond:\n    a = 1\nelse:\n    a = 2\n", "a"),
        ("if cond:\n    a = 1\n", None),
        ("try:\n    a = 1\nexcept Exception:\n    b = 2\n", "a"),
        ("print(1)\n", None),
    ],
    ids=[
        "multiple-targets",
        "attribute-target",
        "tuple-target",
        "plain-assignment",
        "if-else-different-names",
        "if-else-non-assignment-tail",
        "if-else-same-name",
        "if-without-else",
        "try-body-only",
        "expression-tail",
    ],
)
def test_find_trailing_result_name_follows_the_documented_tail_rules(source: str, expected: str | None) -> None:
    """The tail resolver returns a name only when every path ends in the same single assignment.

    The expectations come from the helper's documented contract: one plain name
    target resolves, an ``if`` needs an ``else`` and equal names on both sides,
    a ``try`` resolves from its body, anything else is unresolved.

    Args:
        source: Python source whose top-level statements are inspected.
        expected: The documented result for that tail.
    """
    assert _module_fn("_find_trailing_result_name")(ast.parse(source).body) == expected


def test_find_trailing_result_name_is_none_for_an_empty_suite() -> None:
    """An empty statement suite has no trailing result."""
    assert _module_fn("_find_trailing_result_name")([]) is None


def test_prepare_remote_script_keeps_a_comment_only_script_unchanged() -> None:
    """A script with comments but no statements is returned dedented with no sentinel."""
    rewritten, sentinel = prepare_remote_script("    # nothing to run here\n")

    assert rewritten == "# nothing to run here"
    assert sentinel is None


def test_prepare_remote_script_leaves_a_divergent_if_else_tail_alone() -> None:
    """An if/else whose branches assign different names cannot be captured, so no sentinel is made."""
    script = "if flag:\n    left = 1\nelse:\n    right = 2\n"

    rewritten, sentinel = prepare_remote_script(script)

    assert rewritten == script.strip("\n")
    assert sentinel is None


def test_tri_bool_literal_renders_all_three_states() -> None:
    """The tri-state renderer yields the Jython literals for True, False and None."""
    render = _module_fn("_tri_bool_literal")

    assert render(value=True) == "True"
    assert render(value=False) == "False"
    assert render(value=None) == "None"


def test_resolve_debug_info_path_anchors_a_relative_path_to_the_working_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A relative debug-info path is resolved against the current directory.

    Args:
        tmp_path: Pytest temporary directory holding the symbol file.
        monkeypatch: Pytest fixture used to change the working directory.
    """
    symbol_file = tmp_path / "symbols.pdb"
    symbol_file.write_bytes(b"debug")
    monkeypatch.chdir(tmp_path)

    resolved = _module_fn("_resolve_debug_info_path")("symbols.pdb")

    assert isinstance(resolved, Path)
    assert resolved.is_absolute()
    assert resolved.samefile(symbol_file)


def test_resolve_c_header_path_anchors_a_relative_path_to_the_working_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A relative C header path is resolved against the current directory.

    Args:
        tmp_path: Pytest temporary directory holding the header.
        monkeypatch: Pytest fixture used to change the working directory.
    """
    header = tmp_path / "types.h"
    header.write_text("typedef int widget_t;\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    resolved = _module_fn("_resolve_c_header_path")("types.h")

    assert isinstance(resolved, Path)
    assert resolved.is_absolute()
    assert resolved.samefile(header)


@pytest.mark.parametrize("blank", ["", "   ", "\t\n"], ids=["empty", "spaces", "whitespace"])
def test_resolve_c_header_path_rejects_a_blank_path(blank: str) -> None:
    """An empty or whitespace-only header path is rejected before touching the filesystem.

    Args:
        blank: Blank path text.
    """
    with pytest.raises(ToolError, match=r"^C header file path invalid$"):
        _module_fn("_resolve_c_header_path")(blank)


def test_resolve_c_header_path_rejects_a_directory(tmp_path: Path) -> None:
    """A directory is not a regular file and is reported as such.

    Args:
        tmp_path: Pytest temporary directory used as the rejected target.
    """
    with pytest.raises(ToolError, match=r"^C header path is not a regular file: ") as excinfo:
        _module_fn("_resolve_c_header_path")(str(tmp_path))

    assert os.path.normpath(str(tmp_path)) in str(excinfo.value)


def test_assign_process_to_job_object_logs_when_the_process_cannot_be_opened() -> None:
    """The System Idle Process id cannot be opened, so the assignment is skipped with a warning.

    Windows documents that ``OpenProcess`` fails with ``ERROR_INVALID_PARAMETER``
    for process id 0.
    """
    with capture_logs() as events:
        result = _module_fn("_assign_process_to_job_object")(0, 0)

    assert result is None
    failures = _events_named(events, "ghidra_job_object_open_process_failed")
    assert len(failures) == 1
    assert failures[0]["log_level"] == "warning"
    assert failures[0]["pid"] == 0
    assert not _events_named(events, "ghidra_job_object_assigned")


def test_assign_process_to_job_object_logs_when_the_job_handle_is_invalid() -> None:
    """A real child is opened but a null job handle cannot accept it, so a warning is logged."""
    with ManagedProcess(_sleeper_argv()) as managed, capture_logs() as events:
        result = _module_fn("_assign_process_to_job_object")(0, managed.pid)

        assert managed.process.poll() is None

    assert result is None
    failures = _events_named(events, "ghidra_job_object_assign_failed")
    assert len(failures) == 1
    assert failures[0]["log_level"] == "warning"
    assert failures[0]["pid"] == managed.pid
    assert not _events_named(events, "ghidra_job_object_assigned")


def test_reclaim_stale_project_lock_skips_the_lock_file_that_does_not_exist(tmp_path: Path) -> None:
    """With only ``.lock`` present, it is reclaimed and the absent ``.lock~`` is skipped.

    Args:
        tmp_path: Pytest temporary directory standing in for a project directory.
    """
    lock = tmp_path / "proj.lock"
    lock.write_bytes(b"stale")

    _module_fn("_reclaim_stale_project_lock")(tmp_path, "proj")

    assert not lock.exists()
    assert not (tmp_path / "proj.lock~").exists()


def test_reclaim_stale_project_lock_stops_when_a_lock_file_cannot_be_deleted(tmp_path: Path) -> None:
    """A lock file kept open without delete sharing survives; the reclaim logs and stops.

    Python opens files with read/write sharing but not delete sharing on
    Windows, so a second open succeeds (the lock looks stale) while the
    delete fails with a sharing violation.

    Args:
        tmp_path: Pytest temporary directory standing in for a project directory.
    """
    lock = tmp_path / "held.lock"
    companion = tmp_path / "held.lock~"
    lock.write_bytes(b"held")
    companion.write_bytes(b"companion")

    with lock.open("r+b"), capture_logs() as events:
        result = _module_fn("_reclaim_stale_project_lock")(tmp_path, "held")

    assert result is None
    failures = _events_named(events, "ghidra_stale_project_lock_unlink_failed")
    assert len(failures) == 1
    assert failures[0]["path"] == str(lock)
    assert not _events_named(events, "ghidra_stale_project_lock_reclaimed")
    assert lock.exists()
    assert companion.exists()


@pytest.mark.asyncio
async def test_initialize_records_the_tool_path_and_reports_an_unreachable_port(tmp_path: Path) -> None:
    """``initialize`` stores the given install path, then fails cleanly when nothing listens.

    Args:
        tmp_path: Pytest temporary directory used as the install path.
    """
    port = _reserve_free_port()
    bridge = GhidraBridge()
    bridge.set_port(port)

    with pytest.raises(ToolError) as excinfo:
        await bridge.initialize(tmp_path)

    assert bridge.ghidra_path == tmp_path
    assert f"127.0.0.1:{port}" in str(excinfo.value)
    assert bridge.state.connected is False
    assert bridge.state.tool_running is False
    assert bridge.state.last_error == str(excinfo.value)


def test_close_bridge_client_closes_the_rpc_socket() -> None:
    """The client socket is closed by ``_close_bridge_client``."""
    client = _make_rpc_client(_reserve_free_port())
    connection = _attr(client, "client")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    setattr(connection, "sock", sock)

    _method(GhidraBridge, "_close_bridge_client")(client)

    assert sock.fileno() == -1


def test_close_bridge_client_tolerates_a_client_that_never_connected() -> None:
    """A client with no socket and no communications thread is left alone without error."""
    client = _make_rpc_client(_reserve_free_port())
    connection = _attr(client, "client")

    result = _method(GhidraBridge, "_close_bridge_client")(client)

    assert result is None
    assert _attr(connection, "sock") is None


def test_close_bridge_client_waits_for_the_communications_thread() -> None:
    """Closing the socket releases a thread blocked on its peer, and the thread is joined."""
    client = _make_rpc_client(_reserve_free_port())
    connection = _attr(client, "client")
    near, far = socket.socketpair()
    reader = threading.Thread(target=_block_until_eof, args=(far,), name="critcov-ghidra-reader", daemon=True)
    reader.start()
    setattr(connection, "sock", near)
    setattr(connection, "comms_thread", reader)
    try:
        _method(GhidraBridge, "_close_bridge_client")(client)

        assert near.fileno() == -1
        assert not reader.is_alive()
    finally:
        far.close()
        reader.join(timeout=10)


def test_close_bridge_client_ignores_a_communications_thread_that_never_started() -> None:
    """Joining a never-started thread raises ``RuntimeError``, which is swallowed."""
    client = _make_rpc_client(_reserve_free_port())
    connection = _attr(client, "client")
    pending = threading.Thread(target=_do_nothing, name="critcov-ghidra-pending", daemon=True)
    setattr(connection, "comms_thread", pending)

    result = _method(GhidraBridge, "_close_bridge_client")(client)

    assert result is None
    assert pending.ident is None


def test_cleanup_bridge_script_survives_an_undeletable_script_path(tmp_path: Path) -> None:
    """A script path that is really a directory cannot be unlinked; the error is logged, not raised.

    Args:
        tmp_path: Pytest temporary directory holding the directory-as-script.
    """
    impostor = tmp_path / "start_bridge.py"
    impostor.mkdir()

    with capture_logs() as events:
        result = _method(GhidraBridge, "_cleanup_bridge_script")(impostor)

    assert result is None
    assert len(_events_named(events, "bridge_script_unlink_failed")) == 1
    assert impostor.is_dir()
    assert not _events_named(events, "bridge_script_parent_not_empty")


def test_cleanup_bridge_script_warns_when_the_parent_directory_is_already_gone(tmp_path: Path) -> None:
    """A script whose parent directory never existed is a no-op that warns about the missing parent.

    Args:
        tmp_path: Pytest temporary directory containing the absent parent.
    """
    parent = tmp_path / "already-removed"
    script = parent / "start_bridge.py"

    with capture_logs() as events:
        result = _method(GhidraBridge, "_cleanup_bridge_script")(script)

    assert result is None
    absent = _events_named(events, "bridge_script_parent_already_absent")
    assert len(absent) == 1
    assert absent[0]["parent"] == str(parent)
    assert not parent.exists()


@pytest.mark.asyncio
async def test_start_headless_requires_a_ghidra_path(tmp_path: Path) -> None:
    """Starting without an install path is refused before anything is spawned.

    Args:
        tmp_path: Pytest temporary directory passed as the project directory.
    """
    bridge = GhidraBridge()

    with pytest.raises(ToolError, match=r"^Ghidra path not set$"):
        await bridge.start_headless(tmp_path)

    assert bridge.project_path is None


def test_check_no_live_jython_extension_refuses_an_install_with_jython_jars(tmp_path: Path) -> None:
    """A Jython extension directory that carries a jar makes the install unusable.

    Args:
        tmp_path: Pytest temporary directory used as a fake Ghidra install.
    """
    lib = tmp_path / "Ghidra" / "Features" / "Jython" / "lib"
    lib.mkdir(parents=True)
    (lib / "jython-standalone.jar").write_bytes(b"PK")

    with pytest.raises(ToolError, match=r"^A live Jython extension is installed at ") as excinfo:
        _method(GhidraBridge, "_check_no_live_jython_extension")(tmp_path)

    assert str(lib.parent) in str(excinfo.value)
    assert "Jython.disabled" in str(excinfo.value)


def test_check_no_live_jython_extension_accepts_an_extension_without_jars(tmp_path: Path) -> None:
    """A Jython directory whose ``lib`` holds no jar files does not block the install.

    Args:
        tmp_path: Pytest temporary directory used as a fake Ghidra install.
    """
    lib = tmp_path / "Ghidra" / "Features" / "Jython" / "lib"
    lib.mkdir(parents=True)
    (lib / "README.txt").write_text("no jars here\n", encoding="utf-8")

    assert _method(GhidraBridge, "_check_no_live_jython_extension")(tmp_path) is None


@pytest.mark.parametrize(
    ("release_text", "expected"),
    [
        (None, None),
        ('IMPLEMENTOR="Example Vendor"\n', None),
        ('JAVA_VERSION="21.0.8"\n', 21),
        ('IMPLEMENTOR="x"\nJAVA_VERSION="17.0.9"\n', 17),
        ('JAVA_VERSION="1.8.0_402"\n', 8),
        ('JAVA_VERSION="abc.1"\n', None),
        ('JAVA_VERSION="1.x"\n', None),
        ('JAVA_VERSION="1"\n', None),
    ],
    ids=[
        "missing-release-file",
        "no-version-line",
        "modern-scheme",
        "version-line-after-others",
        "legacy-scheme",
        "non-numeric-major",
        "legacy-non-numeric-minor",
        "legacy-without-minor",
    ],
)
def test_read_jdk_major_parses_release_files(tmp_path: Path, release_text: str | None, expected: int | None) -> None:
    """The JDK feature number comes from the ``JAVA_VERSION`` entry of the ``release`` file.

    Modern versions carry it first (``21.0.8``), the legacy ``1.x`` scheme in
    the second component, and anything unparseable yields ``None``.

    Args:
        tmp_path: Pytest temporary directory used as the JDK home.
        release_text: Content of the ``release`` file, or ``None`` for no file.
        expected: The feature number the file declares, or ``None``.
    """
    if release_text is not None:
        (tmp_path / "release").write_text(release_text, encoding="utf-8")

    assert _method(GhidraBridge, "_read_jdk_major")(tmp_path) == expected


@pytest.mark.parametrize(
    ("properties_text", "expected"),
    [
        (None, 21),
        ("application.name=Ghidra\n", 21),
        ("application.java.min=17\n", 17),
        ("application.java.min = 25\n", 25),
        ("application.java.min=" + "9" * 5000 + "\n", 21),
    ],
    ids=[
        "missing-properties-file",
        "missing-key",
        "declared-minimum",
        "declared-minimum-with-spaces",
        "digit-run-beyond-the-integer-parse-limit",
    ],
)
def test_required_min_jdk_reads_the_declared_minimum(tmp_path: Path, properties_text: str | None, expected: int) -> None:
    """The minimum JDK comes from ``application.java.min`` and falls back to 21 otherwise.

    A digit run longer than Python's integer-string conversion limit cannot be
    parsed, so it falls back to the default instead of raising.

    Args:
        tmp_path: Pytest temporary directory used as a fake Ghidra install.
        properties_text: Content of ``Ghidra/application.properties``, or ``None``.
        expected: The minimum major version the helper must report.
    """
    if properties_text is not None:
        properties = tmp_path / "Ghidra" / "application.properties"
        properties.parent.mkdir(parents=True)
        properties.write_text(properties_text, encoding="utf-8")

    assert _method(GhidraBridge, "_required_min_jdk")(tmp_path) == expected


def test_discover_jdk_rejects_bundled_jdks_below_the_required_major(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Bundled JDK directories that are too old, or carry no version, are skipped.

    Args:
        tmp_path: Pytest temporary directory used as a fake Ghidra install.
        monkeypatch: Pytest fixture used to clear ``JAVA_HOME``.
    """
    monkeypatch.delenv("JAVA_HOME", raising=False)
    old_jdk = tmp_path / "jdk-17.0.9"
    (old_jdk / "bin").mkdir(parents=True)
    (old_jdk / "release").write_text('JAVA_VERSION="17.0.9"\n', encoding="utf-8")
    (tmp_path / "jdk-unversioned" / "bin").mkdir(parents=True)

    assert _method(GhidraBridge, "_discover_jdk")(tmp_path) is None


def test_discover_jdk_prefers_the_newest_qualifying_bundled_jdk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Among bundled JDKs the highest qualifying major wins and older ones are ignored.

    Args:
        tmp_path: Pytest temporary directory used as a fake Ghidra install.
        monkeypatch: Pytest fixture used to clear ``JAVA_HOME``.
    """
    monkeypatch.delenv("JAVA_HOME", raising=False)
    for name, version in (("jdk-17.0.9", "17.0.9"), ("jdk-21.0.2", "21.0.2"), ("jdk-23.0.1", "23.0.1")):
        (tmp_path / name / "bin").mkdir(parents=True)
        (tmp_path / name / "release").write_text(f'JAVA_VERSION="{version}"\n', encoding="utf-8")

    assert _method(GhidraBridge, "_discover_jdk")(tmp_path) == tmp_path / "jdk-23.0.1"


def test_drain_stream_forwards_decoded_lines_and_skips_blank_ones() -> None:
    """Blank and whitespace-only lines are dropped; the rest are decoded and forwarded in order."""
    collected: list[str] = []
    stream = io.BytesIO(b"\n   \nfirst\r\n\xff-bad\nlast")

    _method(GhidraBridge, "_drain_stream")(stream, "stdout", collected.append)

    assert collected == ["first", "�-bad", "last"]
    assert stream.closed


def test_drain_stream_logs_and_stops_when_the_pipe_is_unreadable() -> None:
    """Reading a closed pipe raises ``ValueError``; the drain logs a warning and returns."""
    collected: list[str] = []
    stream = io.BytesIO(b"never read")
    stream.close()

    with capture_logs() as events:
        result = _method(GhidraBridge, "_drain_stream")(stream, "stderr", collected.append)

    assert result is None
    assert collected == []
    terminated = _events_named(events, "ghidra_pipe_drain_terminated")
    assert len(terminated) == 1
    assert terminated[0]["stream"] == "stderr"
    assert terminated[0]["log_level"] == "warning"


def test_start_drain_threads_without_stderr_pipe_drains_only_stdout() -> None:
    """A process with no stderr pipe gets only the stdout drain thread."""
    bridge = GhidraBridge()
    argv = [sys.executable, "-c", "print('critcov-stdout-line')"]

    with ManagedProcess(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as managed:
        _method(bridge, "_start_drain_threads")(managed.process)
        stdout_thread = _attr(bridge, "_stdout_drain_thread")
        stderr_thread = _attr(bridge, "_stderr_drain_thread")
        assert isinstance(stdout_thread, threading.Thread)
        stdout_thread.join(timeout=30)

        assert stderr_thread is None
        assert stdout_thread.name == "ghidra-stdout-drain"
        assert not stdout_thread.is_alive()
        assert managed.process.stdout is not None
        assert managed.process.stdout.closed


def test_start_drain_threads_without_stdout_pipe_buffers_stderr_lines() -> None:
    """A process with no stdout pipe gets only the stderr drain thread, which buffers its lines."""
    bridge = GhidraBridge()
    argv = [sys.executable, "-c", f"import sys; sys.stderr.write('{_STDERR_MARKER}\\n')"]

    with ManagedProcess(argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE) as managed:
        _method(bridge, "_start_drain_threads")(managed.process)
        stdout_thread = _attr(bridge, "_stdout_drain_thread")
        stderr_thread = _attr(bridge, "_stderr_drain_thread")
        assert isinstance(stderr_thread, threading.Thread)
        stderr_thread.join(timeout=30)

        assert stdout_thread is None
        assert stderr_thread.name == "ghidra-stderr-drain"
        assert not stderr_thread.is_alive()

    tail = _method(bridge, "_captured_stderr_tail")()
    assert isinstance(tail, str)
    assert _STDERR_MARKER in tail.splitlines()


@pytest.mark.asyncio
async def test_wait_for_bridge_port_returns_as_soon_as_a_listener_accepts(listener: tuple[socket.socket, int]) -> None:
    """Polling ends on the first attempt when the port already accepts connections.

    Args:
        listener: Real loopback listener and its port.
    """
    _, port = listener
    bridge = GhidraBridge()
    bridge.set_port(port)

    with capture_logs() as events:
        result = await _async_method(bridge, "_wait_for_bridge_port")(timeout_seconds=30, poll_interval=0.05)

    assert result is None
    ready = _events_named(events, "ghidra_bridge_port_ready")
    assert len(ready) == 1
    assert ready[0]["port"] == port
    assert ready[0]["attempts"] == 1


def test_create_bridge_script_reports_an_unusable_temp_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """When the temp root does not exist, deploying the bridge script fails with a clear error.

    Args:
        tmp_path: Pytest temporary directory containing the absent temp root.
        monkeypatch: Pytest fixture used to point ``tempfile`` at the absent root.
    """
    absent_root = tmp_path / "absent-temp-root"
    monkeypatch.setattr(tempfile, "tempdir", str(absent_root))
    bridge = GhidraBridge()

    with pytest.raises(ToolError, match=r"^Failed to create ghidra bridge script directory: "):
        bridge.create_bridge_script()

    assert bridge.bridge_script_path is None
    assert not absent_root.exists()


@pytest.mark.asyncio
async def test_extract_binary_metadata_without_a_bridge_is_empty() -> None:
    """With no RPC client attached the metadata sweep returns four empty values."""
    bridge = GhidraBridge()

    assert await _async_method(bridge, "_extract_binary_metadata")() == (0, [], [], [])


@pytest.mark.asyncio
async def test_query_ghidra_arch_without_a_bridge_is_none() -> None:
    """With no RPC client attached there is no architecture to query."""
    bridge = GhidraBridge()

    assert await _async_method(bridge, "_query_ghidra_arch")() is None


@pytest.mark.asyncio
async def test_query_ghidra_arch_is_none_when_the_peer_is_unreachable(dead_bridge: GhidraBridge) -> None:
    """A failing remote query is logged and reported as ``None`` rather than raised.

    Args:
        dead_bridge: Bridge whose RPC peer is unreachable.
    """
    with capture_logs() as events:
        result = await _async_method(dead_bridge, "_query_ghidra_arch")()

    assert result is None
    assert len(_events_named(events, "ghidra_arch_query_tool_error")) == 1


@pytest.mark.asyncio
async def test_resolve_architecture_keeps_the_unknown_header_answer_without_ghidra() -> None:
    """With no Ghidra answer, an unrecognizable header resolves to the header parser's ``unknown``."""
    bridge = GhidraBridge()

    resolved = await _async_method(bridge, "_resolve_architecture")(b"plain text, no executable header")

    assert resolved == ("unknown", False)


@pytest.mark.asyncio
async def test_resolve_architecture_survives_an_unreachable_peer(dead_bridge: GhidraBridge) -> None:
    """A dead peer during the architecture fallback leaves the header answer in place.

    Args:
        dead_bridge: Bridge whose RPC peer is unreachable.
    """
    resolved = await _async_method(dead_bridge, "_resolve_architecture")(b"plain text, no executable header")

    assert resolved == ("unknown", False)


@pytest.mark.asyncio
@pytest.mark.parametrize(("name", "call"), _UNCONNECTED_CALLS, ids=[name for name, _ in _UNCONNECTED_CALLS])
async def test_edit_accessors_refuse_to_run_without_a_connection(name: str, call: _BridgeCall) -> None:
    """The edit accessors fail fast with the standard not-connected error.

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
async def test_load_binary_propagates_a_failed_remote_import(dead_bridge: GhidraBridge, sample_file: Path) -> None:
    """When the remote import call fails, ``load_binary`` re-raises it and records no loaded binary.

    Args:
        dead_bridge: Bridge whose RPC peer is unreachable.
        sample_file: Existing file handed to ``load_binary``.
    """
    with pytest.raises(ToolError, match=_REMOTE_FAILURE_PATTERN):
        await dead_bridge.load_binary(sample_file)

    assert dead_bridge.state.binary_loaded is False


@pytest.mark.asyncio
async def test_live_session_runs_scripts_against_the_imported_program(live_session: GhidraBridge, real_pe_exe: Path) -> None:
    """A started headless session answers arithmetic and names the imported program.

    Args:
        live_session: Connected headless Ghidra bridge.
        real_pe_exe: The executable imported by the fixture.
    """
    assert live_session.state.connected is True
    assert live_session.state.tool_running is True
    assert live_session.state.binary_loaded is True
    assert live_session.project_path is not None
    assert live_session.project_path.name == "critcov_ghidra_01"
    assert live_session.bridge_script_path is not None
    assert live_session.bridge_script_path.name == "start_bridge.py"

    assert await live_session.execute_script("6 * 7") == "42"
    program_name = await live_session.execute_script("str(currentProgram.getName())")
    assert program_name.lower() == real_pe_exe.name.lower()


@pytest.mark.asyncio
async def test_live_session_architecture_matches_the_pe_header(live_session: GhidraBridge, real_pe_exe: Path) -> None:
    """Ghidra's own processor and pointer size agree with the PE file header.

    The expectation is read from the ``Machine`` field with ``struct``; the
    bridge reaches the same answer by asking the loaded program, both directly
    and as the fallback for a header it cannot parse.

    Args:
        live_session: Connected headless Ghidra bridge.
        real_pe_exe: The executable imported by the fixture.
    """
    expected = _PE_MACHINE_TO_ARCH[_pe_machine(real_pe_exe)]

    queried = await _async_method(live_session, "_query_ghidra_arch")()
    resolved = await _async_method(live_session, "_resolve_architecture")(b"plain text, no executable header")

    assert queried == expected
    assert resolved == expected


@pytest.mark.asyncio
async def test_live_session_rejects_a_file_no_loader_recognizes(live_session: GhidraBridge, text_file: Path) -> None:
    """Importing plain text into the live session fails with a ``ToolError`` and loads nothing.

    The attempt runs on a second bridge sharing the live RPC client, so the
    session's own bridge state is untouched. Ghidra either raises from its
    import call (reported as a remote failure) or returns no program (reported
    as an import failure); both are the documented ``ToolError`` outcomes.

    Args:
        live_session: Connected headless Ghidra bridge.
        text_file: Plain text file no loader recognizes.
    """
    other = GhidraBridge()
    other.attach_remote_bridge(_attr(live_session, "_bridge"))

    with pytest.raises(ToolError) as excinfo:
        await other.load_binary(text_file)

    assert str(excinfo.value).startswith(("Failed to import binary into Ghidra", "Remote execution failed"))
    assert other.state.binary_loaded is False
    assert live_session.state.binary_loaded is True
